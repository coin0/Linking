package main

import (
	"flag"
	"conf"
	"stun"
	"sync"
	"fmt"
	"strings"
	"os"
	"net/http"
	"net"
	"strconv"
	"io"
	"time"
	. "util/log"
)

var (
	help = flag.Bool("h", false, "print usage")
)

func init() {
	// IPv4
	conf.Args.ServiceIP = flag.String("sip", "0.0.0.0", "IP address for service")
	conf.Args.RelayedIP = flag.String("rip", "", "IP address bound for relayed candidates")
	conf.Args.RelayedInf = flag.String("rif", "", "first ipv4 of specified interface will be used for relay")
	// IPv6
	conf.Args.ServiceIPv6 = flag.String("sip6", "::", "IPv6 address for service")
	conf.Args.RelayedIPv6 = flag.String("rip6", "", "IPv6 address bound for relayed candidates")
	conf.Args.RelayedInf6 = flag.String("rif6", "", "first ipv6 of specified interface used for relay")
	conf.Args.Port = flag.String("port", "3478", "specific port to bind")
	conf.Args.Cert = flag.String("cert", "server.crt", "public certificate for sec transport")
	conf.Args.Key = flag.String("key", "server.key", "private key for sec transport")
	conf.Args.Realm = flag.String("realm", "link", "used for long-term cred for TURN")
	conf.Args.Http = flag.String("http", "8080", "port to receive http api request")
	conf.Args.Log = flag.String("log", "stun.log", "path for log file")
	flag.Var(&conf.Args.Users, "u", "add one user to TURN server")

	flag.Parse()
}

func main() {

	// print message
	if *help {
		flag.Usage()
		return
	}

	// get interface IP address for relay, this should override -rip and -rip6
	// IPv4
	if err := GetInfFirstIP(conf.Args.RelayedInf, conf.Args.RelayedIP, conf.Args.ServiceIP, true); err != nil {
		fmt.Println("Get IPv4:", err)
		os.Exit(1)
	}
	// IPv6
	if err := GetInfFirstIP(conf.Args.RelayedInf6, conf.Args.RelayedIPv6, conf.Args.ServiceIPv6, false); err != nil {
		fmt.Println("Get IPv6:", err)
		os.Exit(1)
	}

	// open log file
	SetLog(*conf.Args.Log)

	// handle user account
	loadUsers()

	wg := &sync.WaitGroup{}

	// start listening
	wg.Add(4)

	// listen on UDP for IPv4 and IPv6 sockets
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		for {
			stun.ListenUDP("udp4", *conf.Args.ServiceIP, *conf.Args.Port)
		}
	}(wg)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		for {
			stun.ListenUDP("udp6", "[" + *conf.Args.ServiceIPv6 + "]", *conf.Args.Port)
		}
	}(wg)

	// listen on TCP or TLS for IPv4 and IPv6 sockets
	go func (wg *sync.WaitGroup) {
		defer wg.Done()
		for {
			stun.ListenTCP("tcp4", *conf.Args.ServiceIP, *conf.Args.Port)
		}
	}(wg)
	go func (wg *sync.WaitGroup) {
		defer wg.Done()
		for {
			stun.ListenTCP("tcp6", "[" + *conf.Args.ServiceIPv6 + "]", *conf.Args.Port)
		}
	}(wg)

	go func () {
		for {
			listenHTTP(*conf.Args.ServiceIP, *conf.Args.Http)
		}
	}()

	wg.Wait()

	return
}

func GetInfFirstIP(inf, relayIP, servIP *string, ipv4 bool) error {

	// get first valid IPv4 / IPv6 address of specified interface
	getIP := func(inf string, needIPv4 bool) (addr string, err error) {

		ief, err := net.InterfaceByName(inf)
		if err != nil {
			return "", fmt.Errorf("interface %s: %s", inf, err)
		}

		addrs, err := ief.Addrs()
		if err != nil {
			return "", fmt.Errorf("interface %s: %s", inf, err)
		}

		for _, addr := range addrs {
			if ip := addr.(*net.IPNet).IP.To4(); ip != nil && needIPv4 {
				return ip.String(), nil
			} else if ip == nil && !needIPv4 {
				return ip.To16().String(), nil
			}
		}

		return "", fmt.Errorf("interface %s: no available address", inf)
	}

	// override relay arguments if interface name is specified
	if len(*inf) > 0 {
		var err error
		*relayIP, err = getIP(*inf, ipv4)
		if err != nil {
			return err
		}
	} else if len(*relayIP) == 0 {
		// use same IP as service address if no relayed IP specified
		*relayIP = *servIP
	}

	return nil
}

func loadUsers() {

	for _, acc := range conf.Args.Users {
		pair := strings.Split(acc, ":")
		if err := conf.Users.Add(pair[0], *conf.Args.Realm, pair[1]); err != nil {
			fmt.Printf("cannot add user \"%s\" from cmd line: %s\n", pair[0], err.Error())
			os.Exit(1)
		}
		fmt.Println("user", pair[0], "added")
	}
}

func listenHTTP(ip, port string) error {

	http.HandleFunc("/get/alloc", httpGetAlloc)
	http.HandleFunc("/get/user", httpGetUser)
	http.HandleFunc("/set/user", httpSetUser)
	err := http.ListenAndServe(ip + ":" + port, nil)
	return err
}

func httpGetAlloc(w http.ResponseWriter, req *http.Request) {

	io.WriteString(w, stun.AllocTable());
}

func httpGetUser(w http.ResponseWriter, req *http.Request) {

	io.WriteString(w, conf.Users.UserTable());
}

func httpSetUser(w http.ResponseWriter, req *http.Request) {

	q := req.URL.Query()

	// get name
	user := ""
	if name, ok := q["name"]; !ok {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "name is required")
		return
	} else {
		user = name[0]
	}

	// add a new user or update password if user exists
	if psw, ok := q["psw"]; ok {
		if err := conf.Users.Add(user, *conf.Args.Realm, psw[0]); err != nil {
			conf.Users.Reset(user, *conf.Args.Realm, psw[0])
		}
	} else {
		// cannot update a user that does not exist
		if !conf.Users.Has(user) {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, "user does not exist")
			return
		}
	}

	// update user enabler
	if enabled, ok := q["enable"]; ok {
		switch enabled[0] {
		case "1":  conf.Users.Enable(user)
		case "0":  conf.Users.Disable(user)
		default:  conf.Users.Enable(user)
		}
	}

	// update expiry
	if exp, ok := q["exp"]; ok {
		h, err := strconv.Atoi(exp[0])
		if err == nil {
			err = conf.Users.Refresh(user, time.Now().Add(time.Duration(h) * time.Hour))
		}
	}

	io.WriteString(w, conf.Users.UserTable());
}
