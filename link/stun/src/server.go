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
	conf.Args.ServiceIP = flag.String("sip", "127.0.0.1", "IP address for service")
	conf.Args.RelayedIP = flag.String("rip", "", "IP address bound for relayed candidates")
	conf.Args.RelayedInf = flag.String("rif", "", "first ipv4 of specified interface will be used for relay")
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

	// override relayed IP address if necessary
	if len(*conf.Args.RelayedInf) > 0 {
		var err error
		*conf.Args.RelayedIP, err = GetInfFirstIPv4(*conf.Args.RelayedInf)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	} else if len(*conf.Args.RelayedIP) == 0 {
		*conf.Args.RelayedIP = *conf.Args.ServiceIP
	}

	// open log file
	SetLog(*conf.Args.Log)

	// handle user account
	loadUsers()

	wg := &sync.WaitGroup{}

	// start listening
	wg.Add(2)

	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		for {
			stun.ListenUDP(*conf.Args.ServiceIP, *conf.Args.Port)
		}
	}(wg)

	go func (wg *sync.WaitGroup) {
		defer wg.Done()
		for {
			stun.ListenTCP(*conf.Args.ServiceIP, *conf.Args.Port)
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

func GetInfFirstIPv4(inf string) (addr string, err error) {

	ief, err := net.InterfaceByName(inf)
	if err != nil {
		return "", fmt.Errorf("interface %s: %s", inf, err)
	}

	addrs, err := ief.Addrs()
	if err != nil {
		return "", fmt.Errorf("interface %s: %s", inf, err)
	}

	for _, addr := range addrs {
		if ipv4 := addr.(*net.IPNet).IP.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}

	return "", fmt.Errorf("interface %s: no IPv4 address bound", inf)
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
