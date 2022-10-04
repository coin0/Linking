package main

import (
	"flag"
	"conf"
	"stun"
	"sync"
	"fmt"
	"strings"
	"os"
	"crypto/md5"
	"net/http"
	"strconv"
	"io"
	"time"
)

var (
	help = flag.Bool("h", false, "print usage")
)

func init() {
	conf.Args.IP = flag.String("ip", "127.0.0.1", "udp server binding IP address")
	conf.Args.Port = flag.String("port", "3478", "specific port to bind")
	conf.Args.Realm = flag.String("realm", "link", "used for long-term cred for TURN")
	conf.Args.Http = flag.String("http", "8080", "port to receive http api request")
	flag.Var(&conf.Args.Users, "u", "add one user to TURN server")

	flag.Parse()
}

func main() {

	// print message
	if *help {
		flag.Usage()
		return
	}

	// handle user account
	loadUsers()

	wg := &sync.WaitGroup{}

	// start listening
	wg.Add(2)

	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		for {
			stun.ListenUDP(*conf.Args.IP, *conf.Args.Port)
		}
	}(wg)

	go func (wg *sync.WaitGroup) {
		defer wg.Done()
		for {
			stun.ListenTCP(*conf.Args.IP, *conf.Args.Port)
		}
	}(wg)

	go func () {
		for {
			listenHTTP(*conf.Args.IP, *conf.Args.Http)
		}
	}()

	wg.Wait()

	return
}

func loadUsers() {

	for _, acc := range conf.Args.Users {
		pair := strings.Split(acc, ":")
		key := md5.Sum([]byte(pair[0] + ":" + *conf.Args.Realm + ":" + pair[1]))
		if err := conf.Users.Add(pair[0], string(key[0:16])); err != nil {
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
		key := md5.Sum([]byte(user + ":" + *conf.Args.Realm + ":" + psw[0]))
		if err := conf.Users.Add(user, string(key[0:16])); err != nil {
			conf.Users.Reset(user, string(key[0:16]))
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
