package main

import (
	"flag"
	"conf"
	"stun"
	"sync"
	"fmt"
	"strings"
	"os"
	"util/net"
	"strconv"
	. "util/log"
	"rest"
	"os/signal"
	"runtime"
	"crypto/tls"
)

var (
	help = flag.Bool("h", false, "print usage")
)

func init() {
	// IPv4
	conf.Args.ServiceIP = flag.String("sip", "0.0.0.0", "IP address for service")
	conf.Args.RelayedIP = flag.String("rip", "", "IP address bound for relayed candidates")
	conf.Args.RelayedInf = flag.String("rif", "", "first ipv4 of specified interface will be used for relay")
	conf.Args.RestfulIP = flag.String("aip", "127.0.0.1", "IP address for restful service")
	// IPv6
	conf.Args.ServiceIPv6 = flag.String("sip6", "::", "IPv6 address for service")
	conf.Args.RelayedIPv6 = flag.String("rip6", "", "IPv6 address bound for relayed candidates")
	conf.Args.RelayedInf6 = flag.String("rif6", "", "first ipv6 of specified interface used for relay")
	conf.Args.Port = flag.String("port", "3478", "specific port to bind")
	conf.Args.Cert = flag.String("cert", "", "public certificate for sec transport")
	conf.Args.Key = flag.String("key", "", "private key for sec transport")
	conf.Args.Realm = flag.String("realm", "link", "used for long-term cred for TURN")
	conf.Args.Http = flag.String("http", "8080", "port to receive http api request")
	conf.Args.Log = flag.String("log", "stun.log", "path for log file")
	conf.Args.LogSize = flag.String("logsize", "100", "maximum log size (MB)")
	conf.Args.LogNum = flag.String("lognum", "6", "maximum log file number")
	conf.Args.CpuProf = flag.String("cpuprof", "cpu.prof", "write cpu profile to file")
	conf.Args.MemProf = flag.String("memprof", "mem.prof", "write memory profile to file")
	flag.Var(&conf.Args.Users, "u", "add one user to TURN server")
	flag.Var(&conf.Args.CertKeys, "c", "add a new cert-key pair")

	flag.Parse()
}

func main() {

	// print message
	if *help {
		flag.Usage()
		return
	}

	// open log file
	SetLog(*conf.Args.Log)
	if logsize, err := strconv.Atoi(*conf.Args.LogSize); err == nil {
		if lognum, err := strconv.Atoi(*conf.Args.LogNum); err == nil {
			SetRotation(logsize * 1024 * 1024, lognum)
		}
	}

	// print system information
	printSysInfo()

	// register signal handler
	initSig()

	// find available IPv4 and IPv6 interfaces
	bindInterfaces()

	// handle user account
	loadUsers()

	// add certificate pairs to list
	loadCerts()

	// service begins to listen
	startServices()
}

func printSysInfo() {

	Info("system info: pid=%d, cpu_num=%d", os.Getpid(), runtime.NumCPU())
}

func initSig() {

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func(){
		<-c
		Info("received SIGINT...")
		os.Exit(0)
	}()
}

func bindInterfaces() {

	// get interface IP address for relay, this should override -rip and -rip6
	// IPv4
	if err := net.GetInfFirstIP(conf.Args.RelayedInf, conf.Args.RelayedIP, true); err != nil {
		Error("get IPv4: %s", err)
		fmt.Println("Get IPv4:", err)
		os.Exit(1)
	}
	// IPv6
	if err := net.GetInfFirstIP(conf.Args.RelayedInf6, conf.Args.RelayedIPv6, false); err != nil {
		Error("get IPv6: %s", err)
		fmt.Println("Get IPv6:", err)
		os.Exit(1)
	}
	if len(*conf.Args.ServiceIP) > 0 {
		Info("service addr %s:%s bound\n", *conf.Args.ServiceIP, *conf.Args.Port)
		fmt.Printf("service addr %s:%s bound\n", *conf.Args.ServiceIP, *conf.Args.Port)
	}
	if len(*conf.Args.ServiceIPv6) > 0 {
		Info("service addr [%s]:%s bound\n", *conf.Args.ServiceIPv6, *conf.Args.Port)
		fmt.Printf("service addr [%s]:%s bound\n", *conf.Args.ServiceIPv6, *conf.Args.Port)
	}
	if len(*conf.Args.RelayedIP) > 0 {
		Info("relayed IP %s bound\n", *conf.Args.RelayedIP)
		fmt.Printf("relayed IP %s bound\n", *conf.Args.RelayedIP)
	}
	if len(*conf.Args.RelayedIPv6) > 0 {
		Info("relayed IP %s bound\n", *conf.Args.RelayedIPv6)
		fmt.Printf("relayed IP %s bound\n", *conf.Args.RelayedIPv6)
	}
	if len(*conf.Args.Http) > 0 {
		Info("restful addr %s:%s bound\n", *conf.Args.RestfulIP, *conf.Args.Http)
		fmt.Printf("restful addr %s:%s bound\n", *conf.Args.RestfulIP, *conf.Args.Http)
	}
}

func loadUsers() {

	for _, acc := range conf.Args.Users {
		pair := strings.Split(acc, ":")
		if err := conf.Users.Add(pair[0], *conf.Args.Realm, pair[1]); err != nil {
			fmt.Printf("cannot add user \"%s\" from cmd line: %s\n", pair[0], err.Error())
			os.Exit(1)
		}
		// the user added by command line will by default have indefinitely expiry
		conf.Users.ExpiryOff(pair[0])
		Info("user %s is added", pair[0])
		fmt.Println("user", pair[0], "added")
	}
}

func loadCerts() {

	if len(*conf.Args.Cert) == 0 && len(*conf.Args.Key) == 0 && len(conf.Args.CertKeys) == 0 { return }

	// append certificate pair to list
	conf.Args.CertKeys = append(conf.Args.CertKeys, *conf.Args.Cert + ":" + *conf.Args.Key)

	for _, one := range conf.Args.CertKeys {
		pair := strings.Split(one, ":")
		if len(pair) != 2 {
			Fatal("invalid cert key format: %s", one)
		}
		// load cert and key files from filesystem
		cert, err := tls.LoadX509KeyPair(pair[0], pair[1])
		if err != nil {
			Fatal("could not load cert: cert=%s, key=%s: %s", pair[0], pair[1], err)
		}
		conf.Args.Certs = append(conf.Args.Certs, cert)
		Info("cert %s is added", pair[0])
		fmt.Println("cert", pair[0], "added")
	}
}

func startServices() {

	wg := &sync.WaitGroup{}

	// start listening
	wg.Add(4) // exclude restful API server

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
			rest.ListenHTTP(*conf.Args.RestfulIP, *conf.Args.Http)
		}
	}()

	wg.Wait()
}
