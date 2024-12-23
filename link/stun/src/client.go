package main

import(
	"fmt"
	"flag"
	"strings"
	"strconv"
	"bufio"
	"os"
	"conf"
	"stun"
	"time"
	"util/ping"
	. "util/log"
	"runtime/debug"
	"net"
)

var (
	relayedProto = ""
	relayedIP    = ""
	relayedPort  = 0
	srflxProto   = ""
	srflxIP      = ""
	srflxPort    = 0
	localProto   = ""
	localIP      = ""
	localPort    = 0
	client, _    = stun.NewClient("", 0, "")
)

func init() {

	raddr := flag.String("r", "udp://127.0.0.1:3478", "TURN/STUN server address")
	laddr := flag.String("l", "", "local address")
	conf.ClientArgs.Username = flag.String("u", "", "TURN/STUN server username")
	conf.ClientArgs.Password = flag.String("p", "", "TURN/STUN server password")
	conf.ClientArgs.Debug    = flag.Bool("d", false, "switch to turn on debug mode")
	conf.ClientArgs.Log      = flag.String("log", "cl.log", "path for log file")
	conf.ClientArgs.LogSize  = flag.Int("logsize", 100, "log size for a single file (MB)")
	conf.ClientArgs.LogNum   = flag.Int("lognum", 6, "maximum log file number")
	conf.ClientArgs.SelfTest = flag.Uint("t", 0, "perform self test (kbps)")
	conf.ClientArgs.VerifyCert = flag.Bool("verify-cert", false, "verify TLS certificate chain")
	flag.Parse()

	// parse server address
	conf.ClientArgs.Proto, conf.ClientArgs.ServerIP, conf.ClientArgs.ServerPort = parseAddr(*raddr)
	// parse client address and bind ANY_IP and ANY_PORT if it's left blank
	if *laddr == "" {
		conf.ClientArgs.ClientIP, conf.ClientArgs.ClientPort = "", 0
	} else {
		// check if local and remote protocols are consistent
		var proto string
		proto, conf.ClientArgs.ClientIP, conf.ClientArgs.ClientPort = parseAddr(*laddr)
		if proto != conf.ClientArgs.Proto {
			fmt.Println("protocol mismatch")
			os.Exit(1)
		}
	}
}

func parseAddr(addr string) (proto string, ip string, port int) {

	str := strings.Split(addr, "://")
	if len(str) != 2 {
		fmt.Println("address format mismatch, try udp/tcp/tls://ipv4:port or udp/tcp/tls://[ipv6]:port")
		os.Exit(1)
	}
	proto = str[0]
	str = strings.Split(str[1], ":")
	if len(str) < 2 {
		fmt.Println("address format mismatch, try udp/tcp/tls://ipv4:port or udp/tcp/tls://[ipv6]:port")
		os.Exit(1)
	} else if len(str) == 2 {
		// IPv4 address
		ip = str[0]
	} else {
		// IPv6 address -> [a:b:c:d::]
		ip = strings.Join(str[:len(str)-1], ":")
		// remove square brakets -> a:b:c:d::
		ip = ip[1:len(ip)-1]
	}
	var err error
	if port, err = strconv.Atoi(str[len(str)-1]); err != nil {
		fmt.Println("not a valid port number")
		os.Exit(1)
	}

	return
}

func verboseIP(ipstr string) string {

	if ip := net.ParseIP(ipstr); ip != nil {
		if ipv4 := ip.To4(); ipv4 == nil {
			return "[" + ip.String()  + "]"
		}
		return ip.String()
	}
	return ipstr
}

func usage() {

	serverAddr := fmt.Sprintf("%s://%s:%d",
		conf.ClientArgs.Proto,
		verboseIP(conf.ClientArgs.ServerIP),
		conf.ClientArgs.ServerPort,
	)

	fmt.Println("******************************************")
	fmt.Println("Simple STUN client")
	fmt.Printf("  NAT type: %s\n", client.NATTypeString())
	if client.NATLifetime() > 0 { fmt.Printf("  NAT lifetime: %d sec\n", client.NATLifetime()) }
	fmt.Printf("  Ready to connect to server address %s\n", serverAddr)
	if localIP != ""   { fmt.Printf("  Local address %s://%s:%d\n", localProto, verboseIP(localIP), localPort) }
	if relayedIP != "" { fmt.Printf("  Relayed address %s://%s:%d\n", relayedProto, verboseIP(relayedIP), relayedPort) }
	if srflxIP != ""   { fmt.Printf("  Reflexive address %s://%s:%d\n", srflxProto, verboseIP(srflxIP), srflxPort) }
	fmt. Printf("  Debug mode: %s\n\n", func() string {
		if *conf.ClientArgs.Debug { return "ON" }
		return "OFF"
	}())
	fmt.Printf("n                        : create a new client instance\n")
	fmt.Printf("b                        : send a bind request\n")
	fmt.Printf("a <tcp/udp> <lifetime>   : start allocation by given arguments\n")
	fmt.Printf("r <lifetime>             : send a refresh request\n")
	fmt.Printf("p <ip1> <ip2> <ip...>    : create permission request\n")
	fmt.Printf("e <ip> <port>            : create a new peer data connection\n")
	fmt.Printf("c <ip> <port>            : bind a channel\n")
	fmt.Printf("x <ip> <port> <message>  : send a single line text message to peers\n")
	fmt.Printf("l                        : start listening messages from other peers\n")
	fmt.Printf("d                        : disconnect from the server\n")
	fmt.Printf("q                        : quit this client\n")
	fmt.Printf("---------------------------------------------------------------------\n")
	fmt.Printf("T                        : probe NAT behavior (rfc5780)\n")
	fmt.Printf("L                        : probe NAT binding lifetime (rfc5780)\n")
	fmt.Printf("P <ip> <port> <sz> <int> : automation ping test with given sz and int\n")
	fmt.Printf("Q <ip> <port>            : automation test for pong response\n")
	fmt.Printf("S <tcp/udp> <sz> <int>   : self ping test with given sz and int\n")
	fmt.Printf("Z <tcp/udp> <lifetime>   : port allocation stress test\n")
	fmt.Printf("\n")
}

func ping1(ip string, port, size, dur int) error {

	meter := ping.NewMeter(time.Second * 5)
	meter.DebugOn = *conf.ClientArgs.Debug

	// respawn receive routine on error out and start initial routine
	ech := make(chan error)
	run := func() {
		client.Receive(func(data []byte, err error) int {
			if err != nil {
				Error("ping receive: %s", err.Error())
				ech <- err
				return -1
			}
			ping.UpdateArrTime(data, time.Now())

			if err := meter.Receive(data); err != nil {
				Error("ping read: %s", err.Error())
			}

			return 0
		})
	}
	refresh := func() {
		if err := client.Refresh(600); err != nil {
			Error("refresh error: %s", err.Error())
		}
	}
	bindchan := func() {
		if err := client.BindChan(ip, port); err != nil {
			Error("bindchan error: %s", err.Error())
		}
	}

	refresh()
	bindchan()
	run()

	// ticker for REFRESH allocation
	reftick := time.NewTicker(time.Second * 180)
	// ticker for CHANBIND
	chantick := time.NewTicker(time.Second * 120)
	// ticker to send ping packets
	sendtick := time.NewTicker(time.Duration(dur) * time.Millisecond)
	// MTU
	const DEFAULT_MTU = 1200

	oneSend := size
	rest := []byte{}
	if size > DEFAULT_MTU {
		oneSend = DEFAULT_MTU
		restBytes := size % DEFAULT_MTU
		if restBytes < ping.PKT_MIN_SIZE { restBytes = ping.PKT_MIN_SIZE }
		rest = make([]byte, restBytes, restBytes)
	}
	payload := make([]byte, oneSend, oneSend)
	var seq uint64
	for {
		select {
		case <-ech:
			run()
		case <-reftick.C:
			refresh()
		case <-chantick.C:
			bindchan()
		case <-sendtick.C:
			toSend := []byte{}
			for r := size; r > 0; {
				if r >= oneSend {
					toSend = payload
					r -= oneSend
				} else {
					// only when sending size > MTU
					toSend = rest
					r = 0
				}

				// send data to pong side
				ping.UpdateSeq(toSend, seq)
				seq++
				ping.UpdateSize(toSend, len(toSend))
				ping.UpdateSendTime(toSend, time.Now())
				if err := client.Send(ip, port, toSend); err != nil {
					Error("ping send: %s", err.Error())
				} else {
					meter.Send(toSend)
				}
			}
		}
	}

	return nil
}

func pong1(ip string, port int) error {

	ech := make(chan error)
	run := func() {
		client.Receive(func(data []byte, err error) int {
			if err != nil {
				Error("pong receive: %s", err.Error())
				ech <- err
				return -1
			}

			// send back to the peer who initiated ping test
			if err := client.Send(ip, port, data); err != nil {
				Error("pong send: %s", err.Error())
				ech <- err
				return -1
			}

			return 0
		})
	}
	refresh := func() {
		if err := client.Refresh(600); err != nil {
			Error("refresh error: %s", err.Error())
		}
	}
	bindchan := func() {
		if err := client.BindChan(ip, port); err != nil {
			Error("bindchan error: %s", err.Error())
		}
	}
	refresh()
	bindchan()
	run()

	// just for keep alive
	reftick := time.NewTicker(time.Second * 180)
	chantick := time.NewTicker(time.Second * 120)
	for {
		select {
		case <-ech:
			run()
		case <-reftick.C:
			refresh()
		case <-chantick.C:
			bindchan()
		}
	}

	return nil
}

// TCP relay support
func ping2(ip string, port, size, dur int) error {

	meter := ping.NewMeter(time.Second * 5)
	meter.DebugOn = *conf.ClientArgs.Debug

	// respawn receive routine on error out and start initial routine
	ech := make(chan error)
	run := func() {
		client.Receive(func(data []byte, err error) int {
			if err != nil {
				Error("ping2 receive: %s", err.Error())
				ech <- err
				return -1
			}

			if err := meter.ReceiveWithTime(data, time.Now()); err != nil {
				Error("ping2 read: %s", err.Error())
			}

			return 0
		})
	}
	refresh := func() {
		if err := client.Refresh(600); err != nil {
			Error("refresh error: %s", err.Error())
		}
	}
	connect := func() {
		if err := client.Connect(ip, port); err != nil {
			Error("connect error: %s", err.Error())
		}
	}

	refresh()
	connect()
	run()

	// ticker for REFRESH allocation
	reftick := time.NewTicker(time.Second * 180)
	// ticker to send ping packets
	sendtick := time.NewTicker(time.Duration(dur) * time.Millisecond)
	payload := make([]byte, size, size)
	var seq uint64
	for {
		select {
		case <-ech:
			run()
		case <-reftick.C:
			refresh()
		case <-sendtick.C:
			// send data to pong side
			ping.UpdateSeq(payload, seq)
			seq++
			ping.UpdateSize(payload, len(payload))
			ping.UpdateSendTime(payload, time.Now())
			if err := client.Send(ip, port, payload); err != nil {
				Error("ping2 send: %s", err.Error())
				return fmt.Errorf("ping2 send: %s", err)
			} else {
				meter.Send(payload)
			}
		}
	}

	return nil
}

// TCP relay support
func pong2(ip string, port int) error {

	ech := make(chan error)
	run := func() {
		client.Receive(func(data []byte, err error) int {
			if err != nil {
				Error("pong2 receive: %s", err.Error())
				ech <- err
				return -1
			}

			// send back to the peer who initiated ping test
			if err := client.Send(ip, port, data); err != nil {
				Error("pong2 send: %s", err.Error())
				ech <- err
				return -1
			}

			return 0
		})
	}
	refresh := func() {
		if err := client.Refresh(600); err != nil {
			Error("refresh error: %s", err.Error())
		}
	}
	createPerm := func() {
		if err := client.CreatePerm([]string{ ip }); err != nil {
			Error("create permission error: %s", err.Error())
		}
	}
	refresh()
	createPerm()
	run()

	// just for keep alive
	reftick := time.NewTicker(time.Second * 180)
	permtick := time.NewTicker(time.Second * 120)
	for {
		select {
		case <-ech:
			run()
		case <-reftick.C:
			refresh()
		case <-permtick.C:
			createPerm()
		}
	}

	return nil
}

func testPort(trans string, life int) error {

	start := time.Now()

	for i := 0;; i++ {
		cl, err := stun.NewClient2(
			"anyip", // an invalid ip results in nil net.IP (any IP)
			0,
			conf.ClientArgs.ServerIP,
			conf.ClientArgs.ServerPort,
			conf.ClientArgs.Proto,
		)
		if err != nil { return err }
		cl.Username = *conf.ClientArgs.Username
		cl.Password = *conf.ClientArgs.Password
		cl.Lifetime = uint32(life)
		cl.NoFragment = true
		cl.EvenPort = true
		cl.ReservToken = make([]byte, 8)
		if err := cl.Alloc(trans); err != nil {
			return fmt.Errorf("%s: %d allocated", err, i)
		}
		if i % 100 == 0 {
			if time.Now().After(start.Add(time.Second * time.Duration(life))) {
				return fmt.Errorf("lifetime %d sec timedout, %d allocated", life, i)
			}
			fmt.Println(i, "ports allocated...")
		}
	}
}

func exec(input string) (err error) {

	defer func() {
		if err := recover(); err != nil {
			Error("RECOVER: %s\n%s", err, string(debug.Stack()))
		}
	}()

	// get command parameter
	get := func(str string, i int) string { return strings.Split(str, " ")[i] }
	getAll := func(str string) []string { return strings.Split(str, " ")[1:] }

	switch []byte(input)[0] {
	case 'n':
		if cl, e := stun.NewClient2(
			conf.ClientArgs.ClientIP,
			conf.ClientArgs.ClientPort,
			conf.ClientArgs.ServerIP,
			conf.ClientArgs.ServerPort,
			conf.ClientArgs.Proto,
		); e == nil {
			client = cl
			client.DebugOn = *conf.ClientArgs.Debug
		} else {
			err = e
		}
	case 'b':
		err = client.Bind()
	case 'a':
		if len(strings.Split(input, " ")) != 3 { return fmt.Errorf("arguments mismatch") }
		client.Username = *conf.ClientArgs.Username
		client.Password = *conf.ClientArgs.Password
		t, _ := strconv.Atoi(get(input, 2))
		client.Lifetime = uint32(t)
		client.NoFragment = true
		client.EvenPort = true
		client.ReservToken = make([]byte, 8)
		transport := "udp"
		ipfam := "4"
		if get(input, 1) == "tcp" || get(input, 1) == "t" {
			transport = "tcp";
		} else if get(input, 1) == "tcp6" || get(input, 1) == "t6" {
			transport = "tcp"; ipfam = "6"
		} else if get(input, 1) == "udp6" || get(input, 1) == "u6" {
			transport = "udp"; ipfam = "6"
		}
		err = client.Alloc(transport + ipfam)
	case 'r':
		if len(strings.Split(input, " ")) != 2 { return fmt.Errorf("arguments mismatch") }
		t, _ := strconv.Atoi(get(input, 1))
		err = client.Refresh(uint32(t))
	case 'p':
		err = client.CreatePerm(getAll(input))
	case 'e':
		if len(strings.Split(input, " ")) != 3 { return fmt.Errorf("arguments mismatch") }
		p, _ := strconv.Atoi(get(input, 2))
		err = client.Connect(get(input, 1), p)
	case 'c':
		if len(strings.Split(input, " ")) != 3 { return fmt.Errorf("arguments mismatch") }
		p, _ := strconv.Atoi(get(input, 2))
		err = client.BindChan(get(input, 1), p)
	case 'x':
		if len(strings.Split(input, " ")) != 4 { return fmt.Errorf("arguments mismatch") }
		p, _ := strconv.Atoi(get(input, 2))
		err = client.Send(get(input, 1), p, []byte(get(input, 3)))
	case 'l':
		client.Receive(func(data []byte, err error) int {
			if err != nil {
				fmt.Println("#ERR#", err)
				return -1
			}
			return 0
		})
	case 'd':
		client.Bye()
	case 'q':
		fmt.Println("Bye!\n")
		os.Exit(0)
	case 'T':
		err = client.ProbeNatType()
	case 'L':
		err = client.ProbeNatLifetime()
	case 'P':
		if len(strings.Split(input, " ")) != 5 { return fmt.Errorf("arguments mismatch") }
		p, _ := strconv.Atoi(get(input, 2))
		sz, _ := strconv.Atoi(get(input, 3))
		dur, _ := strconv.Atoi(get(input, 4))
		if relayedProto == "udp" {
			err = ping1(get(input, 1), p, sz, dur)
		} else {
			err = ping2(get(input, 1), p, sz, dur)
		}
	case 'Q':
		if len(strings.Split(input, " ")) != 3 { return fmt.Errorf("arguments mismatch") }
		p, _ := strconv.Atoi(get(input, 2))
		if relayedProto == "udp" {
			err = pong1(get(input, 1), p)
		} else {
			err = pong2(get(input, 1), p)
		}
	case 'S':
		if len(strings.Split(input, " ")) != 4 { return fmt.Errorf("arguments mismatch") }
		// alloc for a relayed address
		if err = exec(fmt.Sprintf("a %s 600", get(input, 1))); err != nil {
			return fmt.Errorf("alloc: %s", err)
		}
		proto, ip, port, err := client.RelayedAddr()
		if err != nil {
			return fmt.Errorf("could not get relayed address: %s", err)
		}
		// begin self ping test
		sz, _ := strconv.Atoi(get(input, 2))
		dur, _ := strconv.Atoi(get(input, 3))
		if proto == "udp" {
			err = ping1(ip, port, sz, dur)
		} else {
			err = ping2(ip, port, sz, dur)
		}
	case 'Z':
		t, _ := strconv.Atoi(get(input, 2))
		transport := "udp"
		ipfam := "4"
		if get(input, 1) == "tcp" || get(input, 1) == "t" {
			transport = "tcp";
		} else if get(input, 1) == "tcp6" || get(input, 1) == "t6" {
			transport = "tcp"; ipfam = "6"
		} else if get(input, 1) == "udp6" || get(input, 1) == "u6" {
			transport = "udp"; ipfam = "6"
		}
		err = testPort(transport + ipfam, t)
	default:
		err = fmt.Errorf("invalid command")
	}

	return
}

func main() {

	SetLog(*conf.ClientArgs.Log)
	SetRotation(*conf.ClientArgs.LogSize * 1024 * 1024, *conf.ClientArgs.LogNum)

	// create a new stunclient
	var err error
	client, err = stun.NewClient2(
		conf.ClientArgs.ClientIP,
		conf.ClientArgs.ClientPort,
		conf.ClientArgs.ServerIP,
		conf.ClientArgs.ServerPort,
		conf.ClientArgs.Proto,
	)
	if err != nil {
		fmt.Println("could not create client:", err)
		Fatal("create client: %s", err)
	}

	// if user perform TURN self test, only toggle DebugOn switch for statistics
	if *conf.ClientArgs.SelfTest != 0 {
		bandwidth := int(*conf.ClientArgs.SelfTest)
		if err != nil {
			fmt.Println("invalid self test bandwidth")
			Fatal("invalid self test bandwidth")
		}
		// assume we send ping packets every 10ms
		// bandwidth x 1024 (bps) = block_size(bytes) x 8(bits) / 0.01(sec)
		err = exec(fmt.Sprintf("S u %d 10", bandwidth * 1024 / 800))
		fmt.Println(err)
		Fatal("self test: %s", err)
	}

	client.DebugOn = *conf.ClientArgs.Debug
	if client.DebugOn {
		SetLevel(LEVEL_VERB)
	} else {
		SetLevel(LEVEL_INFO)
	}

	for {
		// wait for user input
		if client != nil {
			localProto, localIP, localPort, _ = client.LocalAddr()
			relayedProto, relayedIP, relayedPort, _ = client.RelayedAddr()
			srflxProto, srflxIP, srflxPort, _ = client.SrflxAddr()
		} else {
			localIP, localPort = "", 0
			relayedIP, relayedPort = "", 0
			srflxProto, srflxIP, srflxPort = "", "", 0
		}

		usage()
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("> ")
		input, _ := reader.ReadString('\n')
		fmt.Println("******************************************")
		input = strings.Trim(input, "\n")

		if len(input) == 0 {
			continue
		}

		// execute command with specified args and print error
		if err = exec(input); err != nil {
			fmt.Println("#ERR#", err)
		} else {
			fmt.Println("OK")
		}
		err = nil
	}
}
