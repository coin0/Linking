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
)

var (
	relayedIP    = ""
	relayedPort  = 0
	srflxProto   = ""
	srflxIP      = ""
	srflxPort    = 0
	transport    = ""
	client, _    = stun.NewClient("", 0, "")
)

func init() {

	addr := flag.String("a", "udp://127.0.0.1:3478", "TURN/STUN server address")
	conf.ClientArgs.Username = flag.String("u", "", "TURN/STUN server username")
	conf.ClientArgs.Password = flag.String("p", "", "TURN/STUN server password")
	conf.ClientArgs.Debug    = flag.Bool("d", false, "switch to turn on debug mode")
	conf.ClientArgs.Log      = flag.String("log", "cl.log", "path for log file")
	flag.Parse()

	// parse server address
	conf.ClientArgs.Proto, conf.ClientArgs.ServerIP, conf.ClientArgs.ServerPort = parseAddr(*addr)
}

func parseAddr(addr string) (proto string, ip string, port int) {

	str := strings.Split(addr, "://")
	proto = str[0]
	str = strings.Split(str[1], ":")
	ip = str[0]
	port, _ = strconv.Atoi(str[1])

	return
}

func usage() {

	serverAddr := fmt.Sprintf("%s://%s:%d",
		conf.ClientArgs.Proto,
		conf.ClientArgs.ServerIP,
		conf.ClientArgs.ServerPort,
	)

	fmt.Println("******************************************")
	fmt.Println("Simple STUN client")
	fmt.Printf("  Ready to connect to server address %s\n", serverAddr)
	if relayedIP != "" { fmt.Printf("  Relayed address %s://%s:%d\n", transport, relayedIP, relayedPort) }
	if srflxIP != ""   { fmt.Printf("  Reflexive address %s://%s:%d\n", srflxProto, srflxIP, srflxPort) }
	fmt. Printf("  Debug mode: %s\n\n", func() string {
		if *conf.ClientArgs.Debug { return "ON" }
		return "OFF"
	}())
	fmt.Printf("n                        : create a new client instance\n")
	fmt.Printf("b                        : send a bind request\n")
	fmt.Printf("a <tcp/udp> <lifetime>   : start allocation by given arguments\n")
	fmt.Printf("r <lifetime>             : send a refresh request\n")
	fmt.Printf("p <ip1> <ip2> <ip...>    : create permission request\n")
	fmt.Printf("c <ip> <port>            : bind a channel\n")
	fmt.Printf("x <iP> <port> <message>  : send a single line text message to peers\n")
	fmt.Printf("l                        : start listening messages from other peers\n")
	fmt.Printf("d                        : disconnect from the server\n")
	fmt.Printf("q                        : quit this client\n")
	fmt.Printf("---------------------------------------------------------------------\n")
	fmt.Printf("P <ip> <port> <sz> <int> : automation ping test with given sz and int\n")
	fmt.Printf("Q <ip> <port>            : automation test for pong response\n")
	fmt.Printf("\n")
}

func ping1(ip string, port, size, dur int) error {

	meter := ping.NewMeter(time.Second * 5)

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
				ping.UpdateDur(toSend, time.Duration(dur) * time.Millisecond)
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
			ping.UpdateRespTime(data, time.Now())

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
		if client, err = stun.NewClient(
			conf.ClientArgs.ServerIP,
			conf.ClientArgs.ServerPort,
			conf.ClientArgs.Proto,
		); err == nil {
			client.DebugOn = *conf.ClientArgs.Debug
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
		transport = "udp"
		if get(input, 1) == "tcp" {
			transport = "tcp"
		}
		err = client.Alloc(transport)
	case 'r':
		if len(strings.Split(input, " ")) != 2 { return fmt.Errorf("arguments mismatch") }
		t, _ := strconv.Atoi(get(input, 1))
		err = client.Refresh(uint32(t))
	case 'p':
		err = client.CreatePerm(getAll(input))
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
	case 'P':
		if len(strings.Split(input, " ")) != 5 { return fmt.Errorf("arguments mismatch") }
		p, _ := strconv.Atoi(get(input, 2))
		sz, _ := strconv.Atoi(get(input, 3))
		dur, _ := strconv.Atoi(get(input, 4))
		err = ping1(get(input, 1), p, sz, dur)
	case 'Q':
		if len(strings.Split(input, " ")) != 3 { return fmt.Errorf("arguments mismatch") }
		p, _ := strconv.Atoi(get(input, 2))
		err = pong1(get(input, 1), p)
	default:
		err = fmt.Errorf("invalid command")
	}

	return
}

func main() {

	SetLog(*conf.ClientArgs.Log)

	// create a new stunclient
	var err error
	client, err = stun.NewClient(
		conf.ClientArgs.ServerIP,
		conf.ClientArgs.ServerPort,
		conf.ClientArgs.Proto,
	)
	if err != nil {
		fmt.Println("could not create client:", err)
		Fatal("create client: %s", err)
	} else {
		client.DebugOn = *conf.ClientArgs.Debug
	}

	if client.DebugOn {
		SetLevel(LEVEL_VERB)
	} else {
		SetLevel(LEVEL_INFO)
	}

	for {
		// wait for user input
		relayedIP, relayedPort, _ = client.RelayedAddr()
		srflxProto, srflxIP, srflxPort, _ = client.SrflxAddr()

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
