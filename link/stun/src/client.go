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
)

func init() {

	addr := flag.String("a", "udp://127.0.0.1:3478", "TURN/STUN server address")
	conf.ClientArgs.Username = flag.String("u", "", "TURN/STUN server username")
	conf.ClientArgs.Password = flag.String("p", "", "TURN/STUN server password")
	conf.ClientArgs.Debug    = flag.Bool("d", false, "switch to turn on debug mode")
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
	fmt. Printf("  Debug mode: %s\n\n", func() string {
		if *conf.ClientArgs.Debug { return "ON" }
		return "OFF"
	}())
	fmt.Printf("n                        : create a new client instance\n")
	fmt.Printf("b                        : send a bind request\n")
	fmt.Printf("a <lifetime>             : start allocation by given arguments\n")
	fmt.Printf("r <lifetime>             : send a refresh request\n")
	fmt.Printf("p <ip1> <ip2> <ip...>    : create permission request\n")
	fmt.Printf("c <ip> <port>            : bind a channel\n")
	fmt.Printf("x <IP> <port> <message>  : send a single line text message to peers\n")
	fmt.Printf("l                        : listen messages\n")
	fmt.Printf("\n")
}

func main() {

	// create a new stunclient
	client, err := stun.NewClient(
		conf.ClientArgs.ServerIP,
		conf.ClientArgs.ServerPort,
		conf.ClientArgs.Proto,
	)
	if err != nil {
		fmt.Println("could not create client: %s", err)
	}

	// get command parameter
	get := func(str string, i int) string { return strings.Split(str, " ")[i] }
	getAll := func(str string) []string { return strings.Split(str, " ")[1:] }

	for {
		// wait for user input
		usage()
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("> ")
		input, _ := reader.ReadString('\n')
		fmt.Println("******************************************")
		input = strings.Trim(input, "\n")

		if len(input) == 0 {
			continue
		}

		switch []byte(input)[0] {
		case 'n':
			if client, err = stun.NewClient(
				conf.ClientArgs.ServerIP,
				conf.ClientArgs.ServerPort,
				conf.ClientArgs.Proto,
			); err != nil {
				fmt.Println("could not create client: %s", err)
			} else {
				fmt.Println("OK")
			}
		case 'b':
			err = client.Bind()
		case 'a':
			if len(strings.Split(input, " ")) != 2 { continue }
			client.Username = *conf.ClientArgs.Username
			client.Password = *conf.ClientArgs.Password
			t, _ := strconv.Atoi(get(input, 1))
			client.Lifetime = uint32(t)
			client.NoFragment = true
			client.EvenPort = true
			client.ReservToken = make([]byte, 8)
			err = client.Alloc()
		case 'r':
			if len(strings.Split(input, " ")) != 2 { continue }
			t, _ := strconv.Atoi(get(input, 1))
			err = client.Refresh(uint32(t))
		case 'p':
			err = client.CreatePerm(getAll(input))
		case 'c':
			if len(strings.Split(input, " ")) != 3 { continue }
			p, _ := strconv.Atoi(get(input, 2))
			err = client.BindChan(get(input, 1), p)
		case 'x':
			if len(strings.Split(input, " ")) != 4 { continue }
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
		default:
			err = fmt.Errorf("invalid command")
		}

		// print error
		if err != nil { fmt.Println("#ERR#", err) }
		err = nil
	}
}
