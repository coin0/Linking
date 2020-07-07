package main

import(
	"fmt"
	"time"
	"flag"
	"stun"
	"conf"
)

func init() {

	conf.ClientArgs.ServerIP = flag.String("sip", "127.0.0.1", "server IP address")
	conf.ClientArgs.ServerPort = flag.Int("sport", 3478, "server port")
	conf.ClientArgs.PeerIP = flag.String("pip", "", "peer IP address")
	conf.ClientArgs.PeerPort = flag.Int("pport", 0, "peer port")
	conf.ClientArgs.Username = flag.String("u", "", "username")
	conf.ClientArgs.Password = flag.String("p", "", "password")
	conf.ClientArgs.Proto = flag.String("proto", "udp", "connection protocol")

	flag.Parse()
}

func main() {

	fmt.Println("STUN client SDK")

	client, err := stun.NewClient(*conf.ClientArgs.ServerIP, *conf.ClientArgs.ServerPort, *conf.ClientArgs.Proto)
	if err != nil {
		fmt.Println("could not create client: %s", err)
	}

	// binding request
	err = client.Bind()
	if err != nil {
		fmt.Println("###", err)
	}


	// alloc request
	client.Username = *conf.ClientArgs.Username
	client.Password = *conf.ClientArgs.Password
	client.Lifetime = 500
	client.NoFragment = true
	client.EvenPort = true
	client.ReservToken = make([]byte, 8)
	err = client.Alloc()
	if err != nil {
		fmt.Println("###", err)
	}

	// refresh request
	err = client.Refresh(client.Lifetime)
	if err != nil {
		fmt.Println("###", err)
	}

	// create perm request
	err = client.CreatePerm([]string{"192.168.0.14", "192.168.0.13", "192.168.0.12"})
	if err != nil {
		fmt.Println("###", err)
	}

	// bind channel
	err = client.BindChan(*conf.ClientArgs.PeerIP, *conf.ClientArgs.PeerPort)
	if err != nil {
		fmt.Println("###", err)
	}

	// send data
	err = client.Send(*conf.ClientArgs.PeerIP, *conf.ClientArgs.PeerPort, []byte{'h','e','l','l','o'})
	if err != nil {
		fmt.Println("###", err)
	}

	// receive data
	go func() {
		for {
			_, err := client.Receive(stun.DEFAULT_MTU)
			if err != nil {
				fmt.Println("###", err)
				time.Sleep(time.Second * 60)
			}
		}
	}()

	for {
		time.Sleep(time.Second * 10)
	}

	return
}
