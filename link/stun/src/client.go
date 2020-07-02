package main

import(
	"fmt"
	"stun"
)

func main() {

	fmt.Println("STUN client SDK")

	client, err := stun.NewClient("127.0.0.1", 3478, "udp")
	if err != nil {
		fmt.Println("could not create client: %s", err)
	}

	// binding request
	err = client.Bind()
	if err != nil {
		fmt.Println(err)
	}


	// alloc request
	client.Username = "root"
	client.Password = "aaa"
	client.Lifetime = 500
	client.NoFragment = true
	client.EvenPort = true
	client.ReservToken = make([]byte, 8)
	client.Alloc()

	return
}
