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

	client.Bind()
	
	return
}
