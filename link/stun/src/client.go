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
		fmt.Println("###", err)
	}


	// alloc request
	client.Username = "root"
	client.Password = "aaa"
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
	err = client.CreatePerm([]string{"127.0.0.1", "192.168.0.14", "192.168.0.13", "192.168.0.12"})
	if err != nil {
		fmt.Println("###", err)
	}

	return
}
