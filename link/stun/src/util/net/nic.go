package net

import (
	"net"
	"fmt"
)

func GetInfFirstIP(inf, relayIP *string, ipv4 bool) error {

	// get first valid IPv4 / IPv6 address of specified interface
	getIP := func(inf string, needIPv4 bool) (addr string, err error) {

		ief, err := net.InterfaceByName(inf)
		if err != nil {
			return "", fmt.Errorf("interface %s: %s", inf, err)
		}

		addrs, err := ief.Addrs()
		if err != nil {
			return "", fmt.Errorf("interface %s: %s", inf, err)
		}

		for _, addr := range addrs {
			if ip := addr.(*net.IPNet).IP.To4(); ip != nil && needIPv4 {
				return ip.String(), nil
			} else if ip == nil && !needIPv4 {
				return addr.(*net.IPNet).IP.To16().String(), nil
			}
		}

		return "", fmt.Errorf("interface %s: no available address", inf)
	}

	// override relay arguments if interface name is specified
	if len(*inf) > 0 {
		var err error
		*relayIP, err = getIP(*inf, ipv4)
		if err != nil {
			return err
		}
	}

	return nil
}
