package stun

import (
	"fmt"
)

const (
	STUN_ATTR_REQUESTED_ADDRESS_FAMILY  = 0x0017
)

const (
	STUN_ERR_ADDR_FAMILY_NOT_SUPPORTED  = 440
	STUN_ERR_PEER_ADDR_FAMILY_MISMATCH  = 443
)

// -------------------------------------------------------------------------------------------------

func (this *message) addAttrReqAddrFamily(ipv4 bool) int {

//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |         Type                  |            Length             |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     Family    |            Reserved                           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	attr := &attribute{
		typevalue:  STUN_ATTR_REQUESTED_ADDRESS_FAMILY,
		typename:   parseAttributeType(STUN_ATTR_REQUESTED_ADDRESS_FAMILY),
		length:     4,
		value:      []byte{ 0, 0, 0, 0 },
	}

	if ipv4 {
		attr.value[0] = 0x01
	} else {
		attr.value[0] = 0x02
	}

	this.attributes = append(this.attributes, attr)
	return 8 // 4 + 4
}

// return if requested address family is a IPv4 address
func (this *message) getAttrReqAddrFamily() (bool, error) {

	attr := this.findAttr(STUN_ATTR_REQUESTED_ADDRESS_FAMILY)
	if attr == nil {
		// https://datatracker.ietf.org/doc/html/rfc6156#section-4.2
		// If the REQUESTED-ADDRESS-FAMILY attribute is absent, the server MUST
		// allocate an IPv4-relayed transport address for the TURN client
		return true, fmt.Errorf("IPv4 by default")
	}

	if attr.value[0] == 0x01 {
		return true, nil
	}
	return false, nil
}

// -------------------------------------------------------------------------------------------------

func (this *message) checkReqAddrFamily(alloc *allocation) (int, error) {

	switch this.method {
	case STUN_MSG_METHOD_REFRESH:
		// check refresh https://datatracker.ietf.org/doc/html/rfc6156#section-5.2
		if ipv4, err := this.getAttrReqAddrFamily(); err == nil && ipv4 != alloc.ipv4Relay {
			return STUN_ERR_PEER_ADDR_FAMILY_MISMATCH, fmt.Errorf("alloc address family mismatch")
		}
	case STUN_MSG_METHOD_CREATE_PERM:
		// check permission https://datatracker.ietf.org/doc/html/rfc6156#section-6.2
		addrs, err := this.getAttrXorPeerAddresses()
		if err != nil {
			// do nothing, let doCreatePerm() to validate the msg
			return 0, nil
		}
		for _, addr := range addrs {
			if (addr.IP.To4() != nil) != alloc.ipv4Relay {
				return STUN_ERR_PEER_ADDR_FAMILY_MISMATCH, fmt.Errorf("peer address family mismatch")
			}
		}
	case STUN_MSG_METHOD_CHANNEL_BIND:
		// check channelbind https://datatracker.ietf.org/doc/html/rfc6156#section-7.2
		fallthrough
	case STUN_MSG_METHOD_CONNECT:
		// check connect (no specification)
		addr, err := this.getAttrXorPeerAddress();
		if err != nil {
			// do nothing
			return 0, nil
		}
		if (addr.IP.To4() != nil) != alloc.ipv4Relay {
			return STUN_ERR_PEER_ADDR_FAMILY_MISMATCH, fmt.Errorf("peer address family mismatch")
		}
	}

	return 0, nil
}
