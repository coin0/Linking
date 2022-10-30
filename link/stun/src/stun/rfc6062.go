package stun

const (
	STUN_MSG_METHOD_CONNECT      = 0x000a
	STUN_MSG_METHOD_CONN_BIND    = 0x000b
	STUN_MSG_METHOD_CONN_ATTEMPT = 0x000c
)

const (
	STUN_ATTR_CONNECTION_ID      = 0x002a
)

const (
	STUN_ERR_CONN_ALREADY_EXIST  = 446
	STUN_ERR_CONN_TIMEOUT        = 447
	STUN_ERR_CONN_FAILURE        = 447
)

// -------------------------------------------------------------------------------------------------

func (svr *relayserver) sendToPeerTCP(addr *address, data []byte) {

}

func (svr *relayserver) recvFromPeerTCP(ech chan error) {

}
