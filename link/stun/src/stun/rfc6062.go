package stun

import (
	"net"
	"fmt"
	"time"
)

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

	// TODO
}

func (svr *relayserver) recvFromPeerTCP(ech chan error) {

	dummy, _ := svr.conn.(*dummyConn)

	defer svr.wg.Done()
	defer dummy.tcpListener.Close()

	for {
		tcpConn, err := dummy.tcpListener.AcceptTCP()
		if err != nil {
			ech <- err
			break
		}

		// TODO received a new TCP connection from peer
		// TODO check permissions for this peer

		// start a incoming TCP connection and
		go func(conn *net.TCPConn, svr *relayserver) {
			rm, _ := net.ResolveTCPAddr(conn.RemoteAddr().Network(), conn.RemoteAddr().String())

			// must convert to IPv4, sometimes it's in the form of IPv6
			var ip net.IP
			if ip = rm.IP.To4(); ip == nil {
				ip = rm.IP // IPv6
			}

			addr := &address{
				IP:   ip,
				Port: rm.Port,
			}

			defer svr.tcpConns.del(addr)
			defer conn.Close()
			svr.tcpConns.set(addr, conn)

			for {
				conn.SetDeadline(time.Now().Add(time.Second * time.Duration(TCP_MAX_TIMEOUT)))

				buf := make([]byte, DEFAULT_MTU)
				_, err := conn.Read(buf)
				if err != nil {
					// TODO relayed connection disconnects, close the connection to client as well
				}

				// TODO send to client
				//svr.sendToClientTCP()
			}
		}(tcpConn, svr)
	}
}

func (svr *relayserver) listenTCP(addr string) (*dummyConn, error) {

	tcp, err := net.ResolveTCPAddr("tcp4", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve TCP: %s", err)
	}

	l, err := net.ListenTCP("tcp", tcp)
	if err != nil {
		return nil, fmt.Errorf("listen TCP: %s", err)
	}

	dummy := &dummyConn{
		tcpListener: l,
	}

	return dummy, nil
}

func (svr *relayserver) sendToClientTCP() {

	// TODO
}

func (svr *relayserver) clear() {

	switch svr.allocRef.transport {
	case PROTO_NUM_TCP: svr.clearRelayTCP()
	case PROTO_NUM_UDP: // nothing to do
	}
}

func (svr *relayserver) clearRelayTCP() {

	// TODO close all connections with the client
	// TODO close all connections associated with the relay
}
