package stun

import (
	"net"
	"fmt"
	"time"
	. "util/log"
	"crypto/md5"
	"golang.org/x/sys/unix"
	"context"
	"syscall"
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

func newConnectRequest(username, password, realm, nonce string, peer *address) (*message, error) {

	msg := &message{
		method:        STUN_MSG_METHOD_CONNECT,
		encoding:      STUN_MSG_REQUEST,
		transactionID: genTransactionID(),
	}
	msg.methodName, msg.encodingName = parseMessageType(msg.method, msg.encoding)

	// add credential attributes
	msg.length += msg.addAttrUsername(username)
	msg.length += msg.addAttrRealm(realm)
	msg.length += msg.addAttrNonce(nonce)

	// add xor peer address
	msg.length += msg.addAttrXorPeerAddr(peer)

	// make sure MESSAGE-INTEGRITY is the last attribute
	key := md5.Sum([]byte(username + ":" + realm + ":" + password))
	msg.length += msg.addAttrMsgIntegrity(string(key[0:16]))

	return msg, nil
}

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

	// TCP relayed address must set port and addr reuse since outgoing connection also require
	// the same local address endpoint
	cfg := net.ListenConfig{
		Control: func(net, loc string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			})
		},
	}

	l, err := cfg.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen TCP: %s", err)
	}
	tcp, _ := l.(*net.TCPListener)

	dummy := &dummyConn{
		tcpListener: tcp,
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

// -------------------------------------------------------------------------------------------------

func (cl *stunclient) Connect(ip string, port int) error {

	// peer should be a remote TCP endpoint
	peer := &address{
		IP: net.ParseIP(ip).To4(),
		Port: port,
		Proto: NET_TCP,
	}

	for retry := 2; retry > 0; {

		// rfc-6062: create a new TCP connect request over control connection
		req, _ := newConnectRequest(cl.Username, cl.Password, cl.realm, cl.nonce, peer)
		if cl.DebugOn { req.print(fmt.Sprintf("client > server(%s)", cl.remote)) }
		Info("client > server(%s): %s", cl.remote, req.print4Log())

		// send request to server
		buf, err := cl.transmitMessage(req)
		if err != nil {
			return fmt.Errorf("connect request: %s", err)
		}

		// get response from server
		resp, err := getMessage(buf)
		if err != nil {
			return fmt.Errorf("connect response: %s", err)
		}
		if cl.DebugOn { resp.print(fmt.Sprintf("server(%s) > client", cl.remote)) }
		Info("server(%s) > client: %s", cl.remote, resp.print4Log())

		// handle error code
		code, errStr, err := resp.getAttrErrorCode()
		if err == nil {
			switch code {
			case STUN_ERR_STALE_NONCE:
				nonce, err := resp.getAttrNonce()
				if err != nil {
					return fmt.Errorf("get NONCE: %s", err)
				}
				cl.nonce = nonce // refresh nonce

				retry--
				continue
			default:
				return fmt.Errorf("server returned error: %d:%s", code, errStr)
			}
		}
		break
	}

	return nil
}
