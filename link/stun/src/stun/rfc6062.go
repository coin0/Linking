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
	"sync"
	"sync/atomic"
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
	STUN_ERR_CONN_ALREADY_EXIST   = 446
	STUN_ERR_CONN_TIMEOUT_OR_FAIL = 447
)

const (
	TCP_RELAY_MAX_CONN_TIMEOUT   = 30 // seconds
)

type connInfo struct {
	// connection ID
	id        uint32

	// peer address
	remote    *address

	// creation time of outgoing / incoming TCP connection on relayed address
	creation  time.Time

	// copy of TCP connection
	conn      net.Conn
}

type tcpRelayInfo struct {
	conns  map[uint32]*connInfo

	// cursor pointing to current available connection ID
	cursor uint32

	lck    *sync.Mutex
}

// -------------------------------------------------------------------------------------------------

func (pool *tcpRelayInfo) get(id uint32) *connInfo {

	pool.lck.Lock()
	defer pool.lck.Unlock()

	if val, ok := pool.conns[id]; !ok {
		return nil
	} else {
		return val
	}
}

func (pool *tcpRelayInfo) set(id uint32, info *connInfo) {

	pool.lck.Lock()
	defer pool.lck.Unlock()

	pool.conns[id] = info
}

func (pool *tcpRelayInfo) del(id uint32) {

	pool.lck.Lock()
	defer pool.lck.Unlock()

	delete(pool.conns, id)
}

func (pool *tcpRelayInfo) nextID() uint32 {

	return atomic.AddUint32(&pool.cursor, 1) - 1
}

// -------------------------------------------------------------------------------------------------

func (this *message) doConnectRequest(alloc *allocation) (*message, error) {

	msg := &message{
		method:        this.method,
		encoding:      STUN_MSG_SUCCESS,
		transactionID: this.transactionID,
	}
	msg.methodName, msg.encodingName = parseMessageType(msg.method, msg.encoding)

	// get peer address
	addr, err := this.getAttrXorPeerAddress()
	addr.Proto = NET_TCP
	if err != nil {
		return this.newErrorMessage(STUN_ERR_BAD_REQUEST, "invalid CONNECT request: " + err.Error()), nil
	}

	// check existence of peer address
	if alloc.server.tcpConns.get(addr) != nil {
		return this.newErrorMessage(STUN_ERR_CONN_ALREADY_EXIST, "connection already exists"), nil
	}

	// initiate an outgoing TCP connection to peer
	// https://datatracker.ietf.org/doc/html/rfc6062#section-5.2
	err = alloc.server.connectToPeerTCP(addr)
	if err != nil {
		return this.newErrorMessage(STUN_ERR_CONN_TIMEOUT_OR_FAIL, "connection failed: " + err.Error()), nil
	}

	return msg, nil
}

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

func (svr *relayserver) genConnID() (id uint32, err error) {

	const maxRetry = 40
	for i := 0; i < maxRetry; i++ {
		id = svr.tcpConnInfo.nextID()
		if info := svr.tcpConnInfo.get(id); info != nil {
			continue
		}
		if i == maxRetry - 1 {
			return 0, fmt.Errorf("no available CONNECTION-ID")
		}
	}

	return
}

func (svr *relayserver) sendToPeerTCP(addr *address, data []byte) {

	// TODO
}

// intiate an outgoing connection to the remote peer
func (svr *relayserver) connectToPeerTCP(peer *address) error {

	relay := &svr.allocRef.relay
	laddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", relay.IP, relay.Port))
	if err != nil {
		return fmt.Errorf("invalid relayed address: %s", err)
	}

	// an outgoing TCP connection must keep aligned with relayed transport address
	d := net.Dialer{
		Control: func(net, loc string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			})
		},
		LocalAddr: laddr,
		Timeout: time.Second * TCP_RELAY_MAX_CONN_TIMEOUT,
	}

	// start dialing the peer
	conn, err := d.Dial("tcp", fmt.Sprintf("%s:%d", peer.IP, peer.Port))
	if err != nil {
		return fmt.Errorf("connect peer: %s", err)
	}

	// set r/w buffer size
	tcpConn, _ := conn.(*net.TCPConn)
	tcpConn.SetReadBuffer(TCP_SO_RECVBUF_SIZE)
	tcpConn.SetWriteBuffer(TCP_SO_SNDBUF_SIZE)

	// spawn a listening routine over peer data connection
	go func(conn net.Conn, svr *relayserver) {
		// save this peer data connection and generate a new CONNECTION-ID
		defer svr.tcpConns.del(peer)
		defer conn.Close()
		svr.tcpConns.set(peer, conn)
		id, err := svr.genConnID()
		if err != nil {
			Error("[%s] no available ID when connecting peer %s", keygen(&svr.allocRef.source), peer)
		}
		relay := &connInfo{
			id:       id,
			remote:   peer,
			creation: time.Now(),
			conn:     conn,
		}
		defer svr.tcpConnInfo.del(relay.id)
		svr.tcpConnInfo.set(relay.id, relay)

		// TODO wait here for CONNECTION-BIND to establish client data connection
		// otherwise we do not read any content in TCP buffer

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
	}(conn, svr)

	return nil
}

// wait for incoming connections from remote peers
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

			// save metadata for peer data connection
			id, err := svr.genConnID()
			if err != nil {
				Error("[%s] no available ID when receiving new connection from peer %s",
					keygen(&svr.allocRef.source), addr)
			}
			relay := &connInfo{
				id:       id,
				remote:   addr,
				creation: time.Now(),
				conn:     conn,
			}
			defer svr.tcpConnInfo.del(relay.id)
			svr.tcpConnInfo.set(relay.id, relay)

			// TODO send CONNECTION-ATTEMPT indication and wait for
			// client to bind this connection by CONNECTION-BIND

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
