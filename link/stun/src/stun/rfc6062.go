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
	"encoding/binary"
	"util/dbg"
	"crypto/tls"
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

	// copy of TCP peer data connection maintained by relayserver
	peerConn    net.Conn

	// copy of TCP client data connection maintained by client tcp pool
	clientConn  net.Conn
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

func (pool *tcpRelayInfo) genConnID() (uint32, error) {

	pool.lck.Lock()
	defer pool.lck.Unlock()

	// search available IDs
	for prev := pool.cursor - 1; pool.cursor != prev; pool.cursor++ {
		if _, ok := pool.conns[pool.cursor]; ok {
			continue
		} else {
			pool.cursor++
			return pool.cursor, nil
		}
	}

	return 0, fmt.Errorf("no available CONNECTION-ID")
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
	if err != nil {
		return this.newErrorMessage(STUN_ERR_BAD_REQUEST, "invalid CONNECT request: " + err.Error()), nil
	}
	addr.Proto = NET_TCP

	// check existence of peer address
	if alloc.server.tcpConns.get(addr) != nil {
		return this.newErrorMessage(STUN_ERR_CONN_ALREADY_EXIST, "connection already exists"), nil
	}

	// initiate an outgoing TCP connection to peer
	// https://datatracker.ietf.org/doc/html/rfc6062#section-5.2
	id, err := alloc.server.connectToPeerTCP(addr)
	if err != nil {
		return this.newErrorMessage(STUN_ERR_CONN_TIMEOUT_OR_FAIL, "connection failed: " + err.Error()), nil
	}

	// add connection ID attribute
	msg.length += msg.addAttrConnID(id)

	// add integrity attribute
	if err := msg.addIntegrity(alloc.username); err != nil {
		return this.newErrorMessage(STUN_ERR_WRONG_CRED, err.Error()), nil
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

func newConnBindRequest(username, password, realm, nonce string, id uint32) (*message, error) {

	msg := &message{
		method:        STUN_MSG_METHOD_CONN_BIND,
		encoding:      STUN_MSG_REQUEST,
		transactionID: genTransactionID(),
	}
	msg.methodName, msg.encodingName = parseMessageType(msg.method, msg.encoding)

	// add credential attributes
	msg.length += msg.addAttrUsername(username)
	msg.length += msg.addAttrRealm(realm)
	msg.length += msg.addAttrNonce(nonce)

	// add connection ID attribute
	msg.length += msg.addAttrConnID(id)

	// make sure MESSAGE-INTEGRITY is the last attribute
	key := md5.Sum([]byte(username + ":" + realm + ":" + password))
	msg.length += msg.addAttrMsgIntegrity(string(key[0:16]))

	return msg, nil
}

func (this *message) addAttrConnID(id uint32) int {

	attr := &attribute{
		typevalue:  STUN_ATTR_CONNECTION_ID,
		typename:   parseAttributeType(STUN_ATTR_CONNECTION_ID),
		length:     4,
		value:      []byte{0, 0, 0, 0},
	}
	binary.BigEndian.PutUint32(attr.value[0:], id)

	this.attributes = append(this.attributes, attr)
	return 8 // 4 + 4
}

func (this *message) getAttrConnID() (uint32, error) {

	attr := this.findAttr(STUN_ATTR_CONNECTION_ID)
	if attr == nil {
		return 0, fmt.Errorf("not found")
	}

	if len(attr.value) != 4 {
		return 0, fmt.Errorf("invalid CONNECTION-ID attribute")
	}

	return binary.BigEndian.Uint32(attr.value[0:]), nil
}

// -------------------------------------------------------------------------------------------------

func (svr *relayserver) sendToPeerTCP(addr *address, data []byte) {

	// TODO
}

// intiate an outgoing connection to the remote peer
func (svr *relayserver) connectToPeerTCP(peer *address) (uint32, error) {

	relay := &svr.allocRef.relay
	laddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", relay.IP, relay.Port))
	if err != nil {
		return 0, fmt.Errorf("invalid relayed address: %s", err)
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
		return 0, fmt.Errorf("connect peer: %s", err)
	}

	// set r/w buffer size
	tcpConn, _ := conn.(*net.TCPConn)
	tcpConn.SetReadBuffer(TCP_SO_RECVBUF_SIZE)
	tcpConn.SetWriteBuffer(TCP_SO_SNDBUF_SIZE)

	id, err := dataConns.genConnID()
	if err != nil {
		return 0, err
	}

	// spawn a listening routine over peer data connection
	go func(conn net.Conn, svr *relayserver, id uint32) {
		// save this peer data connection and generate a new CONNECTION-ID
		defer svr.tcpConns.del(peer)
		defer conn.Close()
		svr.tcpConns.set(peer, conn)
		relay := &connInfo{
			id:       id,
			remote:   peer,
			creation: time.Now(),
			peerConn: conn,
		}
		defer dataConns.del(relay.id)
		dataConns.set(relay.id, relay)

		// TODO wait here for CONNECTION-BIND to establish client data connection
		// otherwise we do not read any content in TCP buffer
		// select case ticker, connBound chan bool

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
	}(conn, svr, id)

	return id, nil
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

		// set TCP buffer size
		tcpConn.SetReadBuffer(TCP_SO_RECVBUF_SIZE)
		tcpConn.SetWriteBuffer(TCP_SO_SNDBUF_SIZE)

		// generate a new connection ID for peer data connection
		id, err := dataConns.genConnID()
		if err != nil {
			Error("[%s] no available ID when receiving new connection from peer %s",
				keygen(&svr.allocRef.source), tcpConn.RemoteAddr())
		}

		// start a incoming TCP connection and
		go func(conn *net.TCPConn, svr *relayserver, id uint32) {
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
			relay := &connInfo{
				id:       id,
				remote:   addr,
				creation: time.Now(),
				peerConn: conn,
			}
			defer dataConns.del(relay.id)
			dataConns.set(relay.id, relay)

			// TODO send CONNECTION-ATTEMPT indication and wait for
			// client to bind this connection by CONNECTION-BIND
			// select case ticker, connBound chan bool

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
		}(tcpConn, svr, id)
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
				return fmt.Errorf("server returned error: %d: %s", code, errStr)
			}
		} else {
			id, err := resp.getAttrConnID()
			if err != nil {
				return fmt.Errorf("success response: %s", err)
			}
			cl.dataConnMap.set(id, &connInfo{ id: id, remote: peer })
		}
		break
	}

	return nil
}

func (cl *stunclient) BindConn(id uint32) error {

	for retry := 2; retry > 0; {

		// spawn a new TCP connection to server
		if err := cl.connectTCP2(id, cl.remote.Proto); err != nil {
			return fmt.Errorf("connect TCP: %s", err)
		}

		req, _ := newConnBindRequest(cl.Username, cl.Password, cl.realm, cl.nonce, id)
		if cl.DebugOn { req.print(fmt.Sprintf("client > server(%s)", cl.remote)) }
		Info("client > server(%s): %s", cl.remote, req.print4Log())

		// send request to server and wait for response
		var info *connInfo
		// we should start receive routine whether request succeeds or not
		defer func() { go cl.receiveTCP2(info) }()
		if info = cl.dataConnMap.get(id); info == nil {
			return fmt.Errorf("could not find this connection")
		}
		if err := transmitTCP(info.clientConn, nil, nil, req.buffer()); err != nil {
			return fmt.Errorf("transmit error: %s", err)
		}

		// get response from server
		rbuf := make([]byte, DEFAULT_MTU)
		if _, err := info.clientConn.Read(rbuf); err != nil {
			return fmt.Errorf("read from TCP: %s", err)
		}
		var resp *message
		if buf, _, err := decodeTCP(rbuf); err != nil {
			return fmt.Errorf("decode message: %s", err)
		} else {
			if resp, err = getMessage(buf); err != nil {
				return fmt.Errorf("connection-bind response: %s", err)
			}
		}
		if cl.DebugOn { resp.print(fmt.Sprintf("server(%s) > client", cl.remote)) }
		Info("server(%s) > client: %s", cl.remote, resp.print4Log())
		if resp.isErrorResponse() {
			return fmt.Errorf("connection-bind responds with error")
		}


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
				return fmt.Errorf("server returned error: %d: %s", code, errStr)
			}
		}
		break
	}

	return nil
}

func (cl *stunclient) connectTCP2(connID uint32, connType byte) error {

	// get context of client data connection and set TCP connection once dial() succeeds
	info := cl.dataConnMap.get(connID)
	if info == nil {
		return fmt.Errorf("could not get connection")
	}

	raddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", cl.remote.IP, cl.remote.Port))
	if err != nil {
		return fmt.Errorf("resolve TCP: %s", err)
	}

	tcpConn, err := net.DialTCP("tcp", nil, raddr)
	if err != nil {
		return fmt.Errorf("dial TCP: %s", err)
	}

	tcpConn.SetNoDelay(true)
	tcpConn.SetKeepAlive(true)
	tcpConn.SetReadBuffer(TCP_SO_RECVBUF_SIZE)
	tcpConn.SetWriteBuffer(TCP_SO_SNDBUF_SIZE)

	// save client data connection in the map and correlate its connection ID
	if connType == NET_TLS {
		tlsConn := tls.Client(tcpConn, &tls.Config{ InsecureSkipVerify: true })
		if err := tlsConn.Handshake(); err != nil {
			return fmt.Errorf("TLS handshake: %s", err)
		}
		cl.dataConns.set(info.remote, tlsConn)
		info.clientConn = tlsConn
	} else {
		cl.dataConns.set(info.remote, tcpConn)
		info.clientConn = tcpConn
	}

	return nil
}

func (cl *stunclient) receiveTCP2(info *connInfo) {

	if info == nil || info.clientConn == nil {
		return
	}

	defer cl.dataConns.del(info.remote)
	defer info.clientConn.Close()
	defer cl.dataConnMap.del(info.id)

	for {
		buf := make([]byte, TCP_SO_RECVBUF_SIZE)
		nr, err := info.clientConn.Read(buf)
		if err != nil {
			break
		}

		// receive peer data as-is
		if cl.DebugOn {
			str := fmt.Sprintf("========== server(%s) > client ==========\n", cl.remote)
			str  = fmt.Sprintf("client data connection, length=%d bytes\n", nr)
			str  = fmt.Sprintf("  %s", dbg.DumpMem(buf[:nr], 0))
			fmt.Println(str)
		}
	}

	fmt.Println("connection closed, id: ", info.id)
}
