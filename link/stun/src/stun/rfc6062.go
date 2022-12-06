package stun

import (
	"net"
	"fmt"
	"time"
	. "util/log"
	"crypto/md5"
	"context"
	"sync"
	"encoding/binary"
	"util/dbg"
	"crypto/tls"
	"util/reuse"
	"conf"
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
	TCP_RELAY_READ_SIZE          = 4096 // bytes
)

type connInfo struct {
	// connection ID
	id        uint32

	// peer address
	remote    *address
	// copy of TCP peer data connection maintained by relayserver
	peerConn  net.Conn

	// client control connection source address, a copy of allocation.source
	client    *address

	// copy of TCP client data connection maintained by global tcp pool
	dataConn  net.Conn
	// copy of source address for data connection
	dataAddr  *address

	// creation time of outgoing / incoming TCP connection on relayed address
	creation  time.Time

	// notify relay server to start listening on peer data connection
	connBound chan bool
}

type tcpRelayInfo struct {
	conns  map[uint32]*connInfo

	// cursor pointing to current available connection ID
	cursor uint32

	lck    *sync.Mutex
}

var (
	dataConns = &tcpRelayInfo{
		conns: map[uint32]*connInfo{},
		lck:   &sync.Mutex{},
	}
)

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

	prev := pool.cursor
	for {
		pool.cursor++
		if _, inUse := pool.conns[pool.cursor]; !inUse {
			return pool.cursor, nil
		}
		if pool.cursor == prev {
			return 0, fmt.Errorf("no available CONNECTION-ID")
		}
	}
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

func (this *message) doConnBindRequest(addr *address) (*message, error) {

	// https://datatracker.ietf.org/doc/html/rfc6062#section-5.4
	// validate protocol type of client data connection
	if addr.Proto == NET_UDP {
		return this.newErrorMessage(STUN_ERR_BAD_REQUEST, "protocol mismatch"), nil
	}

	var info *connInfo
	var dataConn net.Conn
	if id, err := this.getAttrConnID(); err != nil {
		return this.newErrorMessage(STUN_ERR_BAD_REQUEST, "missing CONNECTION-ID"), nil
	} else if info = dataConns.get(id); info == nil {
		return this.newErrorMessage(STUN_ERR_BAD_REQUEST, "peer data connection not found"), nil
	} else if addr.Equal(info.client) {
		return this.newErrorMessage(STUN_ERR_BAD_REQUEST, "control connection is not allowed"), nil
	} else if dataConn = tcpConns.get(addr); dataConn == nil {
		return this.newErrorMessage(STUN_ERR_SERVER_ERROR, "client data connection lost"), nil
	}

	// find the allocation of control connection and check credential
	alloc, m := this.generalRequestCheck(info.client)
	if alloc == nil {
		return m, nil
	}

	msg := &message{
		method:    this.method,
		encoding:  STUN_MSG_SUCCESS,
		transactionID: this.transactionID,
	}
	msg.methodName, msg.encodingName = parseMessageType(msg.method, msg.encoding)

	// add integrity attribute
	if err := msg.addIntegrity(alloc.username); err != nil {
		return this.newErrorMessage(STUN_ERR_WRONG_CRED, err.Error()), nil
	}

	// respond connection-bind success to the client on behalf of handleTCP() and start listening
	// on this client raw data connection since handleTCP() only handles stun messages
	Info("[%s][%s] %s", alloc.key, keygen(addr), msg.print4Log())
	dataConn.Write(msg.buffer())

	// save source address and connection before notifying sendToPeerTCP() routine
	info.dataAddr, info.dataConn = addr, dataConn

	// notify relay server to start listening on the peer
	info.connBound <- true

	// this function will block to listen on the client data connection when it returns
	// the connection must be gone
	alloc.server.sendToPeerTCP(info)

	return nil, fmt.Errorf("client data connection closed")
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

func newConnAttemptIndication(id uint32, peer *address) (*message, error) {

	msg := &message{
		method:        STUN_MSG_METHOD_CONN_ATTEMPT,
		encoding:      STUN_MSG_INDICATION,
		transactionID: genTransactionID(),
	}
	msg.methodName, msg.encodingName = parseMessageType(msg.method, msg.encoding)

	// a conn-attempt indication contains connection ID and peer address
	// https://datatracker.ietf.org/doc/html/rfc6062#section-4.4
	msg.length += msg.addAttrConnID(id)
	msg.length += msg.addAttrXorPeerAddr(peer)

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

func (this *message) isConnAttemptIndication() bool {

	return (this.method | this.encoding) == (STUN_MSG_METHOD_CONN_ATTEMPT | STUN_MSG_INDICATION)
}

// -------------------------------------------------------------------------------------------------

// intiate an outgoing connection to the remote peer
func (svr *relayserver) connectToPeerTCP(peer *address) (uint32, error) {

	// concatenate IPv4 or IPv6 relayed transport address string
	relay := &svr.allocRef.relay
	var network, relayAddr, peerAddr string
	if svr.allocRef.ipv4Relay {
		network = "tcp4"
		relayAddr = fmt.Sprintf("%s:%d", relay.IP, relay.Port)
		peerAddr = fmt.Sprintf("%s:%d", peer.IP, peer.Port)
	} else {
		network = "tcp6"
		relayAddr = fmt.Sprintf("[%s]:%d", relay.IP, relay.Port)
		peerAddr = fmt.Sprintf("[%s]:%d", peer.IP, peer.Port)
	}
	laddr, err := net.ResolveTCPAddr(network, relayAddr)
	if err != nil {
		return 0, fmt.Errorf("invalid relayed address: %s", err)
	}

	// an outgoing TCP connection must keep aligned with relayed transport address
	d := net.Dialer{
		Control: reuse.Control,
		LocalAddr: laddr,
		Timeout: time.Second * TCP_RELAY_MAX_CONN_TIMEOUT,
	}

	// start dialing the peer
	conn, err := d.Dial(network, peerAddr)
	if err != nil {
		return 0, fmt.Errorf("connect peer: %s", err)
	}

	// set r/w buffer size
	tcpConn, _ := conn.(*net.TCPConn)
	tcpConn.SetReadBuffer(TCP_SO_RECVBUF_SIZE)
	tcpConn.SetWriteBuffer(TCP_SO_SNDBUF_SIZE)
	tcpConn.SetKeepAlive(true)

	id, err := dataConns.genConnID()
	if err != nil {
		return 0, err
	}

	// spawn a listening routine over peer data connection
	go svr.sendToClientTCP(tcpConn, id)

	return id, nil
}

// wait for incoming connections from remote peers
func (svr *relayserver) recvFromPeerTCP(ech chan error) {

	dummy, _ := svr.conn.(*dummyConn)

	defer svr.wg.Done()
	defer dummy.tcpListener.Close()
	// close all peer data connections
	defer svr.tcpConns.getAll(
		func(c net.Conn) {

			c.SetDeadline(time.Now())
		},
	)

	for {
		tcpConn, err := dummy.tcpListener.AcceptTCP()
		if err != nil {
			ech <- err
			break
		}

		go func(tcpConn *net.TCPConn) {
			rm, _ := net.ResolveTCPAddr(tcpConn.RemoteAddr().Network(), tcpConn.RemoteAddr().String())
			var ip net.IP
			if ip = rm.IP.To4(); ip == nil {
				ip = rm.IP // IPv6
			}

			peer := &address{
				IP:    ip,
				Port:  rm.Port,
				Proto: NET_TCP,
			}

			// check permissions for this peer
			if err := svr.allocRef.checkPerms(peer); err != nil {
				Error("[%s] peer %s is not on perm list", svr.allocRef.key, rm.IP)
				tcpConn.Close()
				return
			}

			// set TCP buffer size
			tcpConn.SetReadBuffer(TCP_SO_RECVBUF_SIZE)
			tcpConn.SetWriteBuffer(TCP_SO_SNDBUF_SIZE)
			tcpConn.SetKeepAlive(true)

			// generate a new connection ID for peer data connection
			id, err := dataConns.genConnID()
			if err != nil {
				Error("[%s] no available ID when receiving new connection from peer %s",
					svr.allocRef.key, peer)
				tcpConn.Close()
				return
			}

			// will wait for conn-bind request and then listen on peer data connection
			go svr.sendToClientTCP(tcpConn, id)

			// send CONNECTION-ATTEMPT indication to client
			msg, _ := newConnAttemptIndication(id, peer)
			if err := sendTo(&svr.allocRef.source, msg.buffer()); err != nil {
				Error("[%s] send conn-attempt: %s, peer=%s", svr.allocRef.key, err, peer)
				tcpConn.Close()
				return
			}
			Info("[%s] %s", svr.allocRef.key, msg.print4Log())
		}(tcpConn)
	}
}

// forward data from peer to client
func (svr *relayserver) sendToClientTCP(peerConn net.Conn, id uint32) {

	rm, _ := net.ResolveTCPAddr(peerConn.RemoteAddr().Network(), peerConn.RemoteAddr().String())

	// must convert to IPv4, sometimes it's in the form of IPv6
	var ip net.IP
	if ip = rm.IP.To4(); ip == nil {
		ip = rm.IP // IPv6
	}

	peer := &address{
		IP:    ip,
		Port:  rm.Port,
		Proto: NET_TCP,
	}

	// save this peer data connection and generate a new CONNECTION-ID
	defer svr.tcpConns.del(peer)
	defer peerConn.Close()
	svr.tcpConns.set(peer, peerConn)

	info := &connInfo{
		id:        id,
		remote:    peer,
		client:    &svr.allocRef.source,
		creation:  time.Now(),
		peerConn:  peerConn,
		connBound: make(chan bool),
	}
	defer dataConns.del(info.id)
	dataConns.set(info.id, info)

	// wait here for CONNECTION-BIND to establish client data connection
	// otherwise we do not read any content in TCP buffer
	ticker := time.NewTicker(time.Second * TCP_RELAY_MAX_CONN_TIMEOUT)
	select {
	case <-ticker.C:
		Warn("[%s] connection bind timeout, id=%d", svr.allocRef.key, info.id)
		return // close this peer connection due to timeout
	case <-info.connBound: break
	}
	Info("[%s] connection bound, id=%d", svr.allocRef.key, info.id)

	// if peer data connection is lost, close client data connection as well
	// following deferred function must be set after CONNECTION-BIND succeeds
	// https://datatracker.ietf.org/doc/html/rfc6062#section-5.5
	defer info.dataConn.SetDeadline(time.Now())

	for {
		peerConn.SetDeadline(time.Now().Add(time.Second * time.Duration(TCP_MAX_TIMEOUT)))

		buf := make([]byte, TCP_RELAY_READ_SIZE)
		// read data and send to client
		if nr, err := peerConn.Read(buf); err != nil {
			Info("[%s] tcp read: fwd to client id=%d: %s", svr.allocRef.key, info.id, err)
			break
		} else if _, err = info.dataConn.Write(buf[:nr]); err != nil {
			Info("[%s] tcp write: fwd to client id=%d: %s", svr.allocRef.key, info.id, err)
			break
		}
	}
}

// forward data from client to peer
func (svr *relayserver) sendToPeerTCP(info *connInfo) {

	defer tcpConns.del(info.dataAddr)
	defer info.dataConn.Close()

	// https://datatracker.ietf.org/doc/html/rfc6062#section-5.5
	// the life cycle for both data connection and peer connection are the same
	defer info.peerConn.SetDeadline(time.Now())

	for {
		info.dataConn.SetDeadline(time.Now().Add(time.Second * time.Duration(TCP_MAX_TIMEOUT)))

		buf := make([]byte, TCP_RELAY_READ_SIZE)
		// read data and send to peer
		if nr, err := info.dataConn.Read(buf); err != nil {
			Info("[%s] tcp read: fwd to peer=%s: %s", svr.allocRef.key, info.remote, err)
			break
		} else if _, err = info.peerConn.Write(buf[:nr]); err != nil {
			Info("[%s] tcp write: fwd to peer=%s: %s", svr.allocRef.key, info.remote, err)
			break
		}
	}
}

func (svr *relayserver) listenTCP(network, addr string) (*dummyConn, error) {

	// TCP relayed address must set port and addr reuse since outgoing connection also require
	// the same local address endpoint
	cfg := net.ListenConfig{
		Control: reuse.Control,
	}

	l, err := cfg.Listen(context.Background(), network, addr)
	if err != nil {
		return nil, fmt.Errorf("listen TCP: %s", err)
	}
	tcp, _ := l.(*net.TCPListener)

	dummy := &dummyConn{
		tcpListener: tcp,
	}

	return dummy, nil
}

// -------------------------------------------------------------------------------------------------

func (cl *stunclient) Connect(ip string, port int) error {

	// peer should be a remote TCP endpoint
	peer := &address{
		IP: net.ParseIP(ip),
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
			// bind a new connection associated with responded connection ID
			if err = cl.bindConn(id); err != nil {
				return fmt.Errorf("bind connection: %s", err)
			}
		}
		break
	}

	return nil
}

func (cl *stunclient) bindConn(id uint32) error {

	for retry := 2; retry > 0; {

		// spawn a new TCP connection to server
		if err := cl.connectTCP2(id, cl.remote.Proto); err != nil {
			cl.dataConnMap.del(id)
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
		if err := transmitTCP(info.dataConn, nil, nil, req.buffer()); err != nil {
			return fmt.Errorf("transmit error: %s", err)
		}

		// get response from server
		rbuf := make([]byte, DEFAULT_MTU)
		if _, err := info.dataConn.Read(rbuf); err != nil {
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

	host := cl.remote.IP.String()
	if cl.remote.IP == nil {
		// connect TURN by hostname
		host = cl.remote.Host
	} else {
		// connect TURN by IP
		if cl.remote.IP.To4() == nil {
			// IPv6
			host = "[" + host + "]"
		}
		cl.remote.Host = "" // clear host
	}
	raddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", host, cl.remote.Port))
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
		config := &tls.Config{ InsecureSkipVerify: false, ServerName: host }
		if !*conf.ClientArgs.VerifyCert {
			config = &tls.Config{ InsecureSkipVerify: true }
		}
		tlsConn := tls.Client(tcpConn, config)
		if err := tlsConn.Handshake(); err != nil {
			return fmt.Errorf("TLS handshake: %s", err)
		}
		cl.dataConns.set(info.remote, tlsConn)
		info.dataConn = tlsConn
	} else {
		cl.dataConns.set(info.remote, tcpConn)
		info.dataConn = tcpConn
	}

	return nil
}

func (cl *stunclient) receiveTCP2(info *connInfo) {

	if info == nil || info.dataConn == nil {
		return
	}

	defer cl.dataConns.del(info.remote)
	defer info.dataConn.Close()
	defer cl.dataConnMap.del(info.id)

	for {
		buf := make([]byte, TCP_RELAY_READ_SIZE)
		nr, err := info.dataConn.Read(buf)
		if err != nil {
			break
		}

		// send data to user's callback function
		if cl.dataBuffer != nil {
			// this channel will block if client does not listen on the data connection
			cl.dataBuffer <- buf[:nr]

			// receive peer data as-is
			if cl.DebugOn {
				str := fmt.Sprintf("========== server(%s) > client(%s) ==========\n",
					cl.remote, info.dataConn.LocalAddr())
				str += fmt.Sprintf("client data connection, length=%d bytes\n", nr)
				str += fmt.Sprintf("  %s", dbg.DumpMem(buf[:nr], 0))
				fmt.Println(str)
			}
		}
	}

	fmt.Printf("connection closed, id=%d\n", info.id)
}

func (cl *stunclient) receiveLoopTCP(cb func([]byte, error)int) error {

	st := 0

	for {
		// read buffer from data connections
		buf := <-cl.dataBuffer

		if buf == nil || len(buf) == 0 {
			st = cb(nil, fmt.Errorf("empty data"))
		} else {
			st = cb(buf, nil)
		}

		if st != 0 {
			break
		}
	}

	return nil
}

func (cl *stunclient) onReceiveConnAttempt(msg *message) error {

	id, err := msg.getAttrConnID()
	if err != nil {
		return fmt.Errorf("missing connection id in CONNECTION-ATTEMPT")
	} else if peer, err := msg.getAttrXorPeerAddress(); err != nil {
		return fmt.Errorf("missing peer address in CONNECTION-ATTEMPT")
	} else {
		peer.Proto = NET_TCP // TCP relay type
		cl.dataConnMap.set(id, &connInfo{ id: id, remote: peer })
	}

	// bind incoming connections
	if err := cl.bindConn(id); err != nil {
		return fmt.Errorf("bind connection: %s", err)
	}

	return nil
}
