package stun

import (
	"net"
	"fmt"
	"sync"
	"time"
	"conf"
	"crypto/tls"
	. "util/log"
)

const (
	PROTO_NUM_TCP     = 6   // RFC6062: TCP relay
	PROTO_NUM_UDP     = 17
)

const (
	NET_UDP = 0x0
	NET_TCP = 0x1
	NET_TLS = 0x2
)

const (
	TCP_MAX_TIMEOUT    = 300
	// tcp buffer size in user space
	TCP_MAX_BUF_SIZE   = 1024 * 1024 * 3 // 3MB

	// socket buffer size
	TCP_SO_RECVBUF_SIZE  = 1024 * 1024 * 1 // 1MB
	TCP_SO_SNDBUF_SIZE   = 1024 * 1024 * 1 // 1MB
	UDP_SO_RECVBUF_SIZE  = 1024 * 1024 * 4 // 4MB
	UDP_SO_SNDBUF_SIZE   = 1024 * 1024 * 4 // 4MB

	DEFAULT_MTU        = 1500
)

type address struct {
	Host    string
	IP      net.IP
	Port    int
	Proto   byte
}

type tcpPool struct {
	conns   map[string]net.Conn
	lck     *sync.Mutex
}

// a dummy connection to hook tlsConn.Read() in order to retain the
// first STUN packet for TURN TCP
type dummyConn struct {
	tcpConn     *net.TCPConn
	tcpListener *net.TCPListener
	readBuf     []byte
}

var (
	udpConn  *net.UDPConn
	tcpConns = &tcpPool{
		conns: map[string]net.Conn{},
		lck:   &sync.Mutex{},
	}
)

// -------------------------------------------------------------------------------------------------

func AllocTable() string {

	return allocPool.printTable()
}

// -------------------------------------------------------------------------------------------------

func (pool *tcpPool) get(addr *address) net.Conn {

	pool.lck.Lock()
	defer pool.lck.Unlock()
	if val, ok := pool.conns[keygen(addr)]; !ok {
		return nil
	} else {
		return val
	}
}

func (pool *tcpPool) set(addr *address, conn net.Conn) {

	pool.lck.Lock()
	defer pool.lck.Unlock()
	pool.conns[keygen(addr)] = conn
}

func (pool *tcpPool) del(addr *address) {

	pool.lck.Lock()
	defer pool.lck.Unlock()
	delete(pool.conns, keygen(addr))
}

// -------------------------------------------------------------------------------------------------

func newDummyConn(tcpConn *net.TCPConn) *dummyConn {

	return &dummyConn{
		tcpConn: tcpConn,
		readBuf: []byte{},
	}
}

func (c *dummyConn) Read(b []byte) (n int, err error) {

	// hook tlsConn.Read() and get first request from stun client
	n, err = c.tcpConn.Read(b)
	if err == nil {
		c.readBuf = append(c.readBuf, b[:n]...)
	}
	return
}

func (c *dummyConn) Write(b []byte) (n int, err error) {

	return c.tcpConn.Write(b)
}

func (c *dummyConn) Close() error {

	return c.tcpConn.Close()
}

func (c *dummyConn) LocalAddr() net.Addr {

	return c.tcpConn.LocalAddr()
}

func (c *dummyConn) RemoteAddr() net.Addr {

	return c.tcpConn.RemoteAddr()
}

func (c *dummyConn) SetDeadline(t time.Time) error {

	if c.tcpListener != nil {
		return c.tcpListener.SetDeadline(t)
	}

	if c.tcpConn != nil {
		return c.tcpConn.SetDeadline(t)
	}

	return nil
}

func (c *dummyConn) SetReadDeadline(t time.Time) error {

	return c.tcpConn.SetReadDeadline(t)
}

func (c *dummyConn) SetWriteDeadline(t time.Time) error {

	return c.tcpConn.SetWriteDeadline(t)
}

// -------------------------------------------------------------------------------------------------

func ListenTCP(ip, port string) error {

	// load cert and key files from filesystem
	cert, err := tls.LoadX509KeyPair(*conf.Args.Cert, *conf.Args.Key)
	if err != nil {
		return fmt.Errorf("wrong cert or key file path")
	}
	tlsconf := &tls.Config{ Certificates: []tls.Certificate{cert} }

	tcp, err := net.ResolveTCPAddr("tcp4", ip + ":" + port)
	if err != nil {
		return fmt.Errorf("resolve TCP: %s", err)
	}
	l, err := net.ListenTCP("tcp", tcp)
	if err != nil {
		return fmt.Errorf("listen TCP: %s", err)
	}
	defer l.Close()

	for {
		tcpConn, err := l.AcceptTCP()
		if err != nil {
			return fmt.Errorf("TCP accept: %s", err)
		}

		handleTCP(tcpConn, tlsconf)
	}
}

func ListenUDP(ip, port string) error {

	udp, err := net.ResolveUDPAddr("udp", ip + ":" + port)
	if err != nil {
		return fmt.Errorf("resolve UDP: %s", err)
	}
	udpConn, err = net.ListenUDP("udp", udp)
	if err != nil {
		return fmt.Errorf("listen UDP: %s", err)
	}
	defer udpConn.Close()

	// set UDP socket options
	udpConn.SetReadBuffer(UDP_SO_RECVBUF_SIZE)
	udpConn.SetWriteBuffer(UDP_SO_SNDBUF_SIZE)

	for {
		buf := make([]byte, DEFAULT_MTU)
		nr, rm, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			return fmt.Errorf("read UDP: %s", err)
		}

		go func(req []byte, r *net.UDPAddr) {

			// must convert to IPv4, sometimes it's in the form of IPv6
			var ip net.IP
			if ip = r.IP.To4(); ip == nil {
				ip = r.IP // IPv6
			}

			addr := &address{
				IP:   ip,
				Port: r.Port,
				Proto: NET_UDP,
			}

			resp := process(req, addr)
			if resp == nil {
				return
			}

			_, err = udpConn.WriteToUDP(resp, r)
			if err != nil {
				return
			}
		}(buf[:nr], rm)
	}
}

func handleTCP(tcpConn *net.TCPConn, tlsConf *tls.Config) {

	go func() {

		// set TCP socket options
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetReadBuffer(TCP_SO_RECVBUF_SIZE)
		tcpConn.SetWriteBuffer(TCP_SO_SNDBUF_SIZE)

		rest := make([]byte, 0)

		// demux TCP TLS and retain data read by tls.handshake()
		conn, addr := demuxTCP(tcpConn, tlsConf)

		defer tcpConns.del(addr)
		defer conn.Close()
		tcpConns.set(addr, conn)

		for {
			conn.SetDeadline(time.Now().Add(time.Second * time.Duration(TCP_MAX_TIMEOUT)))

			buf := make([]byte, DEFAULT_MTU)
			nr, err := conn.Read(buf)
			if err != nil {
				return
			}

			rest = append(rest, buf[:nr]...)
			for {
				one := []byte{}
				one, rest, err = decodeTCP(rest)
				if err != nil {
					if len(rest) > TCP_MAX_BUF_SIZE {
						rest = []byte{}
					}
					break
				}

				resp := process(one, addr)
				if resp != nil {
					conn.Write(resp)
				}
			}
		}
	}()
}

func demuxTCP(tcpConn *net.TCPConn, tlsConf *tls.Config) (conn net.Conn, addr *address) {

	rm, _ := net.ResolveTCPAddr(tcpConn.RemoteAddr().Network(), tcpConn.RemoteAddr().String())

	// must convert to IPv4, sometimes it's in the form of IPv6
	var ip net.IP
	if ip = rm.IP.To4(); ip == nil {
		ip = rm.IP // IPv6
	}

	addr = &address{
		IP:    ip,
		Port:  rm.Port,
	}

	// set TCP timeout before TLS handshake
	tcpConn.SetDeadline(time.Now().Add(time.Second * time.Duration(TCP_MAX_TIMEOUT)))

	// probe TLS ClientHello
	dummy := newDummyConn(tcpConn)
	tlsConn := tls.Server(dummy, tlsConf)

	if err := tlsConn.Handshake(); err != nil {
		// unable to parse ClientHello, we think this is a plain TCP connection
		conn, addr.Proto = tcpConn, NET_TCP

		// we must retain the data read by tls.Handshake() then
		// process this request as the initial allocation
		if one, _, err := decodeTCP(dummy.readBuf); err == nil {
			if resp := process(one, addr); resp != nil {
				conn.Write(resp)
			}
		}
	} else {
		conn, addr.Proto = tlsConn, NET_TLS
	}

	return
}

func decodeTCP(req []byte) ([]byte, []byte, error) {

	if len(req) == 0 {
		return nil, req, fmt.Errorf("empty request")
	}

	// split first stun message or channel data from TCP stream

	switch req[0] & MSG_TYPE_MASK {
	case MSG_TYPE_STUN_MSG:
		// get first stun message
		buf, err := checkMessage(req)
		if err != nil {
			return nil, req, err
		}

		return buf, req[len(buf):], nil

	case MSG_TYPE_CHANNELDATA:
		// get first channel data
		buf, err := checkChannelData(req)
		if err != nil {
			return nil, req, err
		}

		// there may be paddings in channeldata according to https://tools.ietf.org/html/rfc5766#section-11.5
		roundup := 0
		if len(buf) % 4 != 0 {
			roundup = 4 - len(buf) % 4
		}

		// if incoming channel data does not contain round up bytes, return and wait for next part
		if len(buf) + roundup > len(req) {
			return nil, req, fmt.Errorf("invalid channel data: no round up")
		}

		return buf, req[len(buf)+roundup:], nil
	}

	return nil, []byte{}, fmt.Errorf("bad message type")
}

func process(req []byte, addr *address) []byte {

	if len(req) == 0 {
		return nil
	}

	switch req[0] & MSG_TYPE_MASK {
	case MSG_TYPE_STUN_MSG:
		// handle stun messages
		return processStunMessage(req, addr)
	case MSG_TYPE_CHANNELDATA:
		// handle channelData
		processChannelData(req, addr)
	}

	return nil
}

func processStunMessage(req []byte, addr *address) []byte {

	// dbg.PrintMem(req, 8)

	msg, err := getMessage(req)
	if err != nil {
		return nil
	}

	// msg.print("request") // request

	Info("[%s] %s", keygen(addr), msg.print4Log())

	msg, err = msg.process(addr)
	if err != nil {
		return nil
	}

	if msg == nil {
		return nil // no response
	}

	if msg.isIndication() {
		return nil
	}

	// msg.print("response") // response

	Info("[%s] %s", keygen(addr), msg.print4Log())

	resp := msg.buffer()
	return resp
}

func processChannelData(req []byte, addr *address) {

	data, err := getChannelData(req)
	if err != nil {
		return
	}

//	data.print("channel-data")

	data.transport(addr)
}

// -------------------------------------------------------------------------------------------------

func sendUDP(addr *address, data []byte) error {

	r := &net.UDPAddr{
		IP:   addr.IP,
		Port: addr.Port,
	}

	if udpConn == nil {
		return fmt.Errorf("connection not ready")
	}

	_, err := udpConn.WriteToUDP(data, r)
	if err != nil {
		return err
	}

	return nil
}

func sendTCP(r *address, data []byte) error {

	conn := tcpConns.get(r)
	if conn == nil {
		return fmt.Errorf("tcp connection not found")
	}

	_, err := conn.Write(data)
	if err != nil {
		return err
	}

	return nil
}

// for TCP relay, this function is only to send data over control connection
func sendTo(addr *address, data []byte) error {

	switch addr.Proto {
	case NET_UDP:
		return sendUDP(addr, data)
	case NET_TCP, NET_TLS:
		// channel data over tcp must roundup to 32 bits
		roundup := 0
		if len(data) % 4 != 0 {
			roundup = 4 - len(data) % 4
		}
		pad := make([]byte, roundup)
		data = append(data, pad...)

		return sendTCP(addr, data)
	}
	return nil
}

func (this *message) process(r *address) (*message, error) {

	// special handlers
	switch this.method | this.encoding {
	case STUN_MSG_METHOD_ALLOCATE | STUN_MSG_REQUEST: return this.doAllocationRequest(r)
	case STUN_MSG_METHOD_BINDING | STUN_MSG_REQUEST:  return this.doBindingRequest(r)
	}

	// general check
	alloc, msg := this.generalRequestCheck(r)
	if alloc == nil {
		return msg, nil
	}

	if this.isRequest() {
		switch this.method {
		case STUN_MSG_METHOD_REFRESH:      return this.doRefreshRequest(alloc)
		case STUN_MSG_METHOD_CREATE_PERM:  return this.doCreatePermRequest(alloc)
		case STUN_MSG_METHOD_CHANNEL_BIND: return this.doChanBindRequest(alloc)
		}

		return this.newErrorMessage(STUN_ERR_BAD_REQUEST, "not support"), nil

	} else if this.isIndication() {
		switch this.method {
		case STUN_MSG_METHOD_SEND: this.doSendIndication(alloc)
		}

		// for an indication, drop silently
		return nil, nil
	}

	return nil, nil // drop
}

func parseMessageType(method, encoding uint16) (m string, e string) {

	switch (method) {
	case STUN_MSG_METHOD_BINDING: m = "binding"
	case STUN_MSG_METHOD_ALLOCATE: m = "allocation"
	case STUN_MSG_METHOD_REFRESH: m = "refresh"
	case STUN_MSG_METHOD_SEND: m = "send"
	case STUN_MSG_METHOD_DATA: m = "data"
	case STUN_MSG_METHOD_CREATE_PERM: m = "create_permission"
	case STUN_MSG_METHOD_CHANNEL_BIND: m = "channel_bind"
	default: m = "unknown"
	}

	switch (encoding) {
	case STUN_MSG_REQUEST: e = "request"
	case STUN_MSG_INDICATION: e = "indication"
	case STUN_MSG_SUCCESS: e = "success_response"
	case STUN_MSG_ERROR: e = "error_response"
	}

	return
}

func parseAttributeType(db uint16) string {

	switch (db) {
	case STUN_ATTR_MAPPED_ADDR: return "MAPPED-ADDRESS"
	case STUN_ATTR_USERNAME: return "USERNAME"
	case STUN_ATTR_MESSAGE_INTEGRITY: return "MESSAGE-INTEGRITY"
	case STUN_ATTR_ERROR_CODE: return "ERROR-CODE"
	case STUN_ATTR_UNKNOWN_ATTR: return "UNKNOWN-ATTRIBUTES"
	case STUN_ATTR_REALM: return "REALM"
	case STUN_ATTR_NONCE: return "NONCE"
	case STUN_ATTR_XOR_MAPPED_ADDR: return "XOR-MAPPED-ADDRESS"
	case STUN_ATTR_SOFTWARE: return "SOFTWARE"
	case STUN_ATTR_ALTERNATE_SERVER: return "ALTERNATE-SERVER"
	case STUN_ATTR_FINGERPRINT: return "FINGERPRINT"
	case STUN_ATTR_CHANNEL_NUMBER: return "CHANNEL-NUMBER"
	case STUN_ATTR_LIFETIME: return "LIFETIME"
	case STUN_ATTR_XOR_PEER_ADDR: return "XOR-PEER-ADDRESS"
	case STUN_ATTR_DATA: return "DATA"
	case STUN_ATTR_XOR_RELAYED_ADDR: return "XOR-RELAYED-ADDRESS"
	case STUN_ATTR_EVENT_PORT: return "EVEN-PORT"
	case STUN_ATTR_REQUESTED_TRAN: return "REQUESTED-TRANSPORT"
	case STUN_ATTR_DONT_FRAGMENT: return "DONT-FRAGMENT"
	case STUN_ATTR_RESERVATION_TOKEN: return "RESERVATION-TOKEN"
	case STUN_ATTR_MESSAGE_INTEGRITY_SHA256: return "MESSAGE-INTEGRITY-SHA256"
	case STUN_ATTR_PASSWORD_ALGORITHM: return "PASSWORD-ALGORITHM"
	case STUN_ATTR_USERHASH: return "USERHASH"
	case STUN_ATTR_PASSWORD_ALGORITHMS: return "PASSWORD-ALGORITHMS"
	case STUN_ATTR_ALTERNATE_DOMAIN: return "ALTERNATE-DOMAIN"
	}
	return "RESERVED"
}

// -------------------------------------------------------------------------------------------------

func (addr *address) String() string {

	var url string
	if len(addr.Host) > 0 {
		url = addr.Host
	} else {
		url = addr.IP.String()
	}

	return fmt.Sprintf("%s://%s:%d",
		func(p byte) string {
			switch p {
			case NET_TCP: return "tcp"
			case NET_UDP: return "udp"
			case NET_TLS: return "tls"
			default: return "unknown"
			}
		}(addr.Proto), url, addr.Port)
}

// -------------------------------------------------------------------------------------------------

// TransmitTCP() and TransmitUDP() are used by stun clients

func transmitTCP(conn net.Conn, r, l *address, buf []byte) error {

	// send message to target server
	_, err := conn.Write(buf)
	if err != nil {
		return fmt.Errorf("write TCP: %s", err)
	}

	return nil
}

func transmitUDP(conn *net.UDPConn, r, l *address, buf []byte) error {

	// send message to target server
	_, err := conn.Write(buf)
	if err != nil {
		return fmt.Errorf("write UDP: %s", err)
	}

	return nil
}
