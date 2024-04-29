package stun

import (
	"net"
	"fmt"
	"sync"
	"time"
	"conf"
	"crypto/tls"
	. "util/log"
	"context"
	"util/reuse"
	"runtime"
	"strconv"
)

const (
	PROTO_NUM_TCP     = 6   // RFC6062: TCP relay
	PROTO_NUM_UDP     = 17
)

const (
	NET_TBD = 0x0
	NET_UDP = 0x3
	NET_TCP = 0x4
	NET_TLS = 0x5
)

const (
	ADDR_FAMILY_IPV4 = 0x1
	ADDR_FAMILY_IPV6 = 0x2
)

// see definition https://www.ietf.org/rfc/rfc5128.txt
const (
	NAT_TYPE_UNKNOWN                = 0x00
	NAT_TYPE_ENDPOINT_INDEP_MAP     = 0x01
	NAT_TYPE_ADDR_DEP_MAP           = 0x02
	NAT_TYPE_ADDR_AND_PORT_DEP_MAP  = 0x03
	NAT_TYPE_ENDPOINT_INDEP_FILT    = 0x10
	NAT_TYPE_ADDR_DEP_FILT          = 0x20
	NAT_TYPE_ADDR_AND_PORT_DEP_FILT = 0x30
	NAT_TYPE_NOT_NATED              = 0xff
)

const (
	TCP_MAX_TIMEOUT    = 300
	// tcp buffer size in user space
	TCP_MAX_BUF_SIZE   = 1024 * 1024 * 3 // 3MB

	// socket buffer size
	TCP_SO_RECVBUF_SIZE  = 87380 // bytes
	TCP_SO_SNDBUF_SIZE   = 65535 // bytes
	UDP_SO_RECVBUF_SIZE  = 1024 * 1024 * 2 // 2MB
	UDP_SO_SNDBUF_SIZE   = 1024 * 1024 * 2 // 2MB

	DEFAULT_MTU        = 1500
)

type address struct {
	Host    string
	IP      net.IP
	Port    int
	Proto   byte
}

type tcpPool struct {
	conns   map[allockey]net.Conn
	lck     *sync.Mutex
}

// a dummy connection to hook tlsConn.Read() in order to retain the
// first STUN packet for TURN TCP
type dummyConn struct {
	tcpConn     *net.TCPConn
	tcpListener *net.TCPListener
	readBuf     []byte
	firstPkt    bool
}

var (
	tcpConns = &tcpPool{
		conns: map[allockey]net.Conn{},
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

func (pool *tcpPool) getAll(cb func(net.Conn)) {

	pool.lck.Lock()
	defer pool.lck.Unlock()
	for _, c := range pool.conns {
		cb(c)
	}
}

// -------------------------------------------------------------------------------------------------

func newDummyConn(tcpConn *net.TCPConn) *dummyConn {

	return &dummyConn{
		tcpConn: tcpConn,
		readBuf: []byte{},
		firstPkt: true,
	}
}

func (c *dummyConn) Read(b []byte) (n int, err error) {

	// hook tlsConn.Read() and get first request from stun client
	n, err = c.tcpConn.Read(b)
	if c.firstPkt && err == nil {
		c.readBuf = append(c.readBuf, b[:n]...)
		c.firstPkt = false
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

func ListenTCP(network, ip string, port int) error {

	var tlsconf *tls.Config
	if len(conf.Args.Certs) > 0 {
		tlsconf = &tls.Config{
			Certificates: conf.Args.Certs,
			MinVersion:   tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,

				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,

				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			},
		}
	}

	tcp, err := net.ResolveTCPAddr(network, ip + ":" + strconv.Itoa(port))
	if err != nil {
		return fmt.Errorf("resolve TCP: %s", err)
	}
	l, err := net.ListenTCP(network, tcp)
	if err != nil {
		return fmt.Errorf("listen TCP: %s", err)
	}
	Info("listening on %s://%s:%s", network, ip, strconv.Itoa(port))
	defer l.Close()

	for {
		tcpConn, err := l.AcceptTCP()
		if err != nil {
			return fmt.Errorf("TCP accept: %s", err)
		}

		handleTCP(tcpConn, tlsconf)
	}
}

func ListenUDP(network, ip string, port int) error {

	n := runtime.NumCPU() / 3
	if n < 1 {
		n = 1
	}
	sem := make(chan bool, n)
	Info("initialize %d threads listening on %s://%s:%d", n, network, ip, port)

	for {
		sem <- true
		handleUDP(network, ip, port, sem)
	}

	return nil
}

func handleUDP(network, ip string, port int, sem chan bool) {

	go func() error {

		defer func() { <- sem }()

		udp, err := net.ResolveUDPAddr(network, ip + ":" + strconv.Itoa(port))
		if err != nil {
			return fmt.Errorf("resolve UDP: %s", err)
		}
		cfg := net.ListenConfig{
			Control: reuse.Control,
		}
		l, err := cfg.ListenPacket(context.Background(), network, udp.String())
		if err != nil {
			return fmt.Errorf("listen UDP: %s", err)
		}
		udpConn, _ := l.(*net.UDPConn)

		defer udpConn.Close()

		// set UDP socket options
		udpConn.SetReadBuffer(UDP_SO_RECVBUF_SIZE)
		udpConn.SetWriteBuffer(UDP_SO_SNDBUF_SIZE)

		buf := make([]byte, DEFAULT_MTU)
		for {
			nr, rm, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return fmt.Errorf("read UDP: %s", err)
			}

			func(req []byte, r *net.UDPAddr) {

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

				resp := process(req, addr, udpConn)
				if resp == nil {
					return
				}

				_, err = udpConn.WriteToUDP(resp, r)
				if err != nil {
					return
				}
			}(buf[:nr], rm)
		}

		return nil
	}()
}

func handleTCP(tcpConn *net.TCPConn, tlsConf *tls.Config) {

	go func() {

		// set TCP socket options
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetReadBuffer(TCP_SO_RECVBUF_SIZE)
		tcpConn.SetWriteBuffer(TCP_SO_SNDBUF_SIZE)

		// demux TCP TLS and retain data read by tls.handshake()
		conn, addr := demuxTCP(tcpConn, tlsConf)

		defer tcpConns.del(addr)
		defer conn.Close()
		tcpConns.set(addr, conn)

		var (
			// make a buffer to store rest of data after being processed
			rest = make([]byte, 0, DEFAULT_MTU * 2) // use capacity for better 'append' performance
			// a buffer to store decoded one stun msg / channel data
			buf  = make([]byte, DEFAULT_MTU)
			// we need retain parsing error for logging
			decErr     error
			// separate complete stun/channeldata and rest data in two slices
			one, more  []byte
		)
		for {
			conn.SetDeadline(time.Now().Add(time.Second * time.Duration(TCP_MAX_TIMEOUT)))

			nr, err := conn.Read(buf)
			if err != nil {
				Info("[%s] handleTCP: read: %s", keygen(addr), err)
				return
			}

			if len(rest) + nr > DEFAULT_MTU * 2 {
				Error("[%s] handleTCP: could not decode TCP stream: %s", keygen(addr), decErr)
				return
			}
			rest = append(rest, buf[:nr]...)

			for {
				one, more, decErr = decodeTCP(rest)
				if decErr != nil { break }

				// copy decoded data and update rest data slice
				copy(buf, one)
				copy(rest, more)
				rest = rest[:len(more)]

				if resp := process(buf[:len(one)], addr, conn); resp != nil {
					if _, err = conn.Write(resp); err != nil {
						Info("[%s] handleTCP: write: %s", keygen(addr), err)
						return
					}
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

	// when there is no cert configured
	if tlsConf == nil {
		conn, addr.Proto = tcpConn, NET_TCP
		Info("[%s] tcp: accept new plain TCP connection", keygen(addr))
		return
	}

	// probe TLS ClientHello
	dummy := newDummyConn(tcpConn)
	tlsConn := tls.Server(dummy, tlsConf)

	if err := tlsConn.Handshake(); err != nil {
		// unable to parse ClientHello, we think this is a plain TCP connection
		conn, addr.Proto = tcpConn, NET_TCP
		Info("[%s] tcp: accept new TCP connection, TLS handshake: %s", keygen(addr), err)

		// this is confusing but we have to save connection here because CONNECTION-BIND request
		// must be sent over a new TCP connection apart from control connection, when server
		// handles CONNECTION-BIND it requires peer address from *connInfo
		tcpConns.set(addr, conn)

		// we must retain the data read by tls.Handshake() then
		// process this request as the initial allocation
		// possible valid requests are ALLOCATE and CONNECTION-BIND
		if one, _, err := decodeTCP(dummy.readBuf); err == nil {
			if resp := process(one, addr, conn); resp != nil {
				conn.Write(resp)
			}
		}
	} else {
		conn, addr.Proto = tlsConn, NET_TLS
		Info("[%s] tcp: accept new TLS connection", keygen(addr))
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

func process(req []byte, addr *address, conn net.Conn) []byte {

	if len(req) == 0 {
		return nil
	}

	// receive channel data from client
	if alloc, ok := allocPool.find(keygen(addr)); ok {
		alloc.clientbw.In(len(req))
	}

	switch req[0] & MSG_TYPE_MASK {
	case MSG_TYPE_STUN_MSG:
		// handle stun messages
		return processStunMessage(req, addr, conn)
	case MSG_TYPE_CHANNELDATA:
		// handle channelData
		processChannelData(req, addr)
	}

	return nil
}

func processStunMessage(req []byte, addr *address, conn net.Conn) []byte {

	// dbg.PrintMem(req, 8)

	msg, err := getMessage(req)
	if err != nil {
		return nil
	}

	// msg.print("request") // request

	if !msg.isIndication() {
		Info("[%s] %s", keygen(addr), msg.print4Log())
	}

	msg, err = msg.process(addr, conn)
	if err != nil {
		return nil
	}

	if msg == nil {
		return nil // no response
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

func closeTCP(r *address) {

	conn := tcpConns.get(r)
	if conn == nil {
		return
	}
	conn.Close()
}

func closeConn(addr *address) {

	switch addr.Proto {
	case NET_TCP, NET_TLS:
		closeTCP(addr)
	}
}

func (this *message) process(r *address, conn net.Conn) (*message, error) {

	// discard messages with incorrect fingerprints
	if err := this.checkFingerprint(); err != nil {
		Error("[%s] stun message fingerprint error", keygen(r))
		return nil, err
	}

	// special handlers
	switch this.method | this.encoding {
	case STUN_MSG_METHOD_ALLOCATE | STUN_MSG_REQUEST: return this.doAllocationRequest(r, conn)
	case STUN_MSG_METHOD_BINDING | STUN_MSG_REQUEST:  return this.doBindingRequest(r, conn)
	case STUN_MSG_METHOD_CONN_BIND | STUN_MSG_REQUEST: return this.doConnBindRequest(r)
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
		case STUN_MSG_METHOD_CONNECT:      return this.doConnectRequest(alloc)
		}

		return this.newErrorMessage(STUN_ERR_BAD_REQUEST, "not supported"), nil

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
	case STUN_MSG_METHOD_CONNECT: m = "connect"
	case STUN_MSG_METHOD_CONN_BIND: m = "connection_bind"
	case STUN_MSG_METHOD_CONN_ATTEMPT: m = "connection_attempt"
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
	case STUN_ATTR_CONNECTION_ID: return "CONNECTION-ID"
	case STUN_ATTR_REQUESTED_ADDRESS_FAMILY: return "REQUESTED-ADDRESS-FAMILY"
	case STUN_ATTR_CHANGE_REQUEST: return "CHANGE-REQUEST"
	case STUN_ATTR_RESPONSE_PORT: return "RESPONSE-PORT"
	case STUN_ATTR_PADDING: return "PADDING"
	case STUN_ATTR_CACHE_TIMEOUT: return "CACHE-TIMEOUT"
	case STUN_ATTR_RESPONSE_ORIGIN: return "RESPONSE-ORIGIN"
	case STUN_ATTR_OTHER_ADDRESS: return "OTHER-ADDRESS"
	}
	return "RESERVED"
}

func parseTransportType(b byte) string {

	switch b {
	case PROTO_NUM_TCP: return "tcp"
	case PROTO_NUM_UDP: return "udp"
	}
	return fmt.Sprintf("unknown proto %d", b)
}

func parseNetType(b byte) string {

	switch b {
	case NET_UDP: return "udp"
	case NET_TCP: return "tcp"
	case NET_TLS: return "tls"
	}
	return fmt.Sprintf("unknown net type %d", b)
}

func parseAddrFamilyType(b byte) string {

	switch b {
	case ADDR_FAMILY_IPV4: return "ipv4"
	case ADDR_FAMILY_IPV6: return "ipv6"
	}
	return fmt.Sprintf("unknown addr family %d", b)
}

func parseTransportNetType(b byte) byte {

	switch b {
	case PROTO_NUM_TCP: return NET_TCP
	case PROTO_NUM_UDP: return NET_UDP
	}
	return NET_TBD
}

func parseNATType(b byte) string {

	switch b {
	case NAT_TYPE_UNKNOWN: return "UNKNOWN"
	case NAT_TYPE_ENDPOINT_INDEP_MAP: return "Endpoint-Independent Mapping"
	case NAT_TYPE_ADDR_DEP_MAP: return "Address-Dependent Mapping"
	case NAT_TYPE_ADDR_AND_PORT_DEP_MAP: return "Address and Port-Dependent Mapping"
	case NAT_TYPE_ENDPOINT_INDEP_FILT: return "Endpoint-Independent Filtering"
	case NAT_TYPE_ADDR_DEP_FILT: return "Address-Dependent Filtering"
	case NAT_TYPE_ADDR_AND_PORT_DEP_FILT: return "Address and Port-Dependent Filtering"
	case NAT_TYPE_NOT_NATED: return "Not NATed"
	}
	return "UNKNOWN"
}

// -------------------------------------------------------------------------------------------------

func (addr *address) String() string {

	var url string
	if len(addr.Host) > 0 {
		url = addr.Host
	} else {
		if addr.IP.To4() != nil {
			url = addr.IP.String()
		} else {
			url = "[" + addr.IP.String() + "]"
		}
	}

	if addr.Proto == NET_TBD {
		return fmt.Sprintf("%s:%d", url, addr.Port)
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

func (addr *address) Equal(other *address) bool {

	return (addr.IP.Equal(other.IP) &&
		addr.Port == other.Port &&
		addr.Proto == other.Proto)
}

func (addr *address) ParseNetAddr(a net.Addr) error {

	host, port, err := net.SplitHostPort(a.String())
	if err != nil {
		return fmt.Errorf("address: %s", err)
	}

	addr.Host = host
	addr.IP = net.ParseIP(host)
	addr.Port, err = strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("port: %s", err)
	}

	switch a.Network() {
		case "tcp": addr.Proto = NET_TCP
		case "udp": addr.Proto = NET_UDP
		default: addr.Proto = NET_TBD
	}

	return nil
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
