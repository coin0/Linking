package stun

import (
	"fmt"
	"net"
	"math/rand"
	"encoding/binary"
	. "util/log"
	"time"
	"sync"
	"conf"
	"net/http"
	"strconv"
	"encoding/base64"
	"io"
)

const (
	// recommended ranges of 32768-49151
	STUN_NAT_PROBE_MIN_PORT    = 32768
	STUN_NAT_PROBE_MAX_PORT    = 49151
)

// https://datatracker.ietf.org/doc/html/rfc5780#section-9
const (
	STUN_ATTR_CHANGE_REQUEST   = 0x0003
	STUN_ATTR_RESPONSE_PORT    = 0x0027

	STUN_ATTR_PADDING          = 0x0026
	STUN_ATTR_CACHE_TIMEOUT    = 0x8027
	STUN_ATTR_RESPONSE_ORIGIN  = 0x802b
	STUN_ATTR_OTHER_ADDRESS    = 0x802c
)

// -------------------------------------------------------------------------------------------------

func selectPort() int {

	// https://datatracker.ietf.org/doc/html/rfc5780#section-4.1
	total := STUN_NAT_PROBE_MAX_PORT - STUN_NAT_PROBE_MIN_PORT + 1
	r := rand.New(rand.NewSource(time.Now().Unix()))
	return STUN_NAT_PROBE_MIN_PORT + int(r.Uint32()) % total
}

// -------------------------------------------------------------------------------------------------

// these utility functions implement http IPC support that follows rfc5780 requiring
// stun server to have two IP addresses for stun client detect NAT behaviors

// requestBindingResponse() will be called on-demand when CHANGE-REQUEST IP address
// flag is present, a HTTP request should be made to alternate service IP given by
// startup arguments to respond to the incoming binding request
func requestBindingResponse(tranID []byte, srflx *address, conn net.Conn, srcPort, dstPort int) {

	go func() {
		if *conf.Args.OtherIP == "" || *conf.Args.OtherHttp == 0 {
			return
		}

		idStr := base64.URLEncoding.EncodeToString(tranID)
		tr := &http.Transport{
			MaxIdleConns: 10,
			IdleConnTimeout: 10 * time.Second,
		}
		client := &http.Client{
			Transport: tr,
			Timeout: 10 * time.Second,
		}

		url := "http://" + *conf.Args.OtherIP + ":" + strconv.Itoa(*conf.Args.OtherHttp)
		url += "/stun/response"
		url += "?id=" + idStr + "&xip=" + srflx.IP.String() + "&xport=" + strconv.Itoa(srflx.Port)
		url += "&origip=" + *conf.Args.OtherIP + "&origport=" + strconv.Itoa(srcPort)
		url += "&respport=" + strconv.Itoa(dstPort)

		respondError := func(e error) {
			// reply an explicit error for this stun binding request
			msg := &message{}
			msg.method = STUN_MSG_METHOD_BINDING
			msg.transactionID = append(msg.transactionID, tranID...)
			errMsg := msg.newErrorMessage(STUN_ERR_SERVER_ERROR, "invalid alternate address or port")

			udpConn, _ := conn.(*net.UDPConn)
			udpConn.WriteToUDP(errMsg.buffer(), &net.UDPAddr{ IP: srflx.IP, Port: srflx.Port })

			// rfc5780: only UDP is supported for filtering probe
			srflx.Proto = NET_UDP
			Error("[%s] request bind response: %s, err: %s", keygen(srflx), url, e)
		}

		// request alternate server
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			respondError(err)
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			respondError(err)
			return
		}
		// return binding error response if http status code is not 200
		if resp.StatusCode != http.StatusOK {
			var b []byte
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				respondError(err)
				return
			}
			respondError(fmt.Errorf("bad request: %s", string(b)))
			return
		}

		Info("[%s] request bind response: %s, succeeded", keygen(srflx), url)
	}()
}

// SendBindingResponse() needs be public so that restful service may call this funcion
// this function will send stun binding response on behalf of original service IP address or
// reply from a different udp port when change-port flag is present in CHANGE-REQUEST
func SendBindingResponse(tranID []byte, xorIPStr, origIPStr string, xorPort, origPort, respPort int) error {

	if len(tranID) != 12 {
		return fmt.Errorf("invalid transaction ID length")
	}
	xorIP := net.ParseIP(xorIPStr)
	if xorIP == nil {
		return fmt.Errorf("invalid srflx IP address")
	}
	origIP := net.ParseIP(origIPStr)
	if origIP == nil {
		return fmt.Errorf("invalid response origin IP address")
	}

	found := false
	udpConns.getAll(
		func(conn net.Conn) bool{
			// get one available UDPConn with the listening port we want to respond from
			if _, p, err := net.SplitHostPort(conn.LocalAddr().String()); err != nil {
				return true // continue
			} else {
				port, _ := strconv.Atoi(p)
				if origPort != port {
					return true // continue
				}
			}
			found = true

			// use response port as destination port if required by binding request
			dstPort := xorPort
			if respPort > 0 {
				dstPort = respPort
			}
			dstIP := xorIP

			// build a stun binding response and send it from origPort
			msg := &message{}
			msg.method = STUN_MSG_METHOD_BINDING
			msg.transactionID = append(msg.transactionID, tranID...)
			msg.encoding = STUN_MSG_SUCCESS
			msg.methodName, msg.encodingName = parseMessageType(msg.method, msg.encoding)

			// client reflexive address
			srflxAddr := &address{ IP: xorIP,  Port: xorPort, Proto: NET_UDP }
			len := msg.addAttrXorMappedAddr(srflxAddr)

			// server response origin
			origAddr := &address{ IP: origIP, Port: origPort, Proto: NET_UDP }
			len += msg.addAttrResponseOrigin(origAddr)

			// alternate server address
			if otherIP := net.ParseIP(*conf.Args.OtherIP); otherIP != nil {
				// always return alternate port number that differs from the port sending response
				otherPort := *conf.Args.OtherPort
				if origPort == *conf.Args.OtherPort {
					otherPort = *conf.Args.OtherPort2
				}
				len += msg.addAttrOtherAddress(&address{ IP: otherIP, Port: otherPort})
			}
			msg.length = len

			Info("[%s] %s", keygen(srflxAddr), msg.print4Log())

			// send binding response
			udpConn, _ := conn.(*net.UDPConn)
			udpConn.WriteToUDP(msg.buffer(), &net.UDPAddr{ IP: dstIP, Port: dstPort })

			return false // break
		},
	)

	if !found {
		return fmt.Errorf("no such listening port: %d", origPort)
	}
	return nil
}

// -------------------------------------------------------------------------------------------------

func (this *message) getAttrChangeRequest() (changePort, changeIP bool, err error) {

	attr := this.findAttr(STUN_ATTR_CHANGE_REQUEST)
	if attr == nil {
		return false, false, fmt.Errorf("CHANGE-REQUEST not found")
	}

	if len(attr.value) != 4 {
		return false, false, fmt.Errorf("invalid CHANGE-REQUEST length")
	}

	return uint8(attr.value[3]) & 0x02 > 0, uint8(attr.value[3]) & 0x04 > 0, nil
}

func (this *message) getAttrResponseOrigin() (addr *address, err error) {

	attr := this.findAttr(STUN_ATTR_RESPONSE_ORIGIN)
	if attr == nil {
		return nil, fmt.Errorf("RESPONSE-ORIGIN not found")
	}

	return decodeAddr(attr)
}

func (this *message) getAttrResponsePort() (port uint16, err error) {

	attr := this.findAttr(STUN_ATTR_RESPONSE_PORT)
	if attr == nil {
		return 0, fmt.Errorf("RESPONSE-PORT not found")
	}

	// RESPONSE-PORT is a 16-bit unsigned integer in network byte order
	// followed by 2 bytes of padding.  Allowable values of RESPONSE-PORT
	// are 0-65536

	if len(attr.value) != 4 {
		return 0, fmt.Errorf("invalid RESPONSE-PORT length")
	}

	return binary.BigEndian.Uint16(attr.value[0:]), nil
}

func (this *message) getAttrOtherAddress() (addr *address, err error) {

	attr := this.findAttr(STUN_ATTR_OTHER_ADDRESS)
	if attr == nil {
		return nil, fmt.Errorf("OTHER-ADDRESS not found")
	}

	return decodeAddr(attr)
}

func (this *message) getAttrPadding() (bytes int, err error) {

	attr := this.findAttr(STUN_ATTR_PADDING)
	if attr == nil {
		return 0, fmt.Errorf("PADDING not found")
	}

	return attr.length, nil
}

func (this *message) addAttrChangeRequest(changePort, changeIP bool) int {

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 A B 0|
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

	attr := &attribute{
		typevalue: STUN_ATTR_CHANGE_REQUEST,
		typename:  parseAttributeType(STUN_ATTR_CHANGE_REQUEST),
		length:    4,
	}

	attr.value = make([]byte, 4)
	if changePort {
		attr.value[3] |= 0x2
	}
	if changeIP {
		attr.value[3] |= 0x4
	}

	this.attributes = append(this.attributes, attr)
	return 4 + len(attr.value)
}

func (this *message) addAttrResponseOrigin(addr *address) int {

	return this.addAttrAddr(addr, STUN_ATTR_RESPONSE_ORIGIN)
}

func (this *message) addAttrResponsePort(port uint16) int {

	attr := &attribute{
		typevalue: STUN_ATTR_RESPONSE_PORT,
		typename:  parseAttributeType(STUN_ATTR_RESPONSE_PORT),
		length:    4,
	}

	attr.value = make([]byte, 4)
	binary.BigEndian.PutUint16(attr.value[0:], port)

	this.attributes = append(this.attributes, attr)
	return 4 + 4
}

func (this *message) addAttrOtherAddress(addr *address) int {

	return this.addAttrAddr(addr, STUN_ATTR_OTHER_ADDRESS)
}

func (this *message) addAttrPadding(bytes int) int {

	attr := &attribute{
		typevalue: STUN_ATTR_PADDING,
		typename:  parseAttributeType(STUN_ATTR_RESPONSE_PORT),
		length:    bytes,
	}

	// stun paddings alignment
	total := attr.length
	if total % 4 != 0 {
		total += 4 - total % 4
	}
	attr.value = make([]byte, total)

	this.attributes = append(this.attributes, attr)
	return 4 + len(attr.value)
}

// -------------------------------------------------------------------------------------------------

func (cl *stunclient) pickUDPAddress() *net.UDPAddr {

	return &net.UDPAddr{
		IP: nil,
		Port: selectPort(),
	}
}

func (cl *stunclient) pickTCPAddress() *net.TCPAddr {

	return &net.TCPAddr{
		IP: nil,
		Port: selectPort(),
	}
}

// this interface mostly follows the flow defined in the standard document
// https://datatracker.ietf.org/doc/html/rfc5780#section-4.3
func (cl *stunclient) ProbeNatType() error {

	cl.natType = NAT_TYPE_UNKNOWN

	// determining NAT Mapping Behavior
	if err := cl.probeMapping(); err != nil {
		return err
	}

	if err := cl.probeFiltering(); err != nil {
		return err
	}

	return nil
}

// https://datatracker.ietf.org/doc/html/rfc5780#section-4.6
func (cl *stunclient) ProbeNatLifetime() error {

	curr := 10 // seconds

	const INIT_MAX = -1
	const PROBE_LIMIT = 320 // seconds
	const PROBE_MULTI = 2 // multiplier of probe interval
	min := 0
	max := INIT_MAX

	for {
		if cl.DebugOn {
			fmt.Printf("\n*** probing binding lifetime threshold %d sec ***\n\n", curr)
			Info("*** probing binding lifetime threshold %d sec ***", curr)
		}

		// we must exit this test immediately when receiving an
		// explicit bad request error code from stun server
		if ok, err := cl.probeLifetime(curr); err != nil  {
			return err
		} else {
			if ok {
				min = curr
			} else {
				max = curr
			}
		}

		if max == INIT_MAX {
			if curr * PROBE_MULTI > PROBE_LIMIT { break }
			// probe lifetime uplimit
			curr *= PROBE_MULTI
		} else {
			if curr == (min + max) / 2 { break }
			// binary search for lifetime boundary
			curr = (min + max) / 2
		}
	}

	cl.natLifetime = uint(curr)
	return nil
}

func (cl *stunclient) probeMapping() (err error) {

	// test I: UDP connectivity test

	// a copy from Bind() request
	msg, _ := newBindingRequest()
	if cl.DebugOn { msg.print(fmt.Sprintf("client > server(%s)", cl.remote)) }
	Info("client > server(%s): %s", cl.remote, msg.print4Log())
	resp, err := cl.transmitMessage(msg)
	if err != nil {
		return fmt.Errorf("binding request: %s", err)
	}

	msg, err = getMessage(resp)
	if err != nil {
		return fmt.Errorf("binding response: %s", err)
	}
	if cl.DebugOn { msg.print(fmt.Sprintf("server(%s) > client", cl.remote)) }
	Info("server(%s) > client: %s", cl.remote, msg.print4Log())

	// save srflx IP address
	cl.srflx, err = msg.getAttrXorMappedAddr()
	if err != nil {
		return fmt.Errorf("binding response: srflx: %s", err)
	}
	cl.srflx.Proto = cl.remote.Proto
	// end of copy

	// examine reflexive address
	if cl.local.Equal(cl.srflx) {
		cl.natType |= NAT_TYPE_NOT_NATED
		return nil
	}

	// get the other server address
	altAddr, err := msg.getAttrOtherAddress()
	if err != nil {
		return fmt.Errorf("get other address: %s", err)
	}

	// test II: request alternate address with primary port

	msg, _ = newBindingRequest()
	altPort := altAddr.Port        // save alternate port
	altAddr.Port = cl.remote.Port  // use primary port
	if cl.DebugOn { msg.print(fmt.Sprintf("client > server(%s)", altAddr)) }
	Info("client > server(%s): %s", altAddr, msg.print4Log())
	resp, err = cl.transmitMessageToAlternate(msg, altAddr)
	if err != nil {
		return fmt.Errorf("binding request: %s", err)
	}

	msg, err = getMessage(resp)
	if err != nil {
		return fmt.Errorf("binding response: %s", err)
	}
	if cl.DebugOn { msg.print(fmt.Sprintf("server(%s) > client", altAddr)) }
	Info("server(%s) > client: %s", altAddr, msg.print4Log())

	// get srflx IP address
	srflx, err := msg.getAttrXorMappedAddr()
	if err != nil {
		return fmt.Errorf("binding response: srflx: %s", err)
	}
	srflx.Proto = cl.remote.Proto
	if srflx.Equal(cl.srflx) {
		cl.natType |= NAT_TYPE_ENDPOINT_INDEP_MAP
		return nil
	}

	// test III: request alternate with changed IP and port

	msg, _ = newBindingRequest()
	altAddr.Port = altPort
	if cl.DebugOn { msg.print(fmt.Sprintf("client > server(%s)", altAddr)) }
	Info("client > server(%s): %s", altAddr, msg.print4Log())
	resp, err = cl.transmitMessageToAlternate(msg, altAddr)
	if err != nil {
		return fmt.Errorf("binding request: %s", err)
	}

	msg, err = getMessage(resp)
	if err != nil {
		return fmt.Errorf("binding response: %s", err)
	}
	if cl.DebugOn { msg.print(fmt.Sprintf("server(%s) > client", altAddr)) }
	Info("server(%s) > client: %s", altAddr, msg.print4Log())

	// get srflx IP address
	srflx2, err := msg.getAttrXorMappedAddr()
	if err != nil {
		return fmt.Errorf("binding response: srflx: %s", err)
	}
	srflx2.Proto = cl.remote.Proto
	if srflx2.Equal(srflx) {
		cl.natType |= NAT_TYPE_ADDR_DEP_MAP
		return nil
	}

	cl.natType |= NAT_TYPE_ADDR_AND_PORT_DEP_MAP
	return nil
}

func (cl *stunclient) probeFiltering() (err error) {

	// test I: UDP connectivity test

	// a copy from Bind() request
	msg, _ := newBindingRequest()
	if cl.DebugOn { msg.print(fmt.Sprintf("client > server(%s)", cl.remote)) }
	Info("client > server(%s): %s", cl.remote, msg.print4Log())
	resp, err := cl.transmitMessage(msg)
	if err != nil {
		return fmt.Errorf("binding request: %s", err)
	}

	msg, err = getMessage(resp)
	if err != nil {
		return fmt.Errorf("binding response: %s", err)
	}
	if cl.DebugOn { msg.print(fmt.Sprintf("server(%s) > client", cl.remote)) }
	Info("server(%s) > client: %s", cl.remote, msg.print4Log())

	// save srflx IP address
	cl.srflx, err = msg.getAttrXorMappedAddr()
	if err != nil {
		return fmt.Errorf("binding response: srflx: %s", err)
	}
	cl.srflx.Proto = cl.remote.Proto
	// end of copy

	// get the other server address
	altAddr, err := msg.getAttrOtherAddress()
	if err != nil {
		return fmt.Errorf("get other address: %s", err)
	}

	// test II: request server to respond from alternate IP and port

	msg, _ = newBindingRequest()
	msg.length += msg.addAttrChangeRequest(true, true)
	if cl.DebugOn { msg.print(fmt.Sprintf("client > server(%s)", cl.remote)) }
	Info("client > server(%s): %s", cl.remote, msg.print4Log())
	resp, err = cl.transmitMessage(msg)
	if err == nil {
		// validate response first
		msg, err = getMessage(resp)
		if err != nil {
			return fmt.Errorf("binding response: %s", err)
		}

		if cl.DebugOn { msg.print(fmt.Sprintf("server(%s) > client", altAddr)) }
		Info("server(%s) > client: %s", altAddr, msg.print4Log())

		if msg.isErrorResponse() {
			return fmt.Errorf("server error")
		} else {
			cl.natType |= NAT_TYPE_ENDPOINT_INDEP_FILT
		}
		return nil
	}

	// test III: request server to respond from alternate port only

	msg, _ = newBindingRequest()
	msg.length += msg.addAttrChangeRequest(true, false)
	if cl.DebugOn { msg.print(fmt.Sprintf("client > server(%s)", cl.remote)) }
	Info("client > server(%s): %s", cl.remote, msg.print4Log())
	resp, err = cl.transmitMessage(msg)
	if err == nil {
		// validate response
		msg, err = getMessage(resp)
		if err != nil {
			return fmt.Errorf("binding response: %s", err)
		}

		altAddr.IP = cl.remote.IP
		if cl.DebugOn { msg.print(fmt.Sprintf("server(%s) > client", altAddr)) }
		Info("server(%s) > client: %s", altAddr, msg.print4Log())
		cl.natType |= NAT_TYPE_ADDR_DEP_FILT
		return nil
	}

	cl.natType |= NAT_TYPE_ADDR_AND_PORT_DEP_FILT
	return nil
}

func (cl *stunclient) probeLifetime(seconds int) (bool, error) {

	/// refresh NAT binding by sending stun binding request from original port
	if err := cl.Bind(); err != nil {
		return false, err
	}

	/// no more outbound traffic from the refreshed server reflexive address
	time.Sleep(time.Second * time.Duration(seconds))

	/// create another udp socket on differnet port
	udp, err := net.ListenUDP("udp", cl.pickUDPAddress())
	if err != nil {
		return false, fmt.Errorf("cannot listen another UDP port")
	}

	/// verify stun binding works for this local udp socket
	wg := &sync.WaitGroup{}
	wg.Add(1)
	// create a go routine to receive binding response
	buf := make([]byte, DEFAULT_MTU)
	go func() {
		defer wg.Done()
		// timeout in 10 sec
		udp.SetDeadline(time.Now().Add(time.Second * time.Duration(STUN_CLIENT_REQUEST_TIMEOUT)))
		_, err = udp.Read(buf)
	}()
	// send binding request and wait for goroutine to exit
	msg, _ := newBindingRequest()
	if cl.DebugOn { msg.print(fmt.Sprintf("client(%s) > server(%s)", udp.LocalAddr().String(), cl.remote)) }
	Info("client(%s) > server(%s): %s", udp.LocalAddr().String(), cl.remote, msg.print4Log())
	_, err = udp.WriteToUDP(msg.buffer(), &net.UDPAddr{ IP: cl.remote.IP, Port: cl.remote.Port })
	if err != nil {
		return false, fmt.Errorf("send binding request from other port: %s", err)
	}
	wg.Wait()
	if err != nil {
		return false, fmt.Errorf("receive binding response from other port: %s", err)
	}
	msg, err = getMessage(buf)
	if err != nil {
		return false, fmt.Errorf("get binding response from other port: %s", err)
	}
	if cl.DebugOn { msg.print(fmt.Sprintf("server(%s) > client(%s)", cl.remote, udp.LocalAddr().String())) }
	Info("server(%s) > client(%s): %s", cl.remote, udp.LocalAddr().String(), msg.print4Log())

	/// send binding request with RESPONSE-PORT (cl.srflx.Port)
	msg, _ = newBindingRequest()
	msg.length += msg.addAttrResponsePort(uint16(cl.srflx.Port))
	wg = &sync.WaitGroup{}
	ech := make(chan error)
	// register transaction ID
	cl.responseSub.transactionID = msg.transactionID
	cl.responseSub.listener = make(chan []byte)
	// reset transaction ID and clear receiving pipe
	defer func() {
		cl.responseSub.transactionID = []byte{}
		close(cl.responseSub.listener)
	}()
	// wait for response or timeout
	wg.Add(1)
	var resp []byte
	go func() {
		defer wg.Done()
		select {
		case <-time.NewTimer(time.Second * STUN_CLIENT_REQUEST_TIMEOUT).C:
			err = fmt.Errorf("timeout")
		case resp = <-cl.responseSub.listener:
		case <-ech:
		}
	}()
	// send stun binding message and block till response or timeout
	if cl.DebugOn { msg.print(fmt.Sprintf("client(%s) > server(%s)", udp.LocalAddr().String(), cl.remote)) }
	Info("client(%s) > server(%s): %s", udp.LocalAddr().String(), cl.remote, msg.print4Log())
	_, e := udp.WriteToUDP(msg.buffer(), &net.UDPAddr{ IP: cl.remote.IP, Port: cl.remote.Port })
	if e != nil {
		ech <- e // notify go routine to exit
		return false, e
	}
	wg.Wait()

	/// check if binding response is received from original port
	if resp == nil {
		// the only reason is response timeout
		return false, nil
	}
	msg, err = getMessage(resp)
	if err != nil {
		return false, fmt.Errorf("get binding response from original port: %s", err)
	}
	if cl.DebugOn { msg.print(fmt.Sprintf("server(%s) > client", cl.remote)) }
	Info("server(%s) > client: %s", cl.remote, msg.print4Log())
	return true, nil
}

func (cl *stunclient) transmitMessageToAlternate(m *message, rm *address) (resp []byte, err error) {

	cl.reqMutex.Lock()
	defer cl.reqMutex.Unlock()

	// send binding request to alternate stun server
	if !m.isBindingRequest() {
		return nil, fmt.Errorf("not a valid binding request")
	}
	if cl.udpConn == nil {
		return nil, fmt.Errorf("RFC5780: only udp protocol is allowed")
	}

	wg := &sync.WaitGroup{}
	ech := make(chan error)

	cl.responseSub.transactionID = m.transactionID
	cl.responseSub.listener = make(chan []byte)

	// reset transaction ID and clear receiving pipe
	defer func() {
		cl.responseSub.transactionID = []byte{}
		close(cl.responseSub.listener)
	}()

	// wait for response or timeout event
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-time.NewTimer(time.Second * STUN_CLIENT_REQUEST_TIMEOUT).C:
			err = fmt.Errorf("timeout")
		case resp = <-cl.responseSub.listener:
		case err = <-ech:
		}
	}()

	start := time.Now()
	// TODO - support TCP mapping behavior discovery
	_, e := cl.udpConn.WriteToUDP(m.buffer(), &net.UDPAddr{ IP: rm.IP, Port: rm.Port })
	if e != nil {
		ech <- e
	}
	wg.Wait()
	end := time.Now()
	Info("timeline: %s %d ms", m.methodName + " " + m.encodingName, end.Sub(start).Milliseconds())

	return
}

func (cl *stunclient) LocalAddr() (string, string, int, error) {

	if cl.local != nil {
		return parseNetType(cl.local.Proto), cl.local.IP.String(), cl.local.Port, nil
	}

	return "", "", 0, fmt.Errorf("local address unknown")
}

func (cl *stunclient) NATTypeString() string {

	return parseNATType(cl.natType)
}

func (cl *stunclient) NATLifetime() uint {

	return cl.natLifetime
}
