package stun

import (
	"fmt"
	"encoding/binary"
	"math/rand"
	"conf"
	"net"
	"time"
	"sync"
	"crypto/md5"
	"util/dbg"
)

const (
	TURN_MAX_LIFETIME            = 600
	TURN_SRV_MIN_PORT            = 49152
	TURN_SRV_MAX_PORT            = 65535
	TURN_PERM_LIFETIME           = 300   // this is fixed (https://tools.ietf.org/html/rfc5766#section-8)
	TURN_PERM_LIMIT              = 10
	TURN_CHANN_EXPIRY            = 600   // this is defined (https://tools.ietf.org/html/rfc5766#page-38)
	TURN_NONCE_EXPIRY            = 3600  // <= 1h is recommended
)

const (
	TURN_RELAY_NEW                 = 0
	TURN_RELAY_BINDED              = 1
	TURN_RELAY_LISTENING           = 2
	TURN_RELAY_CLOSED              = 3
)

const  (
	MSG_TYPE_MASK                = 0xc0
	MSG_TYPE_STUN_MSG            = 0x00
	MSG_TYPE_CHANNELDATA         = 0x40

	STUN_MSG_METHOD_ALLOCATE     = 0x0003
	STUN_MSG_METHOD_REFRESH      = 0x0004
	STUN_MSG_METHOD_SEND         = 0x0006
	STUN_MSG_METHOD_DATA         = 0x0007
	STUN_MSG_METHOD_CREATE_PERM  = 0x0008
	STUN_MSG_METHOD_CHANNEL_BIND = 0x0009
)

const (
	STUN_ATTR_CHANNEL_NUMBER     = 0x000c
	STUN_ATTR_LIFETIME           = 0x000d
	STUN_ATTR_XOR_PEER_ADDR      = 0x0012
	STUN_ATTR_DATA               = 0x0013
	STUN_ATTR_XOR_RELAYED_ADDR   = 0x0016
	STUN_ATTR_EVENT_PORT         = 0x0018
	STUN_ATTR_REQUESTED_TRAN     = 0x0019
	STUN_ATTR_DONT_FRAGMENT      = 0x001a
	STUN_ATTR_RESERVATION_TOKEN  = 0x0022
)

const (
	STUN_ERR_FORBIDDEN           = 403
	STUN_ERR_ALLOC_MISMATCH      = 437
	STUN_ERR_WRONG_CRED          = 441
	STUN_ERR_UNSUPPORTED_PROTO   = 442
	STUN_ERR_ALLOC_QUOTA         = 486
	STUN_ERR_INSUFFICIENT_CAP    = 508
)

type turnpool struct {
	// allocation struct map
	table      map[string]*allocation
	tableLck   *sync.RWMutex

	// available port number cursor
	availPort  int
	portLck    *sync.Mutex
}

type relayserver struct {
	// relay server
	conn        *net.UDPConn

	// sync on exit
	wg          *sync.WaitGroup

	// server status
	status      int

	// server status
	svrLck      *sync.Mutex

	// alloc reference
	allocRef    *allocation
}

type allocation struct {
	// hash key to find the alloc struct in pool
	key         string

	// keep alive time
	lifetime    uint32

	// expired time computed by the recent refresh req
	expiry      time.Time

	// reservation token
	token       []byte

	// client ip and port info
	source      address

	// relayed transport address
	relay       address

	// permission list
	perms       map[string]time.Time
	permsLck    *sync.RWMutex

	// server
	server      *relayserver

	// channels
	channels    map[string]*channel
	chanLck     *sync.Mutex

	// nonce
	nonce       string
	nonceExp    time.Time

	// username
	username    string
}

type channel struct {
	// channel number
	number      uint16

	// expiry time
	expiry      time.Time

	// peer address
	peer        *address
}

type channelData struct {
	// channel number
	channel     uint16

	// data payload
	data        []byte
}

var (
	allocPool = &turnpool{
		table: map[string]*allocation{},
		tableLck: &sync.RWMutex{},
		availPort: TURN_SRV_MIN_PORT,
		portLck: &sync.Mutex{},
	}
)

// -------------------------------------------------------------------------------------------------

func keygen(r *address) string {

	return fmt.Sprintf("%d:%s:%d", r.Proto, r.IP.String(), r.Port)
}

func genNonce(length int) string {

	const dictionary = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	str := make([]byte, length)
	for i := range str {
		str[i] = dictionary[rand.Int63() % int64(len(dictionary))]
	}

	return string(str)
}

// -------------------------------------------------------------------------------------------------

// general behavior
func (this *message) generalRequestCheck(r *address) (*allocation, *message) {

	alloc, ok := allocPool.find(keygen(r))
	if !ok {
		msg := this.newErrorMessage(STUN_ERR_ALLOC_MISMATCH, "allocation not found")
		return nil, msg
	}

	// indications in TURN are never authenticated, return success now
	if this.isIndication() {
		return alloc, nil
	}

	// long-term credential
	if code, err := this.checkCredential(); err != nil {
		return nil, this.newErrorMessage(code, err.Error())
	}

	// check username and nocne, according to rfc5766, username could not change since allocate
	// is created
	username, _, nonce, _, _ := this.getCredential()
	if alloc.username != username {
		msg := this.newErrorMessage(STUN_ERR_WRONG_CRED, "username or password error")
		return nil, msg
	}

	// check whether nonce is expired
	if alloc.nonce != nonce {
		msg, _ := this.replyUnauth(STUN_ERR_STALE_NONCE, alloc.nonce, "NONCE is expired")
		return nil, msg
	}

	return alloc, nil
}

func (this *message) doChanBindRequest(alloc *allocation) (*message, error) {

	channel, err := this.getAttrChanNumber()
	if err != nil {
		return this.newErrorMessage(STUN_ERR_BAD_REQUEST, "invalid CHANNEL-BIND request: " + err.Error()), nil
	}

	addr, err := this.getAttrXorPeerAddress()
	if err != nil {
		return this.newErrorMessage(STUN_ERR_BAD_REQUEST, "invalid CHANNEL-BIND request: " + err.Error()), nil
	}

	if channel < 0x4000 || channel > 0x7ffe {
		return this.newErrorMessage(STUN_ERR_BAD_REQUEST, "invalid channel number"), nil
	}

	if err := alloc.addChan(channel, addr); err != nil {
		return this.newErrorMessage(STUN_ERR_INSUFFICIENT_CAP, "CHANNEL-BIND: " + err.Error()), nil
	}

	// refresh permissions for the peer
	alloc.addPerm(addr)

	msg := &message{}
	msg.method = this.method
	msg.encoding = STUN_MSG_SUCCESS
	msg.methodName, msg.encodingName = parseMessageType(msg.method, msg.encoding)
	msg.transactionID = append(msg.transactionID, this.transactionID...)

	// add integrity attribute
	if err := msg.addIntegrity(alloc.username); err != nil {
		return this.newErrorMessage(STUN_ERR_WRONG_CRED, err.Error()), nil
	}

	return msg, nil
}

func (this *message) doSendIndication(alloc *allocation) {

	addr, err := this.getAttrXorPeerAddress()
	if err != nil {
		// TODO: fmt.Errorf("peer address: %s", err)
		return
	}

	data, err := this.getAttrData()
	if err != nil {
		// TODO: fmt.Errorf("no data")
		return
	}

	// TODO handle DONT-FRAGMENT

	if err := alloc.checkPerms(addr); err != nil {
		// TODO: fmt.Errorf("denied")
		return
	}

	alloc.server.sendToPeer(addr, data)
}

func newSendIndication(peer *address, data []byte) (*message, error) {

	msg := &message{}
	msg.method = STUN_MSG_METHOD_SEND
	msg.encoding = STUN_MSG_INDICATION
	msg.methodName, msg.encodingName = parseMessageType(msg.method, msg.encoding)
	msg.transactionID = append(msg.transactionID, genTransactionID()...)

	// add peer address and data payloads
	msg.length += msg.addAttrXorPeerAddr(peer)
	msg.length += msg.addAttrData(data)

	return msg, nil
}

func (this *message) doCreatePermRequest(alloc *allocation) (*message, error) {

	addrs, err := this.getAttrXorPeerAddresses()
	if err != nil {
		return this.newErrorMessage(STUN_ERR_BAD_REQUEST, "peer addresses: " + err.Error()), nil
	}

	if err := alloc.addPerms(addrs); err != nil {
		return this.newErrorMessage(STUN_ERR_INSUFFICIENT_CAP, err.Error()), nil
	}

	msg := &message{}
	msg.method = this.method
	msg.encoding = STUN_MSG_SUCCESS
	msg.methodName, msg.encodingName = parseMessageType(msg.method, msg.encoding)
	msg.transactionID = append(msg.transactionID, this.transactionID...)

	// add integrity attribute
	if err := msg.addIntegrity(alloc.username); err != nil {
		return this.newErrorMessage(STUN_ERR_WRONG_CRED, err.Error()), nil
	}

	return msg, nil
}

func newCreatePermRequest(username, password, realm, nonce string, peers []*address) (*message, error) {

	msg := &message{}
	msg.method = STUN_MSG_METHOD_CREATE_PERM
	msg.encoding = STUN_MSG_REQUEST
	msg.methodName, msg.encodingName = parseMessageType(msg.method, msg.encoding)
	msg.transactionID = append(msg.transactionID, genTransactionID()...)

	// add credential attributes
	msg.length += msg.addAttrUsername(username)
	msg.length += msg.addAttrRealm(realm)
	msg.length += msg.addAttrNonce(nonce)

	// add each peer to XOR-PEER-ADDRESS
	for _, peer := range peers {
		msg.length += msg.addAttrXorPeerAddr(peer)
	}

	// make sure MESSAGE-INTEGRITY is the last attribute
	key := md5.Sum([]byte(username + ":" + realm + ":" + password))
	msg.length += msg.addAttrMsgIntegrity(string(key[0:16]))

	return msg, nil
}

func (this *message) doRefreshRequest(alloc *allocation) (*message, error) {

	msg := &message{}
	msg.method = this.method
	msg.encoding = STUN_MSG_SUCCESS
	msg.methodName, msg.encodingName = parseMessageType(msg.method, msg.encoding)
	msg.transactionID = append(msg.transactionID, this.transactionID...)

	// add integrity attribute
	addIntegrity := func() (*message, error) {
		if err := msg.addIntegrity(alloc.username); err != nil {
			return this.newErrorMessage(STUN_ERR_WRONG_CRED, err.Error()), nil
		}
		return msg, nil
	}

	// get lifetime attribute from stun message
	lifetime, err := this.getAttrLifetime()
	if err != nil {
		lifetime = TURN_MAX_LIFETIME
	} else {
		if lifetime == 0 {
			alloc.free()
			msg.length += msg.addAttrLifetime(0)

			return addIntegrity()
		}
	}
	alloc.refresh(lifetime)
	msg.length += msg.addAttrLifetime(alloc.lifetime)

	return addIntegrity()
}

func newRefreshRequest(lifetime uint32, username, password, realm, nonce string) (*message, error) {

	msg := &message{}
	msg.method = STUN_MSG_METHOD_REFRESH
	msg.encoding = STUN_MSG_REQUEST
	msg.methodName, msg.encodingName = parseMessageType(msg.method, msg.encoding)
	msg.transactionID = append(msg.transactionID, genTransactionID()...)

	// add LIFETIME + USERNAME + REALM + NONCE + MESSAGE-INTEGRITY
	msg.length += msg.addAttrLifetime(lifetime)
	msg.length += msg.addAttrUsername(username)
	msg.length += msg.addAttrRealm(realm)
	msg.length += msg.addAttrNonce(nonce)

	// make sure MESSAGE-INTEGRITY is the last attribute
	key := md5.Sum([]byte(username + ":" + realm + ":" + password))
	msg.length += msg.addAttrMsgIntegrity(string(key[0:16]))

	return msg, nil
}

func (this *message) doAllocationRequest(r *address) (msg *message, err error) {

	// 1. long-term credential
	username, _, _, _, err := this.getCredential()
	if err != nil {
		// handle first alloc request
		return this.replyUnauth(STUN_ERR_UNAUTHORIZED, genNonce(STUN_NONCE_LENGTH), "missing long-term credential")
	}
	// handle subsequent alloc request
	code, err := this.checkCredential()
	if err != nil {
		return this.newErrorMessage(code, err.Error()), nil
	}

	// 2. find existing allocations
	alloc, err := newAllocation(r)
	if err != nil {
		return this.newErrorMessage(STUN_ERR_ALLOC_MISMATCH, err.Error()), nil
	}

	// 3. check allocation
	if err = this.checkAllocation(); err != nil {
		return this.newErrorMessage(STUN_ERR_BAD_REQUEST, "invalid alloc req: " + err.Error()), nil
	}

	// 4. TODO handle DONT-FRAGMENT attribute

	// 5. TODO get reservation token
	alloc.token, err = this.getAttrReservToken()
	if err == nil {
		return this.newErrorMessage(STUN_ERR_INSUFFICIENT_CAP, "RESERVATION-TOKEN is not supported"), nil
	}

	// 6. TODO get even port

	// 7. TODO check quota

	// 8. TODO handle ALTERNATE attribute

	// set longterm-credential username
	alloc.username = username

	// set nonce to expire right now
	alloc.nonce = genNonce(STUN_NONCE_LENGTH)
	alloc.nonceExp = time.Now()

	// set lifetime
	lifetime, err := this.getAttrLifetime()
	if err != nil {
		lifetime = TURN_MAX_LIFETIME
	}
	alloc.refresh(lifetime)

	// save allocation and reply to the client
	err = alloc.save()
	if err != nil {
		return this.newErrorMessage(STUN_ERR_SERVER_ERROR, "alloc failed: " + err.Error()), nil
	}
	return this.replyAllocationRequest(alloc)
}

func newInitAllocationRequest() (*message, error) {

	msg := &message{}
	msg.method = STUN_MSG_METHOD_ALLOCATE
	msg.encoding = STUN_MSG_REQUEST
	msg.methodName, msg.encodingName = parseMessageType(msg.method, msg.encoding)
	msg.transactionID = append(msg.transactionID, genTransactionID()...)
	msg.length += msg.addAttrRequestedTran()

	return msg, nil
}

func newSubAllocationRequest(username, realm, nonce string) (*message, error) {

	msg, _ := newInitAllocationRequest()
	msg.length += msg.addAttrUsername(username)
	msg.length += msg.addAttrRealm(realm)
	msg.length += msg.addAttrNonce(nonce)

	return msg, nil // this is not done yet, need optional attrs + integrity attr
}

func (this *message) checkAllocation() error {

	// check req tran attr
	if this.findAttr(STUN_ATTR_REQUESTED_TRAN) == nil {
		return fmt.Errorf("missing REQUESTED-TRANSPORT attribute")
	}

	return nil
}

func (this *message) addAttrData(data []byte) int {

	attr := &attribute{}
	attr.typevalue = STUN_ATTR_DATA
	attr.typename = parseAttributeType(attr.typevalue)
	attr.length = len(data)

	// paddings
	total := attr.length
	if total % 4 != 0 {
		total += 4 - total % 4
	}

	attr.value = make([]byte, total)
	copy(attr.value[0:], data)

	this.attributes = append(this.attributes, attr)
	return 4 + len(attr.value)
}

func (this *message) addAttrXorRelayedAddr(r *address) int {

	return this.addAttrXorAddr(r, STUN_ATTR_XOR_RELAYED_ADDR)
}

func (this *message) addAttrXorPeerAddr(r *address) int {

	return this.addAttrXorAddr(r, STUN_ATTR_XOR_PEER_ADDR)
}

func (this *message) addAttrLifetime(t uint32) int {

	attr := &attribute{}
	attr.typevalue = STUN_ATTR_LIFETIME
	attr.typename = parseAttributeType(attr.typevalue)
	attr.length = 4
	attr.value = make([]byte, 4)
	binary.BigEndian.PutUint32(attr.value[0:], t)

	this.attributes = append(this.attributes, attr)
	return 8 // fixed 4 bytes
}

func (this *message) addAttrRequestedTran() int {

	attr := &attribute{}
	attr.typevalue = STUN_ATTR_REQUESTED_TRAN
	attr.typename = parseAttributeType(attr.typevalue)
	attr.length = 4
	attr.value = []byte{PROTO_NUM_UDP, 0, 0, 0}

	this.attributes = append(this.attributes, attr)
	return 8 // 4 + 4
}

func (this *message) getAttrData() ([]byte, error) {

	attr := this.findAttr(STUN_ATTR_DATA)
	if attr == nil {
		return nil, fmt.Errorf("not found")
	}

	return attr.value, nil
}

func (this *message) getAttrChanNumber() (uint16, error) {

	attr := this.findAttr(STUN_ATTR_CHANNEL_NUMBER)
	if attr == nil {
		return 0, fmt.Errorf("not found")
	}

	if len(attr.value) != 4 {
		return 0, fmt.Errorf("invalid CHANNEL-NUMBER attribute")
	}

	ch := binary.BigEndian.Uint16(attr.value[0:])
	rffu := binary.BigEndian.Uint16(attr.value[2:])

	if rffu != 0 {
		return 0, fmt.Errorf("invalid CHANNEL-NUMBER attribute: RFFU is not zero")
	}

	return ch, nil
}

func (this *message) getAttrXorPeerAddress() (*address, error) {

	attr := this.findAttr(STUN_ATTR_XOR_PEER_ADDR)
	if attr == nil {
		return nil, fmt.Errorf("not found")
	}

	return decodeXorAddr(attr)
}

func (this *message) getAttrXorRelayedAddr() (*address, error) {

	attr := this.findAttr(STUN_ATTR_XOR_RELAYED_ADDR)
	if attr == nil {
		return nil, fmt.Errorf("not found")
	}

	return decodeXorAddr(attr)
}

func (this *message) getAttrReservToken() ([]byte, error) {

	attr := this.findAttr(STUN_ATTR_RESERVATION_TOKEN)
	if attr == nil {
		return nil, fmt.Errorf("not found")
	}

	return attr.value, nil
}

func (this *message) getAttrLifetime() (uint32, error) {

	attr := this.findAttr(STUN_ATTR_LIFETIME)
	if attr == nil {
		return 0, fmt.Errorf("not found")
	}

	lifetime := binary.BigEndian.Uint32(attr.value)
	return lifetime, nil
}

func (this *message) getAttrXorPeerAddresses() ([]*address, error) {

	results := []*address{}

	list := this.findAttrAll(STUN_ATTR_XOR_PEER_ADDR)
	if len(list) == 0 {
		return nil, fmt.Errorf("not found")
	}

	for _, attr := range list {
		addr, err := decodeXorAddr(attr)
		if err != nil {
			return nil, fmt.Errorf("value invalid: %s", err)
		}
		results = append(results, addr)
	}

	return results, nil
}

func (this *message) replyAllocationRequest(alloc *allocation) (*message, error) {

	msg := &message{}
	msg.method = STUN_MSG_METHOD_ALLOCATE
	msg.encoding = STUN_MSG_SUCCESS
	msg.methodName, msg.encodingName = parseMessageType(msg.method, msg.encoding)
	msg.transactionID = append(msg.transactionID, this.transactionID...)
	msg.length += msg.addAttrXorRelayedAddr(&alloc.relay)
	msg.length += msg.addAttrLifetime(alloc.lifetime)
	msg.length += msg.addAttrXorMappedAddr(&alloc.source)

	// add integrity attribute
	if err := msg.addIntegrity(alloc.username); err != nil {
		return this.newErrorMessage(STUN_ERR_WRONG_CRED, err.Error()), nil
	}

	return msg, nil
}

func (this *message) replyUnauth(code int, nonce, reason string) (*message, error) {

	msg := &message{}
	msg.method = this.method
	msg.encoding = STUN_MSG_ERROR
	msg.methodName, msg.encodingName = parseMessageType(msg.method, msg.encoding)
	msg.transactionID = append(msg.transactionID, this.transactionID...)
	msg.length += msg.addAttrErrorCode(code, reason)
	msg.length += msg.addAttrRealm(*conf.Args.Realm)
	msg.length += msg.addAttrNonce(nonce)

	return msg, nil
}

// -------------------------------------------------------------------------------------------------

func newAllocation(r *address) (*allocation, error) {

	key := keygen(r)
	if _, ok := allocPool.find(key); ok {
		return nil, fmt.Errorf("allocation already exists")
	}

	return &allocation{
		key:      key,
		source:   *r,
		perms:    map[string]time.Time{},
		permsLck: &sync.RWMutex{},
		channels: map[string]*channel{},
		chanLck:  &sync.Mutex{},
	}, nil
}

func (alloc *allocation) save() error {

	// insert allocation struct to global pool
	if ok := alloc.addToPool(); !ok {
		return  fmt.Errorf("already allocated")
	}

	// create relay service
	alloc.server = newRelay(alloc)
	port, err := alloc.server.bind()
	if err != nil {
		alloc.removeFromPool()
		return err
	}

	// save relay address
	alloc.relay.IP = net.ParseIP(*conf.Args.IP).To4() // use default IP in args
	alloc.relay.Port = port

	// spawn a thread to listen UDP channel
	if err := alloc.server.spawn(); err != nil {
		return err
	}

	return nil
}

func (alloc *allocation) free() error {

	alloc.server.kill() // may block for a while
	alloc.removeFromPool()

	return nil
}

func (alloc *allocation) addToPool() bool {

	return allocPool.insert(alloc)
}

func (alloc *allocation) removeFromPool() {

	allocPool.remove(alloc.key)
}

func (alloc *allocation) refresh(lifetime uint32) {

	alloc.lifetime = lifetime
	if lifetime > TURN_MAX_LIFETIME {
		alloc.lifetime = TURN_MAX_LIFETIME
	}
	alloc.expiry = time.Now().Add(time.Second * time.Duration(alloc.lifetime))
}

func (alloc *allocation) getRestLife() (int, error) {

	t := int(alloc.expiry.Unix() - time.Now().Unix())
	if t <= 0 {
		return 0, fmt.Errorf("expired.")
	} else {
		return t, nil
	}
}

func (alloc *allocation) addPerms(addrs []*address) (err error) {

	err = nil
	now := time.Now()

	alloc.permsLck.Lock()
	defer alloc.permsLck.Unlock()

	// clear expired permissions
	for ip, expiry := range alloc.perms {
		if now.After(expiry) {
			delete(alloc.perms, ip)
		}
	}

	// add/refresh permission entry
	for _, addr := range addrs {
		key := addr.IP.String()
		if _, ok := alloc.perms[key]; !ok {
			// check maximum capacity of permissions
			if len(alloc.perms) >= TURN_PERM_LIMIT {
				err = fmt.Errorf("maximum permissions reached")
			}
		}
		alloc.perms[key] = now.Add(time.Second * time.Duration(TURN_PERM_LIFETIME))
	}

	return err
}

func (alloc *allocation) addPerm(addr *address) (err error) {

	return alloc.addPerms([]*address{addr})
}

func (alloc *allocation) checkPerms(addr *address) error {

	key := addr.IP.String()

	alloc.permsLck.RLock()
	defer alloc.permsLck.RUnlock()

	item, ok := alloc.perms[key]
	if !ok {
		return fmt.Errorf("permission not exists")
	}

	if time.Now().After(item) {
		return fmt.Errorf("permission expired")
	}

	return nil
}

func (alloc *allocation) addChan(ch uint16, addr *address) error {

	alloc.chanLck.Lock()
	defer alloc.chanLck.Unlock()

	now := time.Now()

	// clean expired channels
	for index, channel := range alloc.channels {
		if now.After(channel.expiry) {
			delete(alloc.channels, index)
		}
	}

	// if the channel already exists and the address is matched just refresh the timer
	if channel, ok := alloc.channels[addr.IP.String()]; ok {
		if channel.number == ch {
			channel.expiry = now.Add(time.Second * time.Duration(TURN_CHANN_EXPIRY))
			return nil
		}
		return fmt.Errorf("channel already in use")
	}

	// check if there is a dup channel number
	for _, channel := range alloc.channels {
		if channel.number == ch {
			return fmt.Errorf("channel number already in use")
		}
	}

	alloc.channels[addr.IP.String()] = &channel{
		number: ch,
		expiry: now.Add(time.Second * time.Duration(TURN_CHANN_EXPIRY)),
		peer:   addr,
	}

	return nil
}

func (alloc *allocation) findChan(num uint16) (*address, error) {

	alloc.chanLck.Lock()
	defer alloc.chanLck.Unlock()

	for _, channel := range alloc.channels {
		if channel.number == num && time.Now().Before(channel.expiry){
			return channel.peer, nil
		}
	}

	return nil, fmt.Errorf("channel unbound or expired")
}

func (alloc *allocation) findChanByPeer(peer *address) (uint16, error) {

	alloc.chanLck.Lock()
	defer alloc.chanLck.Unlock()

	ch, ok := alloc.channels[peer.IP.String()]
	if !ok {
		return 0, fmt.Errorf("not found")
	}

	return ch.number, nil
}

// -------------------------------------------------------------------------------------------------

func newRelay(alloc *allocation) *relayserver {

	return &relayserver{
		status:   TURN_RELAY_NEW,
		svrLck:   &sync.Mutex{},
		allocRef: alloc,
		wg:       &sync.WaitGroup{},
	}
}

func (svr *relayserver) bind() (p int, _ error) {

	svr.svrLck.Lock()
	defer svr.svrLck.Unlock()
	if svr.status != TURN_RELAY_NEW {
		return -1, fmt.Errorf("relay server has already started")
	}

	// try 40 times, NEVER ASK WHY 40
	for i := 0; i < 40; i++ {

		p = allocPool.nextPort()
		addr := fmt.Sprintf("%s:%d", *conf.Args.IP, p)

		udp, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			continue
		}

		svr.conn, err = net.ListenUDP("udp", udp)
		if err != nil {
			continue
		}

		svr.status = TURN_RELAY_BINDED
		return p, nil
	}
	return -1, fmt.Errorf("could not bind local address")
}

// TODO connection needs retry
func (svr *relayserver) spawn() error {

	svr.svrLck.Lock()
	defer svr.svrLck.Unlock()
	if svr.status != TURN_RELAY_BINDED {
		return fmt.Errorf("could not listen relay address")
	}
	svr.status = TURN_RELAY_LISTENING

	go func(svr *relayserver) {

		// read from UDP socket
		ech := make(chan error)  // error channel

		// spawn listening thread
		svr.wg.Add(1)
		go func(svr *relayserver, ech chan error) {
			defer svr.wg.Done()
			defer svr.conn.Close()

			for {
				buf := make([]byte, DEFAULT_MTU)
				nr, rm, err := svr.conn.ReadFromUDP(buf)
				if err != nil {
					ech <- err
					break
				}

				// send to client
				svr.sendToClient(rm, buf[:nr])
			}
		}(svr, ech)

		// poll fds
		ticker := time.NewTicker(time.Second * 60)
		timer := time.NewTimer(time.Second * time.Duration(svr.allocRef.lifetime))
		for quit := false; !quit; {
			select {
			case <-ticker.C:
				// refresh nonce
				now := time.Now()
				if now.After(svr.allocRef.nonceExp) {
					svr.allocRef.nonce = genNonce(STUN_NONCE_LENGTH)
					svr.allocRef.nonceExp = now.Add(time.Second * time.Duration(TURN_NONCE_EXPIRY))
				}
			case <-timer.C:
				if seconds, err := svr.allocRef.getRestLife(); err == nil {
					timer = time.NewTimer(time.Second * time.Duration(seconds))
					break
				}
				svr.conn.SetDeadline(time.Now())
				svr.allocRef.removeFromPool()
			case <-ech:
				quit = true
			}
		}

		// wait for listening thread
		svr.wg.Wait()
		svr.status = TURN_RELAY_CLOSED
	}(svr)

	return nil
}

func (svr *relayserver) kill() {

	svr.svrLck.Lock()
	defer svr.svrLck.Unlock()
	svr.conn.SetDeadline(time.Now())
	svr.wg.Wait()
}

func (svr *relayserver) sendToPeer(addr *address, data []byte) {

	r := &net.UDPAddr{
		IP:   addr.IP,
		Port: addr.Port,
	}

	go func(r *net.UDPAddr, data []byte) {

		if svr.conn == nil {
			return
		}

		if svr.status != TURN_RELAY_LISTENING {
			// fmt.Errorf("send error: server status: %d", svr.status)
			return
		}

		_, err := svr.conn.WriteToUDP(data, r)
		if err != nil {
			// fmt.Errorf("send error: %s", err)
			return
		}
	}(r, data)
}

func (svr *relayserver) sendToClient(peer *net.UDPAddr, data []byte) {

	go func(svr *relayserver, peer *net.UDPAddr, data []byte) {

		// look up permissions
		paddr := &address{
			IP:    peer.IP,
			Port:  peer.Port,
		}
		if err := svr.allocRef.checkPerms(paddr); err != nil {
			return
		}

		var buf []byte
		if ch, err := svr.allocRef.findChanByPeer(paddr); err != nil {
			// send data indication
			msg := &message{}
			msg.method = STUN_MSG_METHOD_DATA
			msg.encoding = STUN_MSG_INDICATION
			msg.methodName, msg.encodingName = parseMessageType(msg.method, msg.encoding)
			msg.transactionID = make([]byte, 12)
			binary.BigEndian.PutUint64(msg.transactionID[0:], uint64(time.Now().UnixNano()))
			msg.length += msg.addAttrXorPeerAddr(paddr)
			msg.length += msg.addAttrData(data)
			buf = msg.buffer()
		} else {
			// send channel data
			chdata := newChannelData(ch, data)
			buf = chdata.buffer()
		}

		if err := sendTo(&svr.allocRef.source, buf); err != nil {
			return
		}
	}(svr, peer, data)
}

// -------------------------------------------------------------------------------------------------

func (pool *turnpool) insert(alloc *allocation) bool {

	pool.tableLck.Lock()
	defer pool.tableLck.Unlock()

	if _, ok := pool.table[alloc.key]; !ok {
		pool.table[alloc.key] = alloc
		return true
	}
	return false
}

func (pool *turnpool) remove(key string) {

	pool.tableLck.Lock()
	defer pool.tableLck.Unlock()
	delete(pool.table, key)
}

func (pool *turnpool) find(key string) (alloc *allocation, ok bool) {

	pool.tableLck.RLock()
	defer pool.tableLck.RUnlock()
	alloc, ok = pool.table[key]
	return
}

func (pool *turnpool) nextPort() (p int) {

	pool.portLck.Lock()
	defer pool.portLck.Unlock()

	p = pool.availPort
	if pool.availPort == TURN_SRV_MAX_PORT {
		pool.availPort = TURN_SRV_MIN_PORT
	} else {
		pool.availPort++
	}
	return
}

func (pool *turnpool) printTable() (result string) {

	pool.tableLck.RLock()
	defer pool.tableLck.RUnlock()

	for _, alloc := range pool.table {
		result += fmt.Sprintf("alloc=%s relay=%s\n", alloc.key, keygen(&alloc.relay))
		result += fmt.Sprintf("  owner=%s\n", alloc.username)
		result += fmt.Sprintf("  lifetime=%d before %s\n", alloc.lifetime, alloc.expiry.Format("2006-01-02 15:04:05"))
		result += fmt.Sprintf("  nonce=%s before %s\n", alloc.nonce, alloc.nonceExp.Format("2006-01-02 15:04:05"))

		// permissions
		perms := ""
		for p, t := range alloc.perms {
			perms += fmt.Sprintf("  perm=%s before %s\n", p, t.Format("2006-01-02 15:04:05"))
		}
		result += perms

		// channels
		chs := ""
		for _, ch := range alloc.channels {
			chs += fmt.Sprintf("  chan=no.%d -> %s before %s\n", ch.number, keygen(ch.peer),
				ch.expiry.Format("2006-01-02 15:04:05"))
		}
		result += chs
	}

	return
}

// -------------------------------------------------------------------------------------------------

func newChannelData(channel uint16, data []byte) *channelData {

	return &channelData{
		channel: channel,
		data:    data,
	}
}

func getChannelData(buf []byte) (*channelData, error) {

	buf, err := checkChannelData(buf)
	if err != nil {
		return nil, fmt.Errorf("invalid channel data: %s", err)
	}

	return &channelData{
		channel: binary.BigEndian.Uint16(buf[0:]),
		data:    buf[4:],
	}, nil
}

func checkChannelData(buf []byte) ([]byte, error) {

	if len(buf) < 4 {
		return nil, fmt.Errorf("channelData too short")
	}

	// check channel number
	if binary.BigEndian.Uint16(buf[0:]) >= 0x8000 {
		return nil, fmt.Errorf("invalid channel number")
	}

	// check length
	length := binary.BigEndian.Uint16(buf[2:])
	if 4 + binary.BigEndian.Uint16(buf[2:]) > uint16(len(buf)) {
		return nil, fmt.Errorf("channelData length is too large")
	}

	return buf[:4+length], nil
}

func (ch *channelData) transport(addr *address) {

	alloc, ok := allocPool.find(keygen(addr))
	if !ok {
		return
	}

	peer, err := alloc.findChan(ch.channel)
	if err != nil {
		return
	}

	alloc.server.sendToPeer(peer, ch.data)
}

func (ch *channelData) buffer() []byte {

	payload := make([]byte, 4)

	// channel number
	binary.BigEndian.PutUint16(payload[0:], ch.channel)

	// length
	binary.BigEndian.PutUint16(payload[2:], uint16(len(ch.data)))

	// append application data
	payload = append(payload, ch.data...)

	return payload
}

func (ch *channelData) print(title string) {

	str := fmt.Sprintf("========== %s ==========\n", title)
	str += fmt.Sprintf("channel=0x%04x, length=%d bytes\n", ch.channel, len(ch.data))
	str += fmt.Sprintf("%s\n", dbg.DumpMem(ch.data, 16))
	fmt.Println(str)
}

// -------------------------------------------------------------------------------------------------

func (cl *stunclient) transmit(msg *message) ([]byte, error) {

	if cl.remote == nil {
		return nil, fmt.Errorf("remote address not specified")
	}

	switch cl.remote.Proto {
	case NET_TCP:
	case NET_UDP: return transmitUDP(cl.remote, cl.srflx, msg)
	case NET_TLS:
	}

	return nil, fmt.Errorf("unsupported protocol")
}

func (cl *stunclient) Alloc() error {

	// create initial alloc request
	req, _ := newInitAllocationRequest()
	req.print(fmt.Sprintf("client > server(%s)", cl.remote))
	buf, err := cl.transmit(req)
	if err != nil {
		return fmt.Errorf("alloc request: %s", err)
	}

	// get response from server and return relayed IP address
	resp, err := getMessage(buf)
	if err != nil {
		return fmt.Errorf("alloc response: %s", err)
	}
	resp.print(fmt.Sprintf("server(%s) > client", cl.remote))

	// 401 failure on the first alloc request is expected behavior
	code, errStr, err := resp.getAttrErrorCode()
	if err != nil {
		return fmt.Errorf("missing expected 401 error code")
	}
	if code != 401 {
		return fmt.Errorf("missing 401 error code, actual response: %d:%s", code, errStr)
	}

	// get REALM and NONCE
	cl.realm, err = resp.getAttrRealm()
	if err != nil {
		return fmt.Errorf("alloc response: get realm: %s", err)
	}
	cl.nonce, err = resp.getAttrNonce()
	if err != nil {
		return fmt.Errorf("alloc response: nonce: %s", err)
	}

	// subsequent request
	req, _ = newSubAllocationRequest(cl.Username, cl.realm, cl.nonce)
	if cl.Lifetime != 0 {
		req.length += req.addAttrLifetime(cl.Lifetime)
	}
	if cl.NoFragment {
		// TODO NO-FRAGMENT
	}
	if cl.EvenPort {
		// TODO EVEN-PORT
	}
	if cl.ReservToken != nil {
		// TODO RESERVATION-TOKEN
	}
	// for long-term credentials, key = MD5(username ":" realm ":" SASLprep(password))
	// https://tools.ietf.org/html/rfc5389#section-15.4
	key := md5.Sum([]byte(cl.Username + ":" + cl.realm + ":" + cl.Password))
	req.length += req.addAttrMsgIntegrity(string(key[0:16]))

	// send subsequent request to server
	req.print(fmt.Sprintf("client > server(%s)", cl.remote))
	buf, err = cl.transmit(req)
	if err != nil {
		return fmt.Errorf("alloc request: %s", err)
	}

	// get response from server and return relayed IP address
	resp, err = getMessage(buf)
	if err != nil {
		return fmt.Errorf("alloc response: %s", err)
	}
	resp.print(fmt.Sprintf("server(%s) > client", cl.remote))

	// get response status
	code, errStr, err = resp.getAttrErrorCode()
	if err == nil {
		// err == nil indicates server returns error
		return fmt.Errorf("server returned error %d:%s", code, errStr)
	}

	// save srflx IP address
	cl.srflx, err = resp.getAttrXorMappedAddr()
	if err != nil {
		return fmt.Errorf("binding response: srflx: %s", err)
	}
	cl.srflx.Proto = cl.remote.Proto

	// get relayed address
	cl.relay, err = resp.getAttrXorRelayedAddr()
	if err != nil {
		return fmt.Errorf("alloc response: missing relayed address")
	}
	// only UDP is supported according to https://tools.ietf.org/html/rfc5766#section-14.7
	cl.relay.Proto = NET_UDP

	// adjust lifetime
	cl.Lifetime, err = resp.getAttrLifetime()
	if err != nil {
		return fmt.Errorf("alloc response: no lifetime")
	}

	return nil
}

func (cl *stunclient) Refresh(lifetime uint32) error {

	for retry := 2; retry > 0; {

		req, _ := newRefreshRequest(lifetime, cl.Username, cl.Password, cl.realm, cl.nonce)
		req.print(fmt.Sprintf("client > server(%s)", cl.remote))

		// send request to server
		buf, err := cl.transmit(req)
		if err != nil {
			return fmt.Errorf("refresh request: %s", err)
		}

		// get response from server
		resp, err := getMessage(buf)
		if err != nil {
			return fmt.Errorf("refresh response: %s", err)
		}
		resp.print(fmt.Sprintf("server(%s) > client", cl.remote))

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

func (cl *stunclient) CreatePerm(ipList []string) error {

	for retry := 2; retry > 0; {

		// prepare new message
		req, _ := newCreatePermRequest(cl.Username, cl.Password, cl.realm, cl.nonce,
			func() []*address {
				addrs := []*address{}
				for _, ip := range ipList {
					addrs = append(addrs, &address{
						IP: net.ParseIP(ip).To4(),
						// any port is ok, https://tools.ietf.org/html/rfc5766#section-9.1
						Port: 0,
						Proto: NET_UDP,
					})
				}
				return addrs
			}())
		req.print(fmt.Sprintf("client > server(%s)", cl.remote))

		// send request to server
		buf, err := cl.transmit(req)
		if err != nil {
			return fmt.Errorf("create-permission request: %s", err)
		}

		// get response from server
		resp, err := getMessage(buf)
		if err != nil {
			return fmt.Errorf("create-permission response: %s", err)
		}
		resp.print(fmt.Sprintf("server(%s) > client", cl.remote))

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

func (cl *stunclient) Send(ip string, port int, data []byte) error {

	msg, _ := newSendIndication(
		&address{
			IP: net.ParseIP(ip).To4(),
			Port: port,
		},
		data,
	)
	msg.print(fmt.Sprintf("client > server(%s)", cl.remote))

	// send indication to server
	_, err := cl.transmit(msg)
	if err != nil {
		return fmt.Errorf("send indication: %s", err)
	}

	return nil
}
