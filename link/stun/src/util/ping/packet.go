package ping

import(
	"time"
	"encoding/binary"
	"fmt"
)

const(
	SEQ_INDEX     = 0
	SIZE_INDEX    = 8
	SENDTS_INDEX  = 16
	RECVTS_INDEX  = 24
	PKT_MIN_SIZE  = 32
)

const(
	PKT_SENT      = 0
	PKT_RECV      = 1
	PKT_OBSOLETE  = 2
)

type packetInfo struct {
	// [seq:8][dur:8][sendts:8][respts:8][recvts:8]

	// sequence number starting from 0
	seq   uint64

	// payload size to estimate average bandwidth
	size  uint64

	// packet status
	status int

	// timestamp trackpoints to get RTT
	// client (sendts) -> TURN -> peer -> TURN -> client (recvTs)

	// generate sequence and sending time
	sendts time.Time

	// calculate jitter RTT and loss
	recvts time.Time
}

func (info *packetInfo) String() string {

	return fmt.Sprintf("seq=%d size=%d status=%d", info.seq, info.size, info.status)
}

func loadInfo(data []byte) (*packetInfo, error) {

	if len(data) < PKT_MIN_SIZE {
		return nil, fmt.Errorf("payload is too short")
	}

	n := int64(binary.BigEndian.Uint64(data[SENDTS_INDEX:]))
	sendts := time.Unix(n / 1000000000, n % 1000000000)
	n = int64(binary.BigEndian.Uint64(data[RECVTS_INDEX:]))
	recvts := time.Unix(n / 1000000000, n % 1000000000)

	pkt := &packetInfo{
		seq: 	binary.BigEndian.Uint64(data[SEQ_INDEX:]),
		size:   binary.BigEndian.Uint64(data[SIZE_INDEX:]),
		sendts: sendts,
		recvts: recvts,
	}

	if len(data) < int(pkt.size) {
		return nil, fmt.Errorf("payload is not complete")
	}

	return pkt, nil
}

func put64(data []byte, index int, n uint64) error{

	if len(data) < index + 8 {
		return fmt.Errorf("payload is less than %s", index + 8)
	}
	binary.BigEndian.PutUint64(data[index:], n)
	return nil
}

func UpdateSeq(data []byte, seq uint64) error {

	return put64(data, SEQ_INDEX, seq)
}

func UpdateSize(data []byte, size int) error {

	return put64(data, SIZE_INDEX, uint64(size))
}

func UpdateArrTime(data []byte, t time.Time) error {

	return put64(data, RECVTS_INDEX, uint64(t.UnixNano()))
}

func UpdateSendTime(data []byte, t time.Time) error {

	return put64(data, SENDTS_INDEX, uint64(t.UnixNano()))
}

