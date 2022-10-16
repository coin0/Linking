package ping

import(
	"time"
	"encoding/binary"
	"fmt"
)

const(
	SEQ_INDEX     = 0
	DUR_INDEX     = 8
	SENDTS_INDEX  = 16
	RESPTS_INDEX  = 24
	RECVTS_INDEX  = 32
	PKT_MIN_SIZE  = 40
)

type packetInfo struct {
	// [seq:8][dur:8][sendts:8][respts:8][recvts:8]

	// sequence number starting from 0
	seq   uint64

	// target packet sending rate
	dur   time.Duration

	// payload size to estimate average bandwidth
	size  int

	// timestamp trackpoints to get RTT
	// client (sendts) -> TURN -> peer (respTs) -> TURN -> client (recvTs)

	// generate sequence and sending time
	sendts time.Time

	// calculate jitter and loss
	respts time.Time

	// calculate jitter RTT and loss
	recvts time.Time
}

func loadInfo(data []byte) (*packetInfo, error) {

	if len(data) < PKT_MIN_SIZE {
		return nil, fmt.Errorf("payload is too short")
	}

	dur := time.Nanosecond * time.Duration(binary.BigEndian.Uint64(data[DUR_INDEX:]))
	n := int64(binary.BigEndian.Uint64(data[SENDTS_INDEX:]))
	sendts := time.Unix(n / 1000000000, n % 1000000000)
	n = int64(binary.BigEndian.Uint64(data[RESPTS_INDEX:]))
	respts := time.Unix(n / 1000000000, n % 1000000000)
	n = int64(binary.BigEndian.Uint64(data[RECVTS_INDEX:]))
	recvts := time.Unix(n / 1000000000, n % 1000000000)

	return &packetInfo{
		seq: 	binary.BigEndian.Uint64(data[SEQ_INDEX:]),
		dur:    dur,
		size:   len(data),
		sendts: sendts,
		respts: respts,
		recvts: recvts,
	}, nil
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

func UpdateDur(data []byte, dur time.Duration) error {

	return put64(data, DUR_INDEX, uint64(dur.Nanoseconds()))
}

func UpdateArrTime(data []byte, t time.Time) error {

	return put64(data, RECVTS_INDEX, uint64(t.UnixNano()))
}

func UpdateSendTime(data []byte, t time.Time) error {

	return put64(data, SENDTS_INDEX, uint64(t.UnixNano()))
}

func UpdateRespTime(data []byte, t time.Time) error {

	return put64(data, RESPTS_INDEX, uint64(t.UnixNano()))
}
