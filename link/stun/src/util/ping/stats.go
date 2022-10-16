package ping

import(
	"fmt"
)

type stats struct {
	// basic info
	seqMin       uint64
	seqMax       uint64
	samples      int

	// RTT
	rttMin       int64
	rttMax       int64
	rttAvg       int64

	// loss
	loss         float64
	loss400      float64
	loss800      float64

	// jitter
	jitterAvg    int64
	jitter80     int64
	jitter90     int64
	jitter95     int64
	jitter100    int64
}

func (s *stats) String() string {

	return fmt.Sprintf("seq=%d,%d,%d rtt=%d,%d,%d loss=%.2f,%.2f,%.2f jitter=%d,%d,%d,%d,%d",
		s.seqMin, s.seqMax, s.samples, s.rttMin, s.rttAvg, s.rttMax, s.loss400, s.loss800, s.loss,
		s.jitterAvg, s.jitter80, s.jitter90, s.jitter95, s.jitter100,
	)
}
