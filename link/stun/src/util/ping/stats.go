package ping

import(
	"fmt"
)

type statistics struct {
	// basic info
	seqMin       uint64
	seqMax       uint64
	samples      uint64
	samplesTotal uint64

	// RTT
	rttMin       int64
	rttMax       int64
	rttAvg       int64
	rttTotal     int64

	// loss
	loss         float64
	loss400      float64
	loss800      float64
	lossTotal    float64

	// jitter
	jitterAvg    int64
	jitter80     int64
	jitter90     int64
	jitter95     int64
	jitter100    int64
	jitterTotal  int64
}

func (s *statistics) String() string {

	return fmt.Sprintf("seq=%d,%d,%d rtt=%d,%d,%d,%d loss=%.2f,%.2f,%.2f,%.2f jitter=%d,%d,%d,%d,%d,%d",
		s.seqMin, s.seqMax, s.samples, s.rttMin / 1000, s.rttAvg / 1000, s.rttMax / 1000,
		s.rttTotal / 1000, s.loss400, s.loss800, s.loss, s.lossTotal, s.jitterAvg / 1000,
		s.jitter80 / 1000, s.jitter90 / 1000, s.jitter95 / 1000, s.jitter100 / 1000,
		s.jitterTotal / 1000,
	)
}
