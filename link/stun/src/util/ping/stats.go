package ping

import(
	"fmt"
	"math"
)

// to differentiate average stats for short term interval and whole session
// xxxAvg refers to calculated mean value for current interval
// xxxTotal refers to the mean value calculated for the whole session

type statistics struct {
	index        int64

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

	// IO
	bps          int64
	bpsTotal     int64
	sCounts      int64
	sCountsTotal int64
	rCounts      int64
	rCountsTotal int64
	bytes        int64
	bytesTotal   int64

	// jitter
	jitterAvg    int64
	jitter80     int64
	jitter90     int64
	jitter95     int64
	jitter100    int64
	jitterTotal  int64
}

func (s *statistics) String() string {

	if s.sCounts == 0 || s.sCountsTotal == 0 {
		return fmt.Sprintf(
			"%d rx=%d,%d(kbps) seq=N/A rtt=N/A loss=N/A jitter=N/A",
			s.index,
			s.bps / 1024, s.bpsTotal / 1024,
		)
	}

	// calculate loss ratio
	loss := 100 - math.Min(100, float64(s.rCounts) * 100 / float64(s.sCounts))
	lossTotal := 100 - math.Min(100, float64(s.rCountsTotal) * 100 / float64(s.sCountsTotal))

	if s.rttMin < 0 || s.rttMax < 0 || s.rttAvg < 0 {
		return fmt.Sprintf(
			"%d rx=%d,%d(kbps) seq=N/A rtt=N/A loss=%.2f,%.2f(%%) jitter=N/A",
			s.index,
			s.bps / 1024, s.bpsTotal / 1024,
			loss, lossTotal,
		)
	} else {
		return fmt.Sprintf(
			"%d rx=%d,%d(kbps) seq=%d,%d,%d rtt=%d,%d,%d,%d(us) loss=%.2f,%.2f(%%) jitter=%d,%d,%d,%d,%d,%d(us)",
			s.index,
			s.bps / 1024, s.bpsTotal / 1024,
			s.seqMin, s.seqMax, s.samples,
			s.rttMin / 1000, s.rttAvg / 1000, s.rttMax / 1000, s.rttTotal / 1000,
			loss, lossTotal,
			s.jitterAvg / 1000, s.jitter80 / 1000, s.jitter90 / 1000, s.jitter95 / 1000,
			s.jitter100 / 1000, s.jitterTotal / 1000,
		)
	}
}
