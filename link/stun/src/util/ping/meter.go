package ping

import(
	"time"
	"sync"
	"fmt"
	"sort"
	"sync/atomic"
	. "util/log"
	"math"
)

type trafficMeter struct {
	// statistics
	stats      *statistics

	// analyze ping packet cached in buffer at specific interval
	cycle      time.Duration
	cycleTkr   *time.Ticker

	// buffer to cache ping packet meta info
	buffer     []*packetInfo
	bufferLck  *sync.Mutex

	// send count
	sendCounts  int64
	recvCounts  int64
	recvBytes   int64

	// lock for start() and stop()
	opLck      *sync.Mutex
	// set true after start() gets called and false when routine exits
	running    bool

	// stop should wait for routine to exit
	wg         *sync.WaitGroup
	// notify routine to exit
	ech        chan byte
}

func NewMeter(cycle time.Duration) *trafficMeter {

	newMeter := &trafficMeter{
		stats:     &statistics{},
		cycle:     cycle,
		cycleTkr:  time.NewTicker(cycle),
		buffer:    []*packetInfo{},
		bufferLck: &sync.Mutex{},
		opLck:     &sync.Mutex{},
		wg:        &sync.WaitGroup{},
		ech:       make(chan byte),
		running:   false,
	}

	newMeter.Start()

	return newMeter
}

func (meter *trafficMeter) Start() error {

	meter.opLck.Lock()
	defer meter.opLck.Unlock()

	if meter.running {
		return fmt.Errorf("already run")
	}

	meter.wg.Add(1)
	go func(m *trafficMeter) {

		m.running = true
		defer func(){
			m.wg.Done()
			m.running = false
		}()
		for {
			select {
			case <-m.cycleTkr.C:
				if stat, err := m.analyze(); err != nil {
					Error("analyze(): %s", err.Error())
				} else {
					Info("stats: %s", stat)
				}
			case <-m.ech:
				// exit go routine
				return
			}
		}
	}(meter)

	return nil
}

func (meter *trafficMeter) Stop() error {

	meter.opLck.Lock()
	defer meter.opLck.Unlock()

	if !meter.running {
		return fmt.Errorf("not running")
	}

	meter.ech <- 0
	meter.wg.Wait()

	return nil
}

func (meter *trafficMeter) Send(data []byte) error {

	atomic.AddInt64(&meter.sendCounts, 1)

	return nil
}

func (meter *trafficMeter) Receive(data []byte) error {

	// traffic throughput
	atomic.AddInt64(&meter.recvBytes, int64(len(data)))
	atomic.AddInt64(&meter.recvCounts, 1)

	if info, err := loadInfo(data); err != nil {
		return err
	} else {
		meter.bufferLck.Lock()
		defer meter.bufferLck.Unlock()

		meter.buffer = append(meter.buffer, info)
		return nil
	}
}

func (meter *trafficMeter) analyze() (*statistics, error) {

	meter.bufferLck.Lock()
	defer meter.bufferLck.Unlock()

	// if buffer is empty just return nil list
	if len(meter.buffer) == 0 {
		return meter.getStats(nil)
	}

	now := time.Now()
	list := []*packetInfo{}
	maxSeq := uint64(0)

	// sort by recvts in ascending order
	sort.Slice(meter.buffer, func(i, j int) bool {

		return meter.buffer[i].recvts.Before(meter.buffer[j].recvts)
	})
	// we only analyze packets of recvts < now - cycle
	end := -1
	for i, v := range meter.buffer {
		if v.recvts.Before(now.Add(-meter.cycle)) {
			end = i
		} else {
			break
		}
	}
	if end >= 0 {
		maxSeq = meter.buffer[end].seq
		list = meter.buffer[0:end+1]
		meter.buffer = meter.buffer[end+1:]
	}

	// sort by seq in ascending order
	sort.Slice(meter.buffer, func(i, j int) bool {

		return meter.buffer[i].seq < meter.buffer[j].seq
	})
	// include extra packets of seq < maxSeq
	end = -1
	for i, v := range meter.buffer {
		if v.seq < maxSeq {
			end = i
		} else {
			break
		}
	}
	if end >= 0 {
		list = append(list, meter.buffer[0:end]...)
		meter.buffer = meter.buffer[end+1:]
	}

	return meter.getStats(list)
}

func (meter *trafficMeter) getStats(list []*packetInfo) (*statistics, error) {

	// reset throughput and packet count and update io stats
	meter.stats.bytes = atomic.SwapInt64(&meter.recvBytes, 0)
	meter.stats.rCounts = atomic.SwapInt64(&meter.recvCounts, 0)
	meter.stats.sCounts = atomic.SwapInt64(&meter.sendCounts, 0)

	meter.stats.bytesTotal += meter.stats.bytes
	meter.stats.rCountsTotal += meter.stats.rCounts
	meter.stats.sCountsTotal += meter.stats.sCounts

	meter.stats.bps = meter.stats.bytes * 8 / int64(meter.cycle.Seconds())
	meter.stats.bpsTotal = meter.stats.bytesTotal * 8 / int64(meter.cycle.Seconds()) / (meter.stats.index + 1)

	meter.stats.loss = 1.0 - math.Min(1.0, float64(meter.stats.rCounts) / float64(meter.stats.sCounts))
	meter.stats.lossTotal = 1.0 - math.Min(1.0, float64(meter.stats.rCountsTotal) / float64(meter.stats.sCountsTotal))

	meter.stats.index++

	if list == nil || len(list) == 0 {
		// set a nagative value to ignore quality stats
		meter.stats.rttMax = -1

		return meter.stats, nil
	}

	// sort by sequence
	sort.Slice(list, func(i, j int) bool {

		return list[i].seq < list[j].seq
	})

	minSeq := list[0].seq
	maxSeq := list[len(list)-1].seq

	minRtt := list[0].recvts.UnixNano() - list[0].sendts.UnixNano()
	maxRtt, lastRtt := minRtt, minRtt
	avgRtt, totalRtt := int64(0), int64(0)

	jitters := []int64{}
	totalJitters := int64(0)

	// get max and min sequence, rtt and collect jitters
	for _, v := range list {
		// get rtt
		rtt := v.recvts.UnixNano() - v.sendts.UnixNano()
		totalRtt += rtt
		if rtt > maxRtt {
			maxRtt = rtt
		} else if rtt < minRtt {
			minRtt = rtt
		}


		// sum up jitters
		jitter := int64(math.Abs(float64(rtt - lastRtt)))
		totalJitters += jitter
		jitters = append(jitters, jitter)
		lastRtt = rtt
	}
	avgRtt = totalRtt / int64(len(list))

	// sort by jitters in ascending order
	sort.Slice(jitters, func(i, j int) bool {

		return jitters[i] < jitters[j]
	})

	meter.stats.seqMin = minSeq
	meter.stats.seqMax = maxSeq
	meter.stats.samples = uint64(len(jitters))

	meter.stats.rttMin = minRtt
	meter.stats.rttMax = maxRtt
	meter.stats.rttAvg = avgRtt

	meter.stats.jitterAvg = totalJitters / int64(len(jitters))
	meter.stats.jitter80 = jitters[len(jitters) * 80 / 100]
	meter.stats.jitter90 = jitters[len(jitters) * 90 / 100]
	meter.stats.jitter95 =  jitters[len(jitters) * 95 / 100]
	meter.stats.jitter100 = jitters[len(jitters) - 1]

	// get total statistics for the whole session
	newSampleSum := meter.stats.samplesTotal + meter.stats.samples

	meter.stats.rttTotal = (meter.stats.rttTotal * int64(meter.stats.samplesTotal) + totalRtt) / int64(newSampleSum)
	meter.stats.jitterTotal = (meter.stats.jitterTotal * int64(meter.stats.samplesTotal) + totalJitters) / int64(newSampleSum)
	meter.stats.samplesTotal = newSampleSum

	return meter.stats, nil
}
