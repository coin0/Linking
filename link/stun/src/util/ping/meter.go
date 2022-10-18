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

	// downlink throughput in bytes
	throughput int64
	count      int64

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
					Info("pingstats: %s", stat)
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

func (meter *trafficMeter) Read(data []byte) error {

	// traffic throughput
	atomic.AddInt64(&meter.throughput, int64(len(data)))
	atomic.AddInt64(&meter.count, 1)

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

	// reset throughput
	throughput := atomic.SwapInt64(&meter.throughput, 0)
	count := atomic.SwapInt64(&meter.count, 0)
	Info("iostats: downlink=%d kbps, pkt_count=%d",
		throughput * 8 / 1024 / (meter.cycle.Milliseconds() / 1000), count)

	meter.bufferLck.Lock()
	defer meter.bufferLck.Unlock()

	if len(meter.buffer) == 0 {
		return nil, fmt.Errorf("empty buffer")
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

	if len(list) == 0 {
		return nil, fmt.Errorf("insufficient packets")
	}

	// sort by sequence
	sort.Slice(list, func(i, j int) bool {

		return list[i].seq < list[j].seq
	})

	minSeq := list[0].seq
	maxSeq := list[len(list)-1].seq
	total := maxSeq - minSeq + 1

	minRtt := list[0].recvts.UnixNano() - list[0].sendts.UnixNano()
	maxRtt, lastRtt := minRtt, minRtt
	avgRtt, totalRtt := int64(0), int64(0)

	jitters := []int64{}
	jitter400, jitter800 := uint64(0), uint64(0)
	totalJitters := int64(0)

	// get max and min sequence, rtt and collect jitters
	for _, v := range list {
		rtt := v.recvts.UnixNano() - v.sendts.UnixNano()
		totalRtt += rtt
		if rtt > maxRtt {
			maxRtt = rtt
		} else if rtt < minRtt {
			minRtt = rtt
		}

		jitter := int64(math.Abs(float64(rtt - lastRtt)))
		if jitter < (time.Millisecond * 400).Nanoseconds() {
			jitter400++
			jitter800++
		} else if jitter < (time.Millisecond * 800).Nanoseconds() {
			jitter800++
		}
		totalJitters += jitter
		jitters = append(jitters, jitter)
		lastRtt = rtt
	}
	avgRtt = totalRtt / int64(len(list))

	// sort by jitters in ascending order
	sort.Slice(jitters, func(i, j int) bool {

		return jitters[i] < jitters[j]
	})


	stats := &statistics{
		seqMin:  minSeq,
		seqMax:  maxSeq,
		samples: uint64(len(jitters)),

		rttMin: minRtt,
		rttMax: maxRtt,
		rttAvg: avgRtt,

		loss:    float64((total - uint64(len(jitters))) * 100.0 / total),
		loss400: float64((total - jitter400) * 100.0 / total),
		loss800: float64((total - jitter800) * 100.0 / total),

		jitterAvg: totalJitters / int64(len(jitters)),
		jitter80:  jitters[len(jitters) * 80 / 100],
		jitter90:  jitters[len(jitters) * 90 / 100],
		jitter95:  jitters[len(jitters) * 95 / 100],
		jitter100: jitters[len(jitters) - 1],
	}

	// get total statistics for the whole session
	newSampleSum := meter.stats.samplesTotal + stats.samples
	stats.rttTotal = (meter.stats.rttTotal * int64(meter.stats.samplesTotal) + totalRtt) / int64(newSampleSum)
	stats.lossTotal = (meter.stats.lossTotal * float64(meter.stats.samplesTotal) +
		stats.loss * float64(stats.samples)) / float64(newSampleSum)
	stats.jitterTotal = (meter.stats.jitterTotal * int64(meter.stats.samplesTotal) + totalJitters) / int64(newSampleSum)
	stats.samplesTotal = newSampleSum

	// update new stats for the meter
	meter.stats = stats

	return stats, nil
}
