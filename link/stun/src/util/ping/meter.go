package ping

import(
	"time"
	"sync"
	"fmt"
	"sort"
	. "util/log"
)

type trafficMeter struct {
	// analyze ping packet cached in buffer at specific interval
	cycle      time.Duration
	cycleTkr   *time.Ticker

	// buffer to cache ping packet meta info
	buffer     []*packetInfo
	bufferLck  *sync.Mutex

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

func (meter *trafficMeter) Read(data []byte) error {

	if info, err := loadInfo(data); err != nil {
		return err
	} else {
		meter.bufferLck.Lock()
		defer meter.bufferLck.Unlock()

		meter.buffer = append(meter.buffer, info)
		return nil
	}
}

func (meter *trafficMeter) analyze() (*stats, error) {

	meter.bufferLck.Lock()
	defer meter.bufferLck.Unlock()

	if len(meter.buffer) == 0 {
		return nil, fmt.Errorf("empty buffer")
	}

	now := time.Now()
	list := []*packetInfo{}
	maxSeq := uint64(0)
	minSend := meter.buffer[0].sendts

	// sort by recvts in ascending order
	sort.Slice(meter.buffer, func(i, j int) bool {

		return meter.buffer[i].recvts.Before(meter.buffer[j].recvts)
	})
	// we only analyze packets of recvts < now - cycle
	end := -1
	for i, v := range meter.buffer {
		if v.recvts.Before(now.Add(-meter.cycle)) {
			end = i
			if v.sendts.Before(minSend) {
				minSend = v.sendts
			}
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
			if v.sendts.Before(minSend) {
				minSend = v.sendts
			}
		} else {
			break
		}
	}
	if end >= 0 {
		list = append(list, meter.buffer[0:end]...)
		meter.buffer = meter.buffer[end+1:]
	}

	return getStats(list, minSend)
}

func getStats(list []*packetInfo, minSend time.Time) (*stats, error) {

	if len(list) < 10 {
		return nil, fmt.Errorf("insufficient packets")
	}

	minSeq := list[0].seq
	maxSeq := minSeq

	minRtt := list[0].recvts.UnixNano() - list[0].sendts.UnixNano()
	maxRtt := minRtt
	avgRtt, totalRtt := int64(0), int64(0)

	jitters := []int64{}
	minBase := list[0].recvts.UnixNano() - (list[0].sendts.UnixNano() - minSend.UnixNano())

	// get max and min sequence and rtt
	// collect jitters
	for _, v := range list {
		if v.seq > maxSeq {
			maxSeq = v.seq
		} else if v.seq < minSeq {
			minSeq = v.seq
		}

		rtt := v.recvts.UnixNano() - v.sendts.UnixNano()
		totalRtt += rtt
		if rtt > maxRtt {
			maxRtt = rtt
		} else if rtt < minRtt {
			minRtt = rtt
		}

		base := v.recvts.UnixNano() - (v.sendts.UnixNano() - minSend.UnixNano())
		if base < minBase {
			minBase = base
		}
		jitters = append(jitters, base)
	}
	avgRtt = totalRtt / int64(len(list))

	// sort by jitters in ascending order
	sort.Slice(jitters, func(i, j int) bool {

		return jitters[i] < jitters[j]
	})

	jitter400, jitter800 := uint64(0), uint64(0)
	totalJitters := int64(0)

	// calculate loss rate according to jitter value
	for i, v := range jitters {
		jitters[i] = v - minBase
		if jitters[i] >= (time.Millisecond * 800).Nanoseconds() {
			jitter400++
			jitter800++
		} else if jitters[i] >= (time.Millisecond * 400).Nanoseconds() {
			jitter400++
		}
		totalJitters += jitters[i]
	}

	total := maxSeq - minSeq + 1

	return &stats{
		rttMin: minRtt,
		rttMax: maxRtt,
		rttAvg: avgRtt,

		loss:    float64((total - uint64(len(jitters))) * 100.0 / total),
		loss400: float64(jitter400 * 100.0 / total),
		loss800: float64(jitter800 * 100.0 / total),

		jitterAvg: totalJitters / int64(len(jitters)),
		jitter80:  jitters[len(jitters) * 80 / 100],
		jitter90:  jitters[len(jitters) * 90 / 100],
		jitter95:  jitters[len(jitters) * 95 / 100],
		jitter100: jitters[len(jitters) - 1],
	}, nil
}
