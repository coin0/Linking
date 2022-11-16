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
	DebugOn    bool

	// statistics
	stats      *statistics

	// analyze ping packet cached in buffer at specific interval
	cycle      time.Duration
	cycleTkr   *time.Ticker

	// buffer to cache ping packet meta info
	buffer     []*packetInfo
	bufferLck  *sync.Mutex
	// effective sent pkt count with respective seq
	seqHistory  map[uint64]*packetInfo
	seqSent     int64
	seqRecv     int64
	// for TCP we shall cache payload when input is not a complete packet
	sendBuf     []byte
	recvBuf     []byte

	// send and receive count (dup or invalid pkt might be included)
	sendCounts  int64
	recvCounts  int64
	sendBytes   int64
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
		stats:      &statistics{},
		cycle:      cycle,
		cycleTkr:   time.NewTicker(cycle),
		buffer:     []*packetInfo{},
		bufferLck:  &sync.Mutex{},
		seqHistory: map[uint64]*packetInfo{},
		sendBuf:    []byte{},
		recvBuf:    []byte{},
		opLck:      &sync.Mutex{},
		wg:         &sync.WaitGroup{},
		ech:        make(chan byte),
		running:    false,
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
					if meter.DebugOn {
						fmt.Println(stat)
					}
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

	atomic.AddInt64(&meter.sendBytes, int64(len(data)))

	meter.bufferLck.Lock()
	defer meter.bufferLck.Unlock()

	// for TCP stream we shall  append previous cached incomplete payload
	// to the beginning of current input data
	if len(meter.sendBuf) > 0 {
		data = append(meter.sendBuf, data...)
	}

	offset := 0
	for {
		info, err := loadInfo(data[offset:])
		if err != nil {
			// cache payloads for incomplete packets
			meter.sendBuf = data[offset:]
			break
		}
		// now we've sent a complete packet
		atomic.AddInt64(&meter.sendCounts, 1)
		meter.sendBuf = []byte{}
		offset += int(info.size)

		if _, ok := meter.seqHistory[info.seq]; !ok {
			info.status = PKT_SENT
			meter.seqHistory[info.seq] = info
		}
	}

	return nil
}

func (meter *trafficMeter) Receive(data []byte) error {

	return meter.ReceiveWithTime(data, time.Time{})
}

func (meter *trafficMeter) ReceiveWithTime(data []byte, ts time.Time) error {

	// traffic throughput
	atomic.AddInt64(&meter.recvBytes, int64(len(data)))

	meter.bufferLck.Lock()
	defer meter.bufferLck.Unlock()

	if len(meter.recvBuf) > 0 {
		data = append(meter.recvBuf, data...)
	}

	offset := 0
	for {
		info, err := loadInfo(data[offset:])
		if err != nil {
			meter.recvBuf = data[offset:]
			break
		}

		// tcp stream would receive multiple packets once
		// use ReciveWithTime() instead
		if !ts.IsZero() {
			// update arrival time only when a complete packet is received
			UpdateArrTime(data[offset:], ts)
			info, _ = loadInfo(data[offset:])
		}

		// now we've received a complete packet, clear recvBuf and move offset cursor
		atomic.AddInt64(&meter.recvCounts, 1)
		meter.recvBuf = []byte{}
		offset += int(info.size)

		meter.buffer = append(meter.buffer, info)
		if _, ok := meter.seqHistory[info.seq]; !ok {
			info.status = PKT_OBSOLETE
		} else {
			if meter.seqHistory[info.seq].status == PKT_RECV {
				Verbose("packet with duplicated sequence number %d", info.seq)
			} else {
				info.status = PKT_RECV
			}
		}
		meter.seqHistory[info.seq] = info
	}

	return nil
}

func (meter *trafficMeter) analyze() (*statistics, error) {

	meter.bufferLck.Lock()
	defer meter.bufferLck.Unlock()

	now := time.Now()

	// accumulate sequence statistics for accurate loss ratio calculation
	meter.stats.seqSent, meter.stats.seqRecv, meter.stats.seqObsolete = 0, 0, 0
	for k, v := range meter.seqHistory {
		if v.sendts.Before(now.Add(-meter.cycle)) {
			switch v.status {
			case PKT_SENT: meter.stats.seqSent++
			case PKT_RECV: meter.stats.seqRecv++
			case PKT_OBSOLETE: meter.stats.seqObsolete++
			default:
			}
			delete(meter.seqHistory, k)
		}
	}
	meter.stats.seqSentTotal += meter.stats.seqSent
	meter.stats.seqRecvTotal += meter.stats.seqRecv
	meter.stats.seqObsoTotal += meter.stats.seqObsolete

	// sort by sendts in ascending order
	sort.Slice(meter.buffer, func(i, j int) bool {

		return meter.buffer[i].seq < meter.buffer[j].seq
	})

	// we only analyze packets of recvts < now - cycle
	list := []*packetInfo{}
	end := -1
	for i, v := range meter.buffer {
		end = i
		if v.sendts.After(now.Add(-meter.cycle)) {
			break
		}
	}
	if end >= 0 {
		list = meter.buffer[0:end]
		meter.buffer = meter.buffer[end+1:]
	} else {
		// if buffer is empty just return nil list
		return meter.getStats(nil)
	}

	return meter.getStats(list)
}

func (meter *trafficMeter) getStats(list []*packetInfo) (*statistics, error) {

	// reset throughput and packet count and update io stats
	meter.stats.rBytes = atomic.SwapInt64(&meter.recvBytes, 0)
	meter.stats.sBytes = atomic.SwapInt64(&meter.sendBytes, 0)
	meter.stats.rCounts = atomic.SwapInt64(&meter.recvCounts, 0)
	meter.stats.sCounts = atomic.SwapInt64(&meter.sendCounts, 0)

	meter.stats.rBytesTotal += meter.stats.rBytes
	meter.stats.sBytesTotal += meter.stats.sBytes
	meter.stats.rCountsTotal += meter.stats.rCounts
	meter.stats.sCountsTotal += meter.stats.sCounts

	meter.stats.rBps = meter.stats.rBytes * 8 / int64(meter.cycle.Seconds())
	meter.stats.rBpsTotal = meter.stats.rBytesTotal * 8 / int64(meter.cycle.Seconds()) / (meter.stats.index + 1)

	meter.stats.sBps = meter.stats.sBytes * 8 / int64(meter.cycle.Seconds())
	meter.stats.sBpsTotal = meter.stats.sBytesTotal * 8 / int64(meter.cycle.Seconds()) / (meter.stats.index + 1)

	meter.stats.index++

	if list == nil || len(list) == 0 {
		// set a nagative value to ignore quality stats
		meter.stats.rttMax = -1

		return meter.stats, nil
	}

	// sort by sequence in ascending order
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
