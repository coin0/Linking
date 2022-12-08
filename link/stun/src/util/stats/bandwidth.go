package stats

import(
	"sync/atomic"
	"sync"
	"time"
	"fmt"
)

type bandwidthCB func(int64, int64)

type Bandwidth struct {
	iBytes      atomic.Int64    // bytes
	oBytes      atomic.Int64    // bytes
	interval    time.Duration   // seconds
	ech         chan error
	wg          *sync.WaitGroup
	once        sync.Once
	callback    bandwidthCB
}

func NewBandwidth(interval time.Duration, cb bandwidthCB) *Bandwidth {

	return &Bandwidth{
		interval: interval,
		ech: make(chan error),
		wg: &sync.WaitGroup{},
		callback: cb,
	}
}

func (bw *Bandwidth) In(n int) {

	bw.iBytes.Add(int64(n))
}

func (bw *Bandwidth) Out(n int) {

	bw.oBytes.Add(int64(n))
}

func (bw *Bandwidth) Start() {

	run := func() {

		bw.wg.Add(1)
		defer bw.wg.Done()
		for {
			ticker := time.NewTicker(bw.interval)
			select {
			case <-ticker.C:
				if bw != nil {
					bw.callback(bw.iBytes.Swap(0), bw.oBytes.Swap(0))
				}
			case <-bw.ech:
				return
			}
		}
	}

	bw.once.Do(func(){ go run() })
}

func (bw *Bandwidth) Stop() {

	bw.ech <- fmt.Errorf("intentional stop")
	bw.wg.Wait()
}
