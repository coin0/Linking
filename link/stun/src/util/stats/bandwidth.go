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

	// store previous total I/O traffic at interval
	interval    time.Duration   // seconds
	prevIn      int64
	prevOut     int64

	ech         chan error
	wg          *sync.WaitGroup
	once        sync.Once

	// callback function to get called regularly
	callback    bandwidthCB
	callbackLck *sync.Mutex
}

func NewBandwidth(interval time.Duration, cb bandwidthCB) *Bandwidth {

	return &Bandwidth{
		interval: interval,
		ech: make(chan error),
		wg: &sync.WaitGroup{},
		callback: cb,
		callbackLck: &sync.Mutex{},
	}
}

func (bw *Bandwidth) In(n int) {

	bw.iBytes.Add(int64(n))
}

func (bw *Bandwidth) Out(n int) {

	bw.oBytes.Add(int64(n))
}

func (bw *Bandwidth) Sum() (int64, int64) {

	return bw.iBytes.Load(), bw.oBytes.Load()
}

func (bw *Bandwidth) SetCallback(cb bandwidthCB) {

	bw.callbackLck.Lock()
	defer bw.callbackLck.Unlock()

	bw.callback = cb
}

func (bw *Bandwidth) Start() {

	bw.once.Do(func() {

		go func() {
			bw.wg.Add(1)
			defer bw.wg.Done()
			for {
				ticker := time.NewTicker(bw.interval)
				select {
				case <-ticker.C:
					in := bw.iBytes.Load()
					out := bw.oBytes.Load()

					// invoke callback function
					bw.callbackLck.Lock()
					if bw.callback != nil {
						bw.callback(in - bw.prevIn, out - bw.prevOut)
					}
					bw.callbackLck.Unlock()

					// save I/O traffic statistics
					bw.prevIn = in
					bw.prevOut = out
				case <-bw.ech:
					return
				}
			}
		}()
	})
}

func (bw *Bandwidth) Stop() {

	bw.ech <- fmt.Errorf("intentional stop")
	bw.wg.Wait()
	bw.once = sync.Once{}
}
