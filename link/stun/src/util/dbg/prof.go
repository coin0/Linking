package dbg

import (
	"os"
	"sync/atomic"
	. "util/log"
	"runtime/pprof"
	"runtime"
	"fmt"
)

var (
	cpuProfile, memProfile *os.File
	cpuProfStarted, memProfStarted atomic.Bool
)

// -------------------------------------------------------------------------------------------------

func StartCPUProf(output string) error {

	if cpuProfStarted.Swap(true) {
		Warn("debug: cpu profiling already started")
		return fmt.Errorf("already run")
	}

	err := func () error {
		
		cpuProfile, err := os.Create(output)
		if err != nil {
			Error("debug: could not create CPU profile: %s", err)
			return err
		}
	
		if err = pprof.StartCPUProfile(cpuProfile); err != nil {
			Error("debug: could not start CPU profile: ", err)
			return err
		}

		return nil
	}()
	if err != nil {
		cpuProfStarted.Store(false)
	}
	Warn("debug: cpu profiling is running...")

	return err
}

func StopCPUProf() error {

	if !cpuProfStarted.Swap(false) {
		Warn("debug: cpu profiling already stopped")
		return fmt.Errorf("already stopped")
	}

	pprof.StopCPUProfile()
	cpuProfile.Close()

	return nil
}

func IsCPUProfStarted() bool {

	return cpuProfStarted.Load()
}

func StartMemProf(output string) error {

	if memProfStarted.Swap(true) {
		Warn("debug: memory profiling already started")
		return fmt.Errorf("already run")
	}

	err := func () error {
		memProfile, err := os.Create(output)
		if err != nil {
			Error("debug: could not create memory profile: ", err)
			return err
		}

		runtime.GC()

		if err = pprof.WriteHeapProfile(memProfile); err != nil {
			Error("debug: could not write memory profile: ", err)
			return err
		}

		return nil
	}()
	if err != nil {
		memProfStarted.Store(false)
	}
	Warn("debug: memory profiling is running...")

	return err
}

func StopMemProf() error {

	if !memProfStarted.Swap(false) {
		Warn("debug: memory profiling already stopped")
		return fmt.Errorf("already stopped")
	}

	memProfile.Close()

	return nil
}

func IsMemProfStarted() bool {

	return memProfStarted.Load()
}
