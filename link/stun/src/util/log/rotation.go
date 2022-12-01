package log

import (
	"time"
	"sync"
	"sync/atomic"
	"archive/tar"
	"compress/gzip"
	"fmt"
	"os"
	"io"
)

const (
	LOG_ROTATION_CHECK_INTERVAL = 10 // seconds
)

var (
	rotateIndex atomic.Uint32
	rotationLck = &sync.Mutex{}
)

func SetRotation(maxsize int) error {

	// disable rotation
	if maxsize <= 0 {
		return fmt.Errorf("logger: rotation disabled")
	}

	if !rotationLck.TryLock() {
		return fmt.Errorf("logger: already run")
	}

	go func() {
		defer rotationLck.Unlock()
		ticker := time.NewTicker(time.Second * LOG_ROTATION_CHECK_INTERVAL)
		for range ticker.C {
			// check file status and size
			if logFile == nil {
				continue
			} else if f, err := logFile.Stat(); err != nil {
				continue
			} else if f.Size() < int64(maxsize) {
				continue
			}

			now := time.Now()
			Rotate(logPath + fmt.Sprintf(
				"_%d%02d%02d_%02d%02d%02d.tar.gz",
				now.Year(), now.Month(), now.Day(),
				now.Hour(), now.Minute(), now.Second(),
			))
		}
	}()

	return nil
}

func Rotate(archive string) {

	// switch output to a memory buffer
	setLog("")

	// wait until original log file is renamed
	wg := &sync.WaitGroup{}
	wg.Add(1)

	go func() {

		i := rotateIndex.Add(1)
		npath := fmt.Sprintf("%s_%d", logPath, i)
		func() {
			defer wg.Done()
			if err := os.Rename(logPath, npath); err != nil {
				Error("logger: could not rename %s to %s: %s", logPath, npath, err)
				return
			}
		}()

		compressTarDotGz(npath, archive)
	}()

	// create new log file and switch output back to file
	wg.Wait()
	os.Remove(logPath)
	setLog(logPath)
}

func compressTarDotGz(path, archive string) error {

	ar, err := os.Create(archive)
	if err != nil {
		return fmt.Errorf("create archive: %s", err)
	}
	defer ar.Close()

	gw := gzip.NewWriter(ar)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	// open target file
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open file %s: %s", path, err)
	}

	// get file status to verify if it's open
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("not a valid file %s: %s", path, err)
	}

	// create a tar header
	header, err := tar.FileInfoHeader(info, info.Name())
	if err != nil {
		return fmt.Errorf("create tar header: %s", err)
	}
	header.Name = path

	// write tar header
	err = tw.WriteHeader(header)
	if err != nil {
		return fmt.Errorf("write tar header: %s", err)
	}

	// copy file contents to tar writer
	io.Copy(tw, f)

	// delete original file
	f.Close()
	os.Remove(path)

	return nil
}
