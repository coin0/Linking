package log

import (
	"time"
	"sync"
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
	rotationLck = &sync.Mutex{}
)

func SetRotation(maxsize, maxnum int) error {

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

			// ensure out dated log file must be removed before new archive is created
			Retain(maxnum)

			// roll an archive and delete original copy
			Rotate()
		}
	}()

	return nil
}

func Rotate() {

	// switch output to a memory buffer
	prev := ""
	if logFile != nil {
		prev = logFile.Name()
	}
	setLog(genFilename(logPath, "log"))

	// archive previous log file
	if err := compressTarDotGz(prev, prev + ".tar.gz"); err != nil {
		Error("logger: archive: %s", err)
	}
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
