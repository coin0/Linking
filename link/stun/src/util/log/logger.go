package log

import (
	"log"
	"os"
	"io"
	"sync"
	"fmt"
	"time"
)

const (
	LEVEL_VERB   = 90
	LEVEL_DEBUG  = 80
	LEVEL_INFO   = 70
	LEVEL_WARN   = 60
	LEVEL_ERROR  = 50
	LEVEL_FATAL  = 40
	LEVEL_PANIC  = 30
)

var (
	panicL *log.Logger
	fatalL *log.Logger
	errorL *log.Logger
	warnL  *log.Logger
	infoL  *log.Logger
	debugL *log.Logger
	verbL  *log.Logger

	logLevel  int
	logPath   string
	logFile   *os.File
	logBuffer = newMemBuffer()
	logMutex = &sync.RWMutex{}
)

type memBuffer struct {
	slices    []byte
	mutex     *sync.Mutex
}

// -------------------------------------------------------------------------------------------------

func newMemBuffer() *memBuffer {

	return &memBuffer{
		// reserve 10 MB
		slices: make([]byte, 0, 1024 * 1024 * 10),
		mutex: &sync.Mutex{},
	}
}

func (buf *memBuffer) Write(p []byte) (int, error) {

	buf.mutex.Lock()
	defer buf.mutex.Unlock()

	buf.slices = append(buf.slices, p...)
	return len(p), nil
}

func (buf *memBuffer) flush(out io.Writer) (n int, err error) {

	buf.mutex.Lock()
	defer buf.mutex.Unlock()

	n, err = out.Write(buf.slices)
	buf.slices = []byte{}

	return
}

// -------------------------------------------------------------------------------------------------

func SetLog(path string) {

	// save original log file path
	logPath = path

	// check if target file exists otherwise create a new file
	fname := ""
	if curr, err := os.Readlink(path); err != nil {
		fname = genFilename(path, "log")
	} else {
		fname = curr
	}

	if err := setLog(fname); err != nil {
		Info("logger: buffer output begins...")
	} else {
		Info("logger: file %s begins...", path)
	}
}

func genFilename(p, s string) string {

	now := time.Now()
	return fmt.Sprintf(
		"%s_%d%02d%02d_%02d%02d%02d.%s",
		p,
		now.Year(), now.Month(), now.Day(),
		now.Hour(), now.Minute(), now.Second(),
		s,
	)
}

func setLog(path string) (err error) {

	logMutex.Lock()
	defer logMutex.Unlock()

	if logFile != nil {
		logFile.Close()
	}

	var output io.Writer
	if logFile, err = os.OpenFile(path, os.O_WRONLY | os.O_CREATE | os.O_APPEND, 0644); err != nil {
		output = logBuffer
		defer func() {
			if logFile != nil {
				logFile.Close()
			}
		}()
	} else {
		// create a symbolic link to current log file
		os.Remove(logPath)
		os.Symlink(path, logPath)

		// redirect output to current fd
		output = logFile
		defer logBuffer.flush(output)
	}

	panicL = log.New(output, "[P] ", log.LstdFlags | log.Lmicroseconds)
	fatalL = log.New(output, "[F] ", log.LstdFlags | log.Lmicroseconds)
	errorL = log.New(output, "[E] ", log.LstdFlags | log.Lmicroseconds)
	warnL = log.New(output, "[W] ", log.LstdFlags | log.Lmicroseconds)
	infoL = log.New(output, "[I] ", log.LstdFlags | log.Lmicroseconds)
	debugL = log.New(output, "[D] ", log.LstdFlags | log.Lmicroseconds)
	verbL = log.New(output, "[V] ", log.LstdFlags | log.Lmicroseconds)

	return err
}

func SetLevel(level int) {

	logLevel = level
}

func Panic(format string, v ...any) {

	logMutex.RLock()
	defer logMutex.RUnlock()

	panicL.Panicf(format, v...)
}

func Fatal(format string, v ...any) {

	logMutex.RLock()
	defer logMutex.RUnlock()

	fmt.Printf(format + "\n", v...)
	fatalL.Fatalf(format, v...)
}

func Error(format string, v ...any) {

	logMutex.RLock()
	defer logMutex.RUnlock()

	errorL.Printf(format, v...)
}

func Warn(format string, v ...any) {

	logMutex.RLock()
	defer logMutex.RUnlock()

	warnL.Printf(format, v...)
}

func Info(format string, v ...any) {

	logMutex.RLock()
	defer logMutex.RUnlock()

	infoL.Printf(format, v...)
}

func Debug(format string, v ...any) {

	logMutex.RLock()
	defer logMutex.RUnlock()

	if logLevel >= LEVEL_DEBUG {
		debugL.Printf(format, v...)
	}
}

func Verbose(format string, v ...any) {

	logMutex.RLock()
	defer logMutex.RUnlock()

	if logLevel >= LEVEL_VERB {
		verbL.Printf(format, v...)
	}
}
