package log

import (
	"log"
	"os"
	"io"
	"bytes"
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

	loglevel int

	file   *os.File
	buffer bytes.Buffer
)

func SetLog(path string) {

	var output io.Writer

	file, err := os.OpenFile(path, os.O_WRONLY | os.O_CREATE | os.O_APPEND, 0600)
	if err != nil {
		output = &buffer
	} else {
		output = file
	}

	panicL = log.New(output, "[P] ", log.LstdFlags | log.Lmicroseconds)
	fatalL = log.New(output, "[F] ", log.LstdFlags | log.Lmicroseconds)
	errorL = log.New(output, "[E] ", log.LstdFlags | log.Lmicroseconds)
	warnL = log.New(output, "[W] ", log.LstdFlags | log.Lmicroseconds)
	infoL = log.New(output, "[I] ", log.LstdFlags | log.Lmicroseconds)
	debugL = log.New(output, "[D] ", log.LstdFlags | log.Lmicroseconds)
	verbL = log.New(output, "[V] ", log.LstdFlags | log.Lmicroseconds)

	Info("log file %s begins...", path)
}

func SetLevel(level int) {

	loglevel = level
}

func UnsetLog() {

	Info("log file ends...")
	file.Close()
}

func Panic(format string, v ...any) {

	panicL.Panicf(format, v...)
}

func Fatal(format string, v ...any) {

	fatalL.Fatalf(format, v...)
}

func Error(format string, v ...any) {

	errorL.Printf(format, v...)
}

func Warn(format string, v ...any) {

	warnL.Printf(format, v...)
}

func Info(format string, v ...any) {

	infoL.Printf(format, v...)
}

func Debug(format string, v ...any) {

	if loglevel >= LEVEL_DEBUG {
		debugL.Printf(format, v...)
	}
}

func Verbose(format string, v ...any) {

	if loglevel >= LEVEL_VERB {
		verbL.Printf(format, v...)
	}
}
