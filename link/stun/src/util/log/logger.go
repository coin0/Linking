package log

import (
	"log"
	"os"
	"io"
	"bytes"
)

var (
	panicL *log.Logger
	fatalL *log.Logger
	errorL *log.Logger
	warnL  *log.Logger
	infoL  *log.Logger
	debugL *log.Logger

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

	Debug("log file begins...")
}

func UnsetLog() {

	Debug("log file ends...")
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

	debugL.Printf(format, v...)
}

