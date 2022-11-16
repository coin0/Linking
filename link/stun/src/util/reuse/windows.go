//go:build !unix

package reuse

import (
	"syscall"
	"fmt"
)

func Control(net, loc string, c syscall.RawConn) (err error) {

	return c.Control(func(fd uintptr) {

		// err = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
		err = fmt.Errorf("TURN does not support windows")
		return
	})
}
