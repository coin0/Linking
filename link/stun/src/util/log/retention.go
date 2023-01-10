package log

import (
	"path/filepath"
	"os"
	"strings"
	"sort"
)

func Retain(max int) {

	// open and list all files under log folder
	logdir := filepath.Dir(logPath)
	fd, err := os.Open(logdir)
	if err != nil {
		Error("logger: retention: could not open %s: %s", logdir, err)
		return
	}

	files, err := fd.Readdir(0)
	if err != nil {
		Error("logger: retention: read dir %s: %s", logdir, err)
		return
	}

	// append all log archives to a slice sorted by modification time
	// retain specified number of archives by LFU
	list := []os.FileInfo{}
	basename := filepath.Base(logPath)
	for _, f := range files {
		if !f.Mode().IsRegular() { continue }
		if !strings.Contains(f.Name(), basename) { continue }
		list = append(list, f)
	}

	sort.Slice(list, func(i, j int) bool {

		return list[i].ModTime().Before(list[j].ModTime())
	})
	for n := 0; n < len(list) - max; n++ {
		name := logdir + "/" + list[n].Name()
		os.Remove(name)
	}
}
