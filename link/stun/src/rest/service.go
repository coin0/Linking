package rest

import (
	"net/http"
	"os"
	"io"
	"fmt"
)

func handleServicePid(w http.ResponseWriter, req *http.Request) {

	// only support GET /service/pid
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"error":"unsupported method"}`)
		return
	}

	resp := fmt.Sprintf(`{"pid":%d}`, os.Getpid())
	io.WriteString(w, resp)
}
