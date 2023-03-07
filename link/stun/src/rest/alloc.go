package rest

import (
	"net/http"
	"io"
)

func handleAllocation(w http.ResponseWriter, req *http.Request) {

	logReq(req)

	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"error":"unsupported method"}`)
		return
	}

	//io.WriteString(w, stun.AllocTableJson())
	io.WriteString(w, "handle alloc")
}

func handleAllocationLifetime(w http.ResponseWriter, req *http.Request) {

	io.WriteString(w, "handle lifetime")
}

func handleAllocationPermission(w http.ResponseWriter, req *http.Request) {

	io.WriteString(w, "handle perm")
}

func handleAllocationChannel(w http.ResponseWriter, req *http.Request) {

	io.WriteString(w, "handle channel")
}
