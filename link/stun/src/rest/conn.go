package rest

import (
	"net/http"
	"io"
)

func handleConnectionClient(w http.ResponseWriter, req *http.Request) {

	io.WriteString(w, "handleConnectionClient")
}

func handleConnectionData(w http.ResponseWriter, req *http.Request) {

	io.WriteString(w, "handleConnectionData")
}
