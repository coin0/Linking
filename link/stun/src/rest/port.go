package rest

import (
	"net/http"
	"io"
)

func handlePortRelay(w http.ResponseWriter, req *http.Request) {

	io.WriteString(w, "handlePortRelay")
}
