package rest

import (
	"net/http"
	"io"
	"stun"
	"encoding/base64"
	"fmt"
	"strconv"
	"net"
)

func handleStunResponse(w http.ResponseWriter, req *http.Request) {

	logReq(req)

	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"error":"unsupported method"}`)
		return
	}

	mandatoryList := []string{"id", "xip", "xport", "origip", "origport"}
	optionalList := []string{"respport"}
	dict, err := parseURLQuery(req, mandatoryList, optionalList)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, fmt.Sprintf(`{"error":"%s"}`, err))
		return
	}
	tranID, err := base64.URLEncoding.DecodeString(dict["id"])
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, fmt.Sprintf("invalid transction ID: %s", err))
		return
	}
	xPort, err := strconv.Atoi(dict["xport"])
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "not a valid srflx port")
		return
	}
	origPort, err := strconv.Atoi(dict["origport"])
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "not a valid response origin port")
		return				
	}
	respPortStr, ok := dict["respport"]
	respPort := 0
	if ok {
		if respPort, err = strconv.Atoi(respPortStr); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, "not a valid response port")
			return
		}
	}
	if ip := net.ParseIP(dict["xip"]); ip == nil {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "not a valid srflx IP address")
		return
	} else if ip = net.ParseIP(dict["origip"]); ip == nil {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "not a valid response origin IP address")
		return
	}

	if err := stun.SendBindingResponse(tranID, dict["xip"], dict["origip"],
		xPort, origPort, respPort); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, fmt.Sprintf(`{"error":"%s"}`, err))
		return
	}

	io.WriteString(w, `{"error":""}`)
}
