package rest

import (
	"net/http"
	"io"
	"conf"
	"strconv"
	"stun"
	"time"
	"fmt"
	"util/dbg"
	. "util/log"
	"regexp"
	"context"
)

// -------------------------------------------------------------------------------------------------

type muxer struct {
	routes    map[*regexp.Regexp]http.HandlerFunc
}

func NewMuxer() *muxer {

	return &muxer{
		routes: map[*regexp.Regexp]http.HandlerFunc{},
	}
}

func (mux *muxer) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if !mux.route(w, r) {
		http.NotFound(w, r)
	}
}

func (mux *muxer) Register(pattern string, handler http.HandlerFunc) {

	mux.routes[regexp.MustCompile("^" + pattern + "$")] = handler
}

func (mux *muxer) route(w http.ResponseWriter, r *http.Request) bool {

	for regex, handler := range mux.routes {
		matches := regex.FindStringSubmatch(r.URL.Path)
		if len(matches) > 0 {
			ctx := context.WithValue(r.Context(), 0, matches[1:])
			handler(w, r.WithContext(ctx))
			return true
		}
	}

	return false
}

// -------------------------------------------------------------------------------------------------

func logReq(req *http.Request) {

	if req != nil {
		Info("rest: %s %s", req.Method, req.URL)
	}
}

// -------------------------------------------------------------------------------------------------

func ListenHTTP(ip, port string) error {

	mux := NewMuxer()

	// restful APIs for service management
	mux.Register("/service/pid", handleServicePid)
	mux.Register("/service", handleService)

	// APIs for allocation management
	mux.Register("/allocation", handleAllocation)
	mux.Register("/allocation/([^/]+)/lifetime", handleAllocationLifetime)
	mux.Register("/allocation/([^/]+)/permission", handleAllocationPermission)
	mux.Register("/allocation/([^/]+)/channel", handleAllocationChannel)

	// for debugging
	mux.Register("/get/alloc", httpGetAlloc)
	mux.Register("/get/user", httpGetUser)
	mux.Register("/set/user", httpSetUser)
	mux.Register("/get/prof", httpGetProf)
	mux.Register("/set/prof", httpSetProf)

	err := http.ListenAndServe(ip + ":" + port, mux)
	return err
}

func httpGetAlloc(w http.ResponseWriter, req *http.Request) {

	io.WriteString(w, stun.AllocTable());
}

func httpGetUser(w http.ResponseWriter, req *http.Request) {

	io.WriteString(w, conf.Users.UserTable());
}

func httpSetUser(w http.ResponseWriter, req *http.Request) {

	q := req.URL.Query()

	// get name
	user := ""
	if name, ok := q["name"]; !ok {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "name is required")
		return
	} else {
		user = name[0]
	}

	// add a new user or update password if user exists
	if psw, ok := q["psw"]; ok {
		if err := conf.Users.Add(user, *conf.Args.Realm, psw[0]); err != nil {
			conf.Users.Reset(user, *conf.Args.Realm, psw[0])
		}
	} else {
		// cannot update a user that does not exist
		if !conf.Users.Has(user) {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, "user does not exist")
			return
		}
	}

	// update user enabler
	if enabled, ok := q["enable"]; ok {
		switch enabled[0] {
		case "1":  conf.Users.Enable(user)
		case "0":  conf.Users.Disable(user)
		default:  conf.Users.Enable(user)
		}
	}

	// update expiry
	if exp, ok := q["exp"]; ok {
		h, err := strconv.Atoi(exp[0])
		if err == nil {
			err = conf.Users.Refresh(user, time.Now().Add(time.Duration(h) * time.Hour))
		}
	}

	io.WriteString(w, conf.Users.UserTable());
}

func httpGetProf(w http.ResponseWriter, req *http.Request) {

	io.WriteString(
		w,
		fmt.Sprintf(
			"cpu_prof=%t\nmem_prof=%t\n",
			dbg.IsCPUProfStarted(),
			dbg.IsMemProfStarted(),
		),
	)
}

func httpSetProf(w http.ResponseWriter, req *http.Request) {

	q := req.URL.Query()

	var (
		err        error
		resp       string
	)

	if v, ok := q["cpu"]; ok {
		if v[0] != "0" {
			err = dbg.StartCPUProf(*conf.Args.CpuProf)
		} else {
			err = dbg.StopCPUProf()
		}
		if err != nil {
			resp += fmt.Sprintf("cpu_prof: %s\n", err)
		}
	}

	if v, ok := q["mem"]; ok {
		if v[0] != "0" {
			dbg.StartMemProf(*conf.Args.MemProf)
		} else {
			dbg.StopCPUProf()
		}
		if err != nil {
			resp += fmt.Sprintf("mem_prof: %s\n", err)
		}
	}

	// looks not an error
	if err == nil {
		resp = "OK\n"
	}

	io.WriteString(w, resp);
}
