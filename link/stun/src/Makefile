GOPREFIX := GOPATH="$(GOPATH)"
GOBUILD := ${GOPREFIX} go build

all: gobuild

gobuild:
	GOOS=linux GOARCH=amd64 ${GOBUILD} -ldflags "-X main.Version=$(VERSION)" -a -o ../bin/stund ./server.go
	GOOS=linux GOARCH=amd64 ${GOBUILD} -ldflags "-X main.Version=$(VERSION)" -a -o ../bin/cl ./client.go
	GOOS=windows GOARCH=amd64 ${GOBUILD} -ldflags "-X main.Version=$(VERSION)" -a -o ../bin/tperf_win.exe ./client.go
	GOOS=darwin GOARCH=amd64 ${GOBUILD} -ldflags "-X main.Version=$(VERSION)" -a -o ../bin/tperf_mac.exe ./client.go
	GOOS=darwin GOARCH=arm64 ${GOBUILD} -ldflags "-X main.Version=$(VERSION)" -a -o ../bin/tperf_m1.exe ./client.go
