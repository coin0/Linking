GOPREFIX := GOPATH="$(GOPATH)"
GOBUILD := ${GOPREFIX} go build

all: gobuild

gobuild:
	${GOBUILD} -ldflags "-X main.Version=$(VERSION)" -a -o ../bin/stund ./server.go
	${GOBUILD} -ldflags "-X main.Version=$(VERSION)" -a -o ../bin/cl ./client.go
