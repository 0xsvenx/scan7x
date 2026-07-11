BINARY  := scan7x
VERSION ?= dev
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.PHONY: build test vet fmt run install clean

build:            ## build the binary
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

test:             ## run unit tests
	go test ./...

vet:              ## run go vet
	go vet ./...

fmt:              ## format the code
	gofmt -w .

run: build        ## build and run interactively
	./$(BINARY)

install:          ## go install into GOPATH/bin
	go install -ldflags "$(LDFLAGS)" .

clean:            ## remove build artifacts
	rm -f $(BINARY) $(BINARY).exe
	rm -rf dist output
