CLANG ?= /usr/bin/clang
ARCH_INCLUDE := /usr/include/$(shell gcc -dumpmachine)
.PHONY: all test clean
all: trafficcop
internal/dataplane/trafficcop.bpf.o: bpf/trafficcop.bpf.c include/contract.h
	$(CLANG) -O2 -g -target bpfel -Iinclude -I$(ARCH_INCLUDE) -Wall -Werror -c $< -o $@
trafficcop: internal/dataplane/trafficcop.bpf.o $(shell find cmd internal -name '*.go' -o -path '*/web/*') go.mod go.sum
	CGO_ENABLED=0 go build -trimpath -o $@ ./cmd/trafficcop
test: all
	go test -race ./...
	go vet ./...
clean:
	rm -f trafficcop internal/dataplane/trafficcop.bpf.o
