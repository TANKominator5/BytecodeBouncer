CLANG ?= /usr/bin/clang
ARCH_INCLUDE := /usr/include/$(shell gcc -dumpmachine)
.PHONY: all test integration stress endurance throughput capacity clean
all: trafficcop
internal/dataplane/trafficcop.bpf.o: bpf/trafficcop.bpf.c $(wildcard bpf/*.h) include/contract.h
	$(CLANG) -O2 -g -target bpfel -Iinclude -I$(ARCH_INCLUDE) -Wall -Werror -c $< -o $@
trafficcop: internal/dataplane/trafficcop.bpf.o $(shell find cmd internal -name '*.go' -o -path '*/web/*') go.mod go.sum
	CGO_ENABLED=0 go build -trimpath -o $@ ./cmd/trafficcop
test: all
	bash tests/integration/native-target-test.sh
	bash bpf/test.sh
	go test -race ./...
	go vet ./...
integration: all
	sudo bash tests/integration/bootstrap.sh
	sudo bash tests/integration/firewall.sh
	sudo bash tests/integration/lifecycle.sh
stress: all
	sudo bash tests/integration/stress.sh
endurance: all
	sudo bash tests/integration/endurance.sh
throughput: all
	sudo bash tests/integration/throughput.sh
capacity: all
	sudo env "PATH=$$PATH" bash tests/integration/command-capacity.sh
clean:
	rm -f trafficcop internal/dataplane/trafficcop.bpf.o
