// populate fills only a dedicated bench daemon's source/jail maps. No attachment.
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/TANKominator5/BytecodeBouncer/internal/contract"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func run() error {
	if len(os.Args) != 2 || os.Geteuid() != 0 {
		return fmt.Errorf("usage: root populate <owned-daemon-pid>")
	}
	pid, err := strconv.Atoi(os.Args[1])
	if err != nil || pid <= 1 {
		return fmt.Errorf("invalid daemon pid")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return err
	}
	host, err := os.Readlink("/proc/1/ns/net")
	if err != nil {
		return err
	}
	peer, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		return err
	}
	if self == host || self != peer {
		return fmt.Errorf("refusing to populate outside the owned private namespace")
	}
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fdinfo", pid))
	if err != nil {
		return err
	}
	maps := make(map[string]*ebpf.Map)
	defer func() {
		for _, m := range maps {
			m.Close()
		}
	}()
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(fmt.Sprintf("/proc/%d/fdinfo", pid), entry.Name()))
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 2 || fields[0] != "map_id:" {
				continue
			}
			id, err := strconv.ParseUint(fields[1], 10, 32)
			if err != nil {
				return err
			}
			m, err := ebpf.NewMapFromID(ebpf.MapID(id))
			if err != nil {
				return err
			}
			info, err := m.Info()
			if err != nil {
				m.Close()
				return err
			}
			if (info.Name == "sources" || info.Name == "jail") && maps[info.Name] == nil {
				maps[info.Name] = m
			} else {
				m.Close()
			}
		}
	}
	if maps["sources"] == nil || maps["jail"] == nil {
		return fmt.Errorf("missing owned source/jail maps")
	}
	for name, m := range maps {
		info, err := m.Info()
		if err != nil {
			return err
		}
		size := uint32(8)
		if name == "jail" {
			size = 24
		}
		if info.MaxEntries != 1048576 || info.KeySize != 24 || info.ValueSize != size {
			return fmt.Errorf("unexpected %s layout/capacity", name)
		}
	}
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		return err
	}
	keys := make([]contract.Address, 1024)
	counts := make([]uint64, len(keys))
	jails := make([]contract.JailValue, len(keys))
	for offset := 0; offset < 1048576; offset += len(keys) {
		for i := range keys {
			keys[i] = contract.Address{Family: 6, Bytes: [16]byte{0xfd}}
			binary.BigEndian.PutUint64(keys[i].Bytes[8:], uint64(offset+i+1))
			counts[i] = uint64(offset + i + 1)
			jails[i] = contract.JailValue{UntilNS: uint64(now.Nano()) + uint64(time.Hour)}
		}
		if n, err := maps["sources"].BatchUpdate(keys, counts, nil); err != nil || n != len(keys) {
			return fmt.Errorf("source population %d: %v", n, err)
		}
		if n, err := maps["jail"].BatchUpdate(keys, jails, nil); err != nil || n != len(keys) {
			return fmt.Errorf("jail population %d: %v", n, err)
		}
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Entries int `json:"entries"`
	}{1048576})
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
