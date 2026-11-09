// Package daemon serializes control commands and owns all runtime resources.
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/TANKominator5/BytecodeBouncer/internal/config"
	"github.com/TANKominator5/BytecodeBouncer/internal/dataplane"
	"github.com/TANKominator5/BytecodeBouncer/internal/observe"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

const runtimeDir = "/run/trafficcop"

var socketPath = filepath.Join(runtimeDir, "control.sock")

type Request struct {
	Command string `json:"command"`
}
type Response struct {
	Data  json.RawMessage `json:"data,omitempty"`
	Error string          `json:"error,omitempty"`
}

func Call(command string) (json.RawMessage, error) {
	c, err := net.DialTimeout("unix", socketPath, 500*time.Millisecond)
	if err != nil {
		return nil, errors.New("trafficcop is not running")
	}
	defer c.Close()
	timeout := 900 * time.Millisecond
	if command == "stop" {
		timeout = 4 * time.Second
	}
	c.SetDeadline(time.Now().Add(timeout))
	if err = json.NewEncoder(c).Encode(Request{command}); err != nil {
		return nil, err
	}
	var r Response
	if err = json.NewDecoder(c).Decode(&r); err != nil {
		return nil, err
	}
	if r.Error != "" {
		return nil, errors.New(r.Error)
	}
	return r.Data, nil
}
func Run(iface, rules string, ready *os.File) (runErr error) {
	notified := false
	notify := func(err error) {
		if notified {
			return
		}
		notified = true
		if err != nil {
			fmt.Fprintln(ready, err)
		} else {
			fmt.Fprintln(ready, "READY")
		}
		ready.Close()
	}
	defer func() {
		if !notified {
			notify(runErr)
		}
	}()
	if err := config.Validate(rules); err != nil {
		return err
	}
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(runtimeDir, "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("trafficcop already running")
	}
	// Only the singleton lock owner may remove a stale socket.
	if err = os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	control, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer control.Close()
	if err = os.Chmod(socketPath, 0600); err != nil {
		return err
	}
	web, err := net.Listen("tcp", "127.0.0.1:8088")
	if err != nil {
		return err
	}
	defer web.Close()
	plane, err := dataplane.Attach(iface)
	if err != nil {
		return err
	}
	closed := false
	shutdown := func() error {
		if closed {
			return nil
		}
		closed = true
		return plane.Close()
	}
	defer shutdown()
	snapshot := func() (observe.Stats, error) { return observe.Snapshot(plane) }
	server := &http.Server{Handler: observe.Handler(snapshot), ReadHeaderTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second}
	defer server.Close()
	go func() {
		if err := server.Serve(web); err != nil && !errors.Is(err, http.ErrServerClosed) {
			control.Close()
		}
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-signals:
			control.Close()
		case <-done:
		}
	}()
	notify(nil)
	for {
		conn, err := control.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		var request Request
		var response Response
		stop := false
		if err = json.NewDecoder(conn).Decode(&request); err != nil {
			response.Error = "invalid request"
		} else {
			switch request.Command {
			case "stats":
				s, e := snapshot()
				if e != nil {
					response.Error = e.Error()
				} else {
					response.Data, e = json.Marshal(s)
					if e != nil {
						response.Error = e.Error()
					}
				}
			case "stop":
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				e := server.Shutdown(ctx)
				cancel()
				if e != nil {
					response.Error = e.Error()
				}
				if e = shutdown(); e != nil {
					response.Error = e.Error()
				}
				control.Close()
				lock.Close()
				stop = true
			default:
				response.Error = "command not implemented in bootstrap"
			}
		}
		json.NewEncoder(conn).Encode(response)
		conn.Close()
		if stop {
			return nil
		}
	}
}
