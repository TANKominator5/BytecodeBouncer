package main

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/TANKominator5/BytecodeBouncer/internal/config"
	"github.com/TANKominator5/BytecodeBouncer/internal/daemon"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, strings.NewReplacer("\n", " ", "\r", " ").Replace(err.Error()))
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: trafficcop start <ifname> <rulesfile> [honeypot] | reload <rulesfile> | stats | stop | set add|del <set> <prefix> | jail | unjail <address> | log")
	}
	switch args[0] {
	case "__daemon":
		if len(args) != 4 {
			return errors.New("invalid daemon arguments")
		}
		ready := os.NewFile(3, "ready")
		if ready == nil {
			return errors.New("missing readiness pipe")
		}
		return daemon.Run(args[1], args[2], args[3], ready)
	case "start":
		if len(args) != 3 && len(args) != 4 {
			return errors.New("usage: trafficcop start <ifname> <rulesfile> [honeypot]")
		}
		if os.Geteuid() != 0 {
			return errors.New("start requires root")
		}
		hp := ""
		if len(args) == 4 {
			hp = args[3]
			if hp == "" {
				return errors.New("empty honeypot interface")
			}
		}
		path, err := filepath.Abs(args[2])
		if err != nil {
			return err
		}
		if _, err := config.Parse(path, hp != ""); err != nil {
			return err
		}
		return start(args[1], path, hp)
	}
	request, printJSON, err := command(args)
	if err != nil {
		return err
	}
	data, err := daemon.CallRequest(request)
	if err != nil {
		return err
	}
	if printJSON {
		if _, err := os.Stdout.Write(append(data, '\n')); err != nil {
			return err
		}
	}
	return nil
}
func command(args []string) (daemon.Request, bool, error) {
	r := daemon.Request{Command: args[0]}
	jsonOutput := false
	switch args[0] {
	case "stats", "jail", "log", "stop":
		if len(args) != 1 {
			return r, false, errors.New("unexpected arguments")
		}
		jsonOutput = args[0] != "stop"
	case "reload":
		if len(args) != 2 {
			return r, false, errors.New("usage: trafficcop reload <rulesfile>")
		}
		path, err := filepath.Abs(args[1])
		if err != nil {
			return r, false, err
		}
		r.Path = path
	case "set":
		if len(args) != 4 || (args[1] != "add" && args[1] != "del") {
			return r, false, errors.New("usage: trafficcop set add|del <set> <prefix>")
		}
		prefix, err := config.Prefix(args[3])
		if err != nil {
			return r, false, err
		}
		r.Add = args[1] == "add"
		r.Set = args[2]
		r.Prefix = prefix.String()
	case "unjail":
		if len(args) != 2 {
			return r, false, errors.New("usage: trafficcop unjail <address>")
		}
		a, err := netip.ParseAddr(args[1])
		if err != nil || a.Zone() != "" {
			return r, false, errors.New("invalid jail address")
		}
		r.Address = a.String()
	default:
		return r, false, errors.New("unknown command")
	}
	return r, jsonOutput, nil
}
func start(iface, path, hp string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	read, write, err := os.Pipe()
	if err != nil {
		return err
	}
	defer read.Close()
	cmd := exec.Command(executable, "__daemon", iface, path, hp)
	cmd.ExtraFiles = []*os.File{write}
	cmd.SysProcAttr = &syscallAttributes
	log, err := os.OpenFile("/run/trafficcop-bootstrap.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		write.Close()
		return err
	}
	defer log.Close()
	cmd.Stderr = log
	if err = cmd.Start(); err != nil {
		write.Close()
		return err
	}
	write.Close()
	result := make(chan string, 1)
	go func() {
		s := bufio.NewScanner(read)
		if s.Scan() {
			result <- s.Text()
		} else {
			result <- "daemon exited before readiness; see /run/trafficcop-bootstrap.log"
		}
	}()
	select {
	case message := <-result:
		if message != "READY" {
			cmd.Process.Kill()
			cmd.Wait()
			daemon.CleanupStale()
			return errors.New(message)
		}
		return cmd.Process.Release()
	case <-time.After(4500 * time.Millisecond):
		cmd.Process.Kill()
		cmd.Wait()
		daemon.CleanupStale()
		return errors.New("startup timed out")
	}
}
