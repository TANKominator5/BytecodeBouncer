package main

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/TANKominator5/BytecodeBouncer/internal/config"
	"github.com/TANKominator5/BytecodeBouncer/internal/daemon"
	"os"
	"os/exec"
	"strings"
	"time"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, strings.ReplaceAll(err.Error(), "\n", " "))
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: trafficcop start <ifname> <rulesfile> | stats | stop")
	}
	switch args[0] {
	case "__daemon":
		if len(args) != 3 {
			return errors.New("invalid daemon arguments")
		}
		ready := os.NewFile(3, "ready")
		if ready == nil {
			return errors.New("missing readiness pipe")
		}
		return daemon.Run(args[1], args[2], ready)
	case "start":
		if len(args) != 3 {
			return errors.New("usage: trafficcop start <ifname> <rulesfile> (bootstrap: no honeypot yet)")
		}
		if os.Geteuid() != 0 {
			return errors.New("start requires root")
		}
		if err := config.Validate(args[2]); err != nil {
			return err
		}
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		read, write, err := os.Pipe()
		if err != nil {
			return err
		}
		defer read.Close()
		cmd := exec.Command(executable, "__daemon", args[1], args[2])
		cmd.ExtraFiles = []*os.File{write}
		cmd.SysProcAttr = &syscallAttributes
		// A persistent diagnostic file avoids retaining the caller's stdout/stderr pipes.
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
				return errors.New(message)
			}
			cmd.Process.Release()
			return nil
		case <-time.After(4 * time.Second):
			cmd.Process.Kill()
			cmd.Wait()
			return errors.New("startup timed out")
		}
	case "stats", "stop":
		if len(args) != 1 {
			return errors.New("unexpected arguments")
		}
		data, err := daemon.Call(args[0])
		if err != nil {
			return err
		}
		if args[0] == "stats" {
			fmt.Println(string(data))
		}
		return nil
	case "reload", "set", "jail", "unjail", "log":
		return errors.New("command not implemented in bootstrap")
	default:
		return errors.New("unknown command")
	}
}
