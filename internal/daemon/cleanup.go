package daemon

import (
	"os"
	"path/filepath"
	"syscall"
)

// CleanupStale runs only after a failed child has exited. Never remove a socket
// while another daemon owns the singleton, including a concurrent valid start.
func CleanupStale() {
	f, err := os.OpenFile(filepath.Join(runtimeDir, "lock"), os.O_RDWR, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return
	}
	os.Remove(socketPath)
}
