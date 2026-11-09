// Package config validates the explicitly limited bootstrap rules dialect.
package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Validate accepts only comments, blank lines and a single default pass.
// Rejecting unfinished syntax prevents silently running an unenforced policy.
func Validate(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	line, seen := 0, false
	for s.Scan() {
		line++
		words := strings.Fields(strings.SplitN(s.Text(), "#", 2)[0])
		if len(words) == 0 {
			continue
		}
		if len(words) != 2 || words[0] != "default" || words[1] != "pass" {
			return fmt.Errorf("line %d: bootstrap supports only 'default pass'", line)
		}
		if seen {
			return fmt.Errorf("line %d: duplicate default", line)
		}
		seen = true
	}
	if err := s.Err(); err != nil {
		return fmt.Errorf("line %d: %w", line+1, err)
	}
	return nil
}
