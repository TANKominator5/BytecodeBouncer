package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidation(t *testing.T) {
	for _, tc := range []struct{ name, input, want string }{
		{"comments", "# hi\n\n default\tpass # ok\n", ""},
		{"duplicate", "default pass\n# comment\ndefault pass", "line 3"},
		{"unsupported", "# comment\ndrop proto udp", "line 2"},
		{"typo", "defaut pass", "line 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "rules")
			if err := os.WriteFile(p, []byte(tc.input), 0600); err != nil {
				t.Fatal(err)
			}
			err := Validate(p)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %s", err, tc.want)
			}
		})
	}
}
