package main

import "testing"

func TestCommandArguments(t *testing.T) {
	for _, args := range [][]string{{"stats", "extra"}, {"reload"}, {"set", "put", "s", "::/0"}, {"set", "add", "s", "invalid"}, {"unjail", "fe80::1%eth0"}, {"unjail"}, {"jail", "extra"}, {"log", "extra"}, {"unknown"}} {
		if _, _, err := command(args); err == nil {
			t.Fatalf("accepted %q", args)
		}
	}
	for _, args := range [][]string{{"stats"}, {"stop"}, {"log"}, {"jail"}, {"reload", "a.rules"}, {"set", "add", "s", "10.0.0.7/24"}, {"set", "del", "s", "2001:db8::/32"}, {"unjail", "2001:db8::7"}} {
		if _, _, err := command(args); err != nil {
			t.Fatalf("%q: %v", args, err)
		}
	}
	r, _, err := command([]string{"set", "add", "s", "10.0.0.7/24"})
	if err != nil || r.Prefix != "10.0.0.0/24" || !r.Add {
		t.Fatalf("request %+v %v", r, err)
	}
}
