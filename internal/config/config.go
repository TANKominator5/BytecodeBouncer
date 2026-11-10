// Package config parses and validates the complete rules-file grammar before
// any runtime state is changed. Packet verdicts remain exclusively in XDP.
package config

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/TANKominator5/BytecodeBouncer/internal/contract"
	"golang.org/x/sys/unix"
)

type Set struct {
	Name     string
	ID       uint8
	Prefixes map[netip.Prefix]struct{}
}
type Policy struct {
	Config contract.Config
	Sets   []Set
}

func Validate(path string) error { _, err := Parse(path, false); return err }

// Parse loads a runtime policy. ParseReader separately exposes the full kernel
// grammar; logged policies cannot run until the daemon owns an event consumer.
func Parse(path string, honeypot bool) (*Policy, error) {
	// Nonblocking open lets us reject FIFOs before waiting for a writer. Inspect
	// the opened descriptor, not the path, so a symlink swap cannot bypass this.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	null, err := os.Stat("/dev/null")
	if !info.Mode().IsRegular() && (err != nil || !os.SameFile(info, null)) {
		return nil, fmt.Errorf("rules file must be a regular file or /dev/null")
	}
	// Bound total work even when a regular file is being appended concurrently.
	const maxBytes = 16 << 20
	input := &io.LimitedReader{R: f, N: maxBytes + 1}
	policy, err := ParseReader(input, honeypot)
	if input.N == 0 {
		return nil, fmt.Errorf("rules file exceeds 16 MiB")
	}
	if err != nil {
		return nil, err
	}
	for _, rule := range policy.Config.Rules[:policy.Config.RuleCount] {
		if rule.Log != 0 {
			return nil, fmt.Errorf("line %d: logging requires pending telemetry integration", rule.Line)
		}
	}
	return policy, nil
}

// Prefix accepts a single address or a normalized mixed-family CIDR. IPv4-mapped
// IPv6 remains IPv6; never Unmap full 128-bit identities.
func Prefix(text string) (netip.Prefix, error) {
	if strings.Contains(text, "/") {
		p, err := netip.ParsePrefix(text)
		if err != nil || p.Addr().Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("invalid prefix %q", text)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(text)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("invalid address %q", text)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}
func Address(a netip.Addr) contract.Address {
	r := contract.Address{Family: 6, Bytes: a.As16()}
	if a.Is4() {
		r = contract.Address{Family: 4}
		v := a.As4()
		copy(r.Bytes[:], v[:])
	}
	return r
}
func BinaryPrefix(p netip.Prefix) contract.Prefix {
	a := Address(p.Masked().Addr())
	return contract.Prefix{Bytes: a.Bytes, Family: a.Family, Bits: uint8(p.Bits())}
}
func SetKey(id uint8, p netip.Prefix) contract.SetKey {
	a := Address(p.Masked().Addr())
	return contract.SetKey{PrefixLen: 32 + uint32(p.Bits()), Set: id, Family: a.Family, Bytes: a.Bytes}
}
func Number(s string, min, max uint32) (uint32, error) {
	if s == "" {
		return 0, fmt.Errorf("missing number")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid number %q", s)
		}
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil || n < uint64(min) || n > uint64(max) {
		return 0, fmt.Errorf("number %q outside %d..%d", s, min, max)
	}
	return uint32(n), nil
}
func portRange(text string) (uint16, uint16, error) {
	a, b, found := strings.Cut(text, "-")
	if !found {
		b = a
	}
	lo, err := Number(a, 0, 65535)
	if err != nil {
		return 0, 0, err
	}
	hi, err := Number(b, lo, 65535)
	return uint16(lo), uint16(hi), err
}
func verdict(text string) (uint32, error) {
	switch text {
	case "pass":
		return contract.Pass, nil
	case "drop":
		return contract.Drop, nil
	}
	return 0, fmt.Errorf("expected pass or drop")
}
func validName(s string) bool {
	if len(s) < 1 || len(s) > 32 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

type reference struct {
	rule   int
	source bool
	name   string
	line   int
}

func ParseReader(input io.Reader, honeypot bool) (*Policy, error) {
	p := &Policy{Config: contract.Config{DefaultAction: contract.Pass, FragmentAction: contract.Drop}, Sets: []Set{}}
	names := make(map[string]uint8)
	seen := make(map[string]bool)
	var refs []reference
	s := bufio.NewScanner(input)
	s.Buffer(make([]byte, 4096), 2<<20)
	line, prefixes := 0, 0
	for s.Scan() {
		line++
		text, _, _ := strings.Cut(s.Text(), "#")
		w := strings.FieldsFunc(text, func(c rune) bool { return c == ' ' || c == '\t' })
		if len(w) == 0 {
			continue
		}
		fail := func(err error) (*Policy, error) { return nil, fmt.Errorf("line %d: %w", line, err) }
		switch w[0] {
		case "default", "fragments":
			if seen[w[0]] || len(w) != 2 {
				return fail(fmt.Errorf("invalid or duplicate %s", w[0]))
			}
			seen[w[0]] = true
			v, err := verdict(w[1])
			if err != nil {
				return fail(err)
			}
			if w[0] == "default" {
				p.Config.DefaultAction = v
			} else {
				p.Config.FragmentAction = v
			}
			continue
		case "set":
			if len(w) < 2 || !validName(w[1]) {
				return fail(fmt.Errorf("invalid set name"))
			}
			id, ok := names[w[1]]
			if !ok {
				if len(p.Sets) >= contract.MaxSets {
					return fail(fmt.Errorf("too many sets"))
				}
				id = uint8(len(p.Sets))
				names[w[1]] = id
				p.Sets = append(p.Sets, Set{Name: w[1], ID: id, Prefixes: make(map[netip.Prefix]struct{})})
			}
			for _, value := range w[2:] {
				prefix, err := Prefix(value)
				if err != nil {
					return fail(err)
				}
				if _, exists := p.Sets[id].Prefixes[prefix]; !exists {
					prefixes++
					if prefixes > contract.MaxPrefixes {
						return fail(fmt.Errorf("too many prefixes"))
					}
					p.Sets[id].Prefixes[prefix] = struct{}{}
				}
			}
			continue
		case "portscan":
			if seen["portscan"] || len(w) != 7 || w[2] != "ports" || w[3] != "in" || w[5] != "jail" || !strings.HasSuffix(w[4], "s") {
				return fail(fmt.Errorf("invalid or duplicate portscan"))
			}
			seen["portscan"] = true
			var err error
			p.Config.ScanPorts, err = Number(w[1], 2, 1000)
			if err != nil {
				return fail(err)
			}
			p.Config.ScanWindowSeconds, err = Number(strings.TrimSuffix(w[4], "s"), 1, 60)
			if err != nil {
				return fail(err)
			}
			p.Config.ScanJailSeconds, err = Number(w[6], 1, contract.MaxJailSeconds)
			if err != nil {
				return fail(err)
			}
			continue
		}
		if p.Config.RuleCount >= contract.MaxRules {
			return fail(fmt.Errorf("too many rules"))
		}
		r := contract.Rule{Line: uint32(line)}
		start := 1
		switch w[0] {
		case "pass":
			r.Action = contract.Pass
		case "drop":
			r.Action = contract.Drop
		case "bounce":
			r.Action = contract.Bounce
		case "honeypot":
			if !honeypot {
				return fail(fmt.Errorf("honeypot rule requires a honeypot interface"))
			}
			r.Action = contract.Honeypot
		case "jail":
			if len(w) < 2 {
				return fail(fmt.Errorf("missing jail seconds"))
			}
			r.Action = contract.Jail
			var err error
			r.JailSeconds, err = Number(w[1], 1, contract.MaxJailSeconds)
			if err != nil {
				return fail(err)
			}
			start = 2
		case "limit":
			if len(w) < 4 || w[2] != "burst" || !strings.HasSuffix(w[1], "/s") {
				return fail(fmt.Errorf("expected limit <rate>/s burst <n>"))
			}
			r.Action = contract.Limit
			var err error
			r.Rate, err = Number(strings.TrimSuffix(w[1], "/s"), 1, 1000000)
			if err != nil {
				return fail(err)
			}
			r.Burst, err = Number(w[3], 1, 1000000)
			if err != nil {
				return fail(err)
			}
			start = 4
		default:
			return fail(fmt.Errorf("unknown action %q", w[0]))
		}
		matches := make(map[string]bool)
		for i := start; i < len(w); {
			key := w[i]
			if matches[key] {
				return fail(fmt.Errorf("duplicate match %q", key))
			}
			matches[key] = true
			i++
			if key == "log" {
				r.Log = 1
				continue
			}
			if i >= len(w) {
				return fail(fmt.Errorf("missing value for %q", key))
			}
			value := w[i]
			i++
			switch key {
			case "proto":
				switch value {
				case "any":
				case "udp":
					r.Proto = 17
				case "tcp":
					r.Proto = 6
				case "icmp":
					r.Proto = 1
				case "icmp6":
					r.Proto = 58
				default:
					return fail(fmt.Errorf("invalid protocol %q", value))
				}
			case "family":
				switch value {
				case "any":
				case "ipv4":
					r.Family = 4
				case "ipv6":
					r.Family = 6
				default:
					return fail(fmt.Errorf("invalid family %q", value))
				}
			case "src", "dst":
				if strings.HasPrefix(value, "@") {
					name := strings.TrimPrefix(value, "@")
					if !validName(name) {
						return fail(fmt.Errorf("invalid set reference %q", value))
					}
					refs = append(refs, reference{rule: int(p.Config.RuleCount), source: key == "src", name: name, line: line})
					if key == "src" {
						r.Matches |= contract.SrcSet
					} else {
						r.Matches |= contract.DstSet
					}
				} else {
					prefix, err := Prefix(value)
					if err != nil {
						return fail(err)
					}
					if key == "src" {
						r.Matches |= contract.SrcPrefix
						r.Src = BinaryPrefix(prefix)
					} else {
						r.Matches |= contract.DstPrefix
						r.Dst = BinaryPrefix(prefix)
					}
				}
			case "sport", "dport":
				lo, hi, err := portRange(value)
				if err != nil {
					return fail(err)
				}
				if key == "sport" {
					r.Matches |= contract.Sport
					r.SportMin = lo
					r.SportMax = hi
				} else {
					r.Matches |= contract.Dport
					r.DportMin = lo
					r.DportMax = hi
				}
			case "icmp-type":
				n, err := Number(value, 0, 255)
				if err != nil {
					return fail(err)
				}
				r.Matches |= contract.ICMPType
				r.ICMPType = uint8(n)
			case "vlan":
				if value != "any" {
					r.Matches |= contract.VLAN
					if value == "none" {
						r.VLAN = contract.VLANNone
					} else {
						n, err := Number(value, 0, 4095)
						if err != nil {
							return fail(err)
						}
						r.VLAN = uint16(n)
					}
				}
			default:
				return fail(fmt.Errorf("unknown match %q", key))
			}
		}
		p.Config.Rules[p.Config.RuleCount] = r
		p.Config.RuleCount++
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("line %d: %w", line+1, err)
	}
	for _, ref := range refs {
		id, ok := names[ref.name]
		if !ok {
			return nil, fmt.Errorf("line %d: unknown set %q", ref.line, ref.name)
		}
		if ref.source {
			p.Config.Rules[ref.rule].SrcSet = id
		} else {
			p.Config.Rules[ref.rule].DstSet = id
		}
	}
	return p, nil
}
