// Package contract is the shared A/B/C boundary. Binary layouts mirror
// include/contract.h; JSON types follow problem_Statement.md. Coordinate changes.
package contract

const (
	ABIVersion     = 5
	MaxRules       = 64
	MaxSets        = 16
	MaxPrefixes    = 10000
	MaxJailSeconds = 3600
	BucketSources  = 65536
	Pass           = 2
	Drop           = 1
	Bounce         = 3
	Honeypot       = 4
	Limit          = 5
	Jail           = 6
	VLANNone       = 65535
	UnjailOK       = 1
	UnjailAbsent   = 2
	UnjailRetry    = 3
)
const (
	SrcPrefix = 1 << iota
	DstPrefix
	SrcSet
	DstSet
	Sport
	Dport
	ICMPType
	VLAN
)

// Binary map/event types: little endian integers on the target, network-order
// address bytes, zeroed padding. Never marshal these directly as public JSON.
type Address struct {
	Bytes    [16]byte
	Family   uint8
	Reserved [7]byte
}
type Prefix struct {
	Bytes        [16]byte
	Family, Bits uint8
	Reserved     [2]byte
}
type Rule struct {
	Line, Matches, Action, Rate, Burst, JailSeconds uint32
	Src, Dst                                        Prefix
	SportMin, SportMax, DportMin, DportMax, VLAN    uint16
	Family, Proto, ICMPType, SrcSet, DstSet, Log    uint8
}
type Config struct {
	Generation                                                uint64
	RuleCount, DefaultAction, FragmentAction, HoneypotIfindex uint32
	ScanPorts, ScanWindowSeconds, ScanJailSeconds, Reserved   uint32
	Rules                                                     [MaxRules]Rule
}
type SetKey struct {
	PrefixLen   uint32
	Set, Family uint8
	Reserved    [2]byte
	Bytes       [16]byte
}
type RuleCounters struct{ Hits, Passed, Dropped, Bounced, Honeypotted uint64 }
type Health struct{ SourceFull, JailFull, ScanFull, BucketFailed, EventLost, ConfigMissing uint64 }
type JailValue struct {
	Lock, Retired        uint32
	UntilNS, CancelledNS uint64
}
type BucketValue struct{ NextNS uint64 }
type ScanValue struct {
	Lock, Count                         uint32
	Retired, Reserved                   uint32
	Generation, StartNS, PendingUntilNS uint64
	Ports                               [1024]uint64
}
type EventRecord struct {
	TimeNS, Generation uint64
	Line, Verdict      uint32
	Src, Dst           Address
	Sport, Dport       uint16
	Proto, HasPorts    uint8
	Reserved           [2]byte
}

type Counters struct{ Passed, Dropped, Bounced, Honeypotted, Malformed, Other, Jailed, DefaultHits uint64 }
type UnjailRequest struct {
	Src              Address
	Result, Reserved uint32
}

// CounterReader is implemented by dataplane.Plane; C can test against a fake.
type CounterReader interface{ Counters() (Counters, error) }

// State is a detached, generation-consistent B-to-C map snapshot, not public JSON.
// B reads native map records; C owns address formatting, ordering and aggregation.
type SourceCount struct {
	Src     Address
	Packets uint64
}
type JailRecord struct {
	Src     Address
	UntilNS uint64
}
type RuleSample struct {
	Line     uint32
	Counters RuleCounters
}
type State struct {
	Generation, NowNS uint64
	Counters          Counters
	Health            Health
	Rules             []RuleSample
	Sets              []SetStats
	Sources           []SourceCount
	Jails             []JailRecord
}
type StateReader interface{ ReadState() (State, error) }

// Targeted snapshots avoid scanning source counts for jail/health endpoints.
type JailState struct {
	NowNS uint64
	Jails []JailRecord
}
type TelemetryReader interface {
	StateReader
	ReadJail() (JailState, error)
	ReadHealth() (Health, error)
}

// EventReader is the B-to-C stream boundary. B decodes ABI records; C drains
// continuously and owns the last-1000 history. Close must unblock ReadEvent.
type EventReader interface {
	ReadEvent() (EventRecord, error)
	// Flush interrupts an empty read; pending records precede ErrEventsFlushed.
	// C uses this barrier for an up-to-date log snapshot without timing sleeps.
	Flush() error
	Close() error
}

type StreamError string

func (e StreamError) Error() string { return string(e) }

const ErrEventsFlushed StreamError = "event stream flushed"

// Telemetry is the shared daemon/HTTP boundary. B connects commands; C owns
// snapshots, canonical formatting and continuously drained event history.
// Results are detached snapshots: callers may serialize without holding locks.
// Return non-nil empty slices for JSON []; never reset history on reload.
type Telemetry interface {
	Stats() (Stats, error)
	Jail() ([]JailEntry, error)
	Log() ([]Event, error)
}

type RuleStats struct {
	Line        uint32 `json:"line"`
	Hits        uint64 `json:"hits"`
	Passed      uint64 `json:"passed"`
	Dropped     uint64 `json:"dropped"`
	Bounced     uint64 `json:"bounced"`
	Honeypotted uint64 `json:"honeypotted"`
}
type SetStats struct {
	Name     string `json:"name"`
	Prefixes uint32 `json:"prefixes"`
}
type SourceStats struct {
	Src     string `json:"src"`
	Packets uint64 `json:"packets"`
}
type JailEntry struct {
	Src         string `json:"src"`
	SecondsLeft uint64 `json:"seconds_left"`
}
type Event struct {
	Line    uint32  `json:"line"`
	Verdict string  `json:"verdict"`
	Src     string  `json:"src"`
	Dst     string  `json:"dst"`
	Proto   string  `json:"proto"`
	Sport   *uint16 `json:"sport"`
	Dport   *uint16 `json:"dport"`
}
type Stats struct {
	Passed        uint64        `json:"passed"`
	Dropped       uint64        `json:"dropped"`
	Bounced       uint64        `json:"bounced"`
	Honeypotted   uint64        `json:"honeypotted"`
	Malformed     uint64        `json:"malformed"`
	Other         uint64        `json:"other"`
	Jailed        uint64        `json:"jailed"`
	JailedSources uint64        `json:"jailed_sources"`
	RulesVersion  uint64        `json:"rules_version"`
	DefaultHits   uint64        `json:"default_hits"`
	Rules         []RuleStats   `json:"rules"`
	Sets          []SetStats    `json:"sets"`
	TopSources    []SourceStats `json:"top_sources"`
}
