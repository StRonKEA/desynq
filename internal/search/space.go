package search

import (
	"fmt"

	"dpi/internal/engine"
)

// Tier orders the strategy space by the damage a candidate can do, not by how
// likely it is to work. The search always exhausts the safe tiers first, so a
// user never pays a side effect for a result that a harmless strategy could
// have produced.
type Tier int

const (
	// TierSplit only reorders or fragments the client's own bytes. Nothing is
	// injected onto the network, so nothing outside the tested connection can
	// be affected.
	//
	// Numbering starts at 1 deliberately. Options.MaxTier treats the zero value
	// as "unset" and widens it to TierAggressive; if TierSplit were 0, a caller
	// asking for the safest tier would silently be given the riskiest one, and
	// the tier system is a safety contract rather than a label.
	TierSplit Tier = iota + 1

	// TierFake injects packets the destination server is guaranteed to reject:
	// a bogus TCP-MD5 option, an invalid checksum, an out-of-window sequence.
	// The rejection happens at the server, so a stray fake cannot disturb
	// anything else.
	TierFake

	// TierAggressive relies on TTL expiry, which depends on where the censor
	// sits relative to other hosts. A fake packet meant to die at the DPI can
	// instead die short of a nearby legitimate server, cutting off local ISP
	// sites. Reached only when the safe tiers find nothing.
	TierAggressive
)

func (t Tier) String() string {
	switch t {
	case TierSplit:
		return "split"
	case TierFake:
		return "fake"
	case TierAggressive:
		return "aggressive"
	default:
		return fmt.Sprintf("tier(%d)", int(t))
	}
}

// Candidate is one strategy: an ordered list of winws2 desync stages.
type Candidate struct {
	Stages []string
	Tier   Tier
}

func (c Candidate) String() string { return engine.FormatStages(c.Stages) }

// Position markers understood by winws2. Measurement on real DPI showed the
// split position to be the single most decisive axis, so it is enumerated
// densely while other axes stay coarse.
var splitPositions = []string{"1", "2", "3", "host", "midsld", "endhost", "1,midsld", "1,host,midsld"}

// fakePositions is a deliberately smaller set: once a fake packet is in play
// the position matters much less, so spending the budget here buys little.
var fakePositions = []string{"1", "2", "midsld"}

// safeFooling are rejection methods that cost nothing if the fake reaches the
// server. tcp_md5 is first because it is the safest of all: a server that never
// negotiated an MD5 key simply drops the segment.
var safeFooling = []string{"tcp_md5", "badsum", "tcp_seq=-10000"}

// ttlFooling limits a fake packet's lifetime so that it expires at the censor
// instead of reaching the server.
//
// Both families are named on purpose. `ip_autottl` sets the IPv4 TTL only and
// `ip6_autottl` is its separate IPv6 counterpart — the engine's own presets
// pass the two together (`preset2_example.cmd`). Since the kernel filter covers
// both families, naming only the IPv4 one would let the fake travel the whole
// way to the server on an IPv6 connection, which is exactly the hazard this
// tier is gated for: measured once as a *different* failure mode than the
// censor's, with the fake breaking the connection itself.
const ttlFooling = "ip_autottl=-2,3-20:ip6_autottl=-2,3-20"

// Space returns the candidate space in tier order.
func Space() []Candidate {
	var out []Candidate

	// Tier 1: pure segmentation.
	for _, pos := range splitPositions {
		out = append(out,
			Candidate{Stages: []string{"multisplit:pos=" + pos}, Tier: TierSplit},
			Candidate{Stages: []string{"multidisorder:pos=" + pos}, Tier: TierSplit},
		)
	}
	out = append(out,
		// tcpseg needs exactly two markers and brackets the hostname, which
		// splits the SNI across segments without any injection.
		Candidate{Stages: []string{"tcpseg:pos=host,endhost"}, Tier: TierSplit},
		Candidate{Stages: []string{"tcpseg:pos=1,midsld"}, Tier: TierSplit},
		// Out-of-band data hides a byte from a DPI that ignores the urgent
		// pointer while the server honours it.
		Candidate{Stages: []string{"oob:urp=b"}, Tier: TierSplit},
		Candidate{Stages: []string{"oob:urp=e"}, Tier: TierSplit},

		// Splitting the handshake itself, before any payload exists. Still no
		// injection: only our own SYN/ACK is reshaped, and the effect cannot
		// leave the connection being tested.
		Candidate{Stages: []string{"synack_split:mode=synack"}, Tier: TierSplit},
		Candidate{Stages: []string{"synack_split:mode=syn"}, Tier: TierSplit},
		Candidate{Stages: []string{"synack_split:mode=acksyn"}, Tier: TierSplit},

		// Window manipulation belongs in the safe tier: it changes only our own
		// TCP parameters and injects nothing, so it cannot break anything
		// outside the connection. It can make the transfer slower, which is
		// what the bandwidth measurement is there to catch — that is a cost to
		// be measured, not a hazard to be gated.
		Candidate{Stages: []string{"wsize:wsize=1:scale=6"}, Tier: TierSplit},
		Candidate{Stages: []string{"wsize:wsize=4:scale=0"}, Tier: TierSplit},
		Candidate{Stages: []string{"wssize:wsize=1:scale=6", "multisplit:pos=1"}, Tier: TierSplit},
	)

	// Tier 2: fakes the server rejects.
	for _, f := range safeFooling {
		for _, pos := range fakePositions {
			out = append(out,
				Candidate{Stages: []string{"fakedsplit:pos=" + pos + ":" + f}, Tier: TierFake},
				Candidate{Stages: []string{"fakeddisorder:pos=" + pos + ":" + f}, Tier: TierFake},
				Candidate{Stages: []string{
					"fake:blob=fake_default_tls:" + f,
					"multisplit:pos=" + pos,
				}, Tier: TierFake},
			)
		}
	}
	out = append(out,
		// A fake with no split at all: the decoy alone is sometimes enough,
		// and it is the cheapest thing in this tier.
		Candidate{Stages: []string{"fake:blob=fake_default_tls:tcp_md5"}, Tier: TierFake},

		// A forged RST makes a stateful DPI believe the connection is over, so
		// it stops inspecting while the real exchange continues. The fooling
		// argument is not optional here: without it the server receives the RST
		// and the connection really does die.
		Candidate{Stages: []string{"rst:tcp_md5"}, Tier: TierFake},
		Candidate{Stages: []string{"rst:rstack:tcp_md5"}, Tier: TierFake},
		Candidate{Stages: []string{"rst:tcp_md5", "multisplit:pos=1"}, Tier: TierFake},
		Candidate{Stages: []string{"rst:badsum", "multidisorder:pos=1,midsld"}, Tier: TierFake},

		// A forged SYN+ACK desynchronises the DPI's view of the handshake
		// before any payload is sent.
		Candidate{Stages: []string{"synack:tcp_md5"}, Tier: TierFake},
		Candidate{Stages: []string{"synack:tcp_md5", "multisplit:pos=1"}, Tier: TierFake},

		// Payload inside the SYN. The server rejects it (it negotiated no fast
		// open), but a DPI that reads it has already been given a first packet
		// that does not contain the real SNI.
		Candidate{Stages: []string{"syndata:tcp_md5"}, Tier: TierFake},
		Candidate{Stages: []string{"syndata:tcp_md5:tls_mod=rnd,rndsni"}, Tier: TierFake},
		Candidate{Stages: []string{"syndata:tcp_md5", "multisplit:pos=1"}, Tier: TierFake},

		// A fake carrying a randomised or substituted SNI: the DPI classifies
		// the connection on the decoy name and lets the real one through.
		Candidate{Stages: []string{
			"fake:blob=fake_default_tls:tcp_md5:tls_mod=rnd,rndsni",
			"multisplit:pos=1",
		}, Tier: TierFake},
		Candidate{Stages: []string{
			"fake:blob=fake_default_tls:tcp_md5:tls_mod=sni=www.google.com",
			"multidisorder:pos=1,midsld",
		}, Tier: TierFake},
		// hostfakesplit fabricates a decoy hostname around the split itself.
		Candidate{Stages: []string{"hostfakesplit:host=www.google.com:midhost=midsld:tcp_md5"}, Tier: TierFake},
		// Sequence overlap makes the DPI and the server disagree about which
		// bytes belong where. Overlap must stay below the first split position.
		Candidate{Stages: []string{"multisplit:pos=2:seqovl=1"}, Tier: TierFake},
		Candidate{Stages: []string{"multidisorder:pos=midsld:seqovl=4"}, Tier: TierFake},
	)

	// Tier 3: TTL-dependent and repeat-heavy.
	for _, pos := range fakePositions {
		out = append(out,
			Candidate{Stages: []string{"fakedsplit:pos=" + pos + ":" + ttlFooling}, Tier: TierAggressive},
			Candidate{Stages: []string{
				"fake:blob=fake_default_tls:" + ttlFooling + ":repeats=6",
				"multisplit:pos=" + pos,
			}, Tier: TierAggressive},
		)
	}
	out = append(out,
		Candidate{Stages: []string{
			"fake:blob=fake_default_tls:tcp_md5:repeats=11",
			"multidisorder:pos=1,midsld",
		}, Tier: TierAggressive},
		// A TTL-limited RST is the classic form of this trick, and the classic
		// hazard with it: aimed to expire at the DPI, it can instead expire
		// short of a nearby legitimate server.
		Candidate{Stages: []string{"rst:" + ttlFooling}, Tier: TierAggressive},
		Candidate{Stages: []string{"syndata:" + ttlFooling}, Tier: TierAggressive},
	)

	return out
}

// OfTier filters the space to a single tier.
func OfTier(space []Candidate, t Tier) []Candidate {
	var out []Candidate
	for _, c := range space {
		if c.Tier == t {
			out = append(out, c)
		}
	}
	return out
}
