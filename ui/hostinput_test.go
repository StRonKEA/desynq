package main

import "testing"

// People copy the address bar, not a bare domain. Refusing a pasted link made
// the user do work this can do, so the parser has to survive real clipboard
// content — and refuse rather than guess when there is no site name in it.
func TestParseHostInput(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"discord.com", "discord.com"},
		{"  Discord.COM  ", "discord.com"},
		{"https://discord.com/channels/@me", "discord.com"},
		{"http://discord.com", "discord.com"},
		{"//discord.com/x", "discord.com"},
		{"discord.com/channels/@me", "discord.com"},
		{"https://discord.com:443/x?y=1#z", "discord.com"},
		{"https://user:pw@discord.com/x", "discord.com"},
		{"discord.com.", "discord.com"},
		{"www.pornhub.com", "www.pornhub.com"},
		{"https://sub.domain.co.uk/a/b", "sub.domain.co.uk"},
	}
	for _, c := range cases {
		got, msg := parseHostInput(c.in)
		if msg != "" {
			t.Errorf("parseHostInput(%q) refused: %s", c.in, msg)
			continue
		}
		if got != c.want {
			t.Errorf("parseHostInput(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseHostInputRefusals(t *testing.T) {
	cases := []string{
		"",
		"   ",
		"localhost",       // no dot: not a site name
		"1.2.3.4",         // an address, not a name
		"https://1.2.3.4", // the same, pasted
		"[2606:4700::]",   // an IPv6 literal
		"disc ord.com",    // a space is not host-shaped
		"https:///path",   // nothing before the path
	}
	for _, in := range cases {
		got, msg := parseHostInput(in)
		if msg == "" {
			t.Errorf("parseHostInput(%q) = %q, want a refusal", in, got)
		}
	}
}

// A refusal has to say what to do instead, or it is just a wall.
func TestParseHostInputRefusalsAreUseful(t *testing.T) {
	if _, msg := parseHostInput("localhost"); msg == "" || len(msg) < 10 {
		t.Errorf("unhelpful message for a bare word: %q", msg)
	}
	if _, msg := parseHostInput("1.2.3.4"); msg == "" || len(msg) < 10 {
		t.Errorf("unhelpful message for an address: %q", msg)
	}
}

// The stage strings carry colons and equals signs and go through cmd.exe, where
// an unquoted argument was once split and reached the engine truncated.
func TestQuoteArgWrapsWhatCmdWouldSplit(t *testing.T) {
	if got := quoteArg("multisplit:pos=1"); got != "multisplit:pos=1" {
		t.Errorf("quoteArg over-quoted a plain stage: %q", got)
	}
	for _, in := range []string{"a b", "a&b", "a|b", "a>b", "a<b", "a^b"} {
		got := quoteArg(in)
		if got != `"`+in+`"` {
			t.Errorf("quoteArg(%q) = %q, want it quoted", in, got)
		}
	}
}
