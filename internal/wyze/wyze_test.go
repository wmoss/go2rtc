package wyze

import (
	"net/url"
	"testing"
	"time"
)

func TestWakeDisabled(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		{"wyze://GW_BE1_X?mac=AAA&proto=gwell", false},
		{"wyze://GW_BE1_X?mac=AAA&proto=gwell&wake=1", false},
		{"wyze://GW_BE1_X?mac=AAA&wake=0", true},
		{"wyze://GW_BE1_X?mac=AAA&wake=NO", true},
		{"wyze://GW_BE1_X?mac=AAA&wake=False", true},
		{"wyze://GW_BE1_X?mac=AAA&wake=off", true},
		{"wyze://GW_BE1_X?mac=AAA&wake=", false},
	}
	for _, tc := range cases {
		u, err := url.Parse(tc.raw)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.raw, err)
		}
		if got := wakeDisabled(u.Query()); got != tc.want {
			t.Errorf("wakeDisabled(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}

func TestParseSleepCooldown(t *testing.T) {
	cases := []struct {
		raw  string
		want time.Duration
		ok   bool
	}{
		{"90", 90 * time.Second, true},
		{"90s", 90 * time.Second, true},
		{"2m", 120 * time.Second, true},
		{"1m30s", 90 * time.Second, true},
		{"0", -1, true}, // disabled
		{"0s", -1, true},
		{"-5", 0, false},
		{"abc", 0, false},
	}
	for _, tc := range cases {
		d, err := parseSleepCooldown(tc.raw)
		if tc.ok {
			if err != nil {
				t.Errorf("parseSleepCooldown(%q): %v", tc.raw, err)
				continue
			}
			if d != tc.want {
				t.Errorf("parseSleepCooldown(%q) = %s, want %s", tc.raw, d, tc.want)
			}
		} else if err == nil {
			t.Errorf("parseSleepCooldown(%q): expected error, got %s", tc.raw, d)
		}
	}
}
