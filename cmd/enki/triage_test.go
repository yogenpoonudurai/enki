package main

import (
	"reflect"
	"testing"

	"github.com/yogenpoonudurai/enki/internal/remediate"
)

func TestParseSelection(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want []int
	}{
		{"", 3, nil},
		{"none", 3, nil},
		{"all", 3, []int{1, 2, 3}},
		{"YES", 3, []int{1, 2, 3}},
		{"1,3", 3, []int{1, 3}},
		{" 3 ; 1 ", 4, []int{1, 3}},
		{"2-3", 4, []int{2, 3}},
		{"1 1 2", 3, []int{1, 2}},
	}
	for _, tc := range cases {
		got, err := parseSelection(tc.in, tc.n)
		if err != nil {
			t.Errorf("parseSelection(%q, %d) error: %v", tc.in, tc.n, err)
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("parseSelection(%q, %d) = %v; want %v", tc.in, tc.n, got, tc.want)
		}
	}
}

func TestParseSelectionRejectsInvalid(t *testing.T) {
	for _, in := range []string{"0", "4", "x", "3-2", "1-4", ",", "1,x"} {
		if _, err := parseSelection(in, 3); err == nil {
			t.Errorf("parseSelection(%q) should fail", in)
		}
	}
}

func TestFilterActions(t *testing.T) {
	plan := []remediate.Action{
		{RuleID: "SEC-001"}, {RuleID: "MCP-006"}, {RuleID: "SEC-001"},
	}
	got := filterActions(plan, "sec-001, MCP-006")
	if len(got) != 3 {
		t.Fatalf("filterActions = %d actions; want 3", len(got))
	}
	if got := filterActions(plan, "NOPE"); len(got) != 0 {
		t.Fatalf("filterActions unknown rule = %v; want none", got)
	}
}
