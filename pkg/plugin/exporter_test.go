package plugin

import (
	"strings"
	"testing"
)

func TestParseStreams(t *testing.T) {
	sup := []string{StreamEvents, StreamDecisions, StreamFlows}
	def := []string{StreamEvents}
	if got, err := ParseStreams(nil, def, sup); err != nil || len(got) != 1 || got[0] != StreamEvents {
		t.Fatalf("default: %v %v", got, err)
	}
	if got, err := ParseStreams([]string{StreamFlows, StreamDecisions}, def, sup); err != nil || strings.Join(got, ",") != "flows,decisions" {
		t.Fatalf("explicit: %v %v", got, err)
	}
	if _, err := ParseStreams([]string{"traces"}, def, sup); err == nil {
		t.Fatal("unsupported stream must fail")
	}
	if _, err := ParseStreams([]string{StreamEvents, StreamEvents}, def, sup); err == nil {
		t.Fatal("duplicate stream must fail")
	}
	if _, err := ParseStreams([]string{StreamFlows}, def, []string{StreamEvents}); err == nil {
		t.Fatal("a stream the type cannot carry must fail")
	}
}
