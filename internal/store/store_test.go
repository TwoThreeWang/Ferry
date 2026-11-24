package store

import (
	"fmt"
	"testing"
	"time"
)

func TestUpdatePersistsAndFailedUpdateKeepsState(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update(func(d *State) error { d.Regions["KR"] = Region{"KR", true}; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := s.Update(func(d *State) error { d.Regions["US"] = Region{"US", true}; return fmt.Errorf("rejected") }); err == nil {
		t.Fatal("update error swallowed")
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	regions := reopened.View().Regions
	if !regions["KR"].Enabled || !regions["JP"].Enabled {
		t.Fatalf("saved regions %v", regions)
	}
	if _, ok := regions["US"]; ok {
		t.Fatal("failed update was published")
	}
}

func TestEventsKeepRetentionAndCap(t *testing.T) {
	s := State{Config: Config{RetentionDays: 7}}
	s.Events = []Event{{Time: time.Now().AddDate(0, 0, -8), Message: "expired"}}
	added := make([]Event, 305)
	for i := range added {
		added[i] = Event{Time: time.Now(), Message: fmt.Sprint(i)}
	}
	s.AddEvents(added...)
	if len(s.Events) != 300 || s.Events[0].Message != "5" || s.Events[299].Message != "304" {
		t.Fatalf("kept %d events, first %q", len(s.Events), s.Events[0].Message)
	}
}

func TestPasswordHash(t *testing.T) {
	h := HashPassword("correct-horse-battery")
	if !h.Matches("correct-horse-battery") || h.Matches("wrong") || (PasswordHash{}).Matches("") {
		t.Fatal("password hash mismatch")
	}
}
