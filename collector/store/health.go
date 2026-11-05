package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

const (
	healthFile    = "sources.json"
	maxErrorRunes = 200
)

// SourceStatus is one source's result for the latest run, plus timestamps
// carried over from earlier runs so the UI can spot feeds that died quietly.
type SourceStatus struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Category   string    `json:"category"`
	URL        string    `json:"url"`
	OK         bool      `json:"ok"`
	Error      string    `json:"error,omitempty"`
	Fetched    int       `json:"fetched"`
	Kept       int       `json:"kept"`
	CheckedAt  time.Time `json:"checked_at"`
	LastOKAt   time.Time `json:"last_ok_at,omitempty"`
	LastItemAt time.Time `json:"last_item_at,omitempty"`
}

type healthReport struct {
	GeneratedAt time.Time      `json:"generated_at"`
	Sources     []SourceStatus `json:"sources"`
}

// MergeHealth returns the current statuses with LastOKAt / LastItemAt
// carried forward from prev. Previous entries whose ID is still in
// configured but did not run this time (e.g. a partial -only run) are kept
// unchanged; entries for sources no longer configured are dropped.
// Neither input is modified.
func MergeHealth(prev, cur []SourceStatus, configured map[string]struct{}) []SourceStatus {
	byID := make(map[string]SourceStatus, len(prev))
	for _, p := range prev {
		byID[p.ID] = p
	}
	ran := make(map[string]struct{}, len(cur))
	out := make([]SourceStatus, len(cur), len(cur)+len(prev))
	for i, c := range cur {
		ran[c.ID] = struct{}{}
		p := byID[c.ID]
		if c.OK {
			c.LastOKAt = c.CheckedAt
		} else {
			c.LastOKAt = p.LastOKAt
		}
		if p.LastItemAt.After(c.LastItemAt) {
			c.LastItemAt = p.LastItemAt
		}
		out[i] = c
	}
	for _, p := range prev {
		_, stillConfigured := configured[p.ID]
		_, didRun := ran[p.ID]
		if stillConfigured && !didRun {
			out = append(out, p)
		}
	}
	return out
}

// TruncateError shortens an error message for display.
func TruncateError(msg string) string {
	r := []rune(msg)
	if len(r) <= maxErrorRunes {
		return msg
	}
	return string(r[:maxErrorRunes]) + "…"
}

// LoadHealth reads data/sources.json. A missing file yields (nil, nil).
func (s *Store) LoadHealth() ([]SourceStatus, error) {
	b, err := os.ReadFile(filepath.Join(s.Root, healthFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rep healthReport
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, err
	}
	return rep.Sources, nil
}

// WriteHealth writes data/sources.json.
func (s *Store) WriteHealth(statuses []SourceStatus, now time.Time) error {
	return s.writeJSON(healthFile, healthReport{GeneratedAt: now, Sources: statuses})
}
