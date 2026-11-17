package version

import (
	"testing"
	"time"
)

func TestGetBuildTime(t *testing.T) {
	saved := BuildDate
	t.Cleanup(func() { BuildDate = saved })
	for date, want := range map[string]time.Time{
		"2026-11-17":           time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC),
		"2026-11-17T14:57:34Z": time.Date(2026, 11, 17, 14, 57, 34, 0, time.UTC),
	} {
		BuildDate = date
		if got, err := GetBuildTime(); err != nil || !got.Equal(want) {
			t.Errorf("GetBuildTime(%q) = %v, %v; want %v", date, got, err, want)
		}
	}
	BuildDate = "unknown"
	if _, err := GetBuildTime(); err == nil {
		t.Error("GetBuildTime with an unknown date returned no error")
	}
}
