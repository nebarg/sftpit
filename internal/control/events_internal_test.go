package control

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/events"
)

func TestAStreamSaysWhenEventsItAskedForAreGone(t *testing.T) {
	rec := events.NewRecorder(time.Now(), 2, nil)
	for range 5 {
		rec.Record(events.Event{Kind: events.Connected})
	}
	rec.Close()
	w := httptest.NewRecorder()
	stream(w, httptest.NewRequest("GET", "/", nil), rec, eventQuery{after: 1, limit: 10})

	var got []string
	for block := range strings.SplitSeq(strings.TrimSpace(w.Body.String()), "\n\n") {
		got = append(got, strings.SplitN(block, "\n", 2)[0])
	}
	want := []string{"event: gap", "id: 4", "id: 5", "event: end"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("stream:\n%s\nwant events %v", w.Body.String(), want)
	}
	if !strings.Contains(w.Body.String(), `data: {"after":1,"first_id":4}`) {
		t.Errorf("stream:\n%s\nwant the gap after 1 up to 4", w.Body.String())
	}
}
