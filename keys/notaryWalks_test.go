package keys

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/t2bot/matrix-key-server/db/models"
)

func keysValidUntil(ts int64) *models.CachedRemoteKeys {
	return &models.CachedRemoteKeys{
		RemoteServer: &models.RemoteServer{ServerName: testTarget, ValidUntilTs: models.Timestamp(ts)},
		Keys:         []*models.RemoteKey{{ID: testOriginKeyId}},
	}
}

// fakeNotaries answers walkNotaries from a table, recording who was asked.
type fakeNotaries struct {
	answers map[string]*models.CachedRemoteKeys
	errs    map[string]error
	asked   []string
}

func (f *fakeNotaries) ask(notary string) (*models.CachedRemoteKeys, error) {
	f.asked = append(f.asked, notary)
	return f.answers[notary], f.errs[notary]
}

func TestWalkNotaries(t *testing.T) {
	expired := keysValidUntil(testNow - 50*testDay)
	older := keysValidUntil(testNow - 10*testDay)
	current := keysValidUntil(testNow + testDay)
	later := keysValidUntil(testNow + 2*testDay)
	order := []string{"a.example", "b.example", "c.example"}

	tests := []struct {
		name      string
		answers   map[string]*models.CachedRemoteKeys
		errs      map[string]error
		want      *models.CachedRemoteKeys
		wantErr   bool
		wantAsked []string
	}{
		{
			// The domatix.net case: the first notary holds only an old copy.
			name:      "a stale first answer does not stop the walk",
			answers:   map[string]*models.CachedRemoteKeys{"a.example": expired, "b.example": current, "c.example": later},
			want:      current,
			wantAsked: []string{"a.example", "b.example"},
		},
		{
			name:      "the first valid answer wins",
			answers:   map[string]*models.CachedRemoteKeys{"a.example": current, "b.example": later},
			want:      current,
			wantAsked: []string{"a.example"},
		},
		{
			name:      "no valid answer: the longest-valid one is returned",
			answers:   map[string]*models.CachedRemoteKeys{"a.example": expired, "b.example": older, "c.example": expired},
			want:      older,
			wantAsked: order,
		},
		{
			name:      "a failing notary is skipped",
			answers:   map[string]*models.CachedRemoteKeys{"b.example": current},
			errs:      map[string]error{"a.example": errors.New("timeout")},
			want:      current,
			wantAsked: []string{"a.example", "b.example"},
		},
		{
			name:      "every notary fails",
			errs:      map[string]error{"a.example": errors.New("a"), "b.example": errors.New("b"), "c.example": errors.New("c")},
			wantErr:   true,
			wantAsked: order,
		},
		{
			name:      "no answers and no errors",
			wantAsked: order,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeNotaries{answers: tc.answers, errs: tc.errs}
			got, err := walkNotaries(order, testTarget, models.Timestamp(testNow), f.ask)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want error: %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
			if !reflect.DeepEqual(f.asked, tc.wantAsked) {
				t.Errorf("asked %v, want %v", f.asked, tc.wantAsked)
			}
		})
	}
}

func TestWalkNotariesSkipsSelfAndTarget(t *testing.T) {
	old := SelfDomainName
	SelfDomainName = "keys.example"
	defer func() { SelfDomainName = old }()

	f := &fakeNotaries{}
	_, _ = walkNotaries([]string{"", "keys.example", testTarget, "a.example"}, testTarget, models.Timestamp(testNow), f.ask)
	if want := []string{"a.example"}; !reflect.DeepEqual(f.asked, want) {
		t.Errorf("asked %v, want %v", f.asked, want)
	}
}

func TestWalkSchedule(t *testing.T) {
	w := newWalkSchedule(15 * time.Minute)
	minute := time.Minute.Milliseconds()

	if !w.take("a.example", testNow) {
		t.Fatal("first walk for a server must be allowed")
	}
	if w.take("a.example", testNow) {
		t.Error("a concurrent second walk must not start")
	}
	if w.take("a.example", testNow+14*minute) {
		t.Error("a walk inside the cooldown must not start")
	}
	if !w.take("b.example", testNow+minute) {
		t.Error("another server's cooldown must not apply")
	}
	if !w.take("a.example", testNow+15*minute) {
		t.Error("a walk once the cooldown has passed must be allowed")
	}
}

func TestWalkSchedulePrunes(t *testing.T) {
	w := newWalkSchedule(time.Minute)
	for i := 0; i < walkSchedulePruneAt; i++ {
		w.take(models.ServerName(rune(i)), testNow)
	}
	w.take("late.example", testNow+time.Minute.Milliseconds())
	if len(w.last) != 1 {
		t.Errorf("%d entries left after pruning, want 1", len(w.last))
	}
}
