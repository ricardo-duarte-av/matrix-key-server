package keys

import (
	"sync"
	"time"

	"github.com/t2bot/matrix-key-server/db/models"
)

// notaryWalkCooldown is how long after a notary walk for a server we wait before
// walking again for it. It is independent of the origin backoff, which is about
// whether the origin answers, not about what the notaries hold, and is far
// shorter than that backoff's 24h ceiling: a notary that has fetched a current
// copy is found within minutes, while a long-dead server costs one walk per
// cooldown rather than one per request.
const notaryWalkCooldown = 15 * time.Minute

// notaryWalks is the process-wide walk schedule. It is kept in memory: losing it
// on restart costs at most one extra walk per server.
var notaryWalks = newWalkSchedule(notaryWalkCooldown)

// walkSchedule spaces out notary walks per server.
type walkSchedule struct {
	cooldownMs int64

	mu   sync.Mutex
	last map[models.ServerName]int64
}

func newWalkSchedule(cooldown time.Duration) *walkSchedule {
	return &walkSchedule{cooldownMs: cooldown.Milliseconds(), last: map[models.ServerName]int64{}}
}

// walkSchedulePruneAt is the size above which expired entries are dropped.
const walkSchedulePruneAt = 10000

// take reports whether a walk for serverName may start now, and if so records it
// as started, so that concurrent requests for the same server do not each start
// one.
func (w *walkSchedule) take(serverName models.ServerName, now int64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if last, ok := w.last[serverName]; ok && now < last+w.cooldownMs {
		return false
	}
	if len(w.last) >= walkSchedulePruneAt {
		for name, last := range w.last {
			if now >= last+w.cooldownMs {
				delete(w.last, name)
			}
		}
	}
	w.last[serverName] = now
	return true
}
