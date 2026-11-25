package main

import "sync"

// This ceiling also bounds authored timeouts and replay-state retention.
const v1MaximumSessionSeconds int64 = 86400

type v1SessionConstraints struct {
	Reauth int64 `json:"reauth_seconds"`
	Idle   int64 `json:"idle_seconds"`
	Max    int64 `json:"max_session_seconds"`
}

func (c v1SessionConstraints) valid() bool {
	return c.Reauth > 0 && c.Idle > 0 && c.Max > 0 && c.Reauth <= v1MaximumSessionSeconds && c.Idle <= v1MaximumSessionSeconds && c.Max <= v1MaximumSessionSeconds
}

type v1SessionKey struct{ Tenant, Subject, Session, Segment string }
type v1SessionRecord struct{ Authentication, LastSeen, IdleUntil, HardUntil int64 }

type v1SessionTracker struct {
	mu        sync.Mutex
	startedAt int64
	capacity  int
	records   map[v1SessionKey]v1SessionRecord
}

func newV1SessionTracker(startedAt int64, capacity int) *v1SessionTracker {
	return &v1SessionTracker{startedAt: startedAt, capacity: capacity, records: make(map[v1SessionKey]v1SessionRecord)}
}

// authorize records only an otherwise-allowed request. Expired idle records stay
// until no authored timeout can accept that authentication again. After restart,
// missing history requires authentication newer than startup; idle expiry cannot
// silently reset by refreshing a token or restarting this process.
func (s *v1SessionTracker) authorize(p v1Principal, segment string, limits v1SessionConstraints, now int64) (string, int64) {
	if s == nil || !limits.valid() {
		return "session_state_unavailable", 0
	}
	anchor := p.AuthTime
	if p.Kind == "simulator" {
		anchor = p.IssuedAt
	}
	if anchor <= 0 || anchor > now || now-anchor >= limits.Reauth {
		return "reauthentication_required", 0
	}
	if now-anchor >= limits.Max {
		return "maximum_session_expired", 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := v1SessionKey{p.Tenant, p.Subject, p.Session, segment}
	hardUntil := anchor + limits.Reauth
	if maxUntil := anchor + limits.Max; maxUntil < hardUntil {
		hardUntil = maxUntil
	}
	previous, found := s.records[key]
	if !found {
		if anchor <= s.startedAt {
			return "session_history_requires_reauthentication", 0
		}
		if len(s.records) >= s.capacity {
			for k, record := range s.records {
				if now-record.Authentication >= v1MaximumSessionSeconds {
					delete(s.records, k)
				}
			}
			if len(s.records) >= s.capacity {
				return "session_capacity_reached", 0
			}
		}
	} else {
		if anchor < previous.Authentication || now < previous.LastSeen {
			return "stale_authentication_or_clock", 0
		}
		if anchor == previous.Authentication {
			if now >= previous.HardUntil {
				return "previous_session_limit_expired", 0
			}
			if now >= previous.IdleUntil || now-previous.LastSeen >= limits.Idle {
				return "idle_session_expired", 0
			}
			if previous.HardUntil < hardUntil {
				hardUntil = previous.HardUntil
			}
		}
	}
	s.records[key] = v1SessionRecord{Authentication: anchor, LastSeen: now, IdleUntil: now + limits.Idle, HardUntil: hardUntil}
	if idleUntil := now + limits.Idle; idleUntil < hardUntil {
		return "", idleUntil
	}
	return "", hardUntil
}
