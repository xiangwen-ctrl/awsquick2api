package pool

import (
	"encoding/json"
	"os"
	"time"

	"awsquick2api/internal/safefile"
)

type persistedEntry struct {
	Disabled       bool      `json:"disabled,omitempty"`
	DisabledReason string    `json:"disabled_reason,omitempty"`
	CooldownUntil  int64     `json:"cooldown_until,omitempty"`
	CooldownReason string    `json:"cooldown_reason,omitempty"`
	Quota          QuotaInfo `json:"quota,omitempty"`
	TotalReqs      int64     `json:"total_reqs,omitempty"`
	TotalTokens    int64     `json:"total_tokens,omitempty"`
}

type persistedPoolState struct {
	UpdatedAt int64                     `json:"updated_at"`
	Entries   map[string]persistedEntry `json:"entries"`
}

func (p *Pool) restoreState() {
	if p.cfg.StateFile == "" {
		return
	}
	raw, err := os.ReadFile(p.cfg.StateFile)
	if err != nil {
		return
	}
	var st persistedPoolState
	if err := json.Unmarshal(raw, &st); err != nil || len(st.Entries) == 0 {
		return
	}
	now := time.Now()
	for uid, pe := range st.Entries {
		e := &entry{
			disabled:       pe.Disabled,
			disabledReason: pe.DisabledReason,
			quota:          pe.Quota,
			totalReqs:      pe.TotalReqs,
			totalTokens:    pe.TotalTokens,
		}
		if pe.CooldownUntil > 0 {
			t := time.UnixMilli(pe.CooldownUntil)
			if now.Before(t) {
				e.cooldownUntil = t
				e.cooldownReason = pe.CooldownReason
			}
		}
		p.byUID[uid] = e
	}
}

// Flush writes dirty pool state atomically to StateFile.
func (p *Pool) Flush() error {
	if p.cfg.StateFile == "" {
		return nil
	}
	p.flushMu.Lock()
	defer p.flushMu.Unlock()

	p.mu.Lock()
	if p.dirtyGen == p.flushedGen {
		p.mu.Unlock()
		return nil
	}
	gen := p.dirtyGen
	st := persistedPoolState{
		UpdatedAt: time.Now().UnixMilli(),
		Entries:   make(map[string]persistedEntry, len(p.byUID)),
	}
	now := time.Now()
	for uid, e := range p.byUID {
		if e == nil {
			continue
		}
		pe := persistedEntry{
			Disabled:       e.disabled,
			DisabledReason: e.disabledReason,
			Quota:          e.quota,
			TotalReqs:      e.totalReqs,
			TotalTokens:    e.totalTokens,
		}
		if !e.cooldownUntil.IsZero() && now.Before(e.cooldownUntil) {
			pe.CooldownUntil = e.cooldownUntil.UnixMilli()
			pe.CooldownReason = e.cooldownReason
		}
		st.Entries[uid] = pe
	}
	p.mu.Unlock()

	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := safefile.WriteAtomic(p.cfg.StateFile, raw, 0o600); err != nil {
		return err
	}

	p.mu.Lock()
	if gen > p.flushedGen {
		p.flushedGen = gen
	}
	p.mu.Unlock()
	return nil
}
