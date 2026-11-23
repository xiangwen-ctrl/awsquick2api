package config

import (
	"strings"
	"sync/atomic"
	"time"
)

// LiveSnapshot contains hot-reloadable settings applied immediately without restart.
type LiveSnapshot struct {
	APIKey               string
	AdminKey             string
	Upstream             UpstreamConfig
	Thinking             ThinkingConfig
	SoftCooldown         time.Duration
	SoftCooldownMax      time.Duration
	MaxRotate            int
	ClaudeAliases        bool
	EmptyRetryEnabled    bool
	HiddenModels         map[string]bool
	AllowedModels        map[string]bool
	AllowlistEnabled     bool
	ExposeEffortVariants bool
}

// LiveHolder stores the active hot-reloadable configuration snapshot safely for concurrent reads.
type LiveHolder struct {
	v atomic.Pointer[LiveSnapshot]
}

func NewLiveHolder(cfg *Config) *LiveHolder {
	h := &LiveHolder{}
	h.UpdateFrom(cfg)
	return h
}

func (h *LiveHolder) UpdateFrom(cfg *Config) {
	if cfg == nil {
		return
	}
	snap := SnapshotFromConfig(cfg)
	h.v.Store(&snap)
}

func (h *LiveHolder) Load() LiveSnapshot {
	if h == nil {
		return LiveSnapshot{}
	}
	p := h.v.Load()
	if p == nil {
		return LiveSnapshot{}
	}
	return *p
}

func SnapshotFromConfig(cfg *Config) LiveSnapshot {
	hidden := make(map[string]bool, len(cfg.Models.Hidden))
	for _, m := range cfg.Models.Hidden {
		if k := strings.ToLower(strings.TrimSpace(m)); k != "" {
			hidden[k] = true
		}
	}
	allowed := make(map[string]bool, len(cfg.Models.Allowed))
	for _, m := range cfg.Models.Allowed {
		if k := strings.ToLower(strings.TrimSpace(m)); k != "" {
			allowed[k] = true
		}
	}
	th := cfg.Thinking
	if len(cfg.Thinking.ModelOverrides) > 0 {
		ov := make(map[string]string, len(cfg.Thinking.ModelOverrides))
		for k, v := range cfg.Thinking.ModelOverrides {
			if nk := strings.ToLower(strings.TrimSpace(k)); nk != "" {
				ov[nk] = strings.ToLower(strings.TrimSpace(v))
			}
		}
		th.ModelOverrides = ov
	}
	return LiveSnapshot{
		APIKey:               cfg.APIKey,
		AdminKey:             cfg.AdminKey,
		Upstream:             cfg.Upstream,
		Thinking:             th,
		SoftCooldown:         time.Duration(cfg.Pool.SoftCooldownSec) * time.Second,
		SoftCooldownMax:      time.Duration(cfg.Pool.SoftCooldownMaxSec) * time.Second,
		MaxRotate:            cfg.Pool.MaxRotate,
		ClaudeAliases:        cfg.Features.ClaudeAliases,
		EmptyRetryEnabled:    cfg.Features.EmptyRetryEnabled,
		HiddenModels:         hidden,
		AllowedModels:        allowed,
		AllowlistEnabled:     len(allowed) > 0,
		ExposeEffortVariants: cfg.Models.ExposeEffortVariants,
	}
}
