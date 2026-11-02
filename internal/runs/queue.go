package runs

import (
	"fmt"

	"github.com/nebarg/sftpit/internal/faults"
)

// Queue sets the rules and chaos that the next reset starts its run with
// if it names no scenario and gives none inline, in place of repeating the
// current run's, or clears them if s is nil. Every reset that succeeds
// clears them. Invalid rules or chaos are refused.
func (m *Manager) Queue(s *InlineScenario) error {
	if s != nil {
		if err := faults.Check(s.Rules); err != nil {
			return fmt.Errorf("runs: %w", err)
		}
		if s.Chaos != nil {
			if err := s.Chaos.Check(); err != nil {
				return fmt.Errorf("runs: %w", err)
			}
		}
	}
	// Waiting for a reset under way, which has chosen its run and clears the
	// queue as it ends, keeps what is queued now for the reset after it.
	m.resetting.Lock()
	defer m.resetting.Unlock()
	m.mu.Lock()
	m.queued = s
	m.mu.Unlock()
	if s == nil {
		m.logger.Info("next run unqueued")
	} else {
		m.logger.Info("next run queued", "rules", len(s.Rules), "chaos", s.Chaos != nil)
	}
	return nil
}

// Queued returns the rules and chaos that the next reset starts its run
// with, as Queue set them, or nil.
func (m *Manager) Queued() *InlineScenario {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.queued
}
