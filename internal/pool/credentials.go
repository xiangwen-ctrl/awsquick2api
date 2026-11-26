package pool

import (
	"fmt"
	"strings"
	"time"

	"awsquick2api/internal/auth"
)

// CredentialStore serializes disk and pool credential updates for each account.
type CredentialStore struct {
	Pool  *Pool
	Dir   string
	Vault *auth.Vault
}

func (p *Pool) setCredentialLocked(e *entry, acct *auth.Account, pending bool) {
	p.credentialSeq++
	e.acct = acct.Clone()
	e.credentialVersion = p.credentialSeq
	e.credentialPending = pending
}

// CredentialSnapshot returns an account together with its current credential revision.
func (p *Pool) CredentialSnapshot(uid string) (*auth.Account, uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e := p.byUID[uid]; e != nil && e.acct != nil {
		return e.acct.Clone(), e.credentialVersion
	}
	return nil, 0
}

func (s CredentialStore) save(acct *auth.Account) error {
	if s.Dir == "" {
		return nil
	}
	return auth.SaveAccount(s.Dir, s.Vault, acct)
}

// Put updates the pool after saving the credentials. It returns false for a skipped import.
func (s CredentialStore) Put(account *auth.Account, overwrite, keepDevice bool) (bool, error) {
	if account == nil || !auth.ValidUID(account.UID) {
		return false, fmt.Errorf("invalid account uid")
	}
	saved := false
	err := s.Pool.withUIDLock(s.Pool.credentialLocks, account.UID, func() error {
		next := account.Clone()
		if current := s.Pool.AuthByUID(next.UID); current != nil {
			if !overwrite {
				return nil
			}
			if strings.TrimSpace(next.CustomName) == "" {
				next.CustomName = current.CustomName
			}
			if (keepDevice || !auth.IsDeviceID(next.DeviceID)) && auth.IsDeviceID(current.DeviceID) {
				next.DeviceID = current.DeviceID
			}
		}
		if !auth.IsDeviceID(next.DeviceID) {
			next.DeviceID = auth.NewUUID()
		}
		if err := s.save(next); err != nil {
			return err
		}
		s.Pool.AddOrUpdate(next)
		saved = true
		return nil
	})
	return saved, err
}

// Rename saves the latest credentials with the new name, preserving the credential revision.
func (s CredentialStore) Rename(uid, name string) (*auth.Account, error) {
	var renamed *auth.Account
	err := s.Pool.withUIDLock(s.Pool.credentialLocks, uid, func() error {
		current := s.Pool.AuthByUID(uid)
		if current == nil {
			return nil
		}
		current.CustomName = strings.TrimSpace(name)
		current.UpdatedAt = time.Now().UnixMilli()
		if err := s.save(current); err != nil {
			return err
		}
		s.Pool.mu.Lock()
		if e := s.Pool.byUID[uid]; e != nil {
			e.acct = current.Clone()
			e.credentialPending = false
			s.Pool.dirtyGen++
			renamed = current
		}
		s.Pool.mu.Unlock()
		return nil
	})
	return renamed, err
}

func (s CredentialStore) Delete(uid string) error {
	return s.Pool.withUIDLock(s.Pool.credentialLocks, uid, func() error {
		if s.Dir != "" {
			if err := auth.DeleteAccount(s.Dir, uid); err != nil {
				return err
			}
		}
		s.Pool.Remove(uid)
		return nil
	})
}

// CommitRefresh applies a refresh only to the credentials from which it started.
// A rotated token stays usable in memory if the disk write fails.
func (s CredentialStore) CommitRefresh(uid string, version uint64, updated *auth.Account) (*auth.Account, error) {
	var saved *auth.Account
	err := s.Pool.withUIDLock(s.Pool.credentialLocks, uid, func() error {
		current, latest := s.Pool.CredentialSnapshot(uid)
		if current == nil || latest != version {
			return nil
		}
		if updated == nil || updated.UID != uid {
			return fmt.Errorf("refresh did not return credentials for the same account")
		}
		updated = updated.Clone()
		updated.CustomName = current.CustomName
		updated.DeviceID = current.DeviceID
		err := s.save(updated)
		saved = s.Pool.updateRefreshedAccount(updated, err != nil)
		if err != nil {
			return fmt.Errorf("persist refreshed credentials: %w", err)
		}
		return nil
	})
	return saved, err
}

// DisableExpired applies an OAuth expiry only to the same credential revision.
func (s CredentialStore) DisableExpired(uid string, version uint64, reason string) {
	_ = s.Pool.withUIDLock(s.Pool.credentialLocks, uid, func() error {
		if current, latest := s.Pool.CredentialSnapshot(uid); current != nil && latest == version {
			s.Pool.Disable(uid, reason)
		}
		return nil
	})
}

func (s CredentialStore) PendingUIDs() []string {
	s.Pool.mu.Lock()
	defer s.Pool.mu.Unlock()
	var uids []string
	for _, uid := range s.Pool.order {
		if s.Pool.byUID[uid].credentialPending {
			uids = append(uids, uid)
		}
	}
	return uids
}

// FlushPending retries the latest credentials, without a second token exchange.
func (s CredentialStore) FlushPending(uid string) (bool, error) {
	attempted := false
	err := s.Pool.withUIDLock(s.Pool.credentialLocks, uid, func() error {
		s.Pool.mu.Lock()
		e := s.Pool.byUID[uid]
		var acct *auth.Account
		if e != nil && e.credentialPending {
			acct = e.acct.Clone()
		}
		s.Pool.mu.Unlock()
		if acct == nil {
			return nil
		}
		attempted = true
		if err := s.save(acct); err != nil {
			return fmt.Errorf("persist refreshed credentials: %w", err)
		}
		s.Pool.mu.Lock()
		e.credentialPending = false
		s.Pool.mu.Unlock()
		return nil
	})
	return attempted, err
}
