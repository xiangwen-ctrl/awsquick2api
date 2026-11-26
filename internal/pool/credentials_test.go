package pool

import (
	"path/filepath"
	"testing"

	"awsquick2api/internal/auth"
)

func newCredentialStore(t *testing.T) (CredentialStore, *auth.Account) {
	t.Helper()
	vault, err := auth.NewVaultFromKey(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	store := CredentialStore{Pool: New(Config{}), Dir: t.TempDir(), Vault: vault}
	acct := &auth.Account{UID: "soc_test_1", Provider: auth.ProviderSocial, AccessToken: "before", DeviceID: auth.NewUUID()}
	if saved, err := store.Put(acct, false, false); err != nil || !saved {
		t.Fatalf("initial credentials not saved: %v", err)
	}
	return store, acct
}

func TestCredentialStoreRejectsSupersededRevision(t *testing.T) {
	for _, replace := range []bool{false, true} {
		store, original := newCredentialStore(t)
		_, before := store.Pool.CredentialSnapshot(original.UID)
		if err := store.Delete(original.UID); err != nil {
			t.Fatal(err)
		}
		if replace {
			next := original.Clone()
			next.AccessToken = "replacement"
			if saved, err := store.Put(next, false, false); err != nil || !saved {
				t.Fatalf("replacement credentials not saved: %v", err)
			}
		}
		updated := original.Clone()
		updated.AccessToken = "superseded"
		if saved, err := store.CommitRefresh(original.UID, before, updated); err != nil || saved != nil {
			t.Fatalf("stale credential revision accepted: %v", err)
		}
		disk, err := auth.LoadDir(store.Dir, store.Vault)
		if err != nil || (replace && (len(disk) != 1 || disk[0].AccessToken != "replacement")) || (!replace && len(disk) != 0) {
			t.Fatalf("unexpected credential state after administrative update: %v", err)
		}
	}
}

func TestCredentialStoreRetainsRotationAndRetriesDiskWrite(t *testing.T) {
	store, acct := newCredentialStore(t)
	snapshot, version := store.Pool.CredentialSnapshot(acct.UID)
	if _, err := store.Rename(acct.UID, "new label"); err != nil {
		t.Fatal(err)
	}

	unwritable := store
	unwritable.Dir = filepath.Join(store.Dir, acct.UID+".json")
	snapshot.AccessToken = "rotated"
	saved, err := unwritable.CommitRefresh(acct.UID, version, snapshot)
	if err == nil || saved == nil || saved.AccessToken != "rotated" || saved.CustomName != "new label" {
		t.Fatalf("rotation or rename was lost on save failure, error=%v", err)
	}
	if pending := store.PendingUIDs(); len(pending) != 1 || pending[0] != acct.UID {
		t.Fatalf("wrong pending credential writes: %v", pending)
	}
	if attempted, err := store.FlushPending(acct.UID); err != nil || !attempted {
		t.Fatalf("retry did not persist credentials: %v", err)
	}
	disk, err := auth.LoadDir(store.Dir, store.Vault)
	if err != nil || len(disk) != 1 || disk[0].AccessToken != "rotated" || disk[0].CustomName != "new label" {
		t.Fatalf("disk did not receive both updates, error=%v", err)
	}
	if pending := store.PendingUIDs(); len(pending) != 0 {
		t.Fatalf("successful retry left pending state: %v", pending)
	}
}
