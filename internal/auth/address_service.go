package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/NicoTM77/Mandatary/internal/store"
)

// Post-setup notification-address management (P1.16.4; NIST ANOT-2..4, E16).
//
// Every mutation needs the SAME fresh maximum-account-strength session as the
// factor lifecycle (freshSession): a password-only session of an account that is
// or was AAL2-capable can never change where security notices go. An address is
// never used until its holder proved control with a one-use, expiring proof sent
// to THAT address; at least one confirmed address always remains; the old
// addresses are told about a proposal, and every confirmed address (old and new
// alike, and the removed one) is told about a change. Notices ride the existing
// transactional outbox, so a notice failure never undoes or blocks the change's
// durability and never changes what the page may claim.
const (
	// maxManagedAddresses is the same ceiling setup applies (1–4).
	maxManagedAddresses = setupMaxAddresses
	// addressProofLifetime, addressProofResend and maxProofsPerAddress mirror the
	// setup ceremony (15 minutes, one send per minute per address).
	addressProofLifetime = setupProofLifetime
	addressProofResend   = setupProofResend
	maxProofsPerAddress  = 5
)

// ErrAddressMail reports that the confirmation proof was stored but could not be
// handed to the verified relay. Nothing was retargeted; the person may resend.
var ErrAddressMail = errors.New("address confirmation could not be delivered")

// AddressView is what the page may show about one of the signed-in account's
// own addresses. It is never exposed to any other account.
type AddressView struct {
	ID        string `json:"id"`
	Address   string `json:"address"`
	Confirmed bool   `json:"confirmed"`
}

func liveAddress(a store.NotificationAddress) bool {
	return !a.RevokedAt.Valid && (a.State == "active" || a.State == "quarantined")
}

// ManagedAddresses lists the account's non-revoked addresses. A read needs a live
// normal session but no recent authentication, like every other inventory read.
func (l *Lifecycle) ManagedAddresses(ctx context.Context, session []byte) ([]AddressView, error) {
	out := []AddressView{}
	denied := false
	err := l.repo.Read(ctx, func(q *store.Queries) error {
		now := l.now().Unix()
		c, u, _, e := sessionWithin(ctx, q, session, now, -1)
		if e != nil {
			denied = errors.Is(e, ErrDenied)
			return e
		}
		all, e := q.ListNotificationAddresses(ctx, u.ID)
		if e != nil {
			return e
		}
		for _, a := range all {
			if !liveAddress(a) {
				continue
			}
			out = append(out, AddressView{ID: a.ID, Address: a.Address, Confirmed: a.State == "active" && a.VerifiedAt.Valid && a.AuthorityGeneration == c.AuthorityGeneration})
		}
		return nil
	})
	if err != nil {
		if denied {
			return nil, ErrDenied
		}
		return nil, err
	}
	return out, nil
}

// ProposeAddress stages an UNCONFIRMED address. Nothing is sent to it and it
// receives no notice until its proof is consumed. The existing confirmed
// addresses are told that a change was proposed (old-address alert).
func (l *Lifecycle) ProposeAddress(ctx context.Context, session []byte, address string) (AddressView, error) {
	address = strings.TrimSpace(address)
	if !validMailbox(address) {
		return AddressView{}, ErrDenied
	}
	id, err := randomID()
	if err != nil {
		return AddressView{}, store.ErrStorage // no randomness: unavailable, not a refusal
	}
	var view AddressView
	err = l.addressControl(ctx, func(q *store.Queries) error {
		now := l.now().Unix()
		c, u, _, e := freshSession(ctx, q, session, now)
		if e != nil {
			return e
		}
		all, e := q.ListNotificationAddresses(ctx, u.ID)
		if e != nil {
			return e
		}
		live, version := 0, int64(1)
		for _, a := range all {
			if strings.EqualFold(a.Address, address) {
				if liveAddress(a) {
					return ErrDenied // already present (confirmed or awaiting proof)
				}
				if a.Version >= version {
					version = a.Version + 1
				}
			}
			if liveAddress(a) {
				live++
			}
		}
		active, e := activeAddresses(ctx, q, u.ID, c.AuthorityGeneration)
		if e != nil {
			return e // a read fault is not "no confirmed address"
		}
		if len(active) == 0 || live >= maxManagedAddresses {
			return ErrDenied
		}
		if e = q.CreateManagedAddress(ctx, store.CreateManagedAddressParams{ID: id, UserID: u.ID, Address: address, Version: version, CreatedAt: now}); e != nil {
			return e
		}
		view = AddressView{ID: id, Address: address}
		return l.enqueue(ctx, q, c, u.ID, "address_change_proposed", now)
	})
	if err != nil {
		return AddressView{}, err
	}
	return view, nil
}

// SendAddressConfirmation durably stores a one-use proof bound to this account
// and address, then delivers it to THAT address only, over the same verified TLS
// path as notices. The proof is never returned to the caller.
func (l *Lifecycle) SendAddressConfirmation(ctx context.Context, session []byte, addressID, ip string) error {
	if addressID == "" || len(addressID) > 64 || !l.gate.allow(ip, l.now()) {
		return ErrDenied
	}
	raw := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return store.ErrStorage
	}
	defer clear(raw)
	proof := make([]byte, proofEncoding.EncodedLen(len(raw)))
	proofEncoding.Encode(proof, raw)
	defer clear(proof)
	proofID, err := randomID()
	if err != nil {
		return store.ErrStorage
	}
	var recipient string
	err = l.addressControl(ctx, func(q *store.Queries) error {
		now := l.now().Unix()
		_, u, _, e := freshSession(ctx, q, session, now)
		if e != nil {
			return e
		}
		all, e := q.ListNotificationAddresses(ctx, u.ID)
		if e != nil {
			return e
		}
		var target *store.NotificationAddress
		for i := range all {
			if all[i].ID == addressID && all[i].State == "quarantined" && !all[i].RevokedAt.Valid {
				target = &all[i]
			}
		}
		if target == nil {
			return ErrDenied
		}
		proofs, e := q.ListAddressProofs(ctx, u.ID)
		if e != nil {
			return e
		}
		count := 0
		for _, p := range proofs {
			if p.AddressID == target.ID && p.AddressVersion == target.Version {
				count++
				if now-p.IssuedAt < int64(addressProofResend/time.Second) {
					return ErrDenied
				}
			}
		}
		if count >= maxProofsPerAddress {
			return ErrDenied
		}
		recipient = target.Address
		return q.CreateManagedAddressProof(ctx, store.CreateManagedAddressProofParams{ID: proofID, UserID: u.ID, AddressID: target.ID, AddressVersion: target.Version, ProofHash: proofDigest(target.ID, proof), IssuedAt: now, ExpiresAt: now + int64(addressProofLifetime/time.Second)})
	})
	if err != nil {
		return err
	}
	if failure := l.sendAddressProof(ctx, recipient, string(proof)); failure != "" {
		return ErrAddressMail
	}
	return nil
}

// ConfirmAddressProof consumes the proof for exactly this account and address and
// makes the address usable. A wrong, expired, replayed or foreign proof is one
// outcome. The proof is 128 random bits, so the per-connection traffic gate bounds
// guessing; the change is atomic with the notice that announces it.
func (l *Lifecycle) ConfirmAddressProof(ctx context.Context, session []byte, addressID, proofText, ip string) error {
	proof, ok := canonicalProof(proofText)
	if !ok || addressID == "" || len(addressID) > 64 || !l.gate.allow(ip, l.now()) {
		return ErrDenied
	}
	defer clear(proof)
	digest := proofDigest(addressID, proof)
	return l.addressControl(ctx, func(q *store.Queries) error {
		now := l.now().Unix()
		c, u, _, e := freshSession(ctx, q, session, now)
		if e != nil {
			return e
		}
		row, e := q.GetAddressProofByHash(ctx, digest)
		if e != nil {
			return authorityReadError(e) // no such proof is a refusal; any other error is a fault
		}
		all, e := q.ListNotificationAddresses(ctx, u.ID)
		if e != nil {
			return e
		}
		current := false
		for _, a := range all {
			if a.ID == addressID && a.Version == row.AddressVersion && a.State == "quarantined" && !a.RevokedAt.Valid {
				current = true
			}
		}
		if !current || row.UserID != u.ID || row.AddressID != addressID || row.ConsumedAt.Valid || now < row.IssuedAt || now >= row.ExpiresAt {
			return ErrDenied
		}
		if n, e := q.ConsumeAddressProof(ctx, store.ConsumeAddressProofParams{Now: nullable(now), ID: row.ID}); e != nil {
			return e
		} else if n != 1 {
			return ErrDenied
		}
		if n, e := q.ActivateConfirmedAddress(ctx, store.ActivateConfirmedAddressParams{Now: nullable(now), Generation: c.AuthorityGeneration, ID: addressID, UserID: u.ID}); e != nil {
			return e
		} else if n != 1 {
			return ErrDenied
		}
		return l.enqueue(ctx, q, c, u.ID, "address_changed", now)
	})
}

// RemoveAddress withdraws a proposal or retires a confirmed address. The last
// confirmed address is never removable here. The removed address is told first
// (its recipient snapshot is taken before revocation), as are the remaining ones.
func (l *Lifecycle) RemoveAddress(ctx context.Context, session []byte, addressID string) error {
	if addressID == "" || len(addressID) > 64 {
		return ErrDenied
	}
	return l.addressControl(ctx, func(q *store.Queries) error {
		now := l.now().Unix()
		c, u, _, e := freshSession(ctx, q, session, now)
		if e != nil {
			return e
		}
		all, e := q.ListNotificationAddresses(ctx, u.ID)
		if e != nil {
			return e
		}
		var target *store.NotificationAddress
		for i := range all {
			if all[i].ID == addressID && liveAddress(all[i]) {
				target = &all[i]
			}
		}
		if target == nil {
			return ErrDenied
		}
		if target.State == "active" {
			active, e := activeAddresses(ctx, q, u.ID, c.AuthorityGeneration)
			if e != nil {
				return e
			}
			if len(active) < 2 {
				return ErrDenied // the last confirmed destination stays
			}
			if e = l.enqueue(ctx, q, c, u.ID, "address_changed", now); e != nil {
				return e
			}
		}
		if n, e := q.RevokeManagedAddress(ctx, store.RevokeManagedAddressParams{Now: nullable(now), ID: addressID, UserID: u.ID}); e != nil {
			return e
		} else if n != 1 {
			return ErrDenied
		}
		return nil
	})
}

// addressControl runs fn in one durable control transaction and reduces its outcome to exactly
// two public results (P1.18.4 P116-L5). Repository.Control collapses every callback error to
// store.ErrStorage, so a LOGICAL refusal (wrong owner, stale authentication, unknown or foreign
// address or proof, last confirmed address, limits: the callback returned ErrDenied) is captured
// out of band and returned as the one opaque ErrDenied. Anything else (transaction begin, read,
// write, commit, randomness) is an infrastructure fault and is the fixed store.ErrStorage,
// which the HTTP layer answers as 503 unavailable. Neither carries SQL or driver text, a fault
// never claims success (the transaction is rolled back) and is never reported as a denial.
func (l *Lifecycle) addressControl(ctx context.Context, fn func(*store.Queries) error) error {
	refused := false
	err := l.repo.Control(ctx, func(q *store.Queries) error {
		e := fn(q)
		if errors.Is(e, ErrDenied) {
			refused = true
		}
		return e
	}, nil)
	switch {
	case err == nil:
		return nil
	case refused:
		return ErrDenied
	default:
		return store.ErrStorage
	}
}
