package oplog

import "context"

// AccessController decides who may write to a log. It is consulted for
// every appended entry and for every entry joined from a peer, after the
// entry's signature has been checked.
type AccessController interface {
	CanAppend(ctx context.Context, entry *Entry) (bool, error)
}

// allowAll lets anyone write. It is the default for a bare Log; OrbitDB
// databases use an access controller from package accesscontrollers.
type allowAll struct{}

func (allowAll) CanAppend(context.Context, *Entry) (bool, error) { return true, nil }

// AllowAll returns an AccessController that accepts every entry.
func AllowAll() AccessController { return allowAll{} }
