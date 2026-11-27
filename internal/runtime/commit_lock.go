package runtime

import "errors"

// ErrWorkspaceCommitBusy means another cooperative Mirage writer holds the
// workspace commit lock. It does not imply any change has been committed.
var ErrWorkspaceCommitBusy = errors.New("another Mirage commit holds the workspace lock")
