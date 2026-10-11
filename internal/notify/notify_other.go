//go:build !darwin

package notify

import "context"

func askApproval(context.Context, ApprovalRequest) (bool, error) { return false, ErrNoGUI }

func show(context.Context, string, string) error { return ErrNoGUI }
