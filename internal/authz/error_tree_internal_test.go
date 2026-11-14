package authz

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

type multiWrapErr struct{ errs []error }

func (m multiWrapErr) Error() string   { return "multi" }
func (m multiWrapErr) Unwrap() []error { return m.errs }

type singleWrapErr struct{ inner error }

func (s singleWrapErr) Error() string { return "single" }
func (s singleWrapErr) Unwrap() error { return s.inner }

// P1.18.4 P111-L2: the lease fault classifier walks the whole error tree
// structurally (never by message) and treats only pure context causes as local.
func TestOnlyContextCausesWalksWholeErrorTree(t *testing.T) {
	generic := errors.New("independent fault")
	deep := error(context.Canceled)
	for i := 0; i < maxErrorTreeNodes+5; i++ {
		deep = singleWrapErr{deep}
	}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"canceled", context.Canceled, true},
		{"deadline", context.DeadlineExceeded, true},
		{"wrapped %w", fmt.Errorf("resolve: %w", context.Canceled), true},
		{"join canceled+deadline", errors.Join(context.Canceled, context.DeadlineExceeded), true},
		{"join(nil, canceled)", errors.Join(nil, context.Canceled), true},
		{"nested join pure", errors.Join(fmt.Errorf("a: %w", context.Canceled), errors.Join(context.DeadlineExceeded)), true},
		{"generic", generic, false},
		{"join canceled+generic", errors.Join(context.Canceled, generic), false},
		{"join generic+canceled", errors.Join(generic, context.Canceled), false},
		{"nested join with generic leaf", errors.Join(context.Canceled, fmt.Errorf("x: %w", errors.Join(context.DeadlineExceeded, generic))), false},
		{"multi %w with generic", fmt.Errorf("a: %w, b: %w", context.Canceled, generic), false},
		{"custom Unwrap []error pure", multiWrapErr{[]error{context.Canceled, context.DeadlineExceeded}}, true},
		{"custom Unwrap []error empty", multiWrapErr{}, false},
		{"custom Unwrap []error all nil", multiWrapErr{[]error{nil, nil}}, false},
		{"custom Unwrap error nil inner", singleWrapErr{nil}, false},
		{"error text that merely says canceled is not a context cause", errors.New("context canceled"), false},
		{"depth bound exhausted is conservatively impure", deep, false},
	}
	for _, tc := range cases {
		if got := onlyContextCauses(tc.err); got != tc.want {
			t.Errorf("%s: onlyContextCauses=%v want %v", tc.name, got, tc.want)
		}
	}
}
