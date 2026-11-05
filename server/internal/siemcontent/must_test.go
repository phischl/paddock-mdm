package siemcontent_test

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// must holds fatal assertions built on the standard library only; the server
// module takes no assertion library as a dependency.
var must = asserter{}

type asserter struct{}

func msg(args []any) string {
	if len(args) == 0 {
		return ""
	}
	if f, ok := args[0].(string); ok {
		return ": " + fmt.Sprintf(f, args[1:]...)
	}
	return ": " + fmt.Sprint(args...)
}

func (asserter) fail(t *testing.T, args []any, format string, a ...any) {
	t.Helper()
	t.Fatalf(format+"%s", append(a, msg(args))...)
}

func (asserter) NoError(t *testing.T, err error, args ...any) {
	t.Helper()
	if err != nil {
		must.fail(t, args, "unexpected error: %v", err)
	}
}

func (asserter) Failf(t *testing.T, failureMessage, format string, a ...any) {
	t.Helper()
	t.Fatalf("%s: %s", failureMessage, fmt.Sprintf(format, a...))
}

func (asserter) True(t *testing.T, v bool, args ...any) {
	t.Helper()
	if !v {
		must.fail(t, args, "expected true")
	}
}

func (asserter) False(t *testing.T, v bool, args ...any) {
	t.Helper()
	if v {
		must.fail(t, args, "expected false")
	}
}

func (asserter) Equal(t *testing.T, want, got any, args ...any) {
	t.Helper()
	if !reflect.DeepEqual(want, got) {
		must.fail(t, args, "not equal\nwant: %#v\ngot:  %#v", want, got)
	}
}

func (asserter) NotEqual(t *testing.T, a, b any, args ...any) {
	t.Helper()
	if reflect.DeepEqual(a, b) {
		must.fail(t, args, "values must differ, both are %#v", a)
	}
}

func isNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func, reflect.Interface:
		return rv.IsNil()
	}
	return false
}

func (asserter) Nil(t *testing.T, v any, args ...any) {
	t.Helper()
	if !isNil(v) {
		must.fail(t, args, "expected nil, got %#v", v)
	}
}

func (asserter) NotNil(t *testing.T, v any, args ...any) {
	t.Helper()
	if isNil(v) {
		must.fail(t, args, "expected non-nil")
	}
}

func isEmpty(v any) bool {
	if isNil(v) {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Array, reflect.Chan, reflect.Map, reflect.Slice, reflect.String:
		return rv.Len() == 0
	case reflect.Pointer:
		return isEmpty(rv.Elem().Interface())
	}
	return rv.IsZero()
}

func (asserter) Empty(t *testing.T, v any, args ...any) {
	t.Helper()
	if !isEmpty(v) {
		must.fail(t, args, "expected empty, got %#v", v)
	}
}

func (asserter) NotEmpty(t *testing.T, v any, args ...any) {
	t.Helper()
	if isEmpty(v) {
		must.fail(t, args, "expected non-empty")
	}
}

func (asserter) Zero(t *testing.T, v any, args ...any) {
	t.Helper()
	if v != nil && !reflect.ValueOf(v).IsZero() {
		must.fail(t, args, "expected zero value, got %#v", v)
	}
}

func (asserter) NotZero(t *testing.T, v any, args ...any) {
	t.Helper()
	if v == nil || reflect.ValueOf(v).IsZero() {
		must.fail(t, args, "expected non-zero value")
	}
}

func (asserter) Len(t *testing.T, v any, n int, args ...any) {
	t.Helper()
	if got := reflect.ValueOf(v).Len(); got != n {
		must.fail(t, args, "length %d, want %d", got, n)
	}
}

func (asserter) Positive(t *testing.T, n int, args ...any) {
	t.Helper()
	if n <= 0 {
		must.fail(t, args, "expected positive, got %d", n)
	}
}

func (asserter) GreaterOrEqual(t *testing.T, a, b int, args ...any) {
	t.Helper()
	if a < b {
		must.fail(t, args, "%d is not >= %d", a, b)
	}
}

func (asserter) LessOrEqual(t *testing.T, a, b int, args ...any) {
	t.Helper()
	if a > b {
		must.fail(t, args, "%d is not <= %d", a, b)
	}
}

func containsElem(container, elem any) bool {
	cv := reflect.ValueOf(container)
	switch cv.Kind() {
	case reflect.String:
		return strings.Contains(cv.String(), fmt.Sprint(elem))
	case reflect.Map:
		ev := reflect.ValueOf(elem)
		return ev.IsValid() && ev.Type().AssignableTo(cv.Type().Key()) && cv.MapIndex(ev).IsValid()
	case reflect.Slice, reflect.Array:
		for i := range cv.Len() {
			if reflect.DeepEqual(cv.Index(i).Interface(), elem) {
				return true
			}
		}
	}
	return false
}

func (asserter) Contains(t *testing.T, container, elem any, args ...any) {
	t.Helper()
	if !containsElem(container, elem) {
		must.fail(t, args, "%#v does not contain %#v", container, elem)
	}
}

func (asserter) NotContains(t *testing.T, container, elem any, args ...any) {
	t.Helper()
	if containsElem(container, elem) {
		must.fail(t, args, "%#v must not contain %#v", container, elem)
	}
}

func (asserter) Regexp(t *testing.T, pattern, s string, args ...any) {
	t.Helper()
	if !regexp.MustCompile(pattern).MatchString(s) {
		must.fail(t, args, "%q does not match %s", s, pattern)
	}
}
