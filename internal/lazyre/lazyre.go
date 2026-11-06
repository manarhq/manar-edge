// Package lazyre compiles regular expressions on first use. A Go program compiles every
// package-level regexp.MustCompile at start-up, which cost this binary about 3 ms on each AI tool
// hook call (a hook is a fresh process); most hooks need only a few of them.
package lazyre

import (
	"regexp"
	"sync"
)

// Re is a *regexp.Regexp that is built the first time a method is called.
type Re struct {
	once    sync.Once
	pattern string
	re      *regexp.Regexp
}

// New returns a Re for pattern. It panics on first use if the pattern is invalid, as MustCompile
// does at start-up; the repository's tests exercise every pattern.
func New(pattern string) *Re {
	regMu.Lock()
	registry = append(registry, pattern)
	regMu.Unlock()
	return &Re{pattern: pattern}
}

var (
	regMu    sync.Mutex
	registry []string
)

// Patterns lists every pattern created so far, so a test can check they all compile.
func Patterns() []string {
	regMu.Lock()
	defer regMu.Unlock()
	return append([]string(nil), registry...)
}

func (r *Re) get() *regexp.Regexp {
	r.once.Do(func() { r.re = regexp.MustCompile(r.pattern) })
	return r.re
}

func (r *Re) MatchString(s string) bool              { return r.get().MatchString(s) }
func (r *Re) Match(b []byte) bool                    { return r.get().Match(b) }
func (r *Re) FindString(s string) string             { return r.get().FindString(s) }
func (r *Re) FindStringSubmatch(s string) []string   { return r.get().FindStringSubmatch(s) }
func (r *Re) FindStringIndex(s string) []int         { return r.get().FindStringIndex(s) }
func (r *Re) FindStringSubmatchIndex(s string) []int { return r.get().FindStringSubmatchIndex(s) }
func (r *Re) FindAllString(s string, n int) []string { return r.get().FindAllString(s, n) }
func (r *Re) FindAllStringSubmatch(s string, n int) [][]string {
	return r.get().FindAllStringSubmatch(s, n)
}
func (r *Re) FindAllStringIndex(s string, n int) [][]int { return r.get().FindAllStringIndex(s, n) }
func (r *Re) FindAllStringSubmatchIndex(s string, n int) [][]int {
	return r.get().FindAllStringSubmatchIndex(s, n)
}
func (r *Re) ReplaceAllString(s, repl string) string { return r.get().ReplaceAllString(s, repl) }
func (r *Re) ReplaceAllLiteralString(s, repl string) string {
	return r.get().ReplaceAllLiteralString(s, repl)
}
func (r *Re) ReplaceAllStringFunc(s string, f func(string) string) string {
	return r.get().ReplaceAllStringFunc(s, f)
}
func (r *Re) Find(b []byte) []byte             { return r.get().Find(b) }
func (r *Re) FindSubmatch(b []byte) [][]byte   { return r.get().FindSubmatch(b) }
func (r *Re) FindIndex(b []byte) []int         { return r.get().FindIndex(b) }
func (r *Re) ReplaceAll(b, repl []byte) []byte { return r.get().ReplaceAll(b, repl) }
func (r *Re) ReplaceAllFunc(b []byte, f func([]byte) []byte) []byte {
	return r.get().ReplaceAllFunc(b, f)
}
func (r *Re) Split(s string, n int) []string { return r.get().Split(s, n) }
func (r *Re) String() string                 { return r.pattern }

func (r *Re) FindAllSubmatchIndex(b []byte, n int) [][]int { return r.get().FindAllSubmatchIndex(b, n) }
