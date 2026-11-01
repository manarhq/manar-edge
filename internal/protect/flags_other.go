//go:build !linux

package protect

// Windows has no O_NOFOLLOW; checkPath refuses reparse points before the open.
const oNoFollow = 0
