package undo

// Windows has no O_NOFOLLOW; Lstat refuses links and reparse points before every open.
const oNoFollow = 0
