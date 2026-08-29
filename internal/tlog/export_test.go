package tlog

// Test-only exports for the external test package (tlog_test). The external
// package exists because internal/fixture — which the tests use to build
// realistic exports — mints real delegation chains through internal/aat, whose
// comparator imports this package, and an internal test package would close
// that cycle.
var OpenTestLog = openTestLog

// writeEpoch is the epoch-file writer the tests use to simulate a prior
// process holding the log.
var WriteEpoch = writeEpoch
