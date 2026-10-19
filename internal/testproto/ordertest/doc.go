// Package ordertest holds Protocol Buffers messages for tests only. They
// break the contract's field-order rule on purpose (action-envelope R13
// (k), OQ28 ruling), so tests can show that the contract check would catch
// such a message and that the strict scanner rejects the bytes it marshals
// to. Nothing outside tests imports this package, and it is not part of
// the contract in api/.
package ordertest
