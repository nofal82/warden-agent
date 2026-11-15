package logs

// SetOwnUIDForTest makes OpenFile treat uid as the agent's own uid in
// place of os.Geteuid(). Every file a test creates is owned by the test
// user, which OpenFile must refuse in production (an attacker running as
// the agent's user could plant it); tests that need a readable log set a
// uid that is not theirs, and the own-uid test sets their real uid.
//
// The implementation provides setOwnUID(uid int) (restore func()). Tests
// in this package that call it never run in parallel.
func SetOwnUIDForTest(uid int) (restore func()) { return setOwnUID(uid) }
