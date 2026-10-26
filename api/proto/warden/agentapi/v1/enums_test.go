package agentapiv1_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"unicode"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// enumTable lists, per enum, its values from 1 upwards without prefix, as
// the spec writes them. Every enum also has <ENUM>_UNSPECIFIED = 0
// (agent-api §4, typed-action-catalog §4.8, executor-ipc §4.5), and in the
// .proto each value is prefixed with its enum's name in upper snake case.
type enumTable map[string][]string

// agentapiEnums: agent-api §4.3–§4.8.
var agentapiEnums = enumTable{
	"RenewalRefusal": {"KEY_REUSED", "TOO_EARLY", "ALREADY_SUPERSEDED", "RATE_LIMITED",
		"DECOMMISSIONED", "QUARANTINED", "CSR_INVALID", "INTERNAL"},
	"RedactClass": {"T_NAME", "T_PATH", "T_TEXT", "E_TEXT", "L_VALUE", "N_PATTERNED", "UNSIGNED_BODY"},
	"AgentCondition": {"EXECUTOR_UNAVAILABLE", "OUTBOX_HIGH_WATER", "OUTBOX_FULL",
		"TELEMETRY_DROPPING", "ADMIN_TOOL_RECORD_UNREADABLE", "CONTROLPLANE_TRUST_OUTDATED",
		"TRUST_CHECK_IMPOSSIBLE", "CA_SWITCH_VERIFY_FAILED", "ENROLLMENT_TOKEN_EXPIRED",
		"IDENTITY_EXPIRED_OR_MISSING", "CERTIFICATE_REFUSED", "CONTRACT_VERSION_UNSUPPORTED",
		"EXECUTOR_BINDING_FILE_INVALID", "MEMORY_LIMIT_INVALID"},
	"AckOutcome":     {"ACCEPTED", "DUPLICATE", "RETRY_LATER", "REJECTED"},
	"ReplyKind":      {"ENVELOPE_RESULT", "TRUST_RESULT", "STATUS"},
	"WithheldReason": {"REDACTION_MATCH", "REDACTION_ERROR", "REDACTION_RULES_UNAVAILABLE"},
	"OmitReason":     {"SIZE", "REDACTION"},
	"AdvisoryReason": {"NOT_FORWARDED_OVERSIZED", "NOT_FORWARDED_EXPIRED",
		"NOT_FORWARDED_WRONG_HOST", "NOT_DELIVERED_EXECUTOR_UNAVAILABLE"},
	"AdminToolMode": {"TRUST_UPDATE", "STAGE", "SWITCH", "CONFIRM", "ROLLBACK"},
	"AdminToolCode": {"OK", "RELEASE_INVALID", "DOWNGRADE", "SEQUENCE_TOO_FAR",
		"SEQUENCE_CONFLICT", "ARTIFACT_MISSING", "ARTIFACT_MISMATCH", "SERVICES_RUNNING",
		"UPDATE_PENDING", "HEALTH_FAILED", "FINGERPRINT_MISMATCH", "EXECUTOR_UNAVAILABLE",
		"INPUT_INVALID", "RESULT_KEY_UNAVAILABLE"},
	"EndReason": {"CERTIFICATE_REVOKED", "REVOCATION_STATE_STALE", "DATABASE_UNAVAILABLE",
		"SHUTTING_DOWN", "ENROLLMENT_REFUSED", "IDENTITY_MISMATCH", "RATE_LIMITED",
		"TOO_LARGE", "MALFORMED", "MESSAGE_SEQ_UNREADABLE", "HELLO_REQUIRED",
		"DUPLICATE_STREAM", "CONTRACT_VERSION_UNSUPPORTED", "HELLO_TIMEOUT",
		"CONNECTION_REPLACED", "ACK_TIMEOUT", "DUPLICATE_IDENTITY_CLOSED", "DUPLICATE_IDENTITY"},
	"AckReason": {"REVOCATION_STATE_STALE", "INBOX_FULL", "RATE_LIMITED",
		"DATABASE_UNAVAILABLE", "ORDER", "TOO_LARGE", "MALFORMED"},
}

// v1Enums: the warden.v1 enums added by issue #12.
var v1Enums = enumTable{
	// agent-api §4.10
	"RedactFieldClass": {"S", "X", "I", "U", "T_NAME", "T_PATH", "T_TEXT", "E_TEXT",
		"L_VALUE", "N_PATTERNED"},
	// typed-action-catalog §4.8, §4.8.1
	"PrimitiveStatus":    {"SUCCEEDED", "NO_CHANGE", "FAILED", "TIMED_OUT"},
	"PrimitiveErrorCode": {"EXIT_NONZERO", "DB_ERROR", "IO_ERROR", "PARTIAL", "HELPER_OUTPUT_INVALID"},
	"FsEntryKind":        {"FILE", "DIRECTORY"},
	"UnitLoadState":      {"LOADED", "NOT_FOUND", "BAD_SETTING", "ERROR", "MASKED", "UNKNOWN"},
	"UnitActiveState": {"ACTIVE", "RELOADING", "INACTIVE", "FAILED", "ACTIVATING",
		"DEACTIVATING", "MAINTENANCE", "REFRESHING", "UNKNOWN"},
	"ServiceSubState": {"DEAD", "CONDITION", "START_PRE", "START", "START_POST", "RUNNING",
		"EXITED", "RELOAD", "STOP", "STOP_WATCHDOG", "STOP_SIGTERM", "STOP_SIGKILL",
		"STOP_POST", "FINAL_WATCHDOG", "FINAL_SIGTERM", "FINAL_SIGKILL", "FAILED",
		"AUTO_RESTART", "CLEANING", "UNKNOWN"},
	"ServiceRunResult": {"SUCCESS", "PROTOCOL", "TIMEOUT", "EXIT_CODE", "SIGNAL", "CORE_DUMP",
		"WATCHDOG", "START_LIMIT_HIT", "RESOURCES", "OOM_KILL", "EXEC_CONDITION", "UNKNOWN"},
	"ProcessState": {"RUNNING", "SLEEPING", "DISK_SLEEP", "ZOMBIE", "STOPPED", "TRACING_STOP",
		"DEAD", "IDLE", "UNKNOWN"},
	"ContainerState": {"CREATED", "RUNNING", "PAUSED", "RESTARTING", "REMOVING", "EXITED",
		"DEAD", "UNKNOWN"},
	"ContainerHealth":   {"NONE", "STARTING", "HEALTHY", "UNHEALTHY"},
	"DbClientKind":      {"LOCAL", "REMOTE"},
	"DbSessionState":    {"ACTIVE", "IDLE", "IDLE_IN_TRANSACTION", "IDLE_IN_TRANSACTION_ABORTED", "UNKNOWN"},
	"DbReplicationRole": {"PRIMARY", "REPLICA", "STANDALONE"},
	"DbMemberState": {"PRIMARY", "SECONDARY", "RECOVERING", "STARTUP", "STARTUP2", "ARBITER",
		"DOWN", "ROLLBACK", "REMOVED", "UNKNOWN"},
	"BackupFormat": {"MYSQLDUMP_TEXT", "MYSQLDUMP_COMPRESSED", "POSTGRES_CUSTOM",
		"MONGODB_ARCHIVE", "UNRECOGNISED"},
	"BackupCheck":        {"TOO_OLD", "TOO_SMALL", "BAD_FORMAT", "NOT_FOUND"},
	"DbTerminateOutcome": {"TERMINATED", "NOT_FOUND", "NOT_IDLE_ENOUGH", "PROTECTED", "CHANGED", "FAILED"},
	// executor-ipc §4.3, §4.6, §4.7, §4.9
	"IpcRefusalCode": {"FRAME_INVALID", "PEER_NOT_ALLOWED", "THROTTLED", "SHUTTING_DOWN",
		"BUSY", "RESULT_KEY_UNAVAILABLE"},
	"TrustKind":       {"KEYSET", "CATALOG", "MANIFEST", "CONTROLPLANE_CA"},
	"ExecutorOutcome": {"REJECTED", "EXECUTED"},
	// action-envelope §4.5: each distinct code once, in the order of its
	// first appearance.
	"EnvelopeRejectionCode": {"OVERSIZED", "MALFORMED", "UNKNOWN_KEY", "BAD_SIGNATURE",
		"BODY_INVALID", "UNSUPPORTED_FORMAT_VERSION", "LIFETIME_INVALID", "NOT_YET_VALID",
		"EXPIRED", "WRONG_HOST", "MANIFEST_REQUIRED", "CREATED_BEFORE_RECOVERY",
		"UNKNOWN_PLAYBOOK", "PLAYBOOK_NOT_ENABLED", "PLAYBOOK_VERSION_MISMATCH",
		"PLAYBOOK_DIGEST_MISMATCH", "STEP_NOT_IN_PLAYBOOK", "PRIMITIVE_NOT_IN_STEP",
		"PARAMETERS_INVALID", "POLICY_DECISION_INVALID", "STORE_UNAVAILABLE", "CLOCK_ROLLBACK",
		"REPLAYED", "IDEMPOTENCY_KEY_REUSED", "PLAYBOOK_FROZEN", "RATE_LIMITED", "STORE_FULL"},
	// action-envelope §4.4
	"StoredState": {"STARTED", "SUCCEEDED", "FAILED", "ROLLED_BACK"},
	// executor-ipc §4.6.2; action-envelope §4.6
	"TrustInstallResult": {"INSTALLED", "NO_CHANGE", "KEYSET_INVALID", "KEYSET_ROLLBACK",
		"CATALOG_INVALID", "CATALOG_ROLLBACK", "MANIFEST_INVALID", "MANIFEST_ROLLBACK",
		"SEQUENCE_CONFLICT", "CA_INVALID", "CA_NOT_IN_KEYSET"},
	"SequenceState": {"RECORDED", "NONE_ACCEPTED"},
	"HashState":     {"KNOWN", "UNKNOWN"},
	"TrustState":    {"AVAILABLE", "RECOVERY_IN_PROGRESS", "LOCK_FILE_MISSING", "NEEDS_REPAIR"},
	// executor-ipc §4.9
	"HealthCondition": {"RECOVERY_IN_PROGRESS", "LOCK_FILE_MISSING", "TRUST_STATE_NEEDS_REPAIR",
		"SERVER_IDENTITY_MISSING", "DOCUMENT_HASH_MISMATCH", "RECOVERY_PENDING",
		"STORE_UNAVAILABLE", "STORE_FULL", "STORE_UNREADABLE_RECORDS",
		"DIGEST_KEY_MISSING_OR_INVALID", "RESULT_KEY_MISSING_OR_INVALID", "AGENT_UID_INVALID",
		"DATABASE_PLAYBOOKS_UNAVAILABLE", "CONTROLPLANE_CA_FILE_UNREADABLE", "SHUTTING_DOWN",
		"DB_CONDITIONS_FILE_UNREADABLE"},
	"CgroupVersion":             {"V1", "V2"},
	"HelperLaunchMethod":        {"CLONE_INTO_CGROUP", "LAUNCH_STAGE"},
	"HelperCleanupMethod":       {"CGROUP_KILL", "FREEZE"},
	"ProcessIdentityMethod":     {"PIDFD", "O_PATH_FALLBACK"},
	"DatabaseUnavailableReason": {"CONTAINMENT_INCOMPLETE", "LEFTOVER_HELPER_CGROUP", "HELPER_CGROUP_NOT_EMPTY"},
	"DbCondition": {"MONGODB_AUTHORIZATION_NOT_ENFORCED", "MONGODB_HELPER_LOGIN_FAILED",
		"POSTGRES_TOO_MANY_CONNECTABLE_DATABASES", "POSTGRES_UNCHECKED_DATABASES",
		"POSTGRES_SKIPPED_DATABASES", "POSTGRES_LOGIN_EVENT_TRIGGER"},
}

// upperSnake turns an enum name into its value prefix: AdminToolCode is
// ADMIN_TOOL_CODE (agent-api §4).
func upperSnake(name string) string {
	var b strings.Builder
	for i, r := range name {
		if i > 0 && unicode.IsUpper(r) {
			b.WriteByte('_')
		}
		b.WriteRune(unicode.ToUpper(r))
	}
	return b.String()
}

// enumViolations compares eds with table both ways: every enum has a row,
// every row an enum, and each enum's values (name and number) are exactly
// UNSPECIFIED = 0 followed by the row's values numbered from 1.
func enumViolations(pkg protoreflect.FullName, eds []protoreflect.EnumDescriptor, table enumTable) []string {
	var out []string
	seen := map[string]bool{}
	for _, ed := range eds {
		key := relName(pkg, ed.FullName())
		values, ok := table[key]
		if !ok {
			out = append(out, fmt.Sprintf("%s: enum has no row", ed.FullName()))
			continue
		}
		seen[key] = true
		prefix := upperSnake(string(ed.Name())) + "_"
		want := map[protoreflect.EnumNumber]string{0: prefix + "UNSPECIFIED"}
		for i, v := range values {
			want[protoreflect.EnumNumber(i+1)] = prefix + v
		}
		got := map[protoreflect.EnumNumber]string{}
		for i := 0; i < ed.Values().Len(); i++ {
			v := ed.Values().Get(i)
			got[v.Number()] = string(v.Name())
		}
		for n, name := range got {
			if want[n] != name {
				out = append(out, fmt.Sprintf("%s: value %s = %d, want %q", ed.FullName(), name, n, want[n]))
			}
		}
		for n, name := range want {
			if _, ok := got[n]; !ok {
				out = append(out, fmt.Sprintf("%s: missing value %s = %d", ed.FullName(), name, n))
			}
		}
	}
	for _, key := range sortedKeys(table) {
		if !seen[key] {
			out = append(out, fmt.Sprintf("%s.%s: row has no enum", pkg, key))
		}
	}
	slices.Sort(out)
	return out
}

// TestAgentapiEnumValues: every enum of warden.agentapi.v1 has exactly the
// spec's values and numbers, which are final wire numbers (R52).
func TestAgentapiEnumValues(t *testing.T) {
	for _, v := range enumViolations(agentapiPkg, allEnums(packageFiles(t, agentapiPkg)), agentapiEnums) {
		t.Error(v)
	}
}

// TestNewV1EnumValues: every warden.v1 enum added by issue #12 has exactly
// the spec's values and numbers.
func TestNewV1EnumValues(t *testing.T) {
	for _, v := range enumViolations(wardenPkg, allEnums(newV1Files(t)), v1Enums) {
		t.Error(v)
	}
}

// TestEnumCounts pins the counts the issue calls out, so a value dropped
// from both the table and the .proto is still caught.
func TestEnumCounts(t *testing.T) {
	cases := []struct {
		table enumTable
		name  string
		max   int
	}{
		{agentapiEnums, "EndReason", 18},
		{agentapiEnums, "AgentCondition", 14},
		{agentapiEnums, "AdminToolCode", 14},
		{agentapiEnums, "AckReason", 7},
		{agentapiEnums, "RenewalRefusal", 8},
		{agentapiEnums, "RedactClass", 7},
		{v1Enums, "EnvelopeRejectionCode", 27},
		{v1Enums, "HealthCondition", 16},
		{v1Enums, "TrustInstallResult", 11},
		{v1Enums, "ServiceSubState", 20},
		{v1Enums, "IpcRefusalCode", 6},
		{v1Enums, "DbCondition", 6},
		{v1Enums, "RedactFieldClass", 10},
	}
	for _, c := range cases {
		if got := len(c.table[c.name]); got != c.max {
			t.Errorf("%s: %d values in the table, want %d", c.name, got, c.max)
		}
	}
}

// TestReusedEnumsNotRedeclared: Engine, PrimitiveStatus,
// PrimitiveErrorCode and TrustKind are declared once in warden.v1 and
// reused (executor-ipc §4.5); the agentapi package declares none of the
// warden.v1 types it imports (agent-api R52, AC36).
func TestReusedEnumsNotRedeclared(t *testing.T) {
	count := map[protoreflect.Name]int{}
	for _, ed := range allEnums(packageFiles(t, wardenPkg)) {
		count[ed.Name()]++
	}
	for _, name := range []protoreflect.Name{"Engine", "PrimitiveStatus", "PrimitiveErrorCode", "TrustKind"} {
		if count[name] != 1 {
			t.Errorf("warden.v1 declares enum %s %d times, want 1", name, count[name])
		}
	}
}

// TestUpperSnake checks the prefix helper on the spec's own examples.
func TestUpperSnake(t *testing.T) {
	for in, want := range map[string]string{
		"AdminToolCode": "ADMIN_TOOL_CODE", "AutonomyLevel": "AUTONOMY_LEVEL",
		"TrustState": "TRUST_STATE", "IpcRefusalCode": "IPC_REFUSAL_CODE",
	} {
		if got := upperSnake(in); got != want {
			t.Errorf("upperSnake(%s) = %s, want %s", in, got, want)
		}
	}
}

// TestEnumViolationsDetects feeds the checker a wrong table: a renumbered
// value, a missing value, an extra value and a missing row are each
// reported.
func TestEnumViolationsDetects(t *testing.T) {
	eds := allEnums(packageFiles(t, agentapiPkg))
	bad := enumTable{}
	for k, v := range agentapiEnums {
		bad[k] = slices.Clone(v)
	}
	bad["AckOutcome"] = []string{"ACCEPTED", "RETRY_LATER", "DUPLICATE", "REJECTED"}
	bad["OmitReason"] = []string{"SIZE"}
	bad["ReplyKind"] = append(bad["ReplyKind"], "EXTRA")
	delete(bad, "WithheldReason")
	bad["NoSuchEnum"] = []string{"A"}
	want := []string{
		`warden.agentapi.v1.AckOutcome: value ACK_OUTCOME_DUPLICATE = 2, want "ACK_OUTCOME_RETRY_LATER"`,
		`warden.agentapi.v1.AckOutcome: value ACK_OUTCOME_RETRY_LATER = 3, want "ACK_OUTCOME_DUPLICATE"`,
		`warden.agentapi.v1.NoSuchEnum: row has no enum`,
		`warden.agentapi.v1.OmitReason: value OMIT_REASON_REDACTION = 2, want ""`,
		`warden.agentapi.v1.ReplyKind: missing value REPLY_KIND_EXTRA = 4`,
		`warden.agentapi.v1.WithheldReason: enum has no row`,
	}
	// Violations of the real table are reported by TestAgentapiEnumValues;
	// only the injected ones are compared here.
	baseline := enumViolations(agentapiPkg, eds, agentapiEnums)
	got := slices.DeleteFunc(enumViolations(agentapiPkg, eds, bad), func(v string) bool {
		return slices.Contains(baseline, v)
	})
	if !slices.Equal(got, want) {
		t.Errorf("violations =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
