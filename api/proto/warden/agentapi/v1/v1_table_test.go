package agentapiv1_test

// v1Table is the hand-written golden table of every warden.v1 message
// (agent-api R52c rule 1, extended to warden.v1 by the M2 envelope change,
// decision 0008 as amended 2026-10-25; issue #57): the envelope
// (action-envelope §4.1, §4.2), the typed requests (typed-action-catalog
// §4.1–§4.4), PrimitiveResult and its variants (§4.8, §4.8.1), the IPC
// refusal (executor-ipc §4.3) and the executor bodies with their messages
// (executor-ipc §4.6, §4.7).
//
// Each limit is the spec's limit written as the option of the same meaning
// (agent-api §4.10.1). Readings where a spec rule needs one, recorded in
// the PR for issue #57 and listed in api/proto/warden/v1/README.md:
//
//	V1 A field that may be absent ("absent when", "present only when",
//	   "or empty") carries the bounds of its present value except a least
//	   length or value the absent zero would fail; that part stays
//	   hand-written. A pattern on such a string is made optional as a
//	   whole, as for AdminToolRecord.release_version. A proto3 optional
//	   field carries the bounds of its present value.
//	V2 "0 or a … b" carries only the greatest value; a bound that depends
//	   on the server (100 × online CPUs) or the engine stays hand-written.
//	   A signed integer whose spec range starts at 0 ("clamped to
//	   0 … 2^40 − 1", "MySQL 1 … 2^40 − 1, PostgreSQL 0") also carries
//	   min_int 0, because a negative value is outside every case.
//	V3 A repeated integer carries counts only; per-element value ranges
//	   stay hand-written. A repeated string or bytes field's min_bytes and
//	   max_bytes apply to each element (options.proto).
//	V4 required: on an enum whose UNSPECIFIED is invalid with no presence
//	   condition (typed-action-catalog §4.1 and §4.8.1, executor-ipc §4.5),
//	   and on every field a spec row marks "required" without a condition.
//	V5 max_message_bytes on the warden.v1 messages a spec gives a whole-
//	   message limit: SignedEnvelope (MAX_ENVELOPE_BYTES, 16,384),
//	   IpcRefusal (16), PrimitiveResult (MAX_RESULT_BYTES, 32,768) and
//	   ExecutorResultBody (the signed result body, 1,024).
//	V6 A field the spec gives no length beyond a whole-message limit or
//	   a referenced format carries that bound: SignedEnvelope.body
//	   max_bytes 16,384; a server_id 36; a request unit or instance 256
//	   (as LogEvent.unit_id and DbInstanceHealth.unit_id; the pattern caps
//	   it at 249); a request container 128 (the name pattern's length; a
//	   full id is 64); installed_release_version 32 with the optional
//	   SemVer pattern.
//
// Requests and the envelope are outside redaction.md R5's scope, so they
// carry no redact_class.
var v1Table = msgTable{
	// action-envelope §4.1
	"SignedEnvelope": {opts: maxMsg(16384), fields: []fieldSpec{
		{1, "key_id", "bytes", exactB(32)},
		{2, "body", "bytes", o(minB(1), maxB(16384))},
		{3, "signature", "bytes", exactB(64)},
	}},
	// action-envelope §4.2; created_at and expires_at from R16
	"EnvelopeBody": {opts: none, fields: []fieldSpec{
		{1, "format_version", "uint32", formatV1},
		{2, "action_id", "string", o(exactB(36), pat(uuidV7))},
		{3, "target_server_id", "string", o(exactB(36), pat(uuidV4Pattern))},
		{4, "playbook_id", "string", o(maxB(63), pat(playbookID))},
		{5, "playbook_version", "string", o(maxB(32), pat(semverPattern))},
		{6, "playbook_digest", "bytes", exactB(32)},
		{7, "step_id", "string", o(maxB(63), pat(stepID))},
		{8, "params", "M:TypedRequest", req},
		{9, "policy_decision", "M:PolicyDecision", req},
		{10, "created_at", "int64", o(minI(1), maxI(1<<40-1))},
		{11, "expires_at", "int64", o(minI(1), maxI(1<<40-1))},
		// "No .." (R13 test list) stays hand-written beside the pattern.
		{12, "idempotency_key", "string", o(minB(1), maxB(128), pat(idempotencyKey))},
		{13, "envelope_counter", "uint64", o(minU(1), maxU(1<<63-1))},
	}},
	"PolicyDecision": {opts: none, fields: []fieldSpec{
		{1, "decision_id", "string", o(exactB(36), pat(uuidV4Pattern))},
		{2, "autonomy_level", "E:AutonomyLevel", req},
		{3, "policy_bundle_digest", "bytes", exactB(32)},
		{4, "approval_id", "string", o(maxB(36), pat(optUUIDv4))},
	}},

	// typed-action-catalog §4.4. "Exactly one set" is EnvelopeBody.params'
	// required option and the oneof itself.
	"TypedRequest": {oneof: "request", opts: none, fields: []fieldSpec{
		{1, "fs_usage", "M:FsUsageRequest", none},
		{2, "fs_largest_entries", "M:FsLargestEntriesRequest", none},
		{3, "service_status", "M:ServiceStatusRequest", none},
		{4, "web_config_test", "M:WebConfigTestRequest", none},
		{5, "cert_inspect", "M:CertInspectRequest", none},
		{6, "process_top", "M:ProcessTopRequest", none},
		{7, "mem_status", "M:MemStatusRequest", none},
		{8, "container_inspect", "M:ContainerInspectRequest", none},
		{9, "db_query_readonly", "M:DbQueryReadonlyRequest", none},
		{10, "db_backup_verify", "M:DbBackupVerifyRequest", none},
		{11, "service_restart", "M:ServiceRestartRequest", none},
		{12, "service_reset_failed", "M:ServiceResetFailedRequest", none},
		{13, "service_reload", "M:ServiceReloadRequest", none},
		{14, "service_start", "M:ServiceStartRequest", none},
		{15, "service_set_cpu_quota", "M:ServiceSetCpuQuotaRequest", none},
		{16, "process_signal", "M:ProcessSignalRequest", none},
		{17, "file_delete_by_age", "M:FileDeleteByAgeRequest", none},
		{18, "journal_vacuum", "M:JournalVacuumRequest", none},
		{19, "pkg_cache_clean", "M:PkgCacheCleanRequest", none},
		{21, "container_restart", "M:ContainerRestartRequest", none},
		{22, "db_terminate_session", "M:DbTerminateSessionRequest", none},
	}},
	"FsUsageRequest": {opts: none, fields: []fieldSpec{
		{1, "mount_path", "string", absPath},
	}},
	"FsLargestEntriesRequest": {opts: none, fields: []fieldSpec{
		{1, "path", "string", absPath},
		{2, "max_depth", "uint32", o(minU(1), maxU(4))},
		{3, "top_n", "uint32", o(minU(1), maxU(50))},
		{4, "min_size_bytes", "uint64", maxU(1 << 50)},
		{5, "modified_within_seconds", "uint32", maxU(31536000)},
	}},
	"ServiceStatusRequest": unitRequest(),
	"WebConfigTestRequest": {opts: none, fields: []fieldSpec{
		{1, "server", "E:WebServer", req},
	}},
	"CertInspectRequest": {opts: none, fields: []fieldSpec{
		{1, "path", "string", absPath},
	}},
	"ProcessTopRequest": {opts: none, fields: []fieldSpec{
		{1, "order_by", "E:ProcessOrder", req},
		{2, "top_n", "uint32", o(minU(1), maxU(50))},
		{3, "sample_ms", "uint32", o(minU(200), maxU(5000))},
	}},
	"MemStatusRequest": {opts: none},
	"ContainerInspectRequest": {opts: none, fields: []fieldSpec{
		{1, "container", "string", containerRef},
	}},
	"DbQueryReadonlyRequest": {opts: none, fields: []fieldSpec{
		{1, "engine", "E:Engine", req},
		{2, "instance", "string", unitRef},
		{3, "query", "E:DbQuery", req},
		// Only for list queries, ignored otherwise (V1).
		{4, "limit", "uint32", maxU(100)},
	}},
	"DbBackupVerifyRequest": {opts: none, fields: []fieldSpec{
		{1, "engine", "E:Engine", req},
		{2, "instance", "string", unitRef},
		{3, "backup_location_id", "uint32", o(minU(1), maxU(16))},
		{4, "max_age_hours", "uint32", o(minU(1), maxU(720))},
		{5, "min_size_bytes", "uint64", o(minU(1), maxU(1<<50))},
	}},
	"ServiceRestartRequest":     unitRequest(),
	"ServiceResetFailedRequest": unitRequest(),
	"ServiceReloadRequest":      unitRequest(),
	"ServiceStartRequest":       unitRequest(),
	"ServiceSetCpuQuotaRequest": {opts: none, fields: []fieldSpec{
		{1, "unit", "string", unitRef},
		// 10 … 100 × online CPUs, or 0: server-dependent (V2).
		{2, "cpu_quota_percent", "uint32", none},
		{3, "pid", "uint32", maxU(4194304)},
		{4, "start_time_ticks", "uint64", maxU(1 << 62)},
	}},
	"ProcessSignalRequest": {opts: none, fields: []fieldSpec{
		{1, "pid", "uint32", o(minU(2), maxU(4194304))},
		{2, "start_time_ticks", "uint64", o(minU(1), maxU(1<<62))},
		{3, "signal", "E:Signal", req},
	}},
	"FileDeleteByAgeRequest": {opts: none, fields: []fieldSpec{
		{1, "root", "E:FileDeleteRoot", req},
		{2, "min_age_days", "uint32", o(minU(7), maxU(365))},
		{3, "max_files", "uint32", o(minU(1), maxU(10000))},
		{4, "max_bytes", "uint64", o(minU(1), maxU(1<<44))},
		{5, "dry_run", "bool", none},
	}},
	"JournalVacuumRequest": {opts: none, fields: []fieldSpec{
		{1, "keep_days", "uint32", o(minU(7), maxU(365))},
	}},
	"PkgCacheCleanRequest": {opts: none},
	"ContainerRestartRequest": {opts: none, fields: []fieldSpec{
		{1, "container", "string", containerRef},
		{2, "stop_timeout_seconds", "uint32", o(minU(1), maxU(120))},
	}},
	"DbTerminateSessionRequest": {opts: none, fields: []fieldSpec{
		{1, "engine", "E:Engine", req},
		{2, "instance", "string", unitRef},
		// Per-engine id ranges and "no duplicates" stay hand-written (V3).
		{3, "session_ids", "repeated uint64", o(minC(1), maxC(20))},
		{4, "session_started_at", "repeated int64", maxC(20)},
		// MySQL/MariaDB 1 … 2^40 − 1, PostgreSQL 0 (V2).
		{5, "server_started_at", "int64", o(minI(0), maxI(1<<40-1))},
		// MySQL/MariaDB one per id, PostgreSQL none (V3).
		{6, "session_owner_digests", "repeated bytes", o(maxC(20), exactB(32))},
		{7, "min_idle_seconds", "uint32", o(minU(60), maxU(86400))},
	}},

	// typed-action-catalog §4.8
	"PrimitiveResult": {opts: maxMsg(32768), fields: []fieldSpec{
		{1, "status", "E:PrimitiveStatus", req},
		{2, "error_code", "E:PrimitiveErrorCode", none},
		{3, "exit_status", "optional int32", none},
		{4, "output_truncated", "bool", none},
		{5, "started_at", "int64", none},
		{6, "finished_at", "int64", none},
		{7, "result", "M:TypedResult", none},
	}},
	"TypedResult": {oneof: "result", opts: none, fields: []fieldSpec{
		{1, "fs_usage", "M:FsUsageResult", none},
		{2, "fs_largest_entries", "M:FsLargestEntriesResult", none},
		{3, "service_status", "M:ServiceStatusResult", none},
		{4, "web_config_test", "M:WebConfigTestResult", none},
		{5, "cert_inspect", "M:CertInspectResult", none},
		{6, "process_top", "M:ProcessTopResult", none},
		{7, "mem_status", "M:MemStatusResult", none},
		{8, "container_inspect", "M:ContainerInspectResult", none},
		{9, "db_query_readonly", "M:DbQueryReadonlyResult", none},
		{10, "db_backup_verify", "M:DbBackupVerifyResult", none},
		{11, "service_restart", "M:ServiceRestartResult", none},
		{12, "service_reset_failed", "M:ServiceResetFailedResult", none},
		{13, "service_reload", "M:ServiceReloadResult", none},
		{14, "service_start", "M:ServiceStartResult", none},
		{15, "service_set_cpu_quota", "M:ServiceSetCpuQuotaResult", none},
		{16, "process_signal", "M:ProcessSignalResult", none},
		{17, "file_delete_by_age", "M:FileDeleteByAgeResult", none},
		{18, "journal_vacuum", "M:JournalVacuumResult", none},
		{19, "pkg_cache_clean", "M:PkgCacheCleanResult", none},
		{21, "container_restart", "M:ContainerRestartResult", none},
		{22, "db_terminate_session", "M:DbTerminateSessionResult", none},
	}},

	// typed-action-catalog §4.8.1
	"FsUsageResult": {opts: none, fields: []fieldSpec{
		{1, "fs_type", "string", o(minB(1), maxB(32), rc(clsTName))},
		{2, "total_bytes", "uint64", none},
		{3, "used_bytes", "uint64", none},
		{4, "available_bytes", "uint64", none},
		{5, "inodes_total", "uint64", none},
		{6, "inodes_used", "uint64", none},
		{7, "read_only", "bool", none},
	}},
	"FsLargestEntriesResult": {opts: none, fields: []fieldSpec{
		{1, "entries", "repeated M:FsLargestEntry", maxC(50)},
		{2, "entries_scanned", "uint64", none},
		{3, "truncated", "bool", none},
	}},
	"FsLargestEntry": {opts: none, fields: []fieldSpec{
		{1, "path", "string", o(minB(1), maxB(4095), rc(clsTPath))},
		{2, "kind", "E:FsEntryKind", req},
		{3, "size_bytes", "uint64", none},
		{4, "modified_at", "int64", o(minI(0), maxI(1<<40-1))},
	}},
	"ServiceStatusResult": {opts: none, fields: []fieldSpec{
		{1, "load_state", "E:UnitLoadState", req},
		{2, "active_state", "E:UnitActiveState", req},
		{3, "sub_state", "E:ServiceSubState", req},
		{4, "result", "E:ServiceRunResult", req},
		{5, "n_restarts", "uint32", none},
		{6, "exec_main_status", "int32", none},
		{7, "exec_main_pid", "uint32", none},
		{8, "active_enter_timestamp_monotonic", "uint64", none},
		{9, "can_reload", "bool", none},
		{10, "cpu_quota_per_sec_usec", "uint64", none},
	}},
	"WebConfigTestResult": {opts: none, fields: []fieldSpec{
		{1, "ok", "bool", none},
		{2, "messages", "repeated string", o(maxC(20), minB(1), maxB(512), rc(clsTText))},
		{3, "truncated", "bool", none},
	}},
	"CertInspectResult": {opts: none, fields: []fieldSpec{
		{1, "certificates", "repeated M:CertificateInfo", maxC(10)},
		{2, "truncated", "bool", none},
	}},
	"CertificateInfo": {opts: none, fields: []fieldSpec{
		{1, "subject_cn", "string", o(maxB(255), rc(clsTName))},
		{2, "dns_names", "repeated string", o(maxC(50), minB(1), maxB(255), rc(clsTName))},
		{3, "issuer_cn", "string", o(maxB(255), rc(clsTName))},
		{4, "not_before", "int64", none},
		{5, "not_after", "int64", none},
		{6, "serial_hex", "string", o(minB(1), maxB(64), pat(lowerHex), rc(clsTName))},
		// A fixed-size digest: X (redaction.md §4.1, "every field not
		// listed").
		{7, "sha256_fingerprint", "bytes", o(exactB(32), rc(clsX))},
	}},
	"ProcessTopResult": {opts: none, fields: []fieldSpec{
		{1, "processes", "repeated M:ProcessInfo", maxC(50)},
	}},
	"ProcessInfo": {opts: none, fields: []fieldSpec{
		{1, "pid", "uint32", none},
		{2, "start_time_ticks", "uint64", none},
		{3, "comm", "string", o(maxB(15), rc(clsTName))},
		{4, "uid", "uint32", none},
		{5, "unit", "string", o(maxB(256), rc(clsTName))},
		{6, "cpu_percent", "uint32", none},
		{7, "rss_bytes", "uint64", none},
		{8, "state", "E:ProcessState", req},
	}},
	"MemStatusResult": {opts: none, fields: []fieldSpec{
		{1, "total_bytes", "uint64", none},
		{2, "available_bytes", "uint64", none},
		{3, "swap_total_bytes", "uint64", none},
		{4, "swap_free_bytes", "uint64", none},
		{5, "psi_some_avg10", "optional uint32", maxU(10000)},
		{6, "psi_full_avg10", "optional uint32", maxU(10000)},
		{7, "oom_kills_since_boot", "uint64", none},
	}},
	"ContainerInspectResult": {opts: none, fields: []fieldSpec{
		{1, "id", "string", o(exactB(64), pat(containerID), rc(clsTName))},
		{2, "name", "string", o(maxB(128), pat(containerName), rc(clsTName))},
		{3, "state", "E:ContainerState", req},
		{4, "health", "E:ContainerHealth", req},
		{5, "restart_count", "uint32", none},
		{6, "exit_code", "int32", none},
		{7, "started_at", "int64", none},
		{8, "finished_at", "int64", none},
		{9, "failing_streak", "uint32", none},
	}},
	"DbQueryReadonlyResult": {opts: none, fields: []fieldSpec{
		{1, "data", "M:DbQueryData", req},
		{2, "truncated", "bool", none},
	}},
	// Member numbers equal the request's DbQuery values (ruling (a)).
	"DbQueryData": {oneof: "query", opts: none, fields: []fieldSpec{
		{1, "server_status", "M:DbServerStatus", none},
		{2, "connections_summary", "M:DbConnectionsSummary", none},
		{3, "sessions_top_idle", "M:DbSessionsTopIdle", none},
		{4, "replication_status", "M:DbReplicationStatus", none},
		{5, "replset_status", "M:DbReplsetStatus", none},
	}},
	"DbServerStatus": {opts: none, fields: []fieldSpec{
		{1, "version", "string", o(minB(1), maxB(64), rc(clsTName))},
		{2, "uptime_seconds", "uint64", none},
		{3, "read_only", "bool", none},
	}},
	"DbConnectionsSummary": {opts: none, fields: []fieldSpec{
		{1, "max_connections", "uint32", none},
		{2, "current", "uint32", none},
		{3, "active", "uint32", none},
		{4, "idle", "uint32", none},
		{5, "idle_in_transaction", "uint32", none},
		{6, "reserved_superuser", "uint32", none},
	}},
	"DbSessionsTopIdle": {opts: none, fields: []fieldSpec{
		{1, "sessions", "repeated M:DbSession", maxC(100)},
		{2, "server_started_at", "int64", none},
	}},
	"DbSession": {opts: none, fields: []fieldSpec{
		{1, "session_id", "uint64", none},
		{2, "session_started_at", "int64", none},
		{3, "owner_digest", "bytes", o(maxB(32), rc(clsX))},
		{4, "user", "string", o(maxB(64), rc(clsTName))},
		{5, "database", "string", o(maxB(64), rc(clsTName))},
		{6, "client_kind", "E:DbClientKind", req},
		{7, "state", "E:DbSessionState", req},
		{8, "idle_seconds", "uint64", none},
		{9, "transaction_age_seconds", "uint64", none},
	}},
	"DbReplicationStatus": {opts: none, fields: []fieldSpec{
		{1, "role", "E:DbReplicationRole", req},
		{2, "lag_seconds", "optional uint64", none},
	}},
	"DbReplsetStatus": {opts: none, fields: []fieldSpec{
		{1, "members", "repeated M:DbReplsetMember", maxC(50)},
	}},
	"DbReplsetMember": {opts: none, fields: []fieldSpec{
		{1, "name", "string", o(minB(1), maxB(255), rc(clsTName))},
		{2, "state", "E:DbMemberState", req},
		{3, "health", "bool", none},
		{4, "optime_lag_seconds", "optional uint64", none},
		{5, "is_self", "bool", none},
	}},
	"DbBackupVerifyResult": {opts: none, fields: []fieldSpec{
		{1, "found", "bool", none},
		{2, "newest_name", "string", o(maxB(255), rc(clsTName))},
		{3, "age_seconds", "uint64", none},
		{4, "size_bytes", "uint64", none},
		{5, "format", "E:BackupFormat", none},
		{6, "format_ok", "bool", none},
		{7, "checks_failed", "repeated E:BackupCheck", o(maxC(4), sorted)},
	}},
	"ServiceRestartResult":     beforeAfter("M:ServiceStatusResult"),
	"ServiceResetFailedResult": beforeAfter("M:ServiceStatusResult"),
	"ServiceReloadResult":      beforeAfter("M:ServiceStatusResult"),
	"ServiceStartResult":       beforeAfter("M:ServiceStatusResult"),
	"ServiceSetCpuQuotaResult": {opts: none, fields: []fieldSpec{
		{1, "previous_cpu_quota_percent", "uint32", none},
		{2, "new_cpu_quota_percent", "uint32", none},
	}},
	"ProcessSignalResult": {opts: none, fields: []fieldSpec{
		{1, "delivered", "bool", none},
		{2, "exited_within_wait", "bool", none},
	}},
	"FileDeleteByAgeResult": {opts: none, fields: []fieldSpec{
		{1, "files_deleted", "uint32", none},
		{2, "bytes_freed", "uint64", none},
		{3, "oldest_age_days", "uint32", none},
		{4, "newest_age_days", "uint32", none},
		{5, "stopped_by_limit", "bool", none},
	}},
	"JournalVacuumResult":    beforeAfterBytes(),
	"PkgCacheCleanResult":    beforeAfterBytes(),
	"ContainerRestartResult": beforeAfter("M:ContainerInspectResult"),
	"DbTerminateSessionResult": {opts: none, fields: []fieldSpec{
		{1, "sessions", "repeated M:DbSessionOutcome", o(minC(1), maxC(20))},
	}},
	"DbSessionOutcome": {opts: none, fields: []fieldSpec{
		{1, "session_id", "uint64", none},
		{2, "outcome", "E:DbTerminateOutcome", req},
	}},

	// executor-ipc §4.3
	"IpcRefusal": {opts: maxMsg(16), fields: []fieldSpec{
		{1, "code", "E:IpcRefusalCode", req},
	}},

	// executor-ipc §4.6.1
	"ExecutorResultBody": {opts: maxMsg(1024), fields: []fieldSpec{
		{1, "format_version", "uint32", formatV1},
		{2, "server_id", "string", o(maxB(36), pat(optUUIDv4), rc(clsX))},
		{3, "envelope_sha256", "bytes", o(maxB(32), rc(clsX))},
		{4, "received_length", "uint32", none},
		{5, "body_sha256", "bytes", o(maxB(32), rc(clsX))},
		{6, "action_id", "string", o(maxB(36), pat(optUUIDv7), rc(clsX))},
		{7, "outcome", "E:ExecutorOutcome", req},
		{8, "rejection_code", "E:EnvelopeRejectionCode", none},
		{9, "primitive_status", "E:PrimitiveStatus", none},
		{10, "primitive_error_code", "E:PrimitiveErrorCode", none},
		{11, "exit_status", "optional int32", none},
		{12, "output_truncated", "bool", none},
		{13, "stored_state", "E:StoredState", none},
		{14, "stored_primitive_status", "E:PrimitiveStatus", none},
		{15, "stored_primitive_error_code", "E:PrimitiveErrorCode", none},
		{16, "received_at", "int64", req},
		{17, "started_at", "int64", none},
		{18, "finished_at", "int64", none},
		{19, "signed_at", "int64", req},
		{20, "stored_action_id", "optional string", o(exactB(36), pat(uuidV7), rc(clsX))},
		{21, "result_sequence", "uint64", none},
		{22, "boot_id", "bytes", o(exactB(16), req, rc(clsX))},
	}},

	// executor-ipc §4.6.2
	"TrustInstallResultBody": {opts: none, fields: []fieldSpec{
		{1, "format_version", "uint32", formatV1},
		{2, "server_id", "string", o(maxB(36), pat(optUUIDv4), rc(clsX))},
		{3, "kind", "E:TrustKind", req},
		{4, "document_sha256", "bytes", o(maxB(32), rc(clsX))},
		{5, "received_length", "optional uint32", none},
		{6, "result", "E:TrustInstallResult", req},
		{7, "minimum_sequence", "optional uint64", none},
		{8, "document_sequence", "optional uint64", none},
		{9, "installed", "repeated M:InstalledDocument", o(maxC(3), sortedBy("kind"))},
		{10, "controlplane_ca_sha256", "repeated bytes", o(maxC(2), exactB(32), sorted, rc(clsX))},
		{11, "received_at", "int64", req},
		{12, "signed_at", "int64", req},
		{13, "result_sequence", "uint64", none},
		{14, "boot_id", "bytes", o(exactB(16), req, rc(clsX))},
	}},
	"InstalledDocument": {opts: none, fields: []fieldSpec{
		{1, "kind", "E:TrustKind", req},
		{2, "sequence_state", "E:SequenceState", req},
		{3, "sequence", "uint64", maxU(1<<63 - 1)},
		{4, "hash_state", "E:HashState", req},
		{5, "hash", "bytes", o(maxB(32), rc(clsX))},
		{6, "installed_matches", "bool", none},
	}},

	// executor-ipc §4.7; fields 31 and 32 are the M2 envelope change
	// (agent-api R52a).
	"ExecutorStatusBody": {opts: none, fields: []fieldSpec{
		{1, "format_version", "uint32", formatV1},
		{2, "server_id", "string", o(maxB(36), pat(optUUIDv4), rc(clsX))},
		{3, "challenge", "bytes", o(maxB(32), rc(clsX))},
		{4, "executor_time", "int64", none},
		{5, "binary_version", "string", o(maxB(32), pat(semverPattern), rc(clsX))},
		{6, "installed_release_version", "string", o(maxB(32), pat(semverOrEmptyPattern), rc(clsNPatterned))},
		{7, "installed_release_sequence", "uint64", none},
		{8, "conditions", "repeated E:HealthCondition", o(maxC(32), sorted)},
		{9, "healthy", "bool", none},
		{10, "trust_state", "E:TrustState", req},
		{11, "installed", "repeated M:InstalledDocument", o(maxC(3), sortedBy("kind"))},
		{12, "keyset_signed_bytes", "bytes", o(maxB(4096), rc(clsS))},
		{13, "recovery_pending", "bool", none},
		{14, "recovery_id", "bytes", o(maxB(24), rc(clsX))},
		{15, "recovery_time", "int64", none},
		{16, "recovery_floor", "optional int64", none},
		{17, "frozen", "repeated M:FrozenPlaybook", o(maxC(64), sortedBy("playbook_id"))},
		{18, "controlplane_ca_sha256", "repeated bytes", o(maxC(2), exactB(32), sorted, rc(clsX))},
		{19, "root_key_fingerprint", "bytes", o(exactB(32), rc(clsX))},
		{20, "result_public_key", "bytes", o(maxB(32), rc(clsX))},
		{21, "feature_level", "M:FeatureLevel", req},
		{22, "database_unavailable_reason", "E:DatabaseUnavailableReason", none},
		{23, "db_instances", "repeated M:DbInstanceHealth", o(maxC(32), sortedBy("unit_id"))},
		{24, "db_conditions_since_start", "bool", none},
		{25, "store_records", "uint32", none},
		{26, "store_unreadable_records", "uint32", none},
		{27, "busy", "bool", none},
		{28, "db_instances_truncated", "bool", none},
		{29, "started_at", "int64", none},
		{30, "result_sequence", "uint64", none},
		// "As §4.6.1 field 22": exactly 16 and required (R36a).
		{31, "boot_id", "bytes", o(exactB(16), req, rc(clsX))},
		// Absent (0) when none is recorded (V1).
		{32, "highest_envelope_counter", "uint64", maxU(1<<63 - 1)},
	}},
	"FrozenPlaybook": {opts: none, fields: []fieldSpec{
		{1, "playbook_id", "string", o(maxB(63), pat(playbookID), rc(clsX))},
		{2, "frozen_at", "int64", none},
	}},
	"FeatureLevel": {opts: none, fields: []fieldSpec{
		{1, "cgroup_version", "E:CgroupVersion", req},
		{2, "helper_launch", "E:HelperLaunchMethod", req},
		{3, "helper_cleanup", "E:HelperCleanupMethod", req},
		{4, "process_identity", "E:ProcessIdentityMethod", req},
	}},
	"DbInstanceHealth": {opts: none, fields: []fieldSpec{
		{1, "unit_id", "string", o(maxB(256), pat(unitPattern), rc(clsNPatterned))},
		{2, "engine", "E:Engine", req},
		{3, "conditions", "repeated E:DbCondition", o(minC(1), maxC(6), sorted)},
		{4, "unchecked_databases", "uint32", maxU(64)},
		{5, "skipped_databases", "uint32", maxU(64)},
	}},
}

func beforeAfter(typ string) msgSpec {
	return msgSpec{opts: none, fields: []fieldSpec{
		{1, "before", typ, none},
		{2, "after", typ, none},
	}}
}

func beforeAfterBytes() msgSpec {
	return msgSpec{opts: none, fields: []fieldSpec{
		{1, "before_bytes", "uint64", none},
		{2, "after_bytes", "uint64", none},
	}}
}

// unitRequest is the row of a request whose only field is a systemd
// service unit (P3, P11–P14).
func unitRequest() msgSpec {
	return msgSpec{opts: none, fields: []fieldSpec{
		{1, "unit", "string", unitRef},
	}}
}

// Patterns and option sets the v1 table uses more than once.
const (
	uuidV7    = `^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`
	optUUIDv4 = `^(?:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})?$`
	optUUIDv7 = `^(?:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})?$`
	// action-envelope §4.2 fields 4 and 7.
	playbookID     = `^[a-z][a-z0-9-]{1,62}$`
	stepID         = `^[a-z][a-z0-9-]{0,62}$`
	idempotencyKey = `^[A-Za-z0-9._:-]+$`
	// typed-action-catalog §4.2.
	containerName = `^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`
	containerID   = `^[0-9a-f]{64}$`
	containerAny  = `^(?:[A-Za-z0-9][A-Za-z0-9_.-]{0,127}|[0-9a-f]{64})$`
	lowerHex      = `^[0-9a-f]+$`
)

var (
	formatV1 = o(minU(1), maxU(1))
	// typed-action-catalog §4.3 rule 1; the other path rules stay
	// hand-written.
	absPath      = o(minB(1), maxB(4095))
	unitRef      = o(maxB(256), pat(unitPattern))
	containerRef = o(maxB(128), pat(containerAny))
)
