package agentapiv1_test

// v1Table is the hand-written table of every warden.v1 message added by
// issue #12: PrimitiveResult and its variants (typed-action-catalog §4.8,
// §4.8.1), the IPC refusal (executor-ipc §4.3) and the executor bodies with
// their messages (executor-ipc §4.6, §4.7). Every message is top-level
// (executor-ipc §4.5).
//
// Options: in M1 a warden.v1 message carries only redact_class, on every
// string and bytes field in redaction.md R5's scope, with the class of
// redaction.md §4.1; no limit, count, pattern, required, sorted or
// max_message_bytes option (agent-api §4.10.1, Nofal, 2026-10-26). A
// non-string field of these messages is class X, so it carries nothing
// (§4.10.1 reading 2).
var v1Table = msgTable{
	// typed-action-catalog §4.8
	"PrimitiveResult": {opts: none, fields: []fieldSpec{
		{1, "status", "E:PrimitiveStatus", none},
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
		{1, "fs_type", "string", rc(clsTName)},
		{2, "total_bytes", "uint64", none},
		{3, "used_bytes", "uint64", none},
		{4, "available_bytes", "uint64", none},
		{5, "inodes_total", "uint64", none},
		{6, "inodes_used", "uint64", none},
		{7, "read_only", "bool", none},
	}},
	"FsLargestEntriesResult": {opts: none, fields: []fieldSpec{
		{1, "entries", "repeated M:FsLargestEntry", none},
		{2, "entries_scanned", "uint64", none},
		{3, "truncated", "bool", none},
	}},
	"FsLargestEntry": {opts: none, fields: []fieldSpec{
		{1, "path", "string", rc(clsTPath)},
		{2, "kind", "E:FsEntryKind", none},
		{3, "size_bytes", "uint64", none},
		{4, "modified_at", "int64", none},
	}},
	"ServiceStatusResult": {opts: none, fields: []fieldSpec{
		{1, "load_state", "E:UnitLoadState", none},
		{2, "active_state", "E:UnitActiveState", none},
		{3, "sub_state", "E:ServiceSubState", none},
		{4, "result", "E:ServiceRunResult", none},
		{5, "n_restarts", "uint32", none},
		{6, "exec_main_status", "int32", none},
		{7, "exec_main_pid", "uint32", none},
		{8, "active_enter_timestamp_monotonic", "uint64", none},
		{9, "can_reload", "bool", none},
		{10, "cpu_quota_per_sec_usec", "uint64", none},
	}},
	"WebConfigTestResult": {opts: none, fields: []fieldSpec{
		{1, "ok", "bool", none},
		{2, "messages", "repeated string", rc(clsTText)},
		{3, "truncated", "bool", none},
	}},
	"CertInspectResult": {opts: none, fields: []fieldSpec{
		{1, "certificates", "repeated M:CertificateInfo", none},
		{2, "truncated", "bool", none},
	}},
	"CertificateInfo": {opts: none, fields: []fieldSpec{
		{1, "subject_cn", "string", rc(clsTName)},
		{2, "dns_names", "repeated string", rc(clsTName)},
		{3, "issuer_cn", "string", rc(clsTName)},
		{4, "not_before", "int64", none},
		{5, "not_after", "int64", none},
		{6, "serial_hex", "string", rc(clsTName)},
		// A fixed-size digest: X (redaction.md §4.1, "every field not
		// listed").
		{7, "sha256_fingerprint", "bytes", rc(clsX)},
	}},
	"ProcessTopResult": {opts: none, fields: []fieldSpec{
		{1, "processes", "repeated M:ProcessInfo", none},
	}},
	"ProcessInfo": {opts: none, fields: []fieldSpec{
		{1, "pid", "uint32", none},
		{2, "start_time_ticks", "uint64", none},
		{3, "comm", "string", rc(clsTName)},
		{4, "uid", "uint32", none},
		{5, "unit", "string", rc(clsTName)},
		{6, "cpu_percent", "uint32", none},
		{7, "rss_bytes", "uint64", none},
		{8, "state", "E:ProcessState", none},
	}},
	"MemStatusResult": {opts: none, fields: []fieldSpec{
		{1, "total_bytes", "uint64", none},
		{2, "available_bytes", "uint64", none},
		{3, "swap_total_bytes", "uint64", none},
		{4, "swap_free_bytes", "uint64", none},
		{5, "psi_some_avg10", "optional uint32", none},
		{6, "psi_full_avg10", "optional uint32", none},
		{7, "oom_kills_since_boot", "uint64", none},
	}},
	"ContainerInspectResult": {opts: none, fields: []fieldSpec{
		{1, "id", "string", rc(clsTName)},
		{2, "name", "string", rc(clsTName)},
		{3, "state", "E:ContainerState", none},
		{4, "health", "E:ContainerHealth", none},
		{5, "restart_count", "uint32", none},
		{6, "exit_code", "int32", none},
		{7, "started_at", "int64", none},
		{8, "finished_at", "int64", none},
		{9, "failing_streak", "uint32", none},
	}},
	"DbQueryReadonlyResult": {opts: none, fields: []fieldSpec{
		{1, "data", "M:DbQueryData", none},
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
		{1, "version", "string", rc(clsTName)},
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
		{1, "sessions", "repeated M:DbSession", none},
		{2, "server_started_at", "int64", none},
	}},
	"DbSession": {opts: none, fields: []fieldSpec{
		{1, "session_id", "uint64", none},
		{2, "session_started_at", "int64", none},
		{3, "owner_digest", "bytes", rc(clsX)},
		{4, "user", "string", rc(clsTName)},
		{5, "database", "string", rc(clsTName)},
		{6, "client_kind", "E:DbClientKind", none},
		{7, "state", "E:DbSessionState", none},
		{8, "idle_seconds", "uint64", none},
		{9, "transaction_age_seconds", "uint64", none},
	}},
	"DbReplicationStatus": {opts: none, fields: []fieldSpec{
		{1, "role", "E:DbReplicationRole", none},
		{2, "lag_seconds", "optional uint64", none},
	}},
	"DbReplsetStatus": {opts: none, fields: []fieldSpec{
		{1, "members", "repeated M:DbReplsetMember", none},
	}},
	"DbReplsetMember": {opts: none, fields: []fieldSpec{
		{1, "name", "string", rc(clsTName)},
		{2, "state", "E:DbMemberState", none},
		{3, "health", "bool", none},
		{4, "optime_lag_seconds", "optional uint64", none},
		{5, "is_self", "bool", none},
	}},
	"DbBackupVerifyResult": {opts: none, fields: []fieldSpec{
		{1, "found", "bool", none},
		{2, "newest_name", "string", rc(clsTName)},
		{3, "age_seconds", "uint64", none},
		{4, "size_bytes", "uint64", none},
		{5, "format", "E:BackupFormat", none},
		{6, "format_ok", "bool", none},
		{7, "checks_failed", "repeated E:BackupCheck", none},
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
		{1, "sessions", "repeated M:DbSessionOutcome", none},
	}},
	"DbSessionOutcome": {opts: none, fields: []fieldSpec{
		{1, "session_id", "uint64", none},
		{2, "outcome", "E:DbTerminateOutcome", none},
	}},

	// executor-ipc §4.3
	"IpcRefusal": {opts: none, fields: []fieldSpec{
		{1, "code", "E:IpcRefusalCode", none},
	}},

	// executor-ipc §4.6.1
	"ExecutorResultBody": {opts: none, fields: []fieldSpec{
		{1, "format_version", "uint32", none},
		{2, "server_id", "string", rc(clsX)},
		{3, "envelope_sha256", "bytes", rc(clsX)},
		{4, "received_length", "uint32", none},
		{5, "body_sha256", "bytes", rc(clsX)},
		{6, "action_id", "string", rc(clsX)},
		{7, "outcome", "E:ExecutorOutcome", none},
		{8, "rejection_code", "E:EnvelopeRejectionCode", none},
		{9, "primitive_status", "E:PrimitiveStatus", none},
		{10, "primitive_error_code", "E:PrimitiveErrorCode", none},
		{11, "exit_status", "optional int32", none},
		{12, "output_truncated", "bool", none},
		{13, "stored_state", "E:StoredState", none},
		{14, "stored_primitive_status", "E:PrimitiveStatus", none},
		{15, "stored_primitive_error_code", "E:PrimitiveErrorCode", none},
		{16, "received_at", "int64", none},
		{17, "started_at", "int64", none},
		{18, "finished_at", "int64", none},
		{19, "signed_at", "int64", none},
		{20, "stored_action_id", "optional string", rc(clsX)},
		{21, "result_sequence", "uint64", none},
		{22, "boot_id", "bytes", rc(clsX)},
	}},

	// executor-ipc §4.6.2
	"TrustInstallResultBody": {opts: none, fields: []fieldSpec{
		{1, "format_version", "uint32", none},
		{2, "server_id", "string", rc(clsX)},
		{3, "kind", "E:TrustKind", none},
		{4, "document_sha256", "bytes", rc(clsX)},
		{5, "received_length", "optional uint32", none},
		{6, "result", "E:TrustInstallResult", none},
		{7, "minimum_sequence", "optional uint64", none},
		{8, "document_sequence", "optional uint64", none},
		{9, "installed", "repeated M:InstalledDocument", none},
		{10, "controlplane_ca_sha256", "repeated bytes", rc(clsX)},
		{11, "received_at", "int64", none},
		{12, "signed_at", "int64", none},
		{13, "result_sequence", "uint64", none},
		{14, "boot_id", "bytes", rc(clsX)},
	}},
	"InstalledDocument": {opts: none, fields: []fieldSpec{
		{1, "kind", "E:TrustKind", none},
		{2, "sequence_state", "E:SequenceState", none},
		{3, "sequence", "uint64", none},
		{4, "hash_state", "E:HashState", none},
		{5, "hash", "bytes", rc(clsX)},
		{6, "installed_matches", "bool", none},
	}},

	// executor-ipc §4.7, fields 1–30 only: 31 boot_id and 32
	// highest_envelope_counter arrive with the M2 envelope change (R52a).
	"ExecutorStatusBody": {opts: none, fields: []fieldSpec{
		{1, "format_version", "uint32", none},
		{2, "server_id", "string", rc(clsX)},
		{3, "challenge", "bytes", rc(clsX)},
		{4, "executor_time", "int64", none},
		{5, "binary_version", "string", rc(clsX)},
		{6, "installed_release_version", "string", rc(clsNPatterned)},
		{7, "installed_release_sequence", "uint64", none},
		{8, "conditions", "repeated E:HealthCondition", none},
		{9, "healthy", "bool", none},
		{10, "trust_state", "E:TrustState", none},
		{11, "installed", "repeated M:InstalledDocument", none},
		{12, "keyset_signed_bytes", "bytes", rc(clsS)},
		{13, "recovery_pending", "bool", none},
		{14, "recovery_id", "bytes", rc(clsX)},
		{15, "recovery_time", "int64", none},
		{16, "recovery_floor", "optional int64", none},
		{17, "frozen", "repeated M:FrozenPlaybook", none},
		{18, "controlplane_ca_sha256", "repeated bytes", rc(clsX)},
		{19, "root_key_fingerprint", "bytes", rc(clsX)},
		{20, "result_public_key", "bytes", rc(clsX)},
		{21, "feature_level", "M:FeatureLevel", none},
		{22, "database_unavailable_reason", "E:DatabaseUnavailableReason", none},
		{23, "db_instances", "repeated M:DbInstanceHealth", none},
		{24, "db_conditions_since_start", "bool", none},
		{25, "store_records", "uint32", none},
		{26, "store_unreadable_records", "uint32", none},
		{27, "busy", "bool", none},
		{28, "db_instances_truncated", "bool", none},
		{29, "started_at", "int64", none},
		{30, "result_sequence", "uint64", none},
	}},
	"FrozenPlaybook": {opts: none, fields: []fieldSpec{
		{1, "playbook_id", "string", rc(clsX)},
		{2, "frozen_at", "int64", none},
	}},
	"FeatureLevel": {opts: none, fields: []fieldSpec{
		{1, "cgroup_version", "E:CgroupVersion", none},
		{2, "helper_launch", "E:HelperLaunchMethod", none},
		{3, "helper_cleanup", "E:HelperCleanupMethod", none},
		{4, "process_identity", "E:ProcessIdentityMethod", none},
	}},
	"DbInstanceHealth": {opts: none, fields: []fieldSpec{
		{1, "unit_id", "string", rc(clsNPatterned)},
		{2, "engine", "E:Engine", none},
		{3, "conditions", "repeated E:DbCondition", none},
		{4, "unchecked_databases", "uint32", none},
		{5, "skipped_databases", "uint32", none},
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
