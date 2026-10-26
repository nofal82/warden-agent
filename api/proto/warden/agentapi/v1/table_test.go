package agentapiv1_test

import (
	"math"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// Patterns of agent-api §4, copied from the spec text (agent-identity §4.1,
// §4.2, §4.8; typed-action-catalog §4.2; agent-api §4.7 and §4.10.1).
const (
	uuidV4Pattern     = `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`
	instanceIDPattern = `^[0-9a-f]{32}$`
	tokenPattern      = `^wdn1_[A-Za-z0-9_-]{43}$`
	unitPattern       = `^[A-Za-z0-9][A-Za-z0-9:_.@-]{0,240}\.service$`
	metricNamePattern = `^[a-z_][a-z0-9_]{0,127}$`
	labelKeyPattern   = `^[a-z_][a-z0-9_]{0,63}$`
	ruleIDPattern     = `^[a-z][a-z0-9-]{1,62}$`
	// §4.10.1: strict SemVer 2.0.0 without build metadata.
	semverPattern = `^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?$`
	// §4.10.1: the same, made optional as a whole (empty outside the
	// update modes).
	semverOrEmptyPattern = `^(?:(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?)?$`
)

const (
	pow40      = uint64(1) << 40       // "≤ 2^40"
	maxSigned  = uint64(math.MaxInt64) // "1 … 2^63 − 1"
	formatOnly = uint64(1)             // a format_version limit of "`1`"
)

// agentapiTable is the hand-written table of every message of
// warden.agentapi.v1: field numbers, names and types (agent-api §4.1–§4.8)
// and the complete option set of each message and field (§4.2, §4.10,
// §4.10.1; redaction.md §4.1). It is the golden table of R52c rule 1. An
// empty set is written as none.
//
// Readings applied (§4.10.1 and Nofal, 2026-10-26): a lower bound of 0
// gets no min_* option; "exactly N" is min_bytes = max_bytes = N; "≥ 1" or
// "> 0" is min_uint 1 or min_int 1; a format_version of "`1`" is min_uint
// = max_uint = 1; "N chars" of a fixed-length identifier is exactly N
// bytes; redact_class is on every string and bytes field of an
// agent-to-control-plane message and on another field only when its class
// is not X (the format_version of EnrollRequest and RenewRequest, class
// I); control-plane-to-agent messages carry no redact_class.
var agentapiTable = msgTable{
	// §4.3
	"EnrollRequest": {opts: maxMsg(8192), fields: []fieldSpec{
		{1, "format_version", "uint32", o(minU(formatOnly), maxU(formatOnly), rc(clsI))},
		{2, "token", "string", o(exactB(48), pat(tokenPattern), rc(clsI))},
		{3, "server_id", "string", o(exactB(36), pat(uuidV4Pattern), rc(clsI))},
		{4, "csr", "bytes", o(minB(1), maxB(4096), rc(clsI))},
		{5, "executor_public_key", "bytes", o(exactB(32), rc(clsI))},
		{6, "executor_binding_mac", "bytes", o(exactB(32), rc(clsI))},
	}},
	"EnrollResponse": {opts: maxMsg(4608), fields: []fieldSpec{
		{1, "certificate", "bytes", o(minB(1), maxB(4096))},
	}},
	"RenewRequest": {opts: maxMsg(8192), fields: []fieldSpec{
		{1, "format_version", "uint32", o(minU(formatOnly), maxU(formatOnly), rc(clsI))},
		{2, "csr", "bytes", o(minB(1), maxB(4096), rc(clsI))},
	}},
	"RenewResponse": {oneof: "outcome", opts: maxMsg(4608), fields: []fieldSpec{
		{1, "certificate", "bytes", o(minB(1), maxB(4096))},
		{2, "refusal", "E:RenewalRefusal", none},
	}},

	// §4.4
	"AgentMessage": {oneof: "body", opts: none, fields: []fieldSpec{
		{1, "hello", "M:Hello", none},
		{2, "delivery_ack", "M:DeliveryAck", none},
		{3, "outbox", "M:OutboxMessage", none},
		{4, "health", "M:HealthReport", none},
	}},
	"Hello": {opts: maxMsg(512), fields: []fieldSpec{
		{1, "contract_version_min", "uint32", minU(1)},
		{2, "contract_version_max", "uint32", maxU(65535)},
		{3, "server_id", "string", o(exactB(36), pat(uuidV4Pattern), rc(clsX))},
		{4, "instance_id", "string", o(exactB(32), pat(instanceIDPattern), rc(clsX))},
		{5, "agent_version", "string", o(maxB(32), pat(semverPattern), rc(clsX))},
		{6, "executor_available", "bool", none},
	}},
	"DeliveryAck": {opts: maxMsg(32), fields: []fieldSpec{
		{1, "delivery_id", "uint64", minU(1)},
	}},
	"HealthReport": {opts: maxMsg(1024), fields: []fieldSpec{
		{1, "agent_time_ms", "int64", minI(1)},
		{2, "conditions", "repeated E:AgentCondition", o(maxC(16), sorted)},
		{3, "controlplane_ca_sha256", "repeated bytes", o(maxC(2), exactB(32), sorted, rc(clsX))},
		{4, "outbox_messages", "uint32", maxU(1_000_000)},
		{5, "outbox_bytes", "uint64", maxU(pow40)},
		{6, "telemetry_dropped_batches", "uint64", maxU(pow40)},
		{7, "rejected_messages", "uint64", maxU(pow40)},
		{8, "last_executor_status_at", "int64", none},
		{9, "redact_rules_version", "uint32", minU(1)},
		{10, "redact_drops", "repeated M:RedactDropCount", o(maxC(7), sortedBy("class"))},
	}},
	"RedactDropCount": {opts: none, fields: []fieldSpec{
		{1, "class", "E:RedactClass", none},
		{2, "dropped", "uint64", maxU(pow40)},
	}},

	// §4.5: control plane to agent, outside redaction R5's scope.
	"ControlMessage": {oneof: "body", opts: maxMsg(266240), fields: []fieldSpec{
		{1, "welcome", "M:Welcome", none},
		{2, "delivery", "M:Delivery", none},
		{3, "message_ack", "M:MessageAck", none},
	}},
	"Welcome": {opts: none, fields: []fieldSpec{
		{1, "contract_version", "uint32", none},
		{2, "control_plane_time_ms", "int64", minI(1)},
	}},
	"Delivery": {opts: none, fields: []fieldSpec{
		{1, "delivery_id", "uint64", minU(1)},
		{2, "content", "M:DeliveryContent", req},
	}},
	"DeliveryContent": {oneof: "content", opts: none, fields: []fieldSpec{
		{1, "envelope", "M:EnvelopeDelivery", none},
		{2, "trust_document", "M:TrustDocument", none},
		{3, "status_request", "M:StatusRequest", none},
	}},
	// §4.10.1: one of the two fields with no length option, by design.
	"EnvelopeDelivery": {opts: none, fields: []fieldSpec{
		{1, "signed_envelope", "bytes", none},
	}},
	"TrustDocument": {opts: none, fields: []fieldSpec{
		{1, "kind", "E:warden.v1.TrustKind", req},
		{2, "document", "bytes", none}, // §4.10.1 exemption
	}},
	"StatusRequest": {opts: none, fields: []fieldSpec{
		{1, "challenge", "bytes", exactB(32)},
		{2, "priority", "bool", none},
	}},
	"MessageAck": {opts: none, fields: []fieldSpec{
		{1, "message_seq", "uint64", minU(1)},
		{2, "outcome", "E:AckOutcome", req},
		{3, "reason", "E:AckReason", none},
	}},

	// §4.6
	"OutboxMessage": {opts: maxMsg(65536), fields: []fieldSpec{
		{1, "message_seq", "uint64", minU(1)},
		{2, "payload", "M:OutboxPayload", req},
	}},
	"OutboxPayload": {oneof: "payload", opts: none, fields: []fieldSpec{
		{1, "signed_reply", "M:SignedReplyReport", none},
		{2, "envelope_advisory", "M:EnvelopeAdvisory", none},
		{3, "trust_document_oversize", "M:TrustDocumentOversize", none},
		{4, "recovery_report", "M:RecoveryReport", none},
		{5, "admin_tool_record", "M:AdminToolRecord", none},
	}},
	"SignedReplyReport": {opts: none, fields: []fieldSpec{
		{1, "kind", "E:ReplyKind", req},
		// The option holds the largest per-kind size (R52c); the
		// per-kind sizes stay hand-written.
		{2, "signed", "bytes", o(maxB(28672), rc(clsS))},
		{3, "unsigned_body", "bytes", o(maxB(28672), rc(clsU))},
		{4, "primitive_result", "M:warden.v1.PrimitiveResult", none},
		{5, "advisory_document_sequence", "optional uint64", o(minU(1), maxU(maxSigned))},
		{6, "primitive_result_omitted", "bool", none},
		{7, "unsigned_body_withheld", "E:WithheldReason", none},
		{8, "primitive_result_omitted_reason", "E:OmitReason", none},
	}},
	"EnvelopeAdvisory": {opts: none, fields: []fieldSpec{
		{1, "envelope_sha256", "bytes", o(exactB(32), rc(clsX))},
		{2, "reason", "E:AdvisoryReason", req},
		{3, "last_ipc_refusal", "optional E:warden.v1.IpcRefusalCode", none},
	}},
	"TrustDocumentOversize": {opts: none, fields: []fieldSpec{
		{1, "kind", "E:warden.v1.TrustKind", req},
		{2, "received_size", "uint32", maxU(266240)},
	}},
	"RecoveryReport": {opts: none, fields: []fieldSpec{
		{1, "recovery_id", "bytes", o(exactB(24), rc(clsX))},
	}},
	"AdminToolRecord": {opts: none, fields: []fieldSpec{
		{1, "record_id", "bytes", o(exactB(16), rc(clsX))},
		{2, "mode", "E:AdminToolMode", req},
		{3, "code", "E:AdminToolCode", req},
		{4, "refused_sequence", "optional uint64", o(minU(1), maxU(maxSigned))},
		{5, "release_version", "string", o(maxB(32), pat(semverOrEmptyPattern), rc(clsNPatterned))},
		{6, "release_sequence", "optional uint64", o(minU(1), maxU(maxSigned))},
		{7, "recorded_at", "int64", minI(1)},
		{8, "signed_replies", "repeated bytes", o(maxC(2), maxB(1024), rc(clsS))},
	}},

	// §4.7
	"TelemetryBatch": {opts: maxMsg(262144), fields: []fieldSpec{
		{1, "format_version", "uint32", o(minU(formatOnly), maxU(formatOnly))},
		{2, "server_id", "string", o(exactB(36), pat(uuidV4Pattern), rc(clsX))},
		{3, "instance_id", "string", o(exactB(32), pat(instanceIDPattern), rc(clsX))},
		{4, "batch_seq", "uint64", minU(1)},
		{5, "collected_from_ms", "int64", minI(1)},
		{6, "collected_to_ms", "int64", none},
		{7, "samples", "repeated M:MetricSample", maxC(5000)},
		{8, "log_events", "repeated M:LogEvent", maxC(200)},
		{9, "dropped_batches", "uint64", maxU(pow40)},
	}},
	"MetricSample": {opts: none, fields: []fieldSpec{
		{1, "name", "string", o(maxB(128), pat(metricNamePattern), rc(clsX))},
		{2, "labels", "repeated M:Label", o(maxC(16), sortedBy("key"))},
		{3, "value", "double", none},
		{4, "timestamp_ms", "int64", none},
	}},
	"Label": {opts: none, fields: []fieldSpec{
		{1, "key", "string", o(maxB(64), pat(labelKeyPattern), rc(clsX))},
		{2, "value", "string", o(maxB(256), rc(clsLValue))},
	}},
	"LogEvent": {opts: none, fields: []fieldSpec{
		{1, "rule_id", "string", o(maxB(63), pat(ruleIDPattern), rc(clsX))},
		{2, "unit_id", "string", o(maxB(256), pat(unitPattern), rc(clsNPatterned))},
		{3, "observed_at_ms", "int64", none},
		{4, "count", "uint32", o(minU(1), maxU(1_000_000))},
		{5, "extract", "string", o(maxB(4096), rc(clsEText))},
	}},
	"TelemetryAck": {opts: none, fields: []fieldSpec{
		{1, "batch_seq", "uint64", minU(1)},
	}},

	// §4.8, R45
	"EndDetail": {opts: none, fields: []fieldSpec{
		{1, "reason", "E:EndReason", req},
	}},
}

// boundExempt is the pair of fields §4.10.1 leaves without a length
// option, by design (R52c rules 2 and 3).
var boundExempt = map[protoreflect.FullName]bool{
	"warden.agentapi.v1.EnvelopeDelivery.signed_envelope": true,
	"warden.agentapi.v1.TrustDocument.document":           true,
}

// sizeLimitedMessages is every message §4.2 gives a per-type limit; the
// limit of an AgentMessage member sits on the member type (§4.10).
var sizeLimitedMessages = map[protoreflect.FullName]bool{
	"warden.agentapi.v1.EnrollRequest":  true,
	"warden.agentapi.v1.EnrollResponse": true,
	"warden.agentapi.v1.RenewRequest":   true,
	"warden.agentapi.v1.RenewResponse":  true,
	"warden.agentapi.v1.Hello":          true,
	"warden.agentapi.v1.DeliveryAck":    true,
	"warden.agentapi.v1.OutboxMessage":  true,
	"warden.agentapi.v1.HealthReport":   true,
	"warden.agentapi.v1.TelemetryBatch": true,
	"warden.agentapi.v1.ControlMessage": true,
}

// requiredFields is the exact list of §4.10.1 for option 50012.
var requiredFields = []protoreflect.FullName{
	"warden.agentapi.v1.Delivery.content",
	"warden.agentapi.v1.TrustDocument.kind",
	"warden.agentapi.v1.MessageAck.outcome",
	"warden.agentapi.v1.OutboxMessage.payload",
	"warden.agentapi.v1.SignedReplyReport.kind",
	"warden.agentapi.v1.EnvelopeAdvisory.reason",
	"warden.agentapi.v1.TrustDocumentOversize.kind",
	"warden.agentapi.v1.AdminToolRecord.mode",
	"warden.agentapi.v1.AdminToolRecord.code",
	"warden.agentapi.v1.EndDetail.reason",
}

// r5Roots are the roots of redaction.md R5's walk: the agent-to-control-
// plane requests and stream messages (agent-api §4.3, §4.4, §4.6, §4.7)
// and the executor bodies the agent forwards or scans (executor-ipc §4.6,
// §4.7). PrimitiveResult is reached through SignedReplyReport.
var r5Roots = []protoreflect.FullName{
	"warden.agentapi.v1.EnrollRequest",
	"warden.agentapi.v1.RenewRequest",
	"warden.agentapi.v1.AgentMessage",
	"warden.agentapi.v1.TelemetryBatch",
	"warden.v1.ExecutorResultBody",
	"warden.v1.TrustInstallResultBody",
	"warden.v1.ExecutorStatusBody",
}
