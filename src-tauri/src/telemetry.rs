use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

static ID_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum OtlpAnyValue {
    String(String),
    Bool(bool),
    Int(i64),
    Double(f64),
    Bytes(Vec<u8>),
    StringArray(Vec<String>),
}

impl OtlpAnyValue {
    fn to_json(&self) -> Value {
        match self {
            Self::String(value) => json!({ "stringValue": value }),
            Self::Bool(value) => json!({ "boolValue": value }),
            Self::Int(value) => json!({ "intValue": value.to_string() }),
            Self::Double(value) => json!({ "doubleValue": value }),
            Self::Bytes(value) => {
                json!({ "bytesValue": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, value) })
            }
            Self::StringArray(values) => json!({
                "arrayValue": {
                    "values": values.iter().map(|value| json!({ "stringValue": value })).collect::<Vec<_>>()
                }
            }),
        }
    }

    fn from_json(value: &Value) -> Result<Self, String> {
        if let Some(value) = value.get("stringValue").and_then(Value::as_str) {
            return Ok(Self::String(value.to_string()));
        }
        if let Some(value) = value.get("boolValue").and_then(Value::as_bool) {
            return Ok(Self::Bool(value));
        }
        if let Some(value) = value.get("intValue") {
            let parsed = value
                .as_str()
                .and_then(|value| value.parse::<i64>().ok())
                .or_else(|| value.as_i64())
                .ok_or_else(|| "Invalid OTLP intValue".to_string())?;
            return Ok(Self::Int(parsed));
        }
        if let Some(value) = value.get("doubleValue").and_then(Value::as_f64) {
            return Ok(Self::Double(value));
        }
        if let Some(value) = value.get("bytesValue").and_then(Value::as_str) {
            return base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value)
                .map(Self::Bytes)
                .map_err(|error| error.to_string());
        }
        if let Some(values) = value
            .get("arrayValue")
            .and_then(|value| value.get("values"))
            .and_then(Value::as_array)
        {
            return values
                .iter()
                .map(|value| {
                    value
                        .get("stringValue")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .ok_or_else(|| "Invalid OTLP string array".to_string())
                })
                .collect::<Result<Vec<_>, _>>()
                .map(Self::StringArray);
        }
        Err("Unsupported OTLP AnyValue".to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct OtlpKeyValue {
    pub key: String,
    pub value: OtlpAnyValue,
}

impl OtlpKeyValue {
    pub fn string(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: OtlpAnyValue::String(value.into()),
        }
    }

    fn to_json(&self) -> Value {
        json!({ "key": self.key, "value": self.value.to_json() })
    }

    fn list_to_json(values: &[Self]) -> Result<String, String> {
        serde_json::to_string(&values.iter().map(Self::to_json).collect::<Vec<_>>())
            .map_err(|error| error.to_string())
    }

    fn list_from_json(raw: &str) -> Result<Vec<Self>, String> {
        let values = serde_json::from_str::<Vec<Value>>(raw).map_err(|error| error.to_string())?;
        values
            .into_iter()
            .map(|value| {
                let key = value
                    .get("key")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "Missing OTLP attribute key".to_string())?;
                let value = value
                    .get("value")
                    .ok_or_else(|| "Missing OTLP attribute value".to_string())?;
                Ok(Self {
                    key: key.to_string(),
                    value: OtlpAnyValue::from_json(value)?,
                })
            })
            .collect()
    }
}

pub struct OperationStart<'a> {
    pub name: &'a str,
    pub display_name: &'a str,
    pub category: &'a str,
    pub target_type: &'a str,
    pub target_id: &'a str,
    pub trigger: &'a str,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationQuery {
    pub category: Option<String>,
    pub state: Option<String>,
    pub trigger: Option<String>,
    pub search: Option<String>,
    pub page: Option<u32>,
    pub page_size: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationPage {
    pub items: Vec<OperationSummary>,
    pub total: u32,
    pub page: u32,
    pub page_size: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationSummary {
    pub trace_id: String,
    pub name: String,
    pub display_name: String,
    pub category: String,
    pub target_type: String,
    pub target_id: String,
    pub trigger: String,
    pub state: String,
    pub started_time_unix_nano: i64,
    pub ended_time_unix_nano: Option<i64>,
    pub span_count: u32,
    pub log_count: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationDetail {
    pub summary: OperationSummary,
    pub spans: Vec<SpanSummary>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpanSummary {
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub name: String,
    pub start_time_unix_nano: i64,
    pub end_time_unix_nano: Option<i64>,
    pub status_code: i64,
    pub status_message: String,
    pub attributes: Vec<OtlpKeyValue>,
    pub stdout_bytes: u32,
    pub stderr_bytes: u32,
    pub stdout_preview: Option<String>,
    pub stderr_preview: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputQuery {
    pub trace_id: String,
    pub span_id: String,
    pub stream: String,
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputPage {
    pub trace_id: String,
    pub span_id: String,
    pub stream: String,
    pub offset: u32,
    pub limit: u32,
    pub total_bytes: u32,
    pub text: Option<String>,
    pub bytes_base64: Option<String>,
}

pub struct LogInput {
    event_name: String,
    body: OtlpAnyValue,
    attributes: Vec<OtlpKeyValue>,
    severity_number: i64,
    severity_text: String,
}

#[derive(Debug, Clone)]
pub struct ExceptionInput {
    pub source: String,
    pub exception_type: String,
    pub message: String,
    pub stacktrace: String,
    pub location: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ExceptionUploadRecord {
    pub log_id: i64,
    pub record_id: String,
    pub trace_id: Vec<u8>,
    pub span_id: Vec<u8>,
    pub time_unix_nano: i64,
    pub severity_number: i64,
    pub severity_text: String,
    pub event_name: String,
    pub body_json: String,
    pub attributes_json: String,
    pub resource_attributes_json: String,
    pub scope_name: String,
    pub scope_version: String,
    pub scope_attributes_json: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OperationUploadRecord {
    pub trace_id: Vec<u8>,
    pub resource_attributes_json: String,
    pub scope_name: String,
    pub scope_version: String,
    pub scope_attributes_json: String,
    pub spans: Vec<OperationUploadSpan>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OperationUploadSpan {
    pub span_id: Vec<u8>,
    pub parent_span_id: Vec<u8>,
    pub trace_state: String,
    pub flags: i64,
    pub name: String,
    pub kind: i64,
    pub start_time_unix_nano: i64,
    pub end_time_unix_nano: i64,
    pub attributes_json: String,
    pub dropped_attributes_count: i64,
    pub status_code: i64,
    pub status_message: String,
    pub logs: Vec<OperationUploadLog>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OperationUploadLog {
    pub time_unix_nano: i64,
    pub severity_number: i64,
    pub severity_text: String,
    pub event_name: String,
    pub body_json: String,
    pub attributes_json: String,
    pub dropped_attributes_count: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandStream {
    Stdout,
    Stderr,
}

pub struct CommandRecord<'a> {
    pub args: &'a [String],
    pub stdout: &'a [u8],
    pub stderr: &'a [u8],
    pub success: bool,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub error: Option<&'a str>,
}

impl CommandStream {
    fn as_str(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }

    fn event_name(self) -> &'static str {
        match self {
            Self::Stdout => "agentdock.command.result.stdout",
            Self::Stderr => "agentdock.command.result.stderr",
        }
    }
}

impl LogInput {
    pub fn info(
        event_name: impl Into<String>,
        body: OtlpAnyValue,
        attributes: Vec<OtlpKeyValue>,
    ) -> Self {
        Self {
            event_name: event_name.into(),
            body,
            attributes,
            severity_number: 9,
            severity_text: "INFO".to_string(),
        }
    }

    fn error(
        event_name: impl Into<String>,
        body: OtlpAnyValue,
        attributes: Vec<OtlpKeyValue>,
    ) -> Self {
        Self {
            event_name: event_name.into(),
            body,
            attributes,
            severity_number: 17,
            severity_text: "ERROR".to_string(),
        }
    }
}

impl ExceptionInput {
    fn into_log(self) -> LogInput {
        let source = bounded_text(self.source, 256, "unknown");
        let exception_type = bounded_text(self.exception_type, 256, "Unknown");
        let message = bounded_text(self.message, 16_384, "Unknown exception");
        let stacktrace = truncate_utf8(self.stacktrace, 65_536);
        let location = truncate_utf8(self.location, 2_048);
        let mut attributes = vec![
            OtlpKeyValue::string("exception.type", exception_type),
            OtlpKeyValue::string("exception.message", &message),
            OtlpKeyValue::string("exception.stacktrace", stacktrace),
            OtlpKeyValue {
                key: "exception.escaped".to_string(),
                value: OtlpAnyValue::Bool(true),
            },
            OtlpKeyValue::string("agentdock.exception.source", source),
        ];
        if !location.is_empty() {
            attributes.push(OtlpKeyValue::string("code.filepath", location));
        }
        LogInput::error("exception", OtlpAnyValue::String(message), attributes)
    }
}

#[derive(Clone)]
pub struct SpanContext {
    store: Arc<TelemetryStore>,
    trace_id: Vec<u8>,
    span_id: Vec<u8>,
}

pub struct OperationContext {
    root: SpanContext,
}

impl OperationContext {
    pub fn trace_id(&self) -> &[u8] {
        &self.root.trace_id
    }

    pub fn span_id(&self) -> &[u8] {
        &self.root.span_id
    }

    pub fn root_span(&self) -> &SpanContext {
        &self.root
    }

    pub fn begin_span(
        &self,
        name: &str,
        attributes: Vec<OtlpKeyValue>,
    ) -> Result<SpanContext, String> {
        self.root.begin_child(name, attributes)
    }

    pub fn finish_ok(&self) -> Result<(), String> {
        self.root.finish(1, "")?;
        self.root
            .store
            .finish_operation(&self.root.trace_id, "success")
    }

    pub fn finish_error(&self, message: &str) -> Result<(), String> {
        self.root.finish(2, message)?;
        self.root
            .store
            .finish_operation(&self.root.trace_id, "error")
    }
}

impl SpanContext {
    pub fn trace_id(&self) -> &[u8] {
        &self.trace_id
    }

    pub fn span_id(&self) -> &[u8] {
        &self.span_id
    }

    pub fn begin_child(&self, name: &str, attributes: Vec<OtlpKeyValue>) -> Result<Self, String> {
        let span_id = generate_id(8);
        let attributes_json = OtlpKeyValue::list_to_json(&attributes)?;
        self.store
            .connection
            .lock()
            .map_err(|_| "Telemetry database lock poisoned".to_string())?
            .execute(
                "INSERT INTO otel_spans(
                   trace_id, span_id, parent_span_id, resource_id, scope_id,
                   name, start_time_unix_nano, attributes_json
                 ) VALUES(?1, ?2, ?3, 1, 1, ?4, ?5, ?6)",
                params![
                    self.trace_id,
                    span_id,
                    self.span_id,
                    name,
                    unix_nanos(),
                    attributes_json
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(Self {
            store: Arc::clone(&self.store),
            trace_id: self.trace_id.clone(),
            span_id,
        })
    }

    pub fn append_command_output(
        &self,
        stream: CommandStream,
        output: &[u8],
    ) -> Result<(), String> {
        for (sequence, chunk) in output.chunks(32 * 1024).enumerate() {
            let body = match std::str::from_utf8(chunk) {
                Ok(value) => OtlpAnyValue::String(value.to_string()),
                Err(_) => OtlpAnyValue::Bytes(chunk.to_vec()),
            };
            self.store.append_log(
                self,
                LogInput::info(
                    stream.event_name(),
                    body,
                    vec![
                        OtlpKeyValue::string("agentdock.command.stream", stream.as_str()),
                        OtlpKeyValue {
                            key: "agentdock.command.output.sequence".to_string(),
                            value: OtlpAnyValue::Int(sequence as i64),
                        },
                    ],
                ),
            )?;
        }
        Ok(())
    }

    pub fn append_command_record(&self, record: CommandRecord<'_>) -> Result<(), String> {
        let mut attributes = vec![
            OtlpKeyValue {
                key: "process.command_args".to_string(),
                value: OtlpAnyValue::StringArray(record.args.to_vec()),
            },
            OtlpKeyValue {
                key: "agentdock.command.stdout".to_string(),
                value: command_output_value(record.stdout),
            },
            OtlpKeyValue {
                key: "agentdock.command.stderr".to_string(),
                value: command_output_value(record.stderr),
            },
            OtlpKeyValue {
                key: "agentdock.command.success".to_string(),
                value: OtlpAnyValue::Bool(record.success),
            },
            OtlpKeyValue {
                key: "agentdock.command.duration_ms".to_string(),
                value: OtlpAnyValue::Int(record.duration_ms.min(i64::MAX as u64) as i64),
            },
        ];
        if let Some(exit_code) = record.exit_code {
            attributes.push(OtlpKeyValue {
                key: "process.exit.code".to_string(),
                value: OtlpAnyValue::Int(exit_code as i64),
            });
        }
        if let Some(error) = record.error.filter(|error| !error.is_empty()) {
            attributes.push(OtlpKeyValue::string("error.message", error));
        }
        let command = record.args.join(" ");
        let input = if record.success {
            LogInput::info(
                "agentdock.command",
                OtlpAnyValue::String(command),
                attributes,
            )
        } else {
            LogInput::error(
                "agentdock.command",
                OtlpAnyValue::String(command),
                attributes,
            )
        };
        self.store.append_log(self, input)
    }

    pub fn append_log(&self, input: LogInput) -> Result<(), String> {
        self.store.append_log(self, input)
    }

    pub fn finish_ok(&self) -> Result<(), String> {
        self.finish(1, "")
    }

    pub fn finish_error(&self, message: &str) -> Result<(), String> {
        self.finish(2, message)
    }

    fn finish(&self, status_code: i64, status_message: &str) -> Result<(), String> {
        self.store
            .connection
            .lock()
            .map_err(|_| "Telemetry database lock poisoned".to_string())?
            .execute(
                "UPDATE otel_spans
                 SET end_time_unix_nano = ?1, status_code = ?2, status_message = ?3
                 WHERE trace_id = ?4 AND span_id = ?5",
                params![
                    unix_nanos(),
                    status_code,
                    status_message,
                    self.trace_id,
                    self.span_id
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}

pub struct TelemetryStore {
    path: PathBuf,
    installation_id: String,
    connection: Mutex<Connection>,
}

impl TelemetryStore {
    pub fn open(path: &Path) -> Result<Arc<Self>, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let connection = Connection::open(path).map_err(|error| error.to_string())?;
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA foreign_keys = ON;
                 CREATE TABLE IF NOT EXISTS telemetry_schema (version INTEGER NOT NULL);
                 INSERT INTO telemetry_schema(version)
                   SELECT 2 WHERE NOT EXISTS (SELECT 1 FROM telemetry_schema);
                 CREATE TABLE IF NOT EXISTS telemetry_metadata (
                   key TEXT PRIMARY KEY,
                   value TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS operation_index (
                   trace_id BLOB PRIMARY KEY,
                   root_span_id BLOB NOT NULL,
                   name TEXT NOT NULL,
                   display_name TEXT NOT NULL,
                   category TEXT NOT NULL,
                   target_type TEXT NOT NULL,
                   target_id TEXT NOT NULL,
                   trigger TEXT NOT NULL,
                   state TEXT NOT NULL,
                   started_time_unix_nano INTEGER NOT NULL,
                   ended_time_unix_nano INTEGER,
                   recorded_size_bytes INTEGER NOT NULL DEFAULT 0,
                   upload_state TEXT NOT NULL DEFAULT 'not_configured'
                 );
                 CREATE TABLE IF NOT EXISTS otel_resources (
                   id INTEGER PRIMARY KEY,
                   schema_url TEXT NOT NULL DEFAULT '',
                   attributes_json TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS otel_scopes (
                   id INTEGER PRIMARY KEY,
                   name TEXT NOT NULL,
                   version TEXT NOT NULL,
                   schema_url TEXT NOT NULL DEFAULT '',
                   attributes_json TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS otel_spans (
                   trace_id BLOB NOT NULL,
                   span_id BLOB PRIMARY KEY,
                   parent_span_id BLOB,
                   resource_id INTEGER NOT NULL,
                   scope_id INTEGER NOT NULL,
                   trace_state TEXT NOT NULL DEFAULT '',
                   flags INTEGER NOT NULL DEFAULT 1,
                   name TEXT NOT NULL,
                   kind INTEGER NOT NULL DEFAULT 1,
                   start_time_unix_nano INTEGER NOT NULL,
                   end_time_unix_nano INTEGER,
                   attributes_json TEXT NOT NULL,
                   dropped_attributes_count INTEGER NOT NULL DEFAULT 0,
                   status_code INTEGER NOT NULL DEFAULT 0,
                   status_message TEXT NOT NULL DEFAULT '',
                   FOREIGN KEY(trace_id) REFERENCES operation_index(trace_id) ON DELETE CASCADE
                 );
                 CREATE TABLE IF NOT EXISTS otel_logs (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   record_id TEXT NOT NULL UNIQUE,
                   trace_id BLOB NOT NULL,
                   span_id BLOB NOT NULL,
                   resource_id INTEGER NOT NULL,
                   scope_id INTEGER NOT NULL,
                   time_unix_nano INTEGER NOT NULL,
                   observed_time_unix_nano INTEGER NOT NULL,
                   flags INTEGER NOT NULL DEFAULT 1,
                   severity_number INTEGER NOT NULL,
                   severity_text TEXT NOT NULL,
                   event_name TEXT NOT NULL,
                   body_json TEXT NOT NULL,
                   attributes_json TEXT NOT NULL,
                   dropped_attributes_count INTEGER NOT NULL DEFAULT 0,
                   upload_state TEXT NOT NULL DEFAULT 'pending',
                   upload_attempts INTEGER NOT NULL DEFAULT 0,
                   next_attempt_time_unix_nano INTEGER,
                   last_upload_error TEXT NOT NULL DEFAULT '',
                   uploaded_time_unix_nano INTEGER,
                   FOREIGN KEY(trace_id) REFERENCES operation_index(trace_id) ON DELETE CASCADE
                 );",
            )
            .map_err(|error| error.to_string())?;
        let schema_version = connection
            .query_row("SELECT version FROM telemetry_schema LIMIT 1", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(|error| error.to_string())?;
        match schema_version {
            1 => {
                let transaction = connection
                    .unchecked_transaction()
                    .map_err(|error| error.to_string())?;
                transaction
                    .execute_batch(
                        "ALTER TABLE otel_logs ADD COLUMN upload_state TEXT NOT NULL DEFAULT 'pending';
                         ALTER TABLE otel_logs ADD COLUMN upload_attempts INTEGER NOT NULL DEFAULT 0;
                         ALTER TABLE otel_logs ADD COLUMN next_attempt_time_unix_nano INTEGER;
                         ALTER TABLE otel_logs ADD COLUMN last_upload_error TEXT NOT NULL DEFAULT '';
                         ALTER TABLE otel_logs ADD COLUMN uploaded_time_unix_nano INTEGER;
                         UPDATE telemetry_schema SET version = 2;",
                    )
                    .map_err(|error| error.to_string())?;
                transaction.commit().map_err(|error| error.to_string())?;
            }
            2 => {}
            version => return Err(format!("Unsupported telemetry schema version: {version}")),
        }
        connection
            .execute(
                "UPDATE operation_index SET upload_state = 'retry' WHERE upload_state = 'uploading'",
                [],
            )
            .map_err(|error| error.to_string())?;
        let candidate_installation_id = format!("adk-{}", Uuid::new_v4());
        connection
            .execute(
                "INSERT OR IGNORE INTO telemetry_metadata(key, value)
                 VALUES('installation_id', ?1)",
                params![candidate_installation_id],
            )
            .map_err(|error| error.to_string())?;
        let installation_id = connection
            .query_row(
                "SELECT value FROM telemetry_metadata WHERE key = 'installation_id'",
                [],
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| error.to_string())?;
        let resource_attributes = telemetry_resource_attributes(&installation_id)?;
        connection
            .execute(
                "INSERT INTO otel_resources(id, attributes_json) VALUES(1, ?1)
                 ON CONFLICT(id) DO UPDATE SET attributes_json = excluded.attributes_json",
                params![resource_attributes],
            )
            .map_err(|error| error.to_string())?;
        Ok(Arc::new(Self {
            path: path.to_path_buf(),
            installation_id,
            connection: Mutex::new(connection),
        }))
    }

    #[cfg(test)]
    fn installation_id(&self) -> &str {
        &self.installation_id
    }

    pub fn begin_operation(
        self: &Arc<Self>,
        input: OperationStart<'_>,
    ) -> Result<OperationContext, String> {
        let trace_id = generate_id(16);
        let span_id = generate_id(8);
        let now = unix_nanos();
        let resource_attributes = telemetry_resource_attributes(&self.installation_id)?;
        let span_attributes = OtlpKeyValue::list_to_json(&[
            OtlpKeyValue::string("agentdock.operation.trigger", input.trigger),
            OtlpKeyValue::string("agentdock.target.type", input.target_type),
            OtlpKeyValue::string("agentdock.target.id", input.target_id),
        ])?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| "Telemetry database lock poisoned".to_string())?;
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        transaction
            .execute(
                "INSERT OR IGNORE INTO otel_resources(id, attributes_json) VALUES(1, ?1)",
                params![resource_attributes],
            )
            .map_err(|error| error.to_string())?;
        transaction
            .execute(
                "INSERT OR IGNORE INTO otel_scopes(id, name, version, attributes_json)
                 VALUES(1, 'com.agentdock.operations', ?1, '[]')",
                params![env!("CARGO_PKG_VERSION")],
            )
            .map_err(|error| error.to_string())?;
        transaction
            .execute(
                "INSERT INTO operation_index(
                   trace_id, root_span_id, name, display_name, category, target_type,
                   target_id, trigger, state, started_time_unix_nano
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'running', ?9)",
                params![
                    trace_id,
                    span_id,
                    input.name,
                    input.display_name,
                    input.category,
                    input.target_type,
                    input.target_id,
                    input.trigger,
                    now
                ],
            )
            .map_err(|error| error.to_string())?;
        transaction
            .execute(
                "INSERT INTO otel_spans(
                   trace_id, span_id, resource_id, scope_id, name,
                   start_time_unix_nano, attributes_json
                 ) VALUES(?1, ?2, 1, 1, ?3, ?4, ?5)",
                params![trace_id, span_id, input.name, now, span_attributes],
            )
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(OperationContext {
            root: SpanContext {
                store: Arc::clone(self),
                trace_id,
                span_id,
            },
        })
    }

    pub fn append_log(&self, span: &SpanContext, input: LogInput) -> Result<(), String> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| "Telemetry database lock poisoned".to_string())?;
        append_log_with_connection(&connection, &span.trace_id, &span.span_id, input)
    }

    pub fn record_exception_on_span(
        &self,
        span: &SpanContext,
        input: ExceptionInput,
    ) -> Result<(), String> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| "Telemetry database lock poisoned".to_string())?;
        record_exception_on_span_with_connection(&mut connection, span, input)
    }

    pub fn try_record_exception_on_span(&self, span: &SpanContext, input: ExceptionInput) -> bool {
        let Ok(mut connection) = self.connection.try_lock() else {
            return false;
        };
        record_exception_on_span_with_connection(&mut connection, span, input).is_ok()
    }

    pub fn record_standalone_exception(
        &self,
        target_id: &str,
        input: ExceptionInput,
    ) -> Result<(), String> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| "Telemetry database lock poisoned".to_string())?;
        record_standalone_exception_with_connection(
            &mut connection,
            &self.installation_id,
            target_id,
            input,
        )
    }

    pub fn try_record_standalone_exception(&self, target_id: &str, input: ExceptionInput) -> bool {
        let Ok(mut connection) = self.connection.try_lock() else {
            return false;
        };
        record_standalone_exception_with_connection(
            &mut connection,
            &self.installation_id,
            target_id,
            input,
        )
        .is_ok()
    }

    pub fn pending_exception_uploads(
        &self,
        now_unix_nano: i64,
        limit: usize,
        max_raw_bytes: usize,
    ) -> Result<Vec<ExceptionUploadRecord>, String> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| "Telemetry database lock poisoned".to_string())?;
        let mut statement = connection
            .prepare(
                "SELECT l.id, l.record_id, l.trace_id, l.span_id, l.time_unix_nano,
                        l.severity_number, l.severity_text, l.event_name, l.body_json,
                        l.attributes_json, r.attributes_json, s.name, s.version,
                        s.attributes_json
                 FROM otel_logs l
                 JOIN otel_resources r ON r.id = l.resource_id
                 JOIN otel_scopes s ON s.id = l.scope_id
                 WHERE l.event_name = 'exception'
                   AND (l.upload_state = 'pending'
                     OR (l.upload_state = 'retry'
                       AND COALESCE(l.next_attempt_time_unix_nano, 0) <= ?1))
                 ORDER BY l.id
                 LIMIT ?2",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(params![now_unix_nano, limit.clamp(1, 1000) as i64], |row| {
                Ok(ExceptionUploadRecord {
                    log_id: row.get(0)?,
                    record_id: row.get(1)?,
                    trace_id: row.get(2)?,
                    span_id: row.get(3)?,
                    time_unix_nano: row.get(4)?,
                    severity_number: row.get(5)?,
                    severity_text: row.get(6)?,
                    event_name: row.get(7)?,
                    body_json: row.get(8)?,
                    attributes_json: row.get(9)?,
                    resource_attributes_json: row.get(10)?,
                    scope_name: row.get(11)?,
                    scope_version: row.get(12)?,
                    scope_attributes_json: row.get(13)?,
                })
            })
            .map_err(|error| error.to_string())?;
        let mut records = Vec::new();
        let mut raw_bytes = 0_usize;
        for row in rows {
            let record = row.map_err(|error| error.to_string())?;
            let record_bytes = record.record_id.len()
                + record.trace_id.len()
                + record.span_id.len()
                + record.severity_text.len()
                + record.event_name.len()
                + record.body_json.len()
                + record.attributes_json.len()
                + record.resource_attributes_json.len()
                + record.scope_name.len()
                + record.scope_version.len()
                + record.scope_attributes_json.len();
            if !records.is_empty() && raw_bytes.saturating_add(record_bytes) > max_raw_bytes {
                break;
            }
            raw_bytes = raw_bytes.saturating_add(record_bytes);
            records.push(record);
        }
        Ok(records)
    }

    pub fn mark_exception_upload_success(
        &self,
        ids: &[i64],
        uploaded_at: i64,
    ) -> Result<(), String> {
        if ids.is_empty() {
            return Ok(());
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| "Telemetry database lock poisoned".to_string())?;
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let mut trace_ids = Vec::<Vec<u8>>::new();
        for id in ids {
            let trace_id = transaction
                .query_row(
                    "SELECT trace_id FROM otel_logs WHERE id = ?1 AND event_name = 'exception'",
                    [id],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()
                .map_err(|error| error.to_string())?;
            if let Some(trace_id) = trace_id {
                transaction
                    .execute(
                        "UPDATE otel_logs
                         SET upload_state = 'uploaded', uploaded_time_unix_nano = ?1,
                             next_attempt_time_unix_nano = NULL, last_upload_error = ''
                         WHERE id = ?2 AND event_name = 'exception'",
                        params![uploaded_at, id],
                    )
                    .map_err(|error| error.to_string())?;
                if !trace_ids.contains(&trace_id) {
                    trace_ids.push(trace_id);
                }
            }
        }
        for trace_id in trace_ids {
            transaction
                .execute(
                    "UPDATE operation_index
                     SET upload_state = CASE WHEN EXISTS(
                       SELECT 1 FROM otel_logs
                       WHERE trace_id = ?1 AND event_name = 'exception'
                         AND upload_state != 'uploaded'
                     ) THEN 'pending' ELSE 'uploaded' END
                     WHERE trace_id = ?1",
                    [trace_id],
                )
                .map_err(|error| error.to_string())?;
        }
        transaction.commit().map_err(|error| error.to_string())
    }

    pub fn mark_exception_upload_failure(
        &self,
        ids: &[i64],
        failed_at: i64,
        error: &str,
    ) -> Result<(), String> {
        if ids.is_empty() {
            return Ok(());
        }
        let safe_error = sanitize_upload_error(error);
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| "Telemetry database lock poisoned".to_string())?;
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        for id in ids {
            let attempts = transaction
                .query_row(
                    "SELECT upload_attempts FROM otel_logs
                     WHERE id = ?1 AND event_name = 'exception'",
                    [id],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .map_err(|error| error.to_string())?;
            let Some(attempts) = attempts else {
                continue;
            };
            let next_attempt = attempts.saturating_add(1);
            let exponent = (next_attempt.saturating_sub(1) as u32).min(6);
            let delay_seconds = 5_i64.saturating_mul(1_i64 << exponent).min(300);
            let next_time = failed_at.saturating_add(delay_seconds.saturating_mul(1_000_000_000));
            transaction
                .execute(
                    "UPDATE otel_logs
                     SET upload_state = 'retry', upload_attempts = ?1,
                         next_attempt_time_unix_nano = ?2, last_upload_error = ?3
                     WHERE id = ?4 AND event_name = 'exception'",
                    params![next_attempt, next_time, safe_error, id],
                )
                .map_err(|error| error.to_string())?;
            transaction
                .execute(
                    "UPDATE operation_index SET upload_state = 'retry'
                     WHERE trace_id = (SELECT trace_id FROM otel_logs WHERE id = ?1)",
                    [id],
                )
                .map_err(|error| error.to_string())?;
        }
        transaction.commit().map_err(|error| error.to_string())
    }

    pub fn queue_operation_upload(&self, trace_id_hex: &str) -> Result<(), String> {
        let trace_id = hex_id(trace_id_hex, 16)?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| "Telemetry database lock poisoned".to_string())?;
        let state = connection
            .query_row(
                "SELECT state FROM operation_index WHERE trace_id = ?1",
                params![trace_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "Operation record not found".to_string())?;
        if state == "running" {
            return Err("Operation is still running".to_string());
        }
        connection
            .execute(
                "UPDATE operation_index SET upload_state = 'pending'
                 WHERE trace_id = ?1 AND upload_state != 'uploading'",
                params![trace_id],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn claim_operation_upload(
        &self,
        trace_id_hex: &str,
    ) -> Result<Option<OperationUploadRecord>, String> {
        let trace_id = hex_id(trace_id_hex, 16)?;
        self.claim_operation_upload_by_id(Some(&trace_id))
    }

    pub fn claim_next_operation_upload(&self) -> Result<Option<OperationUploadRecord>, String> {
        self.claim_operation_upload_by_id(None)
    }

    fn claim_operation_upload_by_id(
        &self,
        selected_trace_id: Option<&[u8]>,
    ) -> Result<Option<OperationUploadRecord>, String> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| "Telemetry database lock poisoned".to_string())?;
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let trace_id = if let Some(trace_id) = selected_trace_id {
            transaction
                .query_row(
                    "SELECT trace_id FROM operation_index
                     WHERE trace_id = ?1 AND upload_state IN ('pending', 'retry')
                       AND state != 'running'",
                    params![trace_id],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()
                .map_err(|error| error.to_string())?
        } else {
            transaction
                .query_row(
                    "SELECT trace_id FROM operation_index
                     WHERE upload_state IN ('pending', 'retry') AND state != 'running'
                     ORDER BY started_time_unix_nano, trace_id LIMIT 1",
                    [],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()
                .map_err(|error| error.to_string())?
        };
        let Some(trace_id) = trace_id else {
            return Ok(None);
        };
        let claimed = transaction
            .execute(
                "UPDATE operation_index SET upload_state = 'uploading'
                 WHERE trace_id = ?1 AND upload_state IN ('pending', 'retry')",
                params![trace_id],
            )
            .map_err(|error| error.to_string())?;
        if claimed != 1 {
            return Ok(None);
        }
        let record = read_operation_upload(&transaction, &trace_id)?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(Some(record))
    }

    pub fn mark_operation_upload_success(
        &self,
        trace_id: &[u8],
        uploaded_at: i64,
    ) -> Result<(), String> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| "Telemetry database lock poisoned".to_string())?;
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        transaction
            .execute(
                "UPDATE operation_index SET upload_state = 'uploaded' WHERE trace_id = ?1",
                params![trace_id],
            )
            .map_err(|error| error.to_string())?;
        transaction
            .execute(
                "UPDATE otel_logs
                 SET upload_state = 'uploaded', uploaded_time_unix_nano = ?1,
                     next_attempt_time_unix_nano = NULL, last_upload_error = ''
                 WHERE trace_id = ?2",
                params![uploaded_at, trace_id],
            )
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())
    }

    pub fn mark_operation_upload_failure(&self, trace_id: &[u8]) -> Result<(), String> {
        self.connection
            .lock()
            .map_err(|_| "Telemetry database lock poisoned".to_string())?
            .execute(
                "UPDATE operation_index SET upload_state = 'retry' WHERE trace_id = ?1",
                params![trace_id],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn finish_operation(&self, trace_id: &[u8], state: &str) -> Result<(), String> {
        self.connection
            .lock()
            .map_err(|_| "Telemetry database lock poisoned".to_string())?
            .execute(
                "UPDATE operation_index
                 SET state = ?1, ended_time_unix_nano = ?2
                 WHERE trace_id = ?3",
                params![state, unix_nanos(), trace_id],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn reconstruct_stream(
        &self,
        trace_id: &[u8],
        span_id: &[u8],
        stream: CommandStream,
    ) -> Result<Vec<u8>, String> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| "Telemetry database lock poisoned".to_string())?;
        let combined_attributes = connection
            .query_row(
                "SELECT attributes_json FROM otel_logs
                 WHERE trace_id = ?1 AND span_id = ?2 AND event_name = 'agentdock.command'
                 ORDER BY id DESC LIMIT 1",
                params![trace_id, span_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some(raw) = combined_attributes {
            let key = match stream {
                CommandStream::Stdout => "agentdock.command.stdout",
                CommandStream::Stderr => "agentdock.command.stderr",
            };
            let attributes = OtlpKeyValue::list_from_json(&raw)?;
            if let Some(attribute) = attributes
                .into_iter()
                .find(|attribute| attribute.key == key)
            {
                return match attribute.value {
                    OtlpAnyValue::String(value) => Ok(value.into_bytes()),
                    OtlpAnyValue::Bytes(value) => Ok(value),
                    _ => Err("Command output has an invalid OTLP attribute type".to_string()),
                };
            }
        }
        let mut statement = connection
            .prepare(
                "SELECT body_json FROM otel_logs
                 WHERE trace_id = ?1 AND span_id = ?2 AND event_name = ?3
                 ORDER BY id",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(params![trace_id, span_id, stream.event_name()], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|error| error.to_string())?;
        let mut output = Vec::new();
        for row in rows {
            let raw = row.map_err(|error| error.to_string())?;
            let value = serde_json::from_str::<Value>(&raw).map_err(|error| error.to_string())?;
            match OtlpAnyValue::from_json(&value)? {
                OtlpAnyValue::String(value) => output.extend_from_slice(value.as_bytes()),
                OtlpAnyValue::Bytes(value) => output.extend_from_slice(&value),
                _ => return Err("Command output has an invalid OTLP body type".to_string()),
            }
        }
        Ok(output)
    }

    pub fn delete_operation(&self, trace_id: &[u8]) -> Result<(), String> {
        self.connection
            .lock()
            .map_err(|_| "Telemetry database lock poisoned".to_string())?
            .execute(
                "DELETE FROM operation_index WHERE trace_id = ?1",
                params![trace_id],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn list_operations(&self, query: OperationQuery) -> Result<OperationPage, String> {
        let page = query.page.unwrap_or(0);
        let page_size = query.page_size.unwrap_or(25).clamp(1, 100);
        let offset = (page as i64) * (page_size as i64);
        let category = normalize_filter(query.category);
        let state = normalize_filter(query.state);
        let trigger = normalize_filter(query.trigger);
        let search = normalize_filter(query.search).map(|value| format!("%{value}%"));
        let connection = self
            .connection
            .lock()
            .map_err(|_| "Telemetry database lock poisoned".to_string())?;
        let total = connection
            .query_row(
                "SELECT COUNT(*) FROM operation_index
                 WHERE (?1 IS NULL OR category = ?1)
                   AND (?2 IS NULL OR state = ?2)
                   AND (?3 IS NULL OR trigger = ?3)
                   AND (?4 IS NULL OR name LIKE ?4 OR display_name LIKE ?4 OR target_id LIKE ?4)",
                params![category, state, trigger, search],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|error| error.to_string())? as u32;
        let mut statement = connection
            .prepare(
                "SELECT op.trace_id, op.name, op.display_name, op.category, op.target_type,
                        op.target_id, op.trigger, op.state, op.started_time_unix_nano,
                        op.ended_time_unix_nano,
                        (SELECT COUNT(*) FROM otel_spans s WHERE s.trace_id = op.trace_id),
                        (SELECT COUNT(*) FROM otel_logs l WHERE l.trace_id = op.trace_id)
                 FROM operation_index op
                 WHERE (?1 IS NULL OR op.category = ?1)
                   AND (?2 IS NULL OR op.state = ?2)
                   AND (?3 IS NULL OR op.trigger = ?3)
                   AND (?4 IS NULL OR op.name LIKE ?4 OR op.display_name LIKE ?4 OR op.target_id LIKE ?4)
                 ORDER BY op.started_time_unix_nano DESC, op.trace_id DESC
                 LIMIT ?5 OFFSET ?6",
            )
            .map_err(|error| error.to_string())?;
        let items = statement
            .query_map(
                params![category, state, trigger, search, page_size as i64, offset],
                read_operation_summary,
            )
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        Ok(OperationPage {
            items,
            total,
            page,
            page_size,
        })
    }

    pub fn operation_detail(&self, trace_id_hex: &str) -> Result<OperationDetail, String> {
        let trace_id = hex_id(trace_id_hex, 16)?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| "Telemetry database lock poisoned".to_string())?;
        let summary = connection
            .query_row(
                "SELECT op.trace_id, op.name, op.display_name, op.category, op.target_type,
                        op.target_id, op.trigger, op.state, op.started_time_unix_nano,
                        op.ended_time_unix_nano,
                        (SELECT COUNT(*) FROM otel_spans s WHERE s.trace_id = op.trace_id),
                        (SELECT COUNT(*) FROM otel_logs l WHERE l.trace_id = op.trace_id)
                 FROM operation_index op
                 WHERE op.trace_id = ?1",
                params![trace_id],
                read_operation_summary,
            )
            .optional()
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "Operation record not found".to_string())?;
        let mut statement = connection
            .prepare(
                "SELECT s.span_id, s.parent_span_id, s.name, s.start_time_unix_nano,
                        s.end_time_unix_nano, s.status_code, s.status_message, s.attributes_json,
                        COALESCE((SELECT SUM(LENGTH(l.body_json)) FROM otel_logs l
                          WHERE l.trace_id = s.trace_id AND l.span_id = s.span_id
                            AND l.event_name = 'agentdock.command.result.stdout'), 0),
                        COALESCE((SELECT SUM(LENGTH(l.body_json)) FROM otel_logs l
                          WHERE l.trace_id = s.trace_id AND l.span_id = s.span_id
                            AND l.event_name = 'agentdock.command.result.stderr'), 0)
                 FROM otel_spans s
                 WHERE s.trace_id = ?1
                 ORDER BY s.start_time_unix_nano, s.span_id",
            )
            .map_err(|error| error.to_string())?;
        let mut spans = statement
            .query_map(params![trace_id], |row| {
                let span_id: Vec<u8> = row.get(0)?;
                let parent_span_id: Option<Vec<u8>> = row.get(1)?;
                let attributes_json: String = row.get(7)?;
                Ok(SpanSummary {
                    span_id: id_hex(&span_id),
                    parent_span_id: parent_span_id.as_deref().map(id_hex),
                    name: row.get(2)?,
                    start_time_unix_nano: row.get(3)?,
                    end_time_unix_nano: row.get(4)?,
                    status_code: row.get(5)?,
                    status_message: row.get(6)?,
                    attributes: OtlpKeyValue::list_from_json(&attributes_json)
                        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?,
                    stdout_bytes: row.get::<_, i64>(8)? as u32,
                    stderr_bytes: row.get::<_, i64>(9)? as u32,
                    stdout_preview: None,
                    stderr_preview: None,
                })
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        drop(statement);
        drop(connection);
        for span in &mut spans {
            let span_id = hex_id(&span.span_id, 8)?;
            let stdout = self.reconstruct_stream(&trace_id, &span_id, CommandStream::Stdout)?;
            let stderr = self.reconstruct_stream(&trace_id, &span_id, CommandStream::Stderr)?;
            span.stdout_bytes = stdout.len().min(u32::MAX as usize) as u32;
            span.stderr_bytes = stderr.len().min(u32::MAX as usize) as u32;
            span.stdout_preview = command_preview(&stdout);
            span.stderr_preview = command_preview(&stderr);
        }
        Ok(OperationDetail { summary, spans })
    }

    #[cfg(test)]
    pub(crate) fn latest_operation(&self) -> Result<Option<OperationSummary>, String> {
        Ok(self
            .list_operations(OperationQuery {
                category: None,
                state: None,
                trigger: None,
                search: None,
                page: Some(0),
                page_size: Some(1),
            })?
            .items
            .into_iter()
            .next())
    }

    pub fn operation_output(&self, query: OutputQuery) -> Result<OutputPage, String> {
        let trace_id = hex_id(&query.trace_id, 16)?;
        let span_id = hex_id(&query.span_id, 8)?;
        let stream = parse_stream(&query.stream)?;
        let offset = query.offset.unwrap_or(0);
        let limit = query.limit.unwrap_or(64 * 1024).clamp(1, 256 * 1024);
        let output = self.reconstruct_stream(&trace_id, &span_id, stream)?;
        let total_bytes = output.len().min(u32::MAX as usize) as u32;
        let start = (offset as usize).min(output.len());
        let end = (start + limit as usize).min(output.len());
        let slice = &output[start..end];
        let (text, bytes_base64) = match std::str::from_utf8(slice) {
            Ok(value) => (Some(value.to_string()), None),
            Err(_) => (
                None,
                Some(base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    slice,
                )),
            ),
        };
        Ok(OutputPage {
            trace_id: query.trace_id,
            span_id: query.span_id,
            stream: stream.as_str().to_string(),
            offset,
            limit,
            total_bytes,
            text,
            bytes_base64,
        })
    }

    #[cfg(test)]
    fn operation_state(&self, trace_id: &[u8]) -> Result<String, String> {
        self.connection
            .lock()
            .map_err(|_| "Telemetry database lock poisoned".to_string())?
            .query_row(
                "SELECT state FROM operation_index WHERE trace_id = ?1",
                params![trace_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())
    }

    #[cfg(test)]
    fn schema_version(&self) -> Result<i64, String> {
        self.connection
            .lock()
            .map_err(|_| "Telemetry database lock poisoned".to_string())?
            .query_row("SELECT version FROM telemetry_schema LIMIT 1", [], |row| {
                row.get(0)
            })
            .map_err(|error| error.to_string())
    }

    #[cfg(test)]
    fn otel_log_column_names(&self) -> Result<Vec<String>, String> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| "Telemetry database lock poisoned".to_string())?;
        let mut statement = connection
            .prepare("PRAGMA table_info(otel_logs)")
            .map_err(|error| error.to_string())?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        Ok(columns)
    }

    #[cfg(test)]
    fn trace_record_counts(&self, trace_id: &[u8]) -> Result<(i64, i64, i64), String> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| "Telemetry database lock poisoned".to_string())?;
        let operations = connection
            .query_row(
                "SELECT COUNT(*) FROM operation_index WHERE trace_id = ?1",
                params![trace_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let spans = connection
            .query_row(
                "SELECT COUNT(*) FROM otel_spans WHERE trace_id = ?1",
                params![trace_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let logs = connection
            .query_row(
                "SELECT COUNT(*) FROM otel_logs WHERE trace_id = ?1",
                params![trace_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        Ok((operations, spans, logs))
    }

    #[cfg(test)]
    pub(crate) fn span_names(&self, trace_id: &[u8]) -> Result<Vec<String>, String> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| "Telemetry database lock poisoned".to_string())?;
        let mut statement = connection
            .prepare(
                "SELECT name FROM otel_spans WHERE trace_id = ?1 ORDER BY start_time_unix_nano",
            )
            .map_err(|error| error.to_string())?;
        let names = statement
            .query_map(params![trace_id], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        Ok(names)
    }

    #[cfg(test)]
    fn read_log_bodies(&self, trace_id: &[u8]) -> Result<Vec<OtlpAnyValue>, String> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| "Telemetry database lock poisoned".to_string())?;
        let mut statement = connection
            .prepare("SELECT body_json FROM otel_logs WHERE trace_id = ?1 ORDER BY id")
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(params![trace_id], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        rows.map(|row| {
            let raw = row.map_err(|error| error.to_string())?;
            let value = serde_json::from_str::<Value>(&raw).map_err(|error| error.to_string())?;
            OtlpAnyValue::from_json(&value)
        })
        .collect()
    }

    #[cfg(test)]
    fn read_log_attributes(&self, trace_id: &[u8]) -> Result<Vec<Vec<OtlpKeyValue>>, String> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| "Telemetry database lock poisoned".to_string())?;
        let mut statement = connection
            .prepare("SELECT attributes_json FROM otel_logs WHERE trace_id = ?1 ORDER BY id")
            .map_err(|error| error.to_string())?;
        let attributes = statement
            .query_map(params![trace_id], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?
            .map(|row| OtlpKeyValue::list_from_json(&row.map_err(|error| error.to_string())?))
            .collect();
        attributes
    }

    #[cfg(test)]
    fn read_exception_logs(&self, trace_id: &[u8]) -> Result<Vec<ExceptionLogRecord>, String> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| "Telemetry database lock poisoned".to_string())?;
        let mut statement = connection
            .prepare(
                "SELECT event_name, severity_number, severity_text, body_json, attributes_json
                 FROM otel_logs WHERE trace_id = ?1 AND event_name = 'exception' ORDER BY id",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(params![trace_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| {
            let (event_name, severity_number, severity_text, body_json, attributes_json) =
                row.map_err(|error| error.to_string())?;
            let body_value =
                serde_json::from_str::<Value>(&body_json).map_err(|error| error.to_string())?;
            Ok(ExceptionLogRecord {
                event_name,
                severity_number,
                severity_text,
                body: OtlpAnyValue::from_json(&body_value)?,
                attributes: OtlpKeyValue::list_from_json(&attributes_json)?,
            })
        })
        .collect()
    }
}

#[cfg(test)]
struct ExceptionLogRecord {
    event_name: String,
    severity_number: i64,
    severity_text: String,
    body: OtlpAnyValue,
    attributes: Vec<OtlpKeyValue>,
}

fn append_log_with_connection(
    connection: &Connection,
    trace_id: &[u8],
    span_id: &[u8],
    input: LogInput,
) -> Result<(), String> {
    let now = unix_nanos();
    let body_json =
        serde_json::to_string(&input.body.to_json()).map_err(|error| error.to_string())?;
    let attributes_json = OtlpKeyValue::list_to_json(&input.attributes)?;
    let record_id = id_hex(&generate_id(16));
    connection
        .execute(
            "INSERT INTO otel_logs(
               record_id, trace_id, span_id, resource_id, scope_id,
               time_unix_nano, observed_time_unix_nano, severity_number,
               severity_text, event_name, body_json, attributes_json
             ) VALUES(?1, ?2, ?3, 1, 1, ?4, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                record_id,
                trace_id,
                span_id,
                now,
                input.severity_number,
                input.severity_text,
                input.event_name,
                body_json,
                attributes_json
            ],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn record_exception_on_span_with_connection(
    connection: &mut Connection,
    span: &SpanContext,
    input: ExceptionInput,
) -> Result<(), String> {
    let log = input.into_log();
    let status_message = match &log.body {
        OtlpAnyValue::String(message) => message.clone(),
        _ => "Unknown exception".to_string(),
    };
    let now = unix_nanos();
    let transaction = connection
        .transaction()
        .map_err(|error| error.to_string())?;
    append_log_with_connection(&transaction, &span.trace_id, &span.span_id, log)?;
    let updated = transaction
        .execute(
            "UPDATE otel_spans
             SET end_time_unix_nano = ?1, status_code = 2, status_message = ?2
             WHERE trace_id = ?3 AND span_id = ?4",
            params![now, status_message, span.trace_id, span.span_id],
        )
        .map_err(|error| error.to_string())?;
    if updated != 1 {
        return Err("Exception span was not found".to_string());
    }
    transaction
        .execute(
            "UPDATE operation_index
             SET state = 'error', ended_time_unix_nano = ?1
             WHERE trace_id = ?2",
            params![now, span.trace_id],
        )
        .map_err(|error| error.to_string())?;
    transaction.commit().map_err(|error| error.to_string())
}

fn record_standalone_exception_with_connection(
    connection: &mut Connection,
    installation_id: &str,
    target_id: &str,
    input: ExceptionInput,
) -> Result<(), String> {
    let target_id = bounded_text(target_id.to_string(), 256, "runtime");
    let trace_id = generate_id(16);
    let span_id = generate_id(8);
    let now = unix_nanos();
    let resource_attributes = telemetry_resource_attributes(installation_id)?;
    let span_attributes = OtlpKeyValue::list_to_json(&[
        OtlpKeyValue::string("agentdock.operation.trigger", "automatic"),
        OtlpKeyValue::string("agentdock.target.type", "runtime"),
        OtlpKeyValue::string("agentdock.target.id", &target_id),
    ])?;
    let log = input.into_log();
    let status_message = match &log.body {
        OtlpAnyValue::String(message) => message.clone(),
        _ => "Unknown exception".to_string(),
    };
    let transaction = connection
        .transaction()
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "INSERT OR IGNORE INTO otel_resources(id, attributes_json) VALUES(1, ?1)",
            params![resource_attributes],
        )
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "INSERT OR IGNORE INTO otel_scopes(id, name, version, attributes_json)
             VALUES(1, 'com.agentdock.operations', ?1, '[]')",
            params![env!("CARGO_PKG_VERSION")],
        )
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "INSERT INTO operation_index(
               trace_id, root_span_id, name, display_name, category, target_type,
               target_id, trigger, state, started_time_unix_nano, ended_time_unix_nano
             ) VALUES(?1, ?2, 'agentdock.exception', 'Unhandled exception', 'exception',
                      'runtime', ?3, 'automatic', 'error', ?4, ?4)",
            params![trace_id, span_id, target_id, now],
        )
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "INSERT INTO otel_spans(
               trace_id, span_id, resource_id, scope_id, name, start_time_unix_nano,
               end_time_unix_nano, attributes_json, status_code, status_message
             ) VALUES(?1, ?2, 1, 1, 'agentdock.exception', ?3, ?3, ?4, 2, ?5)",
            params![trace_id, span_id, now, span_attributes, status_message],
        )
        .map_err(|error| error.to_string())?;
    append_log_with_connection(&transaction, &trace_id, &span_id, log)?;
    transaction.commit().map_err(|error| error.to_string())
}

fn unix_nanos() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(i64::MAX as u128) as i64
}

fn normalize_filter(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty() && value != "all")
}

fn read_operation_summary(row: &rusqlite::Row<'_>) -> rusqlite::Result<OperationSummary> {
    let trace_id: Vec<u8> = row.get(0)?;
    Ok(OperationSummary {
        trace_id: id_hex(&trace_id),
        name: row.get(1)?,
        display_name: row.get(2)?,
        category: row.get(3)?,
        target_type: row.get(4)?,
        target_id: row.get(5)?,
        trigger: row.get(6)?,
        state: row.get(7)?,
        started_time_unix_nano: row.get(8)?,
        ended_time_unix_nano: row.get(9)?,
        span_count: row.get::<_, i64>(10)? as u32,
        log_count: row.get::<_, i64>(11)? as u32,
    })
}

fn hex_id(value: &str, expected_len: usize) -> Result<Vec<u8>, String> {
    let trimmed = value.trim();
    if trimmed.len() != expected_len * 2 || !trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Invalid trace or span id".to_string());
    }
    (0..trimmed.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&trimmed[index..index + 2], 16).map_err(|error| error.to_string())
        })
        .collect()
}

fn parse_stream(value: &str) -> Result<CommandStream, String> {
    match value {
        "stdout" => Ok(CommandStream::Stdout),
        "stderr" => Ok(CommandStream::Stderr),
        _ => Err("Invalid command output stream".to_string()),
    }
}

fn command_preview(output: &[u8]) -> Option<String> {
    if output.is_empty() {
        return None;
    }
    let preview = if output.len() > 64 * 1024 {
        &output[..64 * 1024]
    } else {
        output
    };
    let mut text = String::from_utf8_lossy(preview).to_string();
    if output.len() > preview.len() {
        text.push_str("\n... output truncated in preview; open the full stream for all bytes ...");
    }
    Some(text)
}

fn command_output_value(output: &[u8]) -> OtlpAnyValue {
    match std::str::from_utf8(output) {
        Ok(value) => OtlpAnyValue::String(value.to_string()),
        Err(_) => OtlpAnyValue::Bytes(output.to_vec()),
    }
}

fn generate_id(length: usize) -> Vec<u8> {
    let counter = ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut digest = Sha256::new();
    digest.update(std::process::id().to_le_bytes());
    digest.update(unix_nanos().to_le_bytes());
    digest.update(counter.to_le_bytes());
    let bytes = digest.finalize();
    let mut id = bytes[..length].to_vec();
    if id.iter().all(|byte| *byte == 0) {
        id[length - 1] = 1;
    }
    id
}

fn telemetry_resource_attributes(installation_id: &str) -> Result<String, String> {
    OtlpKeyValue::list_to_json(&[
        OtlpKeyValue::string("service.name", "agentdock"),
        OtlpKeyValue::string("service.version", env!("CARGO_PKG_VERSION")),
        OtlpKeyValue::string("os.type", std::env::consts::OS),
        OtlpKeyValue::string("host.arch", std::env::consts::ARCH),
        OtlpKeyValue::string("agentdock.installation.id", installation_id),
    ])
}

fn bounded_text(value: String, max_bytes: usize, fallback: &str) -> String {
    let normalized = if value.trim().is_empty() {
        fallback.to_string()
    } else {
        value
    };
    truncate_utf8(normalized, max_bytes)
}

fn truncate_utf8(mut value: String, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    value
}

fn id_hex(id: &[u8]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_operation_upload(
    connection: &Connection,
    trace_id: &[u8],
) -> Result<OperationUploadRecord, String> {
    let (resource_attributes_json, scope_name, scope_version, scope_attributes_json) = connection
        .query_row(
            "SELECT r.attributes_json, sc.name, sc.version, sc.attributes_json
             FROM otel_spans s
             JOIN otel_resources r ON r.id = s.resource_id
             JOIN otel_scopes sc ON sc.id = s.scope_id
             WHERE s.trace_id = ?1 ORDER BY s.start_time_unix_nano LIMIT 1",
            params![trace_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .map_err(|error| error.to_string())?;
    let mut span_statement = connection
        .prepare(
            "SELECT span_id, parent_span_id, trace_state, flags, name, kind,
                    start_time_unix_nano, COALESCE(end_time_unix_nano, start_time_unix_nano),
                    attributes_json, dropped_attributes_count, status_code, status_message
             FROM otel_spans WHERE trace_id = ?1 ORDER BY start_time_unix_nano, span_id",
        )
        .map_err(|error| error.to_string())?;
    let span_rows = span_statement
        .query_map(params![trace_id], |row| {
            Ok(OperationUploadSpan {
                span_id: row.get(0)?,
                parent_span_id: row.get::<_, Option<Vec<u8>>>(1)?.unwrap_or_default(),
                trace_state: row.get(2)?,
                flags: row.get(3)?,
                name: row.get(4)?,
                kind: row.get(5)?,
                start_time_unix_nano: row.get(6)?,
                end_time_unix_nano: row.get(7)?,
                attributes_json: row.get(8)?,
                dropped_attributes_count: row.get(9)?,
                status_code: row.get(10)?,
                status_message: row.get(11)?,
                logs: Vec::new(),
            })
        })
        .map_err(|error| error.to_string())?;
    let mut spans = span_rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    drop(span_statement);

    for span in &mut spans {
        let mut log_statement = connection
            .prepare(
                "SELECT time_unix_nano, severity_number, severity_text, event_name,
                        body_json, attributes_json, dropped_attributes_count
                 FROM otel_logs WHERE trace_id = ?1 AND span_id = ?2 ORDER BY id",
            )
            .map_err(|error| error.to_string())?;
        span.logs = log_statement
            .query_map(params![trace_id, span.span_id], |row| {
                Ok(OperationUploadLog {
                    time_unix_nano: row.get(0)?,
                    severity_number: row.get(1)?,
                    severity_text: row.get(2)?,
                    event_name: row.get(3)?,
                    body_json: row.get(4)?,
                    attributes_json: row.get(5)?,
                    dropped_attributes_count: row.get(6)?,
                })
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
    }

    Ok(OperationUploadRecord {
        trace_id: trace_id.to_vec(),
        resource_attributes_json,
        scope_name,
        scope_version,
        scope_attributes_json,
        spans,
    })
}

fn sanitize_upload_error(error: &str) -> String {
    let mut parts = error.split_ascii_whitespace();
    if parts.next() == Some("HTTP") {
        if let Some(status) = parts
            .next()
            .filter(|value| value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_digit()))
        {
            return format!("HTTP {status}");
        }
    }
    "Telemetry upload failed".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    fn test_path(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "agentdock-telemetry-{}-{}-{}.sqlite3",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_file(&path);
        path
    }

    fn test_operation(store: &Arc<TelemetryStore>) -> OperationContext {
        store
            .begin_operation(OperationStart {
                name: "agentdock.test",
                display_name: "Test operation",
                category: "test",
                target_type: "test",
                target_id: "test",
                trigger: "manual",
            })
            .unwrap()
    }

    fn panic_input() -> ExceptionInput {
        ExceptionInput {
            source: "rust.panic".into(),
            exception_type: "rust.panic".into(),
            message: "boom".into(),
            stacktrace: "stack".into(),
            location: "lib.rs:42:7".into(),
        }
    }

    fn frontend_input() -> ExceptionInput {
        ExceptionInput {
            source: "frontend.error".into(),
            exception_type: "TypeError".into(),
            message: "render failed".into(),
            stacktrace: "stack".into(),
            location: "index.html:10:2".into(),
        }
    }

    fn latest_log_id(store: &TelemetryStore) -> i64 {
        store
            .connection
            .lock()
            .unwrap()
            .query_row("SELECT MAX(id) FROM otel_logs", [], |row| row.get(0))
            .unwrap()
    }

    fn log_upload_status(store: &TelemetryStore, id: i64) -> (String, i64, Option<i64>, String) {
        store
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT upload_state, upload_attempts, next_attempt_time_unix_nano,
                        last_upload_error FROM otel_logs WHERE id = ?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap()
    }

    #[test]
    fn migrates_version_one_database_to_per_log_upload_state() {
        let path = test_path("upload-schema-migration");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE telemetry_schema (version INTEGER NOT NULL);
                 INSERT INTO telemetry_schema(version) VALUES(1);
                 CREATE TABLE otel_logs (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   record_id TEXT NOT NULL UNIQUE,
                   trace_id BLOB NOT NULL,
                   span_id BLOB NOT NULL,
                   resource_id INTEGER NOT NULL,
                   scope_id INTEGER NOT NULL,
                   time_unix_nano INTEGER NOT NULL,
                   observed_time_unix_nano INTEGER NOT NULL,
                   flags INTEGER NOT NULL DEFAULT 1,
                   severity_number INTEGER NOT NULL,
                   severity_text TEXT NOT NULL,
                   event_name TEXT NOT NULL,
                   body_json TEXT NOT NULL,
                   attributes_json TEXT NOT NULL,
                   dropped_attributes_count INTEGER NOT NULL DEFAULT 0
                 );",
            )
            .unwrap();
        drop(connection);

        let store = TelemetryStore::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), 2);
        let columns = store.otel_log_column_names().unwrap();
        assert!(columns.contains(&"upload_state".to_string()));
        assert!(columns.contains(&"uploaded_time_unix_nano".to_string()));
    }

    #[test]
    fn installation_id_is_stable_per_telemetry_database() {
        let first_path = test_path("installation-id-first");
        let second_path = test_path("installation-id-second");

        let first_store = TelemetryStore::open(&first_path).unwrap();
        let first_id = first_store.installation_id().to_string();
        let operation = test_operation(&first_store);
        operation.finish_ok().unwrap();
        let resource_attributes: String = first_store
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT attributes_json FROM otel_resources WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let reopened_id = TelemetryStore::open(&first_path)
            .unwrap()
            .installation_id()
            .to_string();
        let second_id = TelemetryStore::open(&second_path)
            .unwrap()
            .installation_id()
            .to_string();

        assert_eq!(first_id, reopened_id);
        assert_ne!(first_id, second_id);
        assert!(first_id.starts_with("adk-"));
        assert_eq!(first_id.len(), 40);
        assert!(resource_attributes.contains(&first_id));
    }

    #[test]
    fn pending_upload_batch_contains_only_exception_logs() {
        let path = test_path("upload-selection");
        let store = TelemetryStore::open(&path).unwrap();
        let operation = test_operation(&store);
        operation
            .root_span()
            .append_log(LogInput::info(
                "agentdock.info",
                OtlpAnyValue::String("local only".into()),
                vec![],
            ))
            .unwrap();
        operation.finish_ok().unwrap();
        store
            .record_standalone_exception("frontend", frontend_input())
            .unwrap();

        let records = store
            .pending_exception_uploads(i64::MAX, 100, 9_000_000)
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].event_name, "exception");
        assert_eq!(records[0].severity_text, "ERROR");
    }

    #[test]
    fn successful_upload_acknowledges_exactly_the_sent_log_ids() {
        let path = test_path("upload-success");
        let store = TelemetryStore::open(&path).unwrap();
        store
            .record_standalone_exception("frontend", frontend_input())
            .unwrap();
        let first = latest_log_id(&store);
        store
            .record_standalone_exception("rust", panic_input())
            .unwrap();
        let second = latest_log_id(&store);

        store
            .mark_exception_upload_success(&[first], 2_000_000_000)
            .unwrap();

        assert_eq!(log_upload_status(&store, first).0, "uploaded");
        assert_eq!(log_upload_status(&store, second).0, "pending");
    }

    #[test]
    fn failed_upload_is_sanitized_and_scheduled_with_backoff() {
        let path = test_path("upload-failure");
        let store = TelemetryStore::open(&path).unwrap();
        store
            .record_standalone_exception("frontend", frontend_input())
            .unwrap();
        let id = latest_log_id(&store);

        store
            .mark_exception_upload_failure(
                &[id],
                1_000_000_000,
                "HTTP 503 Authorization: LOG exposed-secret",
            )
            .unwrap();

        let (state, attempts, next_attempt, error) = log_upload_status(&store, id);
        assert_eq!(state, "retry");
        assert_eq!(attempts, 1);
        assert_eq!(next_attempt, Some(6_000_000_000));
        assert_eq!(error, "HTTP 503");
    }

    #[test]
    fn queues_only_the_selected_operation_with_its_command_output() {
        let path = test_path("selected-operation-upload");
        let store = TelemetryStore::open(&path).unwrap();
        let ignored = test_operation(&store);
        ignored.finish_ok().unwrap();
        let selected = test_operation(&store);
        selected
            .root_span()
            .append_command_output(CommandStream::Stdout, b"selected output")
            .unwrap();
        selected.finish_ok().unwrap();
        let selected_trace_id = selected.trace_id().to_vec();

        store
            .queue_operation_upload(&id_hex(&selected_trace_id))
            .unwrap();
        let upload = store.claim_next_operation_upload().unwrap().unwrap();

        assert_eq!(upload.trace_id, selected_trace_id);
        assert_eq!(upload.spans.len(), 1);
        assert!(upload.spans[0]
            .logs
            .iter()
            .any(|log| log.body_json.contains("selected output")));
        assert!(store.claim_next_operation_upload().unwrap().is_none());

        drop(selected);
        drop(ignored);
        drop(store);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn records_exception_on_existing_trace_and_finishes_operation() {
        let path = test_path("exception-associated");
        let store = TelemetryStore::open(&path).unwrap();
        let operation = test_operation(&store);
        let trace_id = operation.trace_id().to_vec();

        store
            .record_exception_on_span(operation.root_span(), panic_input())
            .unwrap();

        assert_eq!(store.operation_state(&trace_id).unwrap(), "error");
        assert_eq!(store.read_exception_logs(&trace_id).unwrap().len(), 1);

        drop(operation);
        drop(store);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn records_standalone_exception_as_completed_error_operation() {
        let path = test_path("exception-standalone");
        let store = TelemetryStore::open(&path).unwrap();

        store
            .record_standalone_exception("frontend", frontend_input())
            .unwrap();

        let page = store
            .list_operations(OperationQuery {
                category: Some("exception".into()),
                state: None,
                trigger: None,
                search: None,
                page: None,
                page_size: None,
            })
            .unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].state, "error");
        assert_eq!(page.items[0].target_type, "runtime");
        assert_eq!(page.items[0].target_id, "frontend");
        assert_eq!((page.items[0].span_count, page.items[0].log_count), (1, 1));

        drop(store);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn panic_recording_is_non_blocking_when_telemetry_is_busy() {
        let path = test_path("exception-busy");
        let store = TelemetryStore::open(&path).unwrap();
        let operation = test_operation(&store);
        let guard = store.connection.lock().unwrap();

        assert!(!store.try_record_exception_on_span(operation.root_span(), panic_input()));
        assert!(!store.try_record_standalone_exception("rust", panic_input()));

        drop(guard);
        drop(operation);
        drop(store);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn non_blocking_standalone_exception_records_when_store_is_available() {
        let path = test_path("exception-try-standalone");
        let store = TelemetryStore::open(&path).unwrap();

        assert!(store.try_record_standalone_exception("rust", panic_input()));
        let page = store
            .list_operations(OperationQuery {
                category: Some("exception".into()),
                state: Some("error".into()),
                trigger: None,
                search: None,
                page: None,
                page_size: None,
            })
            .unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].target_id, "rust");

        drop(store);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn exception_log_uses_otel_error_fields() {
        let path = test_path("exception-fields");
        let store = TelemetryStore::open(&path).unwrap();
        let operation = test_operation(&store);

        store
            .record_exception_on_span(
                operation.root_span(),
                ExceptionInput {
                    source: "rust.panic".into(),
                    exception_type: "rust.panic".into(),
                    message: "boom".into(),
                    stacktrace: "stack".into(),
                    location: "lib.rs:42:7".into(),
                },
            )
            .unwrap();

        let log = store
            .read_exception_logs(operation.trace_id())
            .unwrap()
            .remove(0);
        assert_eq!(
            (
                log.event_name.as_str(),
                log.severity_number,
                log.severity_text.as_str()
            ),
            ("exception", 17, "ERROR")
        );
        assert_eq!(log.body, OtlpAnyValue::String("boom".into()));
        assert!(log
            .attributes
            .contains(&OtlpKeyValue::string("exception.type", "rust.panic")));
        assert!(log
            .attributes
            .contains(&OtlpKeyValue::string("exception.message", "boom")));
        assert!(log
            .attributes
            .contains(&OtlpKeyValue::string("exception.stacktrace", "stack")));
        assert!(log.attributes.contains(&OtlpKeyValue {
            key: "exception.escaped".into(),
            value: OtlpAnyValue::Bool(true),
        }));

        drop(operation);
        drop(store);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn exception_log_bounds_large_utf8_fields() {
        let path = test_path("exception-bounds");
        let store = TelemetryStore::open(&path).unwrap();
        let operation = test_operation(&store);

        store
            .record_exception_on_span(
                operation.root_span(),
                ExceptionInput {
                    source: "rust.panic".into(),
                    exception_type: "rust.panic".into(),
                    message: "界".repeat(10_000),
                    stacktrace: "栈".repeat(30_000),
                    location: String::new(),
                },
            )
            .unwrap();

        let log = store
            .read_exception_logs(operation.trace_id())
            .unwrap()
            .remove(0);
        let message = log
            .attributes
            .iter()
            .find(|item| item.key == "exception.message")
            .unwrap();
        let stack = log
            .attributes
            .iter()
            .find(|item| item.key == "exception.stacktrace")
            .unwrap();
        assert!(matches!(
            &message.value,
            OtlpAnyValue::String(value) if value.len() <= 16_384
        ));
        assert!(matches!(
            &stack.value,
            OtlpAnyValue::String(value) if value.len() <= 65_536
        ));

        drop(operation);
        drop(store);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn initializes_otlp_schema_and_round_trips_typed_values() {
        let path = test_path("schema-roundtrip");
        let store = TelemetryStore::open(&path).unwrap();
        let operation = store
            .begin_operation(OperationStart {
                name: "agentdock.clients.detect",
                display_name: "Detect clients",
                category: "client",
                target_type: "clients",
                target_id: "all",
                trigger: "manual",
            })
            .unwrap();

        assert_eq!(operation.trace_id().len(), 16);
        assert_eq!(operation.span_id().len(), 8);

        store
            .append_log(
                operation.root_span(),
                LogInput::info(
                    "agentdock.test",
                    OtlpAnyValue::Int(42),
                    vec![OtlpKeyValue::string("path", r"C:\Users\xman\project")],
                ),
            )
            .unwrap();

        assert_eq!(
            store.read_log_bodies(operation.trace_id()).unwrap(),
            vec![OtlpAnyValue::Int(42)]
        );
        assert_eq!(
            store.read_log_attributes(operation.trace_id()).unwrap()[0][0].value,
            OtlpAnyValue::String(r"C:\Users\xman\project".to_string())
        );

        drop(operation);
        drop(store);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn command_chunks_reconstruct_exact_bytes_and_finish_operation() {
        let path = test_path("raw-command-output");
        let store = TelemetryStore::open(&path).unwrap();
        let operation = store
            .begin_operation(OperationStart {
                name: "agentdock.skill.install",
                display_name: "Install Skill",
                category: "skill",
                target_type: "skill",
                target_id: "superpowers",
                trigger: "user",
            })
            .unwrap();
        let span = operation
            .begin_span(
                "agentdock.command",
                vec![OtlpKeyValue::string("process.command", "npx")],
            )
            .unwrap();
        let original = b"line one\ninvalid:\xff\xfe\n";

        span.append_command_output(CommandStream::Stdout, original)
            .unwrap();
        span.finish_ok().unwrap();
        operation.finish_ok().unwrap();

        assert_eq!(
            store
                .reconstruct_stream(span.trace_id(), span.span_id(), CommandStream::Stdout)
                .unwrap(),
            original
        );
        assert_eq!(
            store.operation_state(operation.trace_id()).unwrap(),
            "success"
        );

        drop(operation);
        drop(store);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn deleting_operation_removes_its_spans_and_logs_as_one_trace() {
        let path = test_path("whole-trace-delete");
        let store = TelemetryStore::open(&path).unwrap();
        let operation = store
            .begin_operation(OperationStart {
                name: "agentdock.clients.detect",
                display_name: "Detect clients",
                category: "client",
                target_type: "clients",
                target_id: "all",
                trigger: "startup",
            })
            .unwrap();
        let trace_id = operation.trace_id().to_vec();
        operation
            .root_span()
            .append_command_output(CommandStream::Stderr, b"failure")
            .unwrap();
        operation.finish_error("failed").unwrap();

        store.delete_operation(&trace_id).unwrap();

        assert_eq!(store.trace_record_counts(&trace_id).unwrap(), (0, 0, 0));
        drop(operation);
        drop(store);
        let _ = fs::remove_file(path);
    }
}
