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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandStream {
    Stdout,
    Stderr,
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
                   SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM telemetry_schema);
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
                   FOREIGN KEY(trace_id) REFERENCES operation_index(trace_id) ON DELETE CASCADE
                 );",
            )
            .map_err(|error| error.to_string())?;
        Ok(Arc::new(Self {
            path: path.to_path_buf(),
            connection: Mutex::new(connection),
        }))
    }

    pub fn begin_operation(
        self: &Arc<Self>,
        input: OperationStart<'_>,
    ) -> Result<OperationContext, String> {
        let trace_id = generate_id(16);
        let span_id = generate_id(8);
        let now = unix_nanos();
        let resource_attributes = OtlpKeyValue::list_to_json(&[
            OtlpKeyValue::string("service.name", "agentdock"),
            OtlpKeyValue::string("service.version", env!("CARGO_PKG_VERSION")),
            OtlpKeyValue::string("os.type", std::env::consts::OS),
            OtlpKeyValue::string("host.arch", std::env::consts::ARCH),
        ])?;
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
        let now = unix_nanos();
        let body_json =
            serde_json::to_string(&input.body.to_json()).map_err(|error| error.to_string())?;
        let attributes_json = OtlpKeyValue::list_to_json(&input.attributes)?;
        let record_id = id_hex(&generate_id(16));
        self.connection
            .lock()
            .map_err(|_| "Telemetry database lock poisoned".to_string())?
            .execute(
                "INSERT INTO otel_logs(
                   record_id, trace_id, span_id, resource_id, scope_id,
                   time_unix_nano, observed_time_unix_nano, severity_number,
                   severity_text, event_name, body_json, attributes_json
                 ) VALUES(?1, ?2, ?3, 1, 1, ?4, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    record_id,
                    span.trace_id,
                    span.span_id,
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

fn id_hex(id: &[u8]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
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
