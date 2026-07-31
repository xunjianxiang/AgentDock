#[cfg(test)]
use crate::telemetry::OperationUploadSpan;
use crate::telemetry::{ExceptionUploadRecord, OperationUploadRecord};
use futures::{future::BoxFuture, FutureExt};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashSet;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tonic_skywalking::{metadata::MetadataValue, transport::Endpoint, Request};

#[derive(Clone, PartialEq, prost::Message)]
struct KeyStringValuePair {
    #[prost(string, tag = "1")]
    key: String,
    #[prost(string, tag = "2")]
    value: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct Commands {
    #[prost(message, repeated, tag = "1")]
    commands: Vec<Command>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct Command {
    #[prost(string, tag = "1")]
    command: String,
    #[prost(message, repeated, tag = "2")]
    args: Vec<KeyStringValuePair>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct SegmentObject {
    #[prost(string, tag = "1")]
    trace_id: String,
    #[prost(string, tag = "2")]
    trace_segment_id: String,
    #[prost(message, repeated, tag = "3")]
    spans: Vec<SpanObject>,
    #[prost(string, tag = "4")]
    service: String,
    #[prost(string, tag = "5")]
    service_instance: String,
    #[prost(bool, tag = "6")]
    is_size_limited: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
struct SegmentReference {
    #[prost(enumeration = "RefType", tag = "1")]
    ref_type: i32,
    #[prost(string, tag = "2")]
    trace_id: String,
    #[prost(string, tag = "3")]
    parent_trace_segment_id: String,
    #[prost(int32, tag = "4")]
    parent_span_id: i32,
    #[prost(string, tag = "5")]
    parent_service: String,
    #[prost(string, tag = "6")]
    parent_service_instance: String,
    #[prost(string, tag = "7")]
    parent_endpoint: String,
    #[prost(string, tag = "8")]
    network_address_used_at_peer: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct SpanObject {
    #[prost(int32, tag = "1")]
    span_id: i32,
    #[prost(int32, tag = "2")]
    parent_span_id: i32,
    #[prost(int64, tag = "3")]
    start_time: i64,
    #[prost(int64, tag = "4")]
    end_time: i64,
    #[prost(message, repeated, tag = "5")]
    refs: Vec<SegmentReference>,
    #[prost(string, tag = "6")]
    operation_name: String,
    #[prost(string, tag = "7")]
    peer: String,
    #[prost(enumeration = "SpanType", tag = "8")]
    span_type: i32,
    #[prost(enumeration = "SpanLayer", tag = "9")]
    span_layer: i32,
    #[prost(int32, tag = "10")]
    component_id: i32,
    #[prost(bool, tag = "11")]
    is_error: bool,
    #[prost(message, repeated, tag = "12")]
    tags: Vec<KeyStringValuePair>,
    #[prost(message, repeated, tag = "13")]
    logs: Vec<Log>,
    #[prost(bool, tag = "14")]
    skip_analysis: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
struct Log {
    #[prost(int64, tag = "1")]
    time: i64,
    #[prost(message, repeated, tag = "2")]
    data: Vec<KeyStringValuePair>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
enum RefType {
    CrossProcess = 0,
    CrossThread = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
enum SpanType {
    Entry = 0,
    Exit = 1,
    Local = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
enum SpanLayer {
    Unknown = 0,
    Database = 1,
    RpcFramework = 2,
    Http = 3,
    Mq = 4,
    Cache = 5,
    Faas = 6,
}

const BATCH_SIZE: usize = 100;
const MAX_RAW_BATCH_BYTES: usize = 4_500_000;
const POLL_INTERVAL: Duration = Duration::from_secs(30);
static UPLOADER_STARTED: AtomicBool = AtomicBool::new(false);

#[derive(Clone)]
struct OtlpConfig {
    endpoint: String,
    token: String,
    service_name: String,
}

struct SkywalkingRequest {
    endpoint: String,
    token: String,
    segments: Vec<SegmentObject>,
}

#[derive(Debug, PartialEq)]
enum UploadCycleResult {
    NoRecords,
    Uploaded(usize),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationReportResult {
    pub uploaded: bool,
    pub queued: bool,
    pub message: String,
}

trait TelemetryTransport: Send + Sync {
    fn send<'a>(&'a self, request: SkywalkingRequest) -> BoxFuture<'a, Result<(), String>>;
}

struct SkywalkingGrpcTransport;

impl TelemetryTransport for SkywalkingGrpcTransport {
    fn send<'a>(&'a self, request: SkywalkingRequest) -> BoxFuture<'a, Result<(), String>> {
        async move {
            let endpoint = Endpoint::from_shared(request.endpoint)
                .map_err(|_| "Invalid packaged SkyWalking gRPC endpoint".to_string())?
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(10));
            let channel = endpoint
                .connect()
                .await
                .map_err(|_| "SkyWalking gRPC connection failed".to_string())?;
            let authentication = request
                .token
                .parse::<MetadataValue<_>>()
                .map_err(|_| "Invalid packaged SkyWalking token".to_string())?;
            let mut message = Request::new(tokio_stream::iter(request.segments));
            message
                .metadata_mut()
                .insert("authentication", authentication);
            message.set_timeout(Duration::from_secs(10));
            let mut client = tonic_skywalking::client::Grpc::new(channel);
            client
                .ready()
                .await
                .map_err(|_| "SkyWalking gRPC service was not ready".to_string())?;
            let codec = tonic_skywalking::codec::ProstCodec::default();
            let path = tonic_skywalking::codegen::http::uri::PathAndQuery::from_static(
                "/skywalking.v3.TraceSegmentReportService/collect",
            );
            let _: tonic_skywalking::Response<Commands> = client
                .client_streaming(message, path, codec)
                .await
                .map_err(sanitize_grpc_status)?;
            Ok(())
        }
        .boxed()
    }
}

fn packaged_config() -> Result<Option<OtlpConfig>, String> {
    let endpoint = option_env!("AGENTDOCK_OTLP_ENDPOINT")
        .unwrap_or_default()
        .trim();
    let token = option_env!("AGENTDOCK_OTLP_TOKEN")
        .unwrap_or_default()
        .trim();
    let service_name = option_env!("AGENTDOCK_OTLP_SERVICE_NAME")
        .unwrap_or_default()
        .trim();

    if endpoint.is_empty() && token.is_empty() && service_name.is_empty() {
        return Ok(None);
    }
    if endpoint.is_empty() || token.is_empty() || service_name.is_empty() {
        return Err("Packaged OTLP configuration is incomplete".to_string());
    }
    validate_skywalking_endpoint(endpoint)?;
    if service_name.len() > 255 {
        return Err("Packaged OTLP service name is too long".to_string());
    }
    Ok(Some(OtlpConfig {
        endpoint: endpoint.to_string(),
        token: token.to_string(),
        service_name: service_name.to_string(),
    }))
}

fn validate_skywalking_endpoint(raw: &str) -> Result<(), String> {
    let endpoint = reqwest::Url::parse(raw)
        .map_err(|_| "Invalid packaged SkyWalking gRPC endpoint".to_string())?;
    if endpoint.scheme() != "http"
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.port_or_known_default() != Some(8000)
        || endpoint.path() != "/"
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(
            "Invalid packaged SkyWalking gRPC endpoint; expected http://host:8000".to_string(),
        );
    }
    Endpoint::from_shared(raw.to_string())
        .map(|_| ())
        .map_err(|_| "Invalid packaged SkyWalking gRPC endpoint".to_string())
}

pub fn start_background_uploader(
    store: Arc<crate::telemetry::TelemetryStore>,
) -> Result<(), String> {
    let Some(config) = packaged_config()? else {
        return Ok(());
    };
    if UPLOADER_STARTED.swap(true, Ordering::AcqRel) {
        return Ok(());
    }
    tauri::async_runtime::spawn(async move {
        let transport = SkywalkingGrpcTransport;
        tokio::time::sleep(Duration::from_secs(1)).await;
        loop {
            if let Err(error) = upload_next_operation(store.as_ref(), &config, &transport).await {
                eprintln!("AgentDock: SkyWalking operation upload skipped: {error}");
            }
            if let Err(error) =
                upload_once_at(store.as_ref(), &config, &transport, unix_nanos()).await
            {
                eprintln!("AgentDock: SkyWalking telemetry upload skipped: {error}");
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    });
    Ok(())
}

pub async fn report_operation(
    store: Arc<crate::telemetry::TelemetryStore>,
    trace_id: &str,
) -> Result<OperationReportResult, String> {
    store.queue_operation_upload(trace_id)?;
    let Some(config) = packaged_config()? else {
        return Ok(OperationReportResult {
            uploaded: false,
            queued: true,
            message: "遥测上报配置尚未写入安装包，记录已保留".to_string(),
        });
    };
    let Some(record) = store.claim_operation_upload(trace_id)? else {
        return Err("Operation upload is already in progress".to_string());
    };
    match upload_operation_record(store.as_ref(), &config, &SkywalkingGrpcTransport, record).await {
        Ok(()) => Ok(OperationReportResult {
            uploaded: true,
            queued: false,
            message: "执行记录已上报".to_string(),
        }),
        Err(error) => Ok(OperationReportResult {
            uploaded: false,
            queued: true,
            message: format!("上报失败，已进入重试队列：{error}"),
        }),
    }
}

async fn upload_next_operation<T: TelemetryTransport + ?Sized>(
    store: &crate::telemetry::TelemetryStore,
    config: &OtlpConfig,
    transport: &T,
) -> Result<UploadCycleResult, String> {
    let Some(record) = store.claim_next_operation_upload()? else {
        return Ok(UploadCycleResult::NoRecords);
    };
    upload_operation_record(store, config, transport, record).await?;
    Ok(UploadCycleResult::Uploaded(1))
}

async fn upload_operation_record<T: TelemetryTransport + ?Sized>(
    store: &crate::telemetry::TelemetryStore,
    config: &OtlpConfig,
    transport: &T,
    record: OperationUploadRecord,
) -> Result<(), String> {
    let trace_id = record.trace_id.clone();
    let request = match build_operation_request(config, &record) {
        Ok(request) => request,
        Err(_) => {
            store.mark_operation_upload_failure(&trace_id)?;
            return Err("Invalid local operation telemetry".to_string());
        }
    };
    match transport.send(request).await {
        Ok(()) => store.mark_operation_upload_success(&trace_id, unix_nanos()),
        Err(error) => {
            let safe_error = sanitize_transport_error(&error);
            store.mark_operation_upload_failure(&trace_id)?;
            Err(safe_error)
        }
    }
}

async fn upload_once_at<T: TelemetryTransport + ?Sized>(
    store: &crate::telemetry::TelemetryStore,
    config: &OtlpConfig,
    transport: &T,
    now_unix_nano: i64,
) -> Result<UploadCycleResult, String> {
    let records =
        store.pending_exception_uploads(now_unix_nano, BATCH_SIZE, MAX_RAW_BATCH_BYTES)?;
    if records.is_empty() {
        return Ok(UploadCycleResult::NoRecords);
    }
    let ids = records
        .iter()
        .map(|record| record.log_id)
        .collect::<Vec<_>>();
    let request = match build_exception_request(config, &records) {
        Ok(request) => request,
        Err(_) => {
            let error = "Invalid local exception telemetry";
            store.mark_exception_upload_failure(&ids, now_unix_nano, error)?;
            return Err(error.to_string());
        }
    };
    match transport.send(request).await {
        Ok(()) => {
            store.mark_exception_upload_success(&ids, now_unix_nano)?;
            Ok(UploadCycleResult::Uploaded(ids.len()))
        }
        Err(error) => {
            let safe_error = sanitize_transport_error(&error);
            store.mark_exception_upload_failure(&ids, now_unix_nano, &safe_error)?;
            Err(safe_error)
        }
    }
}

fn build_operation_request(
    config: &OtlpConfig,
    record: &OperationUploadRecord,
) -> Result<SkywalkingRequest, String> {
    if record.trace_id.len() != 16 || record.trace_id.iter().all(|byte| *byte == 0) {
        return Err("Invalid local OTLP trace context".to_string());
    }
    if record.spans.is_empty() {
        return Err("Invalid local OTLP operation without spans".to_string());
    }
    let resource_tags = parse_attributes(&record.resource_attributes_json)?;
    let span = flattened_operation_span(record, &resource_tags)?;
    Ok(SkywalkingRequest {
        endpoint: config.endpoint.clone(),
        token: config.token.clone(),
        segments: vec![SegmentObject {
            trace_id: hex_id(&record.trace_id),
            trace_segment_id: hex_id(&record.trace_id),
            spans: vec![span],
            service: config.service_name.clone(),
            service_instance: service_instance_name(&resource_tags),
            is_size_limited: false,
        }],
    })
}

fn flattened_operation_span(
    record: &OperationUploadRecord,
    resource_tags: &[KeyStringValuePair],
) -> Result<SpanObject, String> {
    for span in &record.spans {
        if span.span_id.len() != 8 || span.span_id.iter().all(|byte| *byte == 0) {
            return Err("Invalid local OTLP span context".to_string());
        }
    }
    let span_ids = record
        .spans
        .iter()
        .map(|span| span.span_id.clone())
        .collect::<HashSet<_>>();
    let roots = record
        .spans
        .iter()
        .filter(|span| !span_ids.contains(&span.parent_span_id))
        .collect::<Vec<_>>();
    if roots.len() != 1 {
        return Err("Invalid local OTLP operation root span".to_string());
    }
    let root = roots[0];
    let mut tags = parse_attributes(&root.attributes_json)?;
    tags.extend(resource_tags.iter().cloned());
    tags.push(string_pair(
        "agentdock.command.count",
        &record
            .spans
            .iter()
            .filter(|span| span.name == "agentdock.command")
            .count()
            .to_string(),
    ));
    tags.push(string_pair(
        "agentdock.child_span.count",
        &(record.spans.len() - 1).to_string(),
    ));

    let mut logs = Vec::new();
    for span in &record.spans {
        let mut source_data = parse_attributes(&span.attributes_json)?;
        let duration_ms = span
            .end_time_unix_nano
            .saturating_sub(span.start_time_unix_nano)
            .max(0)
            / 1_000_000;
        source_data.push(string_pair("agentdock.source.span.name", &span.name));
        source_data.push(string_pair(
            "agentdock.source.span.id",
            &hex_id(&span.span_id),
        ));
        source_data.push(string_pair(
            "agentdock.source.span.duration_ms",
            &duration_ms.to_string(),
        ));
        source_data.push(string_pair(
            "agentdock.source.span.status_code",
            &span.status_code.to_string(),
        ));
        if span.name == "agentdock.command" {
            if let Some(parent) = record
                .spans
                .iter()
                .find(|candidate| candidate.span_id == span.parent_span_id)
            {
                let parent_attributes = parse_attributes(&parent.attributes_json)?;
                if let Some(client_id) = parent_attributes
                    .iter()
                    .find(|attribute| attribute.key == "agentdock.target.id")
                    .map(|attribute| attribute.value.as_str())
                {
                    source_data.push(string_pair("agentdock.command.client_id", client_id));
                }
            }
        }
        if !span.status_message.is_empty() {
            source_data.push(string_pair(
                "agentdock.source.span.status_message",
                &span.status_message,
            ));
        }
        for log in &span.logs {
            let mut log = skywalking_log(
                log.time_unix_nano,
                &log.event_name,
                &log.severity_text,
                &log.body_json,
                &log.attributes_json,
            )?;
            log.data.extend(source_data.iter().cloned());
            logs.push(log);
        }
        if span.status_code == 2 {
            let mut data = vec![
                string_pair("event", "agentdock.span.error"),
                string_pair("severity", "ERROR"),
                string_pair(
                    "message",
                    if span.status_message.is_empty() {
                        &span.name
                    } else {
                        &span.status_message
                    },
                ),
            ];
            data.extend(source_data);
            logs.push(Log {
                time: nanos_to_millis(span.end_time_unix_nano),
                data,
            });
        }
    }
    logs.sort_by_key(|log| log.time);

    Ok(SpanObject {
        span_id: 0,
        parent_span_id: -1,
        start_time: nanos_to_millis(
            record
                .spans
                .iter()
                .map(|span| span.start_time_unix_nano)
                .min()
                .unwrap_or(root.start_time_unix_nano),
        ),
        end_time: nanos_to_millis(
            record
                .spans
                .iter()
                .map(|span| span.end_time_unix_nano)
                .max()
                .unwrap_or(root.end_time_unix_nano),
        ),
        refs: Vec::new(),
        operation_name: root.name.clone(),
        peer: String::new(),
        span_type: SpanType::Entry as i32,
        span_layer: 0,
        component_id: 0,
        is_error: record.spans.iter().any(|span| span.status_code == 2),
        tags,
        logs,
        skip_analysis: false,
    })
}

fn build_exception_request(
    config: &OtlpConfig,
    records: &[ExceptionUploadRecord],
) -> Result<SkywalkingRequest, String> {
    let segments = records
        .iter()
        .map(|record| exception_segment(config, record))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SkywalkingRequest {
        endpoint: config.endpoint.clone(),
        token: config.token.clone(),
        segments,
    })
}

fn exception_segment(
    config: &OtlpConfig,
    record: &ExceptionUploadRecord,
) -> Result<SegmentObject, String> {
    if record.trace_id.len() != 16
        || record.trace_id.iter().all(|byte| *byte == 0)
        || record.span_id.len() != 8
        || record.span_id.iter().all(|byte| *byte == 0)
    {
        return Err("Invalid local OTLP trace context".to_string());
    }
    let resource_tags = parse_attributes(&record.resource_attributes_json)?;
    let mut tags = vec![
        string_pair("agentdock.exception.record_id", &record.record_id),
        string_pair("agentdock.local.span_id", &hex_id(&record.span_id)),
    ];
    tags.extend(resource_tags.iter().cloned());
    let log = skywalking_log(
        record.time_unix_nano,
        &record.event_name,
        &record.severity_text,
        &record.body_json,
        &record.attributes_json,
    )?;
    let trace_id = hex_id(&record.trace_id);
    Ok(SegmentObject {
        trace_id: trace_id.clone(),
        trace_segment_id: format!("{trace_id}-{}", record.log_id),
        spans: vec![SpanObject {
            span_id: 0,
            parent_span_id: -1,
            start_time: nanos_to_millis(record.time_unix_nano),
            end_time: nanos_to_millis(record.time_unix_nano),
            refs: Vec::new(),
            operation_name: "AgentDock exception".to_string(),
            peer: String::new(),
            span_type: 0,
            span_layer: 0,
            component_id: 0,
            is_error: true,
            tags,
            logs: vec![log],
            skip_analysis: false,
        }],
        service: config.service_name.clone(),
        service_instance: service_instance_name(&resource_tags),
        is_size_limited: false,
    })
}

fn skywalking_log(
    time_unix_nano: i64,
    event_name: &str,
    severity_text: &str,
    body_json: &str,
    attributes_json: &str,
) -> Result<Log, String> {
    let body = serde_json::from_str::<Value>(body_json)
        .map_err(|_| "Invalid local OTLP log body".to_string())?;
    let mut data = vec![
        string_pair("event", event_name),
        string_pair("severity", severity_text),
        string_pair("message", &otlp_value_text(&body)?),
    ];
    let mut attributes = parse_attributes(attributes_json)?;
    if event_name == "agentdock.command" {
        let mut output_truncated = false;
        for attribute in &mut attributes {
            if matches!(
                attribute.key.as_str(),
                "agentdock.command.stdout" | "agentdock.command.stderr"
            ) {
                output_truncated |= truncate_utf8(&mut attribute.value, 32 * 1024);
            }
        }
        if output_truncated {
            attributes.push(string_pair("agentdock.command.output_truncated", "true"));
        }
    }
    data.extend(attributes);
    Ok(Log {
        time: nanos_to_millis(time_unix_nano),
        data,
    })
}

fn truncate_utf8(value: &mut String, max_bytes: usize) -> bool {
    if value.len() <= max_bytes {
        return false;
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    true
}

fn parse_attributes(raw: &str) -> Result<Vec<KeyStringValuePair>, String> {
    let values = serde_json::from_str::<Vec<Value>>(raw)
        .map_err(|_| "Invalid local OTLP attributes".to_string())?;
    values.iter().map(key_value_from_json).collect()
}

fn key_value_from_json(value: &Value) -> Result<KeyStringValuePair, String> {
    let key = value
        .get("key")
        .and_then(Value::as_str)
        .filter(|key| !key.is_empty())
        .ok_or_else(|| "Invalid local OTLP attribute key".to_string())?;
    let value = value
        .get("value")
        .ok_or_else(|| "Invalid local OTLP attribute value".to_string())?;
    Ok(string_pair(key, &otlp_value_text(value)?))
}

fn otlp_value_text(value: &Value) -> Result<String, String> {
    if let Some(value) = value.get("stringValue").and_then(Value::as_str) {
        Ok(value.to_string())
    } else if let Some(value) = value.get("boolValue").and_then(Value::as_bool) {
        Ok(value.to_string())
    } else if let Some(value) = value.get("intValue") {
        value
            .as_i64()
            .map(|value| value.to_string())
            .or_else(|| value.as_str().map(str::to_string))
            .ok_or_else(|| "Invalid local OTLP integer".to_string())
    } else if let Some(value) = value.get("doubleValue").and_then(Value::as_f64) {
        Ok(value.to_string())
    } else if let Some(value) = value.get("bytesValue").and_then(Value::as_str) {
        Ok(value.to_string())
    } else if let Some(values) = value
        .get("arrayValue")
        .and_then(|value| value.get("values"))
        .and_then(Value::as_array)
    {
        values
            .iter()
            .map(otlp_value_text)
            .collect::<Result<Vec<_>, _>>()
            .map(|values| values.join(", "))
    } else if let Some(values) = value
        .get("kvlistValue")
        .and_then(|value| value.get("values"))
        .and_then(Value::as_array)
    {
        values
            .iter()
            .map(key_value_from_json)
            .collect::<Result<Vec<_>, _>>()
            .map(|values| {
                values
                    .into_iter()
                    .map(|entry| format!("{}={}", entry.key, entry.value))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
    } else {
        Err("Invalid local OTLP value".to_string())
    }
}

fn string_pair(key: &str, value: &str) -> KeyStringValuePair {
    KeyStringValuePair {
        key: key.to_string(),
        value: value.to_string(),
    }
}

fn nanos_to_millis(value: i64) -> i64 {
    value.max(0) / 1_000_000
}

fn service_instance_name(resource_tags: &[KeyStringValuePair]) -> String {
    let base = format!(
        "agentdock-{}-{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    resource_tags
        .iter()
        .find(|tag| tag.key == "agentdock.installation.id" && !tag.value.is_empty())
        .map(|tag| format!("{base}-{}", tag.value))
        .unwrap_or(base)
}

fn hex_id(id: &[u8]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sanitize_grpc_status(status: tonic_skywalking::Status) -> String {
    format!("gRPC {:?}", status.code())
}

fn sanitize_transport_error(error: &str) -> String {
    const SAFE_TRANSPORT_ERRORS: [&str; 3] = [
        "SkyWalking gRPC connection failed",
        "SkyWalking gRPC service was not ready",
        "Invalid packaged SkyWalking token",
    ];
    if SAFE_TRANSPORT_ERRORS.contains(&error) {
        return error.to_string();
    }
    let mut parts = error.split_ascii_whitespace();
    match (parts.next(), parts.next()) {
        (Some("gRPC"), Some(code))
            if !code.is_empty() && code.bytes().all(|byte| byte.is_ascii_alphabetic()) =>
        {
            format!("gRPC {code}")
        }
        _ => "SkyWalking gRPC upload failed".to_string(),
    }
}

fn unix_nanos() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(i64::MAX as u128) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> ExceptionUploadRecord {
        ExceptionUploadRecord {
            log_id: 7,
            record_id: "record-7".to_string(),
            trace_id: vec![1; 16],
            span_id: vec![2; 8],
            time_unix_nano: 123,
            severity_number: 17,
            severity_text: "ERROR".to_string(),
            event_name: "exception".to_string(),
            body_json: r#"{"stringValue":"boom"}"#.to_string(),
            attributes_json: r#"[{"key":"exception.message","value":{"stringValue":"boom"}}]"#
                .to_string(),
            resource_attributes_json: "[]".to_string(),
            scope_name: "agentdock".to_string(),
            scope_version: "1".to_string(),
            scope_attributes_json: "[]".to_string(),
        }
    }

    fn config() -> OtlpConfig {
        OtlpConfig {
            endpoint: "https://collector.example:8000".to_string(),
            token: "secret-token".to_string(),
            service_name: "AgentDock".to_string(),
        }
    }

    fn operation_record() -> OperationUploadRecord {
        let child_id = vec![3; 8];
        let root_id = vec![4; 8];
        let client_id = vec![6; 8];
        let command_attributes = serde_json::json!([
            {
                "key": "agentdock.command.stdout",
                "value": { "stringValue": "x".repeat(40 * 1024) }
            },
            {
                "key": "agentdock.command.stderr",
                "value": { "stringValue": "warning" }
            },
            {
                "key": "agentdock.command.success",
                "value": { "boolValue": true }
            }
        ])
        .to_string();
        OperationUploadRecord {
            trace_id: vec![5; 16],
            resource_attributes_json: r#"[
                {"key":"service.version","value":{"stringValue":"test"}},
                {"key":"agentdock.installation.id","value":{"stringValue":"adk-01234567-89ab-4def-8123-456789abcdef"}}
            ]"#
            .to_string(),
            scope_name: "agentdock".to_string(),
            scope_version: "1".to_string(),
            scope_attributes_json: "[]".to_string(),
            spans: vec![
                OperationUploadSpan {
                    span_id: child_id,
                    parent_span_id: client_id.clone(),
                    trace_state: String::new(),
                    flags: 1,
                    name: "agentdock.command".to_string(),
                    kind: 1,
                    start_time_unix_nano: 2_000_000,
                    end_time_unix_nano: 3_000_000,
                    attributes_json: r#"[
                        {"key":"process.command_args","value":{"arrayValue":{"values":[
                            {"stringValue":"claude"},{"stringValue":"--version"}
                        ]}}},
                        {"key":"process.cwd","value":{"stringValue":"C:\\work"}}
                    ]"#
                    .to_string(),
                    dropped_attributes_count: 0,
                    status_code: 0,
                    status_message: String::new(),
                    logs: vec![crate::telemetry::OperationUploadLog {
                        time_unix_nano: 2_500_000,
                        severity_number: 9,
                        severity_text: "INFO".to_string(),
                        event_name: "agentdock.command".to_string(),
                        body_json: r#"{"stringValue":"claude --version"}"#.to_string(),
                        attributes_json: command_attributes,
                        dropped_attributes_count: 0,
                    }],
                },
                OperationUploadSpan {
                    span_id: client_id,
                    parent_span_id: root_id.clone(),
                    trace_state: String::new(),
                    flags: 1,
                    name: "agentdock.client.detect".to_string(),
                    kind: 1,
                    start_time_unix_nano: 1_500_000,
                    end_time_unix_nano: 3_500_000,
                    attributes_json: r#"[{"key":"agentdock.target.id","value":{"stringValue":"claude-code"}}]"#.to_string(),
                    dropped_attributes_count: 0,
                    status_code: 1,
                    status_message: String::new(),
                    logs: Vec::new(),
                },
                OperationUploadSpan {
                    span_id: root_id,
                    parent_span_id: Vec::new(),
                    trace_state: String::new(),
                    flags: 1,
                    name: "root".to_string(),
                    kind: 1,
                    start_time_unix_nano: 1_000_000,
                    end_time_unix_nano: 4_000_000,
                    attributes_json: "[]".to_string(),
                    dropped_attributes_count: 0,
                    status_code: 0,
                    status_message: String::new(),
                    logs: Vec::new(),
                },
            ],
        }
    }

    #[test]
    fn accepts_aliyun_skywalking_h2c_endpoint() {
        assert!(validate_skywalking_endpoint("http://tracing.example.com:8000").is_ok());
        assert!(validate_skywalking_endpoint("https://tracing.example.com:8000").is_err());
        assert!(validate_skywalking_endpoint(
            "https://tracing.example.com/adapt_token/api/otlp/traces"
        )
        .is_err());
    }

    #[test]
    fn builds_skywalking_segment_with_error_and_exception_log() {
        let request = build_exception_request(&config(), &[record()]).unwrap();
        let segment = &request.segments[0];
        let span = &segment.spans[0];

        assert_eq!(segment.trace_id, "01010101010101010101010101010101");
        assert_eq!(segment.service, "AgentDock");
        assert_eq!(span.parent_span_id, -1);
        assert!(span.is_error);
        assert!(span.logs[0]
            .data
            .iter()
            .any(|entry| entry.key == "event" && entry.value == "exception"));
        assert_eq!(request.token, "secret-token");
        assert_eq!(request.endpoint, "https://collector.example:8000");
    }

    #[test]
    fn flattens_an_operation_and_its_command_logs_into_one_span() {
        let request = build_operation_request(&config(), &operation_record()).unwrap();
        let spans = &request.segments[0].spans;

        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].operation_name, "root");
        assert_eq!(spans[0].parent_span_id, -1);
        assert_eq!(spans[0].start_time, 1);
        assert_eq!(spans[0].end_time, 4);
        assert_eq!(
            request.segments[0].service_instance,
            format!(
                "agentdock-{}-{}-adk-01234567-89ab-4def-8123-456789abcdef",
                std::env::consts::OS,
                std::env::consts::ARCH
            )
        );
        assert!(spans[0]
            .tags
            .iter()
            .any(|entry| entry.key == "service.version" && entry.value == "test"));
        assert!(spans[0]
            .tags
            .iter()
            .any(|entry| entry.key == "agentdock.command.count" && entry.value == "1"));
        assert_eq!(spans[0].logs.len(), 1);
        let command = spans[0]
            .logs
            .iter()
            .find(|log| {
                log.data
                    .iter()
                    .any(|entry| entry.key == "event" && entry.value == "agentdock.command")
            })
            .expect("command should be attached to the operation span");
        assert!(command
            .data
            .iter()
            .any(|entry| entry.key == "message" && entry.value == "claude --version"));
        assert!(command.data.iter().any(|entry| {
            entry.key == "agentdock.source.span.name" && entry.value == "agentdock.command"
        }));
        assert!(command.data.iter().any(|entry| {
            entry.key == "process.command_args" && entry.value == "claude, --version"
        }));
        assert!(command.data.iter().any(|entry| {
            entry.key == "agentdock.command.client_id" && entry.value == "claude-code"
        }));
        assert!(command.data.iter().any(|entry| {
            entry.key == "agentdock.source.span.duration_ms" && entry.value == "1"
        }));
        let stdout = command
            .data
            .iter()
            .find(|entry| entry.key == "agentdock.command.stdout")
            .expect("stdout should be included in the command event");
        assert_eq!(stdout.value.len(), 32 * 1024);
        assert!(command
            .data
            .iter()
            .any(|entry| { entry.key == "agentdock.command.stderr" && entry.value == "warning" }));
        assert!(command.data.iter().any(|entry| {
            entry.key == "agentdock.command.output_truncated" && entry.value == "true"
        }));
    }

    #[test]
    fn rejects_invalid_trace_context() {
        let mut record = record();
        record.trace_id.clear();
        assert_eq!(
            exception_segment(&config(), &record).unwrap_err(),
            "Invalid local OTLP trace context"
        );
    }

    #[test]
    fn transport_errors_never_retain_tokens_or_response_details() {
        assert_eq!(
            sanitize_transport_error("gRPC Unauthenticated secret-token"),
            "gRPC Unauthenticated"
        );
        assert_eq!(
            sanitize_transport_error("SkyWalking gRPC connection failed"),
            "SkyWalking gRPC connection failed"
        );
        assert_eq!(
            sanitize_transport_error("SkyWalking gRPC service was not ready"),
            "SkyWalking gRPC service was not ready"
        );
        assert_eq!(
            sanitize_transport_error("Invalid packaged SkyWalking token"),
            "Invalid packaged SkyWalking token"
        );
        assert_eq!(
            sanitize_transport_error("network error secret-token"),
            "SkyWalking gRPC upload failed"
        );
    }

    #[tokio::test]
    #[ignore = "requires packaged Alibaba Cloud telemetry configuration and network access"]
    async fn live_skywalking_grpc_probe() {
        let config = packaged_config()
            .expect("packaged telemetry configuration should be valid")
            .expect("packaged telemetry configuration should be present");
        let mut diagnostic = record();
        diagnostic.record_id = "agentdock-live-grpc-probe".to_string();
        diagnostic.time_unix_nano = unix_nanos();
        let request = build_exception_request(&config, &[diagnostic]).unwrap();

        SkywalkingGrpcTransport
            .send(request)
            .await
            .expect("SkyWalking gRPC probe should upload");
    }
}
