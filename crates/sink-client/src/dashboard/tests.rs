use std::{
    collections::HashMap,
    error::Error,
    io,
    io::Write as _,
    num::NonZeroU16,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, UNIX_EPOCH},
};

use axum::{
    body::Body,
    http::{
        HeaderName, HeaderValue, Method, Request, StatusCode, Version,
        header::{
            CACHE_CONTROL, CONTENT_ENCODING, CONTENT_SECURITY_POLICY, CONTENT_TYPE, HOST, ORIGIN,
            REFERRER_POLICY,
        },
    },
    response::Response,
};
use flate2::{Compression, write::GzEncoder};
use http_body_util::{BodyExt, Full};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tower::ServiceExt;

use super::*;
use crate::curl::CurlService;
use crate::inspection::{CaptureDecision, InspectionLimits};
use crate::replay::{
    ReplayBodyError, ReplayRequestBody, ReplayResponseBody, ReplayService, ReplayTransport,
    ReplayTransportFuture,
};
use crate::target::LocalTarget;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[derive(Clone)]
struct InMemoryAssets {
    assets: HashMap<String, EmbeddedAsset>,
}

impl EmbeddedAssetSource for InMemoryAssets {
    fn get(&self, path: &str) -> Option<EmbeddedAsset> {
        self.assets.get(path).cloned()
    }
}

fn test_assets() -> TestResult<Arc<dyn EmbeddedAssetSource>> {
    let mut assets = HashMap::new();
    assets.insert(
        INDEX_PATH.to_owned(),
        EmbeddedAsset::new(
            "<!doctype html><html><body><div id=\"app\"></div></body></html>",
            "text/html; charset=utf-8",
        )?,
    );
    assets.insert(
        "/assets/app.js".to_owned(),
        EmbeddedAsset::new(
            "globalThis.dashboardLoaded = true;",
            "application/javascript",
        )?,
    );
    assets.insert(
        "/assets/app.css".to_owned(),
        EmbeddedAsset::new("body { color: canvastext; }", "text/css; charset=utf-8")?,
    );
    assets.insert(
        "/assets/chunks/runtime.js".to_owned(),
        EmbeddedAsset::new(
            "globalThis.nestedDashboardChunk = true;",
            "application/javascript; charset=utf-8",
        )?,
    );
    Ok(Arc::new(InMemoryAssets { assets }))
}

async fn ephemeral_service(store: InspectionStore) -> TestResult<DashboardService> {
    Ok(DashboardService::bind_ephemeral(store, test_assets()?).await?)
}

#[derive(Default)]
struct ApiReplayTransport {
    sends: AtomicUsize,
    saw_sink_control_header: AtomicBool,
}

impl ReplayTransport for ApiReplayTransport {
    fn send(&self, request: Request<ReplayRequestBody>) -> ReplayTransportFuture {
        self.sends.fetch_add(1, Ordering::SeqCst);
        self.saw_sink_control_header.store(
            request
                .headers()
                .keys()
                .any(crate::inspection::is_sink_control_header),
            Ordering::SeqCst,
        );
        Box::pin(async {
            let body: ReplayResponseBody = Full::new(Bytes::from_static(b"replayed-response"))
                .map_err(|never| -> ReplayBodyError { match never {} })
                .boxed_unsync();
            Ok(Response::builder()
                .status(StatusCode::CREATED)
                .header(CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(body)
                .unwrap_or_else(|_| {
                    Response::new(
                        Full::new(Bytes::new())
                            .map_err(|never| -> ReplayBodyError { match never {} })
                            .boxed_unsync(),
                    )
                }))
        })
    }
}

async fn ephemeral_service_with_replay(
    store: InspectionStore,
    transport: Arc<ApiReplayTransport>,
) -> TestResult<DashboardService> {
    let replay = ReplayService::new(store.clone(), transport);
    Ok(DashboardService::bind_ephemeral_with_replay(store, test_assets()?, replay).await?)
}

async fn ephemeral_service_with_curl(
    store: InspectionStore,
    target: &str,
    local_tls_insecure: bool,
) -> TestResult<DashboardService> {
    let curl = CurlService::new(
        store.clone(),
        target.parse::<LocalTarget>()?,
        local_tls_insecure,
    );
    Ok(DashboardService::bind_ephemeral_with_curl(store, test_assets()?, curl).await?)
}

fn dashboard_request(
    service: &DashboardService,
    method: Method,
    path: &str,
    token: Option<&str>,
    origin: Option<&str>,
    json_body: Option<Value>,
) -> TestResult<Request<Body>> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(HOST, dashboard_host(service.address()));
    if let Some(token) = token {
        builder = builder.header(INSPECTOR_TOKEN_HEADER, token);
    }
    if let Some(origin) = origin {
        builder = builder.header(ORIGIN, origin);
    }
    let body = match json_body {
        Some(value) => {
            builder = builder.header(CONTENT_TYPE, "application/json");
            Body::from(serde_json::to_vec(&value)?)
        }
        None => Body::empty(),
    };
    Ok(builder.body(body)?)
}

fn curl_request_with_raw_body(
    service: &DashboardService,
    path: &str,
    body: impl Into<Bytes>,
) -> TestResult<Request<Body>> {
    Ok(Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(HOST, dashboard_host(service.address()))
        .header(ORIGIN, service.url())
        .header(INSPECTOR_TOKEN_HEADER, service.inspector_token().expose())
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body.into()))?)
}

async fn send(service: &DashboardService, request: Request<Body>) -> TestResult<Response> {
    Ok(service.router.clone().oneshot(request).await?)
}

async fn response_bytes(response: Response) -> TestResult<Bytes> {
    Ok(response.into_body().collect().await?.to_bytes())
}

async fn response_json(response: Response) -> TestResult<Value> {
    Ok(serde_json::from_slice(&response_bytes(response).await?)?)
}

fn captured_id(decision: CaptureDecision) -> TestResult<TransactionId> {
    decision
        .captured_id()
        .ok_or_else(|| io::Error::other("capture was unexpectedly paused").into())
}

fn request_snapshot(
    store: &InspectionStore,
    path: &str,
    body_text: &str,
    sensitive_value: &'static str,
) -> TestResult<RequestSnapshot> {
    let mut body = store.body_preview(BodyContentKind::Json, BodyConstraints::ordinary());
    body.record_chunk(body_text.as_bytes())?;
    body.finish()?;
    RequestSnapshot::new(
        Method::POST,
        format!("https://public.example.test{path}").parse()?,
        Version::HTTP_11,
        HeaderSnapshots::from_entries([
            HeaderSnapshot::new(
                HeaderName::from_static("content-type"),
                HeaderValue::from_static("application/json"),
            ),
            HeaderSnapshot::new(
                HeaderName::from_static("authorization"),
                HeaderValue::from_static(sensitive_value),
            ),
            HeaderSnapshot::new(
                HeaderName::from_static("x-public"),
                HeaderValue::from_static("visible"),
            ),
            HeaderSnapshot::new(
                HeaderName::from_static("x-sink-inspector-token"),
                HeaderValue::from_static("reserved-control-value"),
            ),
        ]),
        body,
    )
    .map_err(Into::into)
}

fn capture_completed(
    store: &InspectionStore,
    path: &str,
    body_text: &str,
    sensitive_value: &'static str,
) -> TestResult<TransactionId> {
    let id = captured_id(store.capture_at(
        TransactionOrigin::Original,
        request_snapshot(store, path, body_text, sensitive_value)?,
        UNIX_EPOCH + Duration::from_secs(10),
    ))?;
    let response_body = store.body_preview(BodyContentKind::Text, BodyConstraints::ordinary());
    store.start_response(
        id,
        ResponseSnapshot::new(
            StatusCode::CREATED,
            Version::HTTP_11,
            HeaderSnapshots::from_entries([
                HeaderSnapshot::new(
                    HeaderName::from_static("set-cookie"),
                    HeaderValue::from_static("session=private; HttpOnly"),
                ),
                HeaderSnapshot::new(
                    HeaderName::from_static("content-type"),
                    HeaderValue::from_static("text/plain; charset=utf-8"),
                ),
            ]),
            response_body,
        ),
        Duration::from_millis(2),
    )?;
    store.record_response_body_chunk(id, b"accepted")?;
    store.finish_response_body(id)?;
    store.complete(id, Duration::from_millis(7))?;
    Ok(id)
}

fn capture_curl_source(store: &InspectionStore, path: &str) -> TestResult<TransactionId> {
    let mut body = store.body_preview(BodyContentKind::Json, BodyConstraints::ordinary());
    body.record_chunk(br#"{"secret":"curl-body-secret"}"#)?;
    body.finish()?;
    let request = RequestSnapshot::new(
        Method::POST,
        format!("https://public.example.test{path}").parse()?,
        Version::HTTP_11,
        HeaderSnapshots::from_entries([
            HeaderSnapshot::new(
                HeaderName::from_static("content-type"),
                HeaderValue::from_static("application/json"),
            ),
            HeaderSnapshot::new(
                HeaderName::from_static("cookie"),
                HeaderValue::from_static("session=curl-cookie-secret"),
            ),
            HeaderSnapshot::new(
                HeaderName::from_static("x-sink-control"),
                HeaderValue::from_static("never-export-sink-control"),
            ),
            HeaderSnapshot::new(
                HeaderName::from_static("authorization"),
                HeaderValue::from_static("Bearer curl-authorization-secret"),
            ),
            HeaderSnapshot::new(
                HeaderName::from_static("cookie"),
                HeaderValue::from_static("duplicate=curl-cookie-secret"),
            ),
            HeaderSnapshot::new(
                HeaderName::from_static("x-public"),
                HeaderValue::from_static("curl-public-value"),
            ),
        ]),
        body,
    )?;
    captured_id(store.capture(TransactionOrigin::Original, request))
}

#[tokio::test]
async fn automatic_mode_falls_back_and_explicit_mode_reports_conflict() -> TestResult {
    let occupied_default = match TcpListener::bind(loopback_address(DEFAULT_DASHBOARD_PORT)).await {
        Ok(listener) => Some(listener),
        Err(error) if error.kind() == io::ErrorKind::AddrInUse => None,
        Err(error) => return Err(error.into()),
    };
    let automatic = DashboardService::bind(
        InspectionStore::default(),
        test_assets()?,
        DashboardPort::Automatic,
    )
    .await?;
    assert!(automatic.address().port() > DEFAULT_DASHBOARD_PORT);
    drop(automatic);
    drop(occupied_default);

    let occupied = TcpListener::bind(loopback_address(0)).await?;
    let occupied_address = occupied.local_addr()?;
    let occupied_port = NonZeroU16::new(occupied_address.port())
        .ok_or_else(|| io::Error::other("ephemeral listener returned port zero"))?;
    let error = DashboardService::bind(
        InspectionStore::default(),
        test_assets()?,
        DashboardPort::Explicit(occupied_port),
    )
    .await
    .err()
    .ok_or_else(|| io::Error::other("explicit conflicting bind unexpectedly succeeded"))?;
    assert!(matches!(
        error,
        DashboardBindError::ExplicitAddressInUse { address, .. }
            if address == occupied_address
    ));
    let message = error.to_string();
    assert!(message.contains(&occupied_address.to_string()));
    assert!(message.contains("--dashboard-port"));
    Ok(())
}

#[tokio::test]
async fn ephemeral_test_path_still_reports_an_ipv4_loopback_url() -> TestResult {
    let first = ephemeral_service(InspectionStore::default()).await?;
    let second = ephemeral_service(InspectionStore::default()).await?;
    assert_eq!(first.address().ip(), Ipv4Addr::LOCALHOST);
    assert_ne!(first.address().port(), 0);
    assert_eq!(first.url(), format!("http://{}", first.address()));
    assert_eq!(dashboard_host(loopback_address(80)), "127.0.0.1");
    assert_eq!(dashboard_url(loopback_address(80)), "http://127.0.0.1");
    assert_eq!(first.inspector_token().expose().len(), 64);
    assert_ne!(
        first.inspector_token().expose(),
        second.inspector_token().expose()
    );
    assert_eq!(
        format!("{:?}", first.inspector_token()),
        "InspectorToken([REDACTED])"
    );
    Ok(())
}

#[tokio::test]
async fn graceful_shutdown_closes_a_live_event_stream_and_server_task() -> TestResult {
    let service = ephemeral_service(InspectionStore::default()).await?;
    let address = service.address();
    let shutdown = CancellationToken::new();
    let server_shutdown = shutdown.clone();
    let server = tokio::spawn(service.run_until_cancelled(server_shutdown));

    let mut client = TcpStream::connect(address).await?;
    client
        .write_all(
            format!(
                "GET /api/v1/events HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\r\n",
                dashboard_host(address)
            )
            .as_bytes(),
        )
        .await?;
    let mut response = vec![0_u8; 2048];
    let read = timeout(Duration::from_secs(2), client.read(&mut response)).await??;
    assert!(read > 0);
    assert!(String::from_utf8_lossy(&response[..read]).contains("200 OK"));

    shutdown.cancel();
    timeout(Duration::from_secs(2), server).await???;
    Ok(())
}

#[tokio::test]
async fn embedded_assets_have_mime_types_and_spa_fallback_without_api_fallback() -> TestResult {
    let service = ephemeral_service(InspectionStore::default()).await?;

    let script_request =
        dashboard_request(&service, Method::GET, "/assets/app.js", None, None, None)?;
    let script = send(&service, script_request).await?;
    assert_eq!(script.status(), StatusCode::OK);
    assert_eq!(
        script.headers().get(CONTENT_TYPE),
        Some(&HeaderValue::from_static("application/javascript"))
    );
    assert_eq!(
        response_bytes(script).await?,
        Bytes::from_static(b"globalThis.dashboardLoaded = true;")
    );

    let nested_request = dashboard_request(
        &service,
        Method::GET,
        "/assets/chunks/runtime.js",
        None,
        None,
        None,
    )?;
    let nested = send(&service, nested_request).await?;
    assert_eq!(nested.status(), StatusCode::OK);
    assert_eq!(
        nested.headers().get(CONTENT_TYPE),
        Some(&HeaderValue::from_static(
            "application/javascript; charset=utf-8"
        ))
    );

    let spa_request = dashboard_request(
        &service,
        Method::GET,
        "/transactions/selected",
        None,
        None,
        None,
    )?;
    let spa = send(&service, spa_request).await?;
    assert_eq!(spa.status(), StatusCode::OK);
    assert_eq!(
        spa.headers()
            .get(CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        spa.headers().get("x-content-type-options"),
        Some(&HeaderValue::from_static("nosniff"))
    );
    let content_security_policy = spa
        .headers()
        .get(CONTENT_SECURITY_POLICY)
        .and_then(|value| value.to_str().ok());
    assert_eq!(content_security_policy, Some(CONTENT_SECURITY_POLICY_VALUE));
    assert!(content_security_policy.is_some_and(|value| {
        value.contains("sha256-60LHlRjW/B3CtzIoE/Lf1/NEDvko9efWMFaGVhHu/cs=")
    }));
    assert!(!content_security_policy.is_some_and(|value| value.contains("unsafe-inline")));
    assert_eq!(
        spa.headers().get(REFERRER_POLICY),
        Some(&HeaderValue::from_static("same-origin"))
    );
    let spa_body = response_bytes(spa).await?;
    assert!(spa_body.starts_with(b"<!doctype html>"));

    let missing_asset_request = dashboard_request(
        &service,
        Method::GET,
        "/assets/missing-deadbeef.js",
        None,
        None,
        None,
    )?;
    let missing_asset = send(&service, missing_asset_request).await?;
    assert_eq!(missing_asset.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(missing_asset).await?["error"]["code"],
        "dashboard_asset_not_found"
    );

    let missing_extensionless_asset_request =
        dashboard_request(&service, Method::GET, "/assets/missing", None, None, None)?;
    let missing_extensionless_asset = send(&service, missing_extensionless_asset_request).await?;
    assert_eq!(missing_extensionless_asset.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(missing_extensionless_asset).await?["error"]["code"],
        "dashboard_asset_not_found"
    );

    let missing_api_request = dashboard_request(
        &service,
        Method::GET,
        "/api/v1/does-not-exist",
        None,
        None,
        None,
    )?;
    let missing_api = send(&service, missing_api_request).await?;
    assert_eq!(missing_api.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(missing_api).await?["error"]["code"],
        "api_route_not_found"
    );

    let unknown_api_request = dashboard_request(
        &service,
        Method::GET,
        "/api/v2/does-not-exist",
        None,
        None,
        None,
    )?;
    let unknown_api = send(&service, unknown_api_request).await?;
    assert_eq!(unknown_api.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        unknown_api.headers().get(CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );
    assert!(
        !unknown_api
            .headers()
            .contains_key("access-control-allow-origin")
    );
    Ok(())
}

#[tokio::test]
async fn host_origin_preflight_and_token_guards_reject_without_cors() -> TestResult {
    let service = ephemeral_service(InspectionStore::default()).await?;

    let missing_host = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/session")
        .body(Body::empty())?;
    let missing_host = send(&service, missing_host).await?;
    assert_eq!(missing_host.status(), StatusCode::BAD_REQUEST);
    assert!(
        !missing_host
            .headers()
            .contains_key("access-control-allow-origin")
    );

    let hostile_host = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/session")
        .header(HOST, "attacker.example")
        .body(Body::empty())?;
    assert_eq!(
        send(&service, hostile_host).await?.status(),
        StatusCode::MISDIRECTED_REQUEST
    );

    let mut duplicate_host =
        dashboard_request(&service, Method::GET, "/api/v1/session", None, None, None)?;
    duplicate_host.headers_mut().append(
        HOST,
        HeaderValue::from_str(&dashboard_host(service.address()))?,
    );
    assert_eq!(
        send(&service, duplicate_host).await?.status(),
        StatusCode::BAD_REQUEST
    );

    for origin in ["null", "https://attacker.example"] {
        let request = dashboard_request(
            &service,
            Method::GET,
            "/api/v1/session",
            None,
            Some(origin),
            None,
        )?;
        assert_eq!(
            send(&service, request).await?.status(),
            StatusCode::FORBIDDEN
        );
    }

    let mut duplicate_origin = dashboard_request(
        &service,
        Method::GET,
        "/api/v1/session",
        None,
        Some(service.url()),
        None,
    )?;
    duplicate_origin
        .headers_mut()
        .append(ORIGIN, HeaderValue::from_str(service.url())?);
    assert_eq!(
        send(&service, duplicate_origin).await?.status(),
        StatusCode::FORBIDDEN
    );

    let preflight = dashboard_request(
        &service,
        Method::OPTIONS,
        "/api/v1/capture/pause",
        None,
        Some("https://attacker.example"),
        None,
    )?;
    let preflight = send(&service, preflight).await?;
    assert_eq!(preflight.status(), StatusCode::FORBIDDEN);
    assert!(
        !preflight
            .headers()
            .contains_key("access-control-allow-origin")
    );
    assert!(
        !preflight
            .headers()
            .contains_key("access-control-allow-methods")
    );

    for token in [None, Some("invalid-token")] {
        let request = dashboard_request(
            &service,
            Method::POST,
            "/api/v1/capture/pause",
            token,
            None,
            None,
        )?;
        let response = send(&service, request).await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response
                .headers()
                .get(CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
        assert!(
            !response
                .headers()
                .contains_key("access-control-allow-origin")
        );
    }

    let mut duplicate_token = dashboard_request(
        &service,
        Method::POST,
        "/api/v1/capture/pause",
        Some(service.inspector_token().expose()),
        Some(service.url()),
        None,
    )?;
    duplicate_token.headers_mut().append(
        INSPECTOR_TOKEN_HEADER,
        HeaderValue::from_str(service.inspector_token().expose())?,
    );
    assert_eq!(
        send(&service, duplicate_token).await?.status(),
        StatusCode::FORBIDDEN
    );

    let session_request = dashboard_request(
        &service,
        Method::GET,
        "/api/v1/session",
        None,
        Some(service.url()),
        None,
    )?;
    let session = send(&service, session_request).await?;
    assert_eq!(session.status(), StatusCode::OK);
    assert_eq!(
        session
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        session.headers().get("x-content-type-options"),
        Some(&HeaderValue::from_static("nosniff"))
    );
    assert!(
        !session
            .headers()
            .contains_key("access-control-allow-origin")
    );
    let session_json = response_json(session).await?;
    assert_eq!(
        session_json["inspectorToken"],
        service.inspector_token().expose()
    );

    let wrong_method_request = dashboard_request(
        &service,
        Method::POST,
        "/api/v1/session",
        Some(service.inspector_token().expose()),
        None,
        None,
    )?;
    let wrong_method = send(&service, wrong_method_request).await?;
    assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        response_json(wrong_method).await?["error"]["code"],
        "method_not_allowed"
    );
    Ok(())
}

#[test]
fn compressed_chunked_json_is_decoded_only_for_the_bounded_dashboard_preview() -> TestResult {
    let source = br#"{"coach":{"salary":4200},"currency":"EUR"}"#;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(source)?;
    let compressed = encoder.finish()?;

    let mut preview = BodyPreview::new(
        1024,
        BodyContentKind::Json,
        BodyConstraints::new(true, false, false),
    )?;
    preview.record_chunk(&compressed)?;
    preview.finish()?;
    let headers = HeaderSnapshots::from_entries([
        HeaderSnapshot::new(CONTENT_TYPE, HeaderValue::from_static("application/json")),
        HeaderSnapshot::new(CONTENT_ENCODING, HeaderValue::from_static("gzip")),
    ]);

    let dto = serde_json::to_value(BodyDto::from_preview(&preview, &headers))?;
    assert_eq!(dto["kind"], "json");
    assert_eq!(dto["text"], String::from_utf8(source.to_vec())?);
    assert_eq!(dto["transferredBytes"], compressed.len());
    assert_eq!(dto["retainedBytes"], source.len());
    assert_eq!(dto["truncated"], false);
    assert_eq!(dto["constraints"]["streaming"], true);
    assert!(dto.get("note").is_none());
    assert_eq!(preview.retained_bytes(), compressed);
    Ok(())
}

#[test]
fn decompressed_preview_remains_bounded_and_unknown_encodings_are_not_rendered() -> TestResult {
    let source = vec![b'a'; 512];
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&source)?;
    let compressed = encoder.finish()?;
    let mut preview = BodyPreview::new(64, BodyContentKind::Text, BodyConstraints::ordinary())?;
    preview.record_chunk(&compressed)?;
    preview.finish()?;
    let gzip_headers = HeaderSnapshots::from_entries([
        HeaderSnapshot::new(CONTENT_TYPE, HeaderValue::from_static("text/plain")),
        HeaderSnapshot::new(CONTENT_ENCODING, HeaderValue::from_static("gzip")),
    ]);
    let decoded = serde_json::to_value(BodyDto::from_preview(&preview, &gzip_headers))?;
    assert_eq!(decoded["text"].as_str().map(str::len), Some(64));
    assert_eq!(decoded["truncated"], true);
    assert_eq!(decoded["retention"], "truncated");

    let unknown_headers = HeaderSnapshots::from_entries([
        HeaderSnapshot::new(CONTENT_TYPE, HeaderValue::from_static("text/plain")),
        HeaderSnapshot::new(CONTENT_ENCODING, HeaderValue::from_static("compress")),
    ]);
    let unavailable = serde_json::to_value(BodyDto::from_preview(&preview, &unknown_headers))?;
    assert_eq!(unavailable["kind"], "binary");
    assert_eq!(unavailable["text"], Value::Null);
    assert_eq!(unavailable["retention"], "omitted_binary");
    Ok(())
}

#[tokio::test]
async fn detail_masks_sensitive_headers_and_reveal_returns_one_identified_value() -> TestResult {
    let store = InspectionStore::new(InspectionLimits::new(8, 1024)?);
    let id = capture_completed(
        &store,
        "/orders",
        "{\"order\":42}",
        "Bearer inspector-secret",
    )?;
    let service = ephemeral_service(store).await?;

    let detail_request = dashboard_request(
        &service,
        Method::GET,
        &format!("/api/v1/transactions/{id}"),
        None,
        None,
        None,
    )?;
    let detail = response_json(send(&service, detail_request).await?).await?;
    let serialized_detail = serde_json::to_string(&detail)?;
    assert!(!serialized_detail.contains("Bearer inspector-secret"));
    assert!(!serialized_detail.contains("session=private"));
    assert!(!serialized_detail.contains("reserved-control-value"));
    assert_eq!(detail["request"]["headers"][0]["id"], "request:0");
    assert_eq!(detail["request"]["headers"][1]["id"], "request:1");
    assert_eq!(detail["request"]["headers"][1]["sensitive"], true);
    assert_eq!(detail["request"]["headers"][1]["valueState"], "masked");
    assert!(detail["request"]["headers"][1].get("value").is_none());
    assert_eq!(detail["request"]["headers"][2]["value"], "visible");
    assert_eq!(detail["response"]["headers"][0]["id"], "response:0");

    let reveal_request = dashboard_request(
        &service,
        Method::POST,
        &format!("/api/v1/transactions/{id}/headers/request/1/reveal"),
        Some(service.inspector_token().expose()),
        None,
        None,
    )?;
    let reveal = response_json(send(&service, reveal_request).await?).await?;
    assert_eq!(reveal, json!({ "value": "Bearer inspector-secret" }));
    assert!(!serde_json::to_string(&reveal)?.contains("session=private"));
    Ok(())
}

#[tokio::test]
async fn reserved_dashboard_control_header_cannot_enter_transaction_api_or_reveal() -> TestResult {
    let store = InspectionStore::new(InspectionLimits::new(8, 1024)?);
    let service = ephemeral_service(store.clone()).await?;
    let mut body = store.body_preview(BodyContentKind::Unknown, BodyConstraints::ordinary());
    body.finish()?;
    let id = captured_id(store.capture(
        TransactionOrigin::Original,
        RequestSnapshot::new(
            Method::GET,
            "https://public.example.test/control-boundary".parse()?,
            Version::HTTP_11,
            HeaderSnapshots::from_entries([
                HeaderSnapshot::new(
                    HeaderName::from_static("x-sink-inspector-token"),
                    HeaderValue::from_str(service.inspector_token().expose())?,
                ),
                HeaderSnapshot::new(
                    HeaderName::from_static("x-public"),
                    HeaderValue::from_static("visible"),
                ),
            ]),
            body,
        )?,
    ))?;

    let retained = store
        .get(id)
        .ok_or_else(|| io::Error::other("transaction was not retained"))?;
    assert_eq!(retained.request().headers().len(), 1);
    assert_eq!(
        retained.request().headers().as_slice()[0].name(),
        "x-public"
    );

    let detail = dashboard_request(
        &service,
        Method::GET,
        &format!("/api/v1/transactions/{id}"),
        None,
        Some(service.url()),
        None,
    )?;
    let detail = response_bytes(send(&service, detail).await?).await?;
    assert!(
        !detail
            .windows(service.inspector_token().expose().len())
            .any(|window| window == service.inspector_token().expose().as_bytes())
    );

    let reveal = dashboard_request(
        &service,
        Method::POST,
        &format!("/api/v1/transactions/{id}/headers/request/1/reveal"),
        Some(service.inspector_token().expose()),
        Some(service.url()),
        None,
    )?;
    let reveal = send(&service, reveal).await?;
    assert_eq!(reveal.status(), StatusCode::NOT_FOUND);
    let reveal = response_bytes(reveal).await?;
    assert!(
        !reveal
            .windows(service.inspector_token().expose().len())
            .any(|window| window == service.inspector_token().expose().as_bytes())
    );
    Ok(())
}

#[tokio::test]
async fn pause_resume_delete_and_confirmed_clear_are_token_protected() -> TestResult {
    let store = InspectionStore::new(InspectionLimits::new(8, 1024)?);
    let first = capture_completed(&store, "/first", "one", "Bearer first")?;
    let _second = capture_completed(&store, "/second", "two", "Bearer second")?;
    let service = ephemeral_service(store.clone()).await?;
    let token = service.inspector_token().expose();

    let pause_request = dashboard_request(
        &service,
        Method::POST,
        "/api/v1/capture/pause",
        Some(token),
        None,
        None,
    )?;
    assert_eq!(
        response_json(send(&service, pause_request).await?).await?["paused"],
        true
    );
    assert!(store.is_paused());

    let resume_request = dashboard_request(
        &service,
        Method::POST,
        "/api/v1/capture/resume",
        Some(token),
        None,
        None,
    )?;
    assert_eq!(
        response_json(send(&service, resume_request).await?).await?["paused"],
        false
    );
    assert!(!store.is_paused());

    let delete_request = dashboard_request(
        &service,
        Method::DELETE,
        &format!("/api/v1/transactions/{first}"),
        Some(token),
        None,
        None,
    )?;
    assert_eq!(
        send(&service, delete_request).await?.status(),
        StatusCode::OK
    );
    assert!(store.get(first).is_none());

    let denied_clear_request = dashboard_request(
        &service,
        Method::DELETE,
        "/api/v1/transactions",
        Some(token),
        None,
        Some(json!({ "confirm": false })),
    )?;
    assert_eq!(
        send(&service, denied_clear_request).await?.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(store.len(), 1);

    let clear_request = dashboard_request(
        &service,
        Method::DELETE,
        "/api/v1/transactions",
        Some(token),
        None,
        Some(json!({ "confirm": true })),
    )?;
    assert_eq!(
        response_json(send(&service, clear_request).await?).await?["removed"],
        1
    );
    assert!(store.is_empty());
    Ok(())
}

#[tokio::test]
async fn replay_api_is_protected_and_returns_a_linked_terminal_capture_id() -> TestResult {
    let store = InspectionStore::new(InspectionLimits::new(8, 1024)?);
    let source_id = capture_completed(
        &store,
        "/replay?exact=true",
        "{\"secret\":\"request-body\"}",
        "Bearer replay-api-secret",
    )?;
    let transport = Arc::new(ApiReplayTransport::default());
    let service = ephemeral_service_with_replay(store.clone(), transport.clone()).await?;
    let path = format!("/api/v1/transactions/{source_id}/replay");

    for token in [None, Some("wrong-token")] {
        let request = dashboard_request(&service, Method::POST, &path, token, None, None)?;
        let response = send(&service, request).await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response_json(response).await?["error"]["code"],
            "invalid_inspector_token"
        );
    }

    let hostile_host = Request::builder()
        .method(Method::POST)
        .uri(&path)
        .header(HOST, "attacker.example")
        .header(INSPECTOR_TOKEN_HEADER, service.inspector_token().expose())
        .body(Body::empty())?;
    assert_eq!(
        send(&service, hostile_host).await?.status(),
        StatusCode::MISDIRECTED_REQUEST
    );

    let hostile_origin = dashboard_request(
        &service,
        Method::POST,
        &path,
        Some(service.inspector_token().expose()),
        Some("https://attacker.example"),
        None,
    )?;
    assert_eq!(
        send(&service, hostile_origin).await?.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(transport.sends.load(Ordering::SeqCst), 0);

    let request = dashboard_request(
        &service,
        Method::POST,
        &path,
        Some(service.inspector_token().expose()),
        Some(service.url()),
        None,
    )?;
    let response = send(&service, request).await?;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(
        response.headers().get(CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );
    assert!(
        !response
            .headers()
            .contains_key("access-control-allow-origin")
    );
    let body = response_json(response).await?;
    let serialized = serde_json::to_string(&body)?;
    assert!(!serialized.contains("replay-api-secret"));
    assert!(!serialized.contains("request-body"));
    let replay_id: TransactionId = body["transactionId"]
        .as_str()
        .ok_or_else(|| io::Error::other("replay response omitted transactionId"))?
        .parse()?;

    let replayed = timeout(Duration::from_secs(1), async {
        loop {
            if let Some(transaction) = store.get(replay_id)
                && transaction.lifecycle().is_terminal()
            {
                return transaction;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(replayed.origin(), TransactionOrigin::replay(source_id));
    assert_eq!(replayed.lifecycle(), &TransactionLifecycle::Completed);
    assert_eq!(
        replayed
            .response()
            .ok_or("replay response was not captured")?
            .body()
            .retained_bytes(),
        b"replayed-response"
    );
    assert_eq!(transport.sends.load(Ordering::SeqCst), 1);
    assert!(!transport.saw_sink_control_header.load(Ordering::SeqCst));
    Ok(())
}

#[tokio::test]
async fn replay_api_has_stable_invalid_missing_paused_and_ineligible_errors_without_sends()
-> TestResult {
    let store = InspectionStore::new(InspectionLimits::new(8, 3)?);
    let truncated_id = captured_id(store.capture(
        TransactionOrigin::Original,
        request_snapshot(&store, "/truncated", "1234", "Bearer error-secret")?,
    ))?;
    let transport = Arc::new(ApiReplayTransport::default());
    let service = ephemeral_service_with_replay(store.clone(), transport.clone()).await?;
    let token = service.inspector_token().expose();

    let invalid = dashboard_request(
        &service,
        Method::POST,
        "/api/v1/transactions/not-a-uuid/replay",
        Some(token),
        None,
        None,
    )?;
    let invalid = send(&service, invalid).await?;
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(invalid).await?,
        json!({
            "error": {
                "code": "invalid_transaction_id",
                "message": "transaction id must be a UUID"
            }
        })
    );

    let missing = dashboard_request(
        &service,
        Method::POST,
        &format!("/api/v1/transactions/{}/replay", TransactionId::new()),
        Some(token),
        None,
        None,
    )?;
    let missing = send(&service, missing).await?;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(missing).await?["error"]["code"],
        "transaction_not_found"
    );

    let ineligible = dashboard_request(
        &service,
        Method::POST,
        &format!("/api/v1/transactions/{truncated_id}/replay"),
        Some(token),
        None,
        None,
    )?;
    let ineligible = send(&service, ineligible).await?;
    assert_eq!(ineligible.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let ineligible_json = response_json(ineligible).await?;
    assert_eq!(ineligible_json["error"]["code"], "truncated_request_body");
    assert!(!serde_json::to_string(&ineligible_json)?.contains("error-secret"));

    let eligible_store = InspectionStore::new(InspectionLimits::new(8, 64)?);
    let eligible_id = captured_id(eligible_store.capture(
        TransactionOrigin::Original,
        request_snapshot(&eligible_store, "/paused", "ok", "Bearer paused-secret")?,
    ))?;
    let paused_transport = Arc::new(ApiReplayTransport::default());
    let paused_service =
        ephemeral_service_with_replay(eligible_store.clone(), paused_transport.clone()).await?;
    eligible_store.pause();
    let paused = dashboard_request(
        &paused_service,
        Method::POST,
        &format!("/api/v1/transactions/{eligible_id}/replay"),
        Some(paused_service.inspector_token().expose()),
        None,
        None,
    )?;
    let paused = send(&paused_service, paused).await?;
    assert_eq!(paused.status(), StatusCode::CONFLICT);
    assert_eq!(
        response_json(paused).await?["error"]["code"],
        "capture_paused"
    );
    assert_eq!(transport.sends.load(Ordering::SeqCst), 0);
    assert_eq!(paused_transport.sends.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn curl_api_uses_existing_host_origin_and_token_guards_without_cors() -> TestResult {
    let store = InspectionStore::new(InspectionLimits::new(8, 1024)?);
    let source_id = capture_curl_source(&store, "/guarded")?;
    let service = ephemeral_service_with_curl(store, "http://localhost:3000", false).await?;
    let path = format!("/api/v1/transactions/{source_id}/curl");

    for token in [None, Some("wrong-token")] {
        let request = dashboard_request(
            &service,
            Method::POST,
            &path,
            token,
            Some(service.url()),
            Some(json!({ "includeSensitiveHeaders": false })),
        )?;
        let response = send(&service, request).await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response_json(response).await?["error"]["code"],
            "invalid_inspector_token"
        );
    }

    let hostile_host = Request::builder()
        .method(Method::POST)
        .uri(&path)
        .header(HOST, "attacker.example")
        .header(ORIGIN, service.url())
        .header(INSPECTOR_TOKEN_HEADER, service.inspector_token().expose())
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"includeSensitiveHeaders":false}"#))?;
    assert_eq!(
        send(&service, hostile_host).await?.status(),
        StatusCode::MISDIRECTED_REQUEST
    );

    let hostile_origin = dashboard_request(
        &service,
        Method::POST,
        &path,
        Some(service.inspector_token().expose()),
        Some("https://attacker.example"),
        Some(json!({ "includeSensitiveHeaders": false })),
    )?;
    assert_eq!(
        send(&service, hostile_origin).await?.status(),
        StatusCode::FORBIDDEN
    );

    let accepted = dashboard_request(
        &service,
        Method::POST,
        &path,
        Some(service.inspector_token().expose()),
        Some(service.url()),
        Some(json!({ "includeSensitiveHeaders": false })),
    )?;
    let accepted = send(&service, accepted).await?;
    assert_eq!(accepted.status(), StatusCode::CONFLICT);
    assert_eq!(
        accepted.headers().get(CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );
    assert!(
        !accepted
            .headers()
            .contains_key("access-control-allow-origin")
    );
    Ok(())
}

#[tokio::test]
async fn curl_api_returns_stable_unavailable_error_for_an_existing_source() -> TestResult {
    let store = InspectionStore::new(InspectionLimits::new(8, 1024)?);
    let source_id = capture_curl_source(&store, "/unavailable")?;
    let service = ephemeral_service(store).await?;
    let request = dashboard_request(
        &service,
        Method::POST,
        &format!("/api/v1/transactions/{source_id}/curl"),
        Some(service.inspector_token().expose()),
        Some(service.url()),
        Some(json!({ "includeSensitiveHeaders": false })),
    )?;
    let response = send(&service, request).await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response_json(response).await?,
        json!({
            "error": {
                "code": "curl_unavailable",
                "message": "cURL generation is not configured for this dashboard"
            }
        })
    );
    Ok(())
}

#[tokio::test]
async fn curl_api_has_stable_invalid_missing_ineligible_and_local_uri_errors() -> TestResult {
    let store = InspectionStore::new(InspectionLimits::new(8, 3)?);
    let truncated_id = captured_id(store.capture(
        TransactionOrigin::Original,
        request_snapshot(
            &store,
            "/truncated-curl",
            "body-secret",
            "Bearer curl-error-secret",
        )?,
    ))?;
    let service =
        ephemeral_service_with_curl(store, "http://localhost:3000/current-base/", false).await?;
    let token = service.inspector_token().expose();

    let invalid = dashboard_request(
        &service,
        Method::POST,
        "/api/v1/transactions/not-a-uuid/curl",
        Some(token),
        None,
        Some(json!({ "includeSensitiveHeaders": false })),
    )?;
    let invalid = send(&service, invalid).await?;
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(invalid).await?,
        json!({
            "error": {
                "code": "invalid_transaction_id",
                "message": "transaction id must be a UUID"
            }
        })
    );

    let missing = dashboard_request(
        &service,
        Method::POST,
        &format!("/api/v1/transactions/{}/curl", TransactionId::new()),
        Some(token),
        None,
        Some(json!({ "includeSensitiveHeaders": false })),
    )?;
    let missing = send(&service, missing).await?;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(missing).await?,
        json!({
            "error": {
                "code": "transaction_not_found",
                "message": "the transaction is no longer retained"
            }
        })
    );

    let ineligible = dashboard_request(
        &service,
        Method::POST,
        &format!("/api/v1/transactions/{truncated_id}/curl"),
        Some(token),
        None,
        Some(json!({ "includeSensitiveHeaders": true })),
    )?;
    let ineligible = send(&service, ineligible).await?;
    assert_eq!(ineligible.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let ineligible_json = response_json(ineligible).await?;
    assert_eq!(
        ineligible_json,
        json!({
            "error": {
                "code": "truncated_request_body",
                "message": "the retained request is not eligible for replay"
            }
        })
    );
    let ineligible_text = serde_json::to_string(&ineligible_json)?;
    assert!(!ineligible_text.contains("body-secret"));
    assert!(!ineligible_text.contains("curl-error-secret"));

    let invalid_local_uri = curl_generation_error_response(CurlGenerationError::InvalidLocalUri);
    assert_eq!(invalid_local_uri.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        response_json(invalid_local_uri).await?,
        json!({
            "error": {
                "code": "invalid_local_uri",
                "message": "the retained request URI cannot be resolved against the current local target"
            }
        })
    );
    Ok(())
}

#[tokio::test]
async fn curl_api_rejects_malformed_missing_unknown_and_oversized_json_without_echoing_it()
-> TestResult {
    let store = InspectionStore::new(InspectionLimits::new(8, 1024)?);
    let source_id = capture_curl_source(&store, "/request-shape")?;
    let service = ephemeral_service_with_curl(store, "http://localhost:3000", false).await?;
    let path = format!("/api/v1/transactions/{source_id}/curl");
    let malformed_bodies: &[&[u8]] = &[
        b"",
        b"{}",
        b"{",
        br#"{"includeSensitiveHeaders":"false"}"#,
        br#"{"includeSensitiveHeaders":false,"extra":"do-not-echo"}"#,
    ];

    for body in malformed_bodies {
        let request = curl_request_with_raw_body(&service, &path, Bytes::copy_from_slice(body))?;
        let response = send(&service, request).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json(response).await?,
            json!({
                "error": {
                    "code": "invalid_request",
                    "message": "cURL generation requires a JSON includeSensitiveHeaders boolean"
                }
            })
        );
    }

    let oversized = format!(
        r#"{{"includeSensitiveHeaders":false,"padding":"{}"}}"#,
        "oversized-secret".repeat(32)
    );
    let request = curl_request_with_raw_body(&service, &path, oversized)?;
    let response = send(&service, request).await?;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        response.headers().get(CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );
    let response_json = response_json(response).await?;
    assert_eq!(
        response_json,
        json!({
            "error": {
                "code": "request_too_large",
                "message": "the API request body exceeds its limit"
            }
        })
    );
    assert!(!serde_json::to_string(&response_json)?.contains("oversized-secret"));
    Ok(())
}

#[tokio::test]
async fn curl_api_confirms_names_only_then_generates_for_current_target_and_tls_setting()
-> TestResult {
    let store = InspectionStore::new(InspectionLimits::new(8, 1024)?);
    let source_id = capture_curl_source(&store, "/curl/%2Fraw?mode=api")?;
    let insecure_service =
        ephemeral_service_with_curl(store.clone(), "https://localhost:3443/internal/api/", true)
            .await?;
    let path = format!("/api/v1/transactions/{source_id}/curl");

    let confirmation = dashboard_request(
        &insecure_service,
        Method::POST,
        &path,
        Some(insecure_service.inspector_token().expose()),
        Some(insecure_service.url()),
        Some(json!({ "includeSensitiveHeaders": false })),
    )?;
    let confirmation = send(&insecure_service, confirmation).await?;
    assert_eq!(confirmation.status(), StatusCode::CONFLICT);
    let confirmation = response_json(confirmation).await?;
    assert_eq!(
        confirmation,
        json!({
            "status": "confirmation_required",
            "headerNames": ["cookie", "authorization"]
        })
    );
    let confirmation_text = serde_json::to_string(&confirmation)?;
    for secret in [
        "curl-cookie-secret",
        "curl-authorization-secret",
        "curl-body-secret",
        "curl-public-value",
        "never-export-sink-control",
    ] {
        assert!(!confirmation_text.contains(secret));
    }

    let generated = dashboard_request(
        &insecure_service,
        Method::POST,
        &path,
        Some(insecure_service.inspector_token().expose()),
        Some(insecure_service.url()),
        Some(json!({ "includeSensitiveHeaders": true })),
    )?;
    let generated = send(&insecure_service, generated).await?;
    assert_eq!(generated.status(), StatusCode::OK);
    assert_eq!(
        generated.headers().get(CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );
    assert!(
        !generated
            .headers()
            .contains_key("access-control-allow-origin")
    );
    let generated = response_json(generated).await?;
    let generated_object = generated
        .as_object()
        .ok_or_else(|| io::Error::other("generated response was not an object"))?;
    assert_eq!(generated_object.len(), 3);
    assert_eq!(generated["status"], "generated");
    assert_eq!(generated["containsSecrets"], true);
    let command = generated["command"]
        .as_str()
        .ok_or_else(|| io::Error::other("generated response omitted command"))?;
    assert!(command.contains(" --insecure"));
    assert!(command.contains("--url 'https://localhost:3443/internal/api/curl/%2Fraw?mode=api'"));
    assert!(command.contains("session=curl-cookie-secret"));
    assert!(command.contains("Bearer curl-authorization-secret"));
    assert!(!command.contains("never-export-sink-control"));
    assert!(!command.contains("public.example.test"));

    let secure_service =
        ephemeral_service_with_curl(store, "https://localhost:3443/internal/api/", false).await?;
    let secure = dashboard_request(
        &secure_service,
        Method::POST,
        &path,
        Some(secure_service.inspector_token().expose()),
        Some(secure_service.url()),
        Some(json!({ "includeSensitiveHeaders": true })),
    )?;
    let secure = response_json(send(&secure_service, secure).await?).await?;
    assert!(
        !secure["command"]
            .as_str()
            .ok_or_else(|| io::Error::other("secure response omitted command"))?
            .contains(" --insecure")
    );
    Ok(())
}

#[tokio::test]
async fn list_is_newest_first_and_lightweight_while_detail_contains_one_bounded_body() -> TestResult
{
    let store = InspectionStore::new(InspectionLimits::new(8, 5)?);
    let first = capture_completed(&store, "/first", "123456789", "Bearer first-secret")?;
    let second = captured_id(store.capture_at(
        TransactionOrigin::Original,
        request_snapshot(&store, "/failed", "abcdefghijk", "Bearer second-secret")?,
        UNIX_EPOCH + Duration::from_secs(11),
    ))?;
    store.fail(
        second,
        Duration::from_millis(3),
        "upstream rejected Bearer second-secret",
    )?;
    let service = ephemeral_service(store).await?;

    let list_request = dashboard_request(
        &service,
        Method::GET,
        "/api/v1/transactions",
        None,
        None,
        None,
    )?;
    let list = response_json(send(&service, list_request).await?).await?;
    assert_eq!(list["transactions"][0]["id"], second.to_string());
    assert_eq!(list["transactions"][1]["id"], first.to_string());
    assert!(list["transactions"][0].get("request").is_none());
    assert!(list["transactions"][0].get("response").is_none());
    assert_eq!(list["transactions"][0]["requestBytes"], 11);
    assert_eq!(
        list["transactions"][0]["error"],
        "upstream rejected [MASKED]"
    );
    let list_text = serde_json::to_string(&list)?;
    assert!(!list_text.contains("abcdefghijk"));
    assert!(!list_text.contains("second-secret"));

    let detail_request = dashboard_request(
        &service,
        Method::GET,
        &format!("/api/v1/transactions/{first}"),
        None,
        None,
        None,
    )?;
    let detail = response_json(send(&service, detail_request).await?).await?;
    assert_eq!(detail["request"]["body"]["text"], "12345");
    assert_eq!(detail["request"]["body"]["transferredBytes"], 9);
    assert_eq!(detail["request"]["body"]["retainedBytes"], 5);
    assert_eq!(detail["request"]["body"]["truncated"], true);
    Ok(())
}

#[tokio::test]
async fn sse_maps_store_events_and_emits_explicit_resync_after_lag() -> TestResult {
    let store = InspectionStore::new(InspectionLimits::with_event_capacity(16, 32, 2)?);
    let mut current = store.subscribe();
    let current_id = captured_id(store.capture(
        TransactionOrigin::Original,
        request_snapshot(&store, "/current", "x", "Bearer current")?,
    ))?;
    assert!(matches!(
        receive_live_event(&mut current).await,
        Some(LiveEventDto::TransactionCreated { id, sequence: 1 }) if id == current_id
    ));
    store.pause();
    assert!(matches!(
        receive_live_event(&mut current).await,
        Some(LiveEventDto::CaptureStateChanged {
            sequence: 2,
            paused: true,
        })
    ));
    store.resume();
    assert!(matches!(
        receive_live_event(&mut current).await,
        Some(LiveEventDto::CaptureStateChanged {
            sequence: 3,
            paused: false,
        })
    ));
    assert!(store.delete(current_id));
    assert!(matches!(
        receive_live_event(&mut current).await,
        Some(LiveEventDto::TransactionRemoved {
            sequence: 4,
            id,
            cause: RemovalCauseDto::Deleted,
        }) if id == current_id
    ));
    assert_eq!(store.clear(), 0);
    assert!(matches!(
        receive_live_event(&mut current).await,
        Some(LiveEventDto::Cleared {
            sequence: 5,
            removed: 0,
        })
    ));

    let mut lagging = store.subscribe();
    for index in 0..6 {
        let path = format!("/lag-{index}");
        let _ = store.capture(
            TransactionOrigin::Original,
            request_snapshot(&store, &path, "x", "Bearer lag")?,
        );
    }
    let lagged = receive_live_event(&mut lagging)
        .await
        .ok_or_else(|| io::Error::other("lagging stream closed unexpectedly"))?;
    assert!(matches!(
        lagged,
        LiveEventDto::ResyncRequired {
            skipped,
            reason: ResyncReasonDto::Lagged,
        } if skipped > 0
    ));
    assert_eq!(serde_json::to_value(lagged)?["kind"], "resync_required");
    assert_eq!(serde_json::to_value(lagged)?["reason"], "lagged");

    let service = ephemeral_service(store).await?;
    let events_request =
        dashboard_request(&service, Method::GET, "/api/v1/events", None, None, None)?;
    let events = send(&service, events_request).await?;
    assert_eq!(events.status(), StatusCode::OK);
    assert_eq!(
        events
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream")
    );
    assert_eq!(
        events
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert!(!events.headers().contains_key("access-control-allow-origin"));
    let frame = timeout(Duration::from_secs(1), events.into_body().frame())
        .await?
        .ok_or_else(|| io::Error::other("SSE body ended before initial resync"))??;
    let data = frame
        .data_ref()
        .ok_or_else(|| io::Error::other("initial SSE frame did not contain data"))?;
    let text = std::str::from_utf8(data)?;
    assert!(text.contains("event: resync"));
    assert!(text.contains("\"kind\":\"resync_required\""));
    assert!(text.contains("\"reason\":\"connection_opened\""));
    Ok(())
}
