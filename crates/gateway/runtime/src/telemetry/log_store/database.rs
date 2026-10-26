use super::*;
use crossbeam::channel::{Receiver, Sender, TryRecvError};
use std::{sync::OnceLock, thread};
use tokio::sync::oneshot;
use tracing::{debug, warn};

const INSERT_LOG_PREFIX: &str = r#"
INSERT INTO request_logs (
	id, started_at, completed_at, duration_ms, trace_id, span_id, http_status, error,
	gen_ai_operation_name, gen_ai_provider_name, gen_ai_request_model, gen_ai_response_model,
	input_tokens, output_tokens, total_tokens, cost, agentgateway_user, agentgateway_group,
	user_agent_name, has_payload, attributes_json
) "#;

const INSERT_PAYLOAD_PREFIX: &str = r#"
INSERT INTO request_log_payloads (log_id, request_prompt_json, response_completion_json)
"#;

macro_rules! push_request_log_row {
	($row:expr, $record:expr) => {{
		$row
			.push_bind(&$record.id)
			.push_bind($record.started_at)
			.push_bind($record.completed_at)
			.push_bind($record.duration_ms)
			.push_bind(&$record.trace_id)
			.push_bind(&$record.span_id)
			.push_bind($record.http_status)
			.push_bind(&$record.error)
			.push_bind(&$record.gen_ai_operation_name)
			.push_bind(&$record.gen_ai_provider_name)
			.push_bind(&$record.gen_ai_request_model)
			.push_bind(&$record.gen_ai_response_model)
			.push_bind($record.input_tokens)
			.push_bind($record.output_tokens)
			.push_bind($record.total_tokens)
			.push_bind($record.cost)
			.push_bind(&$record.agentgateway_user)
			.push_bind(&$record.agentgateway_group)
			.push_bind(&$record.user_agent_name)
			.push_bind($record.has_payload)
			.push_bind(sqlx::types::Json(&$record.attributes_json));
	}};
}

macro_rules! push_request_log_payload_row {
	($row:expr, $record:expr, $payload:expr) => {{
		$row
			.push_bind(&$record.id)
			.push_bind($payload.request_prompt_json.as_ref().map(sqlx::types::Json))
			.push_bind(
				$payload
					.response_completion_json
					.as_ref()
					.map(sqlx::types::Json),
			);
	}};
}

#[path = "postgres.rs"]
mod postgres;
#[path = "sqlite.rs"]
mod sqlite;

static REQUEST_LOG_STORE: OnceLock<RequestLogStore> = OnceLock::new();

#[derive(Clone)]
pub struct RequestLogStore {
	tx: Sender<LogStoreMsg>,
}

impl RequestLogStore {
	pub fn emit(&self, record: StoredRequestLog) {
		if let Err(err) = self.tx.send(LogStoreMsg::Record(record)) {
			warn!(target: "request", ?err, "failed to enqueue request log database record");
		}
	}

	async fn request<T: Send + 'static>(
		&self,
		msg: impl FnOnce(QueryResponse<T>) -> LogStoreMsg,
	) -> anyhow::Result<T> {
		let (tx, rx) = oneshot::channel();
		self
			.tx
			.send(msg(tx))
			.map_err(|_| anyhow::anyhow!("request log database worker is stopped"))?;
		rx.await
			.map_err(|_| anyhow::anyhow!("request log database worker is stopped"))?
	}
}

pub async fn setup(cfg: &Config) -> anyhow::Result<RequestLogStoreGuard> {
	cfg.validate_compiled()?;
	let (tx, rx) = crossbeam::channel::unbounded();
	let (ready_tx, ready_rx) = oneshot::channel();
	let writer = LogStoreWorker::new(rx, cfg.clone(), ready_tx)
		.worker_thread("request-log-db-writer".to_string())?;
	ready_rx
		.await
		.map_err(|_| anyhow::anyhow!("request log database worker stopped during startup"))??;
	let store = RequestLogStore { tx: tx.clone() };
	let _ = REQUEST_LOG_STORE.set(store);
	Ok(RequestLogStoreGuard {
		tx,
		writer: Some(writer),
	})
}

pub fn emit(record: StoredRequestLog) {
	if let Some(store) = REQUEST_LOG_STORE.get() {
		store.emit(record);
	}
}

pub fn enabled() -> bool {
	REQUEST_LOG_STORE.get().is_some()
}

pub async fn search(request: SearchRequest) -> anyhow::Result<SearchResponse> {
	let store = REQUEST_LOG_STORE
		.get()
		.ok_or_else(|| anyhow::anyhow!("request log database is not configured"))?;
	store
		.request(|tx| LogStoreMsg::Search { request, tx })
		.await
}

pub async fn get(request: GetRequest) -> anyhow::Result<GetResponse> {
	let store = REQUEST_LOG_STORE
		.get()
		.ok_or_else(|| anyhow::anyhow!("request log database is not configured"))?;
	store.request(|tx| LogStoreMsg::Get { request, tx }).await
}

pub async fn analytics_summary(
	request: AnalyticsSummaryRequest,
) -> anyhow::Result<AnalyticsSummaryResponse> {
	let store = REQUEST_LOG_STORE
		.get()
		.ok_or_else(|| anyhow::anyhow!("request log database is not configured"))?;
	store
		.request(|tx| LogStoreMsg::AnalyticsSummary { request, tx })
		.await
}

pub async fn tail(request: TailRequest) -> anyhow::Result<TailResponse> {
	let store = REQUEST_LOG_STORE
		.get()
		.ok_or_else(|| anyhow::anyhow!("request log database is not configured"))?;
	store.request(|tx| LogStoreMsg::Tail { request, tx }).await
}

pub struct RequestLogStoreGuard {
	tx: Sender<LogStoreMsg>,
	writer: Option<thread::JoinHandle<()>>,
}

impl RequestLogStoreGuard {
	pub async fn shutdown_and_wait(mut self) {
		let _ = self.tx.send(LogStoreMsg::Shutdown);
		if let Some(writer) = self.writer.take() {
			match tokio::task::spawn_blocking(move || writer.join()).await {
				Ok(Ok(())) => {},
				Ok(Err(_)) => {
					warn!(target: "request", "request log database writer panicked");
				},
				Err(err) => {
					warn!(target: "request", ?err, "failed to join request log database writer");
				},
			};
		}
	}
}

impl Drop for RequestLogStoreGuard {
	fn drop(&mut self) {
		let _ = self.tx.send(LogStoreMsg::Shutdown);
	}
}

const LOG_STORE_BATCH_SIZE: usize = 64;

#[allow(clippy::large_enum_variant)] // The StoredRequestLog, which is used 99.9% of the time, is the large one
enum LogStoreMsg {
	Record(StoredRequestLog),
	Search {
		request: SearchRequest,
		tx: QueryResponse<SearchResponse>,
	},
	Get {
		request: GetRequest,
		tx: QueryResponse<GetResponse>,
	},
	AnalyticsSummary {
		request: AnalyticsSummaryRequest,
		tx: QueryResponse<AnalyticsSummaryResponse>,
	},
	Tail {
		request: TailRequest,
		tx: QueryResponse<TailResponse>,
	},
	Shutdown,
}

type QueryResponse<T> = oneshot::Sender<anyhow::Result<T>>;

struct LogStoreWorker {
	receiver: Receiver<LogStoreMsg>,
	cfg: Config,
	ready_tx: Option<oneshot::Sender<anyhow::Result<()>>>,
}

impl LogStoreWorker {
	fn new(
		receiver: Receiver<LogStoreMsg>,
		cfg: Config,
		ready_tx: oneshot::Sender<anyhow::Result<()>>,
	) -> Self {
		Self {
			receiver,
			cfg,
			ready_tx: Some(ready_tx),
		}
	}

	fn worker_thread(self, name: String) -> anyhow::Result<thread::JoinHandle<()>> {
		thread::Builder::new()
			.name(name)
			.spawn(move || self.work())
			.map_err(Into::into)
	}

	fn work(mut self) {
		let runtime = match tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
		{
			Ok(runtime) => runtime,
			Err(err) => {
				warn!(target: "request", ?err, "failed to start request log database worker runtime");
				self.notify_ready(Err(anyhow::Error::new(err)));
				return;
			},
		};
		runtime.block_on(self.work_async());
		debug!(target: "request", "request log database writer stopped");
	}

	fn notify_ready(&mut self, result: anyhow::Result<()>) {
		if let Some(tx) = self.ready_tx.take() {
			let _ = tx.send(result);
		}
	}

	async fn work_async(mut self) {
		let backend = match Backend::connect(&self.cfg).await {
			Ok(backend) => backend,
			Err(err) => {
				self.notify_ready(Err(err));
				return;
			},
		};
		self.notify_ready(Ok(()));
		let mut batch = Vec::with_capacity(LOG_STORE_BATCH_SIZE);
		loop {
			match self.receiver.recv() {
				Ok(msg) => {
					if process_log_store_msg(&backend, &mut batch, msg).await {
						self.drain_available_messages(&backend, &mut batch).await;
						break;
					}
				},
				Err(_) => {
					self.drain_available_messages(&backend, &mut batch).await;
					break;
				},
			}

			let mut shutdown = false;
			while batch.len() < batch.capacity() {
				match self.receiver.try_recv() {
					Ok(msg) => {
						if process_log_store_msg(&backend, &mut batch, msg).await {
							shutdown = true;
							break;
						}
					},
					Err(TryRecvError::Disconnected) => {
						shutdown = true;
						break;
					},
					Err(TryRecvError::Empty) => break,
				}
			}
			flush_log_store_batch(&backend, &mut batch).await;
			if shutdown {
				self.drain_available_messages(&backend, &mut batch).await;
				break;
			}
		}
	}

	async fn drain_available_messages(&self, backend: &Backend, batch: &mut Vec<StoredRequestLog>) {
		loop {
			match self.receiver.try_recv() {
				Ok(msg) => {
					let _ = process_log_store_msg(backend, batch, msg).await;
				},
				Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
			}
			if batch.len() == batch.capacity() {
				flush_log_store_batch(backend, batch).await;
			}
		}
		flush_log_store_batch(backend, batch).await;
	}
}

async fn process_log_store_msg(
	backend: &Backend,
	batch: &mut Vec<StoredRequestLog>,
	msg: LogStoreMsg,
) -> bool {
	match msg {
		LogStoreMsg::Record(record) => {
			batch.push(record);
			false
		},
		LogStoreMsg::Search { request, tx } => {
			flush_log_store_batch(backend, batch).await;
			let _ = tx.send(backend.search(request).await);
			false
		},
		LogStoreMsg::Get { request, tx } => {
			flush_log_store_batch(backend, batch).await;
			let _ = tx.send(backend.get(request).await);
			false
		},
		LogStoreMsg::AnalyticsSummary { request, tx } => {
			flush_log_store_batch(backend, batch).await;
			let _ = tx.send(backend.analytics_summary(request).await);
			false
		},
		LogStoreMsg::Tail { request, tx } => {
			flush_log_store_batch(backend, batch).await;
			let _ = tx.send(backend.tail(request).await);
			false
		},
		LogStoreMsg::Shutdown => true,
	}
}

async fn flush_log_store_batch(backend: &Backend, batch: &mut Vec<StoredRequestLog>) {
	if batch.is_empty() {
		return;
	}
	if let Err(err) = backend.insert_batch(batch).await {
		warn!(target: "request", ?err, count = batch.len(), "failed to persist request log batch");
	}
	batch.clear();
}

enum Backend {
	Sqlite(sqlite::SqliteLogStore),
	Postgres(postgres::PostgresLogStore),
}

impl Backend {
	async fn connect(cfg: &Config) -> anyhow::Result<Self> {
		if cfg.url.starts_with("postgres://") || cfg.url.starts_with("postgresql://") {
			Ok(Self::Postgres(
				postgres::PostgresLogStore::connect(&cfg.url).await?,
			))
		} else {
			Ok(Self::Sqlite(
				sqlite::SqliteLogStore::connect(&cfg.url).await?,
			))
		}
	}

	async fn insert_batch(&self, records: &[StoredRequestLog]) -> anyhow::Result<()> {
		match self {
			Self::Sqlite(store) => store.insert_batch(records).await,
			Self::Postgres(store) => store.insert_batch(records).await,
		}
	}

	async fn search(&self, request: SearchRequest) -> anyhow::Result<SearchResponse> {
		match self {
			Self::Sqlite(store) => store.search(request).await,
			Self::Postgres(store) => store.search(request).await,
		}
	}

	async fn get(&self, request: GetRequest) -> anyhow::Result<GetResponse> {
		match self {
			Self::Sqlite(store) => store.get(request).await,
			Self::Postgres(store) => store.get(request).await,
		}
	}

	async fn analytics_summary(
		&self,
		request: AnalyticsSummaryRequest,
	) -> anyhow::Result<AnalyticsSummaryResponse> {
		match self {
			Self::Sqlite(store) => store.analytics_summary(request).await,
			Self::Postgres(store) => store.analytics_summary(request).await,
		}
	}

	async fn tail(&self, request: TailRequest) -> anyhow::Result<TailResponse> {
		match self {
			Self::Sqlite(store) => store.tail(request).await,
			Self::Postgres(store) => store.tail(request).await,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test]
	async fn infrastructure_sqlite_records_and_payload_survive_reopen() {
		let path =
			std::env::temp_dir().join(format!("aisp-log-boundary-{}.sqlite", uuid::Uuid::new_v4()));
		let config = Config {
			url: format!("sqlite://{}", path.display()),
		};
		let now = Utc::now();
		let record = StoredRequestLog {
			id: "round-trip".into(),
			started_at: now,
			completed_at: now,
			duration_ms: 7,
			trace_id: Some("trace".into()),
			span_id: Some("span".into()),
			http_status: Some(200),
			error: None,
			gen_ai_operation_name: Some("chat".into()),
			gen_ai_provider_name: Some("local".into()),
			gen_ai_request_model: Some("model".into()),
			gen_ai_response_model: Some("model".into()),
			input_tokens: Some(2),
			output_tokens: Some(3),
			total_tokens: Some(5),
			cost: None,
			agentgateway_user: Some("user".into()),
			agentgateway_group: None,
			user_agent_name: None,
			has_payload: true,
			attributes_json: serde_json::json!({"security.request_id":"request-1"}),
			payload: Some(StoredRequestLogPayload {
				request_prompt_json: Some(serde_json::json!(["prompt"])),
				response_completion_json: Some(serde_json::json!("answer")),
			}),
		};
		let store = Backend::connect(&config).await.unwrap();
		store.insert_batch(&[record.clone()]).await.unwrap();
		// A duplicate primary key must fail rather than report a successful persistence.
		assert!(store.insert_batch(&[record]).await.is_err());
		drop(store);
		let store = Backend::connect(&config).await.unwrap();
		let response = store
			.get(GetRequest {
				id: "round-trip".into(),
				include_payload: true,
			})
			.await
			.unwrap();
		let log = response.log.unwrap();
		assert_eq!(log.id, "round-trip");
		assert_eq!(
			log.attributes.as_ref().unwrap()["security.request_id"],
			"request-1"
		);
		assert_eq!(
			log.payload.unwrap().response_completion,
			Some(serde_json::json!("answer"))
		);
		drop(store);
		let _ = std::fs::remove_file(&path);
		let _ = std::fs::remove_file(format!("{}-wal", path.display()));
		let _ = std::fs::remove_file(format!("{}-shm", path.display()));
	}
}
