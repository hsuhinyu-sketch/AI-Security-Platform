use gateway_rag::{RagGatewayAdapter, RagGatewayError, RagHttpService, RagQueryRequest};
use security_audit::InMemoryAuditSink;
use security_pipeline::{Authorizer, GatewayIdentity, SecurityPipeline};
use security_rag::*;
use security_types::{ActionRequest, ActionType, Decision, DecisionEffect};
use std::{
	future::Future,
	pin::Pin,
	sync::{
		Arc, Mutex,
		atomic::{AtomicUsize, Ordering},
	},
	task::{Context, Poll, Waker},
};

#[derive(Clone)]
struct Awaited {
	stages: Arc<Mutex<Vec<ActionType>>>,
	deny: Option<ActionType>,
}
impl Authorizer for Awaited {
	fn decide(&self, _: &ActionRequest) -> Decision {
		panic!("RAG must await the installed authorizer")
	}
	fn decide_async<'a>(
		&'a self,
		request: &'a ActionRequest,
	) -> Pin<Box<dyn Future<Output = Decision> + Send + 'a>> {
		Box::pin(async move {
			let mut first = true;
			std::future::poll_fn(|cx| {
				if first {
					first = false;
					cx.waker().wake_by_ref();
					Poll::Pending
				} else {
					Poll::Ready(())
				}
			})
			.await;
			self
				.stages
				.lock()
				.unwrap()
				.push(request.action.action_type.clone());
			Decision {
				approval: None,
				request_id: request.request_id.clone(),
				effect: if self.deny.as_ref() == Some(&request.action.action_type) {
					DecisionEffect::Deny
				} else {
					DecisionEffect::Allow
				},
				policy_id: Some("rag-test".into()),
				policy_version: None,
				expires_at: None,
			}
		})
	}
}
#[derive(Default)]
struct Backend {
	writes: AtomicUsize,
	queries: AtomicUsize,
}
#[async_trait::async_trait]
impl DocumentIngestBackend for Backend {
	async fn index(&self, _: IndexedDocument) -> Result<(), String> {
		self.writes.fetch_add(1, Ordering::SeqCst);
		Ok(())
	}
	async fn quarantine(&self, _: QuarantinedDocument) -> Result<(), String> {
		self.writes.fetch_add(1, Ordering::SeqCst);
		Ok(())
	}
}
#[async_trait::async_trait]
impl RetrievalBackend for Backend {
	async fn retrieve(
		&self,
		_: &RetrievalQuery,
		filter: &RetrievalFilter,
	) -> Result<Vec<KnowledgeChunk>, String> {
		assert_eq!(filter.tenant_id, "tenant-a");
		self.queries.fetch_add(1, Ordering::SeqCst);
		Ok(vec![])
	}
}
fn drive<T>(future: impl Future<Output = T>) -> T {
	let mut future = Box::pin(future);
	let mut cx = Context::from_waker(Waker::noop());
	for _ in 0..16 {
		if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
			return value;
		}
	}
	panic!("test providers must finish without external I/O")
}
fn identity() -> GatewayIdentity {
	GatewayIdentity {
		user_id: Some("alice".into()),
		tenant_id: Some("tenant-a".into()),
		..Default::default()
	}
}
fn adapter(backend: Arc<Backend>, policy: Awaited) -> impl gateway_rag::RagHttpService {
	let ingest = SecureIngestor::new(
		backend.clone(),
		SecurityPipeline::new(policy.clone(), InMemoryAuditSink::default()),
		Default::default(),
		InMemoryIngestionAuditSink::default(),
	)
	.unwrap();
	let retrieve = SecureRetriever::new(
		backend,
		SecurityPipeline::new(policy, InMemoryAuditSink::default()),
		Default::default(),
		InMemoryRetrievalAuditSink::default(),
	)
	.unwrap();
	RagGatewayAdapter::new(
		ingest,
		retrieve,
		ContextGuard::new(Default::default()).unwrap(),
		InMemoryContextAuditSink::default(),
	)
}
#[test]
fn query_waits_at_retrieval_and_context_boundaries_and_denial_stops_the_chain() {
	for denied in [
		None,
		Some(ActionType::KnowledgeRetrieve),
		Some(ActionType::ContextAssemble),
	] {
		let backend = Arc::new(Backend::default());
		let stages = Arc::new(Mutex::new(vec![]));
		let service = adapter(
			backend.clone(),
			Awaited {
				stages: stages.clone(),
				deny: denied.clone(),
			},
		);
		let result = drive(service.query(
			"request".into(),
			identity(),
			RagQueryRequest::new("docs", "question", 4),
		));
		assert_eq!(result.is_ok(), denied.is_none());
		assert_eq!(
			backend.queries.load(Ordering::SeqCst),
			if denied == Some(ActionType::KnowledgeRetrieve) {
				0
			} else {
				1
			}
		);
		assert_eq!(
			*stages.lock().unwrap(),
			if denied == Some(ActionType::KnowledgeRetrieve) {
				vec![ActionType::KnowledgeRetrieve]
			} else {
				vec![ActionType::KnowledgeRetrieve, ActionType::ContextAssemble]
			}
		);
		if denied == Some(ActionType::ContextAssemble) {
			assert!(matches!(result, Err(RagGatewayError::Context(_))));
		}
	}
}
#[test]
fn import_preflight_and_ingestion_await_before_backend_writes() {
	for denied in [false, true] {
		let backend = Arc::new(Backend::default());
		let stages = Arc::new(Mutex::new(vec![]));
		let service = adapter(
			backend.clone(),
			Awaited {
				stages: stages.clone(),
				deny: denied.then_some(ActionType::KnowledgeIngest),
			},
		);
		assert_eq!(
			drive(service.authorize_import(
				"preflight".into(),
				identity(),
				"docs",
				"document",
				"trusted"
			))
			.is_ok(),
			!denied
		);
		assert_eq!(
			drive(service.ingest(
				"ingest".into(),
				identity(),
				DocumentIngestRequest::new(
					"docs",
					"document",
					"https://sources.test/document",
					"safe knowledge"
				)
			))
			.is_ok(),
			!denied
		);
		assert_eq!(backend.writes.load(Ordering::SeqCst), usize::from(!denied));
		assert_eq!(
			*stages.lock().unwrap(),
			vec![ActionType::KnowledgeIngest, ActionType::KnowledgeIngest]
		);
	}
}
#[test]
fn missing_tenant_and_invalid_query_budget_never_reach_remote_policy_or_backend() {
	let backend = Arc::new(Backend::default());
	let stages = Arc::new(Mutex::new(vec![]));
	let service = adapter(
		backend.clone(),
		Awaited {
			stages: stages.clone(),
			deny: None,
		},
	);
	assert!(
		drive(service.query(
			"missing".into(),
			Default::default(),
			RagQueryRequest::new("docs", "question", 4)
		))
		.is_err()
	);
	assert!(
		drive(service.query(
			"budget".into(),
			identity(),
			RagQueryRequest::new("docs", "question", 0)
		))
		.is_err()
	);
	assert!(stages.lock().unwrap().is_empty());
	assert_eq!(backend.queries.load(Ordering::SeqCst), 0);
}
