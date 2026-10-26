use super::*;
use gateway_rag::http::ContextConstraintIssuer;
use security_integration_runtime::a2a_objects::{A2aObjectConfig, TaskStore};

#[test]
fn task_metadata_rejects_replaced_or_removed_context_even_with_the_same_owner() {
	let config: SecurityConfig = serde_json::from_value(serde_json::json!({
			"mode":"enforce", "policies":[{"id":"allow","enabled":true,"effect":"allow"}],
			"crossComponent":{"namespace":uuid::Uuid::new_v4().to_string(),"destinations":[
					{"classification":"public"},{"classification":"internal"},{"classification":"restricted"}
			]}
	}))
	.unwrap();
	let config = Arc::new(config);
	let claims = crate::http::jwt::Claims {
        inner: serde_json::from_value(serde_json::json!({"iss":"https://issuer.example","sub":"alice","tenantId":"tenant-a","exp":chrono::Utc::now().timestamp()+300})).unwrap(),
        jwt: "unit-test-verified-extension".into(),
    };
	let mut extensions = ::http::Extensions::new();
	extensions.insert(claims.clone());
	let issuer = crate::security_flow::rag_issuer(config.clone(), &claims, "query".into()).unwrap();
	let guarded = security_rag::GuardedContext {
		corpus_id: "docs".into(),
		query_hash: "hash".into(),
		chunks: vec![],
		context_tokens: 0,
		classification: Some(security_types::DataClassification::Restricted),
		removed_chunk_ids: vec![],
		redacted_chunk_ids: vec![],
		findings: vec![],
	};
	let mut gates = Vec::new();
	let flows = (0..2)
		.map(|_| {
			let id = issuer.issue(&guarded, None).unwrap();
			let mut headers = ::http::HeaderMap::new();
			headers.insert(crate::security_flow::HEADER, id.parse().unwrap());
			let flow = crate::security_flow::prepare(&config, &headers, &extensions)
				.unwrap()
				.unwrap();
			let mut request = Request::default();
			*request.headers_mut() = headers;
			*request.extensions_mut() = extensions.clone();
			let mut guards = crate::proxy::RoutingGuards::default();
			guards
				.ensure(
					&crate::store::BackendPolicies {
						a2a: Some(crate::types::agent::A2aPolicy {}),
						security_audit: Some(config.clone()),
						..Default::default()
					},
					&request,
				)
				.unwrap();
			gates.push(guards);
			flow
		})
		.collect::<Vec<_>>();
	let identity = crate::security::identity_from_extensions(&extensions);
	for budget in [None, Some(crate::security::digest("execution"))] {
		let store = Arc::new(TaskStore::default());
		let objects = A2aObjectConfig::default();
		let binding = task_binding(budget.clone(), None, Some(&gates[0])).unwrap();
		let mut permit = store
			.begin(
				&objects,
				&identity,
				"https://issuer.example",
				"scope",
				None,
				TaskOperation::Create,
			)
			.unwrap();
		permit.bind_execution(binding.as_deref()).unwrap();
		store
			.finish(
				&objects,
				&mut permit,
				"task",
				"agent-context",
				TaskState::Working,
			)
			.unwrap();
		for replacement in [
			task_binding(budget.clone(), Some(&flows[1]), None).unwrap(),
			task_binding(budget.clone(), None, None).unwrap(),
			task_binding(
				Some(crate::security::digest("other execution")),
				Some(&flows[0]),
				Some(&gates[0]),
			)
			.unwrap(),
		] {
			let mut read = store
				.begin(
					&objects,
					&identity,
					"https://issuer.example",
					"scope",
					Some("task"),
					TaskOperation::Read,
				)
				.unwrap();
			assert!(matches!(
				read.bind_execution(replacement.as_deref()),
				Err(ObjectError::ExecutionBinding)
			));
		}
		let mut read = store
			.begin(
				&objects,
				&identity,
				"https://issuer.example",
				"scope",
				Some("task"),
				TaskOperation::Read,
			)
			.unwrap();
		read
			.bind_execution(
				task_binding(budget.clone(), Some(&flows[0].clone()), Some(&gates[0]))
					.unwrap()
					.as_deref(),
			)
			.unwrap();
		store.validate_permit(&objects, &read).unwrap();
	}
}
