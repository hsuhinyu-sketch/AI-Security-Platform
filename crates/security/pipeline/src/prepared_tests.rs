use super::*;
use security_audit::InMemoryAuditSink;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};

fn config() -> SecurityPipelineConfig {
	serde_json::from_value(json!({"policies":[{
		"id":"allow","enabled":true,"effect":"allow","tenantId":"tenant-a"
	}]}))
	.unwrap()
}
fn action() -> ActionRequest {
	crate::tool_invoke_for_identity(
		"request",
		crate::GatewayIdentity {
			user_id: Some("alice".into()),
			tenant_id: Some("tenant-a".into()),
			..Default::default()
		},
		"echo",
	)
}

#[test]
fn shared_rules_keep_request_arguments_audit_sinks_and_tenant_decisions_separate() {
	let mut config = config();
	config
		.required_tool_arguments
		.push(RequiredToolArgumentsConfig {
			tool_name: "echo".into(),
			required_fields: vec!["query".into()],
		});
	let prepared = config.prepare();
	let a = InMemoryAuditSink::default();
	let b = InMemoryAuditSink::default();
	let first = prepared.build_with_runtime_controls(&a, RuntimeSecurityControls::default());
	let second = prepared.build_with_runtime_controls(&b, RuntimeSecurityControls::default());
	assert!(Arc::ptr_eq(
		&first.authorizer.static_authorizer.policies,
		&second.authorizer.static_authorizer.policies
	));
	assert!(Arc::ptr_eq(
		&first.action_controls[0],
		&second.action_controls[0]
	));
	assert!(first.authorize(&action(), Some(&json!({}))).is_err());
	assert!(
		second
			.authorize(&action(), Some(&json!({"query":"safe"})))
			.is_ok()
	);
	let mut foreign = action();
	foreign.request_id = "foreign".into();
	foreign.subject.tenant_id = Some("tenant-b".into());
	assert!(
		second
			.authorize(&foreign, Some(&json!({"query":"safe"})))
			.is_err()
	);
	assert_eq!(a.events().len(), 1);
	assert_eq!(b.events().len(), 2);
	assert_eq!(b.events()[1].request_id, "foreign");
	assert_eq!(b.events()[1].decision, DecisionEffect::Deny);
}

#[test]
fn prepared_static_policy_keeps_default_deny_and_deny_override() {
	let sink = InMemoryAuditSink::default();
	assert!(
		SecurityPipelineConfig::default()
			.prepare()
			.build_with_runtime_controls(&sink, RuntimeSecurityControls::default())
			.authorize(&action(), None)
			.is_err()
	);
	let mut config = config();
	let mut deny = config.policies[0].clone();
	deny.id = "deny".into();
	deny.effect = DecisionEffect::Deny;
	deny.priority = -10;
	config.policies[0].priority = 100;
	config.policies.push(deny);
	let decision = config.prepare().prefilter(&action());
	assert_eq!(decision.effect, DecisionEffect::Deny);
	assert_eq!(decision.policy_id.as_deref(), Some("deny"));
}

struct RuntimeControl;
impl SecurityControl for RuntimeControl {
	fn id(&self) -> &str {
		"runtime"
	}
	fn check(
		&self,
		_: &ActionRequest,
		_: Option<&serde_json::Value>,
	) -> Result<Option<security_types::ApprovalGrant>, ControlDenial> {
		Ok(None)
	}
}
#[test]
fn prepared_control_order_and_approval_provider_binding_are_preserved() {
	let mut config = config();
	config.required_identity = Some(RequiredIdentity {
		user: true,
		agent: false,
		tenant: true,
	});
	config
		.required_tool_arguments
		.push(RequiredToolArgumentsConfig {
			tool_name: "echo".into(),
			required_fields: vec!["query".into()],
		});
	config
		.required_tool_approvals
		.push(RequiredToolApprovalConfig {
			tool_name: "echo".into(),
		});
	config.delegations =
		serde_json::from_value(json!([{"id":"d","userId":"alice","agentId":"agent","scopes":[{}]}]))
			.unwrap();
	let prepared = config.prepare();
	let sink = InMemoryAuditSink::default();
	let controls = || {
		RuntimeSecurityControls::default()
			.add_identity_control(RuntimeControl)
			.add_action_control(RuntimeControl)
	};
	let pipeline = prepared.build_with_runtime_controls(&sink, controls());
	assert_eq!(
		pipeline
			.identity_controls
			.iter()
			.map(|c| c.id())
			.collect::<Vec<_>>(),
		["required-identity", "runtime", "agent-delegation"]
	);
	assert_eq!(
		pipeline
			.action_controls
			.iter()
			.map(|c| c.id())
			.collect::<Vec<_>>(),
		[
			"required-tool-arguments",
			"required-tool-approval",
			"runtime"
		]
	);
	assert!(
		pipeline
			.authorize(&action(), Some(&json!({"query":"safe"})))
			.is_err()
	);
	let approved = prepared.build_with_runtime_controls(
		&sink,
		controls().with_approval_provider(StaticApproval(true)),
	);
	assert!(
		approved
			.authorize(&action(), Some(&json!({"query":"safe"})))
			.is_ok()
	);
	let denied = prepared.build_with_runtime_controls(
		&sink,
		controls().with_approval_provider(StaticApproval(false)),
	);
	assert!(
		denied
			.authorize(&action(), Some(&json!({"query":"safe"})))
			.is_err()
	);
	assert!(approved.capabilities.is_none());
}

#[derive(Clone)]
struct ChangingPdp(Arc<AtomicUsize>);
impl RemotePdpTransport for ChangingPdp {
	fn decide(&self, request: RemotePdpRequest) -> Result<RemotePdpResponse, DynamicPdpError> {
		if self.0.fetch_add(1, Ordering::SeqCst) > 0 {
			return Err(DynamicPdpError::unavailable("offline"));
		}
		Ok(RemotePdpResponse {
			request_id: request.request.request_id,
			effect: DecisionEffect::Allow,
			policy_id: "remote".into(),
			policy_version: "v1".into(),
			expires_at: Utc::now() + Duration::seconds(30),
		})
	}
}
fn remote_case(ttl: u64, failure: &str, expect_cached: bool) {
	let mut config = config();
	config.dynamic_authorization = Some(
		serde_json::from_value(
			json!({"policyVersion":"v1","cacheTtlSeconds":ttl,"failureMode":failure}),
		)
		.unwrap(),
	);
	let prepared = config.prepare();
	let calls = Arc::new(AtomicUsize::new(0));
	let sink = InMemoryAuditSink::default();
	let invoke = || {
		prepared
			.build_with_remote_pdp_and_runtime_controls(
				&sink,
				ChangingPdp(calls.clone()),
				RuntimeSecurityControls::default(),
			)
			.unwrap()
			.authorize(&action(), None)
	};
	assert!(invoke().is_ok());
	assert_eq!(invoke().is_ok(), expect_cached);
	assert_eq!(
		calls.load(Ordering::SeqCst),
		if expect_cached { 1 } else { 2 }
	);
}
#[test]
fn prepared_remote_rules_keep_fail_closed_and_explicit_existing_cache_policy() {
	remote_case(60, "failClosed", false);
	remote_case(60, "useCachedDecision", true);
	remote_case(0, "useCachedDecision", false);
}

#[test]
fn excessive_cache_lifetime_does_not_panic_or_cache_an_unbounded_allow() {
	remote_case(u64::MAX, "useCachedDecision", false);
	remote_case((i64::MAX / 1000) as u64, "useCachedDecision", false);
}

#[test]
fn disabling_cache_ignores_an_existing_cached_allow() {
	let mut config = config();
	config.dynamic_authorization = Some(
		serde_json::from_value(
			json!({"policyVersion":"v1","cacheTtlSeconds":60,"failureMode":"useCachedDecision"}),
		)
		.unwrap(),
	);
	let calls = Arc::new(AtomicUsize::new(0));
	let sink = InMemoryAuditSink::default();
	let invoke = |prepared: &PreparedSecurityPipeline| {
		prepared
			.build_with_remote_pdp_and_runtime_controls(
				&sink,
				ChangingPdp(calls.clone()),
				RuntimeSecurityControls::default(),
			)
			.unwrap()
			.authorize(&action(), None)
	};
	assert!(invoke(&config.prepare()).is_ok());
	config
		.dynamic_authorization
		.as_mut()
		.unwrap()
		.cache_ttl_seconds = 0;
	assert!(invoke(&config.prepare()).is_err());
	assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn explicitly_cached_decision_uses_the_current_request_id_without_renewing_expiry() {
	let mut config = config();
	config.dynamic_authorization = Some(
		serde_json::from_value(
			json!({"policyVersion":"v1","cacheTtlSeconds":60,"failureMode":"useCachedDecision"}),
		)
		.unwrap(),
	);
	let prepared = config.prepare();
	let sink = InMemoryAuditSink::default();
	let calls = Arc::new(AtomicUsize::new(0));
	let pipeline = prepared
		.build_with_remote_pdp_and_runtime_controls(
			&sink,
			ChangingPdp(calls.clone()),
			RuntimeSecurityControls::default(),
		)
		.unwrap();
	let first = pipeline.authorize(&action(), None).unwrap();
	let mut request = action();
	request.request_id = "next-request".into();
	let second = pipeline.authorize(&request, None).unwrap();
	assert_eq!(second.request_id, "next-request");
	assert_eq!(first.expires_at, second.expires_at);
	assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn fail_closed_does_not_read_or_populate_an_enabled_cache() {
	let cache = DecisionCache::default();
	let calls = Arc::new(AtomicUsize::new(0));
	let pdp = CachedDynamicPdp::new(
		RemoteDynamicPdp::new(ChangingPdp(calls.clone()), Some("v1".into())),
		cache.clone(),
		"v1",
		Duration::seconds(60),
		DynamicPdpFailureMode::FailClosed,
	);
	let decision = pdp.decide(&action()).unwrap();
	assert!(cache.entries.lock().unwrap().is_empty());
	// An Allow left by a previously enabled cache is also ignored in FailClosed mode.
	cache.insert(pdp.cache_key(&action()), decision, Duration::seconds(60));
	assert!(pdp.decide(&action()).is_err());
	assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn cache_capacity_misses_consult_pdp_and_expiry_reclaims_space() {
	let cache = DecisionCache::default();
	let decision = Decision {
		approval: None,
		request_id: "cached".into(),
		effect: DecisionEffect::Allow,
		policy_id: Some("allow".into()),
		policy_version: Some("v1".into()),
		expires_at: None,
	};
	for index in 0..DecisionCache::MAX_ENTRIES {
		cache.insert(index.to_string(), decision.clone(), Duration::minutes(1));
	}
	// Saturation is a cache miss, never an implicit Allow or a PDP failure fallback.
	let calls = Arc::new(AtomicUsize::new(0));
	let pdp = CachedDynamicPdp::new(
		RemoteDynamicPdp::new(ChangingPdp(calls.clone()), Some("v1".into())),
		cache.clone(),
		"v1",
		Duration::seconds(60),
		DynamicPdpFailureMode::UseCachedDecision,
	);
	assert!(pdp.decide(&action()).is_ok());
	assert!(pdp.decide(&action()).is_err());
	assert_eq!(calls.load(Ordering::SeqCst), 2);
	assert_eq!(
		cache.entries.lock().unwrap().len(),
		DecisionCache::MAX_ENTRIES
	);
	// Exercise concurrent insertion with distinct attacker-controlled keys.
	std::thread::scope(|scope| {
		for worker in 0..4 {
			let cache = &cache;
			let decision = &decision;
			scope.spawn(move || {
				for index in 0..32 {
					cache.insert(
						format!("extra-{worker}-{index}"),
						decision.clone(),
						Duration::minutes(1),
					);
				}
			});
		}
	});
	assert_eq!(
		cache.entries.lock().unwrap().len(),
		DecisionCache::MAX_ENTRIES
	);
	cache
		.entries
		.lock()
		.unwrap()
		.get_mut("0")
		.unwrap()
		.expires_at = Utc::now() - Duration::seconds(1);
	cache.insert("replacement".into(), decision, Duration::minutes(1));
	assert!(cache.get("0", Utc::now()).is_none());
	assert!(cache.get("replacement", Utc::now()).is_some());
	assert_eq!(
		cache.entries.lock().unwrap().len(),
		DecisionCache::MAX_ENTRIES
	);
}

struct LiveApproval(Arc<std::sync::atomic::AtomicBool>, Arc<AtomicUsize>);
impl ApprovalProvider for LiveApproval {
	fn approved(
		&self,
		_: &ActionRequest,
		_: &serde_json::Value,
	) -> Result<Option<security_types::ApprovalGrant>, ApprovalError> {
		self.1.fetch_add(1, Ordering::SeqCst);
		Ok(
			self
				.0
				.load(Ordering::SeqCst)
				.then(|| security_types::ApprovalGrant {
					approval_id: "live".into(),
					expires_at: Utc::now() + Duration::seconds(30),
				}),
		)
	}
}
#[test]
fn shared_rules_do_not_freeze_approval_or_revocation_results() {
	let mut config = config();
	config
		.required_tool_approvals
		.push(RequiredToolApprovalConfig {
			tool_name: "echo".into(),
		});
	let prepared = config.prepare();
	let sink = InMemoryAuditSink::default();
	let allow = Arc::new(std::sync::atomic::AtomicBool::new(true));
	let calls = Arc::new(AtomicUsize::new(0));
	let revocations = Arc::new(DelegationRevocationRegistry::default());
	let controls = RuntimeSecurityControls::default()
		.with_approval_provider(LiveApproval(allow.clone(), calls.clone()))
		.add_identity_control(DelegationRevocationCheck::new(revocations.clone()));
	let pipeline = prepared.build_with_runtime_controls(&sink, controls);
	let mut action = action();
	action.subject.delegation_id = Some("delegation".into());
	let arguments = json!({"query":"safe"});
	assert!(pipeline.authorize(&action, Some(&arguments)).is_ok());
	allow.store(false, Ordering::SeqCst);
	assert!(pipeline.authorize(&action, Some(&arguments)).is_err());
	allow.store(true, Ordering::SeqCst);
	revocations.revoke("delegation");
	assert!(pipeline.authorize(&action, Some(&arguments)).is_err());
	assert_eq!(calls.load(Ordering::SeqCst), 2);
	assert_eq!(sink.events().len(), 3);
}

#[test]
fn prepared_local_rules_recheck_expiry_at_execution_time() {
	let mut config = config();
	config.dynamic_authorization = Some(
		serde_json::from_value(json!({"policyVersion":"v1","policies":[{
			"id":"dynamic","enabled":true,"effect":"allow","expiresAt":Utc::now()+Duration::seconds(1)
		}]}))
		.unwrap(),
	);
	let prepared = config.prepare();
	let sink = InMemoryAuditSink::default();
	let invoke = || {
		prepared
			.build_with_runtime_controls(&sink, RuntimeSecurityControls::default())
			.authorize(&action(), None)
	};
	assert!(invoke().is_ok());
	std::thread::sleep(std::time::Duration::from_millis(1100));
	assert!(invoke().is_err());
}

#[test]
fn awaited_pipeline_preserves_control_order_arguments_and_one_audit_outcome() {
	struct Control {
		stage: &'static str,
		log: Arc<Mutex<Vec<&'static str>>>,
		deny: bool,
	}
	impl SecurityControl for Control {
		fn id(&self) -> &str {
			self.stage
		}
		fn check(
			&self,
			_: &ActionRequest,
			arguments: Option<&serde_json::Value>,
		) -> Result<Option<security_types::ApprovalGrant>, ControlDenial> {
			assert_eq!(arguments.unwrap()["query"], "safe");
			self.log.lock().unwrap().push(self.stage);
			if self.deny {
				Err(ControlDenial {
					control_id: self.stage.into(),
					reason: "refused".into(),
				})
			} else {
				Ok(None)
			}
		}
	}
	struct Awaited {
		log: Arc<Mutex<Vec<&'static str>>>,
		deny: bool,
	}
	impl Authorizer for Awaited {
		fn decide(&self, _: &ActionRequest) -> Decision {
			panic!("awaited path must use the asynchronous provider")
		}
		fn decide_async<'a>(
			&'a self,
			request: &'a ActionRequest,
		) -> std::pin::Pin<Box<dyn std::future::Future<Output = Decision> + Send + 'a>> {
			let mut yielded = false;
			Box::pin(std::future::poll_fn(move |cx| {
				if !yielded {
					yielded = true;
					cx.waker().wake_by_ref();
					return std::task::Poll::Pending;
				}
				self.log.lock().unwrap().push("provider");
				std::task::Poll::Ready(Decision {
					approval: None,
					request_id: request.request_id.clone(),
					effect: if self.deny {
						DecisionEffect::Deny
					} else {
						DecisionEffect::Allow
					},
					policy_id: Some("awaited".into()),
					policy_version: None,
					expires_at: None,
				})
			}))
		}
	}
	use std::{
		future::Future,
		task::{Context, Poll, Waker},
	};
	for rejected in [None, Some("identity"), Some("provider"), Some("action")] {
		let log = Arc::new(Mutex::new(Vec::new()));
		let audit = InMemoryAuditSink::default();
		let pipeline = SecurityPipeline::new(
			Awaited {
				log: log.clone(),
				deny: rejected == Some("provider"),
			},
			&audit,
		)
		.add_identity_control(Control {
			stage: "identity",
			log: log.clone(),
			deny: rejected == Some("identity"),
		})
		.add_action_control(Control {
			stage: "action",
			log: log.clone(),
			deny: rejected == Some("action"),
		});
		let request = action();
		let args = json!({"query":"safe"});
		let mut future = Box::pin(pipeline.authorize_async(&request, Some(&args)));
		let mut cx = Context::from_waker(Waker::noop());
		let result = if rejected == Some("identity") {
			future.as_mut().poll(&mut cx)
		} else {
			assert!(future.as_mut().poll(&mut cx).is_pending());
			assert_eq!(*log.lock().unwrap(), ["identity"]);
			assert!(audit.events().is_empty());
			future.as_mut().poll(&mut cx)
		};
		let Poll::Ready(result) = result else {
			panic!("provider should be ready on the next poll")
		};
		assert_eq!(result.is_ok(), rejected.is_none());
		assert_eq!(
			*log.lock().unwrap(),
			match rejected {
				Some("identity") => vec!["identity"],
				Some("provider") => vec!["identity", "provider"],
				_ => vec!["identity", "provider", "action"],
			}
		);
		assert_eq!(audit.events().len(), 1);
		assert_eq!(
			audit.events()[0].decision,
			if rejected.is_none() {
				DecisionEffect::Allow
			} else {
				DecisionEffect::Deny
			}
		);
	}
}

#[test]
fn local_authorizers_keep_sync_and_object_safe_awaited_compatibility() {
	use std::task::{Context, Poll, Waker};
	let local = PolicyAuthorizer::new(config().policies);
	let object: &dyn Authorizer = &local;
	let request = action();
	let expected = object.decide(&request);
	let mut future = object.decide_async(&request);
	assert!(
		matches!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())), Poll::Ready(actual) if actual==expected)
	);
}

#[test]
fn approval_receipt_survives_authorization_and_bounds_local_capability() {
	let receipt = security_types::ApprovalGrant {
		approval_id: "approval-42".into(),
		expires_at: Utc::now() + Duration::seconds(2),
	};
	struct Provider(security_types::ApprovalGrant);
	impl ApprovalProvider for Provider {
		fn approved(
			&self,
			_: &ActionRequest,
			_: &serde_json::Value,
		) -> Result<Option<security_types::ApprovalGrant>, ApprovalError> {
			Ok(Some(self.0.clone()))
		}
	}
	let sink = InMemoryAuditSink::default();
	let pipeline = SecurityPipeline::new(PolicyAuthorizer::new(config().policies), &sink)
		.add_action_control(ToolApproval::new("echo", Provider(receipt.clone())))
		.with_capability_broker();
	let args = json!({"query":"safe"});
	let decision = pipeline.authorize(&action(), Some(&args)).unwrap();
	assert_eq!(decision.approval.as_ref(), Some(&receipt));
	assert_eq!(decision.expires_at, Some(receipt.expires_at));
	assert_eq!(
		sink.events()[0].authorization_context.approval.as_ref(),
		Some(&receipt)
	);
	let capability = pipeline
		.authorize_tool(&action(), &args, Duration::seconds(30))
		.unwrap();
	assert!(capability.expires_at <= receipt.expires_at);
}

#[test]
fn approval_expiring_during_later_control_cannot_authorize() {
	struct Expire;
	impl SecurityControl for Expire {
		fn id(&self) -> &str {
			"expiry"
		}
		fn check(
			&self,
			_: &ActionRequest,
			_: Option<&serde_json::Value>,
		) -> Result<Option<security_types::ApprovalGrant>, ControlDenial> {
			Ok(Some(security_types::ApprovalGrant {
				approval_id: "expired".into(),
				expires_at: Utc::now() - Duration::seconds(1),
			}))
		}
	}
	let sink = InMemoryAuditSink::default();
	let pipeline = SecurityPipeline::new(PolicyAuthorizer::new(config().policies), &sink)
		.add_action_control(Expire);
	assert!(pipeline.authorize(&action(), Some(&json!({}))).is_err());
	assert_eq!(sink.events().last().unwrap().decision, DecisionEffect::Deny);
}
