use security_pii::*;
use std::sync::{
	Arc,
	atomic::{AtomicUsize, Ordering},
};

fn config() -> PiiConfig {
	serde_json::from_str("{}").unwrap()
}
fn finding(entity: &str, start: usize, end: usize) -> PiiFinding {
	PiiFinding {
		entity_type: entity.into(),
		start,
		end,
		confidence: 0.9,
		source: "test".into(),
	}
}
struct Fixed(Vec<PiiFinding>);
#[async_trait::async_trait]
impl PiiDetector for Fixed {
	async fn detect(&self, _: &str, _: &str) -> Result<Vec<PiiFinding>, PiiError> {
		Ok(self.0.clone())
	}
}
struct Broken(Arc<AtomicUsize>);
#[async_trait::async_trait]
impl PiiDetector for Broken {
	async fn detect(&self, _: &str, _: &str) -> Result<Vec<PiiFinding>, PiiError> {
		self.0.fetch_add(1, Ordering::SeqCst);
		Err(PiiError::Unavailable)
	}
}

#[tokio::test]
async fn native_mixed_text_and_validated_phone_ip() {
	let engine = config().build().unwrap().unwrap();
	let out = engine
		.inspect("张三联系alice@example.com，电话13800138000，地址192.0.2.1或2001:db8::1")
		.await
		.unwrap();
	assert_eq!(
		out.text,
		"张三联系[EMAIL_ADDRESS]，电话[PHONE_NUMBER]，地址[IP_ADDRESS]或[IP_ADDRESS]"
	);
	assert!(out.modified && !out.blocked);
	assert_eq!(out.findings.len(), 4);
	assert_eq!(
		engine.inspect("13800138000 192.0.2.1.").await.unwrap().text,
		"[PHONE_NUMBER] [IP_ADDRESS]."
	);
	assert_eq!(
		engine
			.inspect("错误IP 999.1.2.3，数字1234，普通文字")
			.await
			.unwrap()
			.text,
		"错误IP 999.1.2.3，数字1234，普通文字"
	);
}
#[test]
fn unicode_offsets_are_scalars_and_ranges_must_be_valid() {
	assert_eq!(character_range("甲😀a", 1, 2), Ok((3, 7)));
	for (a, b) in [(0, 0), (2, 1), (0, 4)] {
		assert_eq!(
			character_range("甲😀a", a, b),
			Err(PiiError::InvalidResponse)
		);
	}
}
#[tokio::test]
async fn invalid_findings_cannot_disclose_a_partially_checked_text() {
	for f in [
		finding("EMAIL_ADDRESS", 1, 4),
		finding("EMAIL_ADDRESS", 0, 999),
		finding("UNKNOWN", 0, 3),
		PiiFinding {
			confidence: f32::NAN,
			..finding("EMAIL_ADDRESS", 0, 3)
		},
	] {
		let engine = PiiEngine::with_detector(config(), Arc::new(Fixed(vec![f]))).unwrap();
		assert!(matches!(
			engine.inspect("甲😀abc").await,
			Err(PiiError::InvalidResponse)
		));
	}
}
#[tokio::test]
async fn duplicates_and_overlapping_conflicts_never_leave_sensitive_suffixes() {
	let mut cfg = config();
	cfg
		.policy
		.entities
		.insert("PHONE_NUMBER".into(), PiiAction::Mask);
	let spans = vec![
		finding("EMAIL_ADDRESS", 0, 5),
		finding("EMAIL_ADDRESS", 0, 5),
		finding("PHONE_NUMBER", 3, 8),
	];
	let engine = PiiEngine::with_detector(cfg.clone(), Arc::new(Fixed(spans.clone()))).unwrap();
	let out = engine.inspect("abcdefgh tail").await.unwrap();
	assert_eq!(out.text, "******** tail");
	assert_eq!(out.findings.len(), 2);
	cfg
		.policy
		.entities
		.insert("EMAIL_ADDRESS".into(), PiiAction::Redact);
	let engine = PiiEngine::with_detector(cfg, Arc::new(Fixed(spans))).unwrap();
	assert_eq!(engine.inspect("abcdefgh tail").await.unwrap().text, " tail");
}
#[tokio::test]
async fn block_and_detect_only_are_distinct_from_rewriting() {
	for action in [PiiAction::Block, PiiAction::DetectOnly] {
		let mut cfg = config();
		cfg
			.policy
			.entities
			.insert("EMAIL_ADDRESS".into(), action.clone());
		let out = cfg
			.build()
			.unwrap()
			.unwrap()
			.inspect("alice@example.com")
			.await
			.unwrap();
		if action == PiiAction::Block {
			assert!(out.blocked);
			assert!(out.text.is_empty());
		} else {
			assert!(!out.modified);
			assert_eq!(out.text, "alice@example.com");
		}
	}
}
#[tokio::test]
async fn observation_modes_preserve_text_and_report_failure_disabled_does_not_call_detector() {
	let count = Arc::new(AtomicUsize::new(0));
	for mode in [
		PiiMode::Disabled,
		PiiMode::Audit,
		PiiMode::Shadow,
		PiiMode::Enforce,
	] {
		let mut cfg = config();
		cfg.mode = mode;
		let engine = PiiEngine::with_detector(cfg, Arc::new(Broken(count.clone()))).unwrap();
		match engine.inspect("sensitive").await {
			Ok(out) => {
				assert_eq!(out.text, "sensitive");
				assert!(!out.modified);
				assert_eq!(out.detector_error.is_some(), mode != PiiMode::Disabled);
			},
			Err(e) => {
				assert_eq!(mode, PiiMode::Enforce);
				assert_eq!(e, PiiError::Unavailable);
			},
		}
	}
	assert_eq!(count.load(Ordering::SeqCst), 3);
	for mode in [PiiMode::Audit, PiiMode::Shadow] {
		let mut cfg = config();
		cfg.mode = mode;
		let out = cfg
			.build()
			.unwrap()
			.unwrap()
			.inspect("alice@example.com")
			.await
			.unwrap();
		assert_eq!(out.text, "alice@example.com");
		assert_eq!(out.findings.len(), 1);
	}
}
#[tokio::test]
async fn custom_entity_and_all_limits_are_enforced() {
	// An explicitly supplied detector can implement entities that are not native.
	// Backend capabilities belong in their factories, not the core contract.
	let mut external = config();
	external.policy.entities.clear();
	external.policy.entities.insert(
		"PERSON".into(),
		PiiAction::Replace {
			value: "[PERSON]".into(),
		},
	);
	let engine =
		PiiEngine::with_detector(external, Arc::new(Fixed(vec![finding("PERSON", 0, 4)]))).unwrap();
	assert_eq!(engine.inspect("Anne").await.unwrap().text, "[PERSON]");
	let mut cfg = config();
	cfg.policy.entities.clear();
	cfg
		.policy
		.entities
		.insert("EMPLOYEE_ID".into(), PiiAction::Redact);
	cfg
		.custom_rules
		.insert("EMPLOYEE_ID".into(), r"EMP-\d{4}".into());
	assert_eq!(
		cfg
			.build()
			.unwrap()
			.unwrap()
			.inspect("你好 EMP-1234 bye")
			.await
			.unwrap()
			.text,
		"你好  bye"
	);
	cfg.max_text_bytes = 2;
	assert!(matches!(
		cfg.build().unwrap().unwrap().inspect("你好").await,
		Err(PiiError::InputLimit)
	));
	let mut cfg = config();
	cfg.max_output_bytes = 1;
	assert!(matches!(
		cfg.build().unwrap().unwrap().inspect("a@example.com").await,
		Err(PiiError::OutputLimit)
	));
	cfg = config();
	cfg.max_findings = 1;
	assert!(matches!(
		cfg
			.build()
			.unwrap()
			.unwrap()
			.inspect("a@example.com b@example.com")
			.await,
		Err(PiiError::FindingLimit)
	));
	assert!(serde_json::from_str::<PiiConfig>(r#"{"failurePolicy":"allow"}"#).is_err());
	cfg = config();
	cfg
		.policy
		.entities
		.insert("PERSON".into(), PiiAction::Block);
	assert!(cfg.build().is_err());
}
#[cfg(not(feature = "presidio"))]
#[test]
fn missing_backend_is_rejected_and_disabled_backend_is_not_required() {
	let mut cfg = config();
	cfg.backend = DetectorBackend::Presidio;
	assert!(matches!(cfg.build(), Err(PiiError::NotCompiled)));
	cfg.enabled = false;
	assert!(cfg.build().unwrap().is_none());
}
