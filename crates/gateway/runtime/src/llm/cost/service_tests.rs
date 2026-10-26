use super::super::{Breakdown, CostLookupStatus, lifecycle::load_sources};
use super::*;
use crate::llm::{CacheTokenConvention, InputFormat, LLMRequest, LLMResponse};
use rust_decimal::Decimal;
use std::time::Duration;

fn catalog(rate: &str) -> super::super::Catalog {
	serde_json::from_value(
		serde_json::json!({"providers":{"openai":{"models":{"local":{
			"rates":{"input":rate,"output":"4"}
		}}}}}),
	)
	.unwrap()
}

fn info() -> LLMInfo {
	LLMInfo::new(
		LLMRequest {
			input_tokens: None,
			input_format: InputFormat::Completions,
			native_format: None,
			cache_convention: CacheTokenConvention::InputIncludesCache,
			request_model: "local".into(),
			provider: "openai".into(),
			streaming: false,
			params: Default::default(),
			prompt: None,
			provider_state: None,
		},
		LLMResponse {
			input_tokens: Some(1_000_000),
			output_tokens: Some(0),
			..Default::default()
		},
	)
}

#[tokio::test]
async fn readers_share_updates_and_preserve_cost_projection() {
	fn send_sync<T: Send + Sync>() {}
	send_sync::<CatalogReader>();
	send_sync::<CatalogAdmin>();
	send_sync::<CatalogService>();
	let service = CatalogService::from_catalog(ModelCatalog::empty());
	service
		.catalog
		.replace(CatalogSnapshot::from_catalogs([catalog("2")]))
		.unwrap();
	let reader = service.reader();
	let cloned = reader.clone();
	let old = reader.snapshot();
	let priced = reader.project(&info());
	assert_eq!(priced.status, super::super::CostLookupStatus::Exact);
	assert_eq!(priced.cost.unwrap().total().to_string(), "2");
	assert_eq!(
		serde_json::to_value(cloned.project(&info()).cost).unwrap(),
		serde_json::to_value(service.catalog.project(&info()).cost).unwrap()
	);
	service
		.catalog
		.replace(CatalogSnapshot::from_catalogs([catalog("3")]))
		.unwrap();
	assert_eq!(
		reader.project(&info()).cost.unwrap().total().to_string(),
		"3"
	);
	assert!(!Arc::ptr_eq(&old, &cloned.snapshot()));
	let admin = service.admin();
	assert!(admin.list_models().unwrap().loaded);
	drop(service);
	assert!(admin.list_models().is_err());
	assert!(
		admin
			.refresh_base(std::path::Path::new("/unused-after-close"))
			.await
			.is_err()
	);
	// A final in-flight log can still price usage; it cannot restart the service.
	assert_eq!(
		cloned.project(&info()).cost.unwrap().total().to_string(),
		"3"
	);
}

#[tokio::test]
async fn file_watcher_updates_readers_and_is_aborted_on_host_drop() {
	let dir = std::env::temp_dir().join(format!("aisp-catalog-{}", uuid::Uuid::new_v4()));
	std::fs::create_dir(&dir).unwrap();
	struct Directory(std::path::PathBuf);
	impl Drop for Directory {
		fn drop(&mut self) {
			let _ = std::fs::remove_dir_all(&self.0);
		}
	}
	let _directory = Directory(dir.clone());
	let path = dir.join("catalog.json");
	std::fs::write(&path, serde_json::to_vec(&catalog("2")).unwrap()).unwrap();
	let service = CatalogService::new(vec![ModelCatalogSource::File { file: path.clone() }]).unwrap();
	let reader = service.reader();
	async fn wait_rate(reader: &CatalogReader, expected: &str) {
		tokio::time::timeout(Duration::from_secs(10), async {
			loop {
				if reader
					.project(&info())
					.cost
					.is_some_and(|cost| cost.total().to_string() == expected)
				{
					break;
				}
				tokio::time::sleep(Duration::from_millis(20)).await;
			}
		})
		.await
		.unwrap();
	}
	wait_rate(&reader, "2").await;
	let good = reader.snapshot();
	std::fs::write(&path, b"{ invalid catalog").unwrap();
	let until = tokio::time::Instant::now() + Duration::from_secs(1);
	while tokio::time::Instant::now() < until {
		assert!(
			Arc::ptr_eq(&good, &reader.snapshot()),
			"invalid reload replaced the last valid snapshot"
		);
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	std::fs::write(&path, serde_json::to_vec(&catalog("5")).unwrap()).unwrap();
	wait_rate(&reader, "5").await;
	let tasks = service.catalog.tasks.lock().unwrap().clone();
	assert!(tasks.iter().any(|task| !task.is_finished()));
	let weak = Arc::downgrade(&service.catalog);
	drop(service);
	tokio::time::timeout(Duration::from_secs(5), async {
		while tasks.iter().any(|task| !task.is_finished()) {
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
	assert_eq!(
		reader.project(&info()).cost.unwrap().total().to_string(),
		"5"
	);
	drop(reader);
	assert!(weak.upgrade().is_none());
}

#[test]
fn provider_model_precedes_request_model_and_only_missing_entries_fall_back() {
	let catalog = ModelCatalog::empty();
	catalog
		.replace(CatalogSnapshot::from_catalogs([serde_json::from_value(
			serde_json::json!({"providers":{"openai":{"models":{
					"local":{"rates":{"input":"2"}},
					"resolved":{"rates":{"input":"7"}},
					"unpriced":{}
			}}}}),
		)
		.unwrap()]))
		.unwrap();
	let mut request = info();
	request.response.provider_model = Some("resolved".into());
	assert_eq!(
		catalog.project(&request).cost.unwrap().total(),
		Decimal::from(7)
	);
	request.response.provider_model = Some("absent".into());
	assert_eq!(
		catalog.project(&request).cost.unwrap().total(),
		Decimal::from(2)
	);
	request.response.provider_model = Some("unpriced".into());
	let unpriced = catalog.project(&request);
	assert_eq!(unpriced.status, CostLookupStatus::Unpriced);
	assert!(unpriced.cost.is_none());
	assert!(unpriced.cost_rates.is_none());
	request.request.provider = "other-tenant-provider".into();
	assert_eq!(catalog.project(&request).status, CostLookupStatus::Missing);
	assert_eq!(
		ModelCatalog::empty().project(&request).status,
		CostLookupStatus::NoCatalog
	);
}

#[test]
fn decimal_breakdown_retains_json_and_lazy_cel_fields() {
	use ::cel::types::dynamic::DynamicType;
	let snapshot = CatalogSnapshot::from_catalogs([serde_json::from_value(
		serde_json::json!({"providers":{"openai":{"models":{"local":{
				"rates":{"input":"1","output":"2","cacheRead":"3","cacheWrite":"4",
						"reasoning":"5","inputAudio":"6","outputAudio":"7"}
		}}}}}),
	)
	.unwrap()]);
	let response = LLMResponse {
		input_tokens: Some(3_000_000),
		cached_input_tokens: Some(1_000_000),
		cache_creation_input_tokens: Some(1_000_000),
		input_audio_tokens: Some(1_000_000),
		output_tokens: Some(3_000_000),
		reasoning_tokens: Some(1_000_000),
		output_audio_tokens: Some(1_000_000),
		..Default::default()
	};
	let projection = snapshot.project(
		"openai",
		"local",
		&response,
		CacheTokenConvention::InputIncludesCache,
	);
	let cost = projection.cost.unwrap();
	let wire = serde_json::json!({"total":28.0,"input":1.0,"output":2.0,
        "cacheRead":3.0,"cacheWrite":4.0,"reasoning":5.0,"inputAudio":6.0,"outputAudio":7.0});
	assert_eq!(serde_json::to_value(&cost).unwrap(), wire);
	let roundtrip: Breakdown = serde_json::from_value(wire.clone()).unwrap();
	assert_eq!(roundtrip, cost);
	assert_eq!(cost.materialize(), roundtrip.materialize());
	for (key, expected) in wire.as_object().unwrap() {
		assert_eq!(
			cost.field(key),
			Some(::cel::Value::from(expected.as_f64().unwrap()))
		);
	}
	assert!(cost.field("cache_read").is_none());
	assert!(cost.field("unknown").is_none());
	assert_eq!(
		serde_json::to_value(projection.cost_rates).unwrap(),
		serde_json::json!({
				"input":1.0,"output":2.0,"cacheRead":3.0,"cacheWrite":4.0,
				"reasoning":5.0,"inputAudio":6.0,"outputAudio":7.0
		})
	);
}

#[test]
fn shutdown_serializes_with_concurrent_publication_and_preserves_old_readers() {
	use std::sync::Barrier;
	let service = CatalogService::from_catalog(ModelCatalog::empty());
	service
		.catalog
		.replace(CatalogSnapshot::from_catalogs([catalog("2")]))
		.unwrap();
	let reader = service.reader();
	let old = reader.snapshot();
	let barrier = Arc::new(Barrier::new(9));
	let writers: Vec<_> = (0..8)
		.map(|_| {
			let owner = service.catalog.clone();
			let barrier = barrier.clone();
			std::thread::spawn(move || {
				barrier.wait();
				for _ in 0..32 {
					if owner
						.replace(CatalogSnapshot::from_catalogs([catalog("3")]))
						.is_err()
					{
						break;
					}
				}
			})
		})
		.collect();
	barrier.wait();
	drop(service);
	let closed = reader.snapshot();
	for writer in writers {
		writer.join().unwrap();
	}
	assert!(Arc::ptr_eq(&closed, &reader.snapshot()));
	assert!(
		reader
			.0
			.replace(CatalogSnapshot::from_catalogs([catalog("9")]))
			.is_err()
	);
	assert!(Arc::ptr_eq(&closed, &reader.snapshot()));
	assert_eq!(
		old
			.project(
				"openai",
				"local",
				&info().response,
				CacheTokenConvention::InputIncludesCache
			)
			.cost
			.unwrap()
			.total(),
		Decimal::from(2)
	);
}

#[tokio::test]
async fn invalid_or_unreadable_sources_do_not_produce_a_replacement_snapshot() {
	let owner = ModelCatalog::empty();
	owner
		.replace(CatalogSnapshot::from_catalogs([catalog("2")]))
		.unwrap();
	let good = owner.snapshot();
	for source in [
		ModelCatalogSource::Inline {
			inline: "{bad json".into(),
		},
		ModelCatalogSource::Inline {
			inline: serde_json::json!({"providers":{"p":{"models":{"m":{"rates":{"input":"-1"}}}}}})
				.to_string(),
		},
		ModelCatalogSource::File {
			file: std::env::temp_dir().join(format!("aisp-missing-{}", uuid::Uuid::new_v4())),
		},
		ModelCatalogSource::File {
			file: std::env::temp_dir(),
		},
	] {
		assert!(load_sources(&[source]).await.is_err());
		assert!(Arc::ptr_eq(&good, &owner.snapshot()));
	}
}
