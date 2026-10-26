use super::*;
use crate::{CacheTokenConvention::*, LLMResponse};
use serde_json::json;

fn snapshot(model: serde_json::Value) -> CatalogSnapshot {
	CatalogSnapshot::from_catalogs([from_json(
		&json!({
				"providers":{"openai":{"models":{"local":model}}}
		})
		.to_string(),
	)
	.unwrap()])
}

#[test]
fn validates_money_and_strict_tiers_without_changing_wire_names() {
	for bad in ["-0.01", "0.0000001", "NaN", ""] {
		assert!(Money::parse(bad).is_err(), "{bad}");
	}
	assert_eq!(Money::parse("0.000001").unwrap().0, Decimal::new(1, 6));
	let wire = json!({"rates":{"input":"1.234567","cacheRead":"0"},
        "tiers":[{"contextOver":10,"rates":{"output":"2"}}]});
	let model: Model = serde_json::from_value(wire.clone()).unwrap();
	assert_eq!(serde_json::to_value(model).unwrap(), wire);
	assert!(serde_json::from_value::<Rates>(json!({"input":1})).is_err());
	assert!(serde_json::from_value::<Model>(json!({"unexpected":true})).is_err());
	for thresholds in [[10, 10], [20, 10]] {
		assert!(
			from_json(
				&json!({"providers":{"p":{"models":{"m":{
						"tiers": thresholds.map(|n| json!({"contextOver":n,"rates":{}}))
				}}}}})
				.to_string()
			)
			.is_err()
		);
	}
}

#[test]
fn later_sources_replace_whole_models_and_listing_is_sorted() {
	let first = from_json(r#"{"providers":{"p":{"models":{"z":{"rates":{"input":"9"},"tiers":[{"contextOver":1,"rates":{"input":"20"}}]},"a":{}}}}}"#).unwrap();
	let second = from_json(
		r#"{"providers":{"p":{"models":{"z":{"rates":{"output":"2"}}}},"q":{"models":{"b":{}}}}}"#,
	)
	.unwrap();
	let merged = first.override_with(second);
	assert_eq!(merged.resolve("p", "z").unwrap().tiers.len(), 0);
	assert!(merged.resolve("p", "z").unwrap().rates.input.is_none());
	assert!(merged.resolve("other", "z").is_none());
	let listing = CatalogSnapshot::from_catalogs([merged]).list_models();
	assert_eq!(
		serde_json::to_value(listing).unwrap(),
		json!({"loaded":true,
        "providers":[{"provider":"p","models":["a","z"]},{"provider":"q","models":["b"]}]})
	);
	assert!(!CatalogSnapshot::empty().list_models().loaded);
	// Diagnostics report availability without dumping the entire pricing catalog.
	assert_eq!(
		format!("{:?}", CatalogSnapshot::empty()),
		"CatalogSnapshot { loaded: false }"
	);
	assert_eq!(
		format!("{:?}", CatalogSnapshot::from_catalogs([])),
		"CatalogSnapshot { loaded: true }"
	);
	assert!(CatalogSnapshot::from_catalogs([]).list_models().loaded);
}

#[test]
fn absent_unpriced_and_exact_zero_remain_distinct() {
	let response = LLMResponse::default();
	assert_eq!(
		CatalogSnapshot::empty().project("openai", "local", &response, InputIncludesCache),
		CostProjection::NoCatalog
	);
	assert_eq!(
		snapshot(json!({})).project("other", "local", &response, InputIncludesCache),
		CostProjection::Missing
	);
	assert!(matches!(
		snapshot(json!({})).project("openai", "local", &response, InputIncludesCache),
		CostProjection::Unpriced { .. }
	));
	let CostProjection::Exact { cost, .. } = snapshot(json!({"rates":{"input":"0"}})).project(
		"openai",
		"local",
		&response,
		InputIncludesCache,
	) else {
		panic!("zero rate is priced")
	};
	assert_eq!(cost.total(), Decimal::ZERO);
}

#[test]
fn exact_accounting_keeps_fractional_costs_below_rate_precision() {
	let response = LLMResponse {
		input_tokens: Some(1),
		output_tokens: Some(3),
		..Default::default()
	};
	let CostProjection::Exact { cost, .. } = snapshot(
		json!({"rates":{"input":"0.000001","output":"1.234567"}}),
	)
	.project("openai", "local", &response, InputIncludesCache) else {
		panic!()
	};
	assert_eq!(cost.input, Decimal::from_str("0.000000000001").unwrap());
	assert_eq!(cost.output, Decimal::from_str("0.000003703701").unwrap());
	assert_eq!(cost.total(), Decimal::from_str("0.000003703702").unwrap());
}

#[test]
fn cache_conventions_price_reads_once_with_or_without_dedicated_rate() {
	for convention in [InputIncludesCache, InputExcludesCache] {
		let response = LLMResponse {
			input_tokens: Some(if convention == InputIncludesCache {
				100
			} else {
				60
			}),
			cached_input_tokens: Some(40),
			..Default::default()
		};
		for dedicated in [false, true] {
			let rates = if dedicated {
				json!({"input":"2","cacheRead":"0.5"})
			} else {
				json!({"input":"2"})
			};
			let CostProjection::Exact {
				cost,
				context_tokens,
				usage,
				..
			} = snapshot(json!({"rates":rates})).project("openai", "local", &response, convention)
			else {
				panic!()
			};
			assert_eq!(context_tokens, 100);
			assert_eq!(usage.context_tokens(), 100);
			assert_eq!(usage.cache_read, if dedicated { 40 } else { 0 });
			assert_eq!(
				cost.total(),
				Decimal::from_str(if dedicated { "0.00014" } else { "0.0002" }).unwrap()
			);
		}
	}
}

#[test]
fn tier_threshold_is_strict_and_cache_repricing_does_not_reselect_it() {
	let model = json!({"rates":{"input":"2","output":"3","cacheRead":"1"},"tiers":[
			{"contextOver":100,"rates":{"input":"4","cacheRead":"0"}},
			{"contextOver":200,"rates":{"input":"8"}}
	]});
	for (tokens, expected) in [(100, "2"), (101, "4"), (200, "4"), (201, "8")] {
		let response = LLMResponse {
			input_tokens: Some(tokens),
			cached_input_tokens: Some(40),
			..Default::default()
		};
		let CostProjection::Exact {
			rates,
			context_tokens,
			..
		} = snapshot(model.clone()).project("openai", "local", &response, InputIncludesCache)
		else {
			panic!()
		};
		assert_eq!(context_tokens, tokens);
		assert_eq!(rates.input.unwrap().to_string(), expected);
		assert_eq!(rates.output.unwrap().to_string(), "3");
		// Only the selected tier overlays base rates, not preceding tiers.
		assert_eq!(
			rates.cache_read.unwrap().to_string(),
			if tokens > 100 && tokens <= 200 {
				"0"
			} else {
				"1"
			}
		);
	}
	let response = LLMResponse {
		input_tokens: Some(80),
		cached_input_tokens: Some(40),
		..Default::default()
	};
	let CostProjection::Exact {
		cost,
		context_tokens,
		usage,
		..
	} = snapshot(json!({"rates":{"input":"2"},"tiers":[{"contextOver":100,"rates":{"input":"4"}}]}))
		.project("openai", "local", &response, InputExcludesCache)
	else {
		panic!()
	};
	assert_eq!(context_tokens, 120);
	assert_eq!(usage.input, 120);
	assert_eq!(cost.total(), Decimal::from_str("0.00048").unwrap());
}

#[test]
fn modality_subsets_are_not_double_billed_and_fall_back_to_text_rates() {
	let response = LLMResponse {
		input_tokens: Some(100),
		input_audio_tokens: Some(20),
		output_tokens: Some(100),
		output_audio_tokens: Some(10),
		reasoning_tokens: Some(30),
		..Default::default()
	};
	for dedicated in [false, true] {
		let rates = if dedicated {
			json!({"input":"2","output":"4","inputAudio":"3","outputAudio":"5","reasoning":"6"})
		} else {
			json!({"input":"2","output":"4"})
		};
		let CostProjection::Exact {
			cost,
			usage,
			context_tokens,
			..
		} = snapshot(json!({"rates":rates})).project("openai", "local", &response, InputIncludesCache)
		else {
			panic!()
		};
		assert_eq!(
			(
				usage.input,
				usage.input_audio,
				usage.output,
				usage.output_audio,
				usage.reasoning
			),
			(80, 20, 60, 10, 30)
		);
		assert_eq!(context_tokens, 100);
		assert_eq!(
			cost.total(),
			Decimal::from_str(if dedicated { "0.00069" } else { "0.0006" }).unwrap()
		);
	}
}

#[test]
fn usage_saturates_inconsistent_subset_counts_and_large_context_totals() {
	let response = LLMResponse {
		input_tokens: Some(2),
		input_audio_tokens: Some(3),
		cached_input_tokens: Some(4),
		output_tokens: Some(1),
		reasoning_tokens: Some(2),
		output_audio_tokens: Some(3),
		..Default::default()
	};
	let CostProjection::Exact { usage, .. } = snapshot(json!({"rates":{"input":"1"}})).project(
		"openai",
		"local",
		&response,
		InputIncludesCache,
	) else {
		panic!()
	};
	assert_eq!((usage.input, usage.output), (0, 0));
	let usage = Usage {
		input: u64::MAX,
		cache_read: 1,
		cache_write: 2,
		input_audio: 3,
		..Default::default()
	};
	assert_eq!(usage.context_tokens(), u64::MAX);
}

#[cfg(feature = "schema")]
#[test]
fn catalog_schema_preserves_camel_case_and_string_money() {
	let schema = serde_json::to_value(schemars::schema_for!(Catalog)).unwrap();
	assert_eq!(schema["$defs"]["Money"]["type"], "string");
	assert!(
		schema["$defs"]["Rates"]["properties"]
			.get("cacheRead")
			.is_some()
	);
	assert!(
		schema["$defs"]["Tier"]["properties"]
			.get("contextOver")
			.is_some()
	);
	assert_eq!(schema["$defs"]["Model"]["additionalProperties"], false);
}
