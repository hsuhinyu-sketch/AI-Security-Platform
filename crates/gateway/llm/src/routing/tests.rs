use super::*;
use rand::{Rng, TryRng};
use std::convert::Infallible;

// Deterministic algorithm input, not a production random source.
#[derive(Clone)]
struct Words(u64);
impl TryRng for Words {
	type Error = Infallible;
	fn try_next_u64(&mut self) -> Result<u64, Infallible> {
		self.0 = self
			.0
			.wrapping_mul(6364136223846793005)
			.wrapping_add(1442695040888963407);
		Ok(self.0)
	}
	fn try_next_u32(&mut self) -> Result<u32, Infallible> {
		Ok((self.try_next_u64()? >> 32) as u32)
	}
	fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
		for chunk in dest.chunks_mut(8) {
			chunk.copy_from_slice(&self.try_next_u64()?.to_le_bytes()[..chunk.len()]);
		}
		Ok(())
	}
}
fn table(routing: VirtualModelRouting) -> RoutingTable {
	RoutingTable::new(
		vec![
			ModelRoute {
				name: "internal".into(),
				visibility: ModelVisibility::Internal,
			},
			ModelRoute {
				name: "prod/*".into(),
				visibility: ModelVisibility::Public,
			},
			ModelRoute {
				name: "prod/*".into(),
				visibility: ModelVisibility::Public,
			},
		],
		vec![VirtualModelRoute {
			name: "alias".into(),
			routing,
		}],
	)
}
fn conditional() -> VirtualModelRouting {
	VirtualModelRouting::Conditional(vec![
		ConditionalTarget {
			model: "first".into(),
			has_condition: true,
		},
		ConditionalTarget {
			model: "fallback".into(),
			has_condition: false,
		},
		ConditionalTarget {
			model: "unreachable".into(),
			has_condition: true,
		},
	])
}
#[test]
fn ordered_concrete_selection_short_circuits_host_predicates() {
	let t = table(conditional());
	let mut visited = vec![];
	let id = t
		.resolve_concrete("prod/model", false, |id| {
			let i = t.model_index(id).unwrap();
			visited.push(i);
			i == 2
		})
		.unwrap();
	assert_eq!(t.model_index(id), Some(2));
	assert_eq!(visited, vec![1, 2]);
	assert!(
		t.resolve_concrete("internal", false, |_| panic!(
			"internal route is not a public candidate"
		))
		.is_none()
	);
	assert_eq!(
		t.model_index(t.resolve_concrete("internal", true, |_| true).unwrap()),
		Some(0)
	);
	assert!(
		t.resolve_concrete("absent", true, |_| panic!("no matching name"))
			.is_none()
	);
}
#[test]
fn conditional_selection_is_lazy_and_never_initializes_randomness() {
	let t = table(conditional());
	let id = t.virtual_model("alias").unwrap();
	let mut visited = vec![];
	let selected = t
		.select_virtual::<Words>(
			id,
			|i| {
				visited.push(i);
				false
			},
			|| panic!("not weighted"),
		)
		.unwrap();
	assert_eq!(selected, VirtualTarget::Model("fallback"));
	assert_eq!(visited, vec![0]);
	let selected = t
		.select_virtual::<Words>(
			id,
			|i| {
				assert_eq!(i, 0);
				true
			},
			|| panic!(),
		)
		.unwrap();
	assert_eq!(selected, VirtualTarget::Model("first"));
}
#[test]
fn failover_is_a_host_handoff_and_empty_conditions_are_errors() {
	let t = table(VirtualModelRouting::Failover);
	assert_eq!(
		t.select_virtual::<Words>(t.virtual_model("alias").unwrap(), |_| panic!(), || panic!())
			.unwrap(),
		VirtualTarget::Failover
	);
	let t = table(VirtualModelRouting::Conditional(vec![]));
	assert!(matches!(
		t.select_virtual::<Words>(t.virtual_model("alias").unwrap(), |_| panic!(), || panic!()),
		Err(SelectionError::NoMatchingTarget)
	));
}
#[test]
fn weighted_draws_and_rng_advancement_match_existing_slice_algorithm() {
	let targets = vec![
		WeightedTarget {
			model: "never".into(),
			weight: 0,
		},
		WeightedTarget {
			model: "one".into(),
			weight: 1,
		},
		WeightedTarget {
			model: "three".into(),
			weight: 3,
		},
	];
	let t = table(VirtualModelRouting::Weighted(targets.clone()));
	let id = t.virtual_model("alias").unwrap();
	let mut old = Words(123);
	let mut new = old.clone();
	for _ in 0..256 {
		let expected = targets.choose_weighted(&mut old, |t| t.weight).unwrap();
		assert_eq!(
			t.select_virtual(id, |_| panic!(), || &mut new).unwrap(),
			VirtualTarget::Model(&expected.model)
		);
		assert_eq!(Rng::next_u64(&mut old), Rng::next_u64(&mut new));
	}
}
#[test]
fn invalid_weights_fail_without_fallback_or_conditional_evaluation() {
	for weights in [vec![], vec![0, 0], vec![usize::MAX, 1]] {
		let t = table(VirtualModelRouting::Weighted(
			weights
				.into_iter()
				.map(|weight| WeightedTarget {
					model: "x".into(),
					weight,
				})
				.collect(),
		));
		assert!(matches!(
			t.select_virtual(t.virtual_model("alias").unwrap(), |_| panic!(), || Words(1)),
			Err(SelectionError::InvalidWeights(_))
		));
	}
}
#[test]
fn identifiers_reject_other_snapshots_and_cloned_tables() {
	let first = table(conditional());
	let second = first.clone();
	let (id, _) = first.models().next().unwrap();
	let virtual_id = first.virtual_model("alias").unwrap();
	assert_eq!(second.model_index(id), None);
	assert_eq!(second.virtual_model_index(virtual_id), None);
	assert!(matches!(
		second.select_virtual::<Words>(virtual_id, |_| panic!(), || panic!()),
		Err(SelectionError::ForeignSnapshot)
	));
}
#[test]
fn listing_filters_public_concrete_models_and_preserves_public_aliases() {
	let t = table(conditional());
	let mut checked = vec![];
	assert_eq!(
		t.listed_models(|id| {
			let i = t.model_index(id).unwrap();
			checked.push(i);
			i == 2
		}),
		vec!["prod/*", "alias"]
	);
	assert_eq!(checked, vec![1, 2]);
}
#[test]
fn patterns_and_configuration_order_preserve_existing_rules() {
	for (pattern, name, expected) in [
		("*", "", true),
		("prod/*", "prod/a", true),
		("*suffix", "a-suffix", true),
		("exact", "other", false),
		("*a*", "cat", false),
	] {
		assert_eq!(model_name_matches(pattern, name), expected);
	}
	for pattern in ["*", "exact", "prefix*", "*suffix", ""] {
		validate_model_pattern(pattern).unwrap();
	}
	for pattern in ["*x*", "x*y", "**"] {
		assert!(validate_model_pattern(pattern).is_err());
	}
	assert_eq!(
		ordered_model_indices(["*", "ab*", "ab", "z*", "*ab"]),
		vec![1, 2, 4, 3, 0]
	);
}
