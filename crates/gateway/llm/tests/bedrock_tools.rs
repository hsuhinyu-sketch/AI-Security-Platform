use gateway_llm::provider::bedrock::BedrockToolNameMap;
use serde_json::{Value, json};

#[test]
fn tool_names_match_original_hash_collision_and_restore_golden() {
	let fixture: Value =
		serde_json::from_str(include_str!("fixtures/bedrock-state-golden.json")).unwrap();
	assert_eq!(fixture["maps"].as_array().unwrap().len(), 5);
	for c in fixture["maps"].as_array().unwrap() {
		let mut map = BedrockToolNameMap::default();
		let mut registrations = Vec::new();
		for name in c["names"].as_array().unwrap() {
			let name = name.as_str().unwrap();
			let mapped = map.register(name);
			assert!(
				mapped.len() <= 64
					&& mapped
						.bytes()
						.all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
			);
			let restored = map.restore(&mapped);
			assert_eq!(restored, if name.is_empty() { "tool" } else { name });
			registrations.push(json!({"mapped":mapped,"restored":restored,"empty":map.is_empty()}));
		}
		let probes: Vec<_> = c["probes"]
			.as_array()
			.unwrap()
			.iter()
			.map(|n| map.restore(n.as_str().unwrap()))
			.collect();
		assert_eq!(
			json!({"registrations":registrations,"probes":probes}),
			c["expected"]
		);
	}
}

#[test]
fn concurrent_requests_reverse_only_their_own_aliases_and_drop_clears_ownership() {
	let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
	let threads: Vec<_> = (0..8)
		.map(|n| {
			let barrier = barrier.clone();
			std::thread::spawn(move || {
				let mut map = BedrockToolNameMap::default();
				let original = if n % 2 == 0 {
					"danger.tool"
				} else {
					"danger/tool"
				};
				let alias = map.register(original);
				barrier.wait();
				assert_eq!(alias, "danger_tool");
				assert_eq!(map.restore(&alias), original);
				let occupied = map.register("danger_tool");
				assert_ne!(occupied, alias);
				assert_eq!(map.restore(&occupied), "danger_tool");
				assert_eq!(map.restore(&alias), original);
				drop(map);
				let fresh = BedrockToolNameMap::default();
				assert!(fresh.is_empty());
				assert_eq!(fresh.restore(&alias), alias);
			})
		})
		.collect();
	for thread in threads {
		thread.join().unwrap();
	}
}
