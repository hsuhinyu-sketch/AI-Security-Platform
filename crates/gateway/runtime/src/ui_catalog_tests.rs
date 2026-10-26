use super::*;
use crate::llm::cost::CatalogService;

#[tokio::test]
async fn catalog_management_routes_preserve_json_and_static_refresh_rejection() {
	let mut config = crate::config::parse_config("{}".into(), None).unwrap();
	config.local_config = Some(ConfigSource::Static("{}".into()));
	let config = Arc::new(config);
	let client = crate::client::Client::new(&config.dns, None, config.backend.clone(), None);
	let resources = crate::resource_manager::ResourceManager::new(client).unwrap();
	let service = CatalogService::new(vec![crate::ModelCatalogSource::Inline {
		inline: serde_json::json!({"providers":{"openai":{"models":{"local":{
			"rates":{"input":"2","output":"4"}
		}}}}})
		.to_string(),
	}])
	.unwrap();
	tokio::time::timeout(Duration::from_secs(5), async {
		while !service.reader().list_models().loaded {
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
	let app = router(config, service.admin(), resources);
	let response = app
		.clone()
		.oneshot(
			http::Request::builder()
				.uri("/api/costs/models")
				.body(axum::body::Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	assert_eq!(response.status(), StatusCode::OK);
	let body = axum::body::to_bytes(response.into_body(), 8192)
		.await
		.unwrap();
	assert_eq!(
		serde_json::from_slice::<Value>(&body).unwrap(),
		serde_json::json!({
			"loaded":true,"providers":[{"provider":"openai","models":["local"]}]
		})
	);
	let response = app
		.clone()
		.oneshot(
			http::Request::builder()
				.method("POST")
				.uri("/api/costs/refresh-base")
				.body(axum::body::Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	assert!(!response.status().is_success());
	let body = axum::body::to_bytes(response.into_body(), 8192)
		.await
		.unwrap();
	assert!(String::from_utf8_lossy(&body).contains("Cannot refresh base costs for static config"));
	drop(service);
	let response = app
		.oneshot(
			http::Request::builder()
				.uri("/api/costs/models")
				.body(axum::body::Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	assert!(!response.status().is_success());
	let body = axum::body::to_bytes(response.into_body(), 8192)
		.await
		.unwrap();
	assert!(String::from_utf8_lossy(&body).contains("model catalog service is closed"));
}
