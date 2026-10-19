#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AwsBackendConfig {
	#[serde(flatten)]
	pub service: AwsService,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AwsService {
	AgentCore(crate::agentcore::AgentCoreConfig),
}

impl AwsBackendConfig {
	pub fn region(&self) -> &str {
		match &self.service {
			AwsService::AgentCore(c) => &c.region,
		}
	}

	pub fn service_name(&self) -> &'static str {
		match &self.service {
			AwsService::AgentCore(_) => "bedrock-agentcore",
		}
	}

	pub fn get_host(&self) -> String {
		match &self.service {
			AwsService::AgentCore(c) => c.get_host(),
		}
	}

	pub fn get_path(&self) -> String {
		match &self.service {
			AwsService::AgentCore(c) => c.get_path(),
		}
	}
}
