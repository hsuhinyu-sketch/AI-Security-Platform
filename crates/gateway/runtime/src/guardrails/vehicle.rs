#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Gear {
	Park,
	Reverse,
	Neutral,
	Drive,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SafetyMode {
	Normal,
	Reduced,
	Emergency,
	Factory,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Weather {
	Clear,
	Rain,
	Snow,
	Fog,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RoadType {
	Highway,
	Urban,
	Parking,
	Offroad,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Visibility {
	Good,
	Medium,
	Poor,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentInfo {
	pub weather: Weather,
	pub road_type: RoadType,
	pub visibility: Visibility,
}

impl Default for EnvironmentInfo {
	fn default() -> Self {
		Self {
			weather: Weather::Clear,
			road_type: RoadType::Urban,
			visibility: Visibility::Good,
		}
	}
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VehicleState {
	pub speed_kmh: f64,
	pub gear: Gear,
	pub autopilot_active: bool,
	pub passenger_present: bool,
	pub environment: EnvironmentInfo,
	pub safety_mode: SafetyMode,
}

impl Default for VehicleState {
	fn default() -> Self {
		Self {
			speed_kmh: 0.0,
			gear: Gear::Park,
			autopilot_active: false,
			passenger_present: false,
			environment: EnvironmentInfo::default(),
			safety_mode: SafetyMode::Normal,
		}
	}
}

impl VehicleState {
	pub fn parked() -> Self {
		Self::default()
	}

	pub fn driving(speed_kmh: f64) -> Self {
		Self {
			speed_kmh,
			gear: Gear::Drive,
			..Default::default()
		}
	}
}

/// Interface for supplying current vehicle state to vehicle guardrails.
///
/// The gateway core currently uses a fixed `VehicleState` value. Actual vehicle
/// middleware can implement this trait later without changing the guardrails
/// evaluation API.
#[async_trait::async_trait]
pub trait VehicleStateProvider: Send + Sync {
	async fn current_state(&self) -> VehicleState;
}
