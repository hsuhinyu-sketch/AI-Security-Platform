use std::io::Write;

use ai_security_platform_runtime::cel;
use anyhow::Result;
use schemars::JsonSchema;

pub fn generate_schema() -> Result<()> {
	struct SchemaDoc {
		file: &'static str,
		schema_json: String,
	}

	let xtask_path = std::env::var("CARGO_MANIFEST_DIR")?;
	let schemas = vec![
		SchemaDoc {
			file: "config.json",
			schema_json: make::<ai_security_platform_runtime::types::local::LocalConfig>(false)?,
		},
		SchemaDoc {
			file: "cel.json",
			schema_json: make::<cel::ExecutorSerde>(true)?,
		},
		SchemaDoc {
			file: "admin.json",
			schema_json: make_with_contract::<ai_security_platform_runtime::store::StoresDump>(
				false,
				schemars::generate::Contract::Serialize,
			)?,
		},
	];
	for schema in &schemas {
		let rule_path = format!("{xtask_path}/../../schema/{}", schema.file);
		let mut file = fs_err::File::create(rule_path)?;
		file.write_all(schema.schema_json.as_bytes())?;
	}
	Ok(())
}

pub fn make<T: JsonSchema>(inline_subschemas: bool) -> anyhow::Result<String> {
	make_with_contract::<T>(inline_subschemas, schemars::generate::Contract::Deserialize)
}

pub fn make_with_contract<T: JsonSchema>(
	inline_subschemas: bool,
	contract: schemars::generate::Contract,
) -> anyhow::Result<String> {
	let settings = schemars::generate::SchemaSettings::default().with(|s| {
		s.inline_subschemas = inline_subschemas;
		s.contract = contract;
	});
	let gens = schemars::SchemaGenerator::new(settings);
	let schema = gens.into_root_schema_for::<T>();
	Ok(serde_json::to_string_pretty(&schema)?)
}
