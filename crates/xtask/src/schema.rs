use std::path::Path;

use ai_security_platform_runtime::cel;
use anyhow::{Context, Result, bail};
use schemars::JsonSchema;

struct SchemaDoc {
	file: &'static str,
	schema_json: String,
}

pub fn generate_schema(check: bool) -> Result<()> {
	let xtask_path = env!("CARGO_MANIFEST_DIR");
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
	write_or_check_schemas(&Path::new(xtask_path).join("../../schema"), &schemas, check)
}

fn write_or_check_schemas(directory: &Path, schemas: &[SchemaDoc], check: bool) -> Result<()> {
	let mut stale = Vec::new();
	for schema in schemas {
		let path = directory.join(schema.file);
		if check {
			match fs_err::read(&path) {
				Ok(current) if current == schema.schema_json.as_bytes() => {},
				Ok(_) => stale.push(schema.file),
				Err(error) if error.kind() == std::io::ErrorKind::NotFound => stale.push(schema.file),
				Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
			}
		} else {
			fs_err::write(&path, &schema.schema_json)?;
		}
	}
	if !stale.is_empty() {
		bail!(
			"schema files are missing or out of date: {}. Run `cargo xtask schema` and include the generated changes.",
			stale.join(", ")
		);
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

#[cfg(test)]
#[path = "schema_tests.rs"]
mod tests;
