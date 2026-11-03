use super::*;
use std::{
	fs::{self, File, FileTimes},
	path::PathBuf,
	time::{Duration, SystemTime, UNIX_EPOCH},
};

struct Directory(PathBuf);
impl Directory {
	fn new() -> Self {
		let path = std::env::temp_dir().join(format!(
			"aisp-schema-{}-{}",
			std::process::id(),
			SystemTime::now()
				.duration_since(UNIX_EPOCH)
				.unwrap()
				.as_nanos()
		));
		fs::create_dir(&path).unwrap();
		Self(path)
	}
}
impl Drop for Directory {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.0);
	}
}

#[test]
fn check_is_read_only_and_reports_every_stale_or_missing_schema() {
	let directory = Directory::new();
	let schemas = [
		SchemaDoc {
			file: "config.json",
			schema_json: "config".into(),
		},
		SchemaDoc {
			file: "admin.json",
			schema_json: "admin".into(),
		},
		SchemaDoc {
			file: "cel.json",
			schema_json: "cel".into(),
		},
	];
	write_or_check_schemas(&directory.0, &schemas, false).unwrap();
	let config = directory.0.join("config.json");
	let timestamp = UNIX_EPOCH + Duration::from_secs(1);
	File::open(&config)
		.unwrap()
		.set_times(FileTimes::new().set_modified(timestamp))
		.unwrap();
	write_or_check_schemas(&directory.0, &schemas, true).unwrap();
	assert_eq!(
		fs::metadata(&config).unwrap().modified().unwrap(),
		timestamp
	);

	fs::write(&config, "stale").unwrap();
	fs::remove_file(directory.0.join("admin.json")).unwrap();
	let error = write_or_check_schemas(&directory.0, &schemas, true)
		.unwrap_err()
		.to_string();
	assert!(error.contains("config.json, admin.json"), "{error}");
	assert!(error.contains("cargo xtask schema"), "{error}");
	assert_eq!(fs::read_to_string(&config).unwrap(), "stale");
	assert!(!directory.0.join("admin.json").exists());
	assert_eq!(
		fs::read_to_string(directory.0.join("cel.json")).unwrap(),
		"cel"
	);
	write_or_check_schemas(&directory.0, &schemas, false).unwrap();
	write_or_check_schemas(&directory.0, &schemas, true).unwrap();
}

#[test]
fn check_preserves_read_errors_instead_of_reporting_a_match() {
	let directory = Directory::new();
	fs::create_dir(directory.0.join("config.json")).unwrap();
	let error = write_or_check_schemas(
		&directory.0,
		&[SchemaDoc {
			file: "config.json",
			schema_json: "config".into(),
		}],
		true,
	)
	.unwrap_err();
	assert!(format!("{error:#}").contains("config.json"));
	assert!(directory.0.join("config.json").is_dir());
}
