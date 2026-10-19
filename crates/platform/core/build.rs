use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn command_output(workspace_root: &Path, program: &str, args: &[&str]) -> Option<String> {
	let output = Command::new(program)
		.args(args)
		.current_dir(workspace_root)
		.output()
		.ok()?;
	output
		.status
		.success()
		.then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn repository_revision(workspace_root: &Path) -> String {
	if let Some(revision) = command_output(workspace_root, "git", &["rev-parse", "HEAD"]) {
		let dirty = env::var_os("IGNORE_DIRTY_TREE").is_none()
			&& command_output(workspace_root, "git", &["status", "--porcelain"])
				.is_some_and(|status| !status.is_empty());
		return if dirty {
			format!("{revision}-dirty")
		} else {
			revision
		};
	}

	command_output(
		workspace_root,
		"jj",
		&["log", "-r", "@", "-T", "commit_id", "--no-graph"],
	)
	.unwrap_or_else(|| "unknown".to_owned())
}

fn main() {
	let out_dir = env::var("OUT_DIR").unwrap();
	let profile_name = out_dir
		.split(std::path::MAIN_SEPARATOR)
		.nth_back(3)
		.unwrap_or("unknown");
	let target = env::var("TARGET").unwrap();
	let workspace_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../..");
	let repository_revision = repository_revision(&workspace_root);
	let version = env::var("VERSION").unwrap_or_else(|_| repository_revision.clone());
	let git_revision = env::var("GIT_REVISION").unwrap_or(repository_revision);

	println!("cargo:rustc-env=AISP_BUILD_VERSION={version}");
	println!("cargo:rustc-env=AISP_BUILD_GIT_REVISION={git_revision}");
	println!(
		"cargo:rustc-env=AISP_BUILD_RUSTC_VERSION={}",
		rustc_version::version().unwrap()
	);
	println!("cargo:rustc-env=AISP_BUILD_PROFILE_NAME={profile_name}");
	println!("cargo:rustc-env=AISP_BUILD_TARGET={target}");
	println!("cargo:rerun-if-env-changed=VERSION");
	println!("cargo:rerun-if-env-changed=GIT_REVISION");
	println!("cargo:rerun-if-env-changed=IGNORE_DIRTY_TREE");
}
