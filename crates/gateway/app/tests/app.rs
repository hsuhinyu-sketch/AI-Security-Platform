#[test]
fn test_compiles() {
	let _ = ai_security_platform_app::run as fn() -> anyhow::Result<()>;
}
