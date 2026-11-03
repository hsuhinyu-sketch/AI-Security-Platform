mod cel;
mod schema;

use std::env::args;

use anyhow::{Context, Result, bail};

enum Task {
	Schema { check: bool },
	Cel,
}

fn get_task() -> Result<Task> {
	let message = "argument is missing. Example usage: \ncargo xtask schema";
	let mut arguments = args().skip(1);
	let arg = arguments.next().context(message)?;
	match arg.as_str() {
		"schema" => {
			let check = match (arguments.next().as_deref(), arguments.next()) {
				(None, None) => false,
				(Some("--check"), None) => true,
				_ => bail!("usage: cargo xtask schema [--check]"),
			};
			Ok(Task::Schema { check })
		},
		"cel" => Ok(Task::Cel),
		arg => bail!("unknown task: {}", arg),
	}
}

fn main() -> Result<()> {
	match get_task()? {
		Task::Schema { check } => schema::generate_schema(check),
		Task::Cel => cel::evaluate_command(),
	}
}
