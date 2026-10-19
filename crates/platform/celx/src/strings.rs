// Copied from https://raw.githubusercontent.com/Kuadrant/wasm-shim/refs/heads/main/src/data/cel/strings.rs
// under Apache 2.0 license (https://github.com/Kuadrant/wasm-shim/blob/main/LICENSE)
// TODO: https://github.com/cel-rust/cel-rust/issues/103, have this upstreamed

use cel::extractors::{Argument, This};
use cel::objects::StringValue;
use cel::{Context, ExecutionError, FunctionContext, ResolveResult, Value};

pub fn insert_all(ctx: &mut Context) {
	ctx.add_function("charAt", char_at);
	ctx.add_function("indexOf", index_of);
	ctx.add_function("lastIndexOf", last_index_of);
	ctx.add_function("join", join);
	ctx.add_function("lowerAscii", lower_ascii);
	ctx.add_function("stripPrefix", strip_prefix);
	ctx.add_function("stripSuffix", strip_suffix);
	ctx.add_function("upperAscii", upper_ascii);
	ctx.add_function("trim", trim);
	ctx.add_function("replace", replace);
	ctx.add_function("split", split);
	ctx.add_function("substring", substring);
}

pub fn char_at<'a>(
	ftx: &mut FunctionContext<'a, '_>,
	this: This,
	arg: Argument,
) -> ResolveResult<'a> {
	let this: StringValue = this.load_value(ftx)?;
	let index = arg.load(ftx)?.as_unsigned()?;
	match this.as_ref().chars().nth(index) {
		None => Err(ExecutionError::FunctionError {
			function: "String.charAt".to_owned(),
			message: format!("No index {index} on `{}`", this.as_ref()),
		}),
		Some(c) => Ok(c.to_string().into()),
	}
}

pub fn index_of<'a>(
	ftx: &mut FunctionContext<'a, '_>,
	this: This,
	arg: Argument,
) -> ResolveResult<'a> {
	let this: StringValue = this.load_value(ftx)?;
	let arg: StringValue = arg.load_value(ftx)?;
	let this_str = this.as_ref();
	let needle = arg.as_ref();
	let base = match ftx.args.len() {
		1 => 0,
		2 => ftx.arg::<Value>(1)?.as_unsigned()?,
		_ => {
			return Err(ExecutionError::FunctionError {
				function: "String.indexOf".to_owned(),
				message: format!("Expects 2 arguments at most, got `{}`!", ftx.args.len()),
			});
		},
	};
	if base >= this_str.chars().count() {
		return Ok(Value::Int(-1));
	}
	let base_byte = char_to_byte_idx(this_str, base);
	let suffix = &this_str[base_byte..];
	match suffix.find(needle) {
		Some(idx) => Ok(Value::Int((base + suffix[..idx].chars().count()) as i64)),
		None => Ok(Value::Int(-1)),
	}
}

pub fn last_index_of<'a>(
	ftx: &mut FunctionContext<'a, '_>,
	this: This,
	arg: Argument,
) -> ResolveResult<'a> {
	let this: StringValue = this.load_value(ftx)?;
	let arg: StringValue = arg.load_value(ftx)?;
	let this_str = this.as_ref();
	let needle = arg.as_ref();
	let suffix = match ftx.args.len() {
		1 => this_str,
		2 => {
			let base = ftx.arg::<Value>(1)?.as_unsigned()?;
			if base >= this_str.chars().count() {
				return Ok(Value::Int(-1));
			}
			let end_char = base.saturating_add(needle.chars().count());
			let end_byte = char_to_byte_idx(this_str, end_char);
			&this_str[..end_byte]
		},
		_ => {
			return Err(ExecutionError::FunctionError {
				function: "String.lastIndexOf".to_owned(),
				message: format!("Expects 2 arguments at most, got `{}`!", ftx.args.len()),
			});
		},
	};
	match suffix.rfind(needle) {
		Some(idx) => Ok(Value::Int(suffix[..idx].chars().count() as i64)),
		None => Ok(Value::Int(-1)),
	}
}

pub fn join<'a>(ftx: &mut FunctionContext<'a, '_>, this: This) -> ResolveResult<'a> {
	let this = this.load_value(ftx)?;
	let this = match this {
		Value::List(list) => list,
		other => {
			return Err(ExecutionError::FunctionError {
				function: "List.join".to_owned(),
				message: format!("Expects receiver to be a List, got `{:?}`", other),
			});
		},
	};
	let separator_value = if ftx.args.is_empty() {
		None
	} else {
		Some(ftx.arg(0)?)
	};
	let separator = separator_value
		.as_ref()
		.map(|sep: &StringValue| sep.as_ref())
		.unwrap_or("");
	Ok(
		this
			.as_ref()
			.iter()
			.map(|v| match v {
				Value::String(s) => Ok(s.as_ref().to_string()),
				_ => Err(ExecutionError::FunctionError {
					function: "List.join".to_owned(),
					message: "Expects a list of String values!".to_owned(),
				}),
			})
			.collect::<Result<Vec<_>, _>>()?
			.join(separator)
			.into(),
	)
}

pub fn lower_ascii<'a>(ftx: &mut FunctionContext<'a, '_>, this: This) -> ResolveResult<'a> {
	let this: StringValue = this.load_value(ftx)?;
	Ok(this.as_ref().to_ascii_lowercase().into())
}

pub fn strip_prefix<'a>(
	ftx: &mut FunctionContext<'a, '_>,
	this: This,
	prefix: Argument,
) -> ResolveResult<'a> {
	let this: StringValue = this.load_value(ftx)?;
	let prefix: StringValue = prefix.load_value(ftx)?;
	let stripped = this
		.as_ref()
		.strip_prefix(prefix.as_ref())
		.unwrap_or(this.as_ref());
	Ok(stripped.to_string().into())
}

pub fn strip_suffix<'a>(
	ftx: &mut FunctionContext<'a, '_>,
	this: This,
	suffix: Argument,
) -> ResolveResult<'a> {
	let this: StringValue = this.load_value(ftx)?;
	let suffix: StringValue = suffix.load_value(ftx)?;
	let stripped = this
		.as_ref()
		.strip_suffix(suffix.as_ref())
		.unwrap_or(this.as_ref());
	Ok(stripped.to_string().into())
}

pub fn upper_ascii<'a>(ftx: &mut FunctionContext<'a, '_>, this: This) -> ResolveResult<'a> {
	let this: StringValue = this.load_value(ftx)?;
	Ok(this.as_ref().to_ascii_uppercase().into())
}

pub fn trim<'a>(ftx: &mut FunctionContext<'a, '_>, this: This) -> ResolveResult<'a> {
	let this: StringValue = this.load_value(ftx)?;
	Ok(this.as_ref().trim().to_string().into())
}

pub fn replace<'a>(
	ftx: &mut FunctionContext<'a, '_>,
	this: This,
	from: Argument,
	to: Argument,
) -> ResolveResult<'a> {
	let this: StringValue = this.load_value(ftx)?;
	let from: StringValue = from.load_value(ftx)?;
	let to: StringValue = to.load_value(ftx)?;
	match ftx.args.len() {
		2 => Ok(this.as_ref().replace(from.as_ref(), to.as_ref()).into()),
		3 => {
			let n_value: Value = ftx.arg(2)?;
			let n = n_value.as_signed()?;
			if n < 0 {
				Ok(this.as_ref().replace(from.as_ref(), to.as_ref()).into())
			} else {
				Ok(
					this
						.as_ref()
						.replacen(from.as_ref(), to.as_ref(), n as usize)
						.into(),
				)
			}
		},
		_ => Err(ExecutionError::FunctionError {
			function: "String.replace".to_owned(),
			message: format!("Expects 2 or 3 arguments, got {}!", ftx.args.len()),
		}),
	}
}

pub fn split<'a>(
	ftx: &mut FunctionContext<'a, '_>,
	this: This,
	sep: Argument,
) -> ResolveResult<'a> {
	let this: StringValue = this.load_value(ftx)?;
	let sep: StringValue = sep.load_value(ftx)?;
	match ftx.args.len() {
		1 => Ok(
			this
				.as_ref()
				.split(sep.as_ref())
				.map(|s| Value::String(s.to_owned().into()))
				.collect::<Vec<Value>>()
				.into(),
		),
		2 => {
			let pos_value: Value = ftx.arg(1)?;
			let pos = pos_value.as_signed()?;
			let split = if pos < 0 {
				this
					.as_ref()
					.split(sep.as_ref())
					.map(|s| Value::String(s.to_owned().into()))
					.collect::<Vec<Value>>()
			} else {
				this
					.as_ref()
					.splitn(pos as usize, sep.as_ref())
					.map(|s| Value::String(s.to_owned().into()))
					.collect::<Vec<Value>>()
			};
			Ok(split.into())
		},
		_ => Err(ExecutionError::FunctionError {
			function: "String.split".to_owned(),
			message: format!("Expects at most 2 arguments, got {}!", ftx.args.len()),
		}),
	}
}

pub fn substring<'a>(
	ftx: &mut FunctionContext<'a, '_>,
	this: This,
	start: Argument,
) -> ResolveResult<'a> {
	let this: StringValue = this.load_value(ftx)?;
	let start = start.load(ftx)?.as_unsigned()?;
	match ftx.args.len() {
		1 => {
			let end = this.as_ref().chars().count();
			if end < start {
				return Err(ExecutionError::FunctionError {
					function: "String.substring".to_string(),
					message: format!("Can't have end be before the start: `{end} < {start}"),
				});
			}
			Ok(
				this
					.as_ref()
					.chars()
					.skip(start)
					.take(end - start)
					.collect::<String>()
					.into(),
			)
		},
		2 => {
			let end = ftx.value(1)?.as_unsigned()?;
			if end < start {
				return Err(ExecutionError::FunctionError {
					function: "String.substring".to_string(),
					message: format!("Can't have end be before the start: `{end} < {start}"),
				});
			}
			Ok(
				this
					.as_ref()
					.chars()
					.skip(start)
					.take(end - start)
					.collect::<String>()
					.into(),
			)
		},
		_ => Err(ExecutionError::FunctionError {
			function: "String.substring".to_owned(),
			message: format!("Expects at most 2 arguments, got {}!", ftx.args.len()),
		}),
	}
}

fn char_to_byte_idx(s: &str, idx: usize) -> usize {
	s.char_indices()
		.map(|(byte_idx, _)| byte_idx)
		.chain(std::iter::once(s.len()))
		.nth(idx)
		.unwrap_or(s.len()) // idx beyond string length → clamp to end
}
