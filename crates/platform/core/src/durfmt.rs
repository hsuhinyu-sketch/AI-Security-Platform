use std::time::Duration;

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
	#[error("parse error: {}", err_str(.0))]
	ParseError(go_parse_duration::Error),
}

fn err_str(e: &go_parse_duration::Error) -> &str {
	match e {
		go_parse_duration::Error::ParseError(s) => s,
	}
}

pub fn parse(string: &str) -> Result<Duration, Error> {
	let d = go_parse_duration::parse_duration(string).map_err(Error::ParseError)?;
	if d < 0 {
		return Err(Error::ParseError(go_parse_duration::Error::ParseError(
			"negative string not allowed".to_string(),
		)));
	}
	Ok(Duration::from_nanos(d as u64))
}

pub fn format(d: Duration) -> String {
	durationfmt::to_string(round_to_3_figs(d))
}

fn round_to_3_figs(d: Duration) -> Duration {
	if d <= Duration::from_millis(1) {
		return d;
	}

	let secs = d.as_secs();
	let nanos = d.subsec_nanos();
	if d.as_secs() <= 1 {
		Duration::new(secs, ((nanos as f64) / 1000.0).round() as u32 * 1000)
	} else {
		let rounded = ((nanos as f64) / 1000000.0).round() as u32 * 1000000;
		const NANOS_PER_SEC: u32 = 1_000_000_000;
		if rounded >= NANOS_PER_SEC {
			Duration::new(secs.checked_add(1).unwrap_or(secs), 0)
		} else {
			Duration::new(secs, rounded)
		}
	}
}
