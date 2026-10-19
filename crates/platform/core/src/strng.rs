use std::fmt::Error;
use std::ops::Deref;

use arcstr::ArcStr;
use prometheus_client::encoding::{LabelKeyEncoder, LabelValueEncoder};

/// 'Strng' provides a string type that has better properties for our use case:
/// * Cheap cloning (ref counting)
/// * Efficient storage (8 bytes vs 24 bytes)
/// * Immutable
///
/// This is mostly provided by a library, ArcStr, we just provide a very thin wrapper around it
/// for some flexibility.
pub type Strng = ArcStr;

pub const EMPTY: Strng = literal!("");

pub fn new<A: AsRef<str>>(s: A) -> Strng {
	Strng::from(s.as_ref())
}

pub use arcstr::{format, literal};

/// RichStrng wraps Strng to let us implement arbitrary methods. How annoying.
#[derive(Clone, Hash, Default, Debug, PartialEq, Eq)]
pub struct RichStrng(Strng);

impl prometheus_client::encoding::EncodeLabelValue for RichStrng {
	fn encode(&self, encoder: &mut LabelValueEncoder) -> Result<(), Error> {
		prometheus_client::encoding::EncodeLabelValue::encode(
			&<ArcStr as AsRef<str>>::as_ref(&self.0),
			encoder,
		)
	}
}

impl prometheus_client::encoding::EncodeLabelKey for RichStrng {
	fn encode(&self, encoder: &mut LabelKeyEncoder) -> Result<(), Error> {
		prometheus_client::encoding::EncodeLabelKey::encode(
			&<ArcStr as AsRef<str>>::as_ref(&self.0),
			encoder,
		)
	}
}

impl Deref for RichStrng {
	type Target = Strng;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl<T> From<T> for RichStrng
where
	T: Into<Strng>,
{
	fn from(value: T) -> Self {
		RichStrng(value.into())
	}
}
