use std::ops::Deref;
use std::sync::OnceLock;

/// A cached blocking HTTP client must be destroyed outside a Tokio async worker.
#[derive(Debug)]
pub(crate) struct BlockingClientCache<T: Send + 'static>(OnceLock<Result<T, String>>);

impl<T: Send + 'static> Default for BlockingClientCache<T> {
	fn default() -> Self {
		Self(OnceLock::new())
	}
}

impl<T: Send + 'static> Deref for BlockingClientCache<T> {
	type Target = OnceLock<Result<T, String>>;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl<T: Send + 'static> Drop for BlockingClientCache<T> {
	fn drop(&mut self) {
		let Some(client) = std::mem::take(&mut self.0).into_inner() else {
			return;
		};
		if tokio::runtime::Handle::try_current().is_ok() {
			// reqwest::blocking::Client owns a runtime; dropping it on an async worker panics.
			std::thread::spawn(move || drop(client));
		} else {
			drop(client);
		}
	}
}
