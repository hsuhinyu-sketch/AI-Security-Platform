//! A Host-bound infrastructure dependency call, not an admission receipt or a Tool executor.
//!
//! The Host fixes destination selection, policies and dependency category before injection.
//! Implementations must retain the original request context and run their final dispatch
//! checks on every call. Dropping the returned future cancels that attempt. No raw transport,
//! runtime configuration, authorization boolean or service registry is exposed here.
use std::{future::Future, pin::Pin};

pub type ExecutionFuture<'a, T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'a>>;

pub trait BoundHttpExecution: Send + Sync {
	type RequestBody: Send;
	type ResponseBody: Send;
	type Error;

	fn execute(
		&self,
		request: http::Request<Self::RequestBody>,
	) -> ExecutionFuture<'_, http::Response<Self::ResponseBody>, Self::Error>;
}
