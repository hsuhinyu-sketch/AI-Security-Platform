CARGO_BUILD_ARGS ?=

.PHONY: build check fmt clippy schema clean

build:
	cargo build --release --features ui $(CARGO_BUILD_ARGS)

check:
	cargo check --workspace

fmt:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets --no-deps

schema:
	cargo xtask schema

clean:
	cargo clean
