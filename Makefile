.PHONY: build test lint clean check run

build:
	npm run build
	cargo build --locked --release --manifest-path src-tauri/Cargo.toml

check:
	cargo check --locked --manifest-path src-tauri/Cargo.toml

test:
	cargo test --locked --manifest-path src-tauri/Cargo.toml

lint:
	cargo clippy --locked --manifest-path src-tauri/Cargo.toml -- -D warnings

run:
	npm run tauri dev

clean:
	cargo clean --manifest-path src-tauri/Cargo.toml
