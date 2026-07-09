# Makefile for ai-sudo — build, test, and deploy
#
# Targets:
#   test    — build debug (needed by integration tests) + run all tests
#   update  — build release + install via setup.sh (requires sudo)
#   build   — build release only
#   clean   — clean build artifacts

.PHONY: test update build clean

test:
	cargo build --locked
	cargo test --locked

update:
	sudo ./setup.sh

build:
	cargo build --release --locked

clean:
	cargo clean
