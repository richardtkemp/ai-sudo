# Makefile for ai-sudo — build, test, and deploy
#
# Targets:
#   test      — lint, then build debug (needed by integration tests) + run all tests
#   test-only — tests without the lint gate, for a fast inner loop
#   test-install-rollback — drives setup.sh's rollback through its failure paths
#   lint      — rustfmt and clippy, both failing the build on any finding
#   update    — build release + install via setup.sh (requires sudo)
#   build     — build release only
#   clean     — clean build artifacts

.PHONY: test test-only test-install-rollback lint update build clean

# `test` depends on `lint` deliberately. Before this existed, commit 4b32e43 shipped five
# unformatted hunks and nothing caught it; two further diffs had been sitting in the tree
# since before that. A lint target nobody's workflow runs would not have caught it either,
# so it goes on the path that is actually used before committing. Use `test-only` while
# iterating.
test: lint test-install-rollback
	cargo build --locked
	cargo test --locked

test-only:
	cargo build --locked
	cargo test --locked

# setup.sh's rollback only runs when an install has already gone wrong, so nothing in
# normal use exercises it. It goes on the `test` path because a rollback that has never
# been shown to fire is decoration. Takes well under a second.
test-install-rollback:
	./scripts/test-install-rollback.sh

# -D warnings makes clippy's exit code meaningful. The tree is clean as of #1820; the few
# genuine exceptions carry a targeted #[allow] with a comment saying why, so future findings
# still fail here rather than joining a permanent background hum of warnings.
lint:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --locked -- -D warnings
	shellcheck setup.sh scripts/*.sh

update:
	sudo ./setup.sh

build:
	cargo build --release --locked

clean:
	cargo clean
