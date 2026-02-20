SHELL := /bin/bash

.PHONY: build release install test fmt clippy

build:
	cd bsuppla && cargo build

release:
	cd bsuppla && cargo build --release

install: release
	bash scripts/install.sh

test:
	cd bsuppla && cargo test

fmt:
	cd bsuppla && cargo fmt

clippy:
	cd bsuppla && cargo clippy
