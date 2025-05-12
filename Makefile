
build:
	cargo build

bump-verson: build
	cargo ws version --no-individual-tags
