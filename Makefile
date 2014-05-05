all: test

test:
	@rustc -O --test chacha.rs
	@./chacha --test --bench
