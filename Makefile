all: test

test:
	@rustc --test src/clearcrypt/secret_buffer.rs
	@./secret_buffer --test --bench
