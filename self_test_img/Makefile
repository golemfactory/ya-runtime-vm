all: build

build: src
	docker build -t self-test .
	gvmkit-build self-test:latest -o self-test.gvmi

.PHONY: all

.PHONY: clean
clean:
	cargo clean
	rm -f self-test.gvmi
