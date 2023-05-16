RUST_PARSER_PATH=RustParser
PARSER_AND_REPLAYER_PATH=ParserAndReplayer

build-parser:
	cargo build --release --manifest-path=$(RUST_PARSER_PATH)/Cargo.toml

move-lib:
	mkdir -p $(PARSER_AND_REPLAYER_PATH)/lib
	cp $(RUST_PARSER_PATH)/target/release/libneko_libparser.so $(PARSER_AND_REPLAYER_PATH)/lib/neko_libparser.so

install: build-parser move-lib
	pip install .

clean:
	cargo clean --release --manifest-path=$(RUST_PARSER_PATH)/Cargo.toml
	rm -r build *.egg-info

.PHONY: clean