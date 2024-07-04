GOX := $(shell which go)
BIN := sscgen
SRC := cmd/sscgen
OUT := dist

dist:
	mkdir -p $(OUT)
	$(GOX) build \
		-v \
		-x \
		-o $(OUT)/$(BIN) \
		./$(SRC)

test:
	$(GOX) test ../..

clean:
	rm -rf $(OUT)

.PHONY: test clean
