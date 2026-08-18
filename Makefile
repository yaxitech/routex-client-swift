SHELL := /bin/bash
BIN_PATH := $(shell swift build --show-bin-path 2>/dev/null)

.PHONY: all build test format lint coverage coverage-html docs docs-preview clean

all: format-check lint build test

build:
	swift build

test:
	swift test

format:
	swift format format --in-place --recursive Sources Tests Package.swift

format-check:
	swift format lint --recursive Sources Tests Package.swift

lint:
	swift format lint --strict --recursive Sources Tests Package.swift

# Run tests with coverage instrumentation and print a per-file summary.
coverage:
	swift test --enable-code-coverage
	@BIN=$$(swift build --show-bin-path); \
	  XCTEST=$$(ls $$BIN | grep PackageTests.xctest | head -1); \
	  EXE=$$BIN/$$XCTEST/Contents/MacOS/$${XCTEST%.xctest}; \
	  [ -f "$$EXE" ] || EXE=$$BIN/$$XCTEST; \
	  PROFDATA=$$BIN/codecov/default.profdata; \
	  xcrun llvm-cov report "$$EXE" \
	    -instr-profile="$$PROFDATA" \
	    -ignore-filename-regex='\.build|Tests'

# Generate an LCOV report at .build/coverage/coverage.lcov plus an HTML report.
coverage-html:
	swift test --enable-code-coverage
	@BIN=$$(swift build --show-bin-path); \
	  XCTEST=$$(ls $$BIN | grep PackageTests.xctest | head -1); \
	  EXE=$$BIN/$$XCTEST/Contents/MacOS/$${XCTEST%.xctest}; \
	  [ -f "$$EXE" ] || EXE=$$BIN/$$XCTEST; \
	  PROFDATA=$$BIN/codecov/default.profdata; \
	  mkdir -p .build/coverage; \
	  xcrun llvm-cov export "$$EXE" \
	    -instr-profile="$$PROFDATA" \
	    -ignore-filename-regex='\.build|Tests' \
	    -format=lcov > .build/coverage/coverage.lcov; \
	  xcrun llvm-cov show "$$EXE" \
	    -instr-profile="$$PROFDATA" \
	    -ignore-filename-regex='\.build|Tests' \
	    -format=html \
	    -output-dir=.build/coverage/html; \
	  echo "lcov: .build/coverage/coverage.lcov"; \
	  echo "html: .build/coverage/html/index.html"

# Render DocC API reference for every library with a public API into
# Documentation/. RoutexCrypto is omitted: its symbols are @_spi(Interop) and
# not part of the public API.
# Open Documentation/documentation/<library>/index.html in a browser.
# DocC bakes absolute URLs into the bundle; set HOSTING_BASE_PATH when the
# result is served from a subpath, e.g. `make docs HOSTING_BASE_PATH=swift`
# for https://host/swift/.
DOCS_DIR := Documentation

docs:
	# Combine into a fresh archive: DocC builds the sidebar from index/index.json,
	# and writing into a stale output dir leaves modules missing from the navigation.
	rm -rf $(DOCS_DIR)
	@mkdir -p $(DOCS_DIR)
	swift package --allow-writing-to-directory $(DOCS_DIR) \
	  generate-documentation \
	  --target RoutexClient --target RoutexModels \
	  --target RoutexRefresh --target RoutexSettlement --target RoutexTickets --target RoutexTransport \
	  --enable-experimental-combined-documentation \
	  --output-path $(DOCS_DIR) \
	  --transform-for-static-hosting \
	  --warnings-as-errors \
	  $(if $(HOSTING_BASE_PATH),--hosting-base-path $(HOSTING_BASE_PATH))
	# Site-wide theming. The combined build has no catalog at its root, so the
	# renderer-fetched theme-settings.json is placed into the archive root here.
	cp theme-settings.json $(DOCS_DIR)/theme-settings.json
	# DocC's archive root has no landing page; the combined docs live under
	# documentation/. A relative redirect keeps the root usable at any
	# HOSTING_BASE_PATH. Deep links carry their own copy of the renderer shell,
	# so overwriting this one does not affect them.
	printf '<!DOCTYPE html>\n<html><head><meta charset="utf-8">\n<meta http-equiv="refresh" content="0; url=documentation/">\n<link rel="canonical" href="documentation/">\n</head>\n<body><a href="documentation/">Documentation</a></body></html>\n' > $(DOCS_DIR)/index.html
	@echo "html: $(CURDIR)/$(DOCS_DIR)/documentation/index.html"

# Live preview the DocC bundle for a single target. Defaults to RoutexClient;
# override with `make docs-preview TARGET=RoutexModels`.
TARGET ?= RoutexClient
docs-preview:
	swift package --disable-sandbox preview-documentation --target $(TARGET)

clean:
	swift package clean
	rm -rf .build/coverage $(DOCS_DIR)
