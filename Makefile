default: build

lint:
	golangci-lint run --fix

.PHONY: install
install: ## go install tools
	$(call print-target)
	cd tools && go install $(shell cd tools && go list -f '{{ join .Imports " " }}' -tags=tools)

.PHONY: build
build: ## goreleaser --snapshot --skip-publish --rm-dist
build: install
	$(call print-target)
	goreleaser --snapshot --skip-publish --rm-dist

.PHONY: release
release: ## goreleaser --rm-dist
release: install
	$(call print-target)
	goreleaser --rm-dist


.PHONY: clean
clean: ## remove files created during build pipeline
	$(call print-target)
	rm -rf dist
	rm -f coverage.*