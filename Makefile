# Copyright (C) 2026 JC-Lab
# SPDX-License-Identifier: Apache-2.0

.PHONY: test vet license license-check check

test:
	go test -race ./...

vet:
	go vet ./...

license:
	go run ./tools/licensehdr -fix .

license-check:
	go run ./tools/licensehdr .

check: vet test license-check
