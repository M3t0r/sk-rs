GIT_VERSION = $(shell git describe --tag --always --dirt)
CRATE_VERSION = $(shell cargo read-manifest | jq -r .version)

IMAGE_REGISTRY := ghcr.io/m3t0r
IMAGE_NAME := sk-rs
IMAGE_TAG := ${GIT_VERSION}

BUILD := podman build
BUILDFLAGS :=
PUSH := podman push
PUSHFLAGS :=

export DATABASE_URL ?= sqlite://database.sqlite
DATABASE := $(subst sqlite://,,${DATABASE_URL})

.PHONY: dev
dev:
	cargo watch --ignore "$(basename ${DATABASE}).*" -- cargo run

.PHONY: tag
tag:
	( \
		git tag --list \
		| grep "v${CRATE_VERSION}" \
	) > /dev/null \
	|| git tag "v${CRATE_VERSION}"

.PHONY: image-build
image-build:
	$(BUILD) $(BUILDFLAGS) \
		--label org.opencontainers.image.created="$$(date --rfc-3339=seconds)" \
		--label org.opencontainers.image.version=${GIT_VERSION} \
		--label org.opencontainers.image.revision="$$(git rev-parse HEAD)" \
		-t ${IMAGE_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG} \
		.

.PHONY: image-push
image-push:
	$(PUSH) $(PUSHFLAGS) ${IMAGE_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}

.PHONY: sqlx-prepare
sqlx-prepare: .sqlx/make_sentinel
.sqlx/make_sentinel: DATABASE_URL=sqlite://.sqlx/prepare.db
.sqlx/make_sentinel: $(wildcard src/*.rs)
	cargo sqlx database reset -y
	cargo sqlx prepare
	touch $@
