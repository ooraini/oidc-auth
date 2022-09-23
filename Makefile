IMG ?= ghcr.io/ooraini/oidc-auth

.PHONY: docker-build
docker-build:
	kustomize edit set image oidc-auth=${IMG}:$$(git describe --tags --abbrev=0)
	git diff --quiet || exit 1
	docker build -t ${IMG}:$$(git describe --tags --abbrev=0) .

.PHONY: docker-push
docker-push:
	kustomize edit set image oidc-auth=${IMG}:$$(git describe --tags --abbrev=0)
	git diff --quiet || exit 1
	docker push ${IMG}:$$(git describe --tags --abbrev=0)
