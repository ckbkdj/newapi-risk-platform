.PHONY: fmt test race vet build run init-env deploy update upgrade doctor docker-up docker-down

fmt:
	gofmt -w ./cmd ./internal

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

build:
	CGO_ENABLED=0 go build -trimpath -o bin/riskd ./cmd/riskd

run:
	go run ./cmd/riskd

init-env:
	bash scripts/init-env.sh

deploy:
	bash scripts/deploy-local.sh

update:
	bash scripts/update.sh

upgrade:
	bash scripts/upgrade.sh

doctor:
	bash scripts/doctor.sh

# Kept for compatibility, but unlike a bare `docker compose up`, this waits for
# the HTTP readiness endpoint and prints startup logs on failure.
docker-up: deploy

docker-down:
	docker compose down
