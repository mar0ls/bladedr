.PHONY: build build-probe-linux test vet run demo clean tidy deploy stop migrate

BIN := bin
LDFLAGS :=

build: ## Build server + probe for the host platform
	go build -o $(BIN)/bladedr-server ./cmd/bladedr-server
	go build -o $(BIN)/bladedr-probe  ./cmd/bladedr-probe

build-probe-linux: ## Cross-compile the static probe for Linux targets
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o $(BIN)/bladedr-probe.linux-amd64 ./cmd/bladedr-probe
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o $(BIN)/bladedr-probe.linux-arm64 ./cmd/bladedr-probe

test: ## Run tests
	go test ./...

vet: ## go vet
	go vet ./...

tidy: ## Sync go.mod/go.sum
	go mod tidy

run: build ## Run the server (in-memory store) on :8080
	BLADEDR_PROBE_BIN=./$(BIN)/bladedr-probe ./$(BIN)/bladedr-server

demo: build ## Run an end-to-end demo scan against the bundled malicious snapshot
	@BLADEDR_ADDR=:18080 BLADEDR_PROBE_BIN=./$(BIN)/bladedr-probe \
	  BLADEDR_PROBE_EXTRA="--snapshot-file testdata/malicious-snapshot.json" \
	  BLADEDR_ADMIN_PASSWORD=demo \
	  ./$(BIN)/bladedr-server >/tmp/bladedr-demo.log 2>&1 & \
	  sleep 1; \
	  TOK=$$(curl -fsS -X POST localhost:18080/api/v1/login -H 'content-type: application/json' -d '{"Username":"admin","Password":"demo"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])'); \
	  HID=$$(curl -fsS -H "Authorization: Bearer $$TOK" -X POST localhost:18080/api/v1/hosts -H 'content-type: application/json' -d '{"hostname":"web-01","primary_ip":"10.0.0.5"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])'); \
	  curl -fsS -H "Authorization: Bearer $$TOK" -X POST localhost:18080/api/v1/hosts/$$HID/scans | python3 -m json.tool; \
	  echo "--- observations ---"; \
	  curl -fsS -H "Authorization: Bearer $$TOK" "localhost:18080/api/v1/observations?host=$$HID" | python3 -m json.tool; \
	  pkill -f bladedr-server

deploy: ## Deploy the control plane on this machine (Postgres + persistent key + server)
	./scripts/deploy-server.sh

sensor: ## Cross-build the eBPF sensor (Tetragon wrapper) for Linux hosts
	GOOS=linux GOARCH=amd64 go build -o $(BIN)/bladedr-sensor.linux-amd64 ./cmd/bladedr-sensor
	GOOS=linux GOARCH=arm64 go build -o $(BIN)/bladedr-sensor.linux-arm64 ./cmd/bladedr-sensor

lab: ## Run the attack-emulation range: plant techniques, scan, emit labelled ML data
	GOOS=linux GOARCH=amd64 go build -o $(BIN)/bladedr-probe.linux-amd64 ./cmd/bladedr-probe
	GOOS=linux GOARCH=arm64 go build -o $(BIN)/bladedr-probe.linux-arm64 ./cmd/bladedr-probe
	go run ./cmd/bladedr-lab

migrate: ## Apply the DB schema manually (the server also auto-migrates on startup)
	docker compose exec -T db psql -U bladedr -d bladedr -v ON_ERROR_STOP=1 < internal/store/migrations/0001_init.sql

stop: ## Stop the server (Postgres keeps running; `docker compose down` to stop it too)
	pkill -f 'bin/bladedr-server' || true

clean:
	rm -rf $(BIN)
