# Contributing

Thanks for taking a look. This is a solo project at the moment, so expect the process
to be light.

## Building and testing

Needs Go 1.26+.

```sh
make build          # server + probe
make test           # unit tests (in-memory store)
go test ./...       # same, everything
make demo           # end-to-end scan against the bundled snapshot
```

The Postgres-backed store tests only run when you point them at a database:

```sh
docker compose up -d
BLADEDR_TEST_DATABASE_URL=postgres://bladedr:bladedr@localhost:5432/bladedr go test ./internal/store/
```

## Before you open a PR

CI runs these, so save yourself a round trip:

```sh
gofmt -l internal cmd    # must print nothing
go vet ./...
go test ./...
semgrep --config auto --error --quiet   # if you have semgrep
```

Keep the diff focused. Match the surrounding style — the code leans terse, and
comments explain *why*, not *what*. New behaviour should come with a test.

## Rules and detections

Detection logic is data, not code (YAML + CEL in `internal/rules/builtin/`), so a new
agentless detection usually doesn't need Go changes — add a rule and a test snapshot.
eBPF detections live in the Tetragon policies, not here.

## Branches

`main` is the release branch, `dev` is where work lands. Branch off `dev`, PR back into
it. Commits are plain — no trailers.
