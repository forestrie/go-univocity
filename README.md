# go-univocity

Go implementation of the Forestrie **leaf commitment** and **grant** wire format, aligned with the [univocity](https://github.com/forestrie/univocity) Solidity contracts and the [canopy](https://github.com/forestrie/canopy) TypeScript codec.

The formats are specified in [forestrie/protocol](https://github.com/forestrie/protocol): [`spec/log-authority-and-grants.md`](https://github.com/forestrie/protocol/blob/main/spec/log-authority-and-grants.md) (§2.1 the wire map, §4 the commitment) and the conformance vectors under [`vectors/`](https://github.com/forestrie/protocol/tree/main/vectors). Where this implementation and that text disagree, the text is right or the implementation is, and the fix lands there first.

## Purpose

- Go package: `LeafCommitment`, grant encode/decode; consumable by arbor services (queue consumer, ranger).
- The fixtures under `tests/fixtures/` are copies of the protocol repository's vectors; `tests/scripts/gen_testvectors.py` regenerates the positive ones and must reproduce the protocol bytes exactly.

## Documentation

- The worked guide with examples in Go, TypeScript and Python is [`vectors/grant-and-leaf-format.md`](https://github.com/forestrie/protocol/blob/main/vectors/grant-and-leaf-format.md) in the protocol repository; [docs/grant-and-leaf-format.md](docs/grant-and-leaf-format.md) here only points to it.

## Usage

```go
import "github.com/forestrie/go-univocity/grant"

leafHash := grant.LeafCommitment(idTimestampBE, logId, grantFlags, maxHeight, minGrowth, ownerLogId, grantData)
```

## Tests

```bash
go test ./...
```

Regenerate the positive test vectors (requires Python 3), then confirm they still match the protocol repository's `vectors/fixtures/`:

```bash
python3 tests/scripts/gen_testvectors.py
```

## License

See [LICENSE](LICENSE) if present.
