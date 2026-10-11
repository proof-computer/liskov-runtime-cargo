# Direct-peer v2 wire vectors

Source: `crates/slipway-executor-contracts/src/runtime_diagnostics/direct_peer.rs` and its v4 parser integration.
Source baseline: liskov-rs `origin/main` at `54977276c` (2026-10-11).
Source implementation: proof-computer/liskov-rs `417ea4103a9353e6920d8e834cee4f403c228548` (PR #1662).
This file hashes the portable bytes independently.
All JSON vectors are UTF-8, compact, newline-terminated. SHA-256 includes that newline.

| Fixture | SHA-256 |
| --- | --- |
| `liskov-discovery-v2-advertisement.json` | `f17b77e8c56512859aaaec8a6684b4e05dbd7d4fedbd83d945bb1d485fe7ce74` |
| `liskov-discovery-v2-complete-empty.json` | `b1cfb303e7869e7dfcfc930afc73daa4d61bc3682c9b5052c44878dad3d3be1e` |
| `liskov-discovery-v2-directory.json` | `f1b51194ba9564e98ae035879598a33d3fe80a2389b5f75888e9a465ec012685` |
| `liskov-discovery-v2-invalid-advertisement.json` | `93d689416b7286c194bbbde4ccf8ec344277fda7bde35735d17ab5cd219d1cf9` |
| `liskov-discovery-v2-invalid.json` | `5df4629dd908661b1dc5294d6ae403030bde972d0338f3bb42076a1e73e77349` |
| `liskov-discovery-v2-signed-health-canonical.json` | `37898bc256b812ab3a0bf6bc2d1d674906912be927bb7f1b75b8a2e49585a76b` |
| `liskov-discovery-v2-signed-health-request.json` | `8404e5bc30bb16b68786aa302b787cd569bee03dd5f0abb8c68f5019f89390e9` |
| `liskov-discovery-v2-unavailable.json` | `2e751fae689173e15828648c6b54dbd04f08cb94731696ce78671b2a93f1e8d0` |

The signed-health canonical fixture omits only `signature`; it must equal the existing diagnostic-v4 canonical signed message after parsing the 27-attribute request. `directory` and `complete-empty` use the SHA-256 of their compact serialized `peers` array as `revision`. The unavailable fixture is a response to an accepted health beat and is distinct from a complete empty snapshot.
