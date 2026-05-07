# Horkos Event Schema

`sdk/include/horkos/event_schema.h` is the wire-format source of truth for all
events flowing between Horkos kernel components and the Rust server.

## Versioning rules

- Every new field addition bumps the `version` field in `hk_event_header`.
- Field names are permanent. Never rename a field.
- Deprecated fields are retained as `reserved` padding with a `_deprecated` suffix.
  They are zero-filled by writers and ignored by readers.
- The `payload_bytes` field in `hk_event_header` indicates the size of the struct
  that immediately follows the header. Readers must bounds-check against this value
  before accessing payload fields.

## Size invariants

| Struct | Required size |
|--------|--------------|
| `hk_event_header` | 24 bytes |
| `hk_event_process_create` | 16 bytes |
| `hk_event_image_load` | 16 bytes |
| `hk_event_handle_open` | 16 bytes |

`static_assert` enforces these at compile time. The C++ unit test
`tests/unit/test_event_schema_sizes.cpp` re-validates them at test time.

## Phase 2 mirror contract

The Phase 2 Rust telemetry crate hand-writes `serde::Deserialize` structs that
mirror each C99 struct field-for-field. A contract test in the Rust crate diffs
field names and sizes against the C header. This diff is a merge gate: if it
fails, the PR is blocked.

## Adding a new event type

1. Add a new `HK_EVENT_*` value to `hk_event_type` (append only, never reorder).
2. Define a new payload struct with `static_assert` on its size.
3. Bump the schema version constant.
4. Add the mirrored Rust struct in `server/telemetry/src/schema.rs`.
5. Add size tests in `tests/unit/test_event_schema_sizes.cpp`.
6. Update this document.
