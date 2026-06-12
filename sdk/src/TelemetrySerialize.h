/*
 * Role: Platform-free per-tick telemetry serializer — assembles the JSON
 *       `TickPayload` the server ingests (server/telemetry/src/schema.rs) from
 *       the client's assembled aim-feature POD. THE TICK ECHO LIVES HERE: the
 *       emitted `tick` field is the SERVER simulation tick the client last
 *       consumed (`hk_tick_input.server_tick`), NOT a free-running client
 *       counter — the pipeline pairs telemetry against authoritative snapshots
 *       by this value, and a client that fails to echo it is starved of the
 *       gamestate domain and surfaces as a Review-tier pairing anomaly (see the
 *       TickPayload.tick contract comment in schema.rs).
 * Target platforms: all (PC first). Platform-free (no OS API, no platform
 *       header) so it folds and host-tests with no platform TU (guardrail #4),
 *       mirroring input/AimAccumulator.cpp.
 * Interface: produces the wire shape mirrored by schema.rs::TickPayload. Field
 *       names MUST match the serde field names; omitted fields default to 0 on
 *       the server (`#[serde(default)]`), so this emits the core + the
 *       aim-kinematics block the server scores, not every optional field.
 */

#pragma once

#include <cstddef>
#include <cstdint>

#include "input/AimSampler.h"

namespace hk {
namespace sdk {
namespace telemetry {

/* One tick's worth of client state to serialize. `server_tick` is the echo:
 * the server simulation tick the client acted on this frame. */
struct hk_tick_input {
    uint32_t schema_version;   /* must match server SCHEMA_VERSION (currently 6). */
    uint64_t player_id;        /* server-assigned player id. */
    uint64_t server_tick;      /* THE ECHO: server sim tick last consumed. */
    uint32_t input_state;      /* movement/fire/jump bitmask. */
    uint8_t  fired;            /* 1 = a fire event occurred this tick. */
    uint64_t client_mono_ns;   /* client CLOCK_MONOTONIC at this frame (178). */
    uint16_t client_refresh_hz;/* client display refresh Hz (178 harmonic gate). */

    /* The assembled aim-feature POD (163-171) from the accumulator + backends. */
    hk::sdk::aim::hk_aim_features features;

    /* 169 candidate target angular offsets (radians). Ships as the JSON
     * `candidate_target_offsets` array. May be null with count 0. */
    const float* candidate_offsets;
    uint32_t     candidate_count;
};

/* Serialize `in` into `out` as a JSON TickPayload. Returns the number of bytes
 * the full document occupies (EXCLUDING the NUL). When the return value is
 * <= cap the buffer holds the complete, NUL-terminated JSON; when it is > cap
 * the output was truncated (the caller should retry with a larger buffer) — the
 * function never writes past `cap` and always NUL-terminates when cap > 0.
 * Pure; no OS API; no allocation. */
size_t serialize_tick(const hk_tick_input& in, char* out, size_t cap);

} // namespace telemetry
} // namespace sdk
} // namespace hk
