/*
 * Role: Host unit test for the platform-free per-tick TickPayload serializer
 *       (sdk/src/TelemetrySerialize.cpp). Proves THE TICK ECHO: the emitted
 *       JSON `tick` field carries the SERVER simulation tick the client
 *       consumed (`hk_tick_input.server_tick`), not any client counter — the
 *       contract the server pipeline pairs snapshots against. Also checks the
 *       core/aim fields serialize with the exact server-side field names and
 *       that the candidate-offset array + truncation reporting behave.
 * Target platforms: host (CI). Guardrail #4: links only the platform-free
 *       TelemetrySerialize TU; no kernel/platform TU.
 */

#include "TelemetrySerialize.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>

using hk::sdk::aim::hk_aim_features;
using hk::sdk::telemetry::hk_tick_input;
using hk::sdk::telemetry::serialize_tick;

namespace {

hk_tick_input base_input()
{
    hk_tick_input in{};
    in.schema_version = 6;
    in.player_id = 42;
    in.server_tick = 999;
    in.input_state = 0;
    in.fired = 0;
    in.client_mono_ns = 0;
    in.client_refresh_hz = 0;
    in.features = hk_aim_features{};
    in.candidate_offsets = nullptr;
    in.candidate_count = 0;
    return in;
}

std::string serialize(const hk_tick_input& in)
{
    char buf[4096];
    size_t need = serialize_tick(in, buf, sizeof buf);
    EXPECT_LT(need, sizeof buf) << "fixture must fit the buffer";
    return std::string(buf);
}

} // namespace

TEST(TelemetrySerialize, EchoesServerTickIntoTickField)
{
    hk_tick_input in = base_input();
    in.server_tick = 123456;
    const std::string json = serialize(in);
    // The wire `tick` field MUST be the echoed server tick.
    EXPECT_NE(json.find("\"tick\":123456"), std::string::npos) << json;
}

TEST(TelemetrySerialize, CarriesCoreFieldsWithServerNames)
{
    hk_tick_input in = base_input();
    in.schema_version = 6;
    in.player_id = 7;
    in.input_state = 5;
    const std::string json = serialize(in);
    EXPECT_NE(json.find("\"schema_version\":6"), std::string::npos) << json;
    EXPECT_NE(json.find("\"player_id\":7"), std::string::npos) << json;
    EXPECT_NE(json.find("\"input_state\":5"), std::string::npos) << json;
    EXPECT_EQ(json.front(), '{');
    EXPECT_EQ(json.back(), '}');
}

TEST(TelemetrySerialize, SerializesAimAndBooleanFields)
{
    hk_tick_input in = base_input();
    in.features.ang_vel = 1.5f;
    in.features.weapon_id = 3;
    in.features.switch_event_flag = 1;
    in.features.impulse_is_direction_change = 0;
    const std::string json = serialize(in);
    EXPECT_NE(json.find("\"ang_vel\":1.5"), std::string::npos) << json;
    EXPECT_NE(json.find("\"weapon_id\":3"), std::string::npos) << json;
    EXPECT_NE(json.find("\"switch_event_flag\":true"), std::string::npos) << json;
    EXPECT_NE(json.find("\"impulse_is_direction_change\":false"), std::string::npos) << json;
}

TEST(TelemetrySerialize, SerializesCandidateOffsetArray)
{
    hk_tick_input in = base_input();
    const float offs[3] = {0.1f, -0.2f, 0.3f};
    in.candidate_offsets = offs;
    in.candidate_count = 3;
    const std::string json = serialize(in);
    const size_t arr = json.find("\"candidate_target_offsets\":[");
    ASSERT_NE(arr, std::string::npos) << json;
    // Three comma-separated numbers inside the array.
    const size_t close = json.find(']', arr);
    ASSERT_NE(close, std::string::npos);
    const std::string body = json.substr(arr, close - arr);
    EXPECT_EQ(std::count(body.begin(), body.end(), ','), 2);
}

TEST(TelemetrySerialize, EmptyCandidateArrayIsEmptyBrackets)
{
    const std::string json = serialize(base_input());
    EXPECT_NE(json.find("\"candidate_target_offsets\":[]"), std::string::npos) << json;
}

TEST(TelemetrySerialize, ReportsNeededSizeAndNeverOverflows)
{
    hk_tick_input in = base_input();
    char tiny[8] = {0};
    size_t need = serialize_tick(in, tiny, sizeof tiny);
    // Truncated: need exceeds cap, buffer is NUL-terminated within bounds.
    EXPECT_GE(need, sizeof tiny);
    EXPECT_EQ(tiny[sizeof tiny - 1], '\0');
}
