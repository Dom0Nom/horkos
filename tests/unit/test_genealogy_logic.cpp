/*
 * tests/unit/test_genealogy_logic.cpp
 * Role: Host-buildable unit tests for the process-genealogy pure helpers
 *       (sdk/include/horkos/genealogy_logic.h, signals 199/203). Exercises the
 *       reparent-suspect comparison (incl. the incomplete-data guard) and the
 *       token-integrity delta with synthetic values — no OS, no process tree.
 * Target platforms: host (any).
 * Interface: exercises hk_proc_reparent_suspect / hk_token_integrity_delta.
 */

#include <gtest/gtest.h>

#include "horkos/genealogy_logic.h"

TEST(GenealogyLogic, ReparentSuspectWhenCreatorDiffersFromParent)
{
    EXPECT_EQ(hk_proc_reparent_suspect(/*creator=*/4321, /*parent=*/1000), 1);
}

TEST(GenealogyLogic, NotSuspectWhenCreatorEqualsParent)
{
    EXPECT_EQ(hk_proc_reparent_suspect(1000, 1000), 0);
}

TEST(GenealogyLogic, ReparentIncompleteDataIsNotSuspect)
{
    EXPECT_EQ(hk_proc_reparent_suspect(0, 1000), 0);
    EXPECT_EQ(hk_proc_reparent_suspect(1000, 0), 0);
}

TEST(GenealogyLogic, TokenDeltaSignedDifference)
{
    /* Medium (0x2000) game under a High (0x3000) launcher: negative delta. */
    EXPECT_EQ(hk_token_integrity_delta(0x2000, 0x3000), -0x1000);
    /* Equal levels: zero. */
    EXPECT_EQ(hk_token_integrity_delta(0x3000, 0x3000), 0);
    /* Elevated game above launcher: positive. */
    EXPECT_EQ(hk_token_integrity_delta(0x3000, 0x2000), 0x1000);
}
