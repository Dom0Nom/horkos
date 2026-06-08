/*
 * obfuscator/test/fixtures/fixture.c
 * Role: Source for fixture.ll. `secret` is opted into obfuscation via the
 *       annotate attribute and exercises a branch (CFF + opaque) and a string
 *       literal (string encryption). `plain` is NOT annotated and must come out
 *       of every pass byte-for-byte unchanged — the test that proves opt-in
 *       actually gates the transform.
 * Regenerate fixture.ll with the PINNED llvm@19 clang (see test/README.md);
 * IR text format drifts across LLVM majors.
 */

__attribute__((annotate("hk_obfuscate")))
int secret(int x) {
    const char *msg = "licence-ok";
    if (x > 10)
        return (int)msg[0] + x;
    return x - 1;
}

int plain(int x) {
    if (x > 5)
        return x + 2;
    return x - 2;
}
