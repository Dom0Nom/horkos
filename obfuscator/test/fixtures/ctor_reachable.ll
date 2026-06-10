; Fixture for the ctor-reachable guard test.
; @secret is annotated with hk_obfuscate and references @.str_secret.
; @ctor_fn is a global constructor (registered in llvm.global_ctors at priority 0)
; that calls @secret — making @.str_secret transitively reachable from a ctor.
; The pass must NOT encrypt @.str_secret because the ctor may run before hk_strdec.
;
; @safe_fn is also annotated and references @.str_safe, but is NOT reachable from
; any ctor — the pass MUST encrypt @.str_safe.

source_filename = "ctor_reachable"
target datalayout = "e-m:o-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-apple-macosx15.0.0"

@.str_secret = private unnamed_addr constant [11 x i8] c"ctor-reach\00", align 1
@.str_safe   = private unnamed_addr constant [9 x i8] c"safe-str\00", align 1
@.str.ann    = private unnamed_addr constant [13 x i8] c"hk_obfuscate\00", section "llvm.metadata"
@.str.file   = private unnamed_addr constant [18 x i8] c"ctor_reachable.ll\00", section "llvm.metadata"

@llvm.global.annotations = appending global [2 x { ptr, ptr, ptr, i32, ptr }] [
  { ptr, ptr, ptr, i32, ptr } { ptr @secret,   ptr @.str.ann, ptr @.str.file, i32 1, ptr null },
  { ptr, ptr, ptr, i32, ptr } { ptr @safe_fn,  ptr @.str.ann, ptr @.str.file, i32 2, ptr null }
], section "llvm.metadata"

; Annotated function whose string must NOT be encrypted (ctor-reachable).
define i32 @secret(i32 %x) {
entry:
  %p = getelementptr inbounds [11 x i8], ptr @.str_secret, i32 0, i32 0
  %c = load i8, ptr %p
  %v = sext i8 %c to i32
  %r = add i32 %x, %v
  ret i32 %r
}

; Annotated function whose string MUST be encrypted (not ctor-reachable).
define i32 @safe_fn(i32 %x) {
entry:
  %p = getelementptr inbounds [9 x i8], ptr @.str_safe, i32 0, i32 0
  %c = load i8, ptr %p
  %v = sext i8 %c to i32
  %r = add i32 %x, %v
  ret i32 %r
}

; Global constructor that calls @secret, making @.str_secret ctor-reachable.
define void @ctor_fn() {
entry:
  %dummy = call i32 @secret(i32 0)
  ret void
}

@llvm.global_ctors = appending global [1 x { i32, ptr, ptr }] [
  { i32, ptr, ptr } { i32 0, ptr @ctor_fn, ptr null }
]
