# daemon/macos/CMakeLists.txt
# Role: Build the horkosd launchd/XPC daemon for macOS.
#       Produces the `horkosd` executable that launchd starts via
#       com.horkos.daemon.plist.  No anti-cheat logic yet — this is the
#       Phase 4 Step 4.4 bring-up skeleton.
# Target platforms: macOS only (guarded by APPLE check in parent).
# Interface: standalone executable; no Horkos library headers required at
#            this stage.

if(NOT APPLE)
    return()
endif()

add_executable(horkosd horkosd.cpp)

target_compile_options(horkosd PRIVATE
    -Wall
    -Wextra
    -Werror
)

# xpc/xpc.h and dispatch/dispatch.h ship inside the macOS SDK.  Linking
# against Foundation brings in libSystem, the XPC runtime, and libdispatch
# through the umbrella framework — no separate -lxpc or -ldispatch needed.
# Reference: Xcode SDK headers, WWDC 2012 session 241.
target_link_libraries(horkosd PRIVATE
    "-framework Foundation"
)

# Installation path mirrors what the plist's ProgramArguments entry expects.
# Adjust DESTINATION for packaging; the placeholder matches the plist comment.
install(TARGETS horkosd
    RUNTIME DESTINATION libexec
)
