# drm/CMakeLists.txt
# Builds hk_drm static library. Ed25519 licence verification uses libsodium
# (found below); on a host without it the find fails loudly rather than
# silently degrading the DRM check.

add_library(hk_drm STATIC src/drm.cpp)
target_include_directories(hk_drm PUBLIC include)

# libsodium for Ed25519 (crypto_sign_verify_detached). Prefer pkg-config; fall
# back to a plain find_library (brew installs the lib + headers under
# /usr/local or /opt/homebrew). A real cross-platform build static-links it.
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(SODIUM QUIET libsodium)
endif()
if(NOT SODIUM_FOUND)
    find_path(SODIUM_INCLUDE_DIRS sodium.h
        PATHS /usr/local/include /opt/homebrew/include /usr/include)
    find_library(SODIUM_LIBRARIES NAMES sodium libsodium
        PATHS /usr/local/lib /opt/homebrew/lib /usr/lib)
endif()
if(NOT SODIUM_LIBRARIES)
    message(FATAL_ERROR "libsodium not found (needed by hk_drm for Ed25519). "
                        "Install it (brew install libsodium / apt install libsodium-dev).")
endif()

# PUBLIC so the host unit test (which signs licences with libsodium to exercise
# drm_validate) inherits the include path + link without re-finding the lib.
target_include_directories(hk_drm PUBLIC ${SODIUM_INCLUDE_DIRS})
target_link_libraries(hk_drm PUBLIC hk_platform ${SODIUM_LIBRARIES})
