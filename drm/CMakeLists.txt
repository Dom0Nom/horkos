# drm/CMakeLists.txt
# Builds hk_drm static library. Depends only on hk_platform.

add_library(hk_drm STATIC src/drm.cpp)
target_include_directories(hk_drm PUBLIC include)
target_link_libraries(hk_drm PUBLIC hk_platform)
