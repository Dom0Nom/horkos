# ac/CMakeLists.txt
# Builds hk_ac static library. Depends only on hk_platform.

add_library(hk_ac STATIC src/ac.cpp)
target_include_directories(hk_ac PUBLIC include)
target_link_libraries(hk_ac PUBLIC hk_platform)
