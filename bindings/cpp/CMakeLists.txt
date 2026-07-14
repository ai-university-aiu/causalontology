# CMakeLists.txt - a minimal build for downstream consumers of
# causalontology-cpp. Not used by run_conformance.sh (which invokes g++
# directly); provided so the library can be embedded with add_subdirectory.
cmake_minimum_required(VERSION 3.16)
project(causalontology_cpp CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(causalontology
    src/json.cpp
    src/jcs.cpp
    src/sha2.cpp
    src/bignum.cpp
    src/ed25519.cpp
    src/canonical.cpp
    src/schema.cpp
    src/semantics.cpp
    src/signing.cpp
    src/store.cpp)
target_include_directories(causalontology PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(conformance conformance.cpp)
target_link_libraries(conformance PRIVATE causalontology)
