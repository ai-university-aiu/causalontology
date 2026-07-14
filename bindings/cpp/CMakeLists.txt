# causalontology-cpp - the C++ binding of the Causalontology standard.
# Zero dependencies. Builds the library, installs headers to
# include/causalontology/, and exports a CMake package so consumers can:
#   find_package(causalontology CONFIG REQUIRED)
#   target_link_libraries(app PRIVATE causalontology::causalontology)
# The conformance runner is opt-in (-DCAUSALONTOLOGY_BUILD_CONFORMANCE=ON)
# and needs the repository's conformance/vectors alongside this tree.
cmake_minimum_required(VERSION 3.16)
project(causalontology VERSION 1.0.2 LANGUAGES CXX)

option(CAUSALONTOLOGY_BUILD_CONFORMANCE "Build the conformance runner" OFF)

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
add_library(causalontology::causalontology ALIAS causalontology)

target_compile_features(causalontology PUBLIC cxx_std_17)
set_target_properties(causalontology PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    POSITION_INDEPENDENT_CODE ON)

target_include_directories(causalontology PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
    $<INSTALL_INTERFACE:include/causalontology>)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS causalontology
    EXPORT causalontologyTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

install(FILES
    src/json.hpp src/jcs.hpp src/sha2.hpp src/bignum.hpp src/ed25519.hpp
    src/canonical.hpp src/schema.hpp src/semantics.hpp src/signing.hpp
    src/store.hpp
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/causalontology)

install(EXPORT causalontologyTargets
    FILE causalontologyTargets.cmake
    NAMESPACE causalontology::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/causalontology)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/causalontologyConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/causalontologyConfig.cmake"
    "include(\"\${CMAKE_CURRENT_LIST_DIR}/causalontologyTargets.cmake\")\n")
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/causalontologyConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/causalontologyConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/causalontology)

if(CAUSALONTOLOGY_BUILD_CONFORMANCE)
    add_executable(conformance conformance.cpp)
    target_link_libraries(conformance PRIVATE causalontology)
endif()
