# causalontology-cpp - the C++ binding of the Causalontology standard.
# Zero dependencies. Builds the library, installs headers to
# include/causalontology/, installs the twenty-one JSON Schemas the library
# validates against to share/causalontology/spec/schema/, and exports a CMake
# package so consumers can:
#   find_package(causalontology CONFIG REQUIRED)
#   target_link_libraries(app PRIVATE causalontology::causalontology)
# The conformance runner is opt-in (-DCAUSALONTOLOGY_BUILD_CONFORMANCE=ON)
# and needs the repository's conformance/vectors alongside this tree.
cmake_minimum_required(VERSION 3.16)
project(causalontology VERSION 4.0.0 LANGUAGES CXX)

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

# ------------------------------------------------------------------ schemas
# validate_schema() reads the twenty-one *.schema.json documents at run time,
# so an install that ships only headers and a library is an install that
# fails at its consumer's first validate call. Ship the schemas too, and
# compile their installed location into the library as the last-resort
# lookup (src/schema.cpp documents the full order).
#
# The files are taken straight from the repository's normative spec/schema/;
# nothing is vendored into bindings/cpp/, so no copy here can drift from it.
# A tree that has no spec/schema/ next to it must say where the schemas are,
# and is told so at configure time rather than silently producing a package
# that cannot validate anything.
set(CAUSALONTOLOGY_SCHEMA_SOURCE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/../../spec/schema"
    CACHE PATH
    "Directory holding the twenty-one causalontology *.schema.json files")
file(GLOB CAUSALONTOLOGY_SCHEMA_FILES CONFIGURE_DEPENDS
    "${CAUSALONTOLOGY_SCHEMA_SOURCE_DIR}/*.schema.json")
list(LENGTH CAUSALONTOLOGY_SCHEMA_FILES CAUSALONTOLOGY_SCHEMA_COUNT)
if(NOT CAUSALONTOLOGY_SCHEMA_COUNT EQUAL 21)
    message(FATAL_ERROR
        "causalontology: found ${CAUSALONTOLOGY_SCHEMA_COUNT} *.schema.json "
        "files in '${CAUSALONTOLOGY_SCHEMA_SOURCE_DIR}', expected 21. The "
        "library cannot validate without them, so the build stops here "
        "rather than installing a package that fails at first use. Configure "
        "with -DCAUSALONTOLOGY_SCHEMA_SOURCE_DIR=<dir holding the twenty-one "
        "schemas> (in a full checkout that directory is <root>/spec/schema).")
endif()

set(CAUSALONTOLOGY_INSTALL_SCHEMADIR
    "${CMAKE_INSTALL_DATADIR}/causalontology/spec/schema")

install(FILES ${CAUSALONTOLOGY_SCHEMA_FILES}
    DESTINATION ${CAUSALONTOLOGY_INSTALL_SCHEMADIR})

# The absolute installed path, compiled in. Consumers that relocate the
# prefix afterwards (or install with a --prefix other than the configured
# one) set CAUSALONTOLOGY_SPEC, which overrides this.
target_compile_definitions(causalontology PRIVATE
    "CAUSALONTOLOGY_SCHEMA_DIR=\"${CMAKE_INSTALL_FULL_DATADIR}/causalontology/spec/schema\"")

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
# The package configuration exports causalontology_SCHEMA_DIR and refuses to
# be found at all if the twenty-one schemas are not sitting there - a broken
# or split package fails in the consumer's configure step, with the reason,
# instead of throwing on their first validate call in production.
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/causalontologyConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/causalontologyConfig.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/causalontology"
    PATH_VARS CAUSALONTOLOGY_INSTALL_SCHEMADIR)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/causalontologyConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/causalontologyConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/causalontology)

if(CAUSALONTOLOGY_BUILD_CONFORMANCE)
    add_executable(conformance conformance.cpp)
    target_link_libraries(conformance PRIVATE causalontology)
endif()
