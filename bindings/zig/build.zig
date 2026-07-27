//! Build script for causalontology-zig (Zig 0.13.0).
//!
//! Exposes the library as a named module (consumers add this package by git
//! URL + hash in their build.zig.zon and `@import("causalontology")`), and
//! builds the conformance runner:
//!
//!   zig build                 # install the conformance executable
//!   zig build conformance     # run the 137-vector suite
//!
//! The runner needs the vectors, which it finds by walking up from the
//! working directory or from its own executable, so the step works from a
//! checkout and from inside a fetched package alike. It needs nothing at all
//! for the schemas: those are compiled into the library.

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The library module every downstream build imports.
    _ = b.addModule("causalontology", .{
        .root_source_file = b.path("src/causalontology.zig"),
    });

    // The conformance runner. It locates conformance/vectors itself
    // (CAUSALONTOLOGY_ROOT, else a walk up from the working directory, else a
    // walk up from the executable) and validates against the schemas compiled
    // into the library, so it proves the artifact, not a checkout.
    const exe = b.addExecutable(.{
        .name = "conformance",
        .root_source_file = b.path("conformance.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("conformance", "Run the 137-vector Causalontology conformance suite");
    run_step.dependOn(&run_cmd.step);
}
