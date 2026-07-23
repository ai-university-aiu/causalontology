//! Build script for causalontology-zig (Zig 0.13.0).
//!
//! Exposes the library as a named module (consumers add this package by git
//! URL + hash in their build.zig.zon and `@import("causalontology")`), and
//! builds the conformance runner:
//!
//!   zig build                 # install the conformance executable
//!   zig build conformance     # run the 137-vector suite (from the repo root)

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The library module every downstream build imports.
    _ = b.addModule("causalontology", .{
        .root_source_file = b.path("src/causalontology.zig"),
    });

    // The conformance runner (must run with the repository root as cwd, or
    // with CAUSALONTOLOGY_ROOT pointing at it).
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
