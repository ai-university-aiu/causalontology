//! Repository-root Zig build for the Causalontology standard.
//!
//! Thin manifest: it exposes the library as the module "causalontology"
//! (root source under bindings/zig/src/) so a downstream build can do
//!
//!   const dep = b.dependency("causalontology", .{});
//!   exe.root_module.addImport("causalontology", dep.module("causalontology"));
//!
//! after `zig fetch --save <this repo's tag tarball>`. The conformance
//! runner and the local development build live in bindings/zig/build.zig.

const std = @import("std");

pub fn build(b: *std.Build) void {
    _ = b.addModule("causalontology", .{
        .root_source_file = b.path("bindings/zig/src/causalontology.zig"),
    });
}
