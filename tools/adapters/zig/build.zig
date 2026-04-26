const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Shared library module
    const trustforge_mod = b.addModule("trustforge", .{
        .root_source_file = b.path("src/trustforge.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Zap middleware module (depends on the shared client)
    const zap_mod = b.addModule("trustforge_zap", .{
        .root_source_file = b.path("src/trustforge_zap.zig"),
        .target = target,
        .optimize = optimize,
    });
    zap_mod.addImport("trustforge", trustforge_mod);

    // Static library artifact for the shared client.
    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "trustforge",
        .root_module = trustforge_mod,
    });
    b.installArtifact(lib);

    // Tests
    const test_mod = b.createModule(.{
        .root_source_file = b.path("test/trustforge_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_mod.addImport("trustforge", trustforge_mod);
    test_mod.addImport("trustforge_zap", zap_mod);

    const tests = b.addTest(.{ .root_module = test_mod });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run trustforge adapter tests");
    test_step.dependOn(&run_tests.step);
}
