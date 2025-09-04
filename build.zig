const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardOptimizeOption(.{});

    const main = b.addModule("zcoff", .{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = mode,
    });

    const exe = b.addExecutable(.{
        .name = "zcoff",
        .root_module = main,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
