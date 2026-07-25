const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Main library module
    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/tinytcp.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .name = "tinytcp",
        .root_module = lib_mod,
    });
    b.installArtifact(lib);

    // Unit tests
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/tinytcp.zig"),
        .target = target,
        .optimize = optimize,
    });
    const lib_tests = b.addTest(.{
        .root_module = test_mod,
    });
    const run_tests = b.addRunArtifact(lib_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);

    // Fuzz tests
    const fuzz_mod = b.createModule(.{
        .root_source_file = b.path("src/fuzz_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    const fuzz_tests = b.addTest(.{
        .root_module = fuzz_mod,
    });
    const fuzz_step = b.step("fuzz", "Run fuzz tests");
    fuzz_step.dependOn(&b.addRunArtifact(fuzz_tests).step);

    // Demo executable
    const demo_mod = b.createModule(.{
        .root_source_file = b.path("examples/demo.zig"),
        .target = target,
        .optimize = optimize,
    });
    demo_mod.addImport("tinytcp", lib_mod);
    const demo_exe = b.addExecutable(.{
        .name = "demo",
        .root_module = demo_mod,
    });
    b.installArtifact(demo_exe);
    const run_demo = b.addRunArtifact(demo_exe);
    const demo_step = b.step("demo", "Run the TCP stack demo");
    demo_step.dependOn(&run_demo.step);

    // Minimal echo example (ReleaseSafe: default stack is large for Debug)
    const echo_optimize = if (optimize == .Debug) .ReleaseSafe else optimize;
    const echo_mod = b.createModule(.{
        .root_source_file = b.path("examples/echo.zig"),
        .target = target,
        .optimize = echo_optimize,
    });
    echo_mod.addImport("tinytcp", lib_mod);
    const echo_exe = b.addExecutable(.{
        .name = "echo",
        .root_module = echo_mod,
    });
    b.installArtifact(echo_exe);
    const run_echo = b.addRunArtifact(echo_exe);
    const echo_step = b.step("echo", "Run minimal TCP echo example");
    echo_step.dependOn(&run_echo.step);

    // TUN echo server (macOS utun interop test)
    const tun_mod = b.createModule(.{
        .root_source_file = b.path("examples/tun_echo_server.zig"),
        .target = target,
        .optimize = optimize,
    });
    tun_mod.addImport("tinytcp", lib_mod);
    const tun_exe = b.addExecutable(.{
        .name = "tun-echo",
        .root_module = tun_mod,
    });
    b.installArtifact(tun_exe);
    const run_tun = b.addRunArtifact(tun_exe);
    const tun_step = b.step("tun-echo", "Run TUN echo server (requires sudo)");
    tun_step.dependOn(&run_tun.step);

    // TUN interop test server (Linux, for Docker-based testing)
    const tun_test_mod = b.createModule(.{
        .root_source_file = b.path("tests/tun_interop/tun_test_server.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    tun_test_mod.addImport("tinytcp", lib_mod);
    const tun_test_exe = b.addExecutable(.{
        .name = "tun-test",
        .root_module = tun_test_mod,
    });
    b.installArtifact(tun_test_exe);
    const tun_test_step = b.step("tun-test", "Build TUN interop test server (Linux)");
    tun_test_step.dependOn(&tun_test_exe.step);

    // Embedded build check: verify library compiles for bare-metal ARM (Cortex-M3)
    const embedded_target = b.resolveTargetQuery(.{
        .cpu_arch = .thumb,
        .os_tag = .freestanding,
        .abi = .eabi,
        .cpu_model = .{ .explicit = &std.Target.arm.cpu.cortex_m3 },
    });
    const embedded_mod = b.createModule(.{
        .root_source_file = b.path("src/tinytcp.zig"),
        .target = embedded_target,
        .optimize = .ReleaseSmall,
    });
    const embedded_lib = b.addLibrary(.{
        .name = "tinytcp-embedded",
        .root_module = embedded_mod,
    });
    const embedded_step = b.step("embedded-check", "Verify library compiles for thumb-freestanding-eabi (Cortex-M3)");
    embedded_step.dependOn(&embedded_lib.step);

    // Embedded smoke test: bare-metal binary for QEMU (Cortex-M3, semihosting)
    const smoke_target = b.resolveTargetQuery(.{
        .cpu_arch = .thumb,
        .os_tag = .freestanding,
        .abi = .eabi,
        .cpu_model = .{ .explicit = &std.Target.arm.cpu.cortex_m3 },
    });
    const smoke_tinytcp_mod = b.createModule(.{
        .root_source_file = b.path("src/tinytcp.zig"),
        .target = smoke_target,
        .optimize = .ReleaseSmall,
    });
    const smoke_mod = b.createModule(.{
        .root_source_file = b.path("tests/embedded/smoke_test.zig"),
        .target = smoke_target,
        .optimize = .ReleaseSmall,
    });
    smoke_mod.addImport("tinytcp", smoke_tinytcp_mod);
    smoke_mod.addAssemblyFile(b.path("tests/embedded/startup.s"));
    const smoke_exe = b.addExecutable(.{
        .name = "embedded-smoke",
        .root_module = smoke_mod,
    });
    smoke_exe.setLinkerScript(b.path("tests/embedded/mps2-an385.ld"));
    b.installArtifact(smoke_exe);
    const smoke_step = b.step("embedded-smoke", "Build bare-metal smoke test for QEMU (qemu-system-arm -machine mps2-an385 -semihosting)");
    smoke_step.dependOn(&smoke_exe.step);

    // Embedded network interop test: QEMU + TAP with LAN9118 NIC
    const net_tinytcp_mod = b.createModule(.{
        .root_source_file = b.path("src/tinytcp.zig"),
        .target = smoke_target,
        .optimize = .ReleaseSmall,
    });
    const net_mod = b.createModule(.{
        .root_source_file = b.path("tests/embedded/net_interop.zig"),
        .target = smoke_target,
        .optimize = .ReleaseSmall,
    });
    net_mod.addImport("tinytcp", net_tinytcp_mod);
    net_mod.addAssemblyFile(b.path("tests/embedded/startup.s"));
    const net_exe = b.addExecutable(.{
        .name = "embedded-net",
        .root_module = net_mod,
    });
    net_exe.setLinkerScript(b.path("tests/embedded/mps2-an385.ld"));
    const install_net = b.addInstallArtifact(net_exe, .{});
    const net_step = b.step("embedded-net", "Build QEMU+TAP network interop test (LAN9118, ARP/ICMP/TCP echo)");
    net_step.dependOn(&install_net.step);
}
