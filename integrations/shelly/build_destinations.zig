const std = @import("std");
const Configuration = @import("shellybuild.zig").ShellyBuildConfiguration;
const Command = @import("user_account").caller_io.Command;

pub const Role = enum {
    build,
    source,
    package,
    log,

    pub fn flag(comptime self: Role) []const u8 {
        return switch (self) {
            .build => "--build-destination",
            .source => "--source-destination",
            .package => "--package-destination",
            .log => "--log-destination",
        };
    }

    pub fn field(comptime self: Role) []const u8 {
        return switch (self) {
            .build => "build",
            .source => "sources",
            .package => "packages",
            .log => "logs",
        };
    }

    fn variable(comptime self: Role) []const u8 {
        return switch (self) {
            .build => "BUILDDIR",
            .source => "SRCDEST",
            .package => "PKGDEST",
            .log => "LOGDEST",
        };
    }
};

pub const roles = std.meta.tags(Role);
pub const Overrides = @import("shellybuild.zig").DestinationConfiguration;

pub const Resolved = struct {
    work: []u8,
    packages: []const u8,
    sources: []const u8,
    logs: []const u8,

    pub fn path(self: Resolved, comptime role: Role) []const u8 {
        return switch (role) {
            .build => self.work,
            .source => self.sources,
            .package => self.packages,
            .log => self.logs,
        };
    }
};

pub fn applyOverrides(configuration: *Configuration, overrides: Overrides) !void {
    inline for (roles) |role| {
        if (@field(overrides, role.field())) |value| {
            if (!std.fs.path.isAbsolute(value) or std.mem.indexOfScalar(u8, value, 0) != null)
                return error.DestinationPathNotAbsolute;
        }
    }
    inline for (roles) |role| {
        if (@field(overrides, role.field())) |value|
            @field(configuration.destinations, role.field()) = try configuration.arena.allocator().dupe(u8, value);
    }
}

pub fn appendArguments(allocator: std.mem.Allocator, arguments: *std.ArrayList([]const u8), destinations: Resolved) !void {
    inline for (roles) |role| try arguments.appendSlice(allocator, &.{ role.flag(), destinations.path(role) });
}

pub const ExternalKind = enum { makepkg, chroot };

pub fn externalCommand(allocator: std.mem.Allocator, original: []const []const u8, destinations: Resolved, kind: ExternalKind) !Command {
    var arguments: std.ArrayList([]u8) = .empty;
    errdefer {
        for (arguments.items) |argument| allocator.free(argument);
        arguments.deinit(allocator);
    }
    try arguments.ensureTotalCapacity(allocator, original.len + roles.len + 2);
    arguments.appendAssumeCapacity(try allocator.dupe(u8, "/usr/bin/env"));
    inline for (roles) |role| {
        if (role != .build or kind == .makepkg)
            arguments.appendAssumeCapacity(try std.fmt.allocPrint(allocator, "{s}={s}", .{ role.variable(), destinations.path(role) }));
    }
    arguments.appendAssumeCapacity(try std.fmt.allocPrint(allocator, "SRCPKGDEST={s}", .{destinations.packages}));
    for (original) |argument| arguments.appendAssumeCapacity(try allocator.dupe(u8, argument));
    return .{ .argv = try arguments.toOwnedSlice(allocator) };
}

test "AURLens destination overrides preserve loaded build policy" {
    const allocator = std.testing.allocator;
    var configuration = try Configuration.initFromBuffers(allocator, "[build]\ncheck = false\n[package]\npackager = 'loaded policy'\n", null);
    defer configuration.deinit();
    try applyOverrides(configuration, .{ .build = "/scratch/work", .packages = "/scratch/packages", .sources = "/scratch/sources", .logs = "/scratch/logs" });
    try std.testing.expect(!configuration.build.check);
    try std.testing.expectEqualStrings("loaded policy", configuration.package.packager);
    try std.testing.expectEqualStrings("/scratch/work", configuration.destinations.build.?);
    try std.testing.expectError(error.DestinationPathNotAbsolute, applyOverrides(configuration, .{ .build = "relative", .packages = null, .sources = null, .logs = null }));
}

test "AURLens external destinations preserve argv boundaries and chroot work ownership" {
    const allocator = std.testing.allocator;
    var work = "/owned work".*;
    const outputs: Resolved = .{ .work = &work, .packages = "/owned packages", .sources = "/owned sources", .logs = "/owned logs" };
    for ([_]ExternalKind{ .makepkg, .chroot }) |kind| {
        var command = try externalCommand(allocator, &.{ "/tool path", "argument with spaces" }, outputs, kind);
        defer command.deinit(allocator);
        try std.testing.expectEqualStrings("/usr/bin/env", command.argv[0]);
        try std.testing.expectEqualStrings("/tool path", command.argv[command.argv.len - 2]);
        try std.testing.expectEqualStrings("argument with spaces", command.argv[command.argv.len - 1]);
        var found_work = false;
        var found_sources = false;
        var found_packages = false;
        var found_logs = false;
        var found_source_packages = false;
        for (command.argv) |argument| {
            found_work = found_work or std.mem.eql(u8, argument, "BUILDDIR=/owned work");
            found_sources = found_sources or std.mem.eql(u8, argument, "SRCDEST=/owned sources");
            found_packages = found_packages or std.mem.eql(u8, argument, "PKGDEST=/owned packages");
            found_logs = found_logs or std.mem.eql(u8, argument, "LOGDEST=/owned logs");
            found_source_packages = found_source_packages or std.mem.eql(u8, argument, "SRCPKGDEST=/owned packages");
        }
        try std.testing.expectEqual(kind == .makepkg, found_work);
        try std.testing.expect(found_sources and found_packages and found_logs and found_source_packages);
    }
}
