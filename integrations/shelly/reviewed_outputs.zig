const std = @import("std");
const caller_io = @import("user_account").caller_io;
const builder = @import("builder/builder.zig");
const DestinationConfiguration = @import("shellybuild.zig").DestinationConfiguration;
const pathIsInside = @import("review_integrity.zig").pathIsInside;

pub const ReviewedOutputs = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    environ: std.process.Environ,
    root: []u8,
    work: []u8,
    sources: []u8,
    packages: []u8,
    logs: []u8,

    pub fn create(allocator: std.mem.Allocator, io: std.Io, environ: std.process.Environ, recipe: []const u8, cache_root: []const u8, package_base: []const u8, preferences: DestinationConfiguration) !ReviewedOutputs {
        const canonical_recipe = try std.Io.Dir.cwd().realPathFileAlloc(io, recipe, allocator);
        defer allocator.free(canonical_recipe);
        const parent = try std.fs.path.join(allocator, &.{ cache_root, ".reviewed-outputs" });
        defer allocator.free(parent);
        const root = try builder.uniqueWorkDirectory(allocator, io, parent, package_base);
        defer allocator.free(root);
        const work = try child(allocator, io, preferences.build orelse root, std.fs.path.basename(root), preferences.build == null, "work");
        errdefer allocator.free(work);
        const sources = try child(allocator, io, preferences.sources orelse root, std.fs.path.basename(root), preferences.sources == null, "sources");
        errdefer allocator.free(sources);
        const packages = try canonicalDestination(allocator, io, preferences.packages orelse root);
        defer allocator.free(packages);
        const package_path = if (preferences.packages != null) try allocator.dupe(u8, packages) else try std.fs.path.join(allocator, &.{ packages, "packages" });
        errdefer allocator.free(package_path);
        const logs = try canonicalDestination(allocator, io, preferences.logs orelse root);
        defer allocator.free(logs);
        const log_path = if (preferences.logs != null) try allocator.dupe(u8, logs) else try std.fs.path.join(allocator, &.{ logs, "logs" });
        errdefer allocator.free(log_path);
        for ([_]?[]const u8{ preferences.build, preferences.sources, preferences.packages, preferences.logs }) |configured| {
            if (configured) |path| {
                const canonical = try canonicalDestination(allocator, io, path);
                defer allocator.free(canonical);
                try requireOutside(canonical_recipe, canonical);
            }
        }
        const canonical_root = try canonicalDestination(allocator, io, root);
        defer allocator.free(canonical_root);
        for ([_][]const u8{ canonical_root, work, sources, package_path, log_path }) |path| try requireOutside(canonical_recipe, path);
        try caller_io.makePath(allocator, io, environ, parent);
        try caller_io.run(allocator, io, environ, &.{ "/usr/bin/mkdir", "-m", "700", "--", canonical_root }, null, null);
        errdefer caller_io.deleteTree(allocator, io, environ, canonical_root) catch {};
        try caller_io.makePath(allocator, io, environ, std.fs.path.dirname(work).?);
        try caller_io.run(allocator, io, environ, &.{ "/usr/bin/mkdir", "-m", "700", "--", work }, null, null);
        errdefer caller_io.deleteTree(allocator, io, environ, work) catch {};
        try caller_io.makePath(allocator, io, environ, std.fs.path.dirname(sources).?);
        try caller_io.run(allocator, io, environ, &.{ "/usr/bin/mkdir", "-m", "700", "--", sources }, null, null);
        errdefer caller_io.deleteTree(allocator, io, environ, sources) catch {};
        try caller_io.makePath(allocator, io, environ, package_path);
        try caller_io.makePath(allocator, io, environ, log_path);
        return .{ .allocator = allocator, .io = io, .environ = environ, .root = try allocator.dupe(u8, canonical_root), .work = work, .sources = sources, .packages = package_path, .logs = log_path };
    }

    pub fn deinit(self: *ReviewedOutputs) void {
        caller_io.deleteTree(self.allocator, self.io, self.environ, self.work) catch {};
        caller_io.deleteTree(self.allocator, self.io, self.environ, self.sources) catch {};
        caller_io.deleteTree(self.allocator, self.io, self.environ, self.root) catch {};
        for ([_][]u8{ self.root, self.work, self.sources, self.packages, self.logs }) |path| self.allocator.free(path);
        self.* = undefined;
    }

    pub fn resolve(self: *const ReviewedOutputs, package_base: []const u8) !Resolved {
        return .{
            .work = try builder.uniqueWorkDirectory(self.allocator, self.io, self.work, package_base),
            .packages = self.packages,
            .sources = self.sources,
            .logs = self.logs,
        };
    }
};

pub const Resolved = @import("build_destinations.zig").Resolved;

fn child(allocator: std.mem.Allocator, io: std.Io, base: []const u8, operation_name: []const u8, use_default: bool, name: []const u8) ![]u8 {
    const canonical = try canonicalDestination(allocator, io, base);
    defer allocator.free(canonical);
    if (use_default) return std.fs.path.join(allocator, &.{ canonical, name });
    const unique_name = try std.fmt.allocPrint(allocator, "{s}-{s}", .{ operation_name, name });
    defer allocator.free(unique_name);
    return std.fs.path.join(allocator, &.{ canonical, unique_name });
}

fn requireOutside(recipe: []const u8, destination: []const u8) !void {
    if (std.mem.eql(u8, recipe, destination) or pathIsInside(recipe, destination) or pathIsInside(destination, recipe) or std.mem.eql(u8, destination, "/"))
        return error.UnsafeReviewedOutputDestination;
}

fn canonicalDestination(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    if (!std.fs.path.isAbsolute(path)) return error.UnsafeReviewedOutputDestination;
    const normalized = try allocator.dupe(u8, std.mem.trimEnd(u8, path, "/"));
    defer allocator.free(normalized);
    if (normalized.len == 0) return allocator.dupe(u8, "/");
    var existing: []const u8 = normalized;
    while (true) {
        const canonical = std.Io.Dir.cwd().realPathFileAlloc(io, existing, allocator) catch |err| switch (err) {
            error.FileNotFound => {
                if (std.Io.Dir.cwd().statFile(io, existing, .{ .follow_symlinks = false })) |status| {
                    if (status.kind == .sym_link) return error.UnsafeReviewedOutputDestination;
                } else |stat_error| switch (stat_error) {
                    error.FileNotFound => {},
                    else => return stat_error,
                }
                existing = std.fs.path.dirname(existing) orelse return err;
                continue;
            },
            else => return err,
        };
        defer allocator.free(canonical);
        if (existing.len == normalized.len) return allocator.dupe(u8, canonical);
        return std.fs.path.resolve(allocator, &.{ canonical, std.mem.trimStart(u8, normalized[existing.len..], "/") });
    }
}
