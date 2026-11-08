const std = @import("std");
const toml = @import("toml");
const accounts = @import("user_account");
const linux = std.os.linux;

pub const Settings = struct {
    executable: []u8,
    configuration: []u8,

    pub fn deinit(self: Settings, allocator: std.mem.Allocator) void {
        allocator.free(self.executable);
        allocator.free(self.configuration);
    }
};

pub const Selection = union(enum) {
    environment,
    disabled,
    configured: Settings,

    pub fn deinit(self: Selection, allocator: std.mem.Allocator) void {
        if (self == .configured) self.configured.deinit(allocator);
    }
};

pub fn loadForCaller(allocator: std.mem.Allocator, io: std.Io, environ: std.process.Environ) !Selection {
    const caller = try accounts.caller(allocator, environ);
    defer caller.deinit(allocator);
    const root = if (environ.getPosix("XDG_CONFIG_HOME")) |value| (if (value.len != 0) value else null) else null;
    if (root) |path| if (!std.fs.path.isAbsolute(path)) return error.InvalidAurlensSettings;
    const path = if (root) |directory|
        try std.fs.path.join(allocator, &.{ directory, "aurlens", "config.toml" })
    else
        try std.fs.path.join(allocator, &.{ caller.home, ".config", "aurlens", "config.toml" });
    defer allocator.free(path);
    return load(allocator, io, path, caller.uid);
}

pub fn load(allocator: std.mem.Allocator, io: std.Io, path: []const u8, owner: std.c.uid_t) !Selection {
    if (!std.fs.path.isAbsolute(path) or std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidAurlensSettings;
    const terminated = try allocator.dupeSentinel(u8, path, 0);
    defer allocator.free(terminated);
    const descriptor = std.c.open(terminated, .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOFOLLOW = true, .NONBLOCK = true });
    if (descriptor < 0) {
        if (std.c.errno(descriptor) == .NOENT) return .environment;
        return error.InvalidAurlensSettings;
    }
    const file: std.Io.File = .{ .handle = descriptor, .flags = .{ .nonblocking = true } };
    defer file.close(io);
    var status = std.mem.zeroes(linux.Statx);
    while (true) {
        switch (linux.errno(linux.statx(descriptor, "", linux.AT.EMPTY_PATH, .{ .TYPE = true, .MODE = true, .UID = true, .SIZE = true }, &status))) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.InvalidAurlensSettings,
        }
    }
    if (!status.mask.TYPE or !status.mask.MODE or !status.mask.UID or !status.mask.SIZE or status.mode & linux.S.IFMT != linux.S.IFREG or status.uid != owner or status.mode & 0o077 != 0 or status.size > 65_536)
        return error.InvalidAurlensSettings;
    const buffer = try allocator.alloc(u8, 65_537);
    defer allocator.free(buffer);
    const length = try file.readPositionalAll(io, buffer, 0);
    if (length == 0 or length > 65_536) return error.InvalidAurlensSettings;
    var parser = toml.Parser(toml.Table).init(allocator);
    defer parser.deinit();
    var parsed = parser.parseString(buffer[0..length]) catch return error.InvalidAurlensSettings;
    defer parsed.deinit();
    const header = parsed.value.get("shelly") orelse return .environment;
    const table = switch (header) {
        .table => |value| value,
        else => return error.InvalidAurlensSettings,
    };
    if (table.count() != 3) return error.InvalidAurlensSettings;
    const version = table.get("schema_version") orelse return error.InvalidAurlensSettings;
    if (version != .integer or version.integer != 1) return error.InvalidAurlensSettings;
    const enabled = table.get("enabled") orelse return error.InvalidAurlensSettings;
    if (enabled != .boolean) return error.InvalidAurlensSettings;
    const executable = table.get("executable") orelse return error.InvalidAurlensSettings;
    if (executable != .string or !std.fs.path.isAbsolute(executable.string) or executable.string.len > 4096 or std.mem.indexOfScalar(u8, executable.string, 0) != null)
        return error.InvalidAurlensSettings;
    for (executable.string) |byte| if (byte < 0x20 or byte == 0x7f) return error.InvalidAurlensSettings;
    if (!enabled.boolean) return .disabled;
    const owned_executable = try allocator.dupe(u8, executable.string);
    errdefer allocator.free(owned_executable);
    return .{ .configured = .{ .executable = owned_executable, .configuration = try allocator.dupe(u8, path) } };
}

test "AURLens settings share one private config and reject unsafe files" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);
    const path = try std.fs.path.join(allocator, &.{ root, "config.toml" });
    defer allocator.free(path);
    const contents = "[ai]\nbackend='codex'\nmodel='fixture'\n[shelly]\nschema_version=1\nenabled=true\nexecutable='/usr/bin/aurlens'\n";
    const file = try temporary.dir.createFile(io, "config.toml", .{});
    try file.setPermissions(io, .fromMode(0o600));
    file.close(io);
    try temporary.dir.writeFile(io, .{ .sub_path = "config.toml", .data = contents });
    const configured = try load(allocator, io, path, std.c.geteuid());
    defer configured.deinit(allocator);
    try std.testing.expectEqualStrings("/usr/bin/aurlens", configured.configured.executable);
    try std.testing.expectEqualStrings(path, configured.configured.configuration);
    try std.testing.expectError(error.InvalidAurlensSettings, load(allocator, io, path, std.c.geteuid() + 1));
    try temporary.dir.symLink(io, "config.toml", "link", .{});
    const link = try std.fs.path.join(allocator, &.{ root, "link" });
    defer allocator.free(link);
    try std.testing.expectError(error.InvalidAurlensSettings, load(allocator, io, link, std.c.geteuid()));
    try temporary.dir.writeFile(io, .{ .sub_path = "config.toml", .data = "[shelly]\nschema_version=1\nenabled=false\nexecutable='/usr/bin/aurlens'\n" });
    try std.testing.expectEqual(.disabled, try load(allocator, io, path, std.c.geteuid()));
}
