const std = @import("std");

pub const Digest = [64]u8;
const max_report_bytes = 4 * 1024 * 1024;

const Evidence = struct { path: []const u8, line: usize, quote: []const u8 };
pub const Finding = struct {
    rule_id: []const u8,
    source: []const u8,
    severity: enum { info, review, block },
    message: []const u8,
    evidence: []const Evidence,
};
const Decision = enum(u8) { no_findings = 0, manual_review = 1, blocked = 2, incomplete = 3 };
const Report = struct {
    schema_version: u32,
    decision: Decision,
    exit_code: u8,
    snapshot_digest: ?[]const u8,
    revalidated: bool,
    findings: []const Finding,
    coverage: struct { complete: bool, policy: []const u8, issues: []const []const u8 },
    ai: struct { state: enum { not_run, complete, incomplete } },
};

pub const Review = struct {
    parsed: std.json.Parsed(Report),
    digest: Digest,

    pub fn deinit(self: *Review) void {
        self.parsed.deinit();
        self.* = undefined;
    }

    pub fn findings(self: *const Review) []const Finding {
        return self.parsed.value.findings;
    }
};

fn digest(text: []const u8) !Digest {
    if (text.len != 64) return error.InvalidAurlensReport;
    for (text) |byte| if (!(byte >= '0' and byte <= '9') and !(byte >= 'a' and byte <= 'f'))
        return error.InvalidAurlensReport;
    return text[0..64].*;
}

fn plain(text: []const u8) bool {
    for (text) |byte| if ((byte < 32 and byte != '\t' and byte != '\n') or byte == 127) return false;
    return std.unicode.utf8ValidateSlice(text);
}

pub fn parseReview(allocator: std.mem.Allocator, bytes: []const u8, process_exit: u8, ai_requested: bool) !Review {
    if (bytes.len > max_report_bytes) return error.InvalidAurlensReport;
    const parsed = std.json.parseFromSlice(Report, allocator, bytes, .{ .ignore_unknown_fields = true }) catch
        return error.InvalidAurlensReport;
    errdefer parsed.deinit();
    const report = parsed.value;
    if (report.schema_version != 1 or report.exit_code != process_exit or
        report.exit_code != @backingInt(report.decision)) return error.InvalidAurlensReport;
    if (report.decision == .incomplete) return error.AurlensIncomplete;
    if (report.decision == .blocked) return error.AurlensBlocked;
    if (!report.revalidated or !report.coverage.complete or report.coverage.issues.len != 0 or
        !std.mem.eql(u8, report.coverage.policy, "whole-checkout-v1") or
        report.ai.state == .incomplete or (ai_requested and report.ai.state != .complete))
        return error.AurlensIncomplete;
    const binding = try digest(report.snapshot_digest orelse return error.InvalidAurlensReport);
    var has_review = false;
    for (report.findings) |finding| {
        if (!plain(finding.message) or !plain(finding.rule_id) or !plain(finding.source))
            return error.InvalidAurlensReport;
        switch (finding.severity) {
            .block => return error.InvalidAurlensReport,
            .review => has_review = true,
            .info => {},
        }
        for (finding.evidence) |evidence| {
            if (evidence.line == 0 or !plain(evidence.path) or !plain(evidence.quote))
                return error.InvalidAurlensReport;
        }
    }
    if (has_review != (report.decision == .manual_review)) return error.InvalidAurlensReport;
    return .{ .parsed = parsed, .digest = binding };
}

pub fn verifyResponse(allocator: std.mem.Allocator, bytes: []const u8, process_exit: u8, expected: Digest) !void {
    if (bytes.len > max_report_bytes or process_exit != 0) return error.AurlensVerificationFailed;
    const Wire = struct {
        schema_version: u32,
        operation: []const u8,
        status: enum { matched, changed, incomplete },
        exit_code: u8,
        expected_digest: []const u8,
        snapshot_digest: ?[]const u8,
        issues: []const []const u8,
    };
    const parsed = std.json.parseFromSlice(Wire, allocator, bytes, .{ .ignore_unknown_fields = true }) catch
        return error.InvalidAurlensReport;
    defer parsed.deinit();
    const report = parsed.value;
    if (report.schema_version != 1 or !std.mem.eql(u8, report.operation, "verify_snapshot") or
        report.status != .matched or report.exit_code != 0 or report.issues.len != 0 or
        !std.mem.eql(u8, report.expected_digest, &expected) or
        !std.mem.eql(u8, report.snapshot_digest orelse return error.InvalidAurlensReport, &expected))
        return error.AurlensVerificationFailed;
}

const clean =
    \\{"schema_version":1,"decision":"no_findings","exit_code":0,
    \\ "snapshot_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    \\ "revalidated":true,"findings":[],
    \\ "coverage":{"complete":true,"policy":"whole-checkout-v1","issues":[]},
    \\ "ai":{"state":"not_run"}}
;

test "AURLens accepts only complete matching scan decisions" {
    var review = try parseReview(std.testing.allocator, clean, 0, false);
    defer review.deinit();
    try std.testing.expectEqual(@as(Digest, @splat('a')), review.digest);
    try std.testing.expectError(error.InvalidAurlensReport, parseReview(std.testing.allocator, clean, 2, false));
    try std.testing.expectError(error.AurlensIncomplete, parseReview(std.testing.allocator, clean, 0, true));
    try std.testing.expectError(error.InvalidAurlensReport, parseReview(std.testing.allocator, "{}", 0, false));
    try std.testing.expectError(error.InvalidAurlensReport, parseReview(std.testing.allocator, clean ++ "{}", 0, false));
}

test "AURLens refuses unsupported coverage and inconsistent findings" {
    const allocator = std.testing.allocator;
    const cases = .{
        .{ "whole-checkout-v1", "declared-inputs-v1" },
        .{ "\"revalidated\":true", "\"revalidated\":false" },
        .{ "\"state\":\"not_run\"", "\"state\":\"incomplete\"" },
        .{ "\"decision\":\"no_findings\",\"exit_code\":0", "\"decision\":\"manual_review\",\"exit_code\":1" },
    };
    inline for (cases) |case| {
        const changed = try std.mem.replaceOwned(u8, allocator, clean, case[0], case[1]);
        defer allocator.free(changed);
        if (parseReview(allocator, changed, if (std.mem.eql(u8, case[1], cases[3][1])) 1 else 0, false)) |value| {
            var review = value;
            review.deinit();
            return error.UnsafeReportAccepted;
        } else |_| {}
    }
}

test "AURLens verification binds both report digests and process status" {
    const bytes =
        \\{"schema_version":1,"operation":"verify_snapshot","status":"matched","exit_code":0,
        \\ "expected_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\ "snapshot_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","issues":[]}
    ;
    try verifyResponse(std.testing.allocator, bytes, 0, @as(Digest, @splat('a')));
    try std.testing.expectError(error.AurlensVerificationFailed, verifyResponse(std.testing.allocator, bytes, 3, @as(Digest, @splat('a'))));
    try std.testing.expectError(error.AurlensVerificationFailed, verifyResponse(std.testing.allocator, bytes, 0, @as(Digest, @splat('b'))));
}
