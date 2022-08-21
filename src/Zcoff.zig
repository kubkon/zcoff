const Zcoff = @This();

const std = @import("std");
const fs = std.fs;

const Allocator = std.mem.Allocator;

allocator: Allocator,
file: ?fs.File = null,

pub fn init(allocator: Allocator) Zcoff {
    return .{ .allocator = allocator };
}

pub fn deinit(self: *Zcoff) void {
    _ = self;
}

pub fn parse(self: *Zcoff, file: fs.File) !void {
    self.file = file;
}

pub fn printHeaders(self: *Zcoff, writer: anytype) !void {
    _ = self;
    _ = writer;
    return error.Todo;
}
