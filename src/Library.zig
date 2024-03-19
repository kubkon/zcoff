gpa: Allocator,
data: []const u8,

pub fn isLibrary(data: []const u8) bool {
    return std.mem.eql(u8, data[0..magic.len], magic);
}

const magic = "!<arch>\n";

const std = @import("std");

const Allocator = std.mem.Allocator;
const Library = @This();
