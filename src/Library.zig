gpa: Allocator,
data: []const u8,

symdef: Symdef = .{},
symdef_sorted: SymdefSorted = .{},

pub fn isLibrary(data: []const u8) bool {
    return std.mem.eql(u8, data[0..magic.len], magic);
}

pub fn deinit(self: *Library) void {
    self.symdef.deinit(self.gpa);
    self.symdef_sorted.deinit(self.gpa);
}

pub fn parse(self: *Library) !void {
    var stream = std.io.fixedBufferStream(self.data);
    const reader = stream.reader();
    _ = try reader.readBytesNoEof(magic.len);

    var check: packed struct {
        symdef: bool = false,
        symdef_sorted: bool = false,
        longnames: bool = false,
    } = .{};
    var member_count: usize = 0;

    while (true) {
        if (!std.mem.isAligned(stream.pos, 2)) stream.pos += 1;
        if (stream.pos >= self.data.len) break;

        defer member_count += 1;

        const pos = stream.pos;
        _ = pos;
        const hdr = try reader.readStruct(Header);

        if (!std.mem.eql(u8, &hdr.end, end)) return error.InvalidHeaderDelimiter;

        const size = try hdr.getSize();
        std.debug.print("size={d}\n", .{size});
        defer {
            _ = stream.seekBy(size) catch {};
        }

        if (hdr.isLinkerMember()) {
            if (!check.symdef) {
                if (member_count != 0) return error.InvalidLinkerMemberPosition;
                try self.symdef.parse(self.gpa, self.data[stream.pos..][0..size]);
                check.symdef = true;
                continue;
            }

            if (!check.symdef_sorted) {
                if (member_count != 1) return error.InvalidLinkerMemberPosition;
                try self.symdef_sorted.parse(self.gpa, self.data[stream.pos..][0..size]);
                check.symdef_sorted = true;
                continue;
            }

            return error.InvalidLinkerMemberPosition;
        }
    }
}

fn genMemberName(comptime name: []const u8) *const [16]u8 {
    assert(name.len <= 16);
    const padding = 16 - name.len;
    return name ++ &[_]u8{' '} ** padding;
}

const Header = extern struct {
    name: [16]u8,
    date: [12]u8,
    user_id: [6]u8,
    group_id: [6]u8,
    mode: [8]u8,
    size: [10]u8,
    end: [2]u8,

    fn getSize(hdr: *const Header) !u32 {
        const value = std.mem.trimRight(u8, &hdr.size, " ");
        return std.fmt.parseInt(u32, value, 10);
    }

    fn isLinkerMember(hdr: *const Header) bool {
        return std.mem.eql(u8, &hdr.name, linker_member);
    }

    fn isLongnamesMember(hdr: *const Header) bool {
        return std.mem.eql(u8, &hdr.name, longnames_member);
    }
};

const Symdef = struct {
    entries: std.ArrayListUnmanaged(Entry) = .{},

    fn deinit(tab: *Symdef, allocator: Allocator) void {
        tab.entries.deinit(allocator);
    }

    fn parse(tab: *Symdef, allocator: Allocator, data: []const u8) !void {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();

        const num = try reader.readInt(u32, .big);
        try tab.entries.ensureTotalCapacityPrecise(allocator, num);

        for (0..num) |_| {
            const file = try reader.readInt(u32, .big);
            tab.entries.appendAssumeCapacity(.{ .name = undefined, .file = file });
        }

        const strtab_off = (num + 1) * @sizeOf(u32);
        const strtab_len = data.len - strtab_off;
        const strtab = data[strtab_off..];

        var next: usize = 0;
        var i: usize = 0;
        while (i < strtab_len) : (next += 1) {
            const name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(strtab.ptr + i)), 0);
            tab.entries.items[next].name = name;
            i += name.len + 1;
        }
    }

    const Entry = struct {
        /// Symbol name
        name: [:0]const u8,
        /// Offset of the object member
        file: u32,
    };
};

const SymdefSorted = struct {
    members: std.ArrayListUnmanaged(u32) = .{},
    indexes: std.ArrayListUnmanaged(Entry) = .{},

    fn deinit(tab: *SymdefSorted, allocator: Allocator) void {
        tab.members.deinit(allocator);
        tab.indexes.deinit(allocator);
    }

    fn parse(tab: *SymdefSorted, allocator: Allocator, data: []const u8) !void {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();

        const num_members = try reader.readInt(u32, .little);
        try tab.members.ensureTotalCapacityPrecise(allocator, num_members);

        for (0..num_members) |_| {
            const offset = try reader.readInt(u32, .little);
            tab.members.appendAssumeCapacity(offset);
        }

        const num_indexes = try reader.readInt(u32, .little);
        try tab.indexes.ensureTotalCapacityPrecise(allocator, num_indexes);

        for (0..num_indexes) |_| {
            const index = try reader.readInt(u16, .little);
            tab.indexes.appendAssumeCapacity(.{ .index = index, .name = undefined });
        }

        const strtab_off = 2 * @sizeOf(u32) + num_members * @sizeOf(u32) + num_indexes * @sizeOf(u16);
        const strtab_len = data.len - strtab_off;
        const strtab = data[strtab_off..];

        var next: usize = 0;
        var i: usize = 0;
        while (i < strtab_len) : (next += 1) {
            const name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(strtab.ptr + i)), 0);
            tab.indexes.items[next].name = name;
            i += name.len + 1;
        }
    }

    const Entry = struct {
        /// Index into the members table.
        index: u16,
        /// Name of the symbol
        name: [:0]const u8,
    };
};

const magic = "!<arch>\n";
const end = "`\n";
const pad = "\n";
const linker_member = genMemberName("/");
const longnames_member = genMemberName("//");
const hybridmap_member = genMemberName("/<HYBRIDMAP>/");

const assert = std.debug.assert;
const std = @import("std");

const Allocator = std.mem.Allocator;
const Library = @This();
