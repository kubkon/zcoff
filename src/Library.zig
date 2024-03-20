gpa: Allocator,
data: []const u8,

symdef: Symdef = .{},
symdef_sorted: SymdefSorted = .{},
longnames: []const u8 = &[0]u8{},
members: std.MultiArrayList(Member) = .{},

pub fn isLibrary(data: []const u8) bool {
    return std.mem.eql(u8, data[0..magic.len], magic);
}

pub fn deinit(self: *Library) void {
    self.symdef.deinit(self.gpa);
    self.symdef_sorted.deinit(self.gpa);
    self.members.deinit(self.gpa);
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

        const hdr = try reader.readStruct(Header);

        if (!std.mem.eql(u8, &hdr.end, end)) return error.InvalidHeaderDelimiter;

        const size = try hdr.getSize();
        defer {
            _ = stream.seekBy(size) catch {};
        }

        if (hdr.isLinkerMember()) {
            if (!check.symdef) {
                if (member_count != 0) return error.InvalidLinkerMember;
                try self.symdef.parse(self.gpa, self.data[stream.pos..][0..size]);
                check.symdef = true;
                continue;
            }

            if (!check.symdef_sorted) {
                if (member_count != 1) return error.InvalidLinkerMember;
                try self.symdef_sorted.parse(self.gpa, self.data[stream.pos..][0..size]);
                check.symdef_sorted = true;
                continue;
            }

            return error.InvalidLinkerMember;
        }

        if (hdr.isLongnamesMember()) {
            if (!check.longnames) {
                if (member_count != 2) return error.InvalidLinkerMember;
                self.longnames = self.data[stream.pos..][0..size];
                check.longnames = true;
                continue;
            }
        }

        try self.members.append(self.gpa, .{
            .offset = stream.pos - @sizeOf(Header),
            .header = hdr,
            .object = .{
                .gpa = self.gpa,
                .data = self.data[stream.pos..][0..size],
            },
        });
    }
}

pub fn print(self: *const Library, writer: anytype, options: anytype) !void {
    for (self.members.items(.offset), self.members.items(.header), self.members.items(.object)) |off, *header, object| {
        if (options.archive_members) try self.printArchiveMember(off, header, writer);
        if (isImportHeader(object.data)) {
            if (!options.headers) continue;

            var stream = std.io.fixedBufferStream(object.data);
            const reader = stream.reader();
            const hdr = try reader.readStruct(ImportHeader);
            const strings = object.data[@sizeOf(ImportHeader)..][0..hdr.size_of_data];
            const import_name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(strings.ptr)), 0);
            const dll_name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(strings.ptr + import_name.len + 1)), 0);

            try writer.print("  {s: <13}: {X}\n", .{ "Version", hdr.version });
            try writer.print("  {s: <13}: {s}\n", .{ "Machine", @tagName(hdr.machine) });
            try writer.print("  {s: <13}: {X:0>8}\n", .{ "TimeDateStamp", hdr.time_date_stamp });
            try writer.print("  {s: <13}: {X:0>8}\n", .{ "SizeOfData", hdr.size_of_data });
            try writer.print("  {s: <13}: {s}\n", .{ "DLL name", dll_name });
            try writer.print("  {s: <13}: {s}\n", .{ "Symbol name", import_name });
            try writer.print("  {s: <13}: {s}\n", .{ "Type", @tagName(hdr.types.type) });
            try writer.print("  {s: <13}: {s}\n", .{ "Name type", @tagName(hdr.types.name_type) });
            if (hdr.types.name_type == .ORDINAL) {
                try writer.print("  {s: <13}: {X}\n", .{ "Ordinal", hdr.hint });
            } else {
                try writer.print("  {s: <13}: {X}\n", .{ "Hint", hdr.hint });
            }
            switch (hdr.types.name_type) {
                .ORDINAL => {},
                .NAME => try writer.print("  {s: <13}: {s}\n", .{ "Name", import_name }),
                .NAME_NOPREFIX => try writer.print("  {s: <13}: {s}\n", .{
                    "Name",
                    std.mem.trimLeft(u8, import_name, "?@_"),
                }),
                .NAME_UNDECORATE => {
                    const trimmed = std.mem.trimLeft(u8, import_name, "?@_");
                    const index = std.mem.indexOf(u8, trimmed, "@") orelse trimmed.len;
                    try writer.print("  {s: <13}: {s}\n", .{
                        "Name",
                        trimmed[0..index],
                    });
                },
            }
            try writer.writeByte('\n');
        } else {
            var opts = options;
            opts.summary = false;
            try object.print(writer, opts);
        }
    }

    if (options.summary) try self.printSummary(writer);
}

fn printArchiveMember(self: *const Library, off: usize, hdr: *const Header, writer: anytype) !void {
    const name = hdr.getName() orelse self.getLongname((try hdr.getLongnameOffset()).?);
    try writer.print("Archive member name at {X}: {s}\n", .{ off, name });
    try writer.print("{X: >8} time/date\n", .{try hdr.getDate()});
    if (try hdr.getUserId()) |uid| {
        try writer.print("{X: >8} uid\n", .{uid});
    } else {
        try writer.print("{s: >8} uid\n", .{" "});
    }
    if (try hdr.getGroupId()) |gid| {
        try writer.print("{X: >8} gid\n", .{gid});
    } else {
        try writer.print("{s: >8} gid\n", .{" "});
    }
    try writer.print("{X: >8} mode\n", .{try hdr.getMode()});
    try writer.print("{X: >8} size\n", .{try hdr.getSize()});
    if (!std.mem.eql(u8, &hdr.end, end)) {
        try writer.writeAll("invalid header end\n");
    } else {
        try writer.writeAll("correct header end\n");
    }
    try writer.writeByte('\n');
}

fn printSummary(self: *const Library, writer: anytype) !void {
    try writer.writeAll("  Summary\n\n");

    var arena = std.heap.ArenaAllocator.init(self.gpa);
    defer arena.deinit();

    var summary = std.StringArrayHashMap(u64).init(arena.allocator());

    for (self.members.items(.object)) |object| {
        if (isImportHeader(object.data)) continue;
        const sections = object.getSectionHeaders();
        try summary.ensureUnusedCapacity(sections.len);

        for (sections) |sect| {
            const name = sect.getName() orelse object.getStrtab().?.get(sect.getNameOffset().?);
            const gop = summary.getOrPutAssumeCapacity(try arena.allocator().dupe(u8, name));
            if (!gop.found_existing) gop.value_ptr.* = 0;
            gop.value_ptr.* += sect.size_of_raw_data;
        }
    }

    const Sort = struct {
        fn lessThan(ctx: void, lhs: []const u8, rhs: []const u8) bool {
            _ = ctx;
            return std.mem.order(u8, lhs, rhs) == .lt;
        }
    };
    var keys = try std.ArrayList([]const u8).initCapacity(arena.allocator(), summary.keys().len);
    keys.appendSliceAssumeCapacity(summary.keys());
    std.mem.sort([]const u8, keys.items, {}, Sort.lessThan);

    for (keys.items) |key| {
        const size = summary.get(key).?;
        try writer.print("  {X: >8} {s}\n", .{ size, key });
    }
}

fn getLongname(self: *const Library, off: u32) [:0]const u8 {
    assert(off < self.longnames.len);
    return std.mem.sliceTo(@as([*:0]const u8, @ptrCast(self.longnames.ptr + off)), 0);
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

    fn getName(hdr: *const Header) ?[]const u8 {
        const value = &hdr.name;
        if (value[0] == '/') return null;
        const sentinel = std.mem.indexOfScalar(u8, value, '/') orelse value.len;
        return value[0..sentinel];
    }

    fn getLongnameOffset(hdr: *const Header) !?u32 {
        const value = &hdr.name;
        if (value[0] != '/') return null;
        const trimmed = std.mem.trimRight(u8, value, " ");
        return try std.fmt.parseInt(u32, trimmed[1..], 10);
    }

    fn getDate(hdr: *const Header) !u32 {
        const value = std.mem.trimRight(u8, &hdr.date, " ");
        const parsed = try std.fmt.parseInt(i32, value, 10);
        return @bitCast(parsed);
    }

    fn getUserId(hdr: *const Header) !?u32 {
        const value = std.mem.trimRight(u8, &hdr.user_id, " ");
        if (value.len == 0) return null;
        return try std.fmt.parseInt(u32, value, 10);
    }

    fn getGroupId(hdr: *const Header) !?u32 {
        const value = std.mem.trimRight(u8, &hdr.group_id, " ");
        if (value.len == 0) return null;
        return try std.fmt.parseInt(u32, value, 10);
    }

    fn getMode(hdr: *const Header) !u32 {
        const value = std.mem.trimRight(u8, &hdr.mode, " ");
        return std.fmt.parseInt(u32, value, 10);
    }

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

const Member = struct {
    offset: usize,
    header: Header,
    object: Object,
};

fn isImportHeader(data: []const u8) bool {
    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader();
    const sig1 = reader.readInt(u16, .little) catch return false;
    const sig2 = reader.readInt(u16, .little) catch return false;
    return @as(coff.MachineType, @enumFromInt(sig1)) == .Unknown and sig2 == 0xFFFF;
}

const ImportHeader = extern struct {
    sig1: coff.MachineType,
    sig2: u16,
    version: u16,
    machine: coff.MachineType,
    time_date_stamp: u32,
    size_of_data: u32,
    hint: u16,
    types: packed struct {
        type: ImportType,
        name_type: ImportNameType,
        reserved: u11,
    },
};

const ImportType = enum(u2) {
    /// Executable code.
    CODE = 0,
    /// Data.
    DATA = 1,
    /// Specified as CONST in .def file.
    CONST = 2,
};

const ImportNameType = enum(u3) {
    /// The import is by ordinal. This indicates that the value in the Ordinal/Hint
    /// field of the import header is the import's ordinal. If this constant is not
    /// specified, then the Ordinal/Hint field should always be interpreted as the import's hint.
    ORDINAL = 0,
    /// The import name is identical to the public symbol name.
    NAME = 1,
    /// The import name is the public symbol name, but skipping the leading ?, @, or optionally _.
    NAME_NOPREFIX = 2,
    /// The import name is the public symbol name, but skipping the leading ?, @, or optionally _,
    /// and truncating at the first @.
    NAME_UNDECORATE = 3,
};

const magic = "!<arch>\n";
const end = "`\n";
const pad = "\n";
const linker_member = genMemberName("/");
const longnames_member = genMemberName("//");
const hybridmap_member = genMemberName("/<HYBRIDMAP>/");

const assert = std.debug.assert;
const coff = std.coff;
const std = @import("std");

const Allocator = std.mem.Allocator;
const Library = @This();
const Object = @import("Object.zig");
