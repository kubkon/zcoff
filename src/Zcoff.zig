const Zcoff = @This();

const std = @import("std");
const coff = @import("coff.zig");
const fs = std.fs;
const mem = std.mem;

const Allocator = mem.Allocator;

gpa: Allocator,
data: ?[]const u8 = null,

const pe_offset: usize = 0x3c;
const pe_magic: []const u8 = "PE\x00\x00";

pub fn init(gpa: Allocator) Zcoff {
    return .{ .gpa = gpa };
}

pub fn deinit(self: *Zcoff) void {
    if (self.data) |data| {
        self.gpa.free(data);
    }
    self.data = null;
}

pub fn parse(self: *Zcoff, file: fs.File) !void {
    const stat = try file.stat();
    self.data = try file.readToEndAlloc(self.gpa, stat.size);

    // Do some basic validation upfront
    var stream = std.io.fixedBufferStream(self.data.?);
    const reader = stream.reader();

    var image_magic_buf: [4]u8 = undefined;
    const image_magic = try parseImageMagicNumber(&image_magic_buf, &stream);
    if (mem.eql(u8, pe_magic, image_magic)) {
        const coff_header = try reader.readStruct(coff.CoffHeader);
        if (coff_header.size_of_optional_header == 0) {
            std.log.err("Required PE header missing for image file", .{});
            return error.MalformedImageFile;
        }
    }
}

pub fn printHeaders(self: *Zcoff, writer: anytype) !void {
    var stream = std.io.fixedBufferStream(self.data.?);
    const reader = stream.reader();

    var image_magic_buf: [4]u8 = undefined;
    const image_magic = try parseImageMagicNumber(&image_magic_buf, &stream);
    const is_image = mem.eql(u8, pe_magic, image_magic);

    if (is_image) {
        try writer.writeAll("PE signature found\n\n");
        try writer.writeAll("File type: EXECUTABLE IMAGE\n\n");
    } else {
        try writer.writeAll("No PE signature found\n\n");
        try writer.writeAll("File type: OBJECT FILE\n\n");
        try stream.seekTo(0);
    }

    // COFF header (object and image)
    const coff_header = try reader.readStruct(coff.CoffHeader);
    try writer.writeAll("FILE HEADER VALUES\n");
    try writer.print("{x: >20} machine ({s})\n", .{
        coff_header.machine,
        @tagName(@intToEnum(coff.MachineType, coff_header.machine)),
    });
    try writer.print("{d: >20} number of sections\n", .{coff_header.number_of_sections});
    try writer.print("{x: >20} time date stamp\n", .{coff_header.time_date_stamp});
    try writer.print("{x: >20} file pointer to symbol table\n", .{coff_header.pointer_to_symbol_table});
    try writer.print("{d: >20} number of symbols\n", .{coff_header.number_of_symbols});
    try writer.print("{x: >20} size of optional header\n", .{coff_header.size_of_optional_header});
    try writer.print("{d: >20} characteristics\n", .{coff_header.characteristics});

    inline for (&[_]struct { flag: u16, desc: []const u8 }{
        .{ .flag = coff.IMAGE_FILE_RELOCS_STRIPPED, .desc = "Relocs stripped" },
        .{ .flag = coff.IMAGE_FILE_EXECUTABLE_IMAGE, .desc = "Executable" },
        .{ .flag = coff.IMAGE_FILE_LINE_NUMS_STRIPPED, .desc = "COFF line numbers have been removed" },
        .{ .flag = coff.IMAGE_FILE_LOCAL_SYMS_STRIPPED, .desc = "COFF symbol table entries for local symbols have been removed" },
        .{ .flag = coff.IMAGE_FILE_AGGRESSIVE_WS_TRIM, .desc = "Aggressively trim working set" },
        .{ .flag = coff.IMAGE_FILE_LARGE_ADDRESS_AWARE, .desc = "Application can handle > 2-GB addresses" },
        .{ .flag = coff.IMAGE_FILE_RESERVED, .desc = "Reserved" },
        .{ .flag = coff.IMAGE_FILE_BYTES_REVERSED_LO, .desc = "Little endian" },
        .{ .flag = coff.IMAGE_FILE_32BIT_MACHINE, .desc = "32-bit" },
        .{ .flag = coff.IMAGE_FILE_DEBUG_STRIPPED, .desc = "Debugging information removed" },
        .{ .flag = coff.IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, .desc = "Fully load and copy to swap file from removable media" },
        .{ .flag = coff.IMAGE_FILE_NET_RUN_FROM_SWAP, .desc = "Fully load and copy to swap file from network media" },
        .{ .flag = coff.IMAGE_FILE_SYSTEM, .desc = "System file" },
        .{ .flag = coff.IMAGE_FILE_DLL, .desc = "DLL" },
        .{ .flag = coff.IMAGE_FILE_UP_SYSTEM_ONLY, .desc = "Uniprocessor machine only" },
        .{ .flag = coff.IMAGE_FILE_BYTES_REVERSED_HI, .desc = "Big endian" },
    }) |next| {
        if (coff_header.characteristics & next.flag != 0) {
            try writer.print("{s: >22} {s}\n", .{ "", next.desc });
        }
    }
}

fn parseImageMagicNumber(buf: *[4]u8, stream: anytype) ![]const u8 {
    const reader = stream.reader();
    try stream.seekTo(pe_offset);
    const pe_header_offset = try reader.readByte();
    try stream.seekTo(pe_header_offset);
    try reader.readNoEof(buf);
    return buf[0..];
}
