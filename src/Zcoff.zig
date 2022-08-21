const Zcoff = @This();

const std = @import("std");
const assert = std.debug.assert;
const coff = @import("coff.zig");
const fs = std.fs;
const mem = std.mem;

const Allocator = mem.Allocator;

gpa: Allocator,
data: ?[]const u8 = null,
is_image: bool = false,
coff_header_offset: usize = 0,

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

    var stream = std.io.fixedBufferStream(self.data.?);
    const reader = stream.reader();
    try stream.seekTo(pe_offset);
    const coff_header_offset = try reader.readByte();
    try stream.seekTo(coff_header_offset);
    var buf: [4]u8 = undefined;
    try reader.readNoEof(&buf);
    self.is_image = mem.eql(u8, pe_magic, &buf);

    // Do some basic validation upfront
    if (self.is_image) {
        self.coff_header_offset = coff_header_offset + 4;
        const coff_header = self.getHeader();
        if (coff_header.size_of_optional_header == 0) {
            std.log.err("Required PE header missing for image file", .{});
            return error.MalformedImageFile;
        }
    }
}

pub fn printHeaders(self: *Zcoff, writer: anytype) !void {
    const coff_header = self.getHeader();
    if (self.is_image) {
        try writer.writeAll("PE signature found\n\n");
        try writer.writeAll("File type: EXECUTABLE IMAGE\n\n");
    } else {
        try writer.writeAll("No PE signature found\n\n");
        try writer.writeAll("File type: COFF OBJECT\n\n");
    }

    // COFF header (object and image)
    try writer.writeAll("FILE HEADER VALUES\n");

    {
        try writer.print("{x: >20} machine ({s})\n", .{
            coff_header.machine,
            @tagName(@intToEnum(coff.MachineType, coff_header.machine)),
        });

        const fields = std.meta.fields(coff.CoffHeader);
        inline for (&[_][]const u8{
            "number of sections",
            "time date stamp",
            "file pointer to symbol table",
            "number of symbols",
            "size of optional header",
            "characteristics",
        }) |desc, i| {
            const field = fields[i + 1];
            try writer.print("{x: >20} {s}\n", .{ @field(coff_header, field.name), desc });
        }
    }

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
    try writer.writeByte('\n');

    if (coff_header.size_of_optional_header > 0) {
        var stream = std.io.fixedBufferStream(self.data.?);
        const reader = stream.reader();

        const offset = self.coff_header_offset + @sizeOf(coff.CoffHeader);
        try stream.seekTo(offset);

        try writer.writeAll("OPTIONAL HEADER VALUES\n");
        const magic = try reader.readIntLittle(u16);
        try stream.seekBy(-2);

        var counting_stream = std.io.countingReader(reader);
        const creader = counting_stream.reader();

        var number_of_directories: u32 = 0;

        switch (magic) {
            coff.IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
                const pe_header = try creader.readStruct(coff.OptionalHeaderPE32);
                const fields = std.meta.fields(coff.OptionalHeaderPE32);
                inline for (&[_][]const u8{
                    "magic",
                    "linker version (major)",
                    "linker version (minor)",
                    "size of code",
                    "size of initialized data",
                    "size of uninitialized data",
                    "entry point",
                    "base of code",
                    "base of data",
                    "image base",
                    "section alignment",
                    "file alignment",
                    "OS version (major)",
                    "OS version (minor)",
                    "image version (major)",
                    "image version (minor)",
                    "subsystem version (major)",
                    "subsystem version (minor)",
                    "Win32 version",
                    "size of image",
                    "size of headers",
                    "checksum",
                    "subsystem",
                    "DLL characteristics",
                    "size of stack reserve",
                    "size of stack commit",
                    "size of heap reserve",
                    "size of heap commit",
                    "loader flags",
                    "number of RVA and sizes",
                }) |desc, i| {
                    const field = fields[i];
                    try writer.print("{x: >20} {s}", .{ @field(pe_header, field.name), desc });
                    if (mem.eql(u8, field.name, "magic")) {
                        try writer.writeAll(" # (PE32)");
                        try writer.writeByte('\n');
                    } else if (mem.eql(u8, field.name, "dll_characteristics")) {
                        try writer.writeByte('\n');
                        try printDllCharacteristics(pe_header.dll_characteristics, writer);
                    } else if (mem.eql(u8, field.name, "subsystem")) {
                        try writer.print(" # ({s})", .{@tagName(@intToEnum(coff.Subsystem, pe_header.subsystem))});
                        try writer.writeByte('\n');
                    } else try writer.writeByte('\n');
                }
                number_of_directories = pe_header.number_of_rva_and_sizes;
            },
            coff.IMAGE_NT_OPTIONAL_HDR64_MAGIC => {
                const pe_header = try creader.readStruct(coff.OptionalHeaderPE64);
                const fields = std.meta.fields(coff.OptionalHeaderPE64);
                inline for (&[_][]const u8{
                    "magic",
                    "linker version (major)",
                    "linker version (minor)",
                    "size of code",
                    "size of initialized data",
                    "size of uninitialized data",
                    "entry point",
                    "base of code",
                    "image base",
                    "section alignment",
                    "file alignment",
                    "OS version (major)",
                    "OS version (minor)",
                    "image version (major)",
                    "image version (minor)",
                    "subsystem version (major)",
                    "subsystem version (minor)",
                    "Win32 version",
                    "size of image",
                    "size of headers",
                    "checksum",
                    "subsystem",
                    "DLL characteristics",
                    "size of stack reserve",
                    "size of stack commit",
                    "size of heap reserve",
                    "size of heap commit",
                    "loader flags",
                    "number of directories",
                }) |desc, i| {
                    const field = fields[i];
                    try writer.print("{x: >20} {s}", .{ @field(pe_header, field.name), desc });
                    if (mem.eql(u8, field.name, "magic")) {
                        try writer.writeAll(" # (PE32+)");
                        try writer.writeByte('\n');
                    } else if (mem.eql(u8, field.name, "dll_characteristics")) {
                        try writer.writeByte('\n');
                        try printDllCharacteristics(pe_header.dll_characteristics, writer);
                    } else if (mem.eql(u8, field.name, "subsystem")) {
                        try writer.print(" # ({s})", .{@tagName(@intToEnum(coff.Subsystem, pe_header.subsystem))});
                        try writer.writeByte('\n');
                    } else try writer.writeByte('\n');
                }
                number_of_directories = pe_header.number_of_rva_and_sizes;
            },
            else => {
                std.log.err("unknown PE optional header magic: {x}", .{magic});
                return error.UnknownPEOptionalHeaderMagic;
            },
        }

        if (number_of_directories > 0) {
            inline for (&[_][]const u8{
                "Export Directory",
                "Import Directory",
                "Resource Directory",
                "Exception Directory",
                "Certificates Directory",
                "Base Relocation Directory",
                "Debug Directory",
                "Architecture Directory",
                "Global Pointer Directory",
                "Thread Storage Directory",
                "Load Configuration Directory",
                "Bound Import Directory",
                "Import Address Table Directory",
                "Delay Import Directory",
                "COM Descriptor Directory",
                "Reserved Directory",
            }) |desc, i| {
                if (i < number_of_directories) {
                    const data_dir = try creader.readStruct(coff.ImageDataDirectory);
                    try writer.print("{x: >20} [{x: >10}] RVA [size] of {s}\n", .{
                        data_dir.virtual_address,
                        data_dir.size,
                        desc,
                    });
                }
            }
        }

        assert(counting_stream.bytes_read == coff_header.size_of_optional_header);
    }

    // Section table
    if (coff_header.number_of_sections > 0) {
        var stream = std.io.fixedBufferStream(self.data.?);
        const offset = self.coff_header_offset + @sizeOf(coff.CoffHeader) + coff_header.size_of_optional_header;
        try stream.seekTo(offset);
        const reader = stream.reader();

        try writer.writeByte('\n');

        const strtab = self.getStrtab();

        const fields = std.meta.fields(coff.SectionHeader);
        var i: usize = 0;
        while (i < coff_header.number_of_sections) : (i += 1) {
            try writer.print("SECTION HEADER #{d}\n", .{i});

            const sect_hdr = try reader.readStruct(coff.SectionHeader);
            const name = sect_hdr.getName() orelse blk: {
                const name_offset = sect_hdr.getNameOffset() orelse return error.MalformedSectionHeader;
                break :blk strtab.?.get(name_offset);
            };

            try writer.print("{s: >20} name\n", .{name});

            inline for (&[_][]const u8{
                "virtual size",
                "virtual address",
                "size of raw data",
                "file pointer to raw data",
                "file pointer to relocation table",
                "file pointer to line numbers",
                "number of relocations",
                "number of line numbers",
                "flags",
            }) |desc, field_i| {
                const field = fields[field_i + 1];
                try writer.print("{x: >20} {s}\n", .{ @field(sect_hdr, field.name), desc });
                if (mem.eql(u8, field.name, "flags")) {
                    try printSectionFlags(sect_hdr.flags, writer);
                    if (sect_hdr.getAlignment()) |alignment| {
                        try writer.print("{s: >22} {d} byte align\n", .{ "", alignment });
                    }
                }
            }

            try writer.writeByte('\n');
        }
    }
}

fn printSectionFlags(bitset: u32, writer: anytype) !void {
    inline for (&[_]struct { flag: u32, desc: []const u8 }{
        .{ .flag = coff.IMAGE_SCN_TYPE_NO_PAD, .desc = "No padding" },
        .{ .flag = coff.IMAGE_SCN_CNT_CODE, .desc = "Code" },
        .{ .flag = coff.IMAGE_SCN_CNT_INITIALIZED_DATA, .desc = "Initialized data" },
        .{ .flag = coff.IMAGE_SCN_CNT_UNINITIALIZED_DATA, .desc = "Uninitialized data" },
        .{ .flag = coff.IMAGE_SCN_LNK_INFO, .desc = "Comments" },
        .{ .flag = coff.IMAGE_SCN_LNK_REMOVE, .desc = "Discard" },
        .{ .flag = coff.IMAGE_SCN_LNK_COMDAT, .desc = "COMDAT" },
        .{ .flag = coff.IMAGE_SCN_GPREL, .desc = "GP referenced" },
        .{ .flag = coff.IMAGE_SCN_LNK_NRELOC_OVFL, .desc = "Extended relocations" },
        .{ .flag = coff.IMAGE_SCN_MEM_DISCARDABLE, .desc = "Discardable" },
        .{ .flag = coff.IMAGE_SCN_MEM_NOT_CACHED, .desc = "Not cached" },
        .{ .flag = coff.IMAGE_SCN_MEM_NOT_PAGED, .desc = "Not paged" },
        .{ .flag = coff.IMAGE_SCN_MEM_SHARED, .desc = "Shared" },
        .{ .flag = coff.IMAGE_SCN_MEM_EXECUTE, .desc = "Execute" },
        .{ .flag = coff.IMAGE_SCN_MEM_READ, .desc = "Read" },
        .{ .flag = coff.IMAGE_SCN_MEM_WRITE, .desc = "Write" },
    }) |next| {
        if (bitset & next.flag != 0) {
            try writer.print("{s: >22} {s}\n", .{ "", next.desc });
        }
    }
}

fn printDllCharacteristics(bitset: u16, writer: anytype) !void {
    inline for (&[_]struct { flag: u16, desc: []const u8 }{
        .{ .flag = coff.IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, .desc = "High Entropy Virtual Address" },
        .{ .flag = coff.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, .desc = "Dynamic base" },
        .{ .flag = coff.IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY, .desc = "Force integrity" },
        .{ .flag = coff.IMAGE_DLLCHARACTERISTICS_NX_COMPAT, .desc = "NX compatible" },
        .{ .flag = coff.IMAGE_DLLCHARACTERISTICS_NO_ISOLATION, .desc = "No isolation" },
        .{ .flag = coff.IMAGE_DLLCHARACTERISTICS_NO_SEH, .desc = "No structured exception handling" },
        .{ .flag = coff.IMAGE_DLLCHARACTERISTICS_NO_BIND, .desc = "No bind" },
        .{ .flag = coff.IMAGE_DLLCHARACTERISTICS_APPCONTAINER, .desc = "AppContainer" },
        .{ .flag = coff.IMAGE_DLLCHARACTERISTICS_WDM_DRIVER, .desc = "WDM Driver" },
        .{ .flag = coff.IMAGE_DLLCHARACTERISTICS_GUARD_CF, .desc = "Control Flow Guard" },
        .{ .flag = coff.IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE, .desc = "Terminal Server Aware" },
    }) |next| {
        if (bitset & next.flag != 0) {
            try writer.print("{s: >22} {s}\n", .{ "", next.desc });
        }
    }
}

fn getHeader(self: *Zcoff) coff.CoffHeader {
    return @ptrCast(*align(1) coff.CoffHeader, self.data.?[self.coff_header_offset..][0..@sizeOf(coff.CoffHeader)]).*;
}

const Strtab = struct {
    buffer: []const u8,

    fn get(self: Strtab, off: u32) []const u8 {
        assert(off < self.buffer.len);
        return mem.sliceTo(@ptrCast([*:0]const u8, self.buffer.ptr + off), 0);
    }
};

fn getStrtab(self: *Zcoff) ?Strtab {
    const coff_header = self.getHeader();
    if (coff_header.pointer_to_symbol_table == 0) return null;

    const offset = coff_header.pointer_to_symbol_table + coff.Symbol.sizeOf() * coff_header.number_of_symbols;
    const size = mem.readIntLittle(u32, self.data.?[offset..][0..4]);
    return .{ .buffer = self.data.?[offset..][0..size] };
}
