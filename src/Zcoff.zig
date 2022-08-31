const Zcoff = @This();

const std = @import("std");
const assert = std.debug.assert;
const coff = std.coff;
const fs = std.fs;
const mem = std.mem;

const Allocator = mem.Allocator;

gpa: Allocator,
data: []const u8,
is_image: bool = false,
coff_header_offset: usize = 0,

const Options = struct {
    headers: bool,
    symbols: bool,
    relocations: bool,
    imports: bool,
};

pub fn deinit(self: *Zcoff) void {
    self.gpa.free(self.data);
}

pub fn parse(gpa: Allocator, file: fs.File) !Zcoff {
    const stat = try file.stat();
    const data = try file.readToEndAlloc(gpa, stat.size);
    var self = Zcoff{ .gpa = gpa, .data = data };

    const pe_pointer_offset = 0x3C;
    const pe_magic = "PE\x00\x00";

    var stream = std.io.fixedBufferStream(self.data);
    const reader = stream.reader();
    try stream.seekTo(pe_pointer_offset);
    const coff_header_offset = try reader.readIntLittle(u32);
    try stream.seekTo(coff_header_offset);
    var buf: [4]u8 = undefined;
    try reader.readNoEof(&buf);
    self.is_image = mem.eql(u8, pe_magic, &buf);

    // Do some basic validation upfront
    if (self.is_image) {
        self.coff_header_offset = coff_header_offset + 4;
        const coff_header = self.getCoffHeader();
        if (coff_header.size_of_optional_header == 0) return error.MissingPEHeader;
    }

    return self;
}

pub fn print(self: *Zcoff, writer: anytype, options: Options) !void {
    if (self.is_image) {
        try writer.writeAll("PE signature found\n\n");
        try writer.writeAll("File type: EXECUTABLE IMAGE\n\n");
    } else {
        try writer.writeAll("No PE signature found\n\n");
        try writer.writeAll("File type: COFF OBJECT\n\n");
    }

    if (options.headers) try self.printHeaders(writer);

    try writer.writeByte('\n');

    const data_dirs = self.getDataDirectories();
    const base_relocs_dir: ?coff.ImageDataDirectory = if (options.relocations and @enumToInt(coff.DirectoryEntry.BASERELOC) < data_dirs.len)
        data_dirs[@enumToInt(coff.DirectoryEntry.BASERELOC)]
    else
        null;
    const imports_dir: ?coff.ImageDataDirectory = if (options.imports and @enumToInt(coff.DirectoryEntry.IMPORT) < data_dirs.len)
        data_dirs[@enumToInt(coff.DirectoryEntry.IMPORT)]
    else
        null;

    const sections = self.getSectionHeaders();
    for (sections) |*sect_hdr, sect_id| {
        if (options.headers) try self.printSectionHeader(writer, @intCast(u16, sect_id), sect_hdr);

        if (base_relocs_dir) |dir| {
            if (self.getSectionByAddress(dir.virtual_address).? == sect_id) {
                try writer.print("BASE RELOCATIONS #{d}\n", .{sect_id + 1});
                const offset = dir.virtual_address - sect_hdr.virtual_address + sect_hdr.pointer_to_raw_data;
                const base_relocs = self.data[offset..][0..dir.size];

                var slice = base_relocs;
                while (slice.len > 0) {
                    const block = @ptrCast(*align(1) const coff.BaseRelocationDirectoryEntry, slice).*;
                    const num_relocs = @divExact(block.block_size - 8, @sizeOf(coff.BaseRelocation));
                    const block_relocs = @ptrCast([*]align(1) const coff.BaseRelocation, slice[8..])[0..num_relocs];
                    slice = slice[block.block_size..];

                    try writer.print("{x: >8} RVA, {x: >8} SizeOfBlock\n", .{ block.page_rva, block.block_size });
                    for (block_relocs) |brel| {
                        try writer.print("{x: >8}  {s: <20}", .{ brel.offset, @tagName(brel.@"type") });
                        switch (brel.@"type") {
                            .ABSOLUTE => {},
                            .DIR64 => {
                                const rebase_offset = self.getFileOffsetForAddress(block.page_rva + brel.offset);
                                const pointer = mem.readIntLittle(u64, self.data[rebase_offset..][0..8]);
                                try writer.print(" {x:0>16}", .{pointer});
                            },
                            else => {}, // TODO
                        }
                        try writer.writeByte('\n');
                    }
                }

                try writer.writeByte('\n');
            }
        }

        if (imports_dir) |dir| {
            if (self.getSectionByAddress(dir.virtual_address).? == sect_id) {
                try writer.writeAll("Section contains the following imports:\n\n");
                const offset = dir.virtual_address - sect_hdr.virtual_address + sect_hdr.pointer_to_raw_data;
                const raw_imports = self.data[offset..][0..dir.size];
                const num_imports = @divExact(dir.size, @sizeOf(coff.ImportDirectoryEntry)) - 1; // We exclude the NULL entry
                const imports = @ptrCast([*]align(1) const coff.ImportDirectoryEntry, raw_imports)[0..num_imports];

                const hdr = self.getOptionalHeader();
                const is_32bit = hdr.magic == coff.IMAGE_NT_OPTIONAL_HDR32_MAGIC;
                const image_base = self.getImageBase();

                for (imports) |import| {
                    const name_offset = self.getFileOffsetForAddress(import.name_rva);
                    const name = mem.sliceTo(@ptrCast([*:0]const u8, self.data.ptr + name_offset), 0);

                    try writer.print("  {s}\n", .{name});
                    try writer.print("{x: >20} Import Address Table\n", .{import.import_address_table_rva + image_base});
                    try writer.print("{x: >20} Import Name Table\n", .{import.import_lookup_table_rva + image_base});
                    try writer.print("{x: >20} time date stamp\n", .{import.time_date_stamp});
                    try writer.print("{x: >20} Index of first forwarder reference\n", .{import.forwarder_chain});

                    const lookup_table_offset = self.getFileOffsetForAddress(import.import_lookup_table_rva);
                    if (is_32bit) {
                        const raw_lookups = mem.sliceTo(@ptrCast([*:0]align(1) u32, self.data.ptr + lookup_table_offset), 0);
                        for (raw_lookups) |rl| {
                            if (coff.ImportLookupEntry32.getImportByOrdinal(rl)) |_| {
                                // TODO
                            } else if (coff.ImportLookupEntry32.getImportByName(rl)) |by_name| {
                                const by_name_offset = self.getFileOffsetForAddress(by_name.name_table_rva);
                                const by_name_entry = @ptrCast(*align(1) const coff.ImportHintNameEntry, self.data.ptr + by_name_offset);
                                const symbol_hint = by_name_entry.hint;
                                const symbol_name = mem.sliceTo(@ptrCast([*:0]const u8, &by_name_entry.name), 0);
                                try writer.print("{x: >30} {s}\n", .{ symbol_hint, symbol_name });
                            } else unreachable;
                        }
                    } else {
                        const raw_lookups = mem.sliceTo(@ptrCast([*:0]align(1) u64, self.data.ptr + lookup_table_offset), 0);
                        for (raw_lookups) |rl| {
                            if (coff.ImportLookupEntry64.getImportByOrdinal(rl)) |_| {
                                // TODO
                            } else if (coff.ImportLookupEntry64.getImportByName(rl)) |by_name| {
                                const by_name_offset = self.getFileOffsetForAddress(by_name.name_table_rva);
                                const by_name_entry = @ptrCast(*align(1) const coff.ImportHintNameEntry, self.data.ptr + by_name_offset);
                                const symbol_hint = by_name_entry.hint;
                                const symbol_name = mem.sliceTo(@ptrCast([*:0]const u8, &by_name_entry.name), 0);
                                try writer.print("{x: >30} {s}\n", .{ symbol_hint, symbol_name });
                            } else unreachable;
                        }
                    }
                }

                try writer.writeByte('\n');
            }
        }
    }

    if (options.symbols) try self.printSymbols(writer);
}

fn printHeaders(self: *Zcoff, writer: anytype) !void {
    const coff_header = self.getCoffHeader();

    // COFF header (object and image)
    try writer.writeAll("FILE HEADER VALUES\n");
    try writer.print("{x: >20} machine ({s})\n", .{ @enumToInt(coff_header.machine), @tagName(coff_header.machine) });
    {
        const fields = std.meta.fields(coff.CoffHeader);
        inline for (&[_][]const u8{
            "number of sections",
            "time date stamp",
            "file pointer to symbol table",
            "number of symbols",
            "size of optional header",
        }) |desc, i| {
            const field = fields[i + 1];
            try writer.print("{x: >20} {s}\n", .{ @field(coff_header, field.name), desc });
        }
    }
    try writer.print("{x: >20} {s}\n", .{ @bitCast(u16, coff_header.flags), "flags" });
    {
        const fields = std.meta.fields(coff.CoffHeaderFlags);
        inline for (&[_][]const u8{
            "Relocs stripped",
            "Executable",
            "COFF line numbers have been removed",
            "COFF symbol table entries for local symbols have been removed",
            "Aggressively trim working set",
            "Application can handle > 2-GB addresses",
            "Reserved",
            "Little endian",
            "32-bit",
            "Debugging information removed",
            "Fully load and copy to swap file from removable media",
            "Fully load and copy to swap file from network media",
            "System file",
            "DLL",
            "Uniprocessor machine only",
            "Big endian",
        }) |desc, i| {
            const field = fields[i];
            if (@field(coff_header.flags, field.name) == 0b1) {
                try writer.print("{s: >22} {s}\n", .{ "", desc });
            }
        }
    }
    try writer.writeByte('\n');

    if (coff_header.size_of_optional_header > 0) {
        const common_hdr = self.getOptionalHeader();
        switch (common_hdr.magic) {
            coff.IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
                const pe_header = self.getOptionalHeader32();
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
                    "DLL flags",
                    "size of stack reserve",
                    "size of stack commit",
                    "size of heap reserve",
                    "size of heap commit",
                    "loader flags",
                    "number of RVA and sizes",
                }) |desc, i| {
                    const field = fields[i];
                    if (comptime mem.eql(u8, field.name, "dll_flags")) {
                        try writer.print("{x: >20} {s}\n", .{ @bitCast(u16, pe_header.dll_flags), desc });
                        try printDllFlags(pe_header.dll_flags, writer);
                    } else if (comptime mem.eql(u8, field.name, "subsystem")) {
                        try writer.print("{x: >20} {s} # ({s})\n", .{
                            @enumToInt(pe_header.subsystem),
                            desc,
                            @tagName(pe_header.subsystem),
                        });
                    } else {
                        try writer.print("{x: >20} {s}", .{ @field(pe_header, field.name), desc });
                        if (comptime mem.eql(u8, field.name, "magic")) {
                            try writer.writeAll(" # (PE32+)");
                        }
                        try writer.writeByte('\n');
                    }
                }
            },
            coff.IMAGE_NT_OPTIONAL_HDR64_MAGIC => {
                const pe_header = self.getOptionalHeader64();
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
                    "DLL flags",
                    "size of stack reserve",
                    "size of stack commit",
                    "size of heap reserve",
                    "size of heap commit",
                    "loader flags",
                    "number of directories",
                }) |desc, i| {
                    const field = fields[i];
                    if (comptime mem.eql(u8, field.name, "dll_flags")) {
                        try writer.print("{x: >20} {s}\n", .{ @bitCast(u16, pe_header.dll_flags), desc });
                        try printDllFlags(pe_header.dll_flags, writer);
                    } else if (comptime mem.eql(u8, field.name, "subsystem")) {
                        try writer.print("{x: >20} {s} # ({s})\n", .{
                            @enumToInt(pe_header.subsystem),
                            desc,
                            @tagName(pe_header.subsystem),
                        });
                    } else {
                        try writer.print("{x: >20} {s}", .{ @field(pe_header, field.name), desc });
                        if (comptime mem.eql(u8, field.name, "magic")) {
                            try writer.writeAll(" # (PE32+)");
                        }
                        try writer.writeByte('\n');
                    }
                }
            },
            else => {
                std.log.err("unknown PE optional header magic: {x}", .{common_hdr.magic});
                return error.UnknownPEOptionalHeaderMagic;
            },
        }

        if (self.getNumberOfDataDirectories() > 0) {
            const data_dirs = self.getDataDirectories();
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
                if (i < self.getNumberOfDataDirectories()) {
                    const data_dir = data_dirs[i];
                    try writer.print("{x: >20} [{x: >10}] RVA [size] of {s}\n", .{
                        data_dir.virtual_address,
                        data_dir.size,
                        desc,
                    });
                }
            }
        }
    }
}

fn printDllFlags(flags: coff.DllFlags, writer: anytype) !void {
    inline for (std.meta.fields(coff.DllFlags)) |field| {
        if (field.field_type == u1) {
            if (@field(flags, field.name) == 0b1) {
                try writer.print("{s: >22} {s}\n", .{ "", field.name });
            }
        }
    }
}

fn printSectionHeader(self: *Zcoff, writer: anytype, sect_id: u16, sect_hdr: *align(1) const coff.SectionHeader) !void {
    const fields = std.meta.fields(coff.SectionHeader);

    try writer.print("SECTION HEADER #{d}\n", .{sect_id + 1});

    const name = self.getSectionName(sect_hdr);
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
    }) |desc, field_i| {
        const field = fields[field_i + 1];
        try writer.print("{x: >20} {s}\n", .{ @field(sect_hdr, field.name), desc });
    }

    try writer.print("{x: >20} flags\n", .{@bitCast(u32, sect_hdr.flags)});
    inline for (std.meta.fields(coff.SectionHeaderFlags)) |flag_field| {
        if (flag_field.field_type == u1) {
            if (@field(sect_hdr.flags, flag_field.name) == 0b1) {
                try writer.print("{s: >22} {s}\n", .{ "", flag_field.name });
            }
        }
    }
    if (sect_hdr.getAlignment()) |alignment| {
        try writer.print("{s: >22} {d} byte align\n", .{ "", alignment });
    }
    try writer.writeByte('\n');
}

fn printSymbols(self: *Zcoff, writer: anytype) !void {
    const symtab = self.getSymtab() orelse {
        return writer.writeAll("No symbol table found.\n");
    };

    try writer.writeAll("COFF SYMBOL TABLE\n");

    const sections = self.getSectionHeaders();
    const strtab = self.getStrtab().?;
    var slice = symtab.slice(0, null);

    var index: usize = 0;
    var aux_counter: usize = 0;
    var aux_tag: ?coff.Symtab.Tag = null;
    while (slice.next()) |sym| {
        if (aux_counter == 0) {
            try writer.print("{d:0>3} {d:0>8} ", .{ index, sym.value });
            switch (sym.section_number) {
                .UNDEFINED,
                .ABSOLUTE,
                .DEBUG,
                => try writer.print("{s: <9} ", .{@tagName(sym.section_number)}),
                else => try writer.print("SECT{d: <5} ", .{@enumToInt(sym.section_number)}),
            }
            const name = sym.getName() orelse blk: {
                const offset = sym.getNameOffset() orelse return error.MalformedSymbolRecord;
                break :blk strtab.get(offset);
            };
            try writer.print("{s: <6} {s: <8} {s: <20} | {s}\n", .{
                @tagName(sym.@"type".base_type),
                @tagName(sym.@"type".complex_type),
                @tagName(sym.storage_class),
                name,
            });

            aux_tag = aux_tag: {
                switch (sym.section_number) {
                    .UNDEFINED => {
                        if (sym.storage_class == .WEAK_EXTERNAL and sym.value == 0) {
                            break :aux_tag .weak_ext;
                        }
                    },
                    .ABSOLUTE => {},
                    .DEBUG => {
                        if (sym.storage_class == .FILE) {
                            break :aux_tag .file_def;
                        }
                    },
                    else => {
                        if (sym.storage_class == .FUNCTION) {
                            break :aux_tag .debug_info;
                        }
                        if (sym.storage_class == .EXTERNAL and sym.@"type".complex_type == .FUNCTION) {
                            break :aux_tag .func_def;
                        }
                        if (sym.storage_class == .STATIC) {
                            for (sections) |*sect| {
                                const sect_name = self.getSectionName(sect);
                                if (mem.eql(u8, sect_name, name)) {
                                    break :aux_tag .sect_def;
                                }
                            }
                        }
                    },
                }
                break :aux_tag null;
            };

            aux_counter = sym.number_of_aux_symbols;
        } else {
            if (aux_tag) |tag| switch (symtab.at(index, tag)) {
                .weak_ext => |weak_ext| {
                    try writer.print("     Default index {x: >8} {s}\n", .{ weak_ext.tag_index, @tagName(weak_ext.flag) });
                },
                .file_def => |*file_def| {
                    try writer.print("     {s}\n", .{file_def.getFileName()});
                },
                .sect_def => |sect_def| {
                    try writer.print("     Section length {x: >4}, #relocs {x: >4}, #linenums {x: >4}, checksum {x: >8}", .{
                        sect_def.length,
                        sect_def.number_of_relocations,
                        sect_def.number_of_linenumbers,
                        sect_def.checksum,
                    });
                    const st_sym = symtab.at(index - aux_counter, .symbol).symbol;
                    const sect = sections[@enumToInt(st_sym.section_number) - 1];
                    if (sect.isComdat()) {
                        try writer.print(", selection {d} ({s})", .{ @enumToInt(sect_def.selection), @tagName(sect_def.selection) });
                    } else {
                        assert(sect_def.selection == .NONE); // Expected non COMDAT section would not set the selection field in aux record.
                    }
                    try writer.writeByte('\n');
                },
                else => |other| {
                    std.log.warn("Unhandled auxiliary symbol: {}", .{other});
                },
            };

            aux_counter -= 1;
        }

        index += 1;
    }

    try writer.print("\nString table size = 0x{x} bytes\n", .{strtab.buffer.len});
}

pub fn getCoffHeader(self: Zcoff) coff.CoffHeader {
    return @ptrCast(*align(1) const coff.CoffHeader, self.data[self.coff_header_offset..][0..@sizeOf(coff.CoffHeader)]).*;
}

pub fn getOptionalHeader(self: Zcoff) coff.OptionalHeader {
    assert(self.is_image);
    const offset = self.coff_header_offset + @sizeOf(coff.CoffHeader);
    return @ptrCast(*align(1) const coff.OptionalHeader, self.data[offset..][0..@sizeOf(coff.OptionalHeader)]).*;
}

pub fn getOptionalHeader32(self: Zcoff) coff.OptionalHeaderPE32 {
    assert(self.is_image);
    const offset = self.coff_header_offset + @sizeOf(coff.CoffHeader);
    return @ptrCast(*align(1) const coff.OptionalHeaderPE32, self.data[offset..][0..@sizeOf(coff.OptionalHeaderPE32)]).*;
}

pub fn getOptionalHeader64(self: Zcoff) coff.OptionalHeaderPE64 {
    assert(self.is_image);
    const offset = self.coff_header_offset + @sizeOf(coff.CoffHeader);
    return @ptrCast(*align(1) const coff.OptionalHeaderPE64, self.data[offset..][0..@sizeOf(coff.OptionalHeaderPE64)]).*;
}

pub fn getImageBase(self: Zcoff) u64 {
    const hdr = self.getOptionalHeader();
    return switch (hdr.magic) {
        coff.IMAGE_NT_OPTIONAL_HDR32_MAGIC => self.getOptionalHeader32().image_base,
        coff.IMAGE_NT_OPTIONAL_HDR64_MAGIC => self.getOptionalHeader64().image_base,
        else => unreachable, // We assume we have validated the header already
    };
}

pub fn getNumberOfDataDirectories(self: Zcoff) u32 {
    const hdr = self.getOptionalHeader();
    return switch (hdr.magic) {
        coff.IMAGE_NT_OPTIONAL_HDR32_MAGIC => self.getOptionalHeader32().number_of_rva_and_sizes,
        coff.IMAGE_NT_OPTIONAL_HDR64_MAGIC => self.getOptionalHeader64().number_of_rva_and_sizes,
        else => unreachable, // We assume we have validated the header already
    };
}

pub fn getDataDirectories(self: *const Zcoff) []align(1) const coff.ImageDataDirectory {
    const hdr = self.getOptionalHeader();
    const size: usize = switch (hdr.magic) {
        coff.IMAGE_NT_OPTIONAL_HDR32_MAGIC => @sizeOf(coff.OptionalHeaderPE32),
        coff.IMAGE_NT_OPTIONAL_HDR64_MAGIC => @sizeOf(coff.OptionalHeaderPE64),
        else => unreachable, // We assume we have validated the header already
    };
    const offset = self.coff_header_offset + @sizeOf(coff.CoffHeader) + size;
    return @ptrCast([*]align(1) const coff.ImageDataDirectory, self.data[offset..])[0..self.getNumberOfDataDirectories()];
}

pub fn getSymtab(self: *const Zcoff) ?coff.Symtab {
    const coff_header = self.getCoffHeader();
    if (coff_header.pointer_to_symbol_table == 0) return null;

    const offset = coff_header.pointer_to_symbol_table;
    const size = coff_header.number_of_symbols * coff.Symbol.sizeOf();
    return .{ .buffer = self.data[offset..][0..size] };
}

pub fn getStrtab(self: *const Zcoff) ?coff.Strtab {
    const coff_header = self.getCoffHeader();
    if (coff_header.pointer_to_symbol_table == 0) return null;

    const offset = coff_header.pointer_to_symbol_table + coff.Symbol.sizeOf() * coff_header.number_of_symbols;
    const size = mem.readIntLittle(u32, self.data[offset..][0..4]);
    return .{ .buffer = self.data[offset..][0..size] };
}

pub fn getSectionHeaders(self: *const Zcoff) []align(1) const coff.SectionHeader {
    const coff_header = self.getCoffHeader();
    const offset = self.coff_header_offset + @sizeOf(coff.CoffHeader) + coff_header.size_of_optional_header;
    return @ptrCast([*]align(1) const coff.SectionHeader, self.data.ptr + offset)[0..coff_header.number_of_sections];
}

pub fn getSectionName(self: *const Zcoff, sect_hdr: *align(1) const coff.SectionHeader) []const u8 {
    const name = sect_hdr.getName() orelse blk: {
        const strtab = self.getStrtab().?;
        const name_offset = sect_hdr.getNameOffset().?;
        break :blk strtab.get(name_offset);
    };
    return name;
}

pub fn getSectionByName(self: *const Zcoff, comptime name: []const u8) ?*align(1) const coff.SectionHeader {
    for (self.getSectionHeaders()) |*sect| {
        if (mem.eql(u8, self.getSectionName(sect), name)) {
            return sect;
        }
    }
    return null;
}

// Return an owned slice full of the section data
pub fn getSectionDataAlloc(self: *const Zcoff, comptime name: []const u8, allocator: Allocator) ![]u8 {
    const sec = self.getSectionByName(name) orelse return error.MissingCoffSection;
    const out_buff = try allocator.alloc(u8, sec.virtual_size);
    mem.copy(u8, out_buff, self.data[sec.pointer_to_raw_data..][0..sec.virtual_size]);
    return out_buff;
}

pub fn getSectionByAddress(self: Zcoff, rva: u32) ?u16 {
    for (self.getSectionHeaders()) |*sect_hdr, sect_id| {
        if (rva >= sect_hdr.virtual_address and rva < sect_hdr.virtual_address + sect_hdr.virtual_size)
            return @intCast(u16, sect_id);
    } else return null;
}

pub fn getFileOffsetForAddress(self: Zcoff, rva: u32) u32 {
    const sections = self.getSectionHeaders();
    const sect_id = self.getSectionByAddress(rva).?;
    const sect = &sections[sect_id];
    return rva - sect.virtual_address + sect.pointer_to_raw_data;
}
