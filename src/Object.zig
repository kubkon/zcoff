gpa: Allocator,
data: []const u8,
path: []const u8,

is_image: bool = false,
coff_header_offset: usize = 0,

pub fn deinit(self: *Object) void {
    self.gpa.free(self.path);
}

pub fn parse(self: *Object) !void {
    const msdos_magic = "MZ";
    const pe_pointer_offset = 0x3C;
    const pe_magic = "PE\x00\x00";

    self.is_image = mem.eql(u8, msdos_magic, self.data[0..2]);

    if (self.is_image) {
        var stream = std.io.fixedBufferStream(self.data);
        const reader = stream.reader();
        try stream.seekTo(pe_pointer_offset);
        const coff_header_offset = try reader.readInt(u32, .little);
        try stream.seekTo(coff_header_offset);
        var buf: [4]u8 = undefined;
        try reader.readNoEof(&buf);
        if (!mem.eql(u8, pe_magic, &buf)) return error.InvalidPEHeaderMagic;

        // Do some basic validation upfront
        self.coff_header_offset = coff_header_offset + 4;
        const coff_header = self.getCoffHeader();
        if (coff_header.size_of_optional_header == 0) return error.MissingPEHeader;
    }
}

pub fn print(self: *Object, writer: anytype, options: anytype) !void {
    if (self.is_image) {
        try writer.writeAll("PE signature found\n\n");
        try writer.writeAll("File type: EXECUTABLE IMAGE\n\n");
    } else {
        try writer.writeAll("No PE signature found\n\n");
        try writer.writeAll("File type: COFF OBJECT\n\n");
    }

    if (options.headers) try self.printHeaders(writer);
    if (options.directives) try self.printDirectives(writer);

    var base_relocs_dir: ?coff.ImageDataDirectory = null;
    var imports_dir: ?coff.ImageDataDirectory = null;

    if (self.is_image) {
        const data_dirs = self.getDataDirectories();
        base_relocs_dir = if (options.relocations and @intFromEnum(coff.DirectoryEntry.BASERELOC) < data_dirs.len)
            data_dirs[@intFromEnum(coff.DirectoryEntry.BASERELOC)]
        else
            null;
        imports_dir = if (options.imports and @intFromEnum(coff.DirectoryEntry.IMPORT) < data_dirs.len)
            data_dirs[@intFromEnum(coff.DirectoryEntry.IMPORT)]
        else
            null;
    }

    const sections = self.getSectionHeaders();
    for (sections, 0..) |*sect_hdr, sect_id| {
        if (options.headers) try self.printSectionHeader(writer, @intCast(sect_id), sect_hdr);
        if (options.relocations and sect_hdr.number_of_relocations > 0) try self.printRelocations(writer, @intCast(sect_id), sect_hdr);

        if (base_relocs_dir) |dir| {
            if (self.getSectionByAddress(dir.virtual_address)) |search| blk: {
                if (search != sect_id) break :blk;
                try writer.print("BASE RELOCATIONS #{X}\n", .{sect_id + 1});
                const offset = dir.virtual_address - sect_hdr.virtual_address + sect_hdr.pointer_to_raw_data;
                const base_relocs = self.data[offset..][0..dir.size];

                var slice = base_relocs;
                while (slice.len > 0) {
                    const block = @as(*align(1) const coff.BaseRelocationDirectoryEntry, @ptrCast(slice)).*;
                    const num_relocs = @divExact(block.block_size - 8, @sizeOf(coff.BaseRelocation));
                    const block_relocs = @as([*]align(1) const coff.BaseRelocation, @ptrCast(slice[8..]))[0..num_relocs];
                    slice = slice[block.block_size..];

                    try writer.print("{x: >8} RVA, {x: >8} SizeOfBlock\n", .{ block.page_rva, block.block_size });
                    for (block_relocs) |brel| {
                        try writer.print("{x: >8}  {s: <20}", .{ brel.offset, @tagName(brel.type) });
                        switch (brel.type) {
                            .ABSOLUTE => {},
                            .DIR64 => {
                                const rebase_offset = self.getFileOffsetForAddress(block.page_rva + brel.offset);
                                const pointer = mem.readInt(u64, self.data[rebase_offset..][0..8], .little);
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
            if (self.getSectionByAddress(dir.virtual_address)) |search| blk: {
                if (search != sect_id) break :blk;
                try writer.writeAll("Section contains the following imports:\n\n");
                const offset = dir.virtual_address - sect_hdr.virtual_address + sect_hdr.pointer_to_raw_data;
                const raw_imports = self.data[offset..][0..dir.size];
                const num_imports = @divExact(dir.size, @sizeOf(coff.ImportDirectoryEntry)) - 1; // We exclude the NULL entry
                const imports = @as([*]align(1) const coff.ImportDirectoryEntry, @ptrCast(raw_imports))[0..num_imports];

                const hdr = self.getOptionalHeader();
                const is_32bit = hdr.magic == coff.IMAGE_NT_OPTIONAL_HDR32_MAGIC;
                const image_base = self.getImageBase();

                for (imports) |import| {
                    const name_offset = self.getFileOffsetForAddress(import.name_rva);
                    const name = mem.sliceTo(@as([*:0]const u8, @ptrCast(self.data.ptr + name_offset)), 0);

                    try writer.print("  {s}\n", .{name});
                    try writer.print("{x: >20} Import Address Table\n", .{import.import_address_table_rva + image_base});
                    try writer.print("{x: >20} Import Name Table\n", .{import.import_lookup_table_rva + image_base});
                    try writer.print("{x: >20} time date stamp\n", .{import.time_date_stamp});
                    try writer.print("{x: >20} Index of first forwarder reference\n", .{import.forwarder_chain});

                    const lookup_table_offset = self.getFileOffsetForAddress(import.import_lookup_table_rva);
                    if (is_32bit) {
                        const raw_ptr = try std.math.alignCast(4, self.data.ptr + lookup_table_offset);
                        const raw_lookups = mem.sliceTo(@as([*:0]const u32, @ptrCast(raw_ptr)), 0);
                        for (raw_lookups) |rl| {
                            if (coff.ImportLookupEntry32.getImportByOrdinal(rl)) |_| {
                                // TODO
                            } else if (coff.ImportLookupEntry32.getImportByName(rl)) |by_name| {
                                const by_name_offset = self.getFileOffsetForAddress(by_name.name_table_rva);
                                const by_name_entry = @as(*align(1) const coff.ImportHintNameEntry, @ptrCast(self.data.ptr + by_name_offset));
                                const symbol_hint = by_name_entry.hint;
                                const symbol_name = mem.sliceTo(@as([*:0]const u8, @ptrCast(&by_name_entry.name)), 0);
                                try writer.print("{x: >30} {s}\n", .{ symbol_hint, symbol_name });
                            } else unreachable;
                        }
                    } else {
                        const raw_ptr = try std.math.alignCast(8, self.data.ptr + lookup_table_offset);
                        const raw_lookups = mem.sliceTo(@as([*:0]const u64, @ptrCast(raw_ptr)), 0);
                        for (raw_lookups) |rl| {
                            if (coff.ImportLookupEntry64.getImportByOrdinal(rl)) |_| {
                                // TODO
                            } else if (coff.ImportLookupEntry64.getImportByName(rl)) |by_name| {
                                const by_name_offset = self.getFileOffsetForAddress(by_name.name_table_rva);
                                const by_name_entry = @as(*align(1) const coff.ImportHintNameEntry, @ptrCast(self.data.ptr + by_name_offset));
                                const symbol_hint = by_name_entry.hint;
                                const symbol_name = mem.sliceTo(@as([*:0]const u8, @ptrCast(&by_name_entry.name)), 0);
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

    try self.printSummary(writer);
}

fn printHeaders(self: *Object, writer: anytype) !void {
    const coff_header = self.getCoffHeader();

    // COFF header (object and image)
    try writer.writeAll("FILE HEADER VALUES\n");
    try writer.print("{x: >20} machine ({s})\n", .{ @intFromEnum(coff_header.machine), @tagName(coff_header.machine) });
    {
        const fields = std.meta.fields(coff.CoffHeader);
        inline for (&[_][]const u8{
            "number of sections",
            "time date stamp",
            "file pointer to symbol table",
            "number of symbols",
            "size of optional header",
        }, 0..) |desc, i| {
            const field = fields[i + 1];
            try writer.print("{x: >20} {s}\n", .{ @field(coff_header, field.name), desc });
        }
    }
    try writer.print("{x: >20} {s}\n", .{ @as(u16, @bitCast(coff_header.flags)), "flags" });
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
        }, 0..) |desc, i| {
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
                }, 0..) |desc, i| {
                    const field = fields[i];
                    if (comptime mem.eql(u8, field.name, "dll_flags")) {
                        try writer.print("{x: >20} {s}\n", .{ @as(u16, @bitCast(pe_header.dll_flags)), desc });
                        try printDllFlags(pe_header.dll_flags, writer);
                    } else if (comptime mem.eql(u8, field.name, "subsystem")) {
                        try writer.print("{x: >20} {s} # ({s})\n", .{
                            @intFromEnum(pe_header.subsystem),
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
                }, 0..) |desc, i| {
                    const field = fields[i];
                    if (comptime mem.eql(u8, field.name, "dll_flags")) {
                        try writer.print("{x: >20} {s}\n", .{ @as(u16, @bitCast(pe_header.dll_flags)), desc });
                        try printDllFlags(pe_header.dll_flags, writer);
                    } else if (comptime mem.eql(u8, field.name, "subsystem")) {
                        try writer.print("{x: >20} {s} # ({s})\n", .{
                            @intFromEnum(pe_header.subsystem),
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
            }, 0..) |desc, i| {
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
        if (field.type == u1) {
            if (@field(flags, field.name) == 0b1) {
                try writer.print("{s: >22} {s}\n", .{ "", field.name });
            }
        }
    }
}

fn printSectionHeader(self: *Object, writer: anytype, sect_id: u16, sect_hdr: *align(1) const coff.SectionHeader) !void {
    const fields = std.meta.fields(coff.SectionHeader);

    try writer.print("SECTION HEADER #{X}\n", .{sect_id + 1});

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
    }, 0..) |desc, field_i| {
        const field = fields[field_i + 1];
        try writer.print("{x: >20} {s}\n", .{ @field(sect_hdr, field.name), desc });
    }

    try writer.print("{x: >20} flags\n", .{@as(u32, @bitCast(sect_hdr.flags))});
    inline for (std.meta.fields(coff.SectionHeaderFlags)) |flag_field| {
        if (flag_field.type == u1) {
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

fn printDirectives(self: *Object, writer: anytype) !void {
    // TODO handle UTF-8
    const sect = self.getSectionByName(".drectve") orelse return;
    if (sect.flags.LNK_INFO == 0) return;
    const data = self.data[sect.pointer_to_raw_data..][0..sect.size_of_raw_data];
    try writer.writeAll(
        \\  Linker Directives
        \\  _________________
        \\
    );
    var it = std.mem.splitScalar(u8, data, ' ');
    while (it.next()) |dir| {
        if (dir.len == 0) continue;
        try writer.print("  {s}\n", .{dir});
    }
    try writer.writeByte('\n');
}

fn printRelocations(self: *Object, writer: anytype, sect_id: u16, sect_hdr: *align(1) const coff.SectionHeader) !void {
    try writer.print("RELOCATIONS #{X}\n\n", .{sect_id + 1});
    const machine = self.getCoffHeader().machine;
    var i: usize = 0;
    var offset = sect_hdr.pointer_to_relocations;
    const data = self.getSectionData(sect_id);
    const symtab = self.getSymtab().?;
    const strtab = self.getStrtab().?;
    try writer.print(" {s: <8} {s: <16} {s: <16} {s: <12} {s}\n", .{ "Offset", "Type", "Applied To", "Symbol Index", "Symbol Name" });
    try writer.print(" {s:_<8} {s:_<16} {s:_<16} {s:_<12} {s:_<11}\n", .{ "_", "_", "_", "_", "_" });
    while (i < sect_hdr.number_of_relocations) : (i += 1) {
        const reloc = @as(*align(1) const Relocation, @ptrCast(self.data.ptr + offset)).*;
        // Reloc type
        var rel_type_buffer: [16]u8 = [_]u8{' '} ** 16;
        const rel_type = switch (machine) {
            .X64 => @tagName(@as(ImageRelAmd64, @enumFromInt(reloc.type))),
            .ARM64 => @tagName(@as(ImageRelArm64, @enumFromInt(reloc.type))),
            else => "unknown",
        };
        @memcpy(rel_type_buffer[0..rel_type.len], rel_type); // TODO check we don't overflow
        _ = std.ascii.upperString(&rel_type_buffer, &rel_type_buffer);
        try writer.print(" {X:0>8} {s: <16}", .{
            reloc.virtual_address,
            &rel_type_buffer,
        });
        // Applied To
        const code_size = reloc.getCodeSize(self.*);
        const code = switch (code_size) {
            0 => 0,
            1 => data[reloc.virtual_address],
            2 => mem.readInt(u16, data[reloc.virtual_address..][0..2], .little),
            4 => mem.readInt(u32, data[reloc.virtual_address..][0..4], .little),
            8 => mem.readInt(u64, data[reloc.virtual_address..][0..8], .little),
            else => unreachable,
        };
        switch (code_size) {
            0 => try writer.print("{s: <16}", .{" "}),
            1 => try writer.print("{s: <15}{X:0>2}", .{ " ", code }),
            2 => try writer.print("{s: <12}{X:0>4}", .{ " ", code }),
            4 => try writer.print("{s: <8}{X:0>8}", .{ " ", code }),
            8 => try writer.print("{X:0>16}", .{code}),
            else => unreachable,
        }
        // Symbol Index + Name
        const sym = symtab.at(reloc.symbol_table_index, .symbol).symbol;
        const name = sym.getName() orelse blk: {
            const off = sym.getNameOffset() orelse return error.MalformedSymbolRecord;
            break :blk strtab.get(off);
        };

        try writer.print(" {X: >12} {s}\n", .{
            reloc.symbol_table_index,
            name,
        });

        offset += 10;
    }
    try writer.writeByte('\n');
}

fn printSymbols(self: *Object, writer: anytype) !void {
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
            try writer.print("{X:0>3} {X:0>8} ", .{ index, sym.value });
            switch (sym.section_number) {
                .UNDEFINED,
                .ABSOLUTE,
                .DEBUG,
                => try writer.print("{s: <9} ", .{@tagName(sym.section_number)}),
                else => try writer.print("SECT{X: <5} ", .{@intFromEnum(sym.section_number)}),
            }
            const name = sym.getName() orelse blk: {
                const offset = sym.getNameOffset() orelse return error.MalformedSymbolRecord;
                break :blk strtab.get(offset);
            };
            try writer.print("{s: <6} {s: <8} {s: <20} | {s}\n", .{
                @tagName(sym.type.base_type),
                @tagName(sym.type.complex_type),
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
                        if (sym.storage_class == .EXTERNAL and sym.type.complex_type == .FUNCTION) {
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
                    const sect = sections[@intFromEnum(st_sym.section_number) - 1];
                    if (sect.isComdat()) {
                        try writer.print(", selection {d} ({s})", .{ @intFromEnum(sect_def.selection), @tagName(sect_def.selection) });
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

fn printSummary(self: Object, writer: anytype) !void {
    try writer.writeAll("  Summary\n\n");

    const sections = self.getSectionHeaders();

    var arena = std.heap.ArenaAllocator.init(self.gpa);
    defer arena.deinit();

    var summary = std.StringArrayHashMap(u64).init(arena.allocator());
    try summary.ensureUnusedCapacity(sections.len);

    for (sections) |sect| {
        const name = sect.getName() orelse self.getStrtab().?.get(sect.getNameOffset().?);
        const gop = summary.getOrPutAssumeCapacity(try arena.allocator().dupe(u8, name));
        if (!gop.found_existing) gop.value_ptr.* = 0;
        gop.value_ptr.* += if (self.is_image)
            mem.alignForward(u64, sect.virtual_size, 0x1000) // TODO don't always assume 0x1000 page size
        else
            sect.size_of_raw_data;
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

pub fn getCoffHeader(self: Object) coff.CoffHeader {
    return @as(*align(1) const coff.CoffHeader, @ptrCast(self.data[self.coff_header_offset..][0..@sizeOf(coff.CoffHeader)])).*;
}

pub fn getOptionalHeader(self: Object) coff.OptionalHeader {
    assert(self.is_image);
    const offset = self.coff_header_offset + @sizeOf(coff.CoffHeader);
    return @as(*align(1) const coff.OptionalHeader, @ptrCast(self.data[offset..][0..@sizeOf(coff.OptionalHeader)])).*;
}

pub fn getOptionalHeader32(self: Object) coff.OptionalHeaderPE32 {
    assert(self.is_image);
    const offset = self.coff_header_offset + @sizeOf(coff.CoffHeader);
    return @as(*align(1) const coff.OptionalHeaderPE32, @ptrCast(self.data[offset..][0..@sizeOf(coff.OptionalHeaderPE32)])).*;
}

pub fn getOptionalHeader64(self: Object) coff.OptionalHeaderPE64 {
    assert(self.is_image);
    const offset = self.coff_header_offset + @sizeOf(coff.CoffHeader);
    return @as(*align(1) const coff.OptionalHeaderPE64, @ptrCast(self.data[offset..][0..@sizeOf(coff.OptionalHeaderPE64)])).*;
}

pub fn getImageBase(self: Object) u64 {
    const hdr = self.getOptionalHeader();
    return switch (hdr.magic) {
        coff.IMAGE_NT_OPTIONAL_HDR32_MAGIC => self.getOptionalHeader32().image_base,
        coff.IMAGE_NT_OPTIONAL_HDR64_MAGIC => self.getOptionalHeader64().image_base,
        else => unreachable, // We assume we have validated the header already
    };
}

pub fn getNumberOfDataDirectories(self: Object) u32 {
    const hdr = self.getOptionalHeader();
    return switch (hdr.magic) {
        coff.IMAGE_NT_OPTIONAL_HDR32_MAGIC => self.getOptionalHeader32().number_of_rva_and_sizes,
        coff.IMAGE_NT_OPTIONAL_HDR64_MAGIC => self.getOptionalHeader64().number_of_rva_and_sizes,
        else => unreachable, // We assume we have validated the header already
    };
}

pub fn getDataDirectories(self: *const Object) []align(1) const coff.ImageDataDirectory {
    const hdr = self.getOptionalHeader();
    const size: usize = switch (hdr.magic) {
        coff.IMAGE_NT_OPTIONAL_HDR32_MAGIC => @sizeOf(coff.OptionalHeaderPE32),
        coff.IMAGE_NT_OPTIONAL_HDR64_MAGIC => @sizeOf(coff.OptionalHeaderPE64),
        else => unreachable, // We assume we have validated the header already
    };
    const offset = self.coff_header_offset + @sizeOf(coff.CoffHeader) + size;
    return @as([*]align(1) const coff.ImageDataDirectory, @ptrCast(self.data[offset..]))[0..self.getNumberOfDataDirectories()];
}

pub fn getSymtab(self: *const Object) ?coff.Symtab {
    const coff_header = self.getCoffHeader();
    if (coff_header.pointer_to_symbol_table == 0) return null;

    const offset = coff_header.pointer_to_symbol_table;
    const size = coff_header.number_of_symbols * coff.Symbol.sizeOf();
    return .{ .buffer = self.data[offset..][0..size] };
}

pub fn getStrtab(self: *const Object) ?coff.Strtab {
    const coff_header = self.getCoffHeader();
    if (coff_header.pointer_to_symbol_table == 0) return null;

    const offset = coff_header.pointer_to_symbol_table + coff.Symbol.sizeOf() * coff_header.number_of_symbols;
    const size = mem.readInt(u32, self.data[offset..][0..4], .little);
    return .{ .buffer = self.data[offset..][0..size] };
}

pub fn getSectionHeaders(self: *const Object) []align(1) const coff.SectionHeader {
    const coff_header = self.getCoffHeader();
    const offset = self.coff_header_offset + @sizeOf(coff.CoffHeader) + coff_header.size_of_optional_header;
    return @as([*]align(1) const coff.SectionHeader, @ptrCast(self.data.ptr + offset))[0..coff_header.number_of_sections];
}

pub fn getSectionName(self: *const Object, sect_hdr: *align(1) const coff.SectionHeader) []const u8 {
    const name = sect_hdr.getName() orelse blk: {
        const strtab = self.getStrtab().?;
        const name_offset = sect_hdr.getNameOffset().?;
        break :blk strtab.get(name_offset);
    };
    return name;
}

pub fn getSectionByName(self: *const Object, comptime name: []const u8) ?*align(1) const coff.SectionHeader {
    for (self.getSectionHeaders()) |*sect| {
        if (mem.eql(u8, self.getSectionName(sect), name)) {
            return sect;
        }
    }
    return null;
}

pub fn getSectionData(self: *const Object, sect_id: u16) []const u8 {
    const sec = self.getSectionHeaders()[sect_id];
    return self.data[sec.pointer_to_raw_data..][0..sec.size_of_raw_data];
}

pub fn getSectionByAddress(self: Object, rva: u32) ?u16 {
    for (self.getSectionHeaders(), 0..) |*sect_hdr, sect_id| {
        if (rva >= sect_hdr.virtual_address and rva < sect_hdr.virtual_address + sect_hdr.virtual_size)
            return @as(u16, @intCast(sect_id));
    } else return null;
}

pub fn getFileOffsetForAddress(self: Object, rva: u32) u32 {
    const sections = self.getSectionHeaders();
    const sect_id = self.getSectionByAddress(rva).?;
    const sect = &sections[sect_id];
    return rva - sect.virtual_address + sect.pointer_to_raw_data;
}

const Relocation = extern struct {
    virtual_address: u32,
    symbol_table_index: u32,
    type: u16,

    fn getCodeSize(rel: Relocation, obj: Object) u8 {
        const machine = obj.getCoffHeader().machine;
        return switch (machine) {
            .X64 => switch (@as(ImageRelAmd64, @enumFromInt(rel.type))) {
                .absolute => 0,
                .addr64 => 8,
                .addr32,
                .addr32nb,
                .rel32,
                .rel32_1,
                .rel32_2,
                .rel32_3,
                .rel32_4,
                .rel32_5,
                => 4,
                .section => 2,
                .secrel => 4,
                .secrel7 => 1,
                .token => 8,
                .srel32 => 4,
                .pair,
                .sspan32,
                => 4,
            },
            .ARM64 => switch (@as(ImageRelArm64, @enumFromInt(rel.type))) {
                .absolute => 0,
                .addr32,
                .addr32nb,
                => 4,
                .branch26,
                .pagebase_rel21,
                .rel21,
                .pageoffset_12a,
                .pageoffset_12l,
                .low12a,
                .high12a,
                .low12l,
                => 4,
                .secrel => 4,
                .token => 8,
                .section => 2,
                .addr64 => 8,
                .branch19, .branch14 => 4,
                .rel32 => 4,
            },
            else => @panic("TODO this arch support"),
        };
    }
};

const ImageRelAmd64 = enum(u16) {
    /// The relocation is ignored.
    absolute = 0,

    /// The 64-bit VA of the relocation target.
    addr64 = 1,

    /// The 32-bit VA of the relocation target.
    addr32 = 2,

    /// The 32-bit address without an image base.
    addr32nb = 3,

    /// The 32-bit relative address from the byte following the relocation.
    rel32 = 4,

    /// The 32-bit address relative to byte distance 1 from the relocation.
    rel32_1 = 5,

    /// The 32-bit address relative to byte distance 2 from the relocation.
    rel32_2 = 6,

    /// The 32-bit address relative to byte distance 3 from the relocation.
    rel32_3 = 7,

    /// The 32-bit address relative to byte distance 4 from the relocation.
    rel32_4 = 8,

    /// The 32-bit address relative to byte distance 5 from the relocation.
    rel32_5 = 9,

    /// The 16-bit section index of the section that contains the target.
    /// This is used to support debugging information.
    section = 10,

    /// The 32-bit offset of the target from the beginning of its section.
    /// This is used to support debugging information and static thread local storage.
    secrel = 11,

    /// A 7-bit unsigned offset from the base of the section that contains the target.
    secrel7 = 12,

    /// CLR tokens.
    token = 13,

    /// A 32-bit signed span-dependent value emitted into the object.
    srel32 = 14,

    /// A pair that must immediately follow every span-dependent value.
    pair = 15,

    /// A 32-bit signed span-dependent value that is applied at link time.
    sspan32 = 16,
};

const ImageRelArm64 = enum(u16) {
    /// The relocation is ignored.
    absolute = 0,

    /// The 32-bit VA of the target.
    addr32 = 1,

    /// The 32-bit RVA of the target.
    addr32nb = 2,

    /// The 26-bit relative displacement to the target, for B and BL instructions.
    branch26 = 3,

    /// The page base of the target, for ADRP instruction.
    pagebase_rel21 = 4,

    /// The 21-bit relative displacement to the target, for instruction ADR.
    rel21 = 5,

    /// The 12-bit page offset of the target, for instructions ADD/ADDS (immediate) with zero shift.
    pageoffset_12a = 6,

    /// The 12-bit page offset of the target, for instruction LDR (indexed, unsigned immediate).
    pageoffset_12l = 7,

    /// The 32-bit offset of the target from the beginning of its section.
    /// This is used to support debugging information and static thread local storage.
    secrel = 8,

    /// Bit 0:11 of section offset of the target for instructions ADD/ADDS (immediate) with zero shift.
    low12a = 9,

    /// Bit 12:23 of section offset of the target, for instructions ADD/ADDS (immediate) with zero shift.
    high12a = 10,

    /// Bit 0:11 of section offset of the target, for instruction LDR (indexed, unsigned immediate).
    low12l = 11,

    /// CLR token.
    token = 12,

    /// The 16-bit section index of the section that contains the target.
    /// This is used to support debugging information.
    section = 13,

    /// The 64-bit VA of the relocation target.
    addr64 = 14,

    /// The 19-bit offset to the relocation target, for conditional B instruction.
    branch19 = 15,

    /// The 14-bit offset to the relocation target, for instructions TBZ and TBNZ.
    branch14 = 16,

    /// The 32-bit relative address from the byte following the relocation.
    rel32 = 17,
};

const assert = std.debug.assert;
const coff = std.coff;
const fs = std.fs;
const mem = std.mem;
const std = @import("std");

const Allocator = mem.Allocator;
const Object = @This();
