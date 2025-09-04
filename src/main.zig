const std = @import("std");
const Library = @import("Library.zig");
const Object = @import("Object.zig");

var allocator = std.heap.GeneralPurposeAllocator(.{}){};
const gpa = allocator.allocator();

const usage =
    \\Usage: zcoff [options] file
    \\
    \\General options:
    \\-archivemembers            Print archive members summary.
    \\-archivesymbols            Print archive symbol table.
    \\-directives                Print linker directives.
    \\-headers                   Print headers.
    \\-symbols                   Print symbol table.
    \\-imports                   Print import table.
    \\-relocations               Print relocations.
    \\-help, /?                  Display this help and exit.
    \\
;

fn fatal(comptime format: []const u8, args: anytype) noreturn {
    ret: {
        const msg = std.fmt.allocPrint(gpa, format ++ "\n", args) catch break :ret;
        std.fs.File.stdout().writeAll(msg) catch {};
    }
    std.process.exit(1);
}

const ArgsIterator = struct {
    args: []const []const u8,
    i: usize = 0,

    fn next(it: *@This()) ?[]const u8 {
        if (it.i >= it.args.len) {
            return null;
        }
        defer it.i += 1;
        return it.args[it.i];
    }

    fn nextOrFatal(it: *@This()) []const u8 {
        return it.next() orelse fatal("expected parameter after {s}", .{it.args[it.i - 1]});
    }
};

const ArgsParser = struct {
    next_arg: []const u8 = undefined,
    it: *ArgsIterator,

    pub fn hasMore(p: *ArgsParser) bool {
        p.next_arg = p.it.next() orelse return false;
        return true;
    }

    pub fn flagAny(p: *ArgsParser, comptime pat: []const u8) bool {
        return p.flagPrefix(pat, "-") or p.flagWindows(pat);
    }

    pub fn flagWindows(p: *ArgsParser, comptime pat: []const u8) bool {
        return p.flagPrefix(pat, "/");
    }

    fn flagPrefix(p: *ArgsParser, comptime pat: []const u8, comptime prefix: []const u8) bool {
        if (std.mem.startsWith(u8, p.next_arg, prefix)) {
            const actual_arg = p.next_arg[prefix.len..];
            if (std.mem.eql(u8, actual_arg, pat)) {
                return true;
            }
        }
        return false;
    }

    pub fn arg(p: *ArgsParser, comptime pat: []const u8) ?[]const u8 {
        return p.argPrefix(pat, "-") orelse p.argPrefix(pat, "/");
    }

    fn argPrefix(p: *ArgsParser, comptime pat: []const u8, comptime prefix: []const u8) ?[]const u8 {
        if (std.mem.startsWith(u8, p.next_arg, prefix)) {
            const actual_arg = p.next_arg[prefix.len..];
            if (std.mem.startsWith(u8, actual_arg, pat)) {
                if (std.mem.indexOf(u8, actual_arg, ":")) |index| {
                    if (index == pat.len) {
                        const value = actual_arg[index + 1 ..];
                        return value;
                    }
                }
            }
        }
        return null;
    }
};

pub fn main() !void {
    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const all_args = try std.process.argsAlloc(arena);
    const args = all_args[1..];

    if (args.len == 0) fatal(usage, .{});

    var filename: ?[]const u8 = null;
    var print_matrix: PrintMatrix = .{};

    var it = ArgsIterator{ .args = args };
    var p = ArgsParser{ .it = &it };
    while (p.hasMore()) {
        if (p.flagAny("help") or p.flagWindows("?")) {
            fatal(usage, .{});
        } else if (p.flagAny("archivemembers")) {
            print_matrix.archive_members = true;
        } else if (p.flagAny("archivesymbols")) {
            print_matrix.archive_symbols = true;
        } else if (p.flagAny("directives")) {
            print_matrix.directives = true;
        } else if (p.flagAny("headers")) {
            print_matrix.headers = true;
        } else if (p.flagAny("symbols")) {
            print_matrix.symbols = true;
        } else if (p.flagAny("imports")) {
            print_matrix.imports = true;
        } else if (p.flagAny("relocations")) {
            print_matrix.relocations = true;
        } else {
            if (filename != null) fatal("too many positional arguments specified", .{});
            filename = p.next_arg;
        }
    }

    const fname = filename orelse fatal("no input file specified", .{});
    const file = try std.fs.cwd().openFile(fname, .{});
    defer file.close();
    const data = try file.readToEndAlloc(arena, std.math.maxInt(u32));

    var buffer: [1024]u8 = undefined;
    var fw = std.fs.File.stdout().writer(&buffer);
    var stdout = &fw.interface;
    defer stdout.flush() catch fatal("could not write to stdout", .{});
    try stdout.print("Dump of file {s}\n\n", .{fname});

    if (Library.isLibrary(data)) {
        var library = Library{ .gpa = gpa, .data = data };
        try library.parse();
        try stdout.writeAll("File Type: LIBRARY\n\n");
        try library.print(stdout, print_matrix);
    } else {
        var object = Object{ .gpa = gpa, .data = data };

        const msdos_magic = "MZ";
        const pe_pointer_offset = 0x3C;
        const pe_magic = "PE\x00\x00";
        const is_image = std.mem.eql(u8, msdos_magic, data[0..2]);
        object.is_image = is_image;

        if (is_image) {
            var stream = std.io.fixedBufferStream(data);
            const reader = stream.reader();
            try stream.seekTo(pe_pointer_offset);
            const coff_header_offset = try reader.readInt(u32, .little);
            try stream.seekTo(coff_header_offset);
            var buf: [4]u8 = undefined;
            try reader.readNoEof(&buf);
            if (!std.mem.eql(u8, pe_magic, &buf))
                fatal("invalid PE file - invalid magic bytes", .{});

            // Do some basic validation upfront
            object.coff_header_offset = coff_header_offset + 4;
            const coff_header = object.getCoffHeader();
            if (coff_header.size_of_optional_header == 0)
                fatal("invalid PE file - missing PE header", .{});
        }

        if (is_image) {
            try stdout.writeAll("File Type: EXECUTABLE IMAGE\n\n");
        } else {
            try stdout.writeAll("File Type: COFF OBJECT\n\n");
        }

        try object.print(stdout, print_matrix);
    }
}

pub const PrintMatrix = packed struct {
    archive_members: bool = false,
    archive_symbols: bool = false,
    directives: bool = false,
    headers: bool = false,
    symbols: bool = false,
    imports: bool = false,
    relocations: bool = false,
    summary: bool = true,

    const Int = blk: {
        const bits = @typeInfo(@This()).Struct.fields.len;
        break :blk @Type(.{
            .Int = .{
                .signedness = .unsigned,
                .bits = bits,
            },
        });
    };

    fn enableAll() @This() {
        return @as(@This(), @bitCast(~@as(Int, 0)));
    }

    fn isUnset(pm: @This()) bool {
        return @as(Int, @bitCast(pm)) == 0;
    }

    fn add(pm: *@This(), other: @This()) void {
        pm.* = @as(@This(), @bitCast(@as(Int, @bitCast(pm.*)) | @as(Int, @bitCast(other))));
    }
};
