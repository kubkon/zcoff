const std = @import("std");
const Object = @import("Object.zig");

var allocator = std.heap.GeneralPurposeAllocator(.{}){};
const gpa = allocator.allocator();

const usage =
    \\Usage: zcoff [options] file
    \\
    \\General options:
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
        std.io.getStdErr().writeAll(msg) catch {};
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

    const stdout = std.io.getStdOut().writer();
    try stdout.print("Dump of file {s}\n\n", .{fname});

    var object = Object{ .gpa = gpa, .data = data };
    object.parse() catch |err| switch (err) {
        error.InvalidPEHeaderMagic => fatal("invalid PE file - invalid magic bytes", .{}),
        error.MissingPEHeader => fatal("invalid PE file - missing PE header", .{}),
        else => |e| return e,
    };
    try object.print(stdout, print_matrix);
}

pub const PrintMatrix = packed struct {
    directives: bool = false,
    headers: bool = false,
    symbols: bool = false,
    imports: bool = false,
    relocations: bool = false,

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
