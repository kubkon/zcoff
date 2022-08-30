const std = @import("std");
const clap = @import("clap");
const process = std.process;

const Zcoff = @import("Zcoff.zig");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};

pub fn main() !void {
    const stderr = std.io.getStdErr().writer();

    const params = comptime [_]clap.Param(clap.Help){
        clap.parseParam("--help          Display this help and exit.") catch unreachable,
        clap.parseParam("--headers       Print headers.") catch unreachable,
        clap.parseParam("--symbols       Print symbol table.") catch unreachable,
        clap.parseParam("--relocations   Print relocations.") catch unreachable,
        clap.parseParam("--out <OUT>     Save to file.") catch unreachable,
        clap.parseParam("<FILE>") catch unreachable,
    };

    const parsers = comptime .{
        .OUT = clap.parsers.string,
        .FILE = clap.parsers.string,
    };

    var res = try clap.parse(clap.Help, &params, parsers, .{
        .allocator = gpa.allocator(),
        .diagnostic = null,
    });
    defer res.deinit();

    if (res.args.help) {
        return printUsageWithHelp(stderr, params[0..]);
    }
    if (res.positionals.len == 0) {
        return stderr.print("missing positional argument <FILE>...\n", .{});
    }

    const filename = res.positionals[0];
    const file = try std.fs.cwd().openFile(filename, .{});
    defer file.close();

    var zcoff = try Zcoff.parse(gpa.allocator(), file);
    defer zcoff.deinit();

    const out_file: ?std.fs.File = if (res.args.out) |out| try std.fs.cwd().createFile(out, .{
        .truncate = true,
    }) else null;
    defer if (out_file) |ff| ff.close();
    const writer = if (out_file) |ff| ff.writer() else std.io.getStdOut().writer();

    return zcoff.print(writer, .{
        .headers = res.args.headers,
        .symbols = res.args.symbols,
        .relocations = res.args.relocations,
    });
}

fn printUsageWithHelp(stream: anytype, comptime params: []const clap.Param(clap.Help)) !void {
    try stream.print("zcoff ", .{});
    try clap.usage(stream, clap.Help, params);
    try stream.print("\n", .{});
    try clap.help(stream, clap.Help, params, .{});
}
