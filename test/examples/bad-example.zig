// Zig bad example anti-patterns
const std = @import("std");

pub fn recursiveFactorial(n: u64) u64 {
    if (n <= 1) return 1;
    return n * recursiveFactorial(n - 1);
}

pub fn unboundedLoop() void {
    while (true) {
        std.debug.print("looping\n", .{});
    }
}
