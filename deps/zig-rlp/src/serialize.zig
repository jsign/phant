const std = @import("std");
const testing = std.testing;
const ArrayList = std.array_list.Managed;
const Allocator = std.mem.Allocator;
const hasFn = std.meta.hasFn;

pub const deserialize = @import("deserialize.zig").deserialize;

fn writeLengthLength(length: usize, list: *ArrayList(u8)) !u8 {
    var enc_length_buf: [8]u8 = undefined;
    std.mem.writeInt(usize, &enc_length_buf, length, .big);
    const enc_length = std.mem.trimLeft(u8, &enc_length_buf, &[_]u8{0});
    try list.appendSlice(enc_length);
    return @as(u8, @intCast(enc_length.len));
}

pub const SerializationError = error{
    UnsupportedType,
    OutOfMemory,
};

pub fn serialize(comptime T: type, allocator: Allocator, data: T, list: *ArrayList(u8)) SerializationError!void {
    if (comptime hasFn(T, "encodeToRLP")) {
        return data.encodeToRLP(allocator, list);
    }
    const info = @typeInfo(T);
    return switch (info) {
        .int => switch (data) {
            0 => list.append(0x80),
            1...127 => list.append(@truncate(data)),

            else => {
                // write integer to temp buffer so that it can
                // be left-trimmed.
                var tlist = ArrayList(u8).init(list.allocator);
                defer tlist.deinit();
                try tlist.writer().writeInt(T, data, .big);
                var start_offset: usize = 0; // note that only numbers up to 255 will work
                while (tlist.items[start_offset] == 0) : (start_offset += 1) {}

                // copy final header + trimmed data
                try list.append(@as(u8, @truncate(128 + tlist.items.len - start_offset)));
                _ = try list.writer().write(tlist.items[start_offset..]);
            },
        },
        .array => {
            // shortcut for byte lists
            if (@sizeOf(info.array.child) == 1) {
                switch (data.len) {
                    0 => try list.append(128),
                    1 => if (data[0] >= 128) {
                        try list.append(129);
                    },
                    2...55 => try list.append(128 + data.len),
                    else => {
                        comptime var length_length = 0;
                        comptime {
                            var l = @sizeOf(T);
                            while (l != 0) : (l >>= 8) {
                                length_length += 1;
                            }
                        }

                        try list.append(183 + length_length);
                        _ = try writeLengthLength(@sizeOf(T), list);
                    },
                }
                _ = try list.writer().write(data[0..]);
            } else {
                var tlist = ArrayList(u8).init(allocator);
                defer tlist.deinit();
                for (data) |item| {
                    try serialize(info.array.child, allocator, item, &tlist);
                }

                if (tlist.items.len < 56) {
                    try list.append(192 + @as(u8, @truncate(tlist.items.len)));
                } else {
                    const index = list.items.len;
                    try list.append(0);
                    const length = tlist.items.len;

                    const length_length = try writeLengthLength(length, list);
                    list.items[index] = 247 + length_length;
                }
                _ = try list.writer().write(tlist.items);
            }
        },
        .@"struct" => |sinfo| {
            var tlist = ArrayList(u8).init(allocator);
            defer tlist.deinit();
            inline for (sinfo.fields) |field| {
                try serialize(field.type, allocator, @field(data, field.name), &tlist);
            }
            if (tlist.items.len < 56) {
                try list.append(192 + @as(u8, @truncate(tlist.items.len)));
            } else {
                const index = list.items.len;
                try list.append(0);
                const length_length = try writeLengthLength(tlist.items.len, list);
                list.items[index] = 247 + length_length;
            }
            _ = try list.writer().write(tlist.items);
        },
        .pointer => |ptr| {
            switch (ptr.size) {
                .slice => {
                    // Simple case: string
                    if (@sizeOf(ptr.child) == 1) {
                        switch (data.len) {
                            0 => try list.append(128),
                            // if data.len == 1 and data[0] < 128, don't write the header
                            // the write after this switch will add the unprefixed data.
                            1 => if (data[0] >= 128) try list.append(129),
                            2...55 => try list.append(128 + @as(u8, @truncate(data.len))),
                            else => {
                                const header_offset = list.items.len;
                                try list.append(0); // reserve space for the size header
                                const length_length = try writeLengthLength(data.len, list);
                                list.items[header_offset] = 183 + length_length;
                            },
                        }
                        _ = try list.writer().write(data);
                    } else {
                        var tlist = ArrayList(u8).init(allocator);
                        defer tlist.deinit();
                        for (data) |item| {
                            try serialize(ptr.child, allocator, item, &tlist);
                        }

                        if (tlist.items.len < 56) {
                            try list.append(192 + @as(u8, @truncate(tlist.items.len)));
                        } else {
                            const index = list.items.len;
                            try list.append(0);
                            const length_length: u8 = try writeLengthLength(tlist.items.len, list);

                            list.items[index] = 247 + length_length;
                        }
                        _ = try list.writer().write(tlist.items);
                    }
                },
                .one => {
                    try serialize(ptr.child, allocator, data.*, list);
                },
                else => return error.UnsupportedType,
            }
        },
        .optional => |opt| {
            if (data == null) {
                try list.append(0x80);
            } else {
                try serialize(opt.child, allocator, data.?, list);
            }
        },
        .null => {
            try list.append(0x80);
        },
        .bool => {
            try list.append(if (data) 1 else 0);
        },
        else => return error.UnsupportedType,
    };
}

const RawRLPValue = union(enum) {
    value: []const u8,
    list: []const RawRLPValue,

    pub fn encodeToRLP(self: RawRLPValue, allocator: Allocator, list: *std.ArrayList(u8)) !void {
        return switch (self) {
            .value => |v| {
                try serialize([]const u8, allocator, v, list);
            },
            .list => |v| {
                try serialize([]const RawRLPValue, allocator, v, list);
            },
        };
    }
};

test "serialize an integer" {
    var list = ArrayList(u8).init(testing.allocator);
    defer list.deinit();
    try serialize(u8, testing.allocator, 42, &list);
    const expected1 = [_]u8{42};
    try testing.expect(std.mem.eql(u8, list.items[0..], expected1[0..]));

    list.clearRetainingCapacity();
    try serialize(u8, testing.allocator, 129, &list);
    const expected2 = [_]u8{ 129, 129 };
    try testing.expect(std.mem.eql(u8, list.items[0..], expected2[0..]));

    list.clearRetainingCapacity();
    try serialize(u8, testing.allocator, 128, &list);
    const expected3 = [_]u8{ 129, 128 };
    try testing.expect(std.mem.eql(u8, list.items[0..], expected3[0..]));

    list.clearRetainingCapacity();
    try serialize(u16, testing.allocator, 0xabcd, &list);
    const expected4 = [_]u8{ 130, 0xab, 0xcd };
    try testing.expect(std.mem.eql(u8, list.items[0..], expected4[0..]));

    // Check that multi-byte values that are < 128 also serialize as a
    // single byte integer.
    list.clearRetainingCapacity();
    try serialize(u16, testing.allocator, 42, &list);
    try testing.expect(std.mem.eql(u8, list.items[0..], expected1[0..]));

    list.clearRetainingCapacity();
    try serialize(u32, testing.allocator, 0xdeadbeef, &list);
    const expected6 = [_]u8{ 132, 0xde, 0xad, 0xbe, 0xef };
    try testing.expect(std.mem.eql(u8, list.items[0..], expected6[0..]));
}

test "serialize a byte array" {
    var list = ArrayList(u8).init(testing.allocator);
    defer list.deinit();
    const src = [_]u8{ 1, 2, 3, 4 };
    try serialize([4]u8, testing.allocator, src, &list);
    const expected = [_]u8{ 132, 1, 2, 3, 4 };
    try testing.expect(std.mem.eql(u8, list.items[0..], expected[0..]));

    list.clearRetainingCapacity();
    const src8x58 = [_]u8{0xab} ** 58;
    try serialize([58]u8, testing.allocator, src8x58, &list);
    const expected8x58 = [_]u8{ 0xb8, 0x3a } ++ [_]u8{0xab} ** 58;
    try testing.expect(std.mem.eql(u8, list.items[0..], expected8x58[0..]));

    list.clearRetainingCapacity();
    const src8x1K = [_]u8{0xab} ** 1024;
    try serialize(@TypeOf(src8x1K), testing.allocator, src8x1K, &list);
    const expected8x1K = [_]u8{ 0xb9, 0x04, 0x00 } ++ [_]u8{0xab} ** 1024;
    try testing.expect(std.mem.eql(u8, list.items[0..], expected8x1K[0..]));
}

test "serialize a u16 array" {
    var list = ArrayList(u8).init(testing.allocator);
    defer list.deinit();
    const src16 = [_]u16{ 0xabcd, 0xef01 };
    try serialize([2]u16, testing.allocator, src16, &list);
    const expected16 = [_]u8{ 198, 130, 0xab, 0xcd, 130, 0xef, 0x01 };
    try testing.expect(std.mem.eql(u8, list.items[0..], expected16[0..]));

    list.clearRetainingCapacity();
    const src16x1K = [_]u16{0xabcd} ** 1024;
    try serialize(@TypeOf(src16x1K), testing.allocator, src16x1K, &list);
    const expected16x1K = [_]u8{ 0xf9, 0x0C, 0 } ++ [_]u8{ 130, 0xab, 0xcd } ** 1024;
    try testing.expect(std.mem.eql(u8, list.items[0..], expected16x1K[0..]));
}

test "serialize a string" {
    var list = ArrayList(u8).init(testing.allocator);
    defer list.deinit();
    try serialize([]const u8, testing.allocator, "hello", &list);
    const expected = [_]u8{ 133, 'h', 'e', 'l', 'l', 'o' };
    try testing.expect(std.mem.eql(u8, list.items[0..], expected[0..]));
}

test "serialize a struct" {
    var list = ArrayList(u8).init(testing.allocator);
    defer list.deinit();
    const Person = struct {
        age: u8,
        name: []const u8,
    };
    const jc = Person{ .age = 123, .name = "Jeanne Calment" };
    try serialize(Person, testing.allocator, jc, &list);
    const expected = [_]u8{ 0xc2 + jc.name.len, 123, 128 + jc.name.len } ++ jc.name;
    try testing.expect(std.mem.eql(u8, list.items[0..], expected[0..]));
}

test "serialize a struct with serialized length > 56" {
    var list = ArrayList(u8).init(testing.allocator);
    defer list.deinit();
    const Person = struct {
        age: u8,
        name: []const u8,
    };
    const dt = Person{ .age = 24, .name = "Daenerys Stormborn of the House Targaryen, First of Her Name, the Unburnt, Queen of the Andals and the First Men, Khaleesi of the Great Grass Sea, Breaker of Chains, and Mother of Dragons" };
    try serialize(Person, testing.allocator, dt, &list);
    const expected = [_]u8{ 0xf8, @as(u8, dt.name.len) + 3, 24, 184, @as(u8, dt.name.len) } ++ dt.name;
    try testing.expect(std.mem.eql(u8, list.items[0..], expected[0..]));
}

test "serialize a struct with functions" {
    var list = ArrayList(u8).init(testing.allocator);
    defer list.deinit();
    const Person = struct {
        age: u8,
        name: []const u8,

        pub fn sayHello() void {
            std.debug.print("hello", .{});
        }
    };
    const jc = Person{ .age = 123, .name = "Jeanne Calment" };
    try serialize(Person, testing.allocator, jc, &list);
    const expected = [_]u8{ 0xc2 + jc.name.len, 123, 128 + jc.name.len } ++ jc.name;
    try testing.expect(std.mem.eql(u8, list.items[0..], expected[0..]));
}

test "serialize a boolean" {
    var list = ArrayList(u8).init(testing.allocator);
    defer list.deinit();
    try serialize(bool, testing.allocator, false, &list);
    var expected = [_]u8{0};
    try testing.expect(std.mem.eql(u8, list.items[0..], expected[0..]));

    list.clearRetainingCapacity();
    expected[0] = 1;
    try serialize(bool, testing.allocator, true, &list);
    try testing.expect(std.mem.eql(u8, list.items[0..], expected[0..]));
}

const RLPEncodablePerson = struct {
    name: []const u8,
    age: u8,

    pub fn encodeToRLP(self: RLPEncodablePerson, allocator: Allocator, list: *ArrayList(u8)) !void {
        _ = allocator;
        _ = self;
        return list.append(42);
    }
};

test "custom serializer" {
    var list = ArrayList(u8).init(testing.allocator);
    defer list.deinit();
    const jdoe = RLPEncodablePerson{ .name = "John Doe", .age = 57 };
    try serialize(RLPEncodablePerson, testing.allocator, jdoe, &list);
    try testing.expect(list.items.len == 1);
    try testing.expect(list.items[0] == 42);
}

test "ensure an int is tightly packed" {
    var list = ArrayList(u8).init(testing.allocator);
    defer list.deinit();

    const i: u256 = 0x1234;
    const expected = [_]u8{ 0x82, 0x12, 0x34 };
    try serialize(u256, testing.allocator, i, &list);
    try testing.expect(std.mem.eql(u8, list.items[0..], expected[0..]));
}

test "zero" {
    var out = ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();

    try serialize(u8, std.testing.allocator, 0, &out);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x80}, out.items);
}

test "access list filled" {
    const AccessListItem = struct {
        address: [20]u8,
        storage_keys: [][32]u8,
    };
    const StrippedTxn = struct {
        access_list: []AccessListItem,
    };

    var buf: [128]u8 = undefined;
    const rlp = try std.fmt.hexToBytes(&buf, "f83af838f7940000000000000000000000000000000000001210e1a00000000000000000000000000000000000000000000000000000000000000203");
    var out: StrippedTxn = undefined;
    _ = try deserialize(StrippedTxn, testing.allocator, rlp, &out);

    const expected_address = [_]u8{0} ** 18 ++ [_]u8{ 0x12, 0x10 };
    try testing.expectEqual(out.access_list[0].address, expected_address);

    const expected_access = [_]u8{0} ** 30 ++ [_]u8{ 2, 3 };
    try testing.expectEqual(out.access_list[0].storage_keys[0], expected_access);

    testing.allocator.free(out.access_list[0].storage_keys);
    testing.allocator.free(out.access_list);
}

test "one byte slice" {
    var out = ArrayList(u8).init(testing.allocator);
    defer out.deinit();
    const bytes = [_]u8{0x00};

    try serialize([]const u8, std.testing.allocator, &bytes, &out);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x00}, out.items);
}

test "one byte slicei with value == 128" {
    var out = ArrayList(u8).init(testing.allocator);
    defer out.deinit();
    const bytes = [_]u8{0x80};

    try serialize([]const u8, std.testing.allocator, &bytes, &out);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x81, 0x80 }, out.items);
}

test "one byte slicei with value > 128" {
    var out = ArrayList(u8).init(testing.allocator);
    defer out.deinit();
    const bytes = [_]u8{0xff};

    try serialize([]const u8, std.testing.allocator, &bytes, &out);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x81, 0xff }, out.items);
}

test "raw rlp" {
    const allocator = std.testing.allocator;
    {
        var out_generic = ArrayList(u8).init(allocator);
        defer out_generic.deinit();
        const generic: RawRLPValue = .{ .value = "hello" };
        try serialize(RawRLPValue, allocator, generic, &out_generic);

        var out = ArrayList(u8).init(allocator);
        defer out.deinit();
        const normal = "hello";
        try serialize([]const u8, allocator, normal, &out);

        try std.testing.expectEqualSlices(u8, out.items, out_generic.items);
    }
    {
        var out_generic = ArrayList(u8).init(allocator);
        defer out_generic.deinit();
        const generic: RawRLPValue = .{ .list = &[_]RawRLPValue{ .{ .value = "hello" }, .{ .value = "world" } } };
        try serialize(RawRLPValue, allocator, generic, &out_generic);

        var out = ArrayList(u8).init(allocator);
        defer out.deinit();
        var normal = [_][]const u8{ "hello", "world" };
        try serialize([]const []const u8, allocator, &normal, &out);

        try std.testing.expectEqualSlices(u8, out.items, out_generic.items);
    }
    {
        var out_generic = ArrayList(u8).init(allocator);
        defer out_generic.deinit();
        const generic: RawRLPValue = .{
            .list = &[_]RawRLPValue{
                .{ .value = "hello" },
                .{ .value = "world" },
                .{ .list = &[_]RawRLPValue{.{ .value = "nested" }} },
            },
        };
        try serialize(RawRLPValue, allocator, generic, &out_generic);

        var out = ArrayList(u8).init(allocator);
        defer out.deinit();
        const normal: struct { a: []const u8, b: []const u8, c: []const []const u8 } = .{
            .a = "hello",
            .b = "world",
            .c = &[_][]const u8{"nested"},
        };
        try serialize(@TypeOf(normal), allocator, normal, &out);

        try std.testing.expectEqualSlices(u8, out.items, out_generic.items);
    }
}
