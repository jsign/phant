const std = @import("std");
const serialize = @import("serialize.zig").serialize;
const expect = std.testing.expect;
const expectError = std.testing.expectError;
const eql = std.mem.eql;
const readInt = std.mem.readInt;
const ArrayList = std.ArrayList;
const hasFn = std.meta.hasFn;
const Allocator = std.mem.Allocator;

const rlpByteListShortHeader = 128;
const rlpByteListLongHeader = 183;
const rlpListShortHeader = 192;
const rlpListLongHeader = 247;

// When reading the payload, leading zeros are removed, so there might be a
// difference in byte-size between the number of bytes and the target integer.
// If so, the bytes have to be extracted into a temporary value.
inline fn safeReadSliceIntBig(comptime T: type, payload: []const u8, out: *T) !void {
    // compile time constat to activate the first branch. If
    // @sizeOf(T) > 1, then it is possible (and necessary) to
    // shift temp.
    const log2tgt1 = (@sizeOf(T) > 1);
    if (log2tgt1 and @sizeOf(T) > payload.len) {
        var temp: T = 0;
        var i: usize = 0;
        while (i < payload.len) : (i += 1) {
            temp = @shlExact(temp, 8); // payload.len < @sizeOf(T), should not overflow
            temp |= @as(T, payload[i]);
        }
        out.* = temp;
    } else {
        var bs = std.io.fixedBufferStream(payload[0..]);
        out.* = try bs.reader().readInt(T, .big);
    }
}

// Returns the size of the payload as well as the offset to the
// start of the actual data.
fn sizeAndDataOffset(payload: []const u8) !struct { size: usize, offset: usize } {
    var size: usize = undefined;
    var offset: usize = undefined;

    if (payload.len == 0) {
        return error.RlpPayloadTooShort;
    }

    if (payload[0] < rlpByteListShortHeader) {
        offset = 0;
        size = 1;
    } else if (payload[0] < rlpByteListLongHeader) {
        size = @as(usize, payload[0] - rlpByteListShortHeader);
        offset = 1;
    } else if (payload[0] < rlpListShortHeader) {
        const size_size = @as(usize, payload[0] - rlpByteListLongHeader);

        if (payload.len < 1 + size_size) {
            return error.RlpPayloadTooShort;
        }

        try safeReadSliceIntBig(usize, payload[1 .. 1 + size_size], &size);
        offset = 1 + size_size;
    } else if (payload[0] <= rlpListLongHeader) {
        size = @as(usize, payload[0] - rlpListShortHeader);
        offset = 1;
    } else {
        const size_size = @as(usize, payload[0] - rlpListLongHeader);

        if (payload.len < 1 + size_size) {
            return error.RlpPayloadTooShort;
        }

        try safeReadSliceIntBig(usize, payload[1 .. 1 + size_size], &size);
        offset = 1 + size_size;
    }

    return .{ .size = size, .offset = offset };
}

// Count the number of elements in a list
fn countRlpListItems(serialized: []const u8) !usize {
    var offset: usize = 0;
    var list_size: usize = 0;
    while (offset < serialized.len) : (list_size += 1) {
        const temp = try sizeAndDataOffset(serialized[offset..]);
        offset += temp.offset + temp.size;
    }
    return list_size;
}

// Returns the amount of data consumed from `serialized`.
pub fn deserialize(comptime T: type, allocator: Allocator, serialized: []const u8, out: *T) !usize {
    if (comptime hasFn(T, "decodeFromRLP")) {
        return out.decodeFromRLP(allocator, serialized);
    }

    const info = @typeInfo(T);
    return switch (info) {
        .int => {
            const r = try sizeAndDataOffset(serialized);
            try safeReadSliceIntBig(T, serialized[r.offset .. r.offset + r.size], out);
            return r.offset + r.size;
        },
        .@"struct" => |struc| {
            if (serialized.len == 0) {
                return error.EOF;
            }
            // A structure is encoded as a list, not
            // a bitstring.
            if (serialized[0] < rlpListShortHeader) {
                return error.NotAnRLPList;
            }

            const r = try sizeAndDataOffset(serialized);
            // limit of the struct's rlp encoding inside the larger buffer
            const limit = r.offset + r.size;
            if (limit > serialized.len) {
                return error.InvalidSerializedLength;
            }

            var offset = r.offset;
            inline for (struc.fields) |field| {
                if (offset > limit) {
                    return error.OffsetOverflow;
                }
                offset += try deserialize(field.type, allocator, serialized[offset..limit], &@field(out.*, field.name));
            }

            return limit;
        },
        .pointer => |ptr| switch (ptr.size) {
            .slice => if (ptr.child == u8) {
                const r = try sizeAndDataOffset(serialized);
                out.* = serialized[r.offset .. r.offset + r.size];
                return r.offset + r.size;
            } else {
                if (serialized[0] < rlpListShortHeader) {
                    return error.NotAnRLPList;
                }

                const r = try sizeAndDataOffset(serialized);
                const end = r.offset + r.size;

                const list_size = try countRlpListItems(serialized[r.offset..end]);

                // since it's not possible to say if the slice is "undefined", it has
                // to be allocated regardless.
                out.* = try allocator.alloc(ptr.child, list_size);

                var offset = r.offset;
                var i: usize = 0;
                while (offset < end) : (i += 1) {
                    offset += try deserialize(ptr.child, allocator, serialized[offset..], &out.*[i]);
                }

                return end;
            },
            .one => {
                out.* = try allocator.create(ptr.child);
                return deserialize(ptr.child, allocator, serialized, out.*);
            },
            // TODO missing: Many, C
            else => return error.UnSupportedType,
        },
        .array => |ary| if (@sizeOf(ary.child) == 1) {
            const r = try sizeAndDataOffset(serialized);
            // this is a fixed-size array, so the destination has already been allocated.
            std.mem.copyForwards(u8, out.*[0..], serialized[r.offset .. r.offset + r.size]);
            return r.offset + r.size;
        } else return error.UnsupportedType,
        .optional => |opt| {
            // There are two types of optional: those in the
            // middle of a structure, that MUST be represented
            // by an empty field (0x80) and those who are at
            // the end of a structure and are missing entirely
            // (typical case: block structures being extended
            // fork after fork). In this latter case, the size
            // of the payload will be shorter than the number
            // of fields, but returning an offset step of 0
            // will cause the container deserialization to
            // keep trying with the same offset, and that will
            // mark all optional values as empty.
            if (serialized.len == 0 or serialized[0] == rlpByteListShortHeader or serialized[0] == rlpListLongHeader) {
                out.* = null;
                // 0 if serialized was empty, one in the case of an empty list
                if (serialized.len == 0)
                    return 0;
                return 1;
            } else {
                var t: opt.child = undefined;
                const offset = try deserialize(opt.child, allocator, serialized[0..], &t);
                out.* = t;
                return offset;
            }
        },
        else => return error.UnsupportedType,
    };
}

test "deserialize an integer" {
    var consumed: usize = 0;

    const su8lo = [_]u8{42};
    var u8lo: u8 = undefined;
    consumed = try deserialize(u8, std.testing.allocator, su8lo[0..], &u8lo);
    try expect(u8lo == 42);
    try expect(consumed == 1);

    const su8hi = [_]u8{ 129, 192 };
    var u8hi: u8 = undefined;
    consumed = try deserialize(u8, std.testing.allocator, su8hi[0..], &u8hi);
    try expect(u8hi == 192);
    try expect(consumed == su8hi.len);

    const su16small = [_]u8{ 129, 192 };
    var u16small: u16 = undefined;
    consumed = try deserialize(u16, std.testing.allocator, su16small[0..], &u16small);
    try expect(u16small == 192);
    try expect(consumed == su16small.len);

    const su16long = [_]u8{ 130, 192, 192 };
    var u16long: u16 = undefined;
    consumed = try deserialize(u16, std.testing.allocator, su16long[0..], &u16long);
    try expect(u16long == 0xc0c0);
    try expect(consumed == su16long.len);
}

test "deserialize a structure" {
    const Person = struct {
        age: u8,
        name: []const u8,
    };
    const jc = Person{ .age = 123, .name = "Jeanne Calment" };
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(Person, std.testing.allocator, jc, &list);
    var p: Person = undefined;
    const consumed = try deserialize(Person, std.testing.allocator, list.items[0..], &p);
    try expect(consumed == list.items.len);
    try expect(p.age == jc.age);
    try expect(eql(u8, p.name, jc.name));
}
test "deserialize a string" {
    const str = "abc";
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize([]const u8, std.testing.allocator, str, &list);
    var s: []const u8 = undefined;
    const consumed = try deserialize([]const u8, std.testing.allocator, list.items[0..], &s);
    try expect(eql(u8, str, s));
    try expect(consumed == list.items.len);
}

test "deserialize a byte array" {
    const expected = [_]u8{ 1, 2, 3 };
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(@TypeOf(expected), std.testing.allocator, expected, &list);
    var out: [3]u8 = undefined;
    const consumed = try deserialize([3]u8, std.testing.allocator, list.items[0..], &out);
    try expect(eql(u8, expected[0..], out[0..]));
    try expect(consumed == list.items.len);
}

test "deserialize a byte arrayi with a single byte" {
    const expected = [_]u8{3};
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(@TypeOf(expected), std.testing.allocator, expected, &list);
    var out: [1]u8 = undefined;
    const consumed = try deserialize([1]u8, std.testing.allocator, list.items[0..], &out);
    try std.testing.expectEqual(expected, out);
    try expect(consumed == list.items.len);
}

const RLPDecodablePerson = struct {
    name: []const u8,
    age: u8,

    pub fn decodeFromRLP(self: *RLPDecodablePerson, allocator: Allocator, serialized: []const u8) !usize {
        _ = allocator;
        if (serialized.len == 0) {
            return error.EOF;
        }

        self.age = serialized[0];
        self.name = "freshly deserialized person";
        return 1;
    }
};

test "deserialize with custom serializer" {
    var person: RLPDecodablePerson = undefined;
    const serialized = [_]u8{42};
    const consumed = try deserialize(RLPDecodablePerson, std.testing.allocator, serialized[0..], &person);
    try expect(person.age == serialized[0]);
    try expect(consumed == 1);
}

test "deserialize an optional" {
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    var x: ?u32 = null;

    try serialize(?u32, std.testing.allocator, x, &list);
    var y: ?u32 = undefined;
    _ = try deserialize(?u32, std.testing.allocator, list.items, &y);
    try expect(y == null);

    list.clearAndFree();
    x = 32;
    var z: ?u32 = undefined;
    try serialize(?u32, std.testing.allocator, x, &list);
    _ = try deserialize(?u32, std.testing.allocator, list.items, &z);
    try expect(z.? == x.?);
}

test "deserialize a structure with missing optional fields at the end" {
    const structWithTrailingOptionalFields = struct {
        x: u64,
        y: ?u64,
        z: ?u64,
        alpha: ?[]const u8,
    };
    const serialized = [_]u8{ 0xc6, 0x84, 0xde, 0xad, 0xbe, 0xef, 5 };

    var mystruct: structWithTrailingOptionalFields = undefined;
    _ = try deserialize(structWithTrailingOptionalFields, std.testing.allocator, serialized[0..], &mystruct);
    try expect(mystruct.x == 0xdeadbeef);
    try expect(mystruct.y != null and mystruct.y.? == 5);
    try expect(mystruct.z == null);
    try expect(mystruct.alpha == null);
}

const Header = struct {
    parent_hash: [32]u8,
    uncle_hash: [32]u8,
    fee_recipient: [20]u8,
    state_root: [32]u8,
    transactions_root: [32]u8,
    receipts_root: [32]u8,
    logs_bloom: [256]u8,
    prev_randao: [32]u8,
    block_number: i64,
    gas_limit: i64,
    gas_used: u64,
    timestamp: i64,
    extra_data: []const u8,
    mix_hash: u256,
    nonce: [8]u8,
    base_fee_per_gas: ?u256,
    withdrawals_root: ?[32]u8,
    blob_gas_used: ?u64,
    excess_blob_gas: ?u64,
};

const Block = struct {
    header: Header,
};

test "deserialize a shanghai block" {
    var b: Block = undefined;

    const rlp_bytes = @embedFile("testdata/shanghai_block_1.rlp");
    _ = try deserialize(Block, std.testing.allocator, rlp_bytes[0..], &b);
}

test "detects an invalid length serialization" {
    var b: Block = undefined;

    // removed part of the *header* payload but other fields are
    // still present.
    const rlp_bytes = @embedFile("testdata/faulty_shanghai_block.rlp");
    _ = try expectError(error.InvalidSerializedLength, deserialize(Block, std.testing.allocator, rlp_bytes[0..], &b));
}

test "access list empty" {
    const StrippedTxn = struct {
        access_list: []struct {
            address: [20]u8,
            storage_keys: [][32]u8,
        },
    };

    var buf: [128]u8 = undefined;
    const rlp = try std.fmt.hexToBytes(&buf, "c1c0");

    var out: StrippedTxn = undefined;
    _ = try deserialize(StrippedTxn, std.testing.allocator, rlp, &out);
}

test "deserialize a byte slice" {
    var buf: [128]u8 = undefined;
    const rlp = try std.fmt.hexToBytes(&buf, "940000000000000000000000000000000000001210");
    var out = [_]u8{0} ** 20;
    var out_: []u8 = out[0..];

    _ = try deserialize([]const u8, std.testing.allocator, rlp, &out_);
}

test "deserialize a pointer to an integer" {
    const rlp = [_]u8{ 138, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    var out: *u256 = undefined;
    _ = try deserialize(*u256, std.testing.allocator, &rlp, &out);
    defer std.testing.allocator.destroy(out);
    _ = try std.testing.expectEqual(out.*, 0x0102030405060708090a);
}
