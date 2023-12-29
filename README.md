# zig-scram
SCRAM implmementation for Zig (both client and server) (RFC 5802)

Based on [https://github.com/xdg-go/scram](https://github.com/xdg-go/scram) and [https://github.com/star-tek-mb/pgz/blob/master/src/auth.zig](https://github.com/star-tek-mb/pgz/blob/master/src/auth.zig)

## Missing features
- SASLPrep (Only ASCII allowed right now!)
- Channel binding
- Extensions support

## TODO before first release
- Rename allocator -> alloc
- Add examples for both full client and server
- State machine + step
- Refactor everything with allocators on the functions, not on the structs
- Make the nonce generator functions, not arguments when calling the functions
- Create the Error type
- Allocator less usage:

```zig
const Example = struct {
    st: State = .{},
    pub fn hash(bytes: []const u8, dest: []u8) void {
        var st: Keccak = .{};
        st.update(bytes);
        st.final(dest);
    }
    pub fn update(keccak: *Keccak, bytes: []const u8) void {
        keccak.st.absorb(bytes);
    }
    pub fn final(keccak: *Keccak, dest: []u8) void {
        keccak.st.pad();
        keccak.st.squeeze(dest[0..]);
    }
    fn write(keccak: *Keccak, bytes: []const u8) usize {
        keccak.update(bytes);
        return bytes.len;
    }
};
```
