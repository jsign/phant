// Shim for __cpu_model and __cpu_indicator_init
// These are GCC runtime symbols used by keccak.c's BMI dispatch.
// Zig's compiler-rt doesn't provide them; this stub disables BMI auto-detection
// so the generic keccak implementation is always used.
struct {
    unsigned int __cpu_vendor;
    unsigned int __cpu_type;
    unsigned int __cpu_subtype;
    unsigned int __cpu_features[1];
} __cpu_model = {0};

void __cpu_indicator_init(void) {}
