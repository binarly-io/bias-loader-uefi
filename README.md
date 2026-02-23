# bias-loader-uefi

Rust bindings for [UEFITool](https://github.com/binarly-io/bias-uefitool) with additional parsers for [AMI PFAT](https://github.com/platomav/BIOSUtilities/blob/70c3a0852a6aa2643c8114ea73bc833e3b4cff0d/biosutilities/ami_pfat_extract.py) and [Dell PFS](https://github.com/platomav/BIOSUtilities/blob/70c3a0852a6aa2643c8114ea73bc833e3b4cff0d/biosutilities/dell_pfs_extract.py) formats.

Parse UEFI firmware images to extract modules, NVRAM variables, microcode updates, buf sections, and Secure Boot signature databases.

## Building

The UEFITool sources are compiled automatically via `build.rs`.

```sh
git clone git@github.com:binarly-io/bias-loader-uefi.git
git submodule update --init
cargo build --release
```

## Usage

### Parse a UEFI firmware image

```rust
use bias_loader_uefi::Uefi;

let bytes = std::fs::read("firmware.bin")?;
let fw = Uefi::new(&bytes)?;

// iterate over all modules
fw.for_each(|module| {
    println!("{} [{}] {:?}", module.name(), module.guid(), module.module_type());
});

// count extracted components
println!("modules: {}", fw.count_modules());
println!("nvram vars: {}", fw.count_vars());
println!("microcode: {}", fw.count_microcode());
```

### NVRAM variables

```rust
fw.for_each_var(|var| {
    println!("{} type={:?} valid={}", var.name(), var.var_type(), var.is_valid());
});
```

### Microcode updates

```rust
fw.for_each_microcode(|mc| {
    println!("{:?} date={} cpuid={:#x} rev={}", mc.vendor(), mc.date(), mc.cpu_signature(), mc.update_revision());
});
```

### Early termination

```rust
use bias_loader_uefi::ContinueOrStop;

fw.for_each_until(|module| {
    if module.guid() == "A2DF5376-C2ED-49C0-90FF-8B173B0FD066" {
        // found it, stop iterating
        return ContinueOrStop::Stop;
    }
    ContinueOrStop::Continue
});
```

### Dependency expressions (DepEx)

```rust
use bias_loader_uefi::depex::DepExOpcode;
use uuid::Uuid;

fw.for_each(|module| {
    if !module.depex().is_empty() {
        println!("{}:", module.name());
        for op in module.depex() {
            match op {
                DepExOpcode::Push(guid) => println!("  Push({})", Uuid::from_bytes_le(*guid)),
                DepExOpcode::Before(guid) => println!("  Before({})", Uuid::from_bytes_le(*guid)),
                DepExOpcode::After(guid) => println!("  After({})", Uuid::from_bytes_le(*guid)),
                other => println!("  {other:?}"),
            }
        }
    }
});
```

### Unpack AMI PFAT / Dell PFS firmware

Auto-detect and unpack proprietary firmware containers before parsing:

```rust
use bias_loader_uefi::{try_unpack, Uefi};

let buf = std::fs::read("image.cap")?;
let unpacked = try_unpack(&buf)?;
let fw = Uefi::new(&unpacked)?;
```

For firmware images containing multiple UEFI images (common with Dell PFS):

```rust
use bias_loader_uefi::UefiMulti;

let buf = std::fs::read("image.cap")?;
let multi = UefiMulti::new(&buf)?;

for (uefi, image) in multi.iter_full() {
    println!("image: {} ({} modules)", image.name(), uefi.count_modules());
}
```

### Format detection

```rust
use bias_loader_uefi::parsers::Hint;

match Hint::parse(&bytes) {
    Hint::Pfat => println!("AMI PFAT"),
    Hint::Pfs  => println!("Dell PFS"),
    Hint::Unknown => println!("Unknown"),
}
```

### Secure Boot signature extraction

```rust
use bias_loader_uefi::secureboot::extract_sb_signatures_from_nvram;

fw.for_each_var(|var| {
    let sigs = extract_sb_signatures_from_nvram(var.name(), var.data());
    for sig in sigs {
        println!("{:?} owner={} type={}", sig.database_type, sig.signature_owner, sig.signature_type);
    }
});
```

## Acknowledgements

Special thanks to:

- [@NikolajSchlej](https://github.com/NikolajSchlej) and all UEFITool contributors for [UEFITool](https://github.com/LongSoft/UEFITool)
- [@platomav](https://github.com/platomav) for [BIOSUtilities](https://github.com/platomav/BIOSUtilities)
