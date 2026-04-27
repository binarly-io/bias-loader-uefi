use glob::glob;

const UEFI_TOOL_C_SRC: &[&str] = &[
    "cxx/UEFITool/common/*.c",
    "cxx/UEFITool/common/bstrlib/*.c",
    "cxx/UEFITool/common/digest/*.c",
    "cxx/UEFITool/common/LZMA/*.c",
    "cxx/UEFITool/common/LZMA/SDK/C/*.c",
    "cxx/UEFITool/common/Tiano/*.c",
    "cxx/UEFITool/common/zlib/*.c",
];

const UEFI_TOOL_CXX_SRC: &[&str] = &[
    "cxx/UEFITool/common/*.cpp",
    "cxx/UEFITool/common/bstrlib/*.cpp",
    "cxx/UEFITool/common/generated/*.cpp",
    "cxx/UEFITool/common/kaitai/*.cpp",
    "cxx/UEFITool/ffsdumper.cpp",
    "cxx/UEFITool/uefidump.cpp",
];

const EFIXLOADER_SRC: &[&str] = &["cxx/uefitool.cpp"];

const INCLUDES: &[&str] = &[
    "cxx/UEFITool/common/",
    "cxx/UEFITool/common/generated/",
    "cxx/UEFITool/common/kaitai/",
    "cxx/UEFITool/common/LZMA/",
    "cxx/UEFITool/common/LZMA/SDK/C/",
    "cxx/UEFITool/common/Tiano/",
    "cxx/UEFITool/common/bstrlib/",
    "cxx/UEFITool/common/zlib/",
    "cxx/UEFITool/",
    "cxx/",
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let uefi_tool_csrc = UEFI_TOOL_C_SRC
        .iter()
        .flat_map(|path| glob(path).unwrap().into_iter())
        .collect::<Result<Vec<_>, _>>()?;

    let uefi_tool_cxxsrc = UEFI_TOOL_CXX_SRC
        .iter()
        .flat_map(|path| glob(path).unwrap())
        .filter(|res| {
            res.as_ref().map_or(true, |path| {
                !matches!(
                    path.file_name().and_then(|n| n.to_str()),
                    Some("fitparser.cpp" | "meparser.cpp")
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let efixloader_src = EFIXLOADER_SRC
        .iter()
        .flat_map(|path| glob(path).unwrap().into_iter())
        .collect::<Result<Vec<_>, _>>()?;

    for src in uefi_tool_csrc
        .iter()
        .chain(uefi_tool_cxxsrc.iter().chain(efixloader_src.iter()))
    {
        println!("cargo:rerun-if-changed={}", src.to_str().unwrap());
    }

    let target_def = if cfg!(target_os = "windows") {
        "WIN32"
    } else if cfg!(target_os = "macos") {
        "__APPLE__"
    } else {
        "__linux__"
    };

    cxx_build::bridge("src/lib.rs")
        .includes(INCLUDES)
        .files(efixloader_src)
        .flag_if_supported("-std=c++17")
        .flag_if_supported("-Wno-deprecated-declarations")
        .define(target_def, "1")
        .define("U_ENABLE_NVRAM_PARSING_SUPPORT", None)
        .opt_level(3)
        .warnings(false)
        .try_compile("uefitool")?;

    cc::Build::new()
        .cpp(true)
        .includes(INCLUDES)
        .files(uefi_tool_cxxsrc)
        .flag_if_supported("-std=c++17")
        .define(target_def, "1")
        .define("U_ENABLE_NVRAM_PARSING_SUPPORT", None)
        .opt_level(3)
        .warnings(false)
        .try_compile("uefitool_cxxbits")?;

    cc::Build::new()
        .includes(INCLUDES)
        .files(uefi_tool_csrc)
        .flag_if_supported("-Wno-deprecated-non-prototype")
        .warnings(false)
        .define(target_def, "1")
        .define("U_ENABLE_NVRAM_PARSING_SUPPORT", None)
        .opt_level(3)
        .try_compile("uefitool_cbits")?;

    Ok(())
}
