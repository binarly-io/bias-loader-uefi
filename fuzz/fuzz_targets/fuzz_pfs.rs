#![no_main]
use libfuzzer_sys::fuzz_target;
use bias_loader_uefi::parsers::pfs::DellPfs;

const MAX_INPUT_SIZE: usize = 1024;
const MIN_INPUT_SIZE: usize = 12;

fn do_fuzz(data: &[u8]) {
    if data.len() < MIN_INPUT_SIZE || data.len() > MAX_INPUT_SIZE {
        return;
    }
    let _res = DellPfs::parse(data);
}

fuzz_target!(|data: &[u8]| {
    do_fuzz(data);
});
