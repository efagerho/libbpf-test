use std::mem::MaybeUninit;
use anyhow::Result;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::MapFlags;
use libbpf_rs::MapCore;
use libbpf_rs::MapType;
use libbpf_rs::MapHandle;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use libbpf_rs::libbpf_sys::bpf_map_create_opts;

mod test {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/test.skel.rs"
    ));
}

#[allow(clippy::wildcard_imports)]
use test::*;

fn main() -> Result<()> {
    let skel_builder = TestSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();

    let open_skel = skel_builder.open(&mut open_object)?;
    let skel = open_skel.load()?;

    let cpus = num_cpus::get() as u32;
    let per_cpu_flows = &skel.maps.per_cpu_flows;

    for i in 0..cpus+1 {
        let key = &i.to_ne_bytes();

        let mut opts: bpf_map_create_opts = unsafe { std::mem::zeroed() };
        opts.sz = size_of::<bpf_map_create_opts>() as u64;
        let value = MapHandle::create(MapType::LruHash, format!("cpu-{i}-flows").into(), 8, 16, 1024, &opts).expect("Error creating map");

        per_cpu_flows.update(key, &value.as_fd().as_raw_fd().to_ne_bytes(), MapFlags::ANY).expect("Unable to initialize map for CPU");
    }

    let link = skel.progs.test.attach_xdp(1).expect("Failed to attach XDP program");

    Ok(())
}
