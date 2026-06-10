//! tests/snapshot_ring.rs
//!
//! Role: round-trip the live POSIX shared-memory snapshot ring — a test
//! producer writes the Horkos-owned ring contract (`HkSnapshotRingHeader` +
//! seqlock slots) into a real `shm_open` object, and the production
//! `PosixRingAttach` consumer reads frames back through the same `parse_slot`
//! trust boundary the live reader uses. Also exercises the torn-frame skip
//! (a slot left mid-write, odd sequence) so a partial publish is never parsed.
//!
//! Target platforms: linux/macos host (POSIX shm). Gated off on Windows.
//!
//! This is the merge-gate bypass coverage (guardrail #12) for the live ring:
//! the attack is a producer that publishes a torn frame; the consumer must
//! skip it, never hand torn bytes to `parse_slot`.

#![cfg(unix)]

use std::ffi::CString;
use std::os::raw::c_void;

use telemetry::snapshot::ipc::{
    SnapshotRingAttach, RECORD_HEAD_BYTES, RING_HEADER_BYTES, SLOT_HEADER_BYTES,
    SNAPSHOT_SCHEMA_VERSION, SNAP_RING_MAGIC,
};

const SLOT_COUNT: u32 = 4;
const SLOT_STRIDE: u32 = (SLOT_HEADER_BYTES + RECORD_HEAD_BYTES + 64) as u32;

/// A minimal RAII producer over a freshly-created shm object.
struct Producer {
    name: CString,
    base: *mut u8,
    len: usize,
    write_seq: u64,
}

impl Producer {
    fn create(name: &str) -> Self {
        let cname = CString::new(name).unwrap();
        unsafe {
            // Fresh object each run.
            libc::shm_unlink(cname.as_ptr());
            let fd = libc::shm_open(cname.as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o600);
            assert!(fd >= 0, "shm_open create failed");
            let len = RING_HEADER_BYTES + SLOT_COUNT as usize * SLOT_STRIDE as usize;
            assert_eq!(libc::ftruncate(fd, len as libc::off_t), 0);
            let base = libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            );
            assert_ne!(base, libc::MAP_FAILED, "mmap producer failed");
            libc::close(fd);

            // Write the ring header.
            let hdr = base as *mut u32;
            hdr.add(0).write_volatile(SNAP_RING_MAGIC); // magic
            hdr.add(1).write_volatile(SNAPSHOT_SCHEMA_VERSION); // schema_version
            hdr.add(2).write_volatile(SLOT_COUNT); // slot_count
            hdr.add(3).write_volatile(SLOT_STRIDE); // slot_stride
            (base.add(16) as *mut u64).write_volatile(0); // write_seq
            (base.add(24) as *mut u64).write_volatile(0); // _reserved

            Producer {
                name: cname,
                base: base as *mut u8,
                len,
                write_seq: 0,
            }
        }
    }

    fn slot_ptr(&self, gen: u64) -> *mut u8 {
        let slot = ((gen - 1) % SLOT_COUNT as u64) as usize;
        unsafe {
            self.base
                .add(RING_HEADER_BYTES + slot * SLOT_STRIDE as usize)
        }
    }

    /// Publish a full frame for `tick` (a valid minimal HkSnapshotRecord head).
    fn publish(&mut self, tick: u64, local_player_id: u64) {
        let gen = self.write_seq + 1;
        let slot = self.slot_ptr(gen);
        unsafe {
            // seq = odd (writing)
            (slot as *mut u64).write_volatile(gen * 2 - 1);
            std::sync::atomic::fence(std::sync::atomic::Ordering::Release);

            // payload_len
            (slot.add(8) as *mut u32).write_volatile(RECORD_HEAD_BYTES as u32);
            (slot.add(12) as *mut u32).write_volatile(0); // _pad

            // payload: HkSnapshotRecord head (zeroed) with the fields the
            // consumer needs.
            let payload = slot.add(SLOT_HEADER_BYTES);
            std::ptr::write_bytes(payload, 0, RECORD_HEAD_BYTES);
            (payload.add(0) as *mut u32).write_volatile(SNAPSHOT_SCHEMA_VERSION); // schema_version
            (payload.add(4) as *mut u32).write_volatile(0); // entity_count
            (payload.add(8) as *mut u64).write_volatile(tick); // tick
            (payload.add(24) as *mut u64).write_volatile(local_player_id); // local_player_id
            (payload.add(136) as *mut u32).write_volatile(0); // occluder_count

            std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
            // seq = even (stable, generation `gen`)
            (slot as *mut u64).write_volatile(gen * 2);
            std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
            // publish
            (self.base.add(16) as *mut u64).write_volatile(gen);
        }
        self.write_seq = gen;
    }

    /// Leave a slot mid-write: odd sequence, bumped write_seq — the consumer
    /// must treat this as torn and skip it.
    fn publish_torn(&mut self, tick: u64) {
        let gen = self.write_seq + 1;
        let slot = self.slot_ptr(gen);
        unsafe {
            (slot as *mut u64).write_volatile(gen * 2 - 1); // odd: still writing
            (slot.add(8) as *mut u32).write_volatile(RECORD_HEAD_BYTES as u32);
            let payload = slot.add(SLOT_HEADER_BYTES);
            std::ptr::write_bytes(payload, 0, RECORD_HEAD_BYTES);
            (payload.add(0) as *mut u32).write_volatile(SNAPSHOT_SCHEMA_VERSION);
            (payload.add(8) as *mut u64).write_volatile(tick);
            std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
            (self.base.add(16) as *mut u64).write_volatile(gen); // published while odd
        }
        self.write_seq = gen;
    }
}

impl Drop for Producer {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.base as *mut c_void, self.len);
            libc::shm_unlink(self.name.as_ptr());
        }
    }
}

fn ring_name() -> String {
    // shm names are global and length-capped (macOS SHM_NAME_MAX ~31 incl the
    // leading slash); keep it short and process-unique.
    format!("/hk_sr_{}", std::process::id())
}

#[test]
fn consumer_reads_published_frames() {
    let name = ring_name();
    let mut producer = Producer::create(&name);
    // Publish BEFORE the consumer attaches; attach starts at current write_seq,
    // so publish after attach to be observed.
    let mut ring = telemetry::snapshot::backends::posix::PosixRingAttach::attach(&name)
        .expect("attach to the live ring");

    producer.publish(100, 7);
    producer.publish(101, 7);

    let mut buf = Vec::new();
    let mut ticks = Vec::new();
    // Drain up to a few polls.
    for _ in 0..16 {
        match ring.next_frame(&mut buf) {
            Ok(true) => {
                let snap = telemetry::snapshot::ipc::parse_slot(&buf).expect("frame parses");
                ticks.push(snap.tick);
            }
            Ok(false) => break,
            Err(e) => panic!("reader error: {e}"),
        }
    }
    assert_eq!(ticks, vec![100, 101], "both published frames read in order");
}

#[test]
fn torn_frame_is_skipped_never_parsed() {
    let name = format!("{}_torn", ring_name());
    let mut producer = Producer::create(&name);
    let mut ring =
        telemetry::snapshot::backends::posix::PosixRingAttach::attach(&name).expect("attach");

    // A torn publish (odd seq, write_seq bumped) must NOT yield a frame.
    producer.publish_torn(200);
    let mut buf = Vec::new();
    assert!(
        matches!(ring.next_frame(&mut buf), Ok(false)),
        "torn frame yields no readable frame"
    );

    // A subsequent clean publish IS read (the consumer recovered).
    producer.publish(201, 9);
    let mut got = None;
    for _ in 0..16 {
        match ring.next_frame(&mut buf) {
            Ok(true) => {
                got = Some(
                    telemetry::snapshot::ipc::parse_slot(&buf)
                        .expect("parses")
                        .tick,
                );
                break;
            }
            Ok(false) => continue,
            Err(e) => panic!("reader error: {e}"),
        }
    }
    assert_eq!(got, Some(201), "clean frame after a torn one is recovered");
}

#[tokio::test]
async fn reader_thread_forwards_to_channel() {
    let name = format!("{}_thread", ring_name());
    let mut producer = Producer::create(&name);
    let ring =
        telemetry::snapshot::backends::posix::PosixRingAttach::attach(&name).expect("attach");

    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_reader = std::sync::Arc::clone(&stop);
    let handle = std::thread::spawn(move || {
        telemetry::snapshot::ipc::run_reader(
            ring,
            |snap| tx.blocking_send(snap).is_ok(),
            stop_reader,
            std::time::Duration::from_millis(2),
        );
    });

    producer.publish(300, 5);
    producer.publish(301, 5);

    let first = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
        .await
        .expect("frame within timeout")
        .expect("snapshot");
    assert_eq!(first.tick, 300);
    let second = rx.recv().await.expect("second snapshot");
    assert_eq!(second.tick, 301);

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    handle.join().ok();
}
