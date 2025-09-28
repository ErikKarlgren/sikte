use aya_ebpf::maps::RingBuf;

/// Write and submit an entry with some data to the given ringbuf. If this fails, call `callback`
pub fn submit_or_else<Data, Fn>(ringbuf: &RingBuf, data: Data, callback: Fn) -> Result<u32, u32>
where
    Data: 'static,
    Fn: FnOnce(),
{
    let entry = ringbuf.reserve::<Data>(0);

    if let Some(mut entry) = entry {
        entry.write(data);
        entry.submit(0);
        Ok(0)
    } else {
        callback();
        Err(1)
    }
}
