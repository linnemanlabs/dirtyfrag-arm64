# dirtyfrag-arm64

arm64/aarch64 port of [V4bel/dirtyfrag](https://github.com/V4bel/dirtyfrag) (CVE-2026-43284, CVE-2026-43500).

Tested on Ubuntu 24.04.4 LTS with `linux-aws 6.17.0-1013-aws` on AWS Graviton (newest available as of this writing).

> **Full writeup with Tetragon detection policies, AppArmor hardening analysis, YARA rules, and a mitigation comparison matrix:** [https://linnemanlabs.com/dirtyfrag-arm64](https://linnemanlabs.com/dirtyfrag-arm64) *(coming soon)*

## What's different on arm64

The upstream x86\_64 PoC uses two exploit paths: an ESP/xfrm path that corrupts `/usr/bin/su`, and an rxrpc/rxkad fallback that corrupts `/etc/passwd`. On arm64 the rxrpc path kernel-oopses and cannot be used. The ESP path works cleanly.

### rxrpc crash: `flush_dcache_page`

On x86\_64, `flush_dcache_page()` is a no-op. x86 has hardware-coherent data/instruction caches. On arm64, it performs real dcache maintenance and dereferences the `struct page*` metadata. When the rxrpc crypto path (`rxkad_secure_packet` -> `crypto_pcbc_encrypt` -> `skcipher_walk_done`) calls `flush_dcache_page` on a page whose reference has been manipulated through the splice/vmsplice chain, x86\_64 silently skips it but arm64 hits a translation fault and oopses:

```
pc : flush_dcache_page+0x18/0x58
lr : skcipher_walk_done+0xbc/0x260
     crypto_pcbc_encrypt+0xe8/0x1c8 [pcbc]
     crypto_skcipher_encrypt+0x48/0xb8
     rxkad_secure_packet+0x108/0x270 [rxrpc]
     rxrpc_send_data+0x264/0x550 [rxrpc]
```

On arm64 systems where unprivileged user namespace creation is blocked, neither exploit path should work. The ESP path can't create the required network namespace, and the rxrpc fallback panics the kernel. On x86\_64 the rxrpc path provides a namespace-free alternative.

### ESP-only operation

On arm64, only the ESP path is viable. This path requires unprivileged user namespace creation (`unshare -U -n`), which is enabled by default on most Linux distributions and cloud images. Distributions have ways to restrict it like Ubuntu via AppArmor profiles, Debian via `kernel.unprivileged_userns_clone`, RHEL via `user.max_user_namespaces` can block the ESP path if configured properly.

On x86_64, the rxrpc path provides a fallback that works without namespaces. On arm64, no such fallback exists: blocking unprivileged user namespaces makes the system unexploitable by either path.

### Architecture-specific payload

The exploit overwrites `/usr/bin/su` in the page cache with a minimal static ELF. The upstream PoC embeds an x86\_64 ELF with x86\_64 shellcode. This port replaces it with an equivalent aarch64 ELF:

- ELF `e_machine`: `EM_AARCH64` (183) instead of `EM_X86_64` (62)
- Shellcode: aarch64 instructions using `svc #0` instead of `syscall`
- Syscall numbers: setgid=144, setuid=146, setgroups=159, execve=221 (vs 106, 105, 116, 59 on x86\_64)
- Fixed 4-byte instruction width (vs x86\_64 variable-length), resulting in a slightly larger payload (~216 bytes vs 192)

## Build & run

```bash
# Clone
git clone https://github.com/linnemanlabs/dirtyfrag-arm64.git

# Build
cd dirtyfrag-arm64
gcc -O0 -Wall -o dirtyfrag_arm64 dirtyfrag_arm64.c -lutil

# Run
./dirtyfrag_arm64 --force-esp
```

The `--force-esp` flag skips the rxrpc path entirely to ensure avoiding the arm64 kernel oops.

## Tested environment

| Property | Value |
|---|---|
| Instance | AWS t4g.micro (Graviton2) |
| OS | Ubuntu 24.04.4 LTS |
| Kernel | `6.17.0-1013-aws #13~24.04.1-Ubuntu` (built 2026-04-24) |
| Architecture | aarch64 |
| `unprivileged_userns_clone` | 1 (enabled) |
| esp4 module | available, loadable |
| rxrpc module | available, loadable (but crashes on arm64) |
| Configuration | stock ubuntu 24.04 cloud image, default kernel modules |

As of 2026-05-09, the latest available Ubuntu 24.04 aws kernel (`6.17.0-1013-aws`, built April 24) ships without patches for either Copy Fail (CVE-2026-31431, disclosed April 29) or Dirty Frag (CVE-2026-43284/43500, disclosed May 7).

## Immediate mitigation

Blacklist the vulnerable modules, apply appropriate system hardening for your distro.

### Blacklist the modules
Safe on any system not actively using IPsec transport mode or AFS. To prevent loading of the modules put the following into `/etc/modprobe.d/dirtyfrag.conf`:

```
install esp4 /bin/false
install esp6 /bin/false
install rxrpc /bin/false
```

### Unload the modules

To unload the modules from the running system:

```bash
rmmod esp4 esp6 rxrpc 2>/dev/null
````

### Flush page cache

Flushing the page cache should remove the malicious contents and cause the files to be read from disk again.

```bash
echo 3 > /proc/sys/vm/drop_caches
```
Note: I have had some inconsistent results with this, but the more I try to reproduce it the more it's working as expected. For this PoC, you can check the md5sum on /usr/bin/su, and if it doesn't match, reboot.

### Verify after mitigation

```bash
sha256sum /usr/bin/su

# Or from package manager:

dpkg -V util-linux    # Debian/Ubuntu
rpm -V util-linux     # RHEL/Amazon Linux
```

### Proactive moves

For a more proactive posture that addresses this entire vulnerability class (not just the specific CVEs), see the full writeup for AppArmor userns restrictions, module preloading prevention, and Tetragon-based runtime detection as well as YARA rules.

## Credits

- [Hyunwoo Kim (@v4bel)](https://github.com/V4bel) - original vulnerability research, disclosure, and x86\_64 PoC. aka all of the real work
- [Keith Linneman / LinnemanLabs](https://linnemanlabs.com) - arm64 port, `flush_dcache_page` crash analysis, and detection rules

## Legal

This tool is intended for authorized security testing and research only.

Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical.

## License

MIT. Copy it, steal it, modify it, learn from it, share your improvements with me. Or don't. It's code, do what you want with it.
