# Weak Sudo Configuration — Wildcard Argument Path Traversal

## Vulnerability

A basic sudo misconfiguration pattern: a user is granted sudo rights to run a specific binary, but the **allowed argument includes a wildcard covering a path segment** rather than just a filename. Sudo's privilege boundary is "this command, as this user" — it has no concept of "only within this directory," so if the wildcard expands across a path (not just a filename glob), an attacker can traverse out of the intended directory to read/write arbitrary files as the target user.

### Discovery

```
app-script-ch1@challenge02:~$ sudo -l
Matching Defaults entries for app-script-ch1 on challenge02:
    env_reset, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, !mail_always, !mail_badpass, !mail_no_host, !mail_no_perms, !mail_no_user

User app-script-ch1 may run the following commands on challenge02:
    (app-script-ch1-cracked) /bin/cat /challenge/app-script/ch1/notes/*
```

`sudo -l` is the enumeration step here — it shows the user can run `/bin/cat` as `app-script-ch1-cracked`, with the argument `/challenge/app-script/ch1/notes/*`. Note this is unrelated to the `secure_path`/`env_reset` settings shown above — those harden against `$PATH` hijacking, but do nothing to stop wildcard traversal, since the vulnerable element is the *argument*, not the binary resolution.

## Exploitation

The wildcard `*` covers an entire path segment, not just filenames within the directory — so `..` is valid input to it:

```bash
sudo -u app-script-ch1-cracked /bin/cat /challenge/app-script/ch1/notes/../ch1cracked/.passwd
```

This resolves to `/challenge/app-script/ch1/ch1cracked/.passwd` — a file outside the `notes/` directory the sudoers entry was presumably intended to restrict access to. Since the privilege boundary sudo enforces is "run `/bin/cat` as `app-script-ch1-cracked`," not "only on files inside `notes/`," the traversal is permitted.

## Remediation

- **Avoid wildcards in sudoers command arguments entirely** — specify exact filenames wherever possible.
- **If a wildcard is unavoidable**, restrict it to a filename-only glob (e.g. `/bin/cat /path/notes/*.txt`) rather than a path segment — and still treat the containing directory as untrusted, since a filename glob can still be abused if the directory itself is writable or contains symlinks.
- **Principle of least privilege**: grant "run X on this exact file as user Y," not "run X as user Y" with an open-ended argument. If the use case is "read whatever is dropped in this directory," that's a design smell worth reconsidering rather than solving with a wildcard.
- **Audit existing sudoers entries** for wildcards with `sudo -l` (as a normal user) or `visudo -c` (as an admin) — this pattern is common enough in real environments to be worth a periodic sweep.

## Detection (blue team side)

- Periodically run `sudo -l` for all users (or review `/etc/sudoers` / `/etc/sudoers.d/*` directly) and flag any entry where the allowed argument contains `*`, `?`, or other glob characters spanning a path component rather than a trailing filename pattern.
- Log and alert on sudo invocations where the resolved/executed argument contains `../` — this is a strong indicator of traversal, regardless of which binary was used.

---

## Gaps worth adding to this note

1. **This is a *path traversal* wildcard, not an *argument injection* wildcard** — worth explicitly distinguishing from cases like `sudo tar -czf /backup/*.tar *` where the wildcard is expanded by the shell into multiple arguments and can be abused to smuggle in flags (e.g. `--checkpoint=1 --checkpoint-action=exec=...`). Same root cause category (unsafe wildcard in sudoers), different mechanism — GTFOBins is the standard reference for which binaries are abusable this way, and a "see also" link to that entry would round this note out.
2. **Why `env_reset`/`secure_path` don't help here** — you list them in the `sudo -l` output but don't explicitly note they're irrelevant to this specific vuln; a reader unfamiliar with the distinction might assume a "secure"-looking sudoers config means the entry is safe.
3. **The `(app-script-ch1-cracked)` runas-user detail** — worth a line noting sudo entries can specify a target user other than root, and that "escalation" here means moving laterally to a *different* unprivileged/service account, not necessarily straight to root — useful for readers expecting every sudo abuse to end in a root shell.
4. **Symlink variant** — even without `../` traversal, if the target directory is writable, an attacker can drop a symlink matching the glob pointing anywhere on the filesystem — worth a one-line mention as a sibling technique to keep the note complete.
