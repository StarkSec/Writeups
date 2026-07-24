# Bash — Unquoted Test Expression Injection

## Vulnerability

The script performs a password check like:

```bash
test $PASS -eq ${1}
```

Neither `$PASS` nor `${1}` is quoted. Normally you'd expect `${1}` to simply be "the value the user typed" — but because it's unquoted, bash **word-splits it on whitespace before `test` ever sees it**. If `$1` is `123 -o True`, bash doesn't pass `test` one argument — it passes three: `123`, `-o`, `True`.

`test` (aka `[`) understands `-o` and `-a` as literal logical operators — OR and AND respectively — and treats any single non-empty string on its own as automatically true. So the payload turns:

```bash
test $PASS -eq 123 -o True
```

into, effectively:

```
( $PASS -eq 123 )  OR  ( True )
```

The right-hand side is unconditionally true, and since it's joined with OR, the whole expression evaluates true regardless of the actual password value. There's no need to guess the correct number — the payload supplies a guaranteed-true clause alongside a throwaway guess.

## Exploitation

```bash
./wrapper '123 -o True'
```

This doesn't work because `123` happens to be the password — it works because the payload injects a second, always-true clause via `-o`, and bash's word-splitting on the unquoted argument is what lets `test` see it as multiple distinct tokens rather than one literal string.

## Why this matters beyond this one script

Any time an unquoted variable is passed into `[` or `test`, it's worth probing with values containing spaces and test operators (`-o`, `-a`, `-z`, `-n`) — the same class of bug applies wherever user input reaches a test expression without quoting. `shellcheck` flags this automatically as **SC2086**, making it a fast, mechanical check to run against any bash script under audit rather than something that has to be spotted by eye.

## Remediation

- **Quote both sides**: `test "$PASS" -eq "${1}"` — this prevents word-splitting, so the argument is always passed to `test` as a single token regardless of its contents.
- **Prefer `[[ ... ]]` over `[ ... ]`/`test`** — bash's extended test syntax doesn't perform word-splitting on unquoted variables at all, removing this entire bug class rather than just patching one instance of it.
- **Run `shellcheck` on any script accepting external input** as a standard part of review — SC2086 (and related quoting warnings) catch this pattern automatically before it ships.

## Detection (blue team side)

- Static analysis: run `shellcheck` across the codebase and treat SC2086 findings involving `test`/`[` as high priority, since they're directly exploitable rather than just style issues.
- Code review: flag any script where external input (arguments, environment variables, user-supplied config) reaches a `test`/`[` expression without quoting, even if it isn't obviously security-sensitive at first glance — the impact depends entirely on what the conditional gates.

---

## Gaps worth adding to this note

1. **Other injectable `test` operators beyond `-o`/`-a`** — worth a line on `-z`/`-n` (empty/non-empty string tests) as alternative always-true/always-false levers, since not every target will have `-o`/`-a` reachable depending on argument count expected by the script.
2. **This is a narrower case of the general "unquoted variable expansion" bug class** — worth cross-referencing against unquoted-variable issues in other contexts (e.g. `rm $file` vs `rm "$file"`, or unquoted expansion in `for` loops), since the root cause (missing quotes → word splitting) is identical even though the exploitation mechanics differ per context.
3. **`set -u` / `set -o pipefail` as defense-in-depth** — doesn't fix this specific bug, but worth a mention as general bash hardening that catches adjacent classes of scripting mistakes (unset variables, silent pipeline failures) that tend to show up in the same poorly-written scripts.
