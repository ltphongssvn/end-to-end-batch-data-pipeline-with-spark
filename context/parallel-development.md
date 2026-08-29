<!-- context/parallel-development.md -->
# Parallel development across six laptops

This repo is developed by **six laptops running concurrently**, each hosting an
autonomous agent loop. Nobody is watching when two of them do the same thing at
the same moment.

That single fact drives everything below. In a normal repo these would be
hygiene rules; here they are the only thing standing between six unattended
processes and corrupted shared state. Three properties matter more than
convenience:

- **Allocation is atomic against the remote.** Agents claim identifiers
  simultaneously. A scheme that merely *usually* avoids collisions will collide.
- **Every environment is reconstructible, never copied.** There is no human to
  hand a file between machines.
- **Every gate fails closed.** An agent will not notice a warning. It will
  notice a non-zero exit.

---

## 1. Terminal numbers come from the remote, never from the census

Each agent session claims a **terminal number** from `refs/terminals/*` on the
remote. It does **not** come from `git worktree list`.

`git worktree list` is a *census*: it reads one machine's local worktrees. With
six laptops that is guaranteed to mislead, in two distinct ways:

**It is partial.** Each laptop sees only the worktrees it hosts — roughly a
sixth of the sequence. A MacBook once reported `t77` while another machine was
at `t88`; another day the MacBook read `t94` while a second census said `t97`.
Neither was wrong about what it could see. Neither was authoritative.

**It forgets.** Closing a worktree drops the high-water mark, so the next census
re-issues a number that was already burned. Terminal refs are never deleted, so
the registry's ceiling only ever rises.

One `t90` read was wrong twice over: the census said `t89` because t90 and t91's
worktrees were on other machines, and t90 was already claimed on the remote.

**The registry supersedes the census entirely.**

### Claiming, and why the retry loop is mandatory

```bash
git fetch origin --prune
git ls-remote origin 'refs/terminals/*'      # the ceiling
```

Then claim the next number above it:

```bash
git update-ref refs/terminals/t<N> HEAD
git push origin refs/terminals/t<N> --force-with-lease=refs/terminals/t<N>:
```

`--force-with-lease=refs/terminals/t<N>:` means *push only if this ref does not
yet exist on the remote*. When two laptops race for the same number, the loser
sees:

```
 ! [rejected]  refs/terminals/t<N> -> refs/terminals/t<N> (stale info)
```

**A rejection is not an error to report — it is the protocol working.** An agent
that treats it as fatal stalls; an agent that ignores it corrupts the registry.
The correct behavior is to re-fetch, take the next number above the new
ceiling, and retry. Then read the registry back from the remote; never infer
success from the absence of an error.

```bash
git ls-remote origin 'refs/terminals/*'      # confirm the claim landed
```

## 2. Naming

```
t<terminal>-wt<n>-<slug>
```

`t1-wt1-durable-safe-extraction`. Terminal from the registry, `wt<n>` counting
worktrees within that terminal, slug describing the work.

Because terminal numbers are globally unique, branch names from six laptops
cannot collide even when two agents pick the same slug.

Git refuses to check out one branch in two worktrees. That refusal guards
against two agents writing the same ref; `--force` defeats it and must not be
used.

---

## 3. Preflight, in this order

Every new worktree runs all six steps. **A tooling-only change still gets the
full preflight** — the steps that feel skippable are the ones that fail.

### 3.1 Registry ceiling

Section 1, including the retry loop. Before cutting anything.

### 3.2 Cut off `origin/develop`, never local `develop`

```bash
git fetch origin --prune
git worktree add ../t<N>-wt1-<slug> -b t<N>-wt1-<slug> origin/develop
```

Local `develop` on any given laptop may be hours behind what the other five have
merged. `origin/develop` is the only shared truth.

**Never commit on `develop` or `main`.** The server ruleset rejects the push,
but a local commit still has to be unwound. Recovery, losing nothing:

```bash
git switch -c t<N>-wt<n>-<slug>     # carries the commit onto a proper branch
git switch develop
git reset --hard origin/develop
```

### 3.3 `.env` is reconstructed, never copied between machines

```bash
find ~/code -maxdepth 3 -name '.env' -not -path '*/node_modules/*'
```

Discovery, then judgment. Hits belonging to *other projects* are not
candidates — copying one imports unrelated secrets into a public repo. With six
machines, passing a `.env` around is also how one laptop ends up running
credentials nobody can account for. Rebuild from the committed template:

```bash
install -m 600 .env.example .env
```

`0600` because a secret readable by every account on the box is not a secret.
Each laptop holds its own copy, none is authoritative, any can be regenerated.

### 3.4 Verify ignore rules with `git status`, not `git check-ignore`

```bash
git status --porcelain --ignored=matching -- .env .env.example
```

A double-bang prefix means ignored; `??` means visible to git. Expect ignored
for `.env`, visible for `.env.example`.

**Do not gate on `git check-ignore`'s exit status.** With `-v` it prints the
matching pattern even when that pattern is a *negation*, and its exit status
only reports that *some* path matched. It therefore returns success for
`.env.example` — which reads as "ignored" and is the exact opposite of the
truth. This produced a false alarm here. `git status --porcelain --ignored`
states it unambiguously.

### 3.5 Locked install, twice

```bash
uv sync --locked
uv sync --locked
git status --porcelain -- uv.lock mise.lock   # must print nothing
```

`--locked` installs strictly from `uv.lock` and fails if it is stale. The second
run must be a no-op: that proves the lockfile is authoritative rather than being
quietly rewritten. The `git status` check proves neither lockfile moved — which
is how six machines stay on identical dependency graphs.

### 3.6 Build gate

```bash
mise run check
```

Lint, format, types, tests, config governance, contract drift, and a
full-history secret scan. CI runs this exact task and nothing else, so a green
gate locally means a green pipeline.

---

## 4. Why the toolchain is pinned

`mise.toml` pins Temurin JDK 17, uv, lefthook and betterleaks; `mise.lock`
records checksums and provenance; `uv.lock` pins every Python package;
`.python-version` pins CPython 3.12.3. `task_config.shell` pins bash, because
`sh` is bash-in-POSIX-mode on macOS and dash on Linux — a difference that let
`set -o pipefail` pass locally and fail in CI.

The point is not tidiness. Six laptops plus CI is seven environments, and any
unpinned component becomes a difference that surfaces as a mysterious failure on
one machine only. `mise run setup` reproduces all of it from committed files.

## 5. Daily loop

```bash
mise run check      # optional; the hooks run it anyway
mise run pr         # push, open a PR into develop, arm auto-merge
mise run pr-wait    # optional; block until it lands
mise run sync       # return to develop and prune merged branches
```

GitFlow with server-side enforcement: `develop` and `main` reject direct pushes
and force-pushes, only merge commits are allowed, and GitHub performs the merge
once the gate passes.

Auto-merge matters specifically for unattended agents: the merge fires
server-side when the required check reports, so it lands even when the
laptop that opened the PR is asleep. A polling script cannot promise that.

Six agents opening PRs against one `develop` will produce conflicts. That is
expected, and is why work is split by worktree. An agent that hits a conflict
rebases onto `origin/develop` and re-runs the gate rather than forcing.

## 6. Shell quoting discipline

**A `!` followed by a word character triggers history expansion** and aborts the
line before anything runs. `!tests`, `!r`, and a bare double-bang inside a
double-quoted string have each broken a command here. A heredoc with a *quoted*
delimiter (`<< 'EOF'`) suppresses all expansion, so file content is safe; only
the interactive command line is at risk. `set +H` on the same line does not
help — the whole line is parsed before it executes.

Consequently, **commit messages are written to a file and passed with
`git commit -F`**, never assembled from `-m` arguments, so the shell never
parses the message and backticks, `$`, quotes and `!` survive verbatim.

Author such files into the repo tree, not `/tmp`: a snap-confined `gh` gets a
private `/tmp` and the file vanishes across the process boundary. `.scratch/` is
excluded via `.git/info/exclude`, which is local and uncommitted, so the
exclusion is not imposed on other machines.

File writes are plain POSIX heredocs with a single-quoted delimiter, written as
a full-file rewrite, followed by `&&`-chained gates that only read and verify.
A file write is never chained to further work — the gates must pass first.

## 7. When something fails

Three steps, in order, before writing any fix:

1. **Search recent conversations.** This project has run since May across six
   machines; the problem has probably been solved already, quite possibly in
   another terminal on another laptop.
2. **Read `git log`.** The resolution may already be in history.
3. **Search the web** for current practice, then apply the root fix.

Skipping to step 3 reinvents solutions the repo already contains — and with six
agents in parallel, the same wheel gets reinvented six times.
