# App filesystem and execution model

Urados gives each app exactly one Unix user. App users share the global primary group `users`; there are no per-app Unix groups. Access isolation uses ordinary Unix ownership, mode bits, distinct UIDs, and the kernel `no_new_privs` flag. POSIX ACLs and mandatory access control are not used by the package manager.

An app's name is both its Unix user name and its folder and file name on ext4, so it must match `[a-z_][a-z0-9_-]*` and be at most 32 bytes. Names containing `/`, `.`, upper case, spaces or control characters are refused before any account or file is created.

## On-disk layout

| Path | Owner, group, mode | Purpose |
| --- | --- | --- |
| `/data` | `root:root`, `0711` if created; safe existing modes preserved | Root-managed data root; must not be group/world writable. |
| `/data/app_progs` | `root:root`, `0700` | Root-only package store. |
| `/data/app_progs/.locks` | `root:root`, `0700` | Per-app locks serialize installation and each start's verification, extraction, and launch. |
| `/data/app_progs/<app>.zip` | `root:root`, `0600` | Trusted signed package archive. |
| `/data/app` | `root:root`, `0711` | Traversal-only parent. |
| `/data/app/<app>` | `root:users`, `0710` | Protected app parent; app users can traverse but cannot list or replace its entries. |
| `/data/app/<app>/data` | `<app-UID>:root`, `0700` | Persistent app-private writable data; group and other have no permissions. |
| `/run` | `root:root`, `0755` tmpfs | Init-managed volatile filesystem; must be a real directory/mountpoint, not an app-owned symlink. |
| `/run/app` | `root:root`, `0711` | Created and secured by init at boot; `urpkg start` only validates it. |
| `/run/app/<app>` and payload entries | `<app-UID>:root`, `0570` | Freshly verified runtime payload; app-owner gets `r-x`, GID 0 gets `rwx`, other gets no access. |

App processes have their own UID and exactly the shared `users` group, not GID 0. When the process UID matches a file's owner, Unix permission checks use the owner bits, so the runtime's GID-0 `rwx` group permissions do not give the app write access under the initial `0570` modes. The root-owned `/run/app` parent is not writable by apps, which prevents an app from replacing its top-level runtime entry. If `/data` is absent, the package manager creates it as root:root mode `0711`; an existing `/data` must be root-owned and not writable by group or others, and its group/mode are preserved so mounted data filesystems are not unexpectedly changed. Persistent data is stored separately at `/data/app/<app>/data` and is created with no group or other permissions.

## Package lifecycle and process start

`urpkg install <package.zip>` verifies the signed package, stores the root-owned archive at `/data/app_progs/<name>.zip`, creates the app account, creates its private data home, and sets up persistent package-store permissions. It does not extract package code into persistent storage.

The init system removes any stale `/run` symlink itself, creates a real mountpoint, mounts `/run` as a root-owned tmpfs, and creates `/run/app` as `root:root 0711` during boot. `urpkg start` does not create or chmod `/run/app`; it refuses to start if this init-managed directory is missing or has unsafe ownership/mode.

`urpkg start <name>` takes the per-app lock, opens the root-owned archive without following symlinks, verifies the signature and package metadata through that pinned file descriptor, then extracts the signed payload into a fresh hidden sibling under `/run/app`. Each payload byte is checked against its signed digest while being written. Once the full extract succeeds, it is atomically published as `/run/app/<name>` and the manifest entry is launched from that directory. The existing manifest entry prefix `system_cache/app/` is retained for package compatibility; the part after that prefix maps to the payload root under `/run/app/<name>`. Start validates persistent directory and lock permissions but does not create or repair them; use install to set those up.

A failed signature check or extraction never launches the package and leaves the previous complete runtime tree intact. The next successful `start` replaces that tree with a new extraction from the verified archive. `/run` is normally volatile, so runtime trees are naturally cleared on reboot; the data home is persistent.

Installation configures the persistent package store, lock files, app parent, and private data home. At runtime, `urpkg start` validates those persistent permissions and the init-created `/run/app` parent; it does not create or repair them. It does create and permission the app-specific staging/payload tree as part of extracting the verified archive into volatile storage.

Each app process is started by the root `urpkg` process in a forked child that:

1. (`--root` staging only) changes root to the staging tree;
2. sets supplementary groups to exactly `{users}`, then sets the primary GID and app UID;
3. checks that `setuid(0)` now fails;
4. sets `no_new_privs`, so setuid/setgid binaries and file capabilities cannot raise its privilege again;
5. enters the app's data home, sets `umask 0077`, clears the inherited environment to `PATH=/urados/bin/user`, `HOME`, `USER` and `LANG`, and execs the verified entry under `/run/app/<name>`.

The UID/GID drop and `no_new_privs` are the privilege boundary.

## Permission-model limits

The requested runtime ownership makes the app UID the owner of `/run/app/<name>` and of its payload files. The initial `0570` modes give the app read/execute but not write; however, Unix owners may change permissions on their own files and directories. Therefore this is a default read/execute state, not an immutable package tree: an app can chmod or alter its own runtime tree after launch. The package manager's guarantee is that it verifies and freshly extracts the signed package before each `start`; a later start replaces runtime modifications with the trusted payload. For a stronger guarantee that the tree remains unmodifiable even by its owner, the runtime files/directories must not be owned by the app UID (for example, use root ownership with a named-user read/execute ACL, or a separately enforced read-only mount).

The app also owns its `data/` directory and can change its own mode. The directory starts at `0700` with no group/other permissions, but an app that deliberately chmods its data home or files can expose them to other local users subject to parent traversal permissions. Ownership-based privacy is the default; the owner is trusted with its own data.

Other limitations of the UNIX-only model:

- **Data execution is not blocked.** An app can write a program into its own data home and execute it unless the filesystem is separately mounted `noexec`. Interpreted scripts can still be run by a trusted interpreter.
- **Same-UID isolation is not provided.** Two processes of the same app share its UID and can access that app's runtime and data.
- **No MAC policy is used.** There is no SELinux/AppArmor policy confining path access beyond normal UNIX permissions.

The `--root DIR` staging mode is not a security boundary. It uses a plain chroot for tests and development only.

## Migration and verification

Existing installations that used the old persistent `system_cache` directories or ACL-based data homes need migration. Keep the root-protected archive at `/data/app_progs/<app>.zip`, recreate `/data/app/<app>/data` as owned by that app UID with group 0 and mode `0700`, and remove obsolete `system_cache` trees after verifying that any app-created files which must persist are backed up. Reboot or clear old runtime entries under `/run/app` after upgrading. Existing SELinux mappings (`<name>_u`) or per-app groups also need manual cleanup; ensure app accounts have primary group `users` and remove obsolete group or SELinux records only when safe. `urpkg` does not migrate old ACLs or SELinux records automatically.

Run `make test` for certificate and filesystem end-to-end coverage. The end-to-end suite needs passwordless `sudo`. On the target, verify the `/run` filesystem is writable by root and volatile, each app runs as its own UID with group `users`, runtime trees have owner app UID/group 0/mode `0570`, private data homes have owner app UID/group 0/mode `0700`, and another app cannot access them by default. Passing staged tests does not prove the host's account, mount, or filesystem configuration.
