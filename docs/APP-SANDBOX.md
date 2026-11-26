# App filesystem and execution model

Urados gives each app exactly one Unix user. Every app user has the same primary group, `users`; there are no per-app Unix groups. Because a shared group alone cannot isolate writable data and caches, the root installer applies POSIX ACLs keyed to each app UID. The shared group ACL grants no access to another app's directories.

Confinement uses only standard UNIX mechanisms: a distinct UID per app, file modes, POSIX ACLs, and the kernel `no_new_privs` flag. No mandatory access control (SELinux or otherwise) is used.

An app's name is both its Unix user name and its folder and file name on ext4, so it must match `[a-z_][a-z0-9_-]*` and be at most 32 bytes. Names containing `/`, `.`, upper case, spaces or control characters are refused before any account or file is created.

## On-disk layout

| Path | Owner, group, mode | Purpose |
| --- | --- | --- |
| `/data/app_progs` | `root:root`, `0700` | Root-only package store. |
| `/data/app_progs/.locks` | `root:root`, `0700` | Per-app locks serialize installation state changes and each start's archive verification, extraction, and launch. |
| `/data/app_progs/<app>.zip` | `root:root`, `0600` | Verified, root-protected signed package archive. |
| `/data/app` | `root:root`, `0711` | Traversal-only parent. |
| `/data/app/<app>` | `root:users`, `0710` | Protected app parent; app users can traverse but cannot list or replace its entries. |
| `/data/app/<app>/data` | `root:users`, `0770`, per-UID ACL | Writable only by the matching app UID; `group::---`. Root ownership prevents the app from chmodding the home to expose it to the shared group. |
| `/data/app/<app>/system_cache` | `root:users`, setgid `2730`, per-UID ACL | Root has `rwx`; this app UID has `-wx`; the owning `users` group ACL has no permissions. |
| `/data/app/<app>/system_cache/app` | `root:users`, setgid `2770`, per-UID ACL | Package programs; the owning app UID has `rwx`, other users in `users` have none. |
| `/data/app/<app>/system_cache/user` | `root:users`, setgid `2770`, per-UID ACL | App-created code and programs; only that app UID gets `rwx`. |
| `/urados/bin/user` | Administrator-managed, read-only to apps | Trusted utilities, including BusyBox and command symlinks such as `sh`, `ls`, and `cp`. |

The data-home ACL grants RWX only to its app UID, and its default entries constrain inherited group permissions. Since the app does not own the home directory, it cannot widen the ACL or change the directory mode to admit other `users` members. The ACL default entries are also inherited by new files and directories under the two code directories. Package payload files are root-owned and group-owned by `users`; the named-user ACL grants access to the matching app UID. One app cannot list, read, write, or execute another app's data or cache merely because both accounts share the primary group.

## Package lifecycle and process start

`urpkg install <package.zip>` verifies the certificate chain and signature, then atomically reserves and stores the trusted archive as `/data/app_progs/<manifest-name>.zip`, creates the app account and cache directories, and extracts the signed payload under `/data/app/<name>/system_cache/app`. `urpkg start <name>` takes the same per-app lock, opens the root-owned `/data/app_progs/<name>.zip` without following symlinks, verifies and extracts through that pinned file descriptor, builds a temporary package-code tree, atomically swaps it into `system_cache/app`, and runs the manifest entry. Failed verification or extraction leaves the prior complete package tree in place. The separate `system_cache/user` directory is available for app-created programs and remains mutable across starts. The trusted ZIP, not the cache, is the source used for package verification.

Each app process is started by the root `urpkg` process in a forked child that:

1. (`--root` staging only) changes root to the staging tree;
2. sets its supplementary groups to exactly `{users}`, then its GID, then its UID;
3. checks that `setuid(0)` now fails, so root cannot be regained;
4. sets `no_new_privs`, so `setuid`/`setgid` binaries and file capabilities cannot raise its privilege again;
5. enters its data home, sets `umask 0077`, clears the environment to `PATH=/urados/bin/user`, `HOME`, `USER` and `LANG`, and execs the manifest entry.

The UID/GID drop and `no_new_privs` are the privilege boundary.

## What UNIX permissions do not stop

The UNIX-only model is weaker than the previous SELinux type model in one respect that matters:

- **Execution from `data/` is not blocked.** An app can write a program into `/data/app/<app>/data` and execute it, because `data/` is writable by its app UID and the filesystem is not mounted `noexec`. The former SELinux rule that labelled ordinary app data non-executable no longer exists. If that boundary is required, mount the data area with `noexec` (which must then not apply to `system_cache`, so it needs its own mount) or add a separate control.
- **Interpreted scripts are not blocked.** A trusted shell can run any readable script, including one in `data/`, regardless of mount options.
- **Same-UID isolation is not provided.** Two processes of the same app share its UID; the boundary is between apps, not within one app.

The `--root DIR` staging mode is not a security boundary. It uses a plain chroot and is for tests only.

## Scripts and mutable code

The generated package template uses `/urados/bin/user/sh`, the externally supplied BusyBox shell symlink. Apps can start further code directly from `system_cache`; that area is intentionally mutable. The package manager verifies the root-protected ZIP at install/start but does not treat the mutable cache as a trusted copy.

## Migration and verification

Existing installations that used SELinux user mappings (`<name>_u`, login mappings in the SELinux policy store) or per-app groups need manual cleanup: remove the local SELinux user and login records (`semanage login -d <name>`, `semanage user -d <name>_u`), ensure each app's primary group is `users`, remove obsolete app-specific groups only when safe, place each root-protected archive at `/data/app_progs/<app>.zip`, and recreate cache ACLs. `urpkg` no longer creates or reads SELinux records.

Run `make test` for certificate and filesystem end-to-end coverage. The end-to-end suite needs passwordless `sudo` and `getfacl`. Passing the staged tests does not prove the layout on a device; on the target, verify that the app runs as its own UID with group `users`, that one app cannot read or write another app's data or cache, and that the isolation holds for files the app itself creates.
