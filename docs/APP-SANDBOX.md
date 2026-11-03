# App filesystem and execution model

Urados gives each app exactly one Unix user and a distinct SELinux user. Every app user has the same primary group, `users`; there are no per-app Unix groups. Because a shared group alone cannot isolate writable data and caches, the root installer applies POSIX ACLs keyed to each app UID. The shared group ACL grants no access to another app's directories. The SELinux app domain separately denies execution from ordinary app data.

## On-disk layout

| Path | Owner, group, mode | Purpose |
| --- | --- | --- |
| `/data/app_progs` | `root:root`, `0700` | Root-only package store. |
| `/data/app_progs/.locks` | `root:root`, `0700` | Per-app locks serialize installation state changes and each start's archive verification, extraction, and launch. |
| `/data/app_progs/<app>.zip` | `root:root`, `0600` | Verified, root-protected signed package archive. |
| `/data/app` | `root:root`, `0711` | Traversal-only parent. |
| `/data/app/<app>` | `root:users`, `0710` | Protected app parent; app users can traverse but cannot list or replace its entries. |
| `/data/app/<app>/data` | `root:users`, `0770`, per-UID ACL | Writable only by the matching app UID; `group::---`. Root ownership prevents the app from chmodding the home to expose it to the shared group. SELinux labels its files non-executable. |
| `/data/app/<app>/system_cache` | `root:users`, setgid `2730`, per-UID ACL | Root has `rwx`; this app UID has `-wx`; the owning `users` group ACL has no permissions. |
| `/data/app/<app>/system_cache/app` | `root:users`, setgid `2770`, per-UID ACL | Package programs; the owning app UID has `rwx`, other users in `users` have none. |
| `/data/app/<app>/system_cache/user` | `root:users`, setgid `2770`, per-UID ACL | App-created code and programs; only that app UID gets `rwx`. |
| `/urados/bin/user` | Administrator-managed, read-only to apps | Trusted utilities, including BusyBox and command symlinks such as `sh`, `ls`, and `cp`. |

The data-home ACL grants RWX only to its app UID, and its default entries constrain inherited group permissions. Since the app does not own the home directory, it cannot widen the ACL or change the directory mode to admit other `users` members. The ACL default entries are also inherited by new files and directories under the two code directories. Package payload files are root-owned and group-owned by `users`; the named-user ACL grants access to the matching app UID. App-created entries inherit the same group and UID-specific ACL. One app cannot list, read, write, or execute another app's data or cache merely because both accounts share the primary group.

## Package lifecycle and process start

`urpkg install <package.zip>` verifies the certificate chain and signature, then atomically reserves and stores the trusted archive as `/data/app_progs/<manifest-name>.zip`, creates the app account and cache directories, and extracts the signed payload under `/data/app/<name>/system_cache/app`. `urpkg start <name>` takes the same per-app lock, opens the root-owned `/data/app_progs/<name>.zip` without following symlinks, verifies and extracts through that pinned file descriptor, builds a temporary package-code tree, atomically swaps it into `system_cache/app`, and runs the manifest entry. Failed verification or extraction leaves the prior complete package tree in place. The separate `system_cache/user` directory is available for app-created programs and remains mutable across starts. The trusted ZIP, not the cache, is the source used for package verification.

Production `urpkg start` launches `/urados/bin/urapp-runner`. The helper fails closed unless SELinux is enabled and enforcing and the helper itself runs in `urados_launcher_t`. It selects the per-app SELinux user and `urados_app_t`, passes only the shared `users` group, irreversibly drops UID/GID, enters the app's data home, clears the inherited environment, sets `PATH=/urados/bin/user`, and execs the manifest entry. It deliberately does not set `no_new_privs` before this exec: older kernels or policies with `nnp_nosuid_transition` disabled reject the intended SELinux transition as an invalid bounded transition. The irreversible UID/GID drop plus SELinux file-type boundary provide the privilege boundary; a prepared policy may enable `nnp_nosuid_transition` and add an explicit `process2:nnp_transition` rule if it wants to set the flag before exec. The `/data` filesystem must allow execution for `system_cache`; the SELinux type boundary, not a blanket `noexec` mount option, prevents direct execution from ordinary app data while leaving the code cache runnable.

The policy labels ordinary files below `data` as `urados_app_data_t`, with no execute permission. The root management type may traverse directories and update labels for repair, but cannot read, modify, or execute app-data file contents. The separate cache is `urados_app_code_t`, where the app may create, replace, and execute code. Trusted utility files are `urados_bin_user_t`, readable/executable but not writable by apps. The runner executable has its own label and is not executable by app processes.

The `--root DIR` staging/test mode is not a security boundary: it directly runs the entry in a synthetic chroot and does not emulate SELinux. Deployments must build and install the Urados policy for the device's custom base policy, install `/urados/bin/urapp-runner`, restore file labels, and verify that SELinux is enforcing. If the helper is missing, wrongly labelled, launched from the wrong domain, or SELinux is permissive/disabled, production start fails instead of silently running unconfined.

## Scripts and mutable code

The generated package template uses `/urados/bin/user/sh`, the externally supplied BusyBox shell symlink. Apps can start further code directly from `system_cache`; that area is intentionally mutable. The package manager verifies the root-protected ZIP at install/start but does not treat the mutable cache as a trusted copy.

A filesystem `noexec` rule only blocks direct kernel execution from ordinary data; it does **not** stop a trusted shell from interpreting a script it can read, such as `sh /data/app/<app>/data/script.sh`, or code passed to `sh -c`. Because shell-script apps and writable data are both supported, the data-area execution boundary is enforced for direct executable files, not interpreted shell content. Prohibiting interpreted scripts from app data requires a separate constrained script runner/interface.

## Migration and verification

This layout is not a chmod-only migration. Existing installations that have per-app groups or the former nested archive path need to be migrated: back up user data, ensure each app's primary group is `users`, remove obsolete app-specific groups only when safe, place each root-protected archive at `/data/app_progs/<app>.zip`, and recreate cache ACLs. Existing per-app SELinux user records must have the `urados_app_r` role and `urados_app_t` execution mapping.

Build requirements now include `libacl` development files. Run `make -C pkg_mgr test` for certificate and filesystem E2E coverage. `sh selinux/test/build.sh` compiles the module; the stock-reference `selinux/test/verify.sh` may report conflicts because Urados targets its own prepared base policy. Passing staged-root tests and module compilation does not prove runtime enforcement. On the custom target image with SELinux enforcing, verify that the runner enters the intended per-app context, direct execution from ordinary data is denied, execution from that app's cache and `/urados/bin/user` plus required libraries succeeds, execution from other locations is denied, and one app cannot access another app's data or cache.
