# Native package development

These files stage package development under ADR-0048. No WinGet, APT or DNF
channel has been published. Do not copy a planned installation command onto the
product site until native acceptance and channel publication finish.

The initial candidate is `v0.1.0-rc.4.2`, source commit
`f9f4e43ccc258e85ad2fff91df4bde90e1e09b4f`, protected release run `38603835793`.
Maintainers must authenticate the archive's release attestation before packaging.
The staging script checks fixed bytes but does not replace that authentication.
It neither downloads nor executes Kitrove.

## Linux staging

`python3 packaging/stage_linux.py ARCHIVE NEW_DIRECTORY` reads the exact pinned
Linux archive and creates a Debian package root. It refuses an existing output,
unexpected archive inventory, links, incorrect modes and digest mismatches.
Only the CLI and license notices enter the package. There are no maintainer
scripts or application configuration files.

The Debian version is `0.1.0~rc.4.2-1`, which sorts before `0.1.0-1`.
An isolated Ubuntu 24.04 x86-64 VM passed RC4.1 installation, upgrade to RC4.2,
removal, fresh RC4.2 installation and removal. Version/help checks ran as an
ordinary user after exact executable digest verification against authenticated
release bytes. Synthetic collection and harness canaries remained unchanged.
A foreign-package ownership test refused the overwrite and preserved its bytes.
Those direct-package tests do not cover other distributions or real user data.
The separate local repository checks are described below.
The executable needs glibc 2.34 or newer and libgcc-s1, as recorded in the Debian dependencies.
`python3 packaging/stage_rpm.py ARCHIVE NEW_DIRECTORY` prepares an RPM build tree.
Build on x86-64 Fedora with `rpmbuild --define "_topdir ABSOLUTE_DIRECTORY" -bb
ABSOLUTE_DIRECTORY/SPECS/kitrove-rc.spec`. The spec preserves the authenticated
binary without stripping it and checks its digest without executing it.
Fedora 44 passed local RPM install, ordinary-user version/help, removal and fresh
reinstallation/removal with isolated canary preservation. A subsequent native
RC4.1-to-signed-RC4.2 upgrade passed signature verification, exact executable
digest checks, ordinary-user version/help and canary preservation through removal.
RPM ownership-conflict acceptance also passed: RPM refused a foreign package's
file and preserved its bytes and owner. Isolated local APT and DNF repositories
passed signed-metadata installation and removal, exact executable digest checks,
ordinary-user version/help and canary preservation. Both clients rejected metadata
changed after signing. APT used a dedicated `Signed-By` key and a seven-day
`Valid-Until`; DNF required both package and repository signatures. These checks
do not cover public HTTPS hosting, repository upgrades or key rotation, and do not
establish a published channel. See [signing custody](SIGNING.md).

## Windows staging

`winget/` contains a three-file candidate manifest for the existing signed CLI
ZIP, with an explicit x64 archive digest. Select user scope at installation with
`--scope user`; portable manifests do not support a `Scope` field. WinGet owns the portable
command alias; Kitrove runs no installer script. All three manifests passed the
official JSON schemas. A Windows 11 evaluation VM with WinGet 1.29.380 passed
native manifest validation, installation, RC4.1-to-RC4.2 replacement and removal.
Tests checked exact authenticated executable hashes and Authenticode before
execution. A separate limited-token check passed installed version/help. Three
isolated synthetic canaries survived replacement and removal. These local-manifest
tests do not establish community publication or application-state migration.
The VM's older WinGet 1.6.10121 crashed during attachment security processing;
the test retained that failure and used the updated client without disabling checks.
Community review and publication remain open. Do not advertise an install command
until the channel exists.

Package managers replace their own binary without Kitrove's application-state
locks or rollback protocol. Finish pending application transactions before
changing versions. Package removal must preserve state, harness files and
credentials. Do not invoke the standalone installer against a packaged binary.
