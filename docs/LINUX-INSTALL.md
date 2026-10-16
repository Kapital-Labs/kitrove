# Install the Linux preview

Kitrove's signed APT and DNF preview repositories provide `0.1.0-rc.4.2`
for x86-64 Linux. We tested installation, RC4.1-to-RC4.2 upgrades and removal
through the public HTTPS repositories on Ubuntu 24.04 and Fedora 44.
Other distributions and real application-state migrations need separate testing.

## Before you install

Use one installation method per machine. Run `command -v kitrove` to check for
an existing copy. If you installed a standalone binary, finish pending Kitrove
application transactions and follow that installation's removal instructions
before switching to a package manager. Do not overwrite an existing unmanaged
`/usr/bin/kitrove`, or use the standalone installer on a package-managed binary.
Keep your collection and machine-local state when changing installation methods.

The setup below needs `curl`, `sha256sum` and `gpg`. Run commands in Bash as your
normal user, with `sudo` for package configuration. These are preview packages.
Review package-manager prompts before confirming changes.

## Download and check the repository key

Run this block first, then use the instructions for your distribution in the
same terminal. Stop if the hash check fails. Do not import a different key to
work around an error.

```bash
kitrove_key_dir=$(mktemp -d) &&
curl --fail --proto '=https' --tlsv1.2 \
  https://kitrove.dev/packages/keys/kitrove-packages.asc \
  -o "$kitrove_key_dir/kitrove-packages.asc" &&
  (cd "$kitrove_key_dir" && printf '%s\n' \
    '5ac38737296e75cbabef85ab16de742a9dcf5abb487932f3f2adee4cf8a8aa07  kitrove-packages.asc' \
    | sha256sum --check) &&
  gpg --show-keys --with-fingerprint "$kitrove_key_dir/kitrove-packages.asc"
```

Confirm the primary fingerprint is
`0C0E 4DE9 8C93 CD10 5999 5A39 7438 6FFE 8762 A9E1`.
The signing subkey is `8315 6965 F7FF 656A BF6C 4EFB 60C2 FBF8 5106 58DF`.
Compare these pins with [the public signing record](../packaging/SIGNING.md).
The hash pins key bytes; package managers also verify signed metadata and packages
as applicable. Downloading a key from a website alone does not establish trust.

## Ubuntu / APT

Use x86-64 (`dpkg --print-architecture` must print `amd64`). The executable
requires glibc 2.34 or newer. For first-time repository setup:

```bash
(cd "$kitrove_key_dir" && printf '%s\n' \
  '5ac38737296e75cbabef85ab16de742a9dcf5abb487932f3f2adee4cf8a8aa07  kitrove-packages.asc' \
  | sha256sum --check) &&
test ! -e /etc/apt/keyrings/kitrove-packages.gpg &&
test ! -L /etc/apt/keyrings/kitrove-packages.gpg &&
gpg --dearmor --output "$kitrove_key_dir/kitrove-packages.gpg" \
  "$kitrove_key_dir/kitrove-packages.asc" &&
sudo install -d -m 0755 /etc/apt/keyrings &&
sudo install -m 0644 "$kitrove_key_dir/kitrove-packages.gpg" \
  /etc/apt/keyrings/kitrove-packages.gpg
```

Create `/etc/apt/sources.list.d/kitrove-preview.sources` with `sudoedit` and this
content. If that file exists, inspect it instead of replacing it:

```text
Types: deb
URIs: https://kitrove.dev/packages/apt
Suites: preview
Components: main
Architectures: amd64
Signed-By: /etc/apt/keyrings/kitrove-packages.gpg
```

```bash
sudo apt update && sudo apt install kitrove-rc &&
kitrove --version &&
kitrove init
```

For later upgrades, finish pending application transactions, then run
`sudo apt update && sudo apt install --only-upgrade kitrove-rc`.
To remove the executable, use `sudo apt remove kitrove-rc`. The package contains
no collection, harness configuration or credentials, so removal leaves those
files in place.

## Fedora / DNF

Use x86-64 (`uname -m` must print `x86_64`). For first-time repository setup:

```bash
(cd "$kitrove_key_dir" && printf '%s\n' \
  '5ac38737296e75cbabef85ab16de742a9dcf5abb487932f3f2adee4cf8a8aa07  kitrove-packages.asc' \
  | sha256sum --check) &&
test ! -e /etc/pki/rpm-gpg/RPM-GPG-KEY-kitrove &&
test ! -L /etc/pki/rpm-gpg/RPM-GPG-KEY-kitrove &&
sudo install -m 0644 "$kitrove_key_dir/kitrove-packages.asc" \
  /etc/pki/rpm-gpg/RPM-GPG-KEY-kitrove
```

Create `/etc/yum.repos.d/kitrove-preview.repo` with `sudoedit` and this content.
If that file exists, inspect it instead of replacing it:

```ini
[kitrove-preview]
name=Kitrove preview
baseurl=https://kitrove.dev/packages/rpm
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-kitrove
sslverify=1
metadata_expire=0
```

```bash
sudo dnf install kitrove-rc &&
kitrove --version &&
kitrove init
```

Check the fingerprint above before approving a key-import prompt. DNF may ask
for the key for both package and repository verification.
For later upgrades, finish pending application transactions, then run
`sudo dnf upgrade kitrove-rc`. To remove the executable, use
`sudo dnf remove kitrove-rc`; keep your collection and local state.

## Expiry or signature errors

APT metadata has a seven-day validity window. If it expires, stop and report it
through [GitHub issues](https://github.com/Kapital-Labs/kitrove/issues).
Do not disable `Check-Valid-Until`, signature verification or TLS checks.
Maintainers must publish reviewed, freshly signed metadata to restore service.
We also check RPM metadata freshness before deployment, but DNF does not enforce
an APT-style `Valid-Until` date. See the [renewal process](../packaging/HOSTING.md).

After installation, [follow the onboarding walkthrough](https://kitrove.dev/docs/).
Run `kitrove init` as your normal user, not with `sudo`.
