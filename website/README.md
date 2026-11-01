# Kitrove product site

Dependency-free static product page and getting-started guide. Serve this directory
as the web root; `/docs/` is a real directory and needs no application routing.

```sh
python3 -m http.server 8731 --bind 127.0.0.1 --directory website
python3 -m unittest discover -s website/tests
node --check website/app.js
```

No build step, external fonts, trackers, cookies, or third-party scripts. All
platform instructions remain visible without JavaScript. JavaScript adds tabs
and clipboard buttons, with a manual-copy fallback on clipboard denial.

With Playwright and its Chromium browser already installed, the optional browser
check runs against the preview server on port 8731:

```sh
SITE_TEST_OUTPUT=/absolute/path/to/existing/evidence-directory node website/tests/browser-smoke.cjs
```

Set `PLAYWRIGHT_MODULE` to an absolute module path if Playwright is outside normal
Node resolution. Use a fresh evidence directory to preserve earlier screenshots.
This checks desktop/mobile layouts, keyboard tabs, copy success/failure, platform
deep links, and the no-JavaScript fallback. It is not part of `cargo ci`.

## Design

The signature illustration is a collection folder of skill cards leading to
another tool or computer. It is labeled as an illustration, not fabricated CLI
output. The rest of the layout uses restrained typography and section rules.

Palette: ice `#edf3fa`, ink `#152a43`, cobalt `#315ddd`, white `#ffffff`,
slate `#526579`, pale blue `#dfe9f7`. Display type uses the local Avenir Next /
Segoe UI stack; body uses system sans; labels and commands use system monospace.

```text
wordmark        how / docs / GitHub          install
headline + actions        portable collection illustration
discovery / native details / destination principles
workflow introduction     numbered steps
second computer           connect / combine / select
install introduction      platform tabs + commands
transfer boundaries       concrete limitations
FAQ                       footer
```

Design review: the folder provides a subject-specific focal point without tool
logos implying endorsement or equal support. Large headings should stay readable
on small screens. The longer technical limits belong in docs, while prerelease
and platform restrictions remain visible beside installation.

## Content and release maintenance

Review both pages against `docs/GETTING-STARTED.md`, `docs/RELEASES.md`,
`docs/RELEASE-ACCEPTANCE.md`, ADR-0046, and the public tap whenever commands or
release status change. The website is a curated summary, not generated reference
documentation. Tests freeze current commands and verify local links, but cannot
replace semantic review of product claims.

The primary download is the published RC5.5 fresh-install evaluation preview for
Apple Silicon macOS, x86-64 Linux and x86-64 Windows. Intel Macs are unsupported
in this preview. Link its exact tag, reviewed notes and versioned installer guide;
do not turn generated scripts into an authenticated bootstrap claim. Keep the
new-collection/empty-destination and no-supported-in-place-upgrade boundaries.
Artifact verification is not full fresh-install or clean-Mac acceptance.

Apple Silicon Homebrew and x86-64 APT/DNF repositories still distribute RC4.2;
their commands belong under explicitly older-version instructions, not RC5.5
installation. The Linux guide includes key verification and repository setup.
The RC4.2 WinGet submission is not an RC5.5 distribution path; do not imply its
approval or offer WinGet/Chocolatey install commands. This copy change does not
change any package bytes, signing metadata, channel or publication workflow.
A future package channel needs its own package, distribution trust review,
ordinary-user install/upgrade/uninstall acceptance, and publication approval.
Windows should prioritize WinGet, with Chocolatey optional. Linux packaging
should distinguish Debian/Ubuntu `.deb`/APT from Fedora-family `.rpm`/DNF.

References:

- https://learn.microsoft.com/en-us/windows/package-manager/winget/
- https://learn.microsoft.com/en-us/windows/package-manager/package/repository
- https://docs.chocolatey.org/en-us/community-repository/moderation/
- https://ubuntu.com/server/docs/package-management/
- https://packages.fedoraproject.org/pkgs/dnf/dnf/index.html

## Deployment boundary

GitHub Pages serves `kitrove.dev` from the public `Kapital-Labs/kitrove` repository.
Spaceship remains the DNS provider; no nameserver or DNSSEC change is needed.
The manually dispatched Product website workflow checks the exact current main
commit has successful main CI and Secret scan runs before uploading the site.
Pull requests run validation only, with no deployment permissions. Deployment
uses the `github-pages` environment and a short-lived Pages token, separate from
release signing and package publication.

`python3 website/build.py /new/output/path` copies an explicit public file list
and writes the Pages CNAME. It refuses an existing destination; tests, source
documentation, evidence, and unrelated repository files never enter the artifact.
Enable HTTPS enforcement after the custom-domain certificate is ready. Confirm
the home page, `/docs/`, www redirect, and a missing-path 404 after deployment.
Do not turn this into a download proxy or an unauthenticated installer script.

North-star impact: communicates NS-1 through NS-7 and NS-9/10 without changing
core models, discovery, trust, sync, or application behavior. No product runtime
or supported platform guarantees change in this unit.
