# RC5.14 preparation review

The release includes reviewed PR138 authentication diagnostics and the pipe,
Windows path and dependency fixes prepared for RC5.13. This preparation changes
no application logic, workflow, permissions or third-party dependencies.

Only the 27 workspace versions change in Cargo.lock. Registry versions,
checksums, dependency edges and all other fields are unchanged. The reviewed
lock fingerprint binds that change. The catalog appends RC5.14 with an empty
rollback predecessor list; previous entries are unchanged. Its fingerprint is
updated. Third-party license material remains byte-identical.

Current notes, setup guidance and website references advance to RC5.14. Website
deployment and Homebrew promotion are held until independently verified release
publication. No Linux package, WinGet, Intel support, migration or stable-support
scope is added.

The current HTTP403 cleared after the Account Holder accepted Apple's updated
program agreement. Before and after credential checks used unchanged source and
credentials, with protected reviewer approval and full cleanup. This does not
recover RC5.13's suppressed native response or explain older stapling failures.

Full stable and Rust1.89 validation, manual source review, fresh dependency and
secret scans, nonpublishing packaging checks, exact public PR checks and green
latest main are required. Green exact merged main precedes new tagging/signing.
Source checks and unsigned smokes do not establish production acceptance. User
installation, collections and sync remain untouched.
