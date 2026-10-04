//! Operator-selected production fixtures, never inferred from downloaded metadata.
#[cfg(target_os = "macos")]
pub const ARCHIVE: &str = "kitrove-cli-aarch64-apple-darwin.tar.xz";
#[cfg(target_os = "linux")]
pub const ARCHIVE: &str = "kitrove-cli-x86_64-unknown-linux-gnu.tar.xz";

#[cfg(target_os = "macos")]
pub const BUNDLES: [&str; 2] = [
    "rc1-public-attestations-20260924/kitrove-cli-aarch64-apple-darwin.tar.xz.corrected.bundle.json",
    "rc2-public-attestations-20260924/kitrove-cli-aarch64-apple-darwin.tar.xz.bundle.json",
];
#[cfg(target_os = "linux")]
pub const BUNDLES: [&str; 2] = ["release-a/a.bundle.json", "release-b/b.bundle.json"];

#[cfg(target_os = "macos")]
pub const DIRECTORIES: [&str; 2] = ["rc1-public-20260924", "rc2-public-20260924"];
#[cfg(target_os = "linux")]
pub const DIRECTORIES: [&str; 2] = ["release-a", "release-b"];

pub const TAGS: [&str; 2] = ["v0.1.0-rc.1.3", "v0.1.0-rc.2"];
pub const COMMITS: [&str; 2] = [
    "31b4657a8742756f26aa0596e2c57a4f357c8295",
    "11f2d7b7daa1115e23d95121a6f7c923153b3190",
];
#[cfg(target_os = "macos")]
pub const ARCHIVE_DIGESTS: [&str; 2] = [
    "e8c32f13cd4d6a115a86cfe3192d8863b2e1b2e87fff9052486921c2ef771c3c",
    "45701c8b18120cb0906586eb8371b5041618d1cf226b2f9ab40b52689af86ca5",
];
#[cfg(target_os = "linux")]
pub const ARCHIVE_DIGESTS: [&str; 2] = [
    "b10f9b34cd5ce3650d08a2c534224f5081edb0211be96edbda0ac193bf77f363",
    "569b4e8009480c8d31e37569ad7dcc24c08539885071a6e6dc8393be5105e3b1",
];

// The libtest child authenticates archives but never executes or checks a candidate.
#[allow(dead_code)]
#[cfg(target_os = "macos")]
pub const EXECUTABLE_DIGESTS: [&str; 2] = [
    "766afbe0279cf6a1f623a8a69bb122cfdcb3206f26a7b7c1acceff749e905e7e",
    "54ac690c5ae5b0bcc480f4925b0f7ef5fe4e9b777a6b9390ca0ead593715bed2",
];
#[allow(dead_code)]
#[cfg(target_os = "linux")]
pub const EXECUTABLE_DIGESTS: [&str; 2] = [
    "dcab288f698ff59e1f22404d93641d2a676a8d8b4b854d17c0762e1f8351a5aa",
    "9d0620cc3512ad921f86c32d279212bd9d54e6345360079dad5553044a0e505f",
];
