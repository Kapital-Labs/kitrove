use kitrove_model::AssetId;
use kitrove_testkit::{portable_lockfile, portable_manifest};

#[test]
fn checked_in_portable_fixtures_parse_through_public_persistence_apis() {
    let manifest = portable_manifest();
    let lockfile = portable_lockfile();
    let review = AssetId::parse("review").expect("asset id");
    let review_pack = AssetId::parse("review-pack").expect("pack id");

    assert!(manifest.assets.contains_key(&review));
    assert!(manifest.packs.contains_key(&review_pack));
    assert!(lockfile.assets.contains_key(&review));
    assert!(lockfile.packs.contains_key(&review_pack));
}
