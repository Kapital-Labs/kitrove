use cap_std::fs::DirEntry;

/// A deterministically ordered, bounded result from one capability-relative directory enumeration.
pub enum BoundedDirectoryEntries {
    /// Every entry fit within the allowance and is ordered by encoded file-name bytes.
    Complete(Vec<DirEntry>),
    /// At least one entry existed beyond the allowance; no partial entry set is exposed.
    Overflow,
}

/// Collects at most `allowance + 1` directory entries and orders them deterministically.
///
/// The extra entry proves overflow without consuming an unbounded iterator. Callers retain
/// responsibility for charging their own request budget and choosing fail-closed error behavior.
pub fn collect_bounded_sorted_directory_entries(
    entries: impl Iterator<Item = std::io::Result<DirEntry>>,
    allowance: usize,
) -> std::io::Result<BoundedDirectoryEntries> {
    let bounded = collect_bounded_entries(entries, allowance)?;
    if bounded.overflowed {
        return Ok(BoundedDirectoryEntries::Overflow);
    }
    let mut entries = bounded.entries;
    entries.sort_by(|left, right| {
        left.file_name()
            .as_encoded_bytes()
            .cmp(right.file_name().as_encoded_bytes())
    });
    Ok(BoundedDirectoryEntries::Complete(entries))
}

struct BoundedEntries<T> {
    entries: Vec<T>,
    overflowed: bool,
}

fn collect_bounded_entries<T, E>(
    entries: impl Iterator<Item = Result<T, E>>,
    allowance: usize,
) -> Result<BoundedEntries<T>, E> {
    let entries = entries
        .take(allowance.saturating_add(1))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(BoundedEntries {
        overflowed: entries.len() > allowance,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::convert::Infallible;

    use cap_std::ambient_authority;
    use cap_std::fs::Dir;

    use super::{
        BoundedDirectoryEntries, collect_bounded_entries, collect_bounded_sorted_directory_entries,
    };

    #[test]
    fn bounded_entry_collection_consumes_only_allowance_plus_one() {
        let consumed = Cell::new(0);
        let entries = (0..10).map(|value| {
            consumed.set(consumed.get() + 1);
            Ok::<_, Infallible>(value)
        });

        let bounded = collect_bounded_entries(entries, 2).unwrap();

        assert_eq!(bounded.entries, [0, 1, 2]);
        assert!(bounded.overflowed);
        assert_eq!(consumed.get(), 3);
    }

    #[test]
    fn bounded_directory_entries_detect_overflow_without_exposing_a_partial_set() {
        let temporary = tempfile::tempdir().unwrap();
        for name in ["c", "a", "b"] {
            std::fs::write(temporary.path().join(name), []).unwrap();
        }
        let directory = Dir::open_ambient_dir(temporary.path(), ambient_authority()).unwrap();

        let bounded =
            collect_bounded_sorted_directory_entries(directory.entries().unwrap(), 2).unwrap();

        assert!(matches!(bounded, BoundedDirectoryEntries::Overflow));
    }

    #[test]
    fn complete_directory_entries_are_sorted_by_encoded_name() {
        let temporary = tempfile::tempdir().unwrap();
        for name in ["c", "a", "b"] {
            std::fs::write(temporary.path().join(name), []).unwrap();
        }
        let directory = Dir::open_ambient_dir(temporary.path(), ambient_authority()).unwrap();

        let bounded =
            collect_bounded_sorted_directory_entries(directory.entries().unwrap(), 3).unwrap();

        let BoundedDirectoryEntries::Complete(entries) = bounded else {
            panic!("an exact allowance must return the complete entry set");
        };
        assert_eq!(
            entries
                .into_iter()
                .map(|entry| entry.file_name())
                .collect::<Vec<_>>(),
            ["a", "b", "c"]
        );
    }
}
