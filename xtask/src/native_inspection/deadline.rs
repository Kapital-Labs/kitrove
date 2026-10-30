use super::Refused;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Deadline(u64);

impl Deadline {
    pub(super) fn new(now: u64, parent: Option<&str>) -> Result<Self, Refused> {
        let cap = now.checked_add(60_000_000_000).ok_or(Refused::Deadline)?;
        let end = match parent {
            None => cap,
            Some(value) => {
                if value.is_empty()
                    || value.len() > 20
                    || !value.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(Refused::Deadline);
                }
                let end = value.parse::<u64>().map_err(|_| Refused::Deadline)?;
                let budget = end.checked_sub(now).ok_or(Refused::Deadline)?;
                if budget == 0 || budget > 1_800_000_000_000 {
                    return Err(Refused::Deadline);
                }
                end.min(cap)
            }
        };
        Ok(Self(end))
    }

    pub(super) fn remaining(self, now: u64) -> Result<Duration, Refused> {
        self.0
            .checked_sub(now)
            .filter(|value| *value > 0)
            .map(Duration::from_nanos)
            .ok_or(Refused::Deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_window_is_capped_by_parent_and_never_restarted() {
        let local = Deadline::new(100, None);
        assert!(
            local.is_ok(),
            "standalone closed verifier needs one bounded window"
        );
        let local = local.unwrap();
        assert_eq!(local.remaining(100), Ok(Duration::from_secs(60)));
        assert_eq!(local.remaining(1_000_000_100), Ok(Duration::from_secs(59)));
        assert!(local.remaining(60_000_000_100).is_err());
        let short = Deadline::new(100, Some("200")).unwrap();
        assert_eq!(short.remaining(150), Ok(Duration::from_nanos(50)));
        let long = Deadline::new(100, Some("120000000100")).unwrap();
        assert_eq!(long.remaining(100), Ok(Duration::from_secs(60)));
    }

    #[test]
    fn expired_malformed_overflow_or_excess_parent_bounds_refuse() {
        for value in [
            "",
            "0",
            "99",
            "100",
            "+200",
            " 200",
            "200 ",
            "-1",
            "200.0",
            "18446744073709551616",
            "999999999999999999999999999",
        ] {
            assert!(Deadline::new(100, Some(value)).is_err());
        }
        assert!(Deadline::new(u64::MAX - 1, None).is_err());
        assert!(Deadline::new(100, Some("1800000000101")).is_err());
    }
}
