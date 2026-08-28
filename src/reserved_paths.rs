//! Shared recognition of the Durable Streams reserved control segment.
//!
//! The storage server and the mTLS access proxy are separate binaries. Keeping
//! this predicate in one source module prevents authorization and dispatch from
//! disagreeing about whether a path belongs to the `__ds` control plane.

const CONTROL_SEGMENT: &str = "/__ds";

pub fn control_segment_index(path: &str) -> Option<usize> {
    path.match_indices(CONTROL_SEGMENT).find_map(|(index, _)| {
        let end = index + CONTROL_SEGMENT.len();
        (end == path.len() || path.as_bytes().get(end) == Some(&b'/')).then_some(index)
    })
}

pub fn is_control_path(path: &str) -> bool {
    control_segment_index(path).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_only_an_exact_reserved_segment_and_anchors_the_first_one() {
        let cases = [
            ("/__ds", true),
            ("/root/__ds/subscriptions/s", true),
            ("/root/__ds/subscriptions/s/unknown/__dsy", true),
            ("/root/__dsy/subscriptions/s", false),
            ("/root/events/__ds-not-control", false),
        ];
        for (path, expected) in cases {
            assert_eq!(is_control_path(path), expected, "{path}");
        }
        assert_eq!(
            control_segment_index("/root/__ds/one/__ds/two"),
            Some("/root".len())
        );
    }
}
