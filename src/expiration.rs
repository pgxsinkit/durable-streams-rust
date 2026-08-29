//! A weak, membership-only index for streams with an expiry policy.
//!
//! The future scanner owns its cursor and performs every liveness, deadline,
//! and retirement decision after a page has been returned. Keeping this index
//! deliberately unaware of those concerns prevents it from retaining streams
//! or taking Store locks while it is scanned.

use std::collections::BTreeMap;
use std::ops::Bound::{Excluded, Included, Unbounded};
use std::sync::{Arc, Mutex, Weak};

use crate::store::StreamState;

/// Stable round-robin position owned by an expiration scanner.
///
/// `after` is the last ID yielded in this pass. `anchor` is set only for a
/// caller that deliberately begins after a particular ID; it lets later pages
/// finish the wrapped lower half without re-visiting the upper half.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ExpirationCursor {
    after: Option<u64>,
    anchor: Option<u64>,
    wrapped: bool,
}

impl ExpirationCursor {
    pub(crate) const fn start() -> Self {
        Self {
            after: None,
            anchor: None,
            wrapped: false,
        }
    }

    /// Begin one round-robin pass strictly after `stream_id`, wrapping once to
    /// include lower IDs and `stream_id` itself if it remains registered.
    pub(crate) const fn after(stream_id: u64) -> Self {
        Self {
            after: Some(stream_id),
            anchor: Some(stream_id),
            wrapped: false,
        }
    }
}

/// One weak candidate copied out of the index lock.
#[derive(Clone)]
pub(crate) struct ExpirationCandidate {
    pub(crate) stream_id: u64,
    pub(crate) stream: Weak<StreamState>,
}

/// A bounded page plus the state needed to continue the same pass.
pub(crate) struct ExpirationPage {
    pub(crate) candidates: Vec<ExpirationCandidate>,
    pub(crate) next_cursor: ExpirationCursor,
    /// True once this pass has entered its wrapped, lower-ID half.
    pub(crate) wrapped: bool,
    /// True only when this call has exhausted the current pass.
    pub(crate) pass_complete: bool,
}

/// Weak membership for streams that have an expiration policy.
///
/// Dead weak entries are intentionally returned in bounded pages rather than
/// swept globally. The scanner can call [`Self::prune_dead`] for a candidate it
/// observed dead, keeping each small page O(limit) and avoiding an O(total)
/// stale-entry pass under this lock. Correct Store wiring will unregister an
/// identity before its final strong reference is dropped, so ordinary index
/// cardinality tracks currently registered expiring identities.
#[derive(Default)]
pub(crate) struct ExpiringStreams {
    entries: Mutex<BTreeMap<u64, Weak<StreamState>>>,
}

impl ExpiringStreams {
    /// Register this exact identity. Re-registering it is idempotent; a live
    /// different identity at the same stable ID is replaced as a new occupant.
    pub(crate) fn register_exact(&self, stream: &Arc<StreamState>) {
        self.register_at_id(stream.id, stream);
    }

    fn register_at_id(&self, stream_id: u64, stream: &Arc<StreamState>) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if entries
            .get(&stream_id)
            .and_then(Weak::upgrade)
            .is_some_and(|current| Arc::ptr_eq(&current, stream))
        {
            return;
        }
        entries.insert(stream_id, Arc::downgrade(stream));
    }

    /// Remove only the exact identity currently registered under its stable ID.
    /// A stale old Arc therefore cannot remove a replacement that reuses the ID.
    pub(crate) fn unregister_exact(&self, stream: &Arc<StreamState>) -> bool {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let exact = entries
            .get(&stream.id)
            .and_then(Weak::upgrade)
            .is_some_and(|current| Arc::ptr_eq(&current, stream));
        if exact {
            entries.remove(&stream.id);
        }
        exact
    }

    /// Remove a dead candidate observed in a page, but never a replacement.
    pub(crate) fn prune_dead(&self, candidate: &ExpirationCandidate) -> bool {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let dead_and_same = entries.get(&candidate.stream_id).is_some_and(|current| {
            current.upgrade().is_none() && current.ptr_eq(&candidate.stream)
        });
        if dead_and_same {
            entries.remove(&candidate.stream_id);
        }
        dead_and_same
    }

    /// Return one bounded round-robin page without upgrading a weak reference
    /// or consulting Store state under the index lock.
    pub(crate) fn page(&self, cursor: ExpirationCursor, limit: usize) -> ExpirationPage {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if entries.is_empty() {
            return ExpirationPage {
                candidates: Vec::new(),
                next_cursor: ExpirationCursor::start(),
                wrapped: cursor.wrapped,
                pass_complete: true,
            };
        }
        if limit == 0 {
            return ExpirationPage {
                candidates: Vec::new(),
                next_cursor: cursor,
                wrapped: cursor.wrapped,
                pass_complete: false,
            };
        }

        let mut candidates = Vec::with_capacity(limit.min(entries.len()));
        let mut wrapped = cursor.wrapped;
        let mut complete = false;
        if cursor.wrapped {
            let anchor = cursor
                .anchor
                .expect("a wrapped expiration cursor always has an anchor");
            let after = cursor
                .after
                .expect("a wrapped expiration cursor always has a last ID");
            complete = collect_page(
                entries.range((Excluded(after), Included(anchor))),
                &mut candidates,
                limit,
            );
        } else {
            let upper_exhausted = match cursor.after {
                Some(after) => collect_page(
                    entries.range((Excluded(after), Unbounded)),
                    &mut candidates,
                    limit,
                ),
                None => collect_page(entries.iter(), &mut candidates, limit),
            };
            if upper_exhausted {
                if let Some(anchor) = cursor.anchor {
                    if candidates.len() < limit {
                        wrapped = true;
                        complete = collect_page(
                            entries.range((Unbounded, Included(anchor))),
                            &mut candidates,
                            limit,
                        );
                    }
                } else {
                    complete = true;
                }
            }
        }

        let next_cursor = if complete {
            ExpirationCursor::start()
        } else {
            ExpirationCursor {
                after: candidates.last().map(|candidate| candidate.stream_id),
                anchor: cursor.anchor,
                wrapped,
            }
        };
        ExpirationPage {
            candidates,
            next_cursor,
            wrapped,
            pass_complete: complete,
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .len()
    }

    #[cfg(test)]
    fn register_replacement_for_test(&self, stream_id: u64, replacement: &Arc<StreamState>) {
        self.register_at_id(stream_id, replacement);
    }
}

fn collect_page<'a>(
    mut entries: impl Iterator<Item = (&'a u64, &'a Weak<StreamState>)>,
    output: &mut Vec<ExpirationCandidate>,
    limit: usize,
) -> bool {
    while output.len() < limit {
        let Some((stream_id, stream)) = entries.next() else {
            return true;
        };
        output.push(ExpirationCandidate {
            stream_id: *stream_id,
            stream: stream.clone(),
        });
    }
    entries.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{CreateResult, Store, StreamConfig};
    use crate::tier::TierConfig;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn config() -> StreamConfig {
        StreamConfig {
            content_type: "application/octet-stream".into(),
            ttl_seconds: Some(60),
            expires_at: None,
            expires_at_raw: None,
            create_closed: false,
            forked_from: None,
            fork_offset_raw: None,
            fork_sub_offset: None,
        }
    }

    fn store(tag: &str) -> (std::path::PathBuf, Arc<Store>) {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "ds-expiration-index-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&directory);
        let store =
            Arc::new(Store::new_with_tier(directory.clone(), TierConfig::default()).unwrap());
        (directory, store)
    }

    fn streams(store: &Store, paths: &[&str]) -> Vec<Arc<StreamState>> {
        paths
            .iter()
            .map(
                |path| match store.create(path, config(), None, 0).unwrap() {
                    CreateResult::Created(stream) => stream,
                    _ => panic!("test stream path must be vacant"),
                },
            )
            .collect()
    }

    fn ids(page: &ExpirationPage) -> Vec<u64> {
        page.candidates
            .iter()
            .map(|candidate| candidate.stream_id)
            .collect()
    }

    #[test]
    fn pages_are_sorted_bounded_and_complete_a_fresh_pass() {
        let (directory, store) = store("ordered");
        let streams = streams(&store, &["a", "b", "c"]);
        let index = ExpiringStreams::default();
        for stream in &streams {
            index.register_exact(stream);
            index.register_exact(stream);
        }
        let mut expected: Vec<_> = streams.iter().map(|stream| stream.id).collect();
        expected.sort_unstable();
        assert_eq!(index.len(), 3);

        let first = index.page(ExpirationCursor::start(), 2);
        assert_eq!(ids(&first), expected[..2]);
        assert!(!first.wrapped);
        assert!(!first.pass_complete);
        let second = index.page(first.next_cursor, 2);
        assert_eq!(ids(&second), expected[2..]);
        assert!(second.pass_complete);
        assert_eq!(second.next_cursor, ExpirationCursor::start());

        drop(streams);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn cursor_wraps_once_without_duplicate_entries_at_u64_boundaries() {
        let (directory, store) = store("wrap");
        let streams = streams(&store, &["a", "b", "c"]);
        let index = ExpiringStreams::default();
        for stream in &streams {
            index.register_exact(stream);
        }
        let mut expected: Vec<_> = streams.iter().map(|stream| stream.id).collect();
        expected.sort_unstable();

        let middle = expected[1];
        let page = index.page(ExpirationCursor::after(middle), 10);
        assert_eq!(ids(&page), vec![expected[2], expected[0], expected[1]]);
        assert!(page.wrapped);
        assert!(page.pass_complete);
        let mut distinct = ids(&page);
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct, expected);

        let max = index.page(ExpirationCursor::after(u64::MAX), 10);
        assert_eq!(ids(&max), expected);
        assert!(max.wrapped);
        assert!(max.pass_complete);
        let zero = index.page(ExpirationCursor::after(0), 10);
        let mut expected_after_zero: Vec<_> = expected
            .iter()
            .copied()
            .filter(|stream_id| *stream_id > 0)
            .collect();
        expected_after_zero.extend(expected.iter().copied().filter(|stream_id| *stream_id == 0));
        assert_eq!(ids(&zero), expected_after_zero);
        assert!(
            zero.wrapped,
            "an anchored pass attempts its lower half once"
        );

        drop(streams);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn wrapped_pass_continues_across_live_pages_without_revisiting_an_id() {
        let (directory, store) = store("live-wrap-pages");
        let streams = streams(&store, &["low", "middle", "first-high", "new-high"]);
        let mut ordered = streams.clone();
        ordered.sort_by_key(|stream| stream.id);
        let (low, middle, first_high, new_high) =
            (&ordered[0], &ordered[1], &ordered[2], &ordered[3]);
        let index = ExpiringStreams::default();
        index.register_exact(middle);
        index.register_exact(first_high);

        let first = index.page(ExpirationCursor::after(middle.id), 1);
        assert_eq!(ids(&first), vec![first_high.id]);
        assert!(!first.wrapped);
        assert!(!first.pass_complete);

        // Both insertions happen after the pass began. The new high identity is
        // still ahead of its live `after`, while the low identity belongs only
        // to the wrapped half.
        index.register_exact(new_high);
        index.register_exact(low);
        let second = index.page(first.next_cursor, 1);
        assert_eq!(ids(&second), vec![new_high.id]);
        assert!(!second.wrapped);
        assert!(!second.pass_complete);

        let third = index.page(second.next_cursor, 1);
        assert_eq!(ids(&third), vec![low.id]);
        assert!(third.wrapped, "the first lower-half page flips wrap state");
        assert!(!third.pass_complete);
        let fourth = index.page(third.next_cursor, 1);
        assert_eq!(ids(&fourth), vec![middle.id]);
        assert!(fourth.wrapped);
        assert!(fourth.pass_complete);
        assert_eq!(fourth.next_cursor, ExpirationCursor::start());

        let all = [
            ids(&first)[0],
            ids(&second)[0],
            ids(&third)[0],
            ids(&fourth)[0],
        ];
        assert_eq!(all, [first_high.id, new_high.id, low.id, middle.id]);
        let mut distinct = all.to_vec();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), all.len());

        drop(streams);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn zero_and_oversized_limits_have_defined_cursor_behavior() {
        let (directory, store) = store("limits");
        let streams = streams(&store, &["a", "b"]);
        let index = ExpiringStreams::default();
        for stream in &streams {
            index.register_exact(stream);
        }
        let cursor = ExpirationCursor::after(streams[0].id);
        let zero = index.page(cursor, 0);
        assert!(zero.candidates.is_empty());
        assert_eq!(zero.next_cursor, cursor);
        assert!(!zero.pass_complete);
        let all = index.page(ExpirationCursor::start(), usize::MAX);
        assert_eq!(all.candidates.len(), 2);
        assert!(all.pass_complete);

        let empty = ExpiringStreams::default().page(ExpirationCursor::after(u64::MAX), 0);
        assert!(empty.candidates.is_empty());
        assert!(empty.pass_complete);

        drop(streams);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn deleted_cursor_and_inserts_on_both_sides_remain_ordered() {
        let (directory, store) = store("cursor-churn");
        let streams = streams(&store, &["a", "b", "c", "d"]);
        let mut ordered = streams.clone();
        ordered.sort_by_key(|stream| stream.id);
        let index = ExpiringStreams::default();
        index.register_exact(&ordered[0]);
        index.register_exact(&ordered[2]);
        let cursor_id = ordered[2].id;
        assert!(index.unregister_exact(&ordered[2]));
        index.register_exact(&ordered[1]); // inserted below the now-deleted cursor
        index.register_exact(&ordered[3]); // inserted above it

        let page = index.page(ExpirationCursor::after(cursor_id), 10);
        assert_eq!(
            ids(&page),
            vec![ordered[3].id, ordered[0].id, ordered[1].id]
        );
        assert!(page.wrapped);
        assert!(page.pass_complete);

        drop(streams);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn live_same_id_replacement_is_registered_and_stale_unregistration_is_safe() {
        let (directory, store) = store("replacement");
        let streams = streams(&store, &["old", "replacement"]);
        let index = ExpiringStreams::default();
        index.register_exact(&streams[0]);
        // The test-only stable-ID injection calls the same register_at_id
        // implementation as register_exact; production IDs are immutable.
        index.register_replacement_for_test(streams[0].id, &streams[1]);

        assert!(!index.unregister_exact(&streams[0]));
        let page = index.page(ExpirationCursor::start(), 1);
        assert_eq!(page.candidates[0].stream_id, streams[0].id);
        assert!(page.candidates[0]
            .stream
            .upgrade()
            .is_some_and(|current| Arc::ptr_eq(&current, &streams[1])));

        drop(streams);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn stale_dead_candidate_cannot_prune_live_or_dead_replacements() {
        let (directory, store) = store("stale-prune");
        let mut streams = streams(&store, &["old", "live", "dead"]);
        let dead = streams.pop().unwrap();
        let live = streams.pop().unwrap();
        let old = streams.pop().unwrap();
        let index = ExpiringStreams::default();
        index.register_exact(&old);
        let stale = index
            .page(ExpirationCursor::start(), 1)
            .candidates
            .remove(0);
        assert!(store.streams.remove("old").is_some());
        drop(old);
        assert!(stale.stream.upgrade().is_none());

        index.register_replacement_for_test(stale.stream_id, &live);
        assert!(
            !index.prune_dead(&stale),
            "a stale dead candidate cannot prune a live replacement"
        );
        let live_page = index.page(ExpirationCursor::start(), 1);
        assert!(live_page.candidates[0]
            .stream
            .upgrade()
            .is_some_and(|current| Arc::ptr_eq(&current, &live)));

        index.register_replacement_for_test(stale.stream_id, &dead);
        assert!(store.streams.remove("dead").is_some());
        drop(dead);
        assert!(
            !index.prune_dead(&stale),
            "a stale candidate cannot prune a different dead replacement"
        );
        assert_eq!(index.len(), 1);
        let dead_page = index.page(ExpirationCursor::start(), 1);
        assert!(dead_page.candidates[0].stream.upgrade().is_none());

        drop(live);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn dead_weak_candidates_never_retain_streams_and_prune_exactly() {
        let (directory, store) = store("dead");
        let stream = streams(&store, &["dead"]).pop().expect("one test stream");
        let index = ExpiringStreams::default();
        index.register_exact(&stream);
        assert!(store.streams.remove("dead").is_some());
        drop(stream);
        drop(store);

        let page = index.page(ExpirationCursor::start(), 1);
        assert!(page.candidates[0].stream.upgrade().is_none());
        assert!(index.prune_dead(&page.candidates[0]));
        assert_eq!(index.len(), 0);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn concurrent_register_remove_and_page_are_lock_safe() {
        let (directory, store) = store("concurrent");
        let streams = streams(&store, &["a", "b", "c", "d"]);
        let index = Arc::new(ExpiringStreams::default());
        std::thread::scope(|scope| {
            for stream in &streams {
                let index = Arc::clone(&index);
                scope.spawn(move || {
                    for _ in 0..100 {
                        index.register_exact(stream);
                        let _ = index.page(ExpirationCursor::after(stream.id), 2);
                        assert!(index.unregister_exact(stream));
                    }
                });
            }
        });
        assert_eq!(index.len(), 0);

        drop(streams);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }
}
