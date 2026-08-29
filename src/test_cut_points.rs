//! Exact-identity race cut points used only by crate tests.
//!
//! A registration stores scalar stream identity only: the stable numeric ID
//! and the allocation address of the current `Arc` target.  It deliberately
//! never stores an `Arc<StreamState>`, so a forgotten controller cannot keep a
//! retired stream alive or match a replacement at the same path.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex};
use std::time::Duration;

use tokio::sync::{watch, Notify};

use crate::store::StreamState;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum CutPoint {
    AppendAfterAppenderDropBeforeWalWait,
    AppendPostDurablePreVisible,
    FenceBeforeAppenderTransition,
    FenceAfterAppenderTransition,
    DeletionWatchRecheck,
    SubscriptionTransition,
    RegistryRemoval,
    ExpirationIndexRemoval,
    InventoryRemoval,
    MetadataLockBeforeUnlink,
    MetadataLockAfterUnlink,
    WalForgetBeforeDurableTails,
    WalForgetAndTailsCompleted,
    ForkSourceLease,
    ForkReferenceTransition,
    PhysicalSoftWriteEntry,
    PhysicalSoftWriteDisposition,
    PhysicalHardUnlinkEntry,
    PhysicalHardUnlinkDisposition,
}

/// Exact, non-owning stream incarnation identity. `ptr` is only compared as a
/// scalar while a caller already holds the corresponding stream reference.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct StreamIdentity {
    id: u64,
    ptr: usize,
}

impl StreamIdentity {
    pub(crate) fn of(stream: &StreamState) -> Self {
        Self {
            id: stream.id,
            ptr: stream as *const StreamState as usize,
        }
    }

    #[cfg(test)]
    const fn from_parts_for_test(id: u64, ptr: usize) -> Self {
        Self { id, ptr }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Key {
    point: CutPoint,
    stream: StreamIdentity,
}

struct PauseState {
    held: AtomicBool,
    released: AtomicBool,
    reached: Notify,
    async_release: watch::Sender<bool>,
    blocking_release: (Mutex<bool>, Condvar),
}

impl PauseState {
    fn release(&self) {
        self.released.store(true, Ordering::Release);
        self.async_release.send_replace(true);
        let (released, wake) = &self.blocking_release;
        *released
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
        wake.notify_all();
    }
}

static PAUSES: LazyLock<Mutex<HashMap<Key, Arc<PauseState>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// RAII registration for one exact point on one exact stream incarnation.
/// Dropping it releases a waiter before removing the exact key.
pub(crate) struct CutPointLease {
    key: Key,
    state: Arc<PauseState>,
}

pub(crate) fn pause(point: CutPoint, stream: &StreamState) -> CutPointLease {
    let key = Key {
        point,
        stream: StreamIdentity::of(stream),
    };
    let (async_release, _) = watch::channel(false);
    let state = Arc::new(PauseState {
        held: AtomicBool::new(false),
        released: AtomicBool::new(false),
        reached: Notify::new(),
        async_release,
        blocking_release: (Mutex::new(false), Condvar::new()),
    });
    let old = PAUSES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(key, Arc::clone(&state));
    assert!(old.is_none(), "exact cut point already registered");
    CutPointLease { key, state }
}

impl CutPointLease {
    pub(crate) async fn wait_until_held(&self) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let reached = self.state.reached.notified();
                tokio::pin!(reached);
                reached.as_mut().enable();
                if self.state.held.load(Ordering::Acquire) {
                    return;
                }
                reached.await;
            }
        })
        .await
        .expect("cut point was not reached within five seconds");
    }

    pub(crate) fn release(&self) {
        self.state.release();
    }
}

impl Drop for CutPointLease {
    fn drop(&mut self) {
        self.state.release();
        let mut pauses = PAUSES
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if pauses
            .get(&self.key)
            .is_some_and(|state| Arc::ptr_eq(state, &self.state))
        {
            pauses.remove(&self.key);
        }
    }
}

fn matching_state(point: CutPoint, stream: &StreamState) -> Option<Arc<PauseState>> {
    PAUSES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&Key {
            point,
            stream: StreamIdentity::of(stream),
        })
        .cloned()
}

/// Pause an async boundary after the caller has released every operational
/// lock. The test-only await is intentionally outside the registry lock.
pub(crate) async fn hit_async(point: CutPoint, stream: &StreamState) {
    let Some(state) = matching_state(point, stream) else {
        return;
    };
    hit_async_state(state).await;
}

async fn hit_async_state(state: Arc<PauseState>) {
    if state.released.load(Ordering::Acquire) || state.held.swap(true, Ordering::AcqRel) {
        return;
    }
    state.reached.notify_waiters();
    let mut released = state.async_release.subscribe();
    if !*released.borrow_and_update() {
        let _ = released.changed().await;
    }
}

/// Pause a synchronous physical/filesystem boundary. Callers must invoke this
/// before acquiring, or after dropping, any filesystem or metadata lock.
pub(crate) fn hit_blocking(point: CutPoint, stream: &StreamState) {
    let Some(state) = matching_state(point, stream) else {
        return;
    };
    hit_blocking_state(state);
}

fn hit_blocking_state(state: Arc<PauseState>) {
    if state.released.load(Ordering::Acquire) || state.held.swap(true, Ordering::AcqRel) {
        return;
    }
    state.reached.notify_waiters();
    let (released, wake) = &state.blocking_release;
    let mut released = released
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    while !*released {
        released = wake
            .wait(released)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn exact_identity_and_lease_drop_release_waiters_and_removes_exact_key() {
        let first = StreamIdentity::from_parts_for_test(7, 0x1000);
        let replacement = StreamIdentity::from_parts_for_test(7, 0x2000);
        assert_ne!(first, replacement, "pointer identity fences same-ID reuse");

        let point = CutPoint::FenceAfterAppenderTransition;
        let (async_release, _) = watch::channel(false);
        let state = Arc::new(PauseState {
            held: AtomicBool::new(false),
            released: AtomicBool::new(false),
            reached: Notify::new(),
            async_release,
            blocking_release: (Mutex::new(false), Condvar::new()),
        });
        let key = Key {
            point,
            stream: first,
        };
        PAUSES.lock().unwrap().insert(key, Arc::clone(&state));
        let lease = CutPointLease { key, state };

        let async_waiter = tokio::spawn(hit_async_state(Arc::clone(&lease.state)));
        lease.wait_until_held().await;
        drop(lease);
        async_waiter
            .await
            .expect("async cut waiter completes on lease drop");
        assert!(!PAUSES.lock().unwrap().contains_key(&key));

        let (blocking_release, _) = watch::channel(false);
        let blocking_state = Arc::new(PauseState {
            held: AtomicBool::new(false),
            released: AtomicBool::new(false),
            reached: Notify::new(),
            async_release: blocking_release,
            blocking_release: (Mutex::new(false), Condvar::new()),
        });
        let blocking_key = Key {
            point: CutPoint::PhysicalHardUnlinkEntry,
            stream: replacement,
        };
        PAUSES
            .lock()
            .unwrap()
            .insert(blocking_key, Arc::clone(&blocking_state));
        let blocking_lease = CutPointLease {
            key: blocking_key,
            state: Arc::clone(&blocking_state),
        };
        let blocking_waiter = std::thread::spawn(move || hit_blocking_state(blocking_state));
        blocking_lease.wait_until_held().await;
        drop(blocking_lease);
        blocking_waiter
            .join()
            .expect("blocking cut waiter completes on lease drop");
        assert!(!PAUSES.lock().unwrap().contains_key(&blocking_key));
    }
}
