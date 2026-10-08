// SPDX-License-Identifier: MPL-2.0

//! Useful synchronization primitives.

mod arc_queue;
mod guard;
mod mutex;
mod rcu;
mod rwarc;
mod rwlock;
mod rwmutex;
mod spin;
mod wait;

pub(crate) use self::rcu::finish_grace_period;
#[cfg(feature = "kernelet")]
pub(crate) use self::rcu::{can_park_idle, enter_idle, leave_idle};
pub use self::{
    arc_queue::{ArcQueue, ArcQueueItem, ArcQueueLink},
    guard::{GuardTransfer, LocalIrqDisabled, PreemptDisabled, SpinGuardian, WriteIrqDisabled},
    mutex::{Mutex, MutexGuard},
    rcu::{Rcu, RcuDrop, RcuOption, RcuOptionReadGuard, RcuReadGuard, non_null},
    rwarc::{RoArc, RwArc},
    rwlock::{RwLock, RwLockReadGuard, RwLockUpgradeableGuard, RwLockWriteGuard},
    rwmutex::{RwMutex, RwMutexReadGuard, RwMutexUpgradeableGuard, RwMutexWriteGuard},
    spin::{SpinLock, SpinLockGuard},
    wait::{WaitQueue, Waiter, Waker},
};

pub(crate) fn init() {
    rcu::init();
}
