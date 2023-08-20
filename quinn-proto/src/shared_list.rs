use std::{
    marker::PhantomData,
    ptr,
    sync::{
        atomic::{AtomicBool, AtomicPtr, Ordering},
        Arc,
    },
};

/// A thread-safe intrusive list of `Arc<T>`s singly linked via `Getter`
///
/// An `Arc<T>` may participate in any static number of lists by having that many distinct
/// [`SharedListLink`] fields. The `Getter` helper defines a single `get` method which selects the
/// field associated with a certain list.
pub(crate) struct SharedList<T, Getter>
where
    Getter: LinkGetter<T>,
{
    head: AtomicPtr<T>,
    _marker: PhantomData<Getter>,
}

impl<T, Getter> SharedList<T, Getter>
where
    Getter: LinkGetter<T>,
{
    /// Add an entry to the front of the list
    ///
    /// Does nothing if `entry` was already in the list or one of its `Drain` iterators.
    ///
    /// Returns whether the list was previously empty, in which case a consumer might need to be
    /// notified to see the new entry.
    pub(crate) fn push(&self, entry: Arc<T>) -> bool {
        // `Acquire` synchronizes with the `Release` in `Drain::next` to ensure we don't clobber a
        // `next` pointer that the iterator is still going to read.
        if Getter::get(&*entry).linked.swap(true, Ordering::Acquire) {
            // Already linked
            return false;
        }
        let entry = Arc::into_raw(entry);
        // `Release` ordering ensures the write to `next` is (and any preceding writes to the `T` in
        // `entry` are) visible to anyone who `Acquire`s from `self.head`
        let prev = self
            .head
            .fetch_update(Ordering::Release, Ordering::Relaxed, |head| {
                // Safety: `entry` is trivially still valid here
                Getter::get(unsafe { &*entry })
                    .next
                    .store(head, Ordering::Relaxed);
                Some(entry.cast_mut())
            })
            // Lambda always returns `Some`
            .unwrap();
        prev.is_null()
    }

    /// Consume all entries in the queue
    pub(crate) fn drain(&self) -> Drain<T, Getter> {
        // `Acquire` ordering ensures visibility of the `next` pointers thanks to the `Release` in
        // `push`.
        let head = self.head.swap(ptr::null_mut(), Ordering::Acquire);
        Drain {
            // Safety: above swap means we uniquely own the underlying `Arc<T>`
            next: (!head.is_null()).then(|| unsafe { Arc::from_raw(head) }),
            _marker: PhantomData,
        }
    }
}

impl<T, Getter> Drop for SharedList<T, Getter>
where
    Getter: LinkGetter<T>,
{
    fn drop(&mut self) {
        self.drain();
    }
}

impl<T, Getter> Default for SharedList<T, Getter>
where
    Getter: LinkGetter<T>,
{
    fn default() -> Self {
        Self {
            head: AtomicPtr::new(ptr::null_mut()),
            _marker: PhantomData,
        }
    }
}

/// Trait of helper ZSTs that select which intrusive list for a given `T` to traverse
pub(crate) trait LinkGetter<T>: Sized + 'static {
    fn get(x: &T) -> &Link<T>;
}

/// A link in a [`SharedList`]
///
/// Each `SharedListLink<T>` field in a `T` allows an `Arc<T>` to participate in a distinct list.
#[derive(Debug)]
pub(crate) struct Link<T> {
    next: AtomicPtr<T>,
    /// Whether the link is participating in a list
    ///
    /// `true` when reachable through [`Drain::next`] on any existing [`Drain`] iterator, or on one
    /// newly constructed via [`SharedList::drain`].
    ///
    /// This can be `true` when `next` is null when this is the last item in a list.
    linked: AtomicBool,
}

impl<T> Default for Link<T> {
    fn default() -> Self {
        Self {
            next: AtomicPtr::new(ptr::null_mut()),
            linked: AtomicBool::new(false),
        }
    }
}

pub(crate) struct Drain<T, Getter>
where
    Getter: LinkGetter<T>,
{
    next: Option<Arc<T>>,
    _marker: PhantomData<Getter>,
}

impl<T, Getter> Default for Drain<T, Getter>
where
    Getter: LinkGetter<T>,
{
    /// Construct an empty iterator
    fn default() -> Self {
        Self {
            next: None,
            _marker: PhantomData,
        }
    }
}

impl<T, Getter> Iterator for Drain<T, Getter>
where
    Getter: LinkGetter<T>,
{
    type Item = Arc<T>;

    fn next(&mut self) -> Option<Arc<T>> {
        let current = self.next.take()?;
        let link = Getter::get(&*current);
        let next = link.next.load(Ordering::Relaxed);
        // `Release` synchronizes with the `Acquire` in `SharedList::push` to ensure the above read
        // gets the current value of `next` before it's clobbered by another `push`, ensuring we
        // don't leak the tail of the current list.
        link.linked.store(false, Ordering::Release);
        // Safety: The `Arc<T>` represented by `next` is uniquely owned by this iterator
        self.next = (!next.is_null()).then(|| unsafe { Arc::from_raw(next) });
        Some(current)
    }
}

impl<T, Getter> std::iter::FusedIterator for Drain<T, Getter> where Getter: LinkGetter<T> {}

impl<T, Getter> Drop for Drain<T, Getter>
where
    Getter: LinkGetter<T>,
{
    fn drop(&mut self) {
        // Recover and drop all remaining `Arc<T>`s
        for _ in self.by_ref() {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Item {
        value: u32,
        link: Link<Item>,
    }

    impl Item {
        fn new(x: u32) -> Arc<Self> {
            Arc::new(Self {
                value: x,
                link: Link::default(),
            })
        }
    }

    impl LinkGetter<Item> for () {
        fn get(x: &Item) -> &Link<Item> {
            &x.link
        }
    }

    #[test]
    fn insert_and_iterate() {
        let list = SharedList::<Item, ()>::default();
        assert!(list.push(Item::new(1)));
        assert!(!list.push(Item::new(2)));
        assert!(!list.push(Item::new(3)));

        let mut iter = list.drain();
        assert!(list.push(Item::new(4)));

        assert_eq!(iter.next().unwrap().value, 3);
        assert_eq!(iter.next().unwrap().value, 2);
        assert_eq!(iter.next().unwrap().value, 1);
        assert!(iter.next().is_none());

        let mut iter = list.drain();
        assert_eq!(iter.next().unwrap().value, 4);
        assert!(iter.next().is_none());

        let mut iter = list.drain();
        assert!(iter.next().is_none());
    }

    #[test]
    fn no_leaks() {
        let list = SharedList::<Item, ()>::default();
        let a = Item::new(1);
        let b = Item::new(2);
        list.push(a.clone());
        list.push(b.clone());
        assert_eq!(Arc::strong_count(&a), 2);
        assert_eq!(Arc::strong_count(&b), 2);
        drop(list);
        assert_eq!(Arc::strong_count(&a), 1);
        assert_eq!(Arc::strong_count(&b), 1);
    }

    #[test]
    fn reinsert() {
        let list = SharedList::<Item, ()>::default();
        let a = Item::new(1);
        let b = Item::new(2);
        list.push(a.clone());
        list.push(b);
        list.push(a);
        let mut iter = list.drain();
        assert_eq!(iter.next().unwrap().value, 2);
        assert_eq!(iter.next().unwrap().value, 1);
        assert!(iter.next().is_none());
    }
}
