use std::{borrow::Borrow, collections::HashMap, hash::Hash};

/// Trait primarily added to accommodate both native and FFI usage of maps.
///
/// In FFI, only object references are available. So, if something like a [`HashMap`] is required,
/// then it has to be constructed from those references.
///
/// In native Rust code, the tendency is to already have the [`HashMap`] containing owned values
/// so it would be great to be able to work with that rather tha construct a new [`HashMap`] with
/// references from the one we already have.
pub trait ReferencesMap<K, V>
where
    K: std::hash::Hash + Eq,
{
    type Iter<'a>: IntoIterator<Item = (&'a K, &'a V)>
    where
        K: 'a,
        V: 'a,
        Self: 'a;

    fn get_ref<Q>(&self, key: &Q) -> Option<&V>
    where
        for<'a> &'a K: Borrow<Q>,
        K: Borrow<Q>,
        Q: Hash + Eq;

    fn iter_ref(&self) -> Self::Iter<'_>;
}

impl<K, V> ReferencesMap<K, V> for HashMap<K, V>
where
    K: std::hash::Hash + Eq,
{
    type Iter<'a> = std::collections::hash_map::Iter<'a, K, V>
    where
        K: 'a,
        V: 'a,
        Self: 'a;

    fn get_ref<Q>(&self, key: &Q) -> Option<&V>
    where
        for<'a> &'a K: Borrow<Q>,
        K: Borrow<Q>,
        Q: Hash + Eq,
    {
        self.get(key)
    }

    fn iter_ref(&self) -> Self::Iter<'_> {
        self.iter()
    }
}

type MapFnBothRef<'a, K, V> = fn((&'a &'a K, &'a &'a V)) -> (&'a K, &'a V);
type MapIterBothRef<'a, K, V> = std::collections::hash_map::Iter<'a, &'a K, &'a V>;

impl<K, V> ReferencesMap<K, V> for HashMap<&K, &V>
where
    K: std::hash::Hash + Eq,
{
    type Iter<'a> = std::iter::Map<MapIterBothRef<'a, K, V>, MapFnBothRef<'a, K, V>>
    where
        K: 'a,
        V: 'a,
        Self: 'a;

    fn get_ref<Q>(&self, key: &Q) -> Option<&V>
    where
        for<'a> &'a K: Borrow<Q>,
        K: Borrow<Q>,
        Q: Hash + Eq,
    {
        self.get(key).copied()
    }

    fn iter_ref(&self) -> Self::Iter<'_> {
        self.iter().map(|(k, v)| (*k, *v))
    }
}

type MapFnKeyRef<'a, K, V> = fn((&'a &'a K, &'a V)) -> (&'a K, &'a V);
type MapIterKeyRef<'a, K, V> = std::collections::hash_map::Iter<'a, &'a K, V>;

impl<K, V> ReferencesMap<K, V> for HashMap<&K, V>
where
    K: std::hash::Hash + Eq,
{
    type Iter<'a> = std::iter::Map<MapIterKeyRef<'a, K, V>, MapFnKeyRef<'a, K, V>>
    where
        K: 'a,
        V: 'a,
        Self: 'a;

    fn get_ref<Q>(&self, key: &Q) -> Option<&V>
    where
        for<'a> &'a K: Borrow<Q>,
        K: Borrow<Q>,
        Q: Hash + Eq,
    {
        self.get(key)
    }

    fn iter_ref(&self) -> Self::Iter<'_> {
        self.iter().map(|(k, v)| (*k, v))
    }
}

type MapFnValueRef<'a, K, V> = fn((&'a K, &'a &'a V)) -> (&'a K, &'a V);
type MapIterValueRef<'a, K, V> = std::collections::hash_map::Iter<'a, K, &'a V>;

impl<K, V> ReferencesMap<K, V> for HashMap<K, &V>
where
    K: std::hash::Hash + Eq,
{
    type Iter<'a> = std::iter::Map<MapIterValueRef<'a, K, V>, MapFnValueRef<'a, K, V>>
    where
        K: 'a,
        V: 'a,
        Self: 'a;

    fn get_ref<Q>(&self, key: &Q) -> Option<&V>
    where
        for<'a> &'a K: Borrow<Q>,
        K: Borrow<Q>,
        Q: Hash + Eq,
    {
        self.get(key).copied()
    }

    fn iter_ref(&self) -> Self::Iter<'_> {
        self.iter().map(|(k, v)| (k, *v))
    }
}
