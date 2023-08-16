use std::{
    borrow::Borrow,
    collections::{hash_map, HashMap},
    hash::{self, Hash},
};

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
    K: hash::Hash + Eq,
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
    K: hash::Hash + Eq,
{
    type Iter<'a> = hash_map::Iter<'a, K, V>
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

pub struct MapIterBothRef<'a, K, V>(hash_map::Iter<'a, &'a K, &'a V>);

impl<'a, K, V> Iterator for MapIterBothRef<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|(k, v)| (*k, *v))
    }
}

impl<K, V> ReferencesMap<K, V> for HashMap<&K, &V>
where
    K: hash::Hash + Eq,
{
    type Iter<'a> = MapIterBothRef<'a, K, V>
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
        MapIterBothRef(self.iter())
    }
}

pub struct MapIterKeyRef<'a, K, V>(hash_map::Iter<'a, &'a K, V>);

impl<'a, K, V> Iterator for MapIterKeyRef<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|(k, v)| (*k, v))
    }
}

impl<K, V> ReferencesMap<K, V> for HashMap<&K, V>
where
    K: hash::Hash + Eq,
{
    type Iter<'a> = MapIterKeyRef<'a, K, V>
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
        MapIterKeyRef(self.iter())
    }
}

pub struct MapIterValueRef<'a, K, V>(hash_map::Iter<'a, K, &'a V>);

impl<'a, K, V> Iterator for MapIterValueRef<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|(k, v)| (k, *v))
    }
}

impl<K, V> ReferencesMap<K, V> for HashMap<K, &V>
where
    K: std::hash::Hash + Eq,
{
    type Iter<'a> = MapIterValueRef<'a, K ,V>
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
        MapIterValueRef(self.iter())
    }
}
