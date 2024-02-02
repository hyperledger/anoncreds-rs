/// Helper structure to handle the case when value is either single object or list of objects
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    Many(Vec<T>),
    One(T),
}

impl<T> Default for OneOrMany<T> {
    fn default() -> Self {
        OneOrMany::Many(Vec::new())
    }
}

impl<T> OneOrMany<T> {
    pub fn find_value<'a, F: 'a>(&'a self, closure: &dyn Fn(&'a T) -> Option<F>) -> Option<F> {
        match self {
            OneOrMany::One(value) => closure(value),
            OneOrMany::Many(values) => values.iter().find_map(closure),
        }
    }

    pub(crate) fn find_mut_value<'a, F: 'a>(
        &'a mut self,
        closure: &dyn Fn(&'a mut T) -> Option<F>,
    ) -> Option<F> {
        match self {
            OneOrMany::One(value) => closure(value),
            OneOrMany::Many(values) => values.iter_mut().find_map(closure),
        }
    }
}
