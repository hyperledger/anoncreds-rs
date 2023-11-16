use crate::error::Result;

/// Helper structure to handle the case when value is either single object or list of objects
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> Default for OneOrMany<T> {
    fn default() -> Self {
        OneOrMany::Many(Vec::new())
    }
}

impl<T> OneOrMany<T> {
    pub fn get_value<F>(&self, closure: &dyn Fn(&T) -> Result<&F>) -> Result<&F> {
        match &self {
            OneOrMany::One(value) => closure(value),
            OneOrMany::Many(values) => values
                .iter()
                .find_map(|value| closure(value).ok())
                .ok_or_else(|| err_msg!("Object does not contain required value")),
        }
    }

    pub(crate) fn get_mut_value<F>(
        &mut self,
        closure: &dyn Fn(&mut T) -> Result<&mut F>,
    ) -> Result<&mut F> {
        match self {
            OneOrMany::One(value) => closure(value),
            OneOrMany::Many(values) => values
                .iter_mut()
                .find_map(|value| closure(value).ok())
                .ok_or_else(|| err_msg!("Object does not contain required value")),
        }
    }
}
