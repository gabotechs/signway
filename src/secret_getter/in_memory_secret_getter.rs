use crate::secret_getter::SecretGetter;
use async_trait::async_trait;
use std::collections::HashMap;

pub struct InMemorySecretGetter(pub HashMap<String, String>);

#[async_trait]
impl SecretGetter for InMemorySecretGetter {
    async fn get_secret(&self, id: &str) -> anyhow::Result<Option<String>> {
        Ok(self.0.get(id).cloned())
    }
}
