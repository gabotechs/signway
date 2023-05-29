use async_trait::async_trait;

pub use in_memory_secret_getter::*;

mod in_memory_secret_getter;

#[async_trait]
pub trait SecretGetter: Send + Sync {
    async fn get_secret(&self, id: &str) -> anyhow::Result<Option<String>>;
}
