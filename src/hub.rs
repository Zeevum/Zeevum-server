use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

pub type ClientTx = mpsc::UnboundedSender<String>;

#[derive(Clone, Default)]
pub struct Hub {
    users: Arc<Mutex<HashMap<i64, ClientTx>>>,
}

impl Hub {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, user_id: i64, tx: ClientTx) {
        let mut users = self.users.lock().unwrap();
        users.insert(user_id, tx);
    }

    /// Removes the entry only if it still belongs to this connection, a user
    /// that reconnected from another device must not be unregistered by the
    /// cleanup of the old socket
    pub fn unregister_if(&self, user_id: i64, tx: &ClientTx) {
        let mut users = self.users.lock().unwrap();
        if let Some(current) = users.get(&user_id)
            && current.same_channel(tx)
        {
            users.remove(&user_id);
        }
    }

    pub fn send_to(&self, target_user_id: i64, message: &str) -> bool {
        let users = self.users.lock().unwrap();

        if let Some(tx) = users.get(&target_user_id) {
            tx.send(message.to_string()).is_ok()
        } else {
            false // Means that user is offline
        }
    }
}
