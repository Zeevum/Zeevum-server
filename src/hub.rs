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

    pub fn register(&self, chat_id: i64, tx: ClientTx) {
        let mut users = self.users.lock().unwrap();
        users.insert(chat_id, tx);
    }

    pub fn unregister_if(&self, chat_id: i64, tx: &ClientTx) {
        let mut users = self.users.lock().unwrap();
        if let Some(current) = users.get(&chat_id)
            && current.same_channel(tx) {
                users.remove(&chat_id);
            }
    }

    pub fn send_to(&self, target_chat_id: i64, message: &str) -> bool {
        let users = self.users.lock().unwrap();

        if let Some(tx) = users.get(&target_chat_id) {
            tx.send(message.to_string()).is_ok()
        } else {
            false // Значит что пользователь не в сети
        }
    }
}
