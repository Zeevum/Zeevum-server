use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::sync::watch;

pub type ClientTx = mpsc::UnboundedSender<String>;

/// `kick` is how the server asks a connection to go away, a live socket never
/// re-checks whether its session exists.
#[derive(Clone)]
pub struct Connection {
    pub tx: ClientTx,
    pub kick: watch::Sender<bool>,
}

#[derive(Clone, Default)]
pub struct Hub {
    /// Every connection of a user, a phone and a laptop are both that user.
    users: Arc<Mutex<HashMap<i64, Vec<Connection>>>>,
}

impl Hub {
    pub fn new() -> Self {
        Self::default()
    }

    /// A second device adds another one rather than replacing the entry, which
    /// used to leave the first device connected but deaf.
    pub fn register(&self, user_id: i64, tx: ClientTx, kick: watch::Sender<bool>) {
        let mut users = self.users.lock().unwrap();
        users
            .entry(user_id)
            .or_default()
            .push(Connection { tx, kick });
    }

    /// Only this connection goes, a user that reconnected from another device
    /// must not lose the new socket when the old one cleans up.
    pub fn unregister_if(&self, user_id: i64, tx: &ClientTx) {
        let mut users = self.users.lock().unwrap();
        let Some(connections) = users.get_mut(&user_id) else {
            return;
        };

        connections.retain(|c| !c.tx.same_channel(tx));
        if connections.is_empty() {
            users.remove(&user_id);
        }
    }

    /// Returns whether at least one is still there, which callers read as "online".
    /// A dead channel is dropped, otherwise it would sit here one per reconnect.
    pub fn send_to(&self, target_user_id: i64, message: &str) -> bool {
        let mut users = self.users.lock().unwrap();
        let Some(connections) = users.get_mut(&target_user_id) else {
            return false; // Means that user is offline
        };

        let mut sent = false;
        connections.retain(|c| {
            let alive = c.tx.send(message.to_string()).is_ok();
            sent |= alive;
            alive
        });

        if connections.is_empty() {
            users.remove(&target_user_id);
        }
        sent
    }

    /// Used by "log out everywhere", revoking the tokens is not enough.
    pub fn kick_all(&self, user_id: i64) {
        let users = self.users.lock().unwrap();
        let Some(connections) = users.get(&user_id) else {
            return;
        };

        for c in connections {
            let _ = c.kick.send(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A kick channel the tests ignore, they check `send_to` and cleanup.
    fn kick() -> watch::Sender<bool> {
        let (tx, _rx) = watch::channel(false);
        tx
    }

    #[test]
    fn kicking_a_user_reaches_every_connection() {
        let hub = Hub::new();
        let (phone_tx, _phone_rx) = mpsc::unbounded_channel();
        let (laptop_tx, _laptop_rx) = mpsc::unbounded_channel();
        let (phone_kick, phone_kicked) = watch::channel(false);
        let (laptop_kick, laptop_kicked) = watch::channel(false);

        hub.register(7, phone_tx, phone_kick);
        hub.register(7, laptop_tx, laptop_kick);

        hub.kick_all(7);

        assert!(phone_kicked.has_changed().unwrap());
        assert!(laptop_kicked.has_changed().unwrap());
    }

    #[test]
    fn kicking_one_user_leaves_the_other_alone() {
        let hub = Hub::new();
        let (tx, _rx) = mpsc::unbounded_channel();
        let (kick_tx, kicked) = watch::channel(false);

        hub.register(7, tx, kick_tx);

        hub.kick_all(8);

        assert!(!kicked.has_changed().unwrap());
    }

    #[test]
    fn both_devices_of_a_user_receive_the_message() {
        let hub = Hub::new();
        let (phone_tx, mut phone_rx) = mpsc::unbounded_channel();
        let (laptop_tx, mut laptop_rx) = mpsc::unbounded_channel();

        hub.register(7, phone_tx, kick());
        hub.register(7, laptop_tx, kick());

        assert!(hub.send_to(7, "hello"));
        assert_eq!(phone_rx.try_recv().unwrap(), "hello");
        assert_eq!(laptop_rx.try_recv().unwrap(), "hello");
    }

    #[test]
    fn registering_a_second_device_does_not_deafen_the_first() {
        let hub = Hub::new();
        let (phone_tx, mut phone_rx) = mpsc::unbounded_channel();
        let (laptop_tx, mut laptop_rx) = mpsc::unbounded_channel();

        hub.register(7, phone_tx, kick());
        hub.register(7, laptop_tx, kick());

        hub.send_to(7, "hello");
        assert_eq!(phone_rx.try_recv().unwrap(), "hello");
        assert_eq!(laptop_rx.try_recv().unwrap(), "hello");
    }

    #[test]
    fn unregistering_one_device_leaves_the_other_connected() {
        let hub = Hub::new();
        let (phone_tx, mut phone_rx) = mpsc::unbounded_channel();
        let (laptop_tx, mut laptop_rx) = mpsc::unbounded_channel();

        hub.register(7, phone_tx.clone(), kick());
        hub.register(7, laptop_tx, kick());

        hub.unregister_if(7, &phone_tx);

        assert!(hub.send_to(7, "hello"));
        assert_eq!(laptop_rx.try_recv().unwrap(), "hello");
        assert!(
            phone_rx.try_recv().is_err(),
            "the unregistered device still received the frame"
        );
    }

    /// A socket that died before its cleanup leaves a channel behind. Keeping
    /// it would grow the vec by one per reconnect and report the user online.
    #[test]
    fn a_dead_channel_is_dropped_rather_than_kept() {
        let hub = Hub::new();
        let (dead_tx, dead_rx) = mpsc::unbounded_channel();
        hub.register(7, dead_tx, kick());
        drop(dead_rx);

        assert!(
            !hub.send_to(7, "hello"),
            "a dead channel must not read as online"
        );
        assert!(
            hub.users.lock().unwrap().is_empty(),
            "the dead channel was kept"
        );
    }

    #[test]
    fn a_dead_channel_does_not_hide_a_live_one() {
        let hub = Hub::new();
        let (dead_tx, dead_rx) = mpsc::unbounded_channel();
        let (live_tx, mut live_rx) = mpsc::unbounded_channel();

        hub.register(7, dead_tx, kick());
        hub.register(7, live_tx, kick());
        drop(dead_rx);

        assert!(hub.send_to(7, "hello"));
        assert_eq!(live_rx.try_recv().unwrap(), "hello");

        // The dead one is gone, so only the live channel is left.
        assert_eq!(hub.users.lock().unwrap().get(&7).unwrap().len(), 1);
    }
}
