//! Synthetic I/O only: never enumerate real adapters or contact a server.
use std::cell::{Cell, RefCell};
use std::sync::{Arc, Mutex};

use super::*;
use crate::service::config::{AppConfig, StoredUser};
use crate::service::{AppState, Ipv4InternetStatus};

type Interfaces = Vec<(String, std::net::IpAddr)>;

fn snapshot(ip: &str) -> Interfaces {
    vec![("test-campus".into(), ip.parse().unwrap())]
}

fn online(ip: &str) -> OnlineUserInfo {
    OnlineUserInfo {
        error: "ok".into(),
        user_name: "test-cache-account".into(),
        online_ip: ip.into(),
        ..Default::default()
    }
}

fn fixture() -> (SharedState, Interfaces) {
    let mut s = AppState::new(AppConfig {
        users: vec![StoredUser {
            username: "test-cache-account".into(),
            encrypted_password: String::new(),
            if_name: Some("test-campus".into()),
            ip: None,
        }],
        ..Default::default()
    });
    let interfaces = snapshot("10.0.0.2");
    s.network_interfaces = Some(interfaces.clone());
    s.campus_ip = Some("10.0.0.2".into());
    s.campus_auth = CampusAuthStatus::LoggedIn;
    s.online_info = Some(online("10.0.0.2"));
    s.user_statuses[0].state = LoginState::Online;
    s.user_statuses[0].current_ip = "10.0.0.2".into();
    (Arc::new(Mutex::new(s)), interfaces)
}

#[tokio::test]
async fn healthy_cached_queries_never_enumerate_interfaces() {
    let (state, interfaces) = fixture();
    for _ in 0..10 {
        let guard = StatusQueryGuard::begin(&state, None).unwrap();
        sync_online_state_claimed_with_io(
            guard,
            &interfaces,
            true,
            || async { panic!("healthy cached queries must not read the OS address table") },
            |_, ip| {
                assert_eq!(ip.as_deref(), Some("10.0.0.2"));
                std::future::ready(Ok(Some(online("10.0.0.2"))))
            },
        )
        .await;
        assert_eq!(
            state.lock().unwrap().user_statuses[0].state,
            LoginState::Online
        );
    }
}

#[tokio::test]
async fn cached_suspect_queries_refresh_dhcp_before_demoting_the_account() {
    for first_result in [
        Ok(None),
        Err("synthetic timeout".into()),
        Ok(Some(OnlineUserInfo {
            user_name: "test-other-account".into(),
            ..online("10.0.0.2")
        })),
        Ok(Some(online("10.0.0.4"))),
    ] {
        let (state, interfaces) = fixture();
        let reads = Cell::new(0);
        let requests = RefCell::new(Vec::new());
        // Old A moved to another adapter; the account's binding now owns B.
        let mut fresh = snapshot("10.0.0.4");
        fresh.insert(0, ("test-other".into(), "10.0.0.2".parse().unwrap()));
        let guard = StatusQueryGuard::begin(&state, None).unwrap();
        sync_online_state_claimed_with_io(
            guard,
            &interfaces,
            true,
            || async {
                reads.set(reads.get() + 1);
                fresh.clone()
            },
            |_, ip| {
                requests.borrow_mut().push(ip.clone());
                assert_eq!(
                    state.lock().unwrap().user_statuses[0].state,
                    LoginState::Online,
                    "the cached response must not demote the current session before confirmation"
                );
                std::future::ready(if ip.as_deref() == Some("10.0.0.2") {
                    first_result.clone()
                } else {
                    assert_eq!(ip.as_deref(), Some("10.0.0.4"));
                    Ok(Some(online("10.0.0.4")))
                })
            },
        )
        .await;
        let s = state.lock().unwrap();
        assert_eq!(reads.get(), 1);
        assert_eq!(requests.into_inner().len(), 2);
        assert_eq!(s.user_statuses[0].state, LoginState::Online);
        assert_eq!(s.user_statuses[0].current_ip, "10.0.0.4");
        assert_eq!(s.network_interfaces.as_ref(), Some(&fresh));
        assert!(s.reconnect_targets.is_empty());
        assert!(!s.definitely_offline());
    }
}

#[tokio::test]
async fn base_and_suffixed_names_for_the_same_account_reuse_the_cache() {
    let (state, interfaces) = fixture();
    state.lock().unwrap().config.users[0].username = "test-cache-account@cmcc".into();
    for name in ["test-cache-account@cmcc", "test-cache-account"] {
        let guard = StatusQueryGuard::begin(&state, None).unwrap();
        sync_online_state_claimed_with_io(
            guard,
            &interfaces,
            true,
            || async { panic!("compatible names for the same account must reuse the cache") },
            |_, _| {
                std::future::ready(Ok(Some(OnlineUserInfo {
                    user_name: name.into(),
                    ..online("10.0.0.2")
                })))
            },
        )
        .await;
        assert_eq!(
            state.lock().unwrap().user_statuses[0].state,
            LoginState::Online
        );
    }
}

#[tokio::test]
async fn unchanged_ip_accepts_offline_only_after_refreshing_without_duplicate_http() {
    let (state, interfaces) = fixture();
    let reads = Cell::new(0);
    let requests = Cell::new(0);
    let guard = StatusQueryGuard::begin(&state, None).unwrap();
    sync_online_state_claimed_with_io(
        guard,
        &interfaces,
        true,
        || async {
            reads.set(reads.get() + 1);
            interfaces.clone()
        },
        |_, _| {
            requests.set(requests.get() + 1);
            std::future::ready(Ok(None))
        },
    )
    .await;
    let s = state.lock().unwrap();
    assert_eq!((reads.get(), requests.get()), (1, 1));
    assert!(s.definitely_offline());
    assert_eq!(s.reconnect_targets, vec![0]);
    assert_eq!(
        s.auth_generation, 0,
        "no authentication action should have run"
    );
}

#[tokio::test]
async fn missing_addresses_discard_cached_offline_evidence_and_wait() {
    let (state, interfaces) = fixture();
    {
        let mut s = state.lock().unwrap();
        s.config.enable_ipv4_internet_probe = true;
        s.ipv4_internet = Ipv4InternetStatus::CaptivePortal;
    }
    let guard = StatusQueryGuard::begin(&state, None).unwrap();
    let requests = Cell::new(0);
    sync_online_state_claimed_with_io(
        guard,
        &interfaces,
        true,
        || async { Vec::new() },
        |_, _| {
            requests.set(requests.get() + 1);
            std::future::ready(Ok(None))
        },
    )
    .await;
    let s = state.lock().unwrap();
    assert_eq!(requests.get(), 1);
    assert_eq!(s.network_interfaces.as_deref(), Some([].as_slice()));
    assert_eq!(s.campus_auth, CampusAuthStatus::Unknown);
    assert_eq!(s.ipv4_internet, Ipv4InternetStatus::ProbeFailed);
    assert_eq!(s.user_statuses[0].state, LoginState::Online);
    assert!(!s.definitely_offline());
}

#[tokio::test]
async fn a_late_refresh_cannot_replace_a_new_login_or_its_interface_cache() {
    let (state, interfaces) = fixture();
    let guard = StatusQueryGuard::begin(&state, None).unwrap();
    let requests = Cell::new(0);
    let fresh = snapshot("10.0.0.4");
    sync_online_state_claimed_with_io(
        guard,
        &interfaces,
        true,
        || async {
            let mut s = state.lock().unwrap();
            s.invalidate_auth_context();
            s.user_statuses[0].state = LoginState::PendingConfirm;
            s.user_statuses[0].current_ip = "10.0.0.4".into();
            s.network_interfaces = Some(fresh.clone());
            interfaces.clone()
        },
        |_, _| {
            requests.set(requests.get() + 1);
            std::future::ready(Ok(None))
        },
    )
    .await;
    let s = state.lock().unwrap();
    assert_eq!(requests.get(), 1);
    assert_eq!(s.user_statuses[0].state, LoginState::PendingConfirm);
    assert_eq!(s.user_statuses[0].current_ip, "10.0.0.4");
    assert_eq!(s.network_interfaces.as_ref(), Some(&fresh));
}

#[tokio::test]
async fn forced_refresh_updates_the_cache_and_uses_the_current_binding() {
    let (state, _) = fixture();
    let fresh = snapshot("10.0.0.4");
    let guard = StatusQueryGuard::begin(&state, None).unwrap();
    sync_online_state_claimed_with_io(
        guard,
        &fresh,
        false,
        || async { panic!("a supplied fresh snapshot needs no second collection") },
        |_, ip| {
            assert_eq!(ip.as_deref(), Some("10.0.0.4"));
            std::future::ready(Ok(Some(online("10.0.0.4"))))
        },
    )
    .await;
    let s = state.lock().unwrap();
    assert_eq!(s.network_interfaces.as_ref(), Some(&fresh));
    assert_eq!(s.campus_ip.as_deref(), Some("10.0.0.4"));
    assert_eq!(s.user_statuses[0].current_ip, "10.0.0.4");
}
