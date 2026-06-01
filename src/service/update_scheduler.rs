use std::time::{Duration, Instant};

use crate::service::update::UpdateStatus;
use crate::service::SharedState;

/// Retry delays: 1 min, 5 min, 15 min, then every 30 min.
const RETRY_DELAYS_SECS: &[u64] = &[60, 300, 900];
const STEADY_RETRY_SECS: u64 = 1800; // 30 min
const DAILY_INTERVAL_SECS: u64 = 86400; // 24 h

/// Returns true when the update system is busy (checking/downloading/etc.).
pub fn update_busy(status: &UpdateStatus) -> bool {
    matches!(
        status,
        UpdateStatus::Checking
            | UpdateStatus::Downloading
            | UpdateStatus::PreparingUpdate
            | UpdateStatus::Restarting
    )
}

/// Perform one update check, update AppState accordingly.
async fn check_update_once(state: &SharedState) -> Result<(), String> {
    // Set Checking (if not already busy)
    {
        let s = state.lock().unwrap();
        if update_busy(&s.update_status) {
            return Err("Update already in progress".to_string());
        }
    }
    {
        let mut s = state.lock().unwrap();
        s.update_status = UpdateStatus::Checking;
    }
    crate::service::request_ui_repaint();

    match crate::service::update::check_update().await {
        Ok(Some((latest, release_url, download_url))) => {
            let mut s = state.lock().unwrap();
            s.add_log(format!("[INFO] New version available: {}", latest));
            s.update_status = UpdateStatus::Available {
                latest,
                release_url,
                download_url,
            };
            crate::service::request_ui_repaint();
            Ok(())
        }
        Ok(None) => {
            let mut s = state.lock().unwrap();
            s.update_status = UpdateStatus::UpToDate;
            crate::service::request_ui_repaint();
            Ok(())
        }
        Err(e) => {
            let mut s = state.lock().unwrap();
            s.add_log(format!("[WARN] Update check failed: {}", e));
            s.update_status = UpdateStatus::Failed(e.clone());
            crate::service::request_ui_repaint();
            Err(e)
        }
    }
}

pub fn spawn_update_scheduler(state: SharedState) {
    tokio::spawn(async move {
        // ── Startup check ────────────────────────────────
        let mut last_check = Instant::now();
        let mut retry_count: usize = 0;

        if let Err(_e) = check_update_once(&state).await {
            retry_count = 1;
        }

        // ── Background loop ──────────────────────────────
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;

            // Determine if we should check now
            let should_check = {
                let s = state.lock().unwrap();
                if update_busy(&s.update_status) {
                    false
                } else if matches!(s.update_status, UpdateStatus::Failed(_)) {
                    // Retry after failure
                    true
                } else {
                    // Daily check: every 24h since last check
                    last_check.elapsed().as_secs() >= DAILY_INTERVAL_SECS
                }
            };

            if !should_check {
                continue;
            }

            // Calculate delay for failed retry
            let is_retry = {
                let s = state.lock().unwrap();
                matches!(s.update_status, UpdateStatus::Failed(_))
            };

            if is_retry && retry_count > 0 {
                let delay = if retry_count <= RETRY_DELAYS_SECS.len() {
                    RETRY_DELAYS_SECS[retry_count - 1]
                } else {
                    STEADY_RETRY_SECS
                };
                let elapsed = last_check.elapsed().as_secs();
                if elapsed < delay {
                    continue; // wait more
                }
            }

            match check_update_once(&state).await {
                Ok(()) => {
                    last_check = Instant::now();
                    retry_count = 0;
                }
                Err(_e) => {
                    last_check = Instant::now();
                    if retry_count == 0 {
                        retry_count = 1;
                    } else {
                        retry_count += 1;
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn busy_checking() {
        assert!(update_busy(&UpdateStatus::Checking));
    }

    #[test]
    fn busy_downloading() {
        assert!(update_busy(&UpdateStatus::Downloading));
    }

    #[test]
    fn busy_preparing() {
        assert!(update_busy(&UpdateStatus::PreparingUpdate));
    }

    #[test]
    fn busy_restarting() {
        assert!(update_busy(&UpdateStatus::Restarting));
    }

    #[test]
    fn not_busy_idle() {
        assert!(!update_busy(&UpdateStatus::Idle));
    }

    #[test]
    fn not_busy_uptodate() {
        assert!(!update_busy(&UpdateStatus::UpToDate));
    }

    #[test]
    fn not_busy_available() {
        assert!(!update_busy(&UpdateStatus::Available {
            latest: "v2.0.0".into(),
            release_url: String::new(),
            download_url: String::new(),
        }));
    }

    #[test]
    fn not_busy_failed() {
        assert!(!update_busy(&UpdateStatus::Failed("err".into())));
    }
}
