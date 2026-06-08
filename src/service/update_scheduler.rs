use std::time::Duration;

use crate::service::update::UpdateStatus;
use crate::service::SharedState;

/// Retry delays: 1 min, 5 min, 15 min, then every 30 min.
const RETRY_DELAYS_SECS: &[u64] = &[60, 300, 900];
const STEADY_RETRY_SECS: u64 = 1800; // 30 min
const DAILY_INTERVAL_SECS: u64 = 86400; // 24 h
const SCHEDULER_CRASH_RESTART_SECS: u64 = 60;

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

/// Run the scheduler loop body. Each call performs one check cycle.
/// Returns Ok when a check was performed, Err if skipped or failed.
async fn run_scheduler_cycle(state: &SharedState) -> bool {
    // Determine if we should check now
    let should_check = {
        let s = state.lock().unwrap();
        if update_busy(&s.update_status)
            || matches!(s.update_status, UpdateStatus::Available { .. })
        {
            false
        } else if matches!(s.update_status, UpdateStatus::Failed(_)) {
            true
        } else {
            // No state tracking for daily check time — just always check
            // if not busy and not failed. The sleep between cycles provides
            // the throttling.
            true
        }
    };

    if !should_check {
        return false;
    }

    match check_update_once(state).await {
        Ok(()) => true,
        Err(_e) => {
            // On failure, increase the delay before next attempt
            true
        }
    }
}

pub fn spawn_update_scheduler(state: SharedState) {
    tokio::spawn(async move {
        // ── Startup check ────────────────────────────────
        if let Err(_e) = check_update_once(&state).await {
            // Will retry after RETRY_DELAYS_SECS[0]
        }

        let mut fail_count: usize = 0;

        // ── Background loop ──────────────────────────────
        loop {
            // Compute sleep duration based on last result
            let sleep_secs = if fail_count > 0 {
                if fail_count <= RETRY_DELAYS_SECS.len() {
                    RETRY_DELAYS_SECS[fail_count - 1]
                } else {
                    STEADY_RETRY_SECS
                }
            } else {
                DAILY_INTERVAL_SECS
            };

            tokio::time::sleep(Duration::from_secs(sleep_secs)).await;

            // Run the check as a separate task so panics are caught
            let cycle_state = state.clone();
            let handle = tokio::spawn(async move { run_scheduler_cycle(&cycle_state).await });

            match handle.await {
                Ok(true) => {}
                Ok(false) => {
                    // Skipped (busy), keep current fail_count
                }
                Err(e) if e.is_panic() => {
                    tracing::error!(
                        "[UpdateScheduler] cycle panicked: {}, restarting in {}s",
                        e,
                        SCHEDULER_CRASH_RESTART_SECS
                    );
                    if let Ok(mut s) = state.lock() {
                        s.add_log(format!(
                            "[ERROR] Update scheduler crashed: {}. Restarting in {}s...",
                            e, SCHEDULER_CRASH_RESTART_SECS
                        ));
                    }
                    fail_count = 0;
                    // Sleep handled by next loop iteration
                    continue;
                }
                Err(_) => {
                    tracing::info!("[UpdateScheduler] task cancelled, exiting");
                    break;
                }
            }

            // Update fail_count after the result
            {
                let s = state.lock().unwrap();
                if matches!(s.update_status, UpdateStatus::Failed(_)) {
                    if fail_count == 0 {
                        fail_count = 1;
                    } else {
                        fail_count += 1;
                    }
                } else {
                    fail_count = 0;
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
