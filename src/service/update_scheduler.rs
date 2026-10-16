use std::time::Duration;

use crate::service::update::UpdateStatus;
use crate::service::SharedState;

/// Retry delays: 1 min, 5 min, 15 min, then every 30 min.
const RETRY_DELAYS_SECS: &[u64] = &[60, 300, 900];
const STEADY_RETRY_SECS: u64 = 1800; // 30 min
const DAILY_INTERVAL_SECS: u64 = 86400; // 24 h
const SCHEDULER_CRASH_RESTART_SECS: u64 = 60;

fn next_fail_count(fail_count: usize, checked: bool, status: &UpdateStatus) -> usize {
    if !checked && update_busy(status) {
        // An overlapping manual check/download has not produced a new result.
        fail_count
    } else if matches!(status, UpdateStatus::Failed(_)) {
        fail_count.saturating_add(1)
    } else {
        0
    }
}

fn check_delay_secs(fail_count: usize) -> u64 {
    if fail_count == 0 {
        DAILY_INTERVAL_SECS
    } else {
        RETRY_DELAYS_SECS
            .get(fail_count - 1)
            .copied()
            .unwrap_or(STEADY_RETRY_SECS)
    }
}

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

/// The restart phase and authentication/diagnostics must reserve AppState
/// under the same lock. Downloads themselves do not block normal networking.
pub(crate) fn restart_pending(status: &UpdateStatus) -> bool {
    matches!(
        status,
        UpdateStatus::PreparingUpdate | UpdateStatus::Restarting
    )
}

/// Perform one update check, update AppState accordingly.
pub fn try_begin_update_check(state: &SharedState) -> bool {
    let mut s = state.lock().unwrap();
    if update_busy(&s.update_status) {
        return false;
    }
    s.update_status = UpdateStatus::Checking;
    true
}

async fn check_update_once(state: &SharedState) -> Result<(), String> {
    if !try_begin_update_check(state) {
        return Err("Update already in progress".to_string());
    }
    check_update_claimed(state).await
}

pub async fn check_update_claimed(state: &SharedState) -> Result<(), String> {
    crate::service::request_ui_repaint();
    let result = tokio::spawn(crate::service::update::check_update())
        .await
        .unwrap_or_else(|e| Err(format!("Update check task failed: {}", e)));
    let mut s = state.lock().unwrap();
    if s.update_status != UpdateStatus::Checking {
        return Err("Update check no longer owns its state".to_string());
    }
    let outcome = match result {
        Ok(Some((latest, release_url, download_url))) => {
            s.add_log(format!("[INFO] New version available: {}", latest));
            s.update_status = UpdateStatus::Available {
                latest,
                release_url,
                download_url,
            };
            Ok(())
        }
        Ok(None) => {
            s.update_status = UpdateStatus::UpToDate;
            Ok(())
        }
        Err(e) => {
            s.add_log(format!("[WARN] Update check failed: {}", e));
            s.update_status = UpdateStatus::Failed(e.clone());
            Err(e)
        }
    };
    drop(s);
    crate::service::request_ui_repaint();
    outcome
}

/// Run the scheduler loop body. Each call performs one check cycle.
/// Returns true after a claimed check, including failure, and false if skipped.
async fn run_scheduler_cycle(state: &SharedState) -> bool {
    {
        // Decide and claim together: a manual check cannot take ownership
        // between the busy check and starting the scheduled request.
        let mut s = state.lock().unwrap();
        if update_busy(&s.update_status)
            || matches!(s.update_status, UpdateStatus::Available { .. })
        {
            return false;
        }
        s.update_status = UpdateStatus::Checking;
    }
    let _ = check_update_claimed(state).await;
    true
}

pub fn spawn_update_scheduler(state: SharedState) {
    tokio::spawn(async move {
        let mut fail_count: usize = 0;

        // ── Startup check ────────────────────────────────
        if let Err(_e) = check_update_once(&state).await {
            // Will retry after RETRY_DELAYS_SECS[0]
            fail_count = 1;
        }

        // ── Background loop ──────────────────────────────
        loop {
            // Compute sleep duration based on last result
            let sleep_secs = check_delay_secs(fail_count);

            tokio::time::sleep(Duration::from_secs(sleep_secs)).await;

            // Run the check as a separate task so panics are caught
            let cycle_state = state.clone();
            let handle = tokio::spawn(async move { run_scheduler_cycle(&cycle_state).await });

            let checked = match handle.await {
                Ok(checked) => checked,
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
                    if let Ok(mut s) = state.lock() {
                        if s.update_status == UpdateStatus::Checking {
                            s.update_status =
                                UpdateStatus::Failed("Update scheduler interrupted".into());
                        }
                    }
                    crate::service::request_ui_repaint();
                    fail_count = 1;
                    // Sleep handled by next loop iteration
                    continue;
                }
                Err(_) => {
                    tracing::info!("[UpdateScheduler] task cancelled, exiting");
                    break;
                }
            };

            // Update fail_count after the result
            {
                let s = state.lock().unwrap();
                fail_count = next_fail_count(fail_count, checked, &s.update_status);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_manual_claim_keeps_the_scheduled_check_skipped_and_the_retry_short() {
        let state = std::sync::Arc::new(std::sync::Mutex::new(crate::service::AppState::new(
            crate::service::config::AppConfig::default(),
        )));
        assert!(try_begin_update_check(&state));
        // The claimed check is deliberately not run: this test cannot make an HTTP request.
        let checked = run_scheduler_cycle(&state).await;
        assert!(!checked);
        assert_eq!(
            check_delay_secs(next_fail_count(
                1,
                checked,
                &state.lock().unwrap().update_status
            )),
            60
        );
    }

    #[test]
    fn a_busy_manual_check_does_not_delay_failed_startup_retries_for_a_day() {
        let failed = UpdateStatus::Failed("synthetic failure".into());
        let after_startup = next_fail_count(0, true, &failed);
        assert_eq!(check_delay_secs(after_startup), 60);
        let after_busy = next_fail_count(after_startup, false, &UpdateStatus::Checking);
        assert_eq!(check_delay_secs(after_busy), 60);
        let after_retry_failure = next_fail_count(after_busy, true, &failed);
        assert_eq!(check_delay_secs(after_retry_failure), 300);
        let available = UpdateStatus::Available {
            latest: "v99.0.0".into(),
            release_url: String::new(),
            download_url: String::new(),
        };
        assert_eq!(
            check_delay_secs(next_fail_count(after_retry_failure, false, &available)),
            86400
        );
    }

    #[test]
    fn check_claim_is_exclusive_and_preserves_downloads() {
        let state = std::sync::Arc::new(std::sync::Mutex::new(crate::service::AppState::new(
            crate::service::config::AppConfig::default(),
        )));
        assert!(try_begin_update_check(&state));
        assert!(!try_begin_update_check(&state));
        state.lock().unwrap().update_status = UpdateStatus::Downloading;
        assert!(!try_begin_update_check(&state));
        assert_eq!(
            state.lock().unwrap().update_status,
            UpdateStatus::Downloading
        );
    }

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
