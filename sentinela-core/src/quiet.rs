use crate::env::LoopConfig;
use crate::rev::Rev;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuietWindow {
    quiet_ms: u64,
    ceiling_ms: u64,
}

impl QuietWindow {
    #[must_use]
    pub fn new(quiet_seconds: u64, max_seconds: u64) -> Self {
        let quiet_ms = quiet_seconds.saturating_mul(1000);
        Self {
            quiet_ms,
            ceiling_ms: max_seconds.saturating_mul(1000).max(quiet_ms),
        }
    }

    #[must_use]
    pub fn of(cfg: &LoopConfig) -> Self {
        Self::new(cfg.head_quiet_seconds, cfg.head_quiet_max_seconds)
    }

    #[must_use]
    pub fn quiet_ms(&self) -> u64 {
        self.quiet_ms
    }

    #[must_use]
    pub fn ceiling_ms(&self) -> u64 {
        self.ceiling_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Admission {
    Settled(Rev),
    Settling { rev: Rev, remaining_ms: u64 },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Quiet {
    seen: Option<(Rev, u64)>,
    waiting_since: Option<u64>,
}

impl Quiet {
    pub(crate) fn admit(&mut self, head: Rev, now_ms: u64, window: QuietWindow) -> Admission {
        if window.quiet_ms == 0 {
            return Admission::Settled(head);
        }
        let since = match &self.seen {
            Some((rev, at)) if *rev == head => *at,
            _ => {
                self.seen = Some((head.clone(), now_ms));
                now_ms
            }
        };
        let waiting = *self.waiting_since.get_or_insert(now_ms);
        let quiet_left = window.quiet_ms.saturating_sub(now_ms.saturating_sub(since));
        let ceiling_left = window
            .ceiling_ms
            .saturating_sub(now_ms.saturating_sub(waiting));
        match quiet_left.min(ceiling_left) {
            0 => Admission::Settled(head),
            remaining_ms => Admission::Settling {
                rev: head,
                remaining_ms,
            },
        }
    }

    pub(crate) fn caught_up(&mut self) {
        self.waiting_since = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rev(n: u8) -> Rev {
        Rev::parse(&format!("{:0>40}", format!("{n:x}"))).unwrap()
    }

    #[test]
    fn zero_admits_every_head_at_once() {
        let mut q = Quiet::default();
        assert_eq!(
            q.admit(rev(1), 0, QuietWindow::new(0, 3600)),
            Admission::Settled(rev(1))
        );
    }

    #[test]
    fn a_ceiling_below_the_window_is_raised_to_it() {
        let w = QuietWindow::new(600, 0);
        assert_eq!(w.ceiling_ms(), w.quiet_ms());
        assert_eq!(w.ceiling_ms(), 600_000);
    }

    #[test]
    fn a_moving_head_restarts_the_window_and_the_ceiling_does_not() {
        let w = QuietWindow::new(600, 1000);
        let mut q = Quiet::default();
        assert!(matches!(
            q.admit(rev(1), 0, w),
            Admission::Settling {
                remaining_ms: 600_000,
                ..
            }
        ));
        assert!(matches!(
            q.admit(rev(2), 500_000, w),
            Admission::Settling {
                remaining_ms: 500_000,
                ..
            }
        ));
        assert!(matches!(
            q.admit(rev(3), 900_000, w),
            Admission::Settling {
                remaining_ms: 100_000,
                ..
            }
        ));
        assert_eq!(q.admit(rev(4), 1_000_000, w), Admission::Settled(rev(4)));
    }

    #[test]
    fn catching_up_restarts_the_ceiling() {
        let w = QuietWindow::new(600, 600);
        let mut q = Quiet::default();
        assert_eq!(
            q.admit(rev(1), 0, w),
            Admission::Settling {
                rev: rev(1),
                remaining_ms: 600_000
            }
        );
        assert_eq!(q.admit(rev(1), 600_000, w), Admission::Settled(rev(1)));
        q.caught_up();
        assert_eq!(
            q.admit(rev(2), 700_000, w),
            Admission::Settling {
                rev: rev(2),
                remaining_ms: 600_000
            }
        );
    }
}
