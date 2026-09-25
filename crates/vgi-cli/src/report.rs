//! What `vgi repo init` prints for each step.

use std::io::Write;

/// What a step did — or, under `--dry-run`, would do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// Already as the plan wants it; nothing sent.
    Unchanged,
    /// Absent; created.
    Create,
    /// Present but different; rewritten.
    Update,
    /// Present and no longer wanted; removed.
    Remove,
}

impl Change {
    fn label(self, dry_run: bool) -> &'static str {
        match (self, dry_run) {
            (Change::Unchanged, _) => "unchanged",
            (Change::Create, false) => "created",
            (Change::Update, false) => "updated",
            (Change::Remove, false) => "removed",
            (Change::Create, true) => "would create",
            (Change::Update, true) => "would update",
            (Change::Remove, true) => "would remove",
        }
    }
}

/// Where step lines go, and whether they describe changes made or planned.
pub struct Report<'w> {
    out: &'w mut dyn Write,
    dry_run: bool,
    changes: usize,
}

impl<'w> Report<'w> {
    /// A report to `out`.
    pub fn new(out: &'w mut dyn Write, dry_run: bool) -> Self {
        Report {
            out,
            dry_run,
            changes: 0,
        }
    }

    /// Whether nothing is being written.
    pub fn dry_run(&self) -> bool {
        self.dry_run
    }

    /// How many steps changed (or would change) something.
    pub fn changes(&self) -> usize {
        self.changes
    }

    /// A free-form line.
    pub fn line(&mut self, text: impl AsRef<str>) {
        // A closed stdout is not worth failing a half-applied plan over.
        let _ = writeln!(self.out, "{}", text.as_ref());
    }

    /// One step's outcome. `preview` — the file or request body — is shown
    /// only for a change under `--dry-run`, so the person sees every byte
    /// that would be written before anything is.
    pub fn step(&mut self, id: &str, subject: &str, change: Change, preview: Option<&str>) {
        if change != Change::Unchanged {
            self.changes += 1;
        }
        self.line(format!(
            "  [{:<12}] {id:<36} {subject}",
            change.label(self.dry_run)
        ));
        if self.dry_run
            && change != Change::Unchanged
            && let Some(p) = preview
        {
            for l in p.lines() {
                self.line(format!("      | {l}"));
            }
        }
    }
}
