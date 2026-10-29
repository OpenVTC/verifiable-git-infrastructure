// Generates $OUT_DIR/trust_tasks_generated.rs — the git-ns/bridge job, result
// and event specifications this bridge speaks, and only those — from
// trust-tasks.lock and the bundles vendored under trust-tasks/, after checking
// each bundle against its digest. `trust-tasks add|update` (trust-tasks-cli)
// moves a pin; `trust-tasks check` verifies the vendored bundles.
fn main() -> Result<(), trust_tasks_build::Error> {
    trust_tasks_build::Config::new()
        .lockfile("trust-tasks.lock")
        .compile()?;
    Ok(())
}
