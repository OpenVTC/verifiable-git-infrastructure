//! The trait's defaults and `run_plan`, driven through `dyn Forge` with an
//! in-memory adapter — which is also the proof that the trait stays
//! object-safe.

use std::sync::Mutex;

use http::HeaderMap;
use vgi_forge::{
    ApplyReport, BindCallback, BindRequest, BindStep, BootstrapComponent, BootstrapStep,
    Capabilities, EffectiveRights, Forge, ForgeAccount, ForgeError, ForgeEvent, ForgeKind,
    ForgeRole, LinkCallback, LinkStep, Namespace, NamespaceBinding, NamespaceKind, RepoSpec,
    RepoState, Resource, Right, RoleAssignment, RoleMap, StepAction, StepOutcome, Unlisted,
    VgiConfig, async_trait, run_plan,
};

/// Forgejo-shaped: three role levels. Fails any step whose id is in `fail`.
struct FakeForge {
    fail: Vec<&'static str>,
    ran: Mutex<Vec<String>>,
}

#[async_trait]
impl Forge for FakeForge {
    fn kind(&self) -> ForgeKind {
        ForgeKind::Forgejo
    }
    fn host(&self) -> &str {
        "codeberg.org"
    }
    fn capabilities(&self, _ns: &Namespace) -> Capabilities {
        let mut c = Capabilities::default();
        c.role_levels = vec![ForgeRole::Read, ForgeRole::Write, ForgeRole::Admin];
        c
    }
    async fn begin_bind(&self, _req: BindRequest) -> vgi_forge::Result<BindStep> {
        unimplemented!()
    }
    async fn complete_bind(&self, _cb: BindCallback) -> vgi_forge::Result<NamespaceBinding> {
        unimplemented!()
    }
    async fn begin_account_link(&self, _member: &str) -> vgi_forge::Result<LinkStep> {
        unimplemented!()
    }
    async fn complete_account_link(&self, _cb: LinkCallback) -> vgi_forge::Result<ForgeAccount> {
        unimplemented!()
    }
    async fn inspect(&self, _repo: &Resource) -> vgi_forge::Result<RepoState> {
        unimplemented!()
    }
    async fn create_repo(&self, _spec: &RepoSpec) -> vgi_forge::Result<RepoState> {
        unimplemented!()
    }
    async fn archive_repo(&self, _repo: &Resource) -> vgi_forge::Result<()> {
        unimplemented!()
    }
    async fn apply_roles(
        &self,
        _repo: &Resource,
        _desired: &[RoleAssignment],
        _unlisted: Unlisted,
    ) -> vgi_forge::Result<ApplyReport> {
        unimplemented!()
    }
    fn bootstrap_plan(
        &self,
        _repo: &RepoSpec,
        _cfg: &VgiConfig,
    ) -> vgi_forge::Result<Vec<BootstrapStep>> {
        unimplemented!()
    }
    async fn run_step(
        &self,
        _repo: &Resource,
        step: &BootstrapStep,
    ) -> vgi_forge::Result<StepOutcome> {
        self.ran.lock().unwrap().push(step.id.clone());
        if self.fail.contains(&step.id.as_str()) {
            return Err(ForgeError::Unavailable("boom".into()));
        }
        Ok(StepOutcome::Created)
    }
    fn parse_event(
        &self,
        _headers: &HeaderMap,
        _body: &[u8],
    ) -> vgi_forge::Result<Option<ForgeEvent>> {
        Ok(None)
    }
}

fn fake(fail: Vec<&'static str>) -> Box<dyn Forge> {
    Box::new(FakeForge {
        fail,
        ran: Mutex::new(Vec::new()),
    })
}

fn step(id: &str) -> BootstrapStep {
    BootstrapStep::new(
        id,
        BootstrapComponent::Variables,
        StepAction::SetVariable {
            name: id.into(),
            value: "v".into(),
        },
    )
}

#[test]
fn default_normalize_refuses_other_forges() {
    let forge = fake(vec![]);
    assert_eq!(
        forge
            .normalize("Codeberg.org/Acme/Widgets")
            .unwrap()
            .as_str(),
        "codeberg.org/acme/widgets"
    );
    assert!(matches!(
        forge.normalize("github.com/acme/widgets"),
        Err(ForgeError::WrongResource { .. })
    ));
    assert!(matches!(
        forge.normalize("acme/widgets"),
        Err(ForgeError::InvalidResource(_))
    ));
}

#[test]
fn default_map_role_rounds_maintain_down_on_a_three_level_ladder() {
    let forge = fake(vec![]);
    let ns = Namespace::new(
        Resource::parse("codeberg.org/acme").unwrap(),
        NamespaceKind::Organization,
    );
    let rights = |r| EffectiveRights::from_granted([r]);
    let map = RoleMap::default();
    assert_eq!(
        forge.map_role(&ns, rights(Right::RepoOwn), &map),
        ForgeRole::Admin
    );
    assert_eq!(
        forge.map_role(&ns, rights(Right::RepoMaintain), &map),
        ForgeRole::Write
    );
    assert_eq!(
        forge.map_role(&ns, rights(Right::CommitSign), &map),
        ForgeRole::None
    );
}

#[tokio::test]
async fn run_plan_stops_at_the_first_failure() {
    let forge = fake(vec!["b"]);
    let repo = Resource::parse("codeberg.org/acme/w").unwrap();
    let report = run_plan(forge.as_ref(), &repo, &[step("a"), step("b"), step("c")]).await;
    assert!(!report.is_complete());
    assert_eq!(
        report.completed,
        vec![("a".to_string(), StepOutcome::Created)]
    );
    assert_eq!(report.failed.as_ref().map(|(id, _)| id.as_str()), Some("b"));
    assert_eq!(report.not_run, vec!["c".to_string()]);

    let ok = run_plan(fake(vec![]).as_ref(), &repo, &[step("a"), step("b")]).await;
    assert!(ok.is_complete());
    assert_eq!(ok.completed.len(), 2);
}
