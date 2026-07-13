#![allow(
    dead_code,
    reason = "V2 HTTP handlers will consume the authorization evaluator incrementally"
)]

use std::collections::{BTreeMap, BTreeSet};

type Identifier = [u8; 16];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Action {
    DirectoryList,
    ContentRead,
    ContentWrite,
    EntryDelete,
    SnapshotPublish,
    AclManage,
    TokenIssue,
    DriverUse,
    DriverManage,
    GcRun,
    AuditRead,
    SystemManage,
}

impl Action {
    const fn name(self) -> &'static str {
        match self {
            Self::DirectoryList => "directory.list",
            Self::ContentRead => "content.read",
            Self::ContentWrite => "content.write",
            Self::EntryDelete => "entry.delete",
            Self::SnapshotPublish => "snapshot.publish",
            Self::AclManage => "acl.manage",
            Self::TokenIssue => "token.issue",
            Self::DriverUse => "driver.use",
            Self::DriverManage => "driver.manage",
            Self::GcRun => "gc.run",
            Self::AuditRead => "audit.read",
            Self::SystemManage => "system.manage",
        }
    }

    const fn requires_driver(self) -> bool {
        matches!(self, Self::DriverUse)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RolePreset {
    Viewer,
    Editor,
    Publisher,
    SecurityAdministrator,
    StorageOperator,
    Janitor,
    SystemAdministrator,
}

impl RolePreset {
    const fn actions(self) -> &'static [Action] {
        match self {
            Self::Viewer => &[Action::DirectoryList, Action::ContentRead],
            Self::Editor => &[
                Action::DirectoryList,
                Action::ContentRead,
                Action::ContentWrite,
                Action::EntryDelete,
            ],
            Self::Publisher => &[
                Action::DirectoryList,
                Action::ContentRead,
                Action::ContentWrite,
                Action::EntryDelete,
                Action::SnapshotPublish,
            ],
            Self::SecurityAdministrator => &[
                Action::DirectoryList,
                Action::AclManage,
                Action::TokenIssue,
                Action::AuditRead,
            ],
            Self::StorageOperator => &[Action::DriverUse, Action::DriverManage, Action::AuditRead],
            Self::Janitor => &[Action::DriverUse, Action::GcRun, Action::AuditRead],
            Self::SystemAdministrator => &[
                Action::AclManage,
                Action::TokenIssue,
                Action::DriverManage,
                Action::GcRun,
                Action::AuditRead,
                Action::SystemManage,
            ],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Subject {
    Principal(Identifier),
    Group(Identifier),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Directory {
    id: Identifier,
    parent_id: Option<Identifier>,
    acl_inherits: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Grant {
    directory_id: Identifier,
    subject: Subject,
    action: Action,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TokenScope {
    principal_id: Identifier,
    root_directory_id: Identifier,
    actions: BTreeSet<Action>,
    driver_ids: Option<BTreeSet<Identifier>>,
    snapshot_id: Option<Identifier>,
    expires_at: u64,
    revoked: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthorizationRequest {
    target_directory_id: Identifier,
    action: Action,
    driver_id: Option<Identifier>,
    snapshot_id: Option<Identifier>,
    now: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Denial {
    PrincipalInactive,
    TokenInactive,
    TokenAction,
    TokenDirectory,
    TokenDriver,
    TokenSnapshot,
    DirectoryGraph,
    Acl,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Decision {
    Allowed,
    Denied(Denial),
}

#[derive(Default)]
struct AuthorizationGraph {
    active_principals: BTreeSet<Identifier>,
    directories: BTreeMap<Identifier, Directory>,
    group_members: BTreeMap<Identifier, BTreeSet<Identifier>>,
    grants: Vec<Grant>,
}

impl AuthorizationGraph {
    fn authorize(
        &self,
        principal_id: Identifier,
        token: &TokenScope,
        request: &AuthorizationRequest,
    ) -> Decision {
        if !self.active_principals.contains(&principal_id) {
            return Decision::Denied(Denial::PrincipalInactive);
        }

        if token.principal_id != principal_id || token.revoked || token.expires_at <= request.now {
            return Decision::Denied(Denial::TokenInactive);
        }

        if !token.actions.contains(&request.action) {
            return Decision::Denied(Denial::TokenAction);
        }

        if !self.in_subtree(token.root_directory_id, request.target_directory_id) {
            return Decision::Denied(Denial::TokenDirectory);
        }

        if !driver_scope_allows(token, request) {
            return Decision::Denied(Denial::TokenDriver);
        }

        if token.snapshot_id.is_some() && token.snapshot_id != request.snapshot_id {
            return Decision::Denied(Denial::TokenSnapshot);
        }

        match self.acl_allows(principal_id, request.target_directory_id, request.action) {
            Ok(true) => Decision::Allowed,
            Ok(false) => Decision::Denied(Denial::Acl),
            Err(()) => Decision::Denied(Denial::DirectoryGraph),
        }
    }

    fn in_subtree(&self, root_id: Identifier, target_id: Identifier) -> bool {
        let mut current = Some(target_id);
        let mut visited = BTreeSet::new();

        while let Some(directory_id) = current {
            if !visited.insert(directory_id) {
                return false;
            }
            if directory_id == root_id {
                return true;
            }

            let Some(directory) = self.directories.get(&directory_id) else {
                return false;
            };
            current = directory.parent_id;
        }

        false
    }

    fn acl_allows(
        &self,
        principal_id: Identifier,
        target_id: Identifier,
        action: Action,
    ) -> Result<bool, ()> {
        let groups = self.groups_for(principal_id);
        let mut current = Some(target_id);
        let mut visited = BTreeSet::new();

        while let Some(directory_id) = current {
            if !visited.insert(directory_id) {
                return Err(());
            }

            let directory = self.directories.get(&directory_id).ok_or(())?;
            if self.grants.iter().any(|grant| {
                grant.directory_id == directory_id
                    && grant.action == action
                    && subject_matches(grant.subject, principal_id, &groups)
            }) {
                return Ok(true);
            }

            if !directory.acl_inherits {
                return Ok(false);
            }
            current = directory.parent_id;
        }

        Ok(false)
    }

    fn groups_for(&self, principal_id: Identifier) -> BTreeSet<Identifier> {
        self.group_members
            .iter()
            .filter_map(|(group_id, members)| members.contains(&principal_id).then_some(*group_id))
            .collect()
    }
}

fn driver_scope_allows(token: &TokenScope, request: &AuthorizationRequest) -> bool {
    if request.action.requires_driver() && request.driver_id.is_none() {
        return false;
    }

    match (&token.driver_ids, request.driver_id) {
        (Some(allowed), Some(driver_id)) => allowed.contains(&driver_id),
        (Some(_), None) | (None, _) => true,
    }
}

fn subject_matches(
    subject: Subject,
    principal_id: Identifier,
    groups: &BTreeSet<Identifier>,
) -> bool {
    match subject {
        Subject::Principal(candidate) => candidate == principal_id,
        Subject::Group(candidate) => groups.contains(&candidate),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inherited_group_grant_and_token_attenuation_are_both_required() {
        let principal = identifier(1);
        let group = identifier(2);
        let root = identifier(10);
        let child = identifier(11);
        let graph = AuthorizationGraph {
            active_principals: BTreeSet::from([principal]),
            directories: BTreeMap::from([
                (
                    root,
                    Directory {
                        id: root,
                        parent_id: None,
                        acl_inherits: false,
                    },
                ),
                (
                    child,
                    Directory {
                        id: child,
                        parent_id: Some(root),
                        acl_inherits: true,
                    },
                ),
            ]),
            group_members: BTreeMap::from([(group, BTreeSet::from([principal]))]),
            grants: vec![Grant {
                directory_id: root,
                subject: Subject::Group(group),
                action: Action::ContentRead,
            }],
        };
        let mut token = token(principal, root, [Action::ContentRead]);
        let request = request(child, Action::ContentRead);

        assert_eq!(
            graph.authorize(principal, &token, &request),
            Decision::Allowed
        );

        token.actions.clear();
        assert_eq!(
            graph.authorize(principal, &token, &request),
            Decision::Denied(Denial::TokenAction)
        );
    }

    #[test]
    fn inheritance_break_makes_a_real_subtree_boundary() {
        let principal = identifier(1);
        let root = identifier(10);
        let boundary = identifier(11);
        let graph = AuthorizationGraph {
            active_principals: BTreeSet::from([principal]),
            directories: BTreeMap::from([
                (
                    root,
                    Directory {
                        id: root,
                        parent_id: None,
                        acl_inherits: false,
                    },
                ),
                (
                    boundary,
                    Directory {
                        id: boundary,
                        parent_id: Some(root),
                        acl_inherits: false,
                    },
                ),
            ]),
            grants: vec![Grant {
                directory_id: root,
                subject: Subject::Principal(principal),
                action: Action::ContentRead,
            }],
            ..AuthorizationGraph::default()
        };

        assert_eq!(
            graph.authorize(
                principal,
                &token(principal, root, [Action::ContentRead]),
                &request(boundary, Action::ContentRead),
            ),
            Decision::Denied(Denial::Acl)
        );
    }

    #[test]
    fn directory_driver_snapshot_expiry_and_revocation_scopes_fail_closed() {
        let principal = identifier(1);
        let root = identifier(10);
        let child = identifier(11);
        let outside = identifier(12);
        let allowed_driver = identifier(20);
        let other_driver = identifier(21);
        let snapshot = identifier(30);
        let graph = graph_with_direct_grant(principal, root, child, Action::DriverUse);
        let mut scope = token(principal, child, [Action::DriverUse]);
        scope.driver_ids = Some(BTreeSet::from([allowed_driver]));
        scope.snapshot_id = Some(snapshot);

        let allowed = AuthorizationRequest {
            target_directory_id: child,
            action: Action::DriverUse,
            driver_id: Some(allowed_driver),
            snapshot_id: Some(snapshot),
            now: 1,
        };
        assert_eq!(
            graph.authorize(principal, &scope, &allowed),
            Decision::Allowed
        );

        let mut denied = allowed.clone();
        denied.target_directory_id = outside;
        assert_eq!(
            graph.authorize(principal, &scope, &denied),
            Decision::Denied(Denial::TokenDirectory)
        );

        denied = allowed.clone();
        denied.driver_id = Some(other_driver);
        assert_eq!(
            graph.authorize(principal, &scope, &denied),
            Decision::Denied(Denial::TokenDriver)
        );

        denied = allowed.clone();
        denied.snapshot_id = None;
        assert_eq!(
            graph.authorize(principal, &scope, &denied),
            Decision::Denied(Denial::TokenSnapshot)
        );

        denied = allowed.clone();
        denied.now = scope.expires_at;
        assert_eq!(
            graph.authorize(principal, &scope, &denied),
            Decision::Denied(Denial::TokenInactive)
        );

        scope.revoked = true;
        assert_eq!(
            graph.authorize(principal, &scope, &allowed),
            Decision::Denied(Denial::TokenInactive)
        );
    }

    #[test]
    fn malformed_directory_cycle_and_revoked_acl_fail_closed() {
        let principal = identifier(1);
        let first = identifier(10);
        let second = identifier(11);
        let mut graph = AuthorizationGraph {
            active_principals: BTreeSet::from([principal]),
            directories: BTreeMap::from([
                (
                    first,
                    Directory {
                        id: first,
                        parent_id: Some(second),
                        acl_inherits: true,
                    },
                ),
                (
                    second,
                    Directory {
                        id: second,
                        parent_id: Some(first),
                        acl_inherits: true,
                    },
                ),
            ]),
            ..AuthorizationGraph::default()
        };
        let scope = token(principal, first, [Action::ContentRead]);

        assert_eq!(
            graph.authorize(principal, &scope, &request(first, Action::ContentRead)),
            Decision::Denied(Denial::DirectoryGraph)
        );

        graph
            .directories
            .get_mut(&first)
            .expect("first directory")
            .parent_id = None;
        assert_eq!(
            graph.authorize(principal, &scope, &request(first, Action::ContentRead)),
            Decision::Denied(Denial::Acl)
        );
    }

    #[test]
    fn administrative_presets_never_hide_content_read() {
        for preset in [
            RolePreset::SecurityAdministrator,
            RolePreset::StorageOperator,
            RolePreset::Janitor,
            RolePreset::SystemAdministrator,
        ] {
            assert!(!preset.actions().contains(&Action::ContentRead));
        }

        assert_eq!(Action::SystemManage.name(), "system.manage");
        assert!(RolePreset::Viewer.actions().contains(&Action::ContentRead));
        assert!(RolePreset::Editor.actions().contains(&Action::ContentWrite));
        assert!(
            RolePreset::Publisher
                .actions()
                .contains(&Action::SnapshotPublish)
        );
    }

    fn graph_with_direct_grant(
        principal: Identifier,
        root: Identifier,
        child: Identifier,
        action: Action,
    ) -> AuthorizationGraph {
        AuthorizationGraph {
            active_principals: BTreeSet::from([principal]),
            directories: BTreeMap::from([
                (
                    root,
                    Directory {
                        id: root,
                        parent_id: None,
                        acl_inherits: false,
                    },
                ),
                (
                    child,
                    Directory {
                        id: child,
                        parent_id: Some(root),
                        acl_inherits: true,
                    },
                ),
            ]),
            grants: vec![Grant {
                directory_id: child,
                subject: Subject::Principal(principal),
                action,
            }],
            ..AuthorizationGraph::default()
        }
    }

    fn token(
        principal_id: Identifier,
        root_directory_id: Identifier,
        actions: impl IntoIterator<Item = Action>,
    ) -> TokenScope {
        TokenScope {
            principal_id,
            root_directory_id,
            actions: actions.into_iter().collect(),
            driver_ids: None,
            snapshot_id: None,
            expires_at: 100,
            revoked: false,
        }
    }

    fn request(target_directory_id: Identifier, action: Action) -> AuthorizationRequest {
        AuthorizationRequest {
            target_directory_id,
            action,
            driver_id: None,
            snapshot_id: None,
            now: 1,
        }
    }

    fn identifier(last: u8) -> Identifier {
        let mut identifier = [0; 16];
        identifier[15] = last;
        identifier
    }
}
