use crate::repository::{Group, GroupRepository, NewGroup};
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GroupResponse {
    pub group_id: i64,
    pub external_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub policies: Vec<PolicyResponse>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyResponse {
    pub policy_id: i64,
    pub external_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub resource: String,
    pub action: String,
    pub effect: String,
}

#[derive(Debug, Clone)]
pub struct GroupService<G: GroupRepository> {
    pub repo: Arc<G>,
}

impl<G: GroupRepository> GroupService<G> {
    pub fn new(repo: Arc<G>) -> Self {
        Self { repo }
    }

    pub async fn create_group(&self, req: CreateGroupRequest) -> Result<Group> {
        // Check if group already exists
        if self.repo.find_by_name(&req.name).await?.is_some() {
            return Err(anyhow!("group name already exists"));
        }

        let new_group = NewGroup {
            external_id: Uuid::new_v4(),
            name: req.name,
            description: req.description,
        };

        self.repo.insert_group(new_group).await
    }

    pub async fn get_group_by_name(&self, name: &str) -> Result<Option<Group>> {
        self.repo.find_by_name(name).await
    }

    pub async fn get_group_by_id(&self, group_id: i64) -> Result<Option<Group>> {
        self.repo.find_by_id(group_id).await
    }

    pub async fn list_groups(&self) -> Result<Vec<Group>> {
        self.repo.list_groups().await
    }

    pub async fn get_group_with_policies(&self, group_id: i64) -> Result<Option<GroupResponse>> {
        let group = self.repo.find_by_id(group_id).await?;

        if let Some(group) = group {
            let policies = self.repo.get_group_policies(group_id).await?;
            let policy_responses: Vec<PolicyResponse> = policies
                .into_iter()
                .map(|p| PolicyResponse {
                    policy_id: p.policy_id,
                    external_id: p.external_id,
                    name: p.name,
                    description: p.description,
                    resource: p.resource,
                    action: p.action,
                    effect: p.effect.to_string(),
                })
                .collect();

            Ok(Some(GroupResponse {
                group_id: group.group_id,
                external_id: group.external_id,
                name: group.name,
                description: group.description,
                policies: policy_responses,
            }))
        } else {
            Ok(None)
        }
    }

    pub async fn assign_user_to_group(
        &self,
        user_id: i64,
        group_id: i64,
        assigned_by: Option<i64>,
    ) -> Result<()> {
        // Verify group exists
        if self.repo.find_by_id(group_id).await?.is_none() {
            return Err(anyhow!("group not found"));
        }

        self.repo
            .assign_user_to_group(user_id, group_id, assigned_by)
            .await
    }

    pub async fn remove_user_from_group(&self, user_id: i64, group_id: i64) -> Result<()> {
        self.repo.remove_user_from_group(user_id, group_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::{Group, Policy, PolicyEffect};
    use anyhow::Result;
    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    struct MockGroupRepository {
        groups: Mutex<Vec<Group>>,
        user_groups: Mutex<Vec<(i64, i64)>>, // (user_id, group_id)
    }

    impl MockGroupRepository {
        fn new() -> Self {
            Self {
                groups: Mutex::new(Vec::new()),
                user_groups: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl GroupRepository for MockGroupRepository {
        async fn find_by_name(&self, name: &str) -> Result<Option<Group>> {
            let groups = self.groups.lock().unwrap();
            Ok(groups.iter().find(|g| g.name == name).cloned())
        }

        async fn find_by_id(&self, group_id: i64) -> Result<Option<Group>> {
            let groups = self.groups.lock().unwrap();
            Ok(groups.iter().find(|g| g.group_id == group_id).cloned())
        }

        async fn insert_group(&self, new_group: NewGroup) -> Result<Group> {
            let mut groups = self.groups.lock().unwrap();
            let group = Group {
                group_id: (groups.len() + 1) as i64,
                external_id: new_group.external_id,
                name: new_group.name,
                description: new_group.description,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };
            groups.push(group.clone());
            Ok(group)
        }

        async fn list_groups(&self) -> Result<Vec<Group>> {
            let groups = self.groups.lock().unwrap();
            Ok(groups.clone())
        }

        async fn assign_user_to_group(
            &self,
            user_id: i64,
            group_id: i64,
            _assigned_by: Option<i64>,
        ) -> Result<()> {
            let mut user_groups = self.user_groups.lock().unwrap();
            user_groups.push((user_id, group_id));
            Ok(())
        }

        async fn remove_user_from_group(&self, user_id: i64, group_id: i64) -> Result<()> {
            let mut user_groups = self.user_groups.lock().unwrap();
            user_groups.retain(|(uid, gid)| !(*uid == user_id && *gid == group_id));
            Ok(())
        }

        async fn get_group_policies(&self, _group_id: i64) -> Result<Vec<Policy>> {
            Ok(Vec::new())
        }
    }

    #[tokio::test]
    async fn test_create_group() {
        let repo = Arc::new(MockGroupRepository::new());
        let service = GroupService::new(repo);

        let req = CreateGroupRequest {
            name: "test_group".to_string(),
            description: Some("Test group description".to_string()),
        };

        let group = service.create_group(req).await.unwrap();
        assert_eq!(group.name, "test_group");
        assert_eq!(
            group.description,
            Some("Test group description".to_string())
        );
    }

    #[tokio::test]
    async fn test_create_duplicate_group() {
        let repo = Arc::new(MockGroupRepository::new());
        let service = GroupService::new(repo);

        let req = CreateGroupRequest {
            name: "duplicate_group".to_string(),
            description: None,
        };

        // Create first group
        service.create_group(req.clone()).await.unwrap();

        // Try to create duplicate
        let result = service.create_group(req).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "group name already exists");
    }
}
