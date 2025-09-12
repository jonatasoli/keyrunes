use crate::repository::{NewPolicy, Policy, PolicyEffect, PolicyRepository};
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
pub struct CreatePolicyRequest {
    pub name: String,
    pub description: Option<String>,
    pub resource: String,
    pub action: String,
    pub effect: PolicyEffect,
    pub conditions: Option<JsonValue>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyResponse {
    pub policy_id: i64,
    pub external_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub resource: String,
    pub action: String,
    pub effect: PolicyEffect,
    pub conditions: Option<JsonValue>,
}

impl From<Policy> for PolicyResponse {
    fn from(policy: Policy) -> Self {
        Self {
            policy_id: policy.policy_id,
            external_id: policy.external_id,
            name: policy.name,
            description: policy.description,
            resource: policy.resource,
            action: policy.action,
            effect: policy.effect,
            conditions: policy.conditions,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PolicyService<P: PolicyRepository> {
    pub repo: Arc<P>,
}

impl<P: PolicyRepository> PolicyService<P> {
    pub fn new(repo: Arc<P>) -> Self {
        Self { repo }
    }

    pub async fn create_policy(&self, req: CreatePolicyRequest) -> Result<Policy> {
        // Check if policy already exists
        if self.repo.find_by_name(&req.name).await?.is_some() {
            return Err(anyhow!("policy name already exists"));
        }

        // Validate resource and action
        if req.resource.is_empty() {
            return Err(anyhow!("resource cannot be empty"));
        }
        if req.action.is_empty() {
            return Err(anyhow!("action cannot be empty"));
        }

        let new_policy = NewPolicy {
            external_id: Uuid::new_v4(),
            name: req.name,
            description: req.description,
            resource: req.resource,
            action: req.action,
            effect: req.effect,
            conditions: req.conditions,
        };

        self.repo.insert_policy(new_policy).await
    }

    pub async fn get_policy_by_name(&self, name: &str) -> Result<Option<Policy>> {
        self.repo.find_by_name(name).await
    }

    pub async fn get_policy_by_id(&self, policy_id: i64) -> Result<Option<Policy>> {
        self.repo.find_by_id(policy_id).await
    }

    pub async fn list_policies(&self) -> Result<Vec<Policy>> {
        self.repo.list_policies().await
    }

    pub async fn assign_policy_to_user(
        &self,
        user_id: i64,
        policy_id: i64,
        assigned_by: Option<i64>,
    ) -> Result<()> {
        // Verify policy exists
        if self.repo.find_by_id(policy_id).await?.is_none() {
            return Err(anyhow!("policy not found"));
        }

        self.repo
            .assign_policy_to_user(user_id, policy_id, assigned_by)
            .await
    }

    pub async fn assign_policy_to_group(
        &self,
        group_id: i64,
        policy_id: i64,
        assigned_by: Option<i64>,
    ) -> Result<()> {
        // Verify policy exists
        if self.repo.find_by_id(policy_id).await?.is_none() {
            return Err(anyhow!("policy not found"));
        }

        self.repo
            .assign_policy_to_group(group_id, policy_id, assigned_by)
            .await
    }

    pub async fn remove_policy_from_user(&self, user_id: i64, policy_id: i64) -> Result<()> {
        self.repo.remove_policy_from_user(user_id, policy_id).await
    }

    pub async fn remove_policy_from_group(&self, group_id: i64, policy_id: i64) -> Result<()> {
        self.repo
            .remove_policy_from_group(group_id, policy_id)
            .await
    }

    /// Evaluate if a user has permission for a specific resource and action
    pub async fn evaluate_permission(
        &self,
        user_policies: &[Policy],
        resource: &str,
        action: &str,
    ) -> bool {
        let mut allow = false;
        let mut deny = false;

        for policy in user_policies {
            if self.matches_policy(policy, resource, action) {
                match policy.effect {
                    PolicyEffect::Allow => allow = true,
                    PolicyEffect::Deny => deny = true,
                }
            }
        }

        // Deny takes precedence over allow
        allow && !deny
    }

    fn matches_policy(&self, policy: &Policy, resource: &str, action: &str) -> bool {
        let resource_match = policy.resource == "*" || policy.resource == resource || {
            // Check for wildcard patterns like "user:*"
            if policy.resource.ends_with("*") {
                let prefix = &policy.resource[..policy.resource.len() - 1];
                resource.starts_with(prefix)
            } else {
                false
            }
        };

        let action_match = policy.action == "*" || policy.action == action;

        resource_match && action_match
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::{Policy, PolicyEffect};
    use anyhow::Result;
    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    struct MockPolicyRepository {
        policies: Mutex<Vec<Policy>>,
        user_policies: Mutex<Vec<(i64, i64)>>, // (user_id, policy_id)
        group_policies: Mutex<Vec<(i64, i64)>>, // (group_id, policy_id)
    }

    impl MockPolicyRepository {
        fn new() -> Self {
            Self {
                policies: Mutex::new(Vec::new()),
                user_policies: Mutex::new(Vec::new()),
                group_policies: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl PolicyRepository for MockPolicyRepository {
        async fn find_by_name(&self, name: &str) -> Result<Option<Policy>> {
            let policies = self.policies.lock().unwrap();
            Ok(policies.iter().find(|p| p.name == name).cloned())
        }

        async fn find_by_id(&self, policy_id: i64) -> Result<Option<Policy>> {
            let policies = self.policies.lock().unwrap();
            Ok(policies.iter().find(|p| p.policy_id == policy_id).cloned())
        }

        async fn insert_policy(&self, new_policy: NewPolicy) -> Result<Policy> {
            let mut policies = self.policies.lock().unwrap();
            let policy = Policy {
                policy_id: (policies.len() + 1) as i64,
                external_id: new_policy.external_id,
                name: new_policy.name,
                description: new_policy.description,
                resource: new_policy.resource,
                action: new_policy.action,
                effect: new_policy.effect,
                conditions: new_policy.conditions,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };
            policies.push(policy.clone());
            Ok(policy)
        }

        async fn list_policies(&self) -> Result<Vec<Policy>> {
            let policies = self.policies.lock().unwrap();
            Ok(policies.clone())
        }

        async fn assign_policy_to_user(
            &self,
            user_id: i64,
            policy_id: i64,
            _assigned_by: Option<i64>,
        ) -> Result<()> {
            let mut user_policies = self.user_policies.lock().unwrap();
            user_policies.push((user_id, policy_id));
            Ok(())
        }

        async fn assign_policy_to_group(
            &self,
            group_id: i64,
            policy_id: i64,
            _assigned_by: Option<i64>,
        ) -> Result<()> {
            let mut group_policies = self.group_policies.lock().unwrap();
            group_policies.push((group_id, policy_id));
            Ok(())
        }

        async fn remove_policy_from_user(&self, user_id: i64, policy_id: i64) -> Result<()> {
            let mut user_policies = self.user_policies.lock().unwrap();
            user_policies.retain(|(uid, pid)| !(*uid == user_id && *pid == policy_id));
            Ok(())
        }

        async fn remove_policy_from_group(&self, group_id: i64, policy_id: i64) -> Result<()> {
            let mut group_policies = self.group_policies.lock().unwrap();
            group_policies.retain(|(gid, pid)| !(*gid == group_id && *pid == policy_id));
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_create_policy() {
        let repo = Arc::new(MockPolicyRepository::new());
        let service = PolicyService::new(repo);

        let req = CreatePolicyRequest {
            name: "test_policy".to_string(),
            description: Some("Test policy".to_string()),
            resource: "user:*".to_string(),
            action: "read".to_string(),
            effect: PolicyEffect::Allow,
            conditions: None,
        };

        let policy = service.create_policy(req).await.unwrap();
        assert_eq!(policy.name, "test_policy");
        assert_eq!(policy.resource, "user:*");
        assert_eq!(policy.action, "read");
        assert_eq!(policy.effect, PolicyEffect::Allow);
    }

    #[tokio::test]
    async fn test_evaluate_permission() {
        let repo = Arc::new(MockPolicyRepository::new());
        let service = PolicyService::new(repo);

        let policies = vec![
            Policy {
                policy_id: 1,
                external_id: Uuid::new_v4(),
                name: "allow_read".to_string(),
                description: None,
                resource: "user:*".to_string(),
                action: "read".to_string(),
                effect: PolicyEffect::Allow,
                conditions: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            Policy {
                policy_id: 2,
                external_id: Uuid::new_v4(),
                name: "deny_delete".to_string(),
                description: None,
                resource: "*".to_string(),
                action: "delete".to_string(),
                effect: PolicyEffect::Deny,
                conditions: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        ];

        // Should allow read on user resource
        assert!(
            service
                .evaluate_permission(&policies, "user:123", "read")
                .await
        );

        // Should deny delete on any resource
        assert!(
            !service
                .evaluate_permission(&policies, "user:123", "delete")
                .await
        );

        // Should not allow write (no matching policy)
        assert!(
            !service
                .evaluate_permission(&policies, "user:123", "write")
                .await
        );
    }

    #[tokio::test]
    async fn test_wildcard_matching() {
        let repo = Arc::new(MockPolicyRepository::new());
        let service = PolicyService::new(repo);

        let policy = Policy {
            policy_id: 1,
            external_id: Uuid::new_v4(),
            name: "wildcard_policy".to_string(),
            description: None,
            resource: "api:*".to_string(),
            action: "*".to_string(),
            effect: PolicyEffect::Allow,
            conditions: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Should match resource with wildcard
        assert!(service.matches_policy(&policy, "api:users", "read"));
        assert!(service.matches_policy(&policy, "api:admin", "write"));

        // Should not match different resource
        assert!(!service.matches_policy(&policy, "database:users", "read"));
    }
}
