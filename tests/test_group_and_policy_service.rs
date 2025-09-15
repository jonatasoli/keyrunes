use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use keyrunes::repository::{
    Group, GroupRepository, NewGroup, NewPolicy, Policy, PolicyEffect, PolicyRepository,
};
use keyrunes::services::group_service::{CreateGroupRequest, GroupService};
use keyrunes::services::policy_service::{CreatePolicyRequest, PolicyService};
use proptest::prelude::*;
use rstest::*;
use serde_json::json;
use std::sync::{Arc, Mutex};
use test_case::test_case;
use uuid::Uuid;

// ============= Mock Repositories =============

#[derive(Clone)]
struct MockGroupRepository {
    groups: Arc<Mutex<Vec<Group>>>,
    user_groups: Arc<Mutex<Vec<(i64, i64)>>>,
    group_policies: Arc<Mutex<Vec<(i64, i64)>>>,
    should_fail: Arc<Mutex<bool>>,
}

impl MockGroupRepository {
    fn new() -> Self {
        Self {
            groups: Arc::new(Mutex::new(Vec::new())),
            user_groups: Arc::new(Mutex::new(Vec::new())),
            group_policies: Arc::new(Mutex::new(Vec::new())),
            should_fail: Arc::new(Mutex::new(false)),
        }
    }

    fn set_should_fail(&self, fail: bool) {
        *self.should_fail.lock().unwrap() = fail;
    }

    fn add_test_group(&self, name: &str, description: Option<String>) -> Group {
        let group = Group {
            group_id: self.groups.lock().unwrap().len() as i64 + 1,
            external_id: Uuid::new_v4(),
            name: name.to_string(),
            description,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        self.groups.lock().unwrap().push(group.clone());
        group
    }
}

#[async_trait]
impl GroupRepository for MockGroupRepository {
    async fn find_by_name(&self, name: &str) -> Result<Option<Group>> {
        if *self.should_fail.lock().unwrap() {
            return Err(anyhow::anyhow!("Database error"));
        }
        Ok(self.groups.lock().unwrap().iter().find(|g| g.name == name).cloned())
    }

    async fn find_by_id(&self, group_id: i64) -> Result<Option<Group>> {
        if *self.should_fail.lock().unwrap() {
            return Err(anyhow::anyhow!("Database error"));
        }
        Ok(self.groups.lock().unwrap().iter().find(|g| g.group_id == group_id).cloned())
    }

    async fn insert_group(&self, new_group: NewGroup) -> Result<Group> {
        if *self.should_fail.lock().unwrap() {
            return Err(anyhow::anyhow!("Database error"));
        }
        let group = Group {
            group_id: self.groups.lock().unwrap().len() as i64 + 1,
            external_id: new_group.external_id,
            name: new_group.name,
            description: new_group.description,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        self.groups.lock().unwrap().push(group.clone());
        Ok(group)
    }

    async fn list_groups(&self) -> Result<Vec<Group>> {
        if *self.should_fail.lock().unwrap() {
            return Err(anyhow::anyhow!("Database error"));
        }
        Ok(self.groups.lock().unwrap().clone())
    }

    async fn assign_user_to_group(&self, user_id: i64, group_id: i64, _assigned_by: Option<i64>) -> Result<()> {
        if *self.should_fail.lock().unwrap() {
            return Err(anyhow::anyhow!("Database error"));
        }
        self.user_groups.lock().unwrap().push((user_id, group_id));
        Ok(())
    }

    async fn remove_user_from_group(&self, user_id: i64, group_id: i64) -> Result<()> {
        if *self.should_fail.lock().unwrap() {
            return Err(anyhow::anyhow!("Database error"));
        }
        self.user_groups.lock().unwrap().retain(|(u, g)| !(*u == user_id && *g == group_id));
        Ok(())
    }

    async fn get_group_policies(&self, group_id: i64) -> Result<Vec<Policy>> {
        if *self.should_fail.lock().unwrap() {
            return Err(anyhow::anyhow!("Database error"));
        }
        
        // Return mock policies for the group
        let policies: Vec<Policy> = self.group_policies
            .lock()
            .unwrap()
            .iter()
            .filter(|(g, _)| *g == group_id)
            .map(|(_, p)| Policy {
                policy_id: *p,
                external_id: Uuid::new_v4(),
                name: format!("policy_{}", p),
                description: None,
                resource: "resource:*".to_string(),
                action: "read".to_string(),
                effect: PolicyEffect::Allow,
                conditions: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            })
            .collect();
        Ok(policies)
    }
}

#[derive(Clone)]
struct MockPolicyRepository {
    policies: Arc<Mutex<Vec<Policy>>>,
    user_policies: Arc<Mutex<Vec<(i64, i64)>>>,
    group_policies: Arc<Mutex<Vec<(i64, i64)>>>,
    should_fail: Arc<Mutex<bool>>,
}

impl MockPolicyRepository {
    fn new() -> Self {
        Self {
            policies: Arc::new(Mutex::new(Vec::new())),
            user_policies: Arc::new(Mutex::new(Vec::new())),
            group_policies: Arc::new(Mutex::new(Vec::new())),
            should_fail: Arc::new(Mutex::new(false)),
        }
    }

    fn set_should_fail(&self, fail: bool) {
        *self.should_fail.lock().unwrap() = fail;
    }
}

#[async_trait]
impl PolicyRepository for MockPolicyRepository {
    async fn find_by_name(&self, name: &str) -> Result<Option<Policy>> {
        if *self.should_fail.lock().unwrap() {
            return Err(anyhow::anyhow!("Database error"));
        }
        Ok(self.policies.lock().unwrap().iter().find(|p| p.name == name).cloned())
    }

    async fn find_by_id(&self, policy_id: i64) -> Result<Option<Policy>> {
        if *self.should_fail.lock().unwrap() {
            return Err(anyhow::anyhow!("Database error"));
        }
        Ok(self.policies.lock().unwrap().iter().find(|p| p.policy_id == policy_id).cloned())
    }

    async fn insert_policy(&self, new_policy: NewPolicy) -> Result<Policy> {
        if *self.should_fail.lock().unwrap() {
            return Err(anyhow::anyhow!("Database error"));
        }
        let policy = Policy {
            policy_id: self.policies.lock().unwrap().len() as i64 + 1,
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
        self.policies.lock().unwrap().push(policy.clone());
        Ok(policy)
    }

    async fn list_policies(&self) -> Result<Vec<Policy>> {
        if *self.should_fail.lock().unwrap() {
            return Err(anyhow::anyhow!("Database error"));
        }
        Ok(self.policies.lock().unwrap().clone())
    }

    async fn assign_policy_to_user(&self, user_id: i64, policy_id: i64, _assigned_by: Option<i64>) -> Result<()> {
        if *self.should_fail.lock().unwrap() {
            return Err(anyhow::anyhow!("Database error"));
        }
        self.user_policies.lock().unwrap().push((user_id, policy_id));
        Ok(())
    }

    async fn assign_policy_to_group(&self, group_id: i64, policy_id: i64, _assigned_by: Option<i64>) -> Result<()> {
        if *self.should_fail.lock().unwrap() {
            return Err(anyhow::anyhow!("Database error"));
        }
        self.group_policies.lock().unwrap().push((group_id, policy_id));
        Ok(())
    }

    async fn remove_policy_from_user(&self, user_id: i64, policy_id: i64) -> Result<()> {
        if *self.should_fail.lock().unwrap() {
            return Err(anyhow::anyhow!("Database error"));
        }
        self.user_policies.lock().unwrap().retain(|(u, p)| !(*u == user_id && *p == policy_id));
        Ok(())
    }

    async fn remove_policy_from_group(&self, group_id: i64, policy_id: i64) -> Result<()> {
        if *self.should_fail.lock().unwrap() {
            return Err(anyhow::anyhow!("Database error"));
        }
        self.group_policies.lock().unwrap().retain(|(g, p)| !(*g == group_id && *p == policy_id));
        Ok(())
    }
}

// ============= Fixtures =============

#[fixture]
fn group_service() -> GroupService<MockGroupRepository> {
    let repo = Arc::new(MockGroupRepository::new());
    GroupService::new(repo)
}

#[fixture]
fn policy_service() -> PolicyService<MockPolicyRepository> {
    let repo = Arc::new(MockPolicyRepository::new());
    PolicyService::new(repo)
}

// ============= Group Service Tests =============

#[tokio::test]
async fn test_create_group_success() {
    let service = group_service();
    
    let req = CreateGroupRequest {
        name: "test_group".to_string(),
        description: Some("Test group description".to_string()),
    };
    
    let result = service.create_group(req).await;
    assert!(result.is_ok());
    
    let group = result.unwrap();
    assert_eq!(group.name, "test_group");
    assert_eq!(group.description, Some("Test group description".to_string()));
}

#[tokio::test]
async fn test_create_duplicate_group() {
    let service = group_service();
    
    let req = CreateGroupRequest {
        name: "duplicate_group".to_string(),
        description: None,
    };
    
    // First creation should succeed
    assert!(service.create_group(req.clone()).await.is_ok());
    
    // Second creation should fail
    let result = service.create_group(req).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "group name already exists");
}

#[tokio::test]
async fn test_get_group_by_name() {
    let service = group_service();
    
    let req = CreateGroupRequest {
        name: "find_by_name".to_string(),
        description: None,
    };
    
    service.create_group(req).await.unwrap();
    
    let result = service.get_group_by_name("find_by_name").await.unwrap();
    assert!(result.is_some());
    assert_eq!(result.unwrap().name, "find_by_name");
}

#[tokio::test]
async fn test_get_group_by_id() {
    let service = group_service();
    
    let req = CreateGroupRequest {
        name: "find_by_id".to_string(),
        description: None,
    };
    
    let group = service.create_group(req).await.unwrap();
    
    let result = service.get_group_by_id(group.group_id).await.unwrap();
    assert!(result.is_some());
    assert_eq!(result.unwrap().group_id, group.group_id);
}

#[tokio::test]
async fn test_list_groups() {
    let service = group_service();
    
    // Create multiple groups
    for i in 0..3 {
        let req = CreateGroupRequest {
            name: format!("group_{}", i),
            description: None,
        };
        service.create_group(req).await.unwrap();
    }
    
    let groups = service.list_groups().await.unwrap();
    assert!(groups.len() >= 3);
}

#[tokio::test]
async fn test_assign_user_to_group() {
    let service = group_service();
    
    let req = CreateGroupRequest {
        name: "assign_group".to_string(),
        description: None,
    };
    
    let group = service.create_group(req).await.unwrap();
    
    let result = service.assign_user_to_group(1, group.group_id, Some(2)).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_assign_user_to_nonexistent_group() {
    let service = group_service();
    
    let result = service.assign_user_to_group(1, 999, None).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "group not found");
}

#[tokio::test]
async fn test_remove_user_from_group() {
    let service = group_service();
    
    let req = CreateGroupRequest {
        name: "remove_group".to_string(),
        description: None,
    };
    
    let group = service.create_group(req).await.unwrap();
    
    // Assign and then remove
    service.assign_user_to_group(1, group.group_id, None).await.unwrap();
    let result = service.remove_user_from_group(1, group.group_id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_get_group_with_policies() {
    let repo = Arc::new(MockGroupRepository::new());
    let service = GroupService::new(repo.clone());
    
    // Create group
    let req = CreateGroupRequest {
        name: "group_with_policies".to_string(),
        description: None,
    };
    let group = service.create_group(req).await.unwrap();
    
    // Add some policies to the group
    repo.group_policies.lock().unwrap().push((group.group_id, 1));
    repo.group_policies.lock().unwrap().push((group.group_id, 2));
    
    let result = service.get_group_with_policies(group.group_id).await.unwrap();
    assert!(result.is_some());
    
    let group_response = result.unwrap();
    assert_eq!(group_response.policies.len(), 2);
}

// ============= Policy Service Tests =============

#[tokio::test]
async fn test_create_policy_success() {
    let service = policy_service();
    
    let req = CreatePolicyRequest {
        name: "test_policy".to_string(),
        description: Some("Test policy".to_string()),
        resource: "api:users".to_string(),
        action: "read".to_string(),
        effect: PolicyEffect::Allow,
        conditions: None,
    };
    
    let result = service.create_policy(req).await;
    assert!(result.is_ok());
    
    let policy = result.unwrap();
    assert_eq!(policy.name, "test_policy");
    assert_eq!(policy.resource, "api:users");
    assert_eq!(policy.action, "read");
    assert_eq!(policy.effect, PolicyEffect::Allow);
}

#[tokio::test]
async fn test_create_policy_empty_resource() {
    let service = policy_service();
    
    let req = CreatePolicyRequest {
        name: "invalid_policy".to_string(),
        description: None,
        resource: "".to_string(),
        action: "read".to_string(),
        effect: PolicyEffect::Allow,
        conditions: None,
    };
    
    let result = service.create_policy(req).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "resource cannot be empty");
}

#[tokio::test]
async fn test_create_policy_empty_action() {
    let service = policy_service();
    
    let req = CreatePolicyRequest {
        name: "invalid_policy".to_string(),
        description: None,
        resource: "api:users".to_string(),
        action: "".to_string(),
        effect: PolicyEffect::Allow,
        conditions: None,
    };
    
    let result = service.create_policy(req).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "action cannot be empty");
}

#[tokio::test]
async fn test_create_duplicate_policy() {
    let service = policy_service();
    
    let req = CreatePolicyRequest {
        name: "duplicate_policy".to_string(),
        description: None,
        resource: "api:*".to_string(),
        action: "*".to_string(),
        effect: PolicyEffect::Allow,
        conditions: None,
    };
    
    // First creation should succeed
    assert!(service.create_policy(req.clone()).await.is_ok());
    
    // Second creation should fail
    let result = service.create_policy(req).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "policy name already exists");
}

#[tokio::test]
async fn test_get_policy_by_name() {
    let service = policy_service();
    
    let req = CreatePolicyRequest {
        name: "find_policy".to_string(),
        description: None,
        resource: "doc:*".to_string(),
        action: "read".to_string(),
        effect: PolicyEffect::Allow,
        conditions: None,
    };
    
    service.create_policy(req).await.unwrap();
    
    let result = service.get_policy_by_name("find_policy").await.unwrap();
    assert!(result.is_some());
    assert_eq!(result.unwrap().name, "find_policy");
}

#[tokio::test]
async fn test_list_policies() {
    let service = policy_service();
    
    // Create multiple policies
    for i in 0..3 {
        let req = CreatePolicyRequest {
            name: format!("policy_{}", i),
            description: None,
            resource: format!("resource:{}", i),
            action: "read".to_string(),
            effect: PolicyEffect::Allow,
            conditions: None,
        };
        service.create_policy(req).await.unwrap();
    }
    
    let policies = service.list_policies().await.unwrap();
    assert!(policies.len() >= 3);
}

#[tokio::test]
async fn test_assign_policy_to_user() {
    let service = policy_service();
    
    let req = CreatePolicyRequest {
        name: "user_policy".to_string(),
        description: None,
        resource: "user:profile".to_string(),
        action: "update".to_string(),
        effect: PolicyEffect::Allow,
        conditions: None,
    };
    
    let policy = service.create_policy(req).await.unwrap();
    
    let result = service.assign_policy_to_user(1, policy.policy_id, Some(2)).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_assign_nonexistent_policy() {
    let service = policy_service();
    
    let result = service.assign_policy_to_user(1, 999, None).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "policy not found");
}

#[tokio::test]
async fn test_evaluate_permission() {
    let service = policy_service();
    
    let policies = vec![
        Policy {
            policy_id: 1,
            external_id: Uuid::new_v4(),
            name: "allow_read".to_string(),
            description: None,
            resource: "document:*".to_string(),
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
            resource: "document:sensitive".to_string(),
            action: "delete".to_string(),
            effect: PolicyEffect::Deny,
            conditions: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
    ];
    
    // Should allow reading documents
    assert!(service.evaluate_permission(&policies, "document:123", "read").await);
    assert!(service.evaluate_permission(&policies, "document:sensitive", "read").await);
    
    // Should deny deleting sensitive documents
    assert!(!service.evaluate_permission(&policies, "document:sensitive", "delete").await);
    
    // Should not allow actions not covered by policies
    assert!(!service.evaluate_permission(&policies, "document:123", "write").await);
}

#[tokio::test]
async fn test_wildcard_policy_matching() {
    let service = policy_service();
    
    let policies = vec![
        Policy {
            policy_id: 1,
            external_id: Uuid::new_v4(),
            name: "admin_all".to_string(),
            description: None,
            resource: "*".to_string(),
            action: "*".to_string(),
            effect: PolicyEffect::Allow,
            conditions: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
    ];
    
    // Wildcard should match everything
    assert!(service.evaluate_permission(&policies, "any:resource", "any_action").await);
    assert!(service.evaluate_permission(&policies, "user:123", "delete").await);
    assert!(service.evaluate_permission(&policies, "api:endpoint", "execute").await);
}

#[tokio::test]
async fn test_deny_precedence() {
    let service = policy_service();
    
    let policies = vec![
        Policy {
            policy_id: 1,
            external_id: Uuid::new_v4(),
            name: "allow_all".to_string(),
            description: None,
            resource: "*".to_string(),
            action: "*".to_string(),
            effect: PolicyEffect::Allow,
            conditions: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
        Policy {
            policy_id: 2,
            external_id: Uuid::new_v4(),
            name: "deny_specific".to_string(),
            description: None,
            resource: "sensitive:data".to_string(),
            action: "delete".to_string(),
            effect: PolicyEffect::Deny,
            conditions: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
    ];
    
    // Allow should work for most cases
    assert!(service.evaluate_permission(&policies, "normal:data", "delete").await);
    
    // But deny should take precedence for specific resource
    assert!(!service.evaluate_permission(&policies, "sensitive:data", "delete").await);
    
    // Other actions on sensitive data should still be allowed
    assert!(service.evaluate_permission(&policies, "sensitive:data", "read").await);
}

// ============= RSTest Parameterized Tests =============

#[rstest]
#[case("admin", Some("Administrators group"))]
#[case("users", Some("Regular users"))]
#[case("guests", None)]
#[tokio::test]
async fn test_create_various_groups(
    #[case] name: &str,
    #[case] description: Option<&str>,
) {
    let service = group_service();
    
    let req = CreateGroupRequest {
        name: format!("{}_{}", name, Uuid::new_v4()),
        description: description.map(String::from),
    };
    
    let result = service.create_group(req).await;
    assert!(result.is_ok());
}

#[rstest]
#[case("api:*", "read", PolicyEffect::Allow)]
#[case("document:sensitive", "delete", PolicyEffect::Deny)]
#[case("user:profile", "update", PolicyEffect::Allow)]
#[tokio::test]
async fn test_create_various_policies(
    #[case] resource: &str,
    #[case] action: &str,
    #[case] effect: PolicyEffect,
) {
    let service = policy_service();
    
    let req = CreatePolicyRequest {
        name: format!("policy_{}", Uuid::new_v4()),
        description: None,
        resource: resource.to_string(),
        action: action.to_string(),
        effect,
        conditions: None,
    };
    
    let result = service.create_policy(req).await;
    assert!(result.is_ok());
    
    let policy = result.unwrap();
    assert_eq!(policy.resource, resource);
    assert_eq!(policy.action, action);
    assert_eq!(policy.effect, effect);
}

// ============= Test Case Tests =============

#[test_case("resource:*", "action", "resource:123" => true ; "wildcard match")]
#[test_case("resource:specific", "action", "resource:specific" => true ; "exact match")]
#[test_case("resource:specific", "action", "resource:other" => false ; "no match")]
#[test_case("api:*", "read", "api:users" => true ; "api wildcard")]
fn test_resource_matching(policy_resource: &str, _action: &str, test_resource: &str) -> bool {
    if policy_resource == "*" || policy_resource == test_resource {
        return true;
    }
    
    if policy_resource.ends_with("*") {
        let prefix = &policy_resource[..policy_resource.len() - 1];
        test_resource.starts_with(prefix)
    } else {
        false
    }
}

// ============= Property Tests =============

proptest! {
    #[test]
    fn test_group_name_validation(
        name in "[a-zA-Z][a-zA-Z0-9_-]{0,99}"
    ) {
        // Group names should be valid
        assert!(!name.is_empty());
        assert!(name.len() <= 100);
    }
    
    #[test]
    fn test_policy_resource_format(
        resource_type in "(api|document|user|admin)",
        resource_id in "([a-z0-9_-]{1,20}|\\*)"
    ) {
        let resource = format!("{}:{}", resource_type, resource_id);
        
        // Resource should follow the pattern
        assert!(resource.contains(':'));
        
        let parts: Vec<&str> = resource.split(':').collect();
        assert_eq!(parts.len(), 2);
        assert!(!parts[0].is_empty());
        assert!(!parts[1].is_empty());
    }
    
    #[test]
    fn test_policy_conditions_json(
        key in "[a-z]{3,10}",
        value in "[a-z0-9]{3,20}"
    ) {
        let conditions = json!({
            key.clone(): value
        });
        
        // Should be valid JSON
        let serialized = conditions.to_string();
        let parsed: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        
        prop_assert_eq!(parsed[&key].clone(), value);
    }
}

// ============= Database Failure Tests =============

#[tokio::test]
async fn test_group_service_database_failure() {
    let repo = Arc::new(MockGroupRepository::new());
    repo.set_should_fail(true);
    let service = GroupService::new(repo);
    
    let req = CreateGroupRequest {
        name: "test".to_string(),
        description: None,
    };
    
    let result = service.create_group(req).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Database error"));
}

#[tokio::test]
async fn test_policy_service_database_failure() {
    let repo = Arc::new(MockPolicyRepository::new());
    repo.set_should_fail(true);
    let service = PolicyService::new(repo);
    
    let req = CreatePolicyRequest {
        name: "test".to_string(),
        description: None,
        resource: "test".to_string(),
        action: "test".to_string(),
        effect: PolicyEffect::Allow,
        conditions: None,
    };
    
    let result = service.create_policy(req).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Database error"));
}

// ============= Integration Tests =============

#[tokio::test]
async fn test_complete_rbac_flow() {
    let group_repo = Arc::new(MockGroupRepository::new());
    let policy_repo = Arc::new(MockPolicyRepository::new());
    let group_service = GroupService::new(group_repo.clone());
    let policy_service = PolicyService::new(policy_repo.clone());
    
    // 1. Create a group
    let group_req = CreateGroupRequest {
        name: "admins".to_string(),
        description: Some("Administrator group".to_string()),
    };
    let group = group_service.create_group(group_req).await.unwrap();
    
    // 2. Create policies
    let read_policy_req = CreatePolicyRequest {
        name: "admin_read".to_string(),
        description: None,
        resource: "*".to_string(),
        action: "read".to_string(),
        effect: PolicyEffect::Allow,
        conditions: None,
    };
    let read_policy = policy_service.create_policy(read_policy_req).await.unwrap();
    
    let write_policy_req = CreatePolicyRequest {
        name: "admin_write".to_string(),
        description: None,
        resource: "*".to_string(),
        action: "write".to_string(),
        effect: PolicyEffect::Allow,
        conditions: None,
    };
    let write_policy = policy_service.create_policy(write_policy_req).await.unwrap();
    
    // 3. Assign policies to group
    policy_service.assign_policy_to_group(group.group_id, read_policy.policy_id, None).await.unwrap();
    policy_service.assign_policy_to_group(group.group_id, write_policy.policy_id, None).await.unwrap();
    
    // 4. Assign user to group
    let user_id = 1;
    group_service.assign_user_to_group(user_id, group.group_id, None).await.unwrap();
    
    // 5. Get group with policies
    let group_with_policies = group_service.get_group_with_policies(group.group_id).await.unwrap().unwrap();
    assert_eq!(group_with_policies.policies.len(), 2);
    
    // 6. Evaluate permissions
    let policies = vec![read_policy, write_policy];
    assert!(policy_service.evaluate_permission(&policies, "any:resource", "read").await);
    assert!(policy_service.evaluate_permission(&policies, "any:resource", "write").await);
    assert!(!policy_service.evaluate_permission(&policies, "any:resource", "delete").await);
}
