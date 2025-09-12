use axum::{
    extract::{Extension, Path},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Serialize;
use std::sync::Arc;

use crate::repository::sqlx_impl::{
    PgGroupRepository, PgPasswordResetRepository, PgPolicyRepository, PgUserRepository,
};
use crate::services::{
    group_service::{CreateGroupRequest, GroupService},
    policy_service::{CreatePolicyRequest, PolicyService},
    user_service::UserService,
};

use crate::handler::auth::AuthenticatedUser;
type UserServiceType = UserService<PgUserRepository, PgGroupRepository, PgPasswordResetRepository>;
type GroupServiceType = GroupService<PgGroupRepository>;
type PolicyServiceType = PolicyService<PgPolicyRepository>;

#[derive(Serialize)]
pub struct AdminDashboard {
    pub total_users: i64,
    pub total_groups: i64,
    pub total_policies: i64,
    pub current_admin: AdminInfo,
}

#[derive(Serialize)]
pub struct AdminInfo {
    pub user_id: i64,
    pub username: String,
    pub email: String,
    pub groups: Vec<String>,
}

// GET /api/admin/dashboard
pub async fn admin_dashboard(
    Extension(user): Extension<AuthenticatedUser>,
    Extension(pool): Extension<sqlx::PgPool>,
) -> impl IntoResponse {
    // Check if user is superadmin
    if !user.groups.contains(&"superadmin".to_string()) {
        return (StatusCode::FORBIDDEN, "Superadmin access required").into_response();
    }

    // Get statistics
    let user_count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM users")
        .fetch_one(&pool)
        .await
        .unwrap_or(None)
        .unwrap_or(0);

    let group_count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM groups")
        .fetch_one(&pool)
        .await
        .unwrap_or(None)
        .unwrap_or(0);

    let policy_count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM policies")
        .fetch_one(&pool)
        .await
        .unwrap_or(None)
        .unwrap_or(0);

    let dashboard = AdminDashboard {
        total_users: user_count,
        total_groups: group_count,
        total_policies: policy_count,
        current_admin: AdminInfo {
            user_id: user.user_id,
            username: user.username,
            email: user.email,
            groups: user.groups,
        },
    };

    (StatusCode::OK, Json(dashboard)).into_response()
}

// GET /api/admin/users
pub async fn list_users(
    Extension(user): Extension<AuthenticatedUser>,
    Extension(pool): Extension<sqlx::PgPool>,
) -> impl IntoResponse {
    // Check if user is superadmin
    if !user.groups.contains(&"superadmin".to_string()) {
        return (StatusCode::FORBIDDEN, "Superadmin access required").into_response();
    }

    let users = sqlx::query!(
        r#"
        SELECT u.user_id, u.external_id, u.email, u.username, u.first_login, u.created_at,
               array_agg(g.name) as groups
        FROM users u
        LEFT JOIN user_groups ug ON u.user_id = ug.user_id
        LEFT JOIN groups g ON ug.group_id = g.group_id
        GROUP BY u.user_id
        ORDER BY u.created_at DESC
        "#
    )
    .fetch_all(&pool)
    .await
    .unwrap_or_else(|_| Vec::new());

    let user_list: Vec<serde_json::Value> = users
        .into_iter()
        .map(|u| {
            serde_json::json!({
                "user_id": u.user_id,
                "external_id": u.external_id,
                "email": u.email,
                "username": u.username,
                "first_login": u.first_login,
                "groups": u.groups.unwrap_or_else(|| vec![]),
                "created_at": u.created_at
            })
        })
        .collect();

    (StatusCode::OK, Json(user_list)).into_response()
}

// GET /api/admin/groups
pub async fn list_groups(
    Extension(user): Extension<AuthenticatedUser>,
    Extension(pool): Extension<sqlx::PgPool>,
) -> impl IntoResponse {
    // Check if user is superadmin
    if !user.groups.contains(&"superadmin".to_string()) {
        return (StatusCode::FORBIDDEN, "Superadmin access required").into_response();
    }

    let group_repo = Arc::new(PgGroupRepository::new(pool));
    let group_service = GroupService::new(group_repo);

    match group_service.list_groups().await {
        Ok(groups) => (StatusCode::OK, Json(groups)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// POST /api/admin/groups
pub async fn create_group(
    Extension(user): Extension<AuthenticatedUser>,
    Extension(pool): Extension<sqlx::PgPool>,
    Json(payload): Json<CreateGroupRequest>,
) -> impl IntoResponse {
    // Check if user is superadmin
    if !user.groups.contains(&"superadmin".to_string()) {
        return (StatusCode::FORBIDDEN, "Superadmin access required").into_response();
    }

    let group_repo = Arc::new(PgGroupRepository::new(pool));
    let group_service = GroupService::new(group_repo);

    match group_service.create_group(payload).await {
        Ok(group) => (StatusCode::CREATED, Json(group)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

// GET /api/admin/policies
pub async fn list_policies(
    Extension(user): Extension<AuthenticatedUser>,
    Extension(pool): Extension<sqlx::PgPool>,
) -> impl IntoResponse {
    // Check if user is superadmin
    if !user.groups.contains(&"superadmin".to_string()) {
        return (StatusCode::FORBIDDEN, "Superadmin access required").into_response();
    }

    let policy_repo = Arc::new(PgPolicyRepository::new(pool));
    let policy_service = PolicyService::new(policy_repo);

    match policy_service.list_policies().await {
        Ok(policies) => (StatusCode::OK, Json(policies)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// POST /api/admin/policies
pub async fn create_policy(
    Extension(user): Extension<AuthenticatedUser>,
    Extension(pool): Extension<sqlx::PgPool>,
    Json(payload): Json<CreatePolicyRequest>,
) -> impl IntoResponse {
    // Check if user is superadmin
    if !user.groups.contains(&"superadmin".to_string()) {
        return (StatusCode::FORBIDDEN, "Superadmin access required").into_response();
    }

    let policy_repo = Arc::new(PgPolicyRepository::new(pool));
    let policy_service = PolicyService::new(policy_repo);

    match policy_service.create_policy(payload).await {
        Ok(policy) => (StatusCode::CREATED, Json(policy)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

// POST /api/admin/users/:user_id/groups/:group_id
pub async fn assign_user_to_group(
    Extension(admin): Extension<AuthenticatedUser>,
    Extension(pool): Extension<sqlx::PgPool>,
    Path((user_id, group_id)): Path<(i64, i64)>,
) -> impl IntoResponse {
    // Check if user is superadmin
    if !admin.groups.contains(&"superadmin".to_string()) {
        return (StatusCode::FORBIDDEN, "Superadmin access required").into_response();
    }

    let group_repo = Arc::new(PgGroupRepository::new(pool));
    let group_service = GroupService::new(group_repo);

    match group_service
        .assign_user_to_group(user_id, group_id, Some(admin.user_id))
        .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "message": "User assigned to group successfully"
            })),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

// DELETE /api/admin/users/:user_id/groups/:group_id
pub async fn remove_user_from_group(
    Extension(admin): Extension<AuthenticatedUser>,
    Extension(pool): Extension<sqlx::PgPool>,
    Path((user_id, group_id)): Path<(i64, i64)>,
) -> impl IntoResponse {
    // Check if user is superadmin
    if !admin.groups.contains(&"superadmin".to_string()) {
        return (StatusCode::FORBIDDEN, "Superadmin access required").into_response();
    }

    let group_repo = Arc::new(PgGroupRepository::new(pool));
    let group_service = GroupService::new(group_repo);

    match group_service.remove_user_from_group(user_id, group_id).await {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "message": "User removed from group successfully"
            })),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::PolicyEffect;

    #[test]
    fn test_admin_dashboard_serialization() {
        let dashboard = AdminDashboard {
            total_users: 10,
            total_groups: 3,
            total_policies: 5,
            current_admin: AdminInfo {
                user_id: 1,
                username: "admin".to_string(),
                email: "admin@example.com".to_string(),
                groups: vec!["superadmin".to_string()],
            },
        };

        let json = serde_json::to_string(&dashboard).unwrap();
        assert!(json.contains("total_users"));
        assert!(json.contains("10"));
    }
}
