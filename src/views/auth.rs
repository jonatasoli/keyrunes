use axum::{
    extract::{Extension, Form},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
};
use std::sync::Arc;
use tera::Context;

use crate::repository::sqlx_impl::PgUserRepository;
use crate::services::user_service::{RegisterRequest, UserService};

#[derive(serde::Deserialize)]
pub struct RegisterForm {
    pub email: String,
    pub username: String,
    pub password: String,
}

#[derive(serde::Deserialize)]
pub struct LoginForm {
    pub identity: String, // email ou username
    pub password: String,
}

// GET /register
pub async fn register_page(Extension(tmpl): Extension<tera::Tera>) -> impl IntoResponse {
    let mut ctx = Context::new();
    ctx.insert("title", "Register");
    let body = tmpl.render("register.html", &ctx).unwrap();
    Html(body)
}

// POST /register
pub async fn register_post(
    Extension(service): Extension<Arc<UserService<PgUserRepository>>>,
    Extension(tmpl): Extension<tera::Tera>,
    Form(payload): Form<RegisterForm>,
) -> impl IntoResponse {
    let req = RegisterRequest {
        email: payload.email,
        username: payload.username,
        password: payload.password,
    };

    match service.register(req).await {
        Ok(_) => Redirect::to("/login").into_response(),
        Err(e) => {
            let mut ctx = Context::new();
            ctx.insert("title", "Register");
            ctx.insert("error", &format!("{}", e));
            let body = tmpl.render("register.html", &ctx).unwrap();
            (StatusCode::BAD_REQUEST, Html(body)).into_response()
        }
    }
}

// GET /login
pub async fn login_page(Extension(tmpl): Extension<tera::Tera>) -> impl IntoResponse {
    let mut ctx = Context::new();
    ctx.insert("title", "Login");
    let body = tmpl.render("login.html", &ctx).unwrap();
    Html(body)
}

// POST /login
pub async fn login_post(
    Extension(service): Extension<Arc<UserService<PgUserRepository>>>,
    Extension(tmpl): Extension<tera::Tera>,
    Form(payload): Form<LoginForm>,
) -> impl IntoResponse {
    match service.login(payload.identity, payload.password).await {
        Ok(user) => {
            let mut ctx = Context::new();
            ctx.insert("title", "Welcome");
            ctx.insert("username", &user.username);
            let body = tmpl.render("welcome.html", &ctx).unwrap();
            (StatusCode::OK, Html(body))
        }
        Err(e) => {
            let mut ctx = Context::new();
            ctx.insert("title", "Login");
            ctx.insert("error", &format!("{}", e));
            let body = tmpl.render("login.html", &ctx).unwrap();
            (StatusCode::UNAUTHORIZED, Html(body))
        }
    }
}
