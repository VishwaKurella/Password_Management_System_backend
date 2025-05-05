mod models;
mod services;
mod api;

use actix_web::{App, HttpServer, get, Responder, HttpResponse, post, web::Path, web};
use env_logger::Env;
use crate::services::{database::Database};
use crate::api::{auth::{create_user, signin, authenticate}};
use actix_governor::{Governor, GovernorConfigBuilder};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(Env::default().default_filter_or("debug"));
    let db = Database::init().await;
    let data = web::Data::new(db);
    let jwt_secret = dotenv::var("JWT_SECRET").expect("DATABASE_URL must be set");
    let auth_limiter_cfg = GovernorConfigBuilder::default()
        .requests_per_second(1)
        .burst_size(10)
        .finish()
        .expect("invalid governor config");

    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .app_data(web::Data::new(jwt_secret.clone()))
            .wrap(actix_web::middleware::Logger::default())
            .wrap(Governor::new(&auth_limiter_cfg))
            .service(create_user)
            .service(signin)
            .service(authenticate)
            .service(hello)
            .service(hello_name)
    })
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}

#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello fellow, how you doin".to_string())
}

#[get("/hello/{name}")]
async fn hello_name(name: Path<String>) -> impl Responder {
    let name = name.into_inner();
    HttpResponse::Ok().body(format!("Hello {}", name))
}

