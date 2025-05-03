mod models;
mod services;
mod api;

use actix_web::{App, HttpServer, get, Responder, HttpResponse, post, web::Data, web::Path};

use crate::services::{database::Database};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let database = Database::init().await;
    let data = Data::new(database);
    HttpServer::new(move || {
        App::new().app_data(data.clone()).service(hello).service(hello_name)
    }).bind(("127.0.0.1", 8080))?.run().await
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

