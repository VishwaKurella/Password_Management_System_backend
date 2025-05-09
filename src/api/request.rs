use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use actix_web::cookie::Cookie;
use jsonwebtoken::errors::ErrorKind::Json;
use crate::models::response::AuthResponseError;
use crate::models::users::UserServiceResponse;
use crate::services::database::Database;
use crate::services::jwt::{validate_jwt};

// #[get("/api/request/me")]
// pub async fn user_details(
//     db: web::Data<Database>,
//     jwt_secret: web::Data<String>,
//     req: HttpResponse,
// ) -> impl Responder {
//     // Extract the cookie from the request headers
//     let token = match req.cookies(). {
//         Some(cookie) => cookie.value().to_string(),
//         None => {
//             return HttpResponse::Unauthorized().json(AuthResponseError {
//                 success: false,
//                 message: "Missing auth token".to_string(),
//             });
//         }
//     };
//
//     // Validate the token
//     let claims = match validate_jwt(&token, jwt_secret.get_ref()) {
//         Ok(data) => data.claims,
//         Err(_) => {
//             return HttpResponse::Unauthorized().json(AuthResponseError {
//                 success: false,
//                 message: "Invalid or expired token".to_string(),
//             });
//         }
//     };
//
//     // Fetch user details from database (example stub)
//     let user = match db.get_user_by_id(&claims.sub).await {
//         Ok(user) => user,
//         Err(_) => {
//             return HttpResponse::InternalServerError().json(AuthResponseError {
//                 success: false,
//                 message: "Failed to fetch user".to_string(),
//             });
//         }
//     };
//
//     HttpResponse::Ok().json(UserResponseSuccess {
//         success: true,
//         user,
//     })
// }

#[get("/api/request")]
async fn get_entries(database: web::Data<Database>, req: HttpRequest) -> impl Responder {
    match req.cookie("auth_token") {
        Some(cookie) => {
            let token = cookie.value();
            let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_default();
            match validate_jwt(token, &jwt_secret) {
                Ok(data) => {
                    let user_id_str = data.claims.sub;
                    let user_id = match mongodb::bson::oid::ObjectId::parse_str(&user_id_str) {
                        Ok(oid) => oid,
                        Err(_) => {
                            return HttpResponse::Unauthorized().json(UserServiceResponse {
                                success: false,
                                message: "Invalid user ID in token".to_string(),
                            });
                        }
                    };
                    match database.get_user_by_id(user_id).await {
                        Ok(Some(user)) => {
                            HttpResponse::Ok().json(user)
                        }
                        Ok(None) => HttpResponse::Unauthorized().json(UserServiceResponse {
                            success: false,
                            message: "User not found".to_string(),
                        }),
                        Err(_) => HttpResponse::InternalServerError().json(UserServiceResponse {
                            success: false,
                            message: "Database error".to_string(),
                        }),
                    }
                }
                Err(_) => HttpResponse::Unauthorized().json(UserServiceResponse {
                    success: false,
                    message: "Invalid or expired token".to_string(),
                }),
            }
        }
        None => {
            HttpResponse::Unauthorized().json(UserServiceResponse {
                success: false,
                message: "Unauthorized. Please sign in".to_string(),
            })
        }
    }
}
