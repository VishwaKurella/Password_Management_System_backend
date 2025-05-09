use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use actix_web::web::Data;
use mongodb::bson::{oid::ObjectId};
use crate::models::users::{UserServiceResponse, UserSessionResponse};
use crate::services::database::Database;
use crate::services::jwt::validate_jwt;
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

// #[get("/api/request")]
// async fn get_entries(database: web::Data<Database>, req: HttpRequest) -> impl Responder {
//     match req.cookie("auth_token") {
//         Some(cookie) => {
//
//         },
//         None => {
//             return HttpResponse::Unauthorized().json(UserServiceResponse{
//                 success: false,
//                 message: "Unauthorized. Please sign in".to_string()
//             })
//         }
//     }
// }

#[get("/api/request/me")]
async fn user_details(db: Data<Database>, jwt_secret: Data<String>, req: HttpRequest) -> impl Responder {
    let token = match req.cookie("auth_token") {
        Some(c) => c.value().to_string(),
        None => {
            return HttpResponse::Unauthorized().json(UserSessionResponse {
                success: false,
                message: "Could not find token".to_string(),
                is_expired: true,
            });
        }
    };

    let token_data = match validate_jwt(&token, jwt_secret.get_ref()) {
        Ok(data) => data,
        Err(_) => {
            return HttpResponse::Unauthorized().json(UserSessionResponse {
                success: false,
                message: "Invalid or expired auth token".into(),
                is_expired: true,
            });
        }
    };

    let user_id = match ObjectId::parse_str(token_data.claims.sub) {
        Ok(oid) => oid,
        Err(_) => {
            return HttpResponse::BadRequest().json(UserSessionResponse {
                success: false,
                message: "Invalid user ID in token".into(),
                is_expired: true,
            });
        }
    };

    match db.get_user_by_id(user_id.clone()).await {
        Ok(Some(user)) => HttpResponse::Ok().json(user),
        Ok(None) => HttpResponse::NotFound().json(UserSessionResponse {
            success: false,
            message: "User not found".into(),
            is_expired: false,
        }),
        Err(_) => HttpResponse::InternalServerError().json(UserSessionResponse {
            success: false,
            message: "Database error while fetching user".into(),
            is_expired: false,
        }),
    }
}
