use actix_web::{delete, get, post, web, HttpRequest, HttpResponse, Responder};
use actix_web::web::{Data, Json};
use bcrypt::verify;
use mongodb::bson::{oid::ObjectId};
use crate::models::entries::{Entries, UserCreateEntriesRequest, UserCreateEntriesResponse, UserDeleteEntriesRequest, UserUpdateEntriesRequest};
use crate::models::response::{AuthIssuerResponse, AuthResponseError, UserChangeNameRequest, UserChangeNameResponse, UserChangePasswordRequest, UserChangePasswordResponse, UserDataResponse, UserDeleteResponse};
use crate::models::users::{UserServiceResponse, UserSessionResponse, User};
use crate::services::database::Database;
use crate::services::email::send_email;
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
        Ok(Some(user)) => {
            let is_master_key_set = if user.master_key == "" {
                false
            }else{
                true
            };
            HttpResponse::Ok().json(UserDataResponse {
                success: true,
                message: "user data".to_string(),
                id: user._id.to_string(),
                name: user.name,
                email: user.email,
                salt: user.salt,
                // is_expired: false,
                is_master_key_set,
            })
        },
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

#[get("/api/request/issuer")]
pub async fn get_issuer_from_cookie(req: HttpRequest, jwt_secret: web::Data<String>) -> impl Responder {
    let token_cookie = req.cookie("auth_token");
    println!("{:?}",token_cookie);
    println!("{:?}",token_cookie);
    if let Some(cookie) = token_cookie {
        let token = cookie.value();

        match validate_jwt(token, jwt_secret.get_ref()) {
            Ok(token_data) => {
                let issuer = token_data.claims.iss;
                HttpResponse::Ok().json(AuthIssuerResponse {
                    success: true,
                    message: "Token validated successfully".to_string(),
                    issuer,
                })
            }
            Err(e) => {
                HttpResponse::Unauthorized().json(AuthIssuerResponse {
                    success: false,
                    message: "Invalid or expired token".to_string(),
                    issuer: "null".to_string(),
                })
            }
        }
    } else {
        HttpResponse::BadRequest().json(AuthIssuerResponse {
            success: false,
            message: "auth_token cookie not found".to_string(),
            issuer: "null".to_string(),
        })
    }
}


#[post("/api/request/create_entries")]
pub async fn create_entries(db: Data<Database>, jwt_secret: Data<String>, req: HttpRequest, user_form: Json<UserCreateEntriesRequest>)-> impl Responder {
    let token = match req.cookie("auth_token") {
        Some(c) => c.value().to_string(),
        None => {
            return HttpResponse::Unauthorized().json(UserCreateEntriesResponse {
                success: false,
                message: "Could not find token".to_string(),
                is_expired: true,
                id: "".to_string(),
            });
        }
    };

    let token_data = match validate_jwt(&token, jwt_secret.get_ref()) {
        Ok(data) => data,
        Err(_) => {
            return HttpResponse::Unauthorized().json(UserCreateEntriesResponse {
                success: false,
                message: "Invalid or expired auth token".into(),
                is_expired: true,
                id: "".to_string(),
            });
        }
    };

    let user_id = match ObjectId::parse_str(token_data.claims.sub) {
        Ok(oid) => oid,
        Err(_) => {
            return HttpResponse::BadRequest().json(UserCreateEntriesResponse {
                success: false,
                message: "Invalid user ID in token".into(),
                is_expired: true,
                id: "".to_string(),
            });
        }
    };
    let user_form =user_form.into_inner();
    let data = user_form.data;
    let nonce = user_form.nonce;
    let new_entry = Entries::new(user_id,data,nonce);
    let new_entry_id= new_entry._id.clone().to_string();
    match db.create_entries(new_entry).await {
        Ok(_)=>{
             HttpResponse::Ok().json(UserCreateEntriesResponse {
                success: true,
                message: "Entry created successful".to_string(),
                is_expired: false,
                 id: new_entry_id
            })
        }
        Err(_)=>{
            HttpResponse::InternalServerError().json(UserCreateEntriesResponse {
                success: false,
                message: "Server Error".to_string(),
                is_expired: false,
                id: "".to_string(),
            })
        }
    }
}

#[post("/api/request/update_entries")]
pub async fn update_entries(db: Data<Database>, jwt_secret: Data<String>, req: HttpRequest, user_form: Json<UserUpdateEntriesRequest>)-> impl Responder {
    let token = match req.cookie("auth_token") {
        Some(c) => c.value().to_string(),
        None => {
            return HttpResponse::Unauthorized().json(UserCreateEntriesResponse {
                success: false,
                message: "Could not find token".to_string(),
                is_expired: true,
                id: "".to_string(),
            });
        }
    };

    if let Err(_) = validate_jwt(&token, jwt_secret.get_ref()) {
        return HttpResponse::Unauthorized().json(UserCreateEntriesResponse {
            success: false,
            message: "Invalid or expired auth token".into(),
            is_expired: true,
            id: "".to_string(),
        });
    };

    let user_form = user_form.into_inner();
    let entry_id = match ObjectId::parse_str(user_form.id) {
        Ok(oid) => oid,
        Err(_) => {
            return HttpResponse::BadRequest().json(UserSessionResponse {
                success: false,
                message: "Invalid entry ID".into(),
                is_expired: false,
            });
        }
    };
    let data = user_form.data;
    let nonce = user_form.nonce;

    match db.update_entries(entry_id, data, nonce).await {
        Ok(_)=>{
            HttpResponse::Ok().json(UserSessionResponse {
                success: true,
                message: "Entry updated successfully".into(),
                is_expired: false,
            })
        }
        Err(_)=>{
            HttpResponse::InternalServerError().json(UserSessionResponse {
                success: false,
                message: "Server error while updating entry".into(),
                is_expired: false,
            })
        }
    }
}

#[post("/api/request/delete_entries")]
pub async fn delete_entries(db: Data<Database>, jwt_secret: Data<String>, req: HttpRequest, user_form: Json<UserDeleteEntriesRequest>)->impl Responder {
    let token = match req.cookie("auth_token") {
        Some(c) => c.value().to_string(),
        None => {
            return HttpResponse::Unauthorized().json(UserCreateEntriesResponse {
                success: false,
                message: "Could not find token".to_string(),
                is_expired: true,
                id: "".to_string(),
            });
        }
    };

    if let Err(_) = validate_jwt(&token, jwt_secret.get_ref()) {
        return HttpResponse::Unauthorized().json(UserCreateEntriesResponse {
            success: false,
            message: "Invalid or expired auth token".into(),
            is_expired: true,
            id: "".to_string(),
        });
    };

    let user_form = user_form.into_inner();
    let user_id = user_form.id;
    let entry_id = match ObjectId::parse_str(user_id) {
        Ok(oid) => oid,
        Err(_) => {
            return HttpResponse::BadRequest().json(UserSessionResponse {
                success: false,
                message: "Invalid entry ID".into(),
                is_expired: false,
            });
        }
    };
    match db.delete_entries(entry_id).await {
        Ok(_)=>{
             HttpResponse::Ok().json(UserSessionResponse {
                success: true,
                message: "Entry Deleted successfully".into(),
                is_expired: false,
            })
        }
        Err(_)=>{
            HttpResponse::InternalServerError().json(UserSessionResponse {
                success: false,
                message: "Server error while deleting entry".into(),
                is_expired: false,
            })
        }
    }
}

#[post("/api/request/change_name")]
pub async fn change_name(db: Data<Database>, jwt_secret: Data<String>, req: HttpRequest, user_form: Json<UserChangeNameRequest>)->impl Responder {
    let token = match req.cookie("auth_token") {
        Some(c) => c.value().to_string(),
        None => {
            return HttpResponse::Unauthorized().json(UserChangeNameResponse {
                success: false,
                message: "Could not find token".to_string(),
                is_expired: true,
            });
        }
    };

    let token_data = match validate_jwt(&token, jwt_secret.get_ref()) {
        Ok(data) => data,
        Err(_) => {
            return HttpResponse::Unauthorized().json(UserChangeNameResponse {
                success: false,
                message: "Invalid or expired auth token".into(),
                is_expired: true,
            });
        }
    };

    let user_id = match ObjectId::parse_str(token_data.claims.sub) {
        Ok(oid) => oid,
        Err(_) => {
            return HttpResponse::BadRequest().json(UserChangeNameResponse {
                success: false,
                message: "Invalid user ID in token".into(),
                is_expired: true,
            });
        }
    };
    let user_form = user_form.into_inner();
    let name = user_form.name;
    match db.set_user_name(user_id, name).await {
        Ok(_)=>{
            HttpResponse::Ok().json(UserChangeNameResponse {
                success: true,
                message: "Name updated successfully".to_string(),
                is_expired: false,
            })
        }
        Err(_)=>{
            HttpResponse::InternalServerError().json(UserChangeNameResponse {
                success: false,
                message: "Server error".to_string(),
                is_expired: false,
            })
        }
    }
}


#[post("/api/user/change_password")]
pub async fn change_password(
    db: Data<Database>,
    jwt_secret: Data<String>,
    req: HttpRequest,
    user_form: Json<UserChangePasswordRequest>,
) -> impl Responder {
    let token = match req.cookie("auth_token") {
        Some(c) => c.value().to_string(),
        None => {
            return HttpResponse::Unauthorized().json(UserChangePasswordResponse {
                success: false,
                message: "Could not find token".to_string(),
                is_expired: true,
            })
        }
    };

    let token_data = match validate_jwt(&token, jwt_secret.get_ref()) {
        Ok(data) => data,
        Err(_) => {
            return HttpResponse::Unauthorized().json(UserChangePasswordResponse {
                success: false,
                message: "Invalid or expired auth token".into(),
                is_expired: true,
            })
        }
    };
    let user_id = match ObjectId::parse_str(&token_data.claims.sub) {
        Ok(oid) => oid,
        Err(_) => {
            return HttpResponse::BadRequest().json(UserChangePasswordResponse {
                success: false,
                message: "Invalid user ID in token".into(),
                is_expired: false,
            })
        }
    };
    let user_form = user_form.into_inner();
    let old_password = user_form.old_password;
    let new_password = user_form.new_password;
    let current_password = match db.get_user_by_id(user_id).await{
        Ok(Some(u)) => {
            if let Some(current_password) = u.password_hash {
                current_password
            } else {
                return HttpResponse::Unauthorized().json(UserChangePasswordResponse {
                    success: false,
                    message: "Unauthorized".to_string(),
                    is_expired: false,
                })
            }
        },
        _ => {
            return HttpResponse::InternalServerError().json(UserChangePasswordResponse {
                success: false,
                message: "Unauthorised".to_string(),
                is_expired: true
            })
        }
    };

    let password_matches = match verify(&current_password, &old_password){
        Ok(matched) if matched => true,
        _ => {
            return HttpResponse::Unauthorized().json(UserChangePasswordResponse {
                success: false,
                message: "Invalid credentials".to_string(),
                is_expired: false,
            });
        }
    };

    let new_password_hash = User::generate_hash(new_password);

    match db.set_password(user_id, new_password_hash).await {
        Ok(_) => HttpResponse::Ok().json(UserChangePasswordResponse {
            success: true,
            message: "Password updated successfully".into(),
            is_expired: false,
        }),
        Err(_) => HttpResponse::InternalServerError().json(UserChangePasswordResponse {
            success: false,
            message: "Server error".into(),
            is_expired: false,
        }),
    }
}



#[delete("/api/user/delete_account")]
pub async fn delete_account(
    db: Data<Database>,
    jwt_secret: Data<String>,
    req: HttpRequest,
) -> impl Responder {
    let token = match req.cookie("auth_token") {
        Some(c) => c.value().to_string(),
        None => {
            return HttpResponse::Unauthorized().json(UserDeleteResponse {
                success: false,
                message: "Could not find token".to_string(),
                is_expired: true,
            })
        }
    };

    let token_data = match validate_jwt(&token, jwt_secret.get_ref()) {
        Ok(data) => data,
        Err(_) => {
            return HttpResponse::Unauthorized().json(UserDeleteResponse {
                success: false,
                message: "Invalid or expired auth token".into(),
                is_expired: true,
            })
        }
    };

    let user_id = match ObjectId::parse_str(&token_data.claims.sub) {
        Ok(oid) => oid,
        Err(_) => {
            return HttpResponse::BadRequest().json(UserDeleteResponse {
                success: false,
                message: "Invalid user ID in token".into(),
                is_expired: false,
            })
        }
    };

    if let Err(_) =  db.delete_entries_by_user_id(user_id).await {
        return HttpResponse::InternalServerError().json(UserDeleteResponse {
            success: false,
            message: "Server error".into(),
            is_expired: false,
        })
    };
    match db.delete_user_by_id(user_id).await {
        Ok(_) => HttpResponse::Ok().json(UserDeleteResponse {
            success: true,
            message: "Account deleted successfully".into(),
            is_expired: false,
        }),
        Err(_) => HttpResponse::InternalServerError().json(UserDeleteResponse {
            success: false,
            message: "Server error".into(),
            is_expired: false,
        }),
    }
}