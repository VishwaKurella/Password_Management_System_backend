use actix_web::{get, post, web, HttpResponse, Responder};
use actix_web::cookie::{Cookie, SameSite};
use actix_web::web::Json;
use crate::models::{users::{UserSignUpForm, User}};
use crate::models::users::{UserSignInForm, UserSignUpGitHubForm};
use crate::services::database::Database;
use crate::services::jwt::generate_jwt;
use bcrypt::verify;
use crate::models::otp::{OtpVerificationRequest};
use crate::models::response::{AuthResponseError, AuthResponseSuccess};

#[post("/api/auth/signup")]
pub async fn create_user(
    db: web::Data<Database>,
    jwt_secret: web::Data<String>,
    user: web::Json<UserSignUpForm>,
) -> impl Responder {
    let user = user.into_inner();
    let new_user = User::new(user.name, user.email, user.password);
    let _id = new_user._id.clone().to_string();
    match db.create_user(new_user).await {
        Ok(_) => {
            match generate_jwt(&_id, jwt_secret.get_ref()) {
                Ok(token) => {
                    let cookie = Cookie::build("auth_token", token)
                        .http_only(true)
                        .secure(true)
                        .same_site(SameSite::Lax)
                        .path("/")
                        .finish();

                    HttpResponse::Ok()
                        .cookie(cookie)
                        .json(AuthResponseSuccess {
                            success: true,
                            message: "User created successfully".to_string(),
                            new_user: true,
                        })
                }
                Err(_) => HttpResponse::InternalServerError().json(AuthResponseError {
                    success: false,
                    message: "Token generation failed".to_string(),
                }),
            }
        }
        Err(_) => HttpResponse::InternalServerError().json(AuthResponseError {
            success: false,
            message: "Server error, failed to create user".to_string(),
        }),
    }
}


#[post("/api/auth/signin")]
pub async fn signin(
    db: web::Data<Database>,
    jwt_secret: web::Data<String>,
    user_form: web::Json<UserSignInForm>,
) -> impl Responder {
    let user_form = user_form.into_inner();
    let user = match db.get_user_by_email(user_form.email).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return HttpResponse::Unauthorized().json(AuthResponseError {
                success: false,
                message: "Invalid credentials".to_string(),
            });
        }
        Err(_) => {
            return HttpResponse::InternalServerError().json(AuthResponseError {
                success: false,
                message: "Server error while fetching user".to_string(),
            });
        }
    };
    let user_password = match user.password_hash {
        Some(password) => password,
        None => return HttpResponse::Unauthorized().json(AuthResponseError {
            success: false,
            message: "Invalid credentials".to_string(),
        })
    };
    let password_matches = verify(&user_form.password, &user_password);
    match password_matches {
        Ok(true) => {
            match generate_jwt(&user._id.to_string(), &jwt_secret) {
                Ok(token) => {
                    let cookie = Cookie::build("auth_token", token)
                        .http_only(true)
                        .secure(true)
                        .same_site(SameSite::Lax)
                        .path("/")
                        .finish();

                    return HttpResponse::Ok()
                        .cookie(cookie)
                        .json(AuthResponseSuccess {
                            success: true,
                            message: "Login successful".to_string(),
                            new_user: false,
                        });
                }
                Err(_) => HttpResponse::InternalServerError().json(AuthResponseError {
                    success: false,
                    message: "Failed to generate token".to_string(),
                }),
            }
        }
        _ => HttpResponse::Unauthorized().json(AuthResponseError {
            success: false,
            message: "Invalid credentials".to_string(),
        }),
    }
}

#[post("/api/auth/authenticate")]
pub async fn authenticate(
    db: web::Data<Database>,
    jwt_secret: web::Data<String>,
    user: web::Json<UserSignUpGitHubForm>,
) -> impl Responder {
    let user = user.into_inner();
    println!("{:?}", user);
    match db.get_user_by_email(user.email.clone()).await {
        Ok(Some(db_user)) => {
            match generate_jwt(&db_user._id.to_string(), &jwt_secret) {
                Ok(token) => {
                    let cookie = Cookie::build("auth_token", token)
                        .http_only(true)
                        .secure(true)
                        .same_site(SameSite::Lax)
                        .path("/")
                        .finish();
                    return HttpResponse::Ok()
                        .cookie(cookie)
                        .json(AuthResponseSuccess {
                            success: true,
                            message: "Login successful".to_string(),
                            new_user: false,
                        });
                }
                Err(_) => {
                    return HttpResponse::InternalServerError().json(AuthResponseError {
                        success: false,
                        message: "Failed to generate token".to_string(),
                    });
                }
            }
        }
        Ok(None) => {
            let new_user = User::new_oauth(user.name, user.email);
            let _id = new_user._id.clone().to_string();

            match db.create_user(new_user).await {
                Ok(_) => {
                    match generate_jwt(&_id, jwt_secret.get_ref()) {
                        Ok(token) => {
                            let cookie = Cookie::build("auth_token", token)
                                .http_only(true)
                                .secure(true)
                                .same_site(SameSite::Lax)
                                .path("/")
                                .finish();

                            return HttpResponse::Ok()
                                .cookie(cookie)
                                .json(AuthResponseSuccess {
                                    success: true,
                                    message: "User created successfully".to_string(),
                                    new_user: false,
                                });
                        }
                        Err(_) => {
                            return HttpResponse::InternalServerError().json(AuthResponseError {
                                success: false,
                                message: "Token generation failed".to_string(),
                            });
                        }
                    }
                }
                Err(_) => {
                    return HttpResponse::InternalServerError().json(AuthResponseError {
                        success: false,
                        message: "Server error, failed to create user".to_string(),
                    });
                }
            }
        }
        Err(_) => {
            return HttpResponse::InternalServerError().json(AuthResponseError {
                success: false,
                message: "Failed to fetch user from database".to_string(),
            });
        }
    }
}


// #[post("/api/auth/otp")]
// pub async fn otp_validate(db: web::Data<Database>, user: Json<OtpVerificationRequest>)-> impl Responder {
//
// }
//


