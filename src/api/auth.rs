use actix_web::{get, post, web, HttpResponse, Responder};
use actix_web::cookie::{Cookie, SameSite};
use actix_web::web::{Data, Json};
use crate::models::{users::{UserSignUpForm, User}};
use crate::models::users::{UserResetMasterKeyRequest, UserResetPassword, UserServiceResponse, UserSignInForm, UserSignUpGitHubForm, UsersForgetPassword};
use crate::services::database::Database;
use crate::services::jwt::generate_jwt;
use bcrypt::{hash_with_salt, verify, DEFAULT_COST};
use crate::models::otp::{Otp, OtpGenerationSuccess, OtpIssued, OtpVerificationRequest};
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
                        .secure(false)
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
                        .secure(false)
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
                        .secure(false)
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
            let new_user = User::new(user.name, user.email,String::new());
            let _id = new_user._id.clone().to_string();

            match db.create_user(new_user).await {
                Ok(_) => {
                    match generate_jwt(&_id, jwt_secret.get_ref()) {
                        Ok(token) => {
                            let cookie = Cookie::build("auth_token", token)
                                .http_only(true)
                                .secure(false)
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

#[post("/api/auth/forgot_password")]
pub async fn forgot_password(db:Data<Database>, email: Json<UsersForgetPassword>)->impl Responder {
    let user_form = email.into_inner();

    let user = match db.get_user_by_email(user_form.email).await {
        Ok(Some(user)) => {
            user
        },
        Ok(None) => {
            return HttpResponse::InternalServerError().json(AuthResponseError {
                success: false,
                message: "User doesn't exist".to_string(),
            })
        },
        Err(_) => {
            return HttpResponse::InternalServerError().json(AuthResponseError {
                success: false,
                message: "Server error, failed to find user".to_string(),
            })
        }
    };

    let _id = user._id.clone();
    let otp = Otp::new(OtpIssued::ForResetPassword,_id);
    match db.create_otp(otp).await {
        Ok(_) => {
            return HttpResponse::Ok().json(OtpGenerationSuccess {
                success: true,
                _id
            })
        },
        Err(_) => {
            return HttpResponse::InternalServerError().json(AuthResponseError {
                success: false,
                message: "Server error, please try again".to_string(),
            })
        }
    }
}

#[post("/api/auth/reset_password")]
pub async fn reset_password(db: Data<Database>, user_form: Json<UserResetPassword>) -> impl Responder {
    let user_form = user_form.into_inner();

    let otp = match db.get_otp_by_id(user_form._id.clone()).await {
        Ok(Some(otp)) => {
            if otp.is_verified() {
                let salt = User::generate_salt();
                let password_hash = hash_with_salt(&user_form.password, DEFAULT_COST, &salt).unwrap().to_string();

                match db.set_password(user_form._id, password_hash).await {
                    Ok(_) => {
                        return HttpResponse::Ok().json(UserServiceResponse {
                            success: true,
                            message: "Password reset successfully.".to_string(),
                        });
                    }
                    Err(_) => {
                        return HttpResponse::InternalServerError().json(UserServiceResponse {
                            success: false,
                            message: "Failed to update password in the database.".to_string(),
                        });
                    }
                }
            } else {
                return HttpResponse::Unauthorized().json(UserServiceResponse {
                    success: false,
                    message: "OTP is not verified.".to_string(),
                });
            }
        }
        Ok(None) => {
            return HttpResponse::Unauthorized().json(AuthResponseError {
                success: false,
                message: "User doesn't have permission to reset password.".to_string(),
            });
        }
        Err(_) => {
            return HttpResponse::InternalServerError().json(AuthResponseError {
                success: false,
                message: "Server error, failed to reset password.".to_string(),
            });
        }
    };
}


// #[post("/api/auth/reset_master_key")]
// pub async fn reset_master_key(db: Data<Database>, user_form: Json<UserResetMasterKeyRequest>) -> impl Responder {
//     let user_form = user_form.into_inner();
//     match db.get_otp_by_id(user_form._id).await {
//         Ok(Some(otp)) => {
//             if otp.is_verified() {
//                 match db.set_master_key(otp.user_id,user_form.master_key).await {
//                     Ok(_) => HttpResponse::Ok().json(UserServiceResponse {
//                         success: true,
//                         message: "Master key reset successfully.".to_string(),
//                     }),
//                     Err(_) => HttpResponse::InternalServerError().json(UserServiceResponse {
//                         success: false,
//                         message: "Failed to update master key.".to_string(),
//                     }),
//                 }
//             }else{
//                 HttpResponse::Unauthorized().json(UserServiceResponse {
//                     success: false,
//                     message: "OTP not verified.".to_string(),
//                 })
//             }
//         },
//         Ok(None) => HttpResponse::NotFound().json(UserServiceResponse {
//             success: false,
//             message: "OTP record not found.".to_string(),
//         }),
//         Err(_) => HttpResponse::InternalServerError().json(UserServiceResponse {
//             success: false,
//             message: "Database error while retrieving OTP.".to_string(),
//         }),
//     }
// }

#[post("/api/auth/reset_master_key")]
pub async fn reset_master_key(
    db: Data<Database>,
    user_form: Json<UserResetMasterKeyRequest>,
) -> impl Responder {
    let user_form = user_form.into_inner();

    // Retrieve OTP by ID
    match db.get_otp_by_id(user_form._id).await {
        Ok(Some(otp)) => {
            if otp.is_verified() {
                // Attempt to set the master key
                match db.set_master_key(otp.user_id, user_form.master_key).await {
                    Ok(_) => HttpResponse::Ok().json(UserServiceResponse {
                        success: true,
                        message: "Master key reset successfully.".to_string(),
                    }),
                    Err(e) => {
                        log::error!("Failed to update master key: {}", e);
                        HttpResponse::InternalServerError().json(UserServiceResponse {
                            success: false,
                            message: "Failed to update master key.".to_string(),
                        })
                    }
                }
            } else {
                HttpResponse::Unauthorized().json(UserServiceResponse {
                    success: false,
                    message: "OTP not verified.".to_string(),
                })
            }
        }
        Ok(None) => HttpResponse::NotFound().json(UserServiceResponse {
            success: false,
            message: "OTP record not found.".to_string(),
        }),
        Err(e) => {
            log::error!("Database error while retrieving OTP: {}", e);
            HttpResponse::InternalServerError().json(UserServiceResponse {
                success: false,
                message: "Database error while retrieving OTP.".to_string(),
            })
        }
    }
}
