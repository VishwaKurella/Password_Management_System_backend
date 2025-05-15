use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use actix_web::{cookie::{Cookie, SameSite}};
use mongodb::bson::{oid::ObjectId, DateTime};
use actix_web::web::{Data, Json};
use crate::models::{users::{UserSignUpForm, User}};
use crate::models::users::{UserResetMasterKeyRequest, UserResetPassword, UserServiceResponse, UserSignInForm, UserSignUpGitHubForm, UsersForgetPassword};
use crate::services::database::Database;
use crate::services::jwt::{generate_jwt, validate_jwt};
use bcrypt::{hash_with_salt, verify, DEFAULT_COST};
use chrono::Utc;
use crate::models::otp::{Otp, OtpGenerationSuccess, OtpIssued, OtpVerificationRequest};
use crate::models::response::{AuthIssuerResponse, AuthResponseError, AuthResponseSuccess, AuthSignInResponse, AuthSignUpResponse};
use crate::services::email::send_email;

#[post("/api/auth/signup")]
pub async fn create_user(
    db: web::Data<Database>,
    jwt_secret: web::Data<String>,
    user: web::Json<UserSignUpForm>,
) -> impl Responder {
    let user = user.into_inner();
    match db.get_user_by_email(user.email.clone()).await {
        Ok(Some(_)) => {
            return HttpResponse::BadRequest().json(AuthResponseError {
                success: false,
                message: "User already exists".to_string(),
            });
        }
        Err(_) => {
            return HttpResponse::InternalServerError().json(AuthResponseError {
                success: false,
                message: "Database error checking existing user".to_string(),
            });
        }
        Ok(None) => {}
    }
    let new_user = User::new(user.name, user.email, user.password);
    let user_id = new_user._id.clone();
    let user_email = new_user.email.clone();

    if let Err(_) = db.create_user(new_user).await {
        return HttpResponse::InternalServerError().json(AuthResponseError {
            success: false,
            message: "Server error: failed to create user".to_string(),
        });
    }
    let otp = Otp::new(OtpIssued::ForEmailVerification, user_id.clone());
    let secret = otp.secret.clone();
    let otp_id = otp._id.clone().to_string();
    match db.create_otp(otp).await {
        Ok(_) => {
            match send_email(user_email,secret,&otp_id, OtpIssued::ForEmailVerification).await {
                Ok(_) => HttpResponse::Ok().json(AuthSignUpResponse {
                    success: true,
                    message: "OTP sent for email verification".to_string(),
                    _id: otp_id,
                }),
                Err(e) => {
                    let _ = db.delete_user_by_id(user_id).await;
                    HttpResponse::InternalServerError().json(AuthResponseError {
                        success: false,
                        message: "Failed to send verification email. User creation reverted.".to_string(),
                    })
                }
            }
        },
        Err(_) => {
            let _ = db.delete_user_by_id(user_id).await;
            HttpResponse::InternalServerError().json(AuthResponseError {
                success: false,
                message: "Failed to generate OTP. User creation reverted.".to_string(),
            })
        }
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

    let user_password = match user.password_hash.as_ref() {
        Some(password) => password,
        None => return HttpResponse::Unauthorized().json(AuthResponseError {
            success: false,
            message: "Invalid credentials".to_string(),
        })
    };

    let password_matches = match verify(&user_form.password, &user_password) {
        Ok(matched) if matched => true,
        _ => {
            return HttpResponse::Unauthorized().json(AuthResponseError {
                success: false,
                message: "Invalid credentials".to_string(),
            });
        }
    };

    if !user.is_verified() {
        let user_id = user._id.clone();
        match db.delete_otp_by_id(user_id).await {
            Ok(_) => {},
            Err(_) => {
                return HttpResponse::InternalServerError().json(AuthResponseError {
                    success: false,
                    message: "Server Error, please try again".to_string(),
                });
            }
        }
        let otp = Otp::new(OtpIssued::ForEmailVerification, user_id.clone());
        let otp_secret = otp.secret.clone();
        let otp_id = otp._id.clone().to_string();

        if let Err(_) = db.create_otp(otp).await {
            return HttpResponse::InternalServerError().json(AuthResponseError {
                success: false,
                message: "Failed to regenerate OTP for unverified user".to_string(),
            });
        }
        if let Err(e) = send_email(user.email.clone(),otp_secret,&otp_id,OtpIssued::ForEmailVerification).await {
            return HttpResponse::InternalServerError().json(AuthResponseError {
                success: false,
                message: "Failed to send verification email".to_string(),
            });
        }

        return HttpResponse::Ok().json(AuthSignInResponse {
            success: true,
            message: "User is not verified. Verification OTP has been resent.".to_string(),
            is_verified: false,
            _id: otp_id,
        });
    }

    match generate_jwt(&user._id.to_string(), &jwt_secret,"Own") {
        Ok(token) => {
            let cookie = Cookie::build("auth_token", token)
                .http_only(true)
                .secure(false)
                .same_site(SameSite::Lax)
                .path("/")
                .finish();

            HttpResponse::Ok()
                .cookie(cookie)
                .json(AuthSignInResponse {
                    success: true,
                    message: "Login successful".to_string(),
                    is_verified: true,
                    _id: "".to_string(),
                })
        }
        Err(_) => HttpResponse::InternalServerError().json(AuthResponseError {
            success: false,
            message: "Failed to generate token".to_string(),
        }),
    }

    // let password_matches = verify(&user_form.password, &user_password);
    // match password_matches {
    //     Ok(true) => {
    //         match generate_jwt(&user._id.to_string(), &jwt_secret) {
    //             Ok(token) => {
    //                 let cookie = Cookie::build("auth_token", token)
    //                     .http_only(true)
    //                     .secure(false)
    //                     .same_site(SameSite::Lax)
    //                     .path("/")
    //                     .finish();
    //
    //                 return HttpResponse::Ok()
    //                     .cookie(cookie)
    //                     .json(AuthResponseSuccess {
    //                         success: true,
    //                         message: "Login successful".to_string(),
    //                         new_user: false,
    //                     });
    //             }
    //             Err(_) => HttpResponse::InternalServerError().json(AuthResponseError {
    //                 success: false,
    //                 message: "Failed to generate token".to_string(),
    //             }),
    //         }
    //     }
    //     _ => HttpResponse::Unauthorized().json(AuthResponseError {
    //         success: false,
    //         message: "Invalid credentials".to_string(),
    //     }),
    // }
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
            match generate_jwt(&db_user._id.to_string(), &jwt_secret,"OAuth") {
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
                    match generate_jwt(&_id, jwt_secret.get_ref(),"OAuth") {
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

    let user = match db.get_user_by_email(user_form.email.clone()).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return HttpResponse::NotFound().json(AuthResponseError {
                success: false,
                message: "No account found for the provided email.".to_string(),
            });
        }
        Err(err) => {
            log::error!("Database error on get_user_by_email: {:?}", err);
            return HttpResponse::InternalServerError().json(AuthResponseError {
                success: false,
                message: "Server error. Please try again later.".to_string(),
            });
        }
    };

    let _id = user._id.clone();
    if let Err(err) = db.delete_otp_by_id(_id.clone()).await {
        log::error!("Failed to delete old OTP for user {}: {:?}", _id, err);
        return HttpResponse::InternalServerError().json(AuthResponseError {
            success: false,
            message: "Unable to clear previous OTP. Please try again.".to_string(),
        });
    }

    let otp = Otp::new(OtpIssued::ForResetPassword, _id.clone());
    let otp_id = otp._id.clone();
    let otp_secret = otp.secret.clone();
    if let Err(err) = db.create_otp(otp).await {
        log::error!("Database error on create_otp: {:?}", err);
        return HttpResponse::InternalServerError().json(AuthResponseError {
            success: false,
            message: "Failed to generate OTP. Please try again.".to_string(),
        });
    }

    if let Err(err) = send_email(
        user.email.clone(),
        otp_secret,
        &otp_id.to_string(),
        OtpIssued::ForResetPassword,
    ).await {
        log::error!("Failed to send OTP email to {}: {:?}", user.email, err);

        if let Err(del_err) = db.delete_otp(otp_id).await {
            log::error!("Failed to cleanup OTP after email failure: {:?}", del_err);
        }

        return HttpResponse::InternalServerError().json(AuthResponseError {
            success: false,
            message: "Failed to send OTP email. Please try again.".to_string(),
        });
    }
    println!("the otp id is {}", otp_id);
    HttpResponse::Ok().json(OtpGenerationSuccess {
        success: true,
        id: otp_id.to_string(),
    })
}

#[post("/api/auth/reset_password")]
pub async fn reset_password(db: Data<Database>, user_form: Json<UserResetPassword>) -> impl Responder {
    let user_form = user_form.into_inner();

    let otp = match db.get_otp_by_id(user_form._id.clone()).await {
        Ok(Some(otp)) => {
            if otp.is_verified() {
                let created_ms = otp.created_at.timestamp_millis();
                let valid_until = DateTime::from_millis(created_ms + 10 * 60 * 1000);
                let now = DateTime::now();

                if now > valid_until {
                    let _ = db.delete_otp(otp._id.clone()).await;
                    return HttpResponse::Unauthorized().json(UserServiceResponse {
                        success: false,
                        message: "Password reset link has expired.".to_string(),
                    });
                }
                let salt = User::generate_salt();
                let password_hash = hash_with_salt(&user_form.password, DEFAULT_COST, &salt).unwrap().to_string();

                match db.set_password(user_form._id, password_hash).await {
                    Ok(_) => {
                        let _ = db.delete_otp(otp._id.clone()).await;
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
    let user_id = ObjectId::parse_str(user_form._id).unwrap();
    // Retrieve OTP by ID
    match db.get_otp_by_id(user_id.clone()).await {
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


// #[get("/api/auth/logout")]
// pub async fn logout(req: HttpRequest, jwt_secret: web::Data<String>) -> impl Responder {
//     let expired = time::OffsetDateTime::now_utc() - time::Duration::days(1);
//
//     let cookie = Cookie::build("auth_token", "")
//         .http_only(true)
//         .secure(true)
//         .same_site(SameSite::Lax)
//         .path("/")
//         .expires(expired)
//         .finish();
//
//     HttpResponse::Ok()
//         .cookie(cookie)
//         .json(AuthIssuerResponse {
//             success: true,
//             message: "Logged out successfully".to_string(),
//             issuer: "".to_string(), })
//
//     // if let Some(cookie) = req.cookie("auth_token") {
//     //     let token = cookie.value();
//     //     match validate_jwt(token, jwt_secret.get_ref()) {
//     //         Ok(token_data) => {
//     //             let issuer = token_data.claims.iss;
//     //             let expired_time = Utc::now();
//     //             let cookie = Cookie::build("auth_token", "")
//     //                 .http_only(true)
//     //                 .secure(true)
//     //                 .same_site(actix_web::cookie::SameSite::Lax)
//     //                 .path("/")
//     //                 .expires(time::OffsetDateTime::now_utc() - time::Duration::days(1))
//     //                 .finish();
//     //
//     //             HttpResponse::Ok()
//     //                 .cookie(cookie)
//     //                 .json({
//     //                     AuthIssuerResponse {
//     //                         success: true,
//     //                         message: "Logged out successfully".to_string(),
//     //                         issuer,
//     //                     }
//     //                 })
//     //         },
//     //         Err(_) => {
//     //             HttpResponse::Unauthorized().json(AuthIssuerResponse {
//     //                 success: false,
//     //                 message: "Invalid or expired token".to_string(),
//     //                 issuer: "null".to_string(),
//     //             })
//     //         }
//     //     }
//     // } else {
//     //     HttpResponse::BadRequest().json(AuthIssuerResponse {
//     //         success: false,
//     //         message: "No auth_token cookie found".to_string(),
//     //         issuer: "null".to_string(),
//     //     })
//     // }
// }

// #[get("/api/auth/logout")]
// pub async fn logout() -> impl Responder {
//     let expired_cookie = Cookie::build("auth_token", "")
//         .path("/")                                  // must match original
//         .secure(true)                               // must match original
//         .same_site(SameSite::Lax)                   // must match original
//         .max_age(time::Duration::ZERO)                  // immediate expiry
//         .finish();
//
//     HttpResponse::Ok()
//         .cookie(expired_cookie)
//         .json(AuthIssuerResponse {
//             success: true,
//             message: "Logged out successfully".to_string(),
//             issuer: "".to_string(),
//         })
// }
