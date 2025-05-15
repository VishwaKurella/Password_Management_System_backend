use actix_web::{get, post, HttpRequest, HttpResponse, Responder};
use actix_web::web::{Data, Json, Path, Query};
use mongodb::bson::oid::ObjectId;
use crate::models::otp::{OtpIssued, OtpVerificationRequest, OtpVerificationResponse};
use crate::models::response::{AuthResponseError, UserSetMasterKeyResponse, UserVerifyMasterKeyRequest, UserVerifyMasterKeyResponse};
use crate::models::users::{UserServiceIdQuery, UserServiceResponse, UserServiceAllowRequest, UserSessionResponse};
use crate::services::database::Database;
use crate::services::jwt::{generate_jwt, validate_jwt};
use actix_web::cookie::{Cookie, SameSite};
use bcrypt::verify;
// #[post("api/verify/otp")]
// pub async fn verify_otp(db:Data<Database>,jwt_secret: Data<String>,user_form: Json<OtpVerificationRequest>) -> impl Responder {
//     let user_form = user_form.into_inner();
//
//     match db.get_otp_by_id(user_form._id).await {
//         Ok(otp) => {
//             match otp {
//                 Some(otp) => {
//                     if otp.verify_secret(user_form.secret) {
//                         return HttpResponse::Ok().json(OtpVerificationResponse{
//                             success: true,
//                             message: "otp successfully verified".to_string(),
//                             issued_for: otp.issued_for,
//                         })
//                     }else{
//                         return HttpResponse::Ok().json(OtpVerificationResponse{
//                             success: false,
//                             message: "Invalid otp, please try again".to_string(),
//                             issued_for: OtpIssued::Invalid
//                         })
//                     }
//                 },
//                 None => {
//                     return HttpResponse::Unauthorized().json(AuthResponseError {
//                         success: false,
//                         message: "Session expired please, try again.".to_string()
//                     })
//                 }
//             }
//         },
//         Err(_) => {
//             return HttpResponse::InternalServerError().json(AuthResponseError {
//                 success: false,
//                 message: "Server Error, Please try again".to_string()
//              })
//         }
//      }
//     let user_id = match ObjectId::parse_str(user_form._id.to_string()) {
//         Ok(id) => id,
//         Err(_) => return HttpResponse::BadRequest().json(AuthResponseError {
//             success: false,
//             message: "Server error, please try again".to_string(),
//         })
//     };
//     match db.get_otp_by_id(user_id).await {
//         Ok(Some(otp)) => {
//             if otp.verify_secret(user_form.secret) {
//                 match otp.issued_for {
//                     OtpIssued::ForEmailVerification => {
//                         let token = match generate_jwt(&otp.user_id.to_string(), jwt_secret.get_ref(), "Own")
//                             {
//                             Ok(token) => token,
//                             Err(_) => return HttpResponse::InternalServerError().json(AuthResponseError {
//                                 success: false,
//                                 message: "Failed to generate token".into()
//                             })
//                         };
//
//                         let cookie = Cookie::build("auth_token", token)
//                             .http_only(true)
//                             .secure(false)
//                             .same_site(SameSite::Lax)
//                             .path("/")
//                             .finish();
//
//                         return HttpResponse::Ok()
//                             .cookie(cookie)
//                             .json(OtpVerificationResponse {
//                                 success: true,
//                                 message: "otp successfully verified".into(),
//                                 issued_for: OtpIssued::ForEmailVerification,
//                             });
//                     }
//                     OtpIssued::ForResetPassword => {
//                         return HttpResponse::Ok().json(OtpVerificationResponse {
//                             success: true,
//                             message: "otp verified for password reset".into(),
//                             issued_for: OtpIssued::ForResetPassword,
//                         });
//                     }
//                     OtpIssued::ForResetMasterKey => {
//                         return HttpResponse::Ok().json(OtpVerificationResponse {
//                             success: true,
//                             message: "otp verified for master key reset".into(),
//                             issued_for: OtpIssued::ForResetMasterKey,
//                         });
//                     }
//                     OtpIssued::Invalid => {
//                         return HttpResponse::Ok().json(OtpVerificationResponse {
//                             success: false,
//                             message: "Invalid OTP context".into(),
//                             issued_for: OtpIssued::Invalid,
//                         });
//                     }
//                 }
//             } else {
//                 return HttpResponse::Ok().json(OtpVerificationResponse {
//                     success: false,
//                     message: "Invalid otp, please try again".into(),
//                     issued_for: OtpIssued::Invalid,
//                 });
//             }
//         }
//         Ok(None) => HttpResponse::Unauthorized().json(AuthResponseError {
//             success: false,
//             message: "Session expired please, try again.".into(),
//         }),
//         Err(_) => HttpResponse::InternalServerError().json(AuthResponseError {
//             success: false,
//             message: "Server Error, Please try again".into(),
//         }),
//     }
// }

#[post("/api/verify/otp")]
pub async fn verify_otp(
    db: Data<Database>,
    jwt_secret: Data<String>,
    user_form: Json<OtpVerificationRequest>,
) -> impl Responder {
    let user_form = user_form.into_inner();
    let otp_id = user_form._id.clone();
    let user_secret = user_form.secret.clone();

    let otp_id = match ObjectId::parse_str(&otp_id) {
        Ok(id) => id,
        Err(_) => return HttpResponse::BadRequest().json(AuthResponseError {
            success: false,
            message: "Invalid ID format.".into(),
        }),
    };

    match db.get_otp_by_id(otp_id).await {
        Ok(Some(otp)) => {
            if otp.verify_secret(user_secret) {
                if let Err(_) = db.set_otp_verified(otp_id).await {
                    return HttpResponse::InternalServerError().json(AuthResponseError {
                        success: false,
                        message: "Failed to update OTP as verified".into(),
                    });
                }

                match otp.issued_for {
                    OtpIssued::ForEmailVerification => {
                        if let Err(_) = db.set_user_verified(otp.user_id).await {
                            return HttpResponse::InternalServerError().json(AuthResponseError {
                                success: false,
                                message: "Failed to update user as verified".into(),
                            });
                        }

                        if let Err(_) = db.delete_otp(otp_id).await {
                            println!("otp for user not deleted");
                        }

                        let token = match generate_jwt(&otp.user_id.to_string(), jwt_secret.get_ref(), "Own") {
                            Ok(token) => token,
                            Err(_) => return HttpResponse::InternalServerError().json(AuthResponseError {
                                success: false,
                                message: "Failed to generate token".into(),
                            }),
                        };

                        let cookie = Cookie::build("auth_token", token)
                            .http_only(true)
                            .secure(false)
                            .same_site(SameSite::Lax)
                            .path("/")
                            .finish();

                        return HttpResponse::Ok()
                            .cookie(cookie)
                            .json(OtpVerificationResponse {
                                success: true,
                                message: "otp successfully verified".into(),
                                issued_for: OtpIssued::ForEmailVerification,
                            });
                    }
                    OtpIssued::ForResetPassword => HttpResponse::Ok().json(OtpVerificationResponse {
                        success: true,
                        message: "otp verified for password reset".into(),
                        issued_for: OtpIssued::ForResetPassword,
                    }),
                    OtpIssued::ForResetMasterKey => HttpResponse::Ok().json(OtpVerificationResponse {
                        success: true,
                        message: "otp verified for master key reset".into(),
                        issued_for: OtpIssued::ForResetMasterKey,
                    }),
                    OtpIssued::Invalid => HttpResponse::Ok().json(OtpVerificationResponse {
                        success: false,
                        message: "Invalid OTP context".into(),
                        issued_for: OtpIssued::Invalid,
                    }),
                }
            } else {
                HttpResponse::Ok().json(OtpVerificationResponse {
                    success: false,
                    message: "Invalid otp, please try again".into(),
                    issued_for: OtpIssued::Invalid,
                })
            }
        }
        Ok(None) => HttpResponse::Unauthorized().json(AuthResponseError {
            success: false,
            message: "Session expired please, try again.".into(),
        }),
        Err(_) => HttpResponse::InternalServerError().json(AuthResponseError {
            success: false,
            message: "Server Error, Please try again".into(),
        }),
    }
}



#[get("api/verify/allow/{service}/{id}")]
pub async fn verify_path(
    db: Data<Database>,
    user_form: Path<UserServiceAllowRequest>
) -> impl Responder {
    let user_form = user_form.into_inner();
    let service =user_form.service;
    let service_id = user_form.id;
    let _id = ObjectId::parse_str(service_id.as_str()).unwrap();
    match db.get_otp_by_id(_id).await {
        Ok(otp_opt) => match otp_opt {
            Some(otp) => {
                if otp.is_verified() {
                    return HttpResponse::Ok().json(UserServiceResponse {
                        success: true,
                        message: "Authorized".to_string(),
                    });
                } else {
                    return HttpResponse::Unauthorized().json(UserServiceResponse {
                        success: false,
                        message: "OTP not verified".to_string(),
                    });
                }
            }
            None => {
                return HttpResponse::Unauthorized().json(UserServiceResponse {
                    success: false,
                    message: "Session expired, try again".to_string(),
                });
            }
        },
        Err(_) => {
            return HttpResponse::InternalServerError().json(UserServiceResponse {
                success: false,
                message: "Server error, please try again".to_string(),
            });
        }
    }
}

#[get("/api/allow_otp/{id}")]
pub async fn allow_otp(db: Data<Database>, id: Path<String>) -> impl Responder {
    let id_str = id.into_inner();
    let obj_id = match ObjectId::parse_str(&id_str) {
        Ok(oid) => oid,
        Err(_) => {
            return HttpResponse::BadRequest().json(UserServiceResponse {
                success: false,
                message: "Invalid OTP ID".to_string(),
            });
        }
    };
    match db.get_otp_by_id(obj_id).await {
        Ok(Some(otp)) => {
            if otp.is_verified() {
                return HttpResponse::Ok().json(UserServiceResponse {
                    success: false,
                    message: "OTP already verified".to_string(),
                });
            }
            if otp.is_expired() {
                let _ = db.delete_otp_by_id(otp.user_id).await;
                return HttpResponse::Ok().json(UserServiceResponse {
                    success: false,
                    message: "OTP has expired. Please request a new one.".to_string(),
                });
            }
            HttpResponse::Ok().json(UserServiceResponse {
                success: true,
                message: "OTP is valid. Proceed with verification.".to_string(),
            })
        }
        Ok(None) => HttpResponse::NotFound().json(UserServiceResponse {
            success: false,
            message: "OTP not found".to_string(),
        }),
        Err(_) => HttpResponse::InternalServerError().json(UserServiceResponse {
            success: false,
            message: "Failed to fetch OTP".to_string(),
        }),
    }
}


#[get("/api/verify/me")]
pub async fn verify_me(db: Data<Database>, jwt_secret: Data<String>, req: HttpRequest) -> impl Responder {
    match req.cookie("auth_token") {
        Some(cookie) => {
            let auth_token = cookie.value().to_string();

            match validate_jwt(&auth_token, &jwt_secret) {
                Ok(_) => HttpResponse::Ok().json(UserServiceResponse {
                    success: true,
                    message: "Token is valid.".to_string(),
                }),
                Err(_) => HttpResponse::Unauthorized().json(UserServiceResponse {
                    success: false,
                    message: "Session expired or token is invalid.".to_string(),
                }),
            }
        },
        None => HttpResponse::Unauthorized().json(UserServiceResponse {
            success: false,
            message: "No auth token found.".to_string(),
        }),
    }
}


// #[get("/api/verify/is_master_key_set")]
// pub async fn is_master_key_set(db: Data<Database>, req: HttpRequest) -> impl Responder {
//     let token = match req.cookie("token") {
//         Some(cookie) => {
//             cookie.value().to_string()
//         },
//         None => {
//             return HttpResponse::Unauthorized().json(UserSessionResponse {
//                 success: false,
//                 message: "Session Expired.".to_string(),
//                 is_expired: true
//             })
//         }
//     };
//
// }

// #[post("/api/verify/master_key")]
// pub async fn verify_master_key(db: Data<Database>, jwt_secret: Data<String>, req: HttpRequest, user_form: Json<UserVerifyMasterKeyRequest>) -> impl Responder {
//     let token = match req.cookie("auth_token") {
//         Some(c) => c.value().to_string(),
//         None => return HttpResponse::Unauthorized().json(UserVerifyMasterKeyResponse {
//             success: false,
//             message: "Unauthorized: missing authentication token".into(),
//             is_expired: false,
//             data: vec![],
//         }),
//     };
//
//     let claims = match validate_jwt(&token, jwt_secret.get_ref()) {
//         Ok(data) => data.claims,
//         Err(_) => return HttpResponse::Unauthorized().json(UserVerifyMasterKeyResponse {
//             success: false,
//             message: "Invalid or expired authentication token".into(),
//             is_expired: true,
//             data: vec![],
//         }),
//     };
//
//     let user_id = match ObjectId::parse_str(&claims.sub) {
//         Ok(oid) => oid,
//         Err(_) => {
//             return HttpResponse::BadRequest().json(UserVerifyMasterKeyResponse {
//                 success: false,
//                 message: "Invalid user identifier in token".into(),
//                 is_expired: false,
//                 data: vec![],
//             });
//         }
//     };
//
//     let hashed_master_key = match db.get_user_by_id(user_id).await {\
//         Ok(Some(user_data)) => user_data.master_key,
//         Ok(None) => {
//             return HttpResponse::NotFound().json(UserVerifyMasterKeyResponse {
//                 success: false,
//                 message: "User not found".into(),
//                 is_expired: false,
//                 data: vec![],
//             });
//         }
//         Err(_) => {
//             return HttpResponse::InternalServerError().json(UserVerifyMasterKeyResponse {
//                 success: false,
//                 message: "Internal server error retrieving user".into(),
//                 is_expired: false,
//                 data: vec![],
//             });
//         }
//     }
//     let user_form = user_form.into_inner();
//     let master_key = user_form.master_key;
//
//     let master_key_matches = match verify(&master_key, &hashed_master_key) {
//         Ok(matched) if matched => true,
//         _ => {
//             return HttpResponse::Forbidden().json(UserVerifyMasterKeyResponse {
//                 success: false,
//                 message: "Master key mismatch".into(),
//                 is_expired: false,
//                 data: vec![],
//             })
//         }
//     };
//
//     match db.get_entries_by_user_id(user_id).await {
//         Ok(entries) => HttpResponse::Ok().json(UserVerifyMasterKeyResponse {
//             success: true,
//             message: "Master key verified".into(),
//             is_expired: false,
//             data: entries,
//         }),
//         Err(_) => HttpResponse::InternalServerError().json(UserVerifyMasterKeyResponse {
//             success: false,
//             message: "Failed to retrieve entries".into(),
//             is_expired: false,
//             data: vec![],
//         }),
//     }
// }

#[post("/api/verify/master_key")]
pub async fn verify_master_key(
    db: Data<Database>,
    jwt_secret: Data<String>,
    req: HttpRequest,
    user_form: Json<UserVerifyMasterKeyRequest>,
) -> impl Responder {
    println!("{:?}", user_form);
    let token = match req.cookie("auth_token") {
        Some(c) => c.value().to_string(),
        None => {
            return HttpResponse::Unauthorized().json(UserVerifyMasterKeyResponse {
                success: false,
                message: "Unauthorized: missing authentication token".into(),
                is_expired: false,
                data: vec![],
            });
        }
    };

    // Step 2: Validate JWT token
    let claims = match validate_jwt(&token, jwt_secret.get_ref()) {
        Ok(data) => data.claims,
        Err(_) => {
            return HttpResponse::Unauthorized().json(UserVerifyMasterKeyResponse {
                success: false,
                message: "Invalid or expired authentication token".into(),
                is_expired: true,
                data: vec![],
            });
        }
    };

    // Step 3: Parse user ID from claims
    let user_id = match ObjectId::parse_str(&claims.sub) {
        Ok(oid) => oid,
        Err(_) => {
            return HttpResponse::BadRequest().json(UserVerifyMasterKeyResponse {
                success: false,
                message: "Invalid user identifier in token".into(),
                is_expired: false,
                data: vec![],
            });
        }
    };

    // Step 4: Retrieve user from DB
    let hashed_master_key = match db.get_user_by_id(user_id).await {
        Ok(Some(user_data)) => user_data.master_key,
        Ok(None) => {
            return HttpResponse::NotFound().json(UserVerifyMasterKeyResponse {
                success: false,
                message: "User not found".into(),
                is_expired: false,
                data: vec![],
            });
        }
        Err(e) => {
            log::error!("DB error retrieving user: {:?}", e);
            return HttpResponse::InternalServerError().json(UserVerifyMasterKeyResponse {
                success: false,
                message: "Internal server error retrieving user".into(),
                is_expired: false,
                data: vec![],
            });
        }
    };

    // Step 5: Compare master key
    let master_key = user_form.into_inner().master_key;
    match verify(&master_key, &hashed_master_key) {
        Ok(true) => {} // Proceed
        Ok(false) | Err(_) => {
            return HttpResponse::Forbidden().json(UserVerifyMasterKeyResponse {
                success: false,
                message: "Master key mismatch".into(),
                is_expired: false,
                data: vec![],
            });
        }
    };

    // Step 6: Fetch entries
    match db.get_entries_by_user_id(user_id).await {
        Ok(entries) => HttpResponse::Ok().json(UserVerifyMasterKeyResponse {
            success: true,
            message: "Master key verified".into(),
            is_expired: false,
            data: entries,
        }),
        Err(e) => {
            log::error!("Error fetching entries: {:?}", e);
            HttpResponse::InternalServerError().json(UserVerifyMasterKeyResponse {
                success: false,
                message: "Failed to retrieve entries".into(),
                is_expired: false,
                data: vec![],
            })
        }
    }
}
