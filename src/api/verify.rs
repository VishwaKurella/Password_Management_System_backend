use actix_web::{get, post, HttpRequest, HttpResponse, Responder};
use actix_web::web::{Data, Json, Path, Query};
use mongodb::bson::oid::ObjectId;
use crate::models::otp::{OtpIssued, OtpVerificationRequest, OtpVerificationResponse};
use crate::models::response::AuthResponseError;
use crate::models::users::{UserServiceIdQuery, UserServiceResponse};
use crate::services::database::Database;
use crate::services::jwt::{generate_jwt, validate_jwt};
use actix_web::cookie::{Cookie, SameSite};

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


#[post("api/verify/otp")]
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
    service: Path<String>,
    service_id: Path<String>,
) -> impl Responder {
    let service = service.into_inner();
    let service_id = service_id.into_inner();
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