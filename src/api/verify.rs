use actix_web::{get, post, HttpRequest, HttpResponse, Responder};
use actix_web::cookie::Cookie;
use actix_web::web::{Data, Json, Path, Query};
use crate::models::otp::{OtpIssued, OtpVerificationRequest, OtpVerificationResponse};
use crate::models::response::AuthResponseError;
use crate::models::users::{UserServiceIdQuery, UserServiceResponse};
use crate::services::database::Database;
use crate::services::jwt::validate_jwt;

#[post("api/verify/otp")]
pub async fn verify_otp(db:Data<Database>,user_form: Json<OtpVerificationRequest>) -> impl Responder {
    let user_form  = user_form.into_inner();
    match db.get_otp_by_id(user_form._id).await {
        Ok(otp) => {
            match otp {
                Some(otp) => {
                    if otp.verify_secret(user_form.secret) {
                        return HttpResponse::Ok().json(OtpVerificationResponse{
                            success: true,
                            message: "otp successfully verified".to_string(),
                            issued_for: otp.issued_for,
                        })
                    }else{
                        return HttpResponse::Ok().json(OtpVerificationResponse{
                            success: false,
                            message: "Invalid otp, please try again".to_string(),
                            issued_for: OtpIssued::Invalid
                        })
                    }
                },
                None => {
                    return HttpResponse::Unauthorized().json(AuthResponseError {
                        success: false,
                        message: "Session expired please, try again.".to_string()
                    })
                }
            }
        },
        Err(_) => {
            return HttpResponse::InternalServerError().json(AuthResponseError {
                success: false,
                message: "Server Error, Please try again".to_string()
            })
        }
    }
}

#[get("api/verify/allow/{service}")]
async fn verify_path(db:Data<Database>, service: Path<String>, service_id: Query<UserServiceIdQuery> ) -> impl Responder {
    let service = service.into_inner();
    let service_id = service_id.into_inner()._id;
    match db.get_otp_by_id(service_id).await {
        Ok(otp) => {
            match otp {
                Some(otp) => {
                    if otp.is_verified() {
                        return HttpResponse::Ok().json(UserServiceResponse{
                            success: true,
                            message: "Authorized".to_string(),
                        });
                    } else {
                        return HttpResponse::Unauthorized().json(UserServiceResponse {
                            success: false,
                            message: "OTP not verified".to_string()
                        });
                    }
                }
                None => {
                    return HttpResponse::Unauthorized().json(UserServiceResponse {
                        success: false,
                        message: "Session expired, try again".to_string()
                    });
                }
            }
        }
        Err(_) => {
            return HttpResponse::InternalServerError().json(UserServiceResponse {
                success: false,
                message: "Server Error, Please try again".to_string()
            });
        }
    }
}


#[get("/api/verify/me")]
async fn verify_me(db: Data<Database>, jwt_secret: Data<String>, req: HttpRequest) -> impl Responder {
    match req.cookie("auth_token") {
        Some(cookie) => {
            let auth_token = cookie.value().to_string();

            match validate_jwt(&auth_token, &jwt_secret) {
                Ok(_) => return HttpResponse::Ok().json(UserServiceResponse {
                    success: true,
                    message: "Token is valid.".to_string(),
                }),
                Err(_) => return HttpResponse::Unauthorized().json(UserServiceResponse {
                    success: false,
                    message: "Session expired or token is invalid.".to_string(),
                }),
            }
        },
        None => return HttpResponse::Unauthorized().json(UserServiceResponse {
            success: false,
            message: "No auth token found.".to_string(),
        }),
    }
}
