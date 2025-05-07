use actix_web::{post, Responder};
use actix_web::web::{Data, Json};
use crate::models::otp::OtpVerificationRequest;
use crate::services::database::Database;





#[post("api/otp/verify")]
pub async fn verify_otp(db:Data<Database>,otp: Json<OtpVerificationRequest>) -> impl Responder {
    let otp = otp.into_inner();
    match db.
}

#[post("/api/verify/otpAllow")]
async fn verify_otp_allow(db: Data<Database>, otp_id: Json<>) -> impl Responder {

}
