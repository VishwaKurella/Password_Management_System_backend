use mongodb::bson::DateTime;
use mongodb::bson::oid::ObjectId;
use rand::{rng, Rng};
use chrono::{Duration, Utc};

pub enum OtpIssued {
    ForResetPassword,
    ForEmailVerification,
    ForResetMasterKey,
}

pub struct Otp{
    pub _id: ObjectId,
    pub user_id: ObjectId,
    pub secret: String,
    pub expires: DateTime,
    pub verified: bool,
    pub issued_for: OtpIssued,
}

impl Otp {
    pub fn new(issued_for: OtpIssued, user_id: ObjectId) -> Self {
        let secret = Self::generate_secret();
        let expires = DateTime::from(Utc::now() + Duration::minutes(6));
        Self{
            _id: ObjectId::new(),
            user_id,
            secret,
            expires,
            verified: false,
            issued_for,
        }
    }
    pub fn generate_secret() -> String {
        let mut rng = rng();
        let otp: u32 = rng.random_range(0..1_000_000);
        format!("{:06}", otp)
    }
}




pub struct OtpVerificationRequest{
    pub _id: ObjectId,
    pub secret: String,

}


pub struct OtpVerificationResponse{
    pub success: bool,
    pub message: String,
    pub issued_for: OtpIssued,
}

pub struct OtpSessionId {
    pub _id: ObjectId,
}