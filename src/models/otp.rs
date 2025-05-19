use mongodb::bson::DateTime;
use mongodb::bson::oid::ObjectId;
use rand::{rng, Rng};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Serialize, Deserialize, Debug)]
pub enum OtpIssued {
    ForResetPassword,
    ForEmailVerification,
    ForEmailUpdate,
    Invalid
}

impl fmt::Display for OtpIssued {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            OtpIssued::ForEmailVerification => "Email Verification",
            OtpIssued::ForResetPassword => "Password Reset",
            OtpIssued::ForEmailUpdate => "Email Update",
            OtpIssued::Invalid => "Invalid",

        };
        write!(f, "{}", text)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Otp{
    pub _id: ObjectId,
    pub user_id: ObjectId,
    pub secret: String,
    pub expires: DateTime,
    pub verified: bool,
    pub issued_for: OtpIssued,
    pub created_at: DateTime,
}

impl Otp {
    pub fn new(issued_for: OtpIssued, user_id: ObjectId) -> Self {
        let secret = Self::generate_secret();
        let chrono_dt = Utc::now() + Duration::minutes(6);
        let millis = chrono_dt.timestamp_millis();
        let expires = DateTime::from_millis(millis);
        Self{
            _id: ObjectId::new(),
            user_id,
            secret,
            expires,
            verified: false,
            issued_for,
            created_at: DateTime::now(),
        }
    }
    pub fn generate_secret() -> String {
        let mut rng = rng();
        let otp: u32 = rng.random_range(0..1_000_000);
        format!("{:06}", otp)
    }

    pub fn is_expired(&self) -> bool {
        DateTime::now() > self.expires
    }

    pub fn verify_secret(&self, input_secret: String) -> bool {
        !self.is_expired() && self.secret == input_secret
    }

    pub fn is_verified(&self) -> bool {
        self.verified
    }
}



#[derive(Serialize, Deserialize, Debug)]
pub struct OtpVerificationRequest{
    pub _id: String,
    pub secret: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OtpGenerationSuccess{
    pub success: bool,
    pub id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OtpVerificationResponse{
    pub success: bool,
    pub message: String,
    pub issued_for: OtpIssued,
}

pub struct OtpSessionId {
    pub _id: ObjectId,
}