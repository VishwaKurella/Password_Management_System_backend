use mongodb::bson::DateTime;
use mongodb::bson::oid::ObjectId;

pub struct Otp{
    pub _id: ObjectId,
    pub secret: String,
    pub expires: DateTime,
}

pub struct OtpVerificationRequest{
    pub secret: String,
    pub email: String,
}