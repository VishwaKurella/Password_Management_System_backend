use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthResponseSuccess {
    pub success: bool,
    pub message: String,
    pub new_user: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthResponseError {
    pub success: bool,
    pub message: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthSignInResponse {
    pub success: bool,
    pub message: String,
    pub is_verified: bool,
    pub _id: String,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthSignUpResponse {
    pub success: bool,
    pub message: String,
    pub _id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthIssuerResponse {
    pub success: bool,
    pub message: String,
    pub issuer: String,
}