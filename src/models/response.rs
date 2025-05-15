use serde::{Deserialize, Serialize};
use crate::models::entries::ReducedEntries;

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

#[derive(Serialize, Deserialize, Debug)]
pub struct UserDataResponse {
    pub success: bool,
    pub message: String,
    pub id: String,
    pub name: String,
    pub salt: String,
    pub email: String,
    // pub is_expired: bool,
    pub is_master_key_set: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserSetMasterKeyRequest{
    pub master_key: String,
    pub salt: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserSetMasterKeyResponse {
    pub success: bool,
    pub message: String,
    pub is_expired: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserVerifyMasterKeyRequest{
    pub master_key: String,
}


#[derive(Serialize, Deserialize, Debug)]
pub struct UserVerifyMasterKeyResponse {
    pub success: bool,
    pub message: String,
    pub is_expired: bool,
    pub data: Vec<ReducedEntries>,
}