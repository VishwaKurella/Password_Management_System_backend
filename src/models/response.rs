use serde::Serialize;

#[derive(Serialize)]
pub struct AuthResponseSuccess {
    pub success: bool,
    pub message: String,
    pub new_user: bool,
}

#[derive(Serialize)]
pub struct AuthResponseError {
    pub success: bool,
    pub message: String,
}