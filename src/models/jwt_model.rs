use serde::{Serialize, Deserialize};


#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub iat: usize,
    pub exp: usize,
    pub jti: String,
}