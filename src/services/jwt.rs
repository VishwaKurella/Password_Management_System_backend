use jsonwebtoken::{encode, EncodingKey, Header, Validation, decode, DecodingKey, TokenData};
use crate::models::jwt_model::Claims;
use chrono::{Duration, Utc};

pub fn generate_jwt(user_id: &str, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now().timestamp() as usize;
    let exp = (Utc::now() + Duration::hours(1)).timestamp() as usize;
    let jti = uuid::Uuid::new_v4().to_string();

    let claims = Claims {
        sub: user_id.to_owned(),
        iat: now,
        exp,
        jti: jti.clone(),
    };

    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref()))
}


pub fn validate_jwt(token: &str, secret: &str) -> Result<TokenData<Claims>, jsonwebtoken::errors::Error> {
    let mut validation = Validation::default();
    validation.set_required_spec_claims(&["exp", "iat", "sub", "jti"]);

    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &validation,
    )?;
    Ok(data)
}