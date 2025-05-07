use mongodb::bson::{oid::ObjectId, DateTime};
use rand::RngCore;
use serde::{Serialize, Deserialize};
use bcrypt::{hash_with_salt, DEFAULT_COST};
use rand::rng;
use base64::encode;

#[derive(Serialize, Deserialize, Debug)]
pub struct User {
    pub _id: ObjectId,
    pub name: String,
    pub email: String,
    pub password_hash: Option<String>,
    //pub encryption_salt: String,
    pub verified: bool,
    pub oauth: bool,
    pub master_key: String,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

// #[derive(Serialize, Deserialize, Debug)]
// pub struct OAuthUser{
//     pub _id: ObjectId,
//     pub name: String,
//     pub email: String,
//     pub master_key: String,
//     pub provider: String,
//     pub created_at: DateTime,
//     pub updated_at: DateTime,
// }

// impl OAuthUser {
//     pub fn new(name: String, email: String, provider: String) -> Self {
//         Self{
//             _id: ObjectId::new(),
//             name,
//             email,
//             master_key: String::new(),
//             provider,
//             created_at: DateTime::now(),
//             updated_at: DateTime::now(),
//         }
//     }
// }

impl User {
    pub fn new(name: String, email: String, password: String) -> Self {
        let salt = Self::generate_salt();
        let password_hash = hash_with_salt(&password, DEFAULT_COST, &salt).unwrap().to_string();
        //let salt_str = encode(&salt);

        Self {
            _id: ObjectId::new(),
            name,
            email,
            password_hash: Some(password_hash),
            //encryption_salt: salt_str,
            verified: false,
            oauth: false,
            master_key: String::new(),
            created_at: DateTime::now(),
            updated_at: DateTime::now(),
        }
    }

    // pub fn new_oauth(name: String, email: String ) -> Self {
    //     Self{
    //         _id: ObjectId::new(),
    //         name,
    //         email,
    //         password_hash: None,
    //         oauth: true,
    //         master_key: String::new(),
    //         created_at: DateTime::now(),
    //         updated_at: DateTime::now(),
    //     }
    // }

    fn generate_salt() -> [u8; 16] {
        let mut rng = rng();
        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);
        salt
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserSignUpForm {
    pub name: String,
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserSignInForm {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserSignUpGitHubForm{
    pub name: String,
    pub email: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserSignUpGoogleForm{
    pub name: String,
    pub email: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserUpdateForm{
    pub name: String,
    pub email: String,
}

