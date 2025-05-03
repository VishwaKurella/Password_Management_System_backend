use mongodb::bson::{oid::ObjectId,DateTime};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct User{
    pub _id: ObjectId,
    pub name: String,
    pub email: String,
    pub password_hash: String,
    pub encryption_salt: String,
    pub master_key: String,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}


impl User{
    
}