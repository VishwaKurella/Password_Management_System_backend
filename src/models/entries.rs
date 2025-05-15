use mongodb::bson::{oid::ObjectId,DateTime};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Entries {
    pub _id: ObjectId,
    user_id: ObjectId,
    pub data: String,
    pub nonce: String,
    created_at: DateTime,
    updated_at: DateTime,
}

impl Entries {
    pub fn new(user_id: ObjectId, data: String, nonce: String,) -> Self {
        Self{
            _id: ObjectId::new(),
            user_id,
            data,
            nonce,
            created_at: DateTime::now(),
            updated_at: DateTime::now(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ReducedEntries {
    pub _id: ObjectId,
    pub data: String,
    pub nonce: String,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct UserEntriesResponse {
    pub success: bool,
    pub entries: Option<Vec<ReducedEntries>>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct UserCreateEntriesRequest {
    pub data: String,
    pub nonce: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserCreateEntriesResponse {
    pub success: bool,
    pub message: String,
    pub is_expired: bool,
    pub id: String,
}