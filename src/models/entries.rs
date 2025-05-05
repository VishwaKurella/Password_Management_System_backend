use mongodb::bson::{oid::ObjectId,DateTime};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Entries {
    _id: ObjectId,
    user_id: ObjectId,
    data: String,
    nonce: String,
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