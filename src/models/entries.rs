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