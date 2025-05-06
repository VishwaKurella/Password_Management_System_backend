use mongodb::{Collection, Client};
use mongodb::bson::{oid::ObjectId,doc,to_document};
use mongodb::error::Error;
use mongodb::results::{DeleteResult, InsertOneResult, UpdateResult};
use crate::models::{users::User, entries::Entries};
use crate::models::otp::Otp;
use crate::models::users::UserSignUpForm;

pub struct Database {
    users: Collection<User>,
    entries: Collection<Entries>,
    otp: Collection<Otp>,
}

impl Database {
    pub async fn init() -> Self {
        let uri= dotenv::var("URI").expect("DATABASE_URL must be set");
        println!("Connecting to {}", uri);
        let client = Client::with_uri_str(uri).await.expect("failed to initialize client");
        let db = client.database("database_rust");
        let users = db.collection("users");
        let entries = db.collection("entries");
        Self { users, entries }
    }

    pub async fn create_user(&self, user: User) -> Result<InsertOneResult, Error> {
        let result = self.users.insert_one(user).await;
        result
    }

    pub async fn delete_user_by_id(&self, user_id: ObjectId) -> Result<DeleteResult, Error> {
        let result = self.users.delete_one(doc!{ "_id": user_id }).await;
        result
    }

    pub async fn get_user_by_id(&self, user_id: ObjectId) -> Result<Option<User>, Error> {
        let result = self.users.find_one(doc!{"_id": user_id}).await;
        result
    }

    pub async fn get_user_by_email(&self, email: String)->Result<Option<User>, Error> {
        let result = self.users.find_one(doc!{"email": email}).await;
        result
    }

    pub async fn update_user(&self, user_id: ObjectId, user: UserSignUpForm) -> Result<UpdateResult, Error> {
        let mut updated_user = User::new(user.name, user.email, user.password);
        let current_user = match self.get_user_by_id(user_id).await? {
            Some(user) => user,
            _ => return Err(Error::custom(String::from("Unable to update user")))
        };
        updated_user.created_at = current_user.created_at;
        let mut user_document = to_document(&updated_user)?;
        user_document.remove("_id");
        let result = self.users.update_one(doc!{"_id": user_id},doc!{"$set": user_document}).await;
        result
    }

    pub async fn create_entries(&self, entry: Entries) -> Result<InsertOneResult, Error> {
        let result = self.entries.insert_one(entry).await;
        result
    }

    pub async fn delete_entries(&self, entries_id: ObjectId) -> Result<DeleteResult, Error> {
        let result = self.entries.delete_one(doc!{"_id": entries_id}).await;
        result
    }

    pub async fn get_entries(&self, entries_id: ObjectId) -> Result<Option<Entries>, Error> {
        let result = self.entries.find_one(doc!{"_id": entries_id}).await;
        result
    }

    pub async fn update_entries(&self, entries_id: ObjectId, entries: Entries) -> Result<UpdateResult, Error> {
        let mut entries_document = to_document(&entries)?;
        entries_document.remove("_id");
        let result = self.entries.update_one(doc!{"_id": entries_id},doc!{"$set": entries_document}).await;
        result
    }

    pub async fn
}