use lettre::{
    message::{header, Message},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Tokio1Executor,
};
use std::error::Error;
use dotenv;


pub async fn send_email(message: String, to: String) -> Result<(), Box<dyn Error>> {
    let smtp_username = dotenv::var("SMTP_USERNAME")?;
    let smtp_password = dotenv::var("SMTP_PASSWORD")?;
    let smtp_server = dotenv::var("SMTP_SERVER")?;
    let smtp_port: u16 = dotenv::var("SMTP_PORT")?.parse()?;

    let email = Message::builder()
        .from(smtp_username.parse()?)
        .to(to.parse()?)
        .subject("Your OTP Code")
        .header(header::ContentType::TEXT_PLAIN)
        .body(message)?;

    let creds = Credentials::new(smtp_username.clone(), smtp_password);
    let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp_server)?
        .port(smtp_port)
        .credentials(creds)
        .build();

    mailer.send(email).await?;
    println!("Email sent successfully!");
    Ok(())
}