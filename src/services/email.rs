use dotenv::dotenv;
use lettre::message::{header, Message};
use lettre::transport::smtp::authentication::Credentials;
use lettre::AsyncSmtpTransport;
use lettre::AsyncTransport;
use lettre::Tokio1Executor;
use lettre::Transport;
use crate::models::otp::Otp;

pub async fn send_email(to: &str, otp: &str) -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    let smtp_username = std::env::var("SMTP_USERNAME").expect("SMTP_USERNAME not set");
    let smtp_password = std::env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD not set");
    let smtp_server = std::env::var("SMTP_SERVER").expect("SMTP_SERVER not set");
    let smtp_port: u16 = std::env::var("SMTP_PORT")
        .expect("SMTP_PORT not set")
        .parse()
        .unwrap();

    let email = Message::builder()
        .from(smtp_username.parse().unwrap())
        .to(to.parse().unwrap())
        .subject("Your OTP Code")
        .header(header::ContentType::TEXT_PLAIN)
        .body(format!("Your OTP code is: {}", otp))
        .unwrap();

    let creds = Credentials::new(smtp_username.clone(), smtp_password);

    let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp_server)
        .unwrap()
        .port(smtp_port)
        .credentials(creds)
        .build();

    match mailer.send(email).await {
        Ok(_) => println!("Email sent successfully!"),
        Err(e) => eprintln!("Failed to send email: {e}"),
    }
    Ok(())
}
