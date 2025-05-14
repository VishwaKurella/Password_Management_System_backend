// // use lettre::{
// //     message::{header, Message},
// //     transport::smtp::authentication::Credentials,
// //     AsyncSmtpTransport, AsyncTransport, Tokio1Executor,
// // };
// // use std::error::Error;
// // use dotenv;
// //
// //
// // pub async fn send_email(message: String, to: String) -> Result<(), Box<dyn Error>> {
// //     let smtp_username = dotenv::var("SMTP_USERNAME")?;
// //     let smtp_password = dotenv::var("SMTP_PASSWORD")?;
// //     let smtp_server = dotenv::var("SMTP_SERVER")?;
// //     let smtp_port: u16 = dotenv::var("SMTP_PORT")?.parse()?;
// //
// //     let email = Message::builder()
// //         .from(smtp_username.parse()?)
// //         .to(to.parse()?)
// //         .subject("Your OTP Code")
// //         .header(header::ContentType::TEXT_PLAIN)
// //         .body(message)?;
// //
// //     let creds = Credentials::new(smtp_username.clone(), smtp_password);
// //     let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp_server)?
// //         .port(smtp_port)
// //         .credentials(creds)
// //         .build();
// //
// //     mailer.send(email).await?;
// //     println!("Email sent successfully!");
// //     Ok(())
// // }
//
// use lettre::{
//     message::{header, Message},
//     transport::smtp::authentication::Credentials,
//     AsyncSmtpTransport, AsyncTransport, Tokio1Executor,
// };
// use std::error::Error;
// use dotenv::dotenv;
//
//
// pub async fn send_email(message: String, to: String) -> Result<(), Box<dyn Error>> {
//     dotenv().ok();
//     let smtp_username = std::env::var("SMTP_USERNAME").expect("SMTP_USERNAME not set");
//     let smtp_password = std::env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD not set");
//     let smtp_server = std::env::var("SMTP_SERVER").expect("SMTP_SERVER not set");
//     let smtp_port: u16 = std::env::var("SMTP_PORT")
//         .expect("SMTP_PORT not set")
//         .parse()
//         .unwrap();
//
//     let email = Message::builder()
//         .from(smtp_username.parse().unwrap())
//         .to(to)
//         .subject("Your OTP Code")
//         .header(header::ContentType::TEXT_PLAIN)
//         .body(format!("Your OTP code is: {}", message))
//         .unwrap();
//
//     let creds = Credentials::new(smtp_username.clone(), smtp_password);
//
//     let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp_server)
//         .unwrap()
//         .port(smtp_port)
//         .credentials(creds)
//         .build();
//
//     match mailer.send(email).await {
//         Ok(_) => println!("Email sent successfully!"),
//         Err(e) => eprintln!("Failed to send email: {e}"),
//     }
//     Ok(())
// }

use lettre::{
    message::{header, Message},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Tokio1Executor,
};
use std::error::Error;
use dotenv::dotenv;
use crate::models::otp::OtpIssued;
// pub async fn send_email(to: String, message: String) -> Result<(), Box<dyn Error>> {
//     dotenv().ok();
//     let smtp_username = std::env::var("SMTP_USERNAME").expect("SMTP_USERNAME not set");
//     let smtp_password = std::env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD not set");
//     let smtp_server = std::env::var("SMTP_SERVER").expect("SMTP_SERVER not set");
//     let smtp_port: u16 = std::env::var("SMTP_PORT")
//         .expect("SMTP_PORT not set")
//         .parse()
//         .unwrap();
//
//     let email = Message::builder()
//         .from(smtp_username.parse().unwrap())
//         .to(to.parse().unwrap())
//         .subject("Your OTP Code")
//         .header(header::ContentType::TEXT_PLAIN)
//         .body(format!("Your OTP code is: {}", message))
//         .unwrap();
//
//     let creds = Credentials::new(smtp_username.clone(), smtp_password);
//
//     let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp_server)
//         .unwrap()
//         .port(smtp_port)
//         .credentials(creds)
//         .build();
//
//     match mailer.send(email).await {
//         Ok(_) => println!("Email sent successfully!"),
//         Err(e) => eprintln!("Failed to send email: {e}"),
//     }
//     Ok(())
// }

pub async fn send_email(to: String, otp: String, otp_id: &str, issued_for: OtpIssued) -> Result<(), Box<dyn Error>> {
    // Load environment
    dotenv().ok();
    let smtp_username = std::env::var("SMTP_USERNAME").expect("SMTP_USERNAME not set");
    let smtp_password = std::env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD not set");
    let smtp_server = std::env::var("SMTP_SERVER").expect("SMTP_SERVER not set");
    let smtp_port: u16 = std::env::var("SMTP_PORT")
        .expect("SMTP_PORT not set")
        .parse()
        .expect("Invalid SMTP_PORT");

    // Build verification link
    let frontend_base = std::env::var("FRONTEND_BASE_URL").unwrap_or_else(|_| "http://localhost:3000".into());
    let verify_link = format!("{}/verify-otp/{}", frontend_base, otp_id);

    let email_body = format!(
        "This OTP was requested for: {}\n\nYour OTP code is: {}\n\nTo verify, click the link below:\n{}\n\nIf the link doesn't work, paste it into your browser.",
        issued_for, // uses Display impl
        otp,
        verify_link
    );

    // Build email message
    let email = Message::builder()
        .from(smtp_username.parse().expect("Invalid from address"))
        .to(to.parse().expect("Invalid to address"))
        .subject("Your OTP Code")
        .header(header::ContentType::TEXT_PLAIN)
        .body(email_body)
        .expect("Failed to build email message");

    // Set up credentials and mailer
    let creds = Credentials::new(smtp_username.clone(), smtp_password);
    let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp_server)
        .expect("Failed to create SMTP transport")
        .port(smtp_port)
        .credentials(creds)
        .build();

    // Send the email
    match mailer.send(email).await {
        Ok(_) => println!("Email sent successfully to {}", &to),
        Err(e) => eprintln!("Failed to send email: {}", e),
    }

    Ok(())
}
