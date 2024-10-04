use hyper::http::header::{ACCEPT_ENCODING, CONNECTION, AUTHORIZATION};
use hyper_tls::HttpsConnector;
use std::error::Error;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Bytes;
use hyper::Request;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Create a new HTTPS client
    let https = HttpsConnector::new();
    let client = Client::builder(TokioExecutor::new()).build::<_, Empty<Bytes>>(https);

    // Build the request
    let req = Request::builder()
        .method("GET")
        .uri("https://api-fxpractice.oanda.com/v3/accounts/101-004-5845779-004/trades")
        .header(ACCEPT_ENCODING, "identity")
        .header(CONNECTION, "close")
        .header(AUTHORIZATION, "Bearer 3487192cc456d1584a5ba92ebc2692bf-bffe1410087f02fa96fbb13df93d2b59")
        .body(Empty::<Bytes>::new())
        .unwrap();

    // Send the request and wait for the response
    let resp = client.request(req).await?;

    // Print the response status
    println!("Response status: {}", resp.status());

    // Print the response headers
    println!("Response headers: {:#?}", resp.headers());


    // Get the response body
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes().to_vec();
    let body = String::from_utf8(body_bytes.to_vec())?;

    // Print the response body
    println!("Response body: {}", body);

    Ok(())
}