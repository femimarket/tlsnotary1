// This example demonstrates how to use the Prover to acquire an attestation for
// an HTTP request sent to example.com. The attestation and secrets are saved to
// disk.
use std::ops::Deref;
use std::str::FromStr;
use actix_web::{post, Responder};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;
use actix_web::{web, App, HttpServer};
use http_body_util::{Empty, Full};
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use tlsn_common::config::ProtocolConfig;
use tlsn_core::{attestation, request::RequestConfig, transcript::TranscriptCommitConfig};
use tlsn_examples::run_notary;
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};
use tlsn_prover::{Prover, ProverConfig};

// Setting of the application server
const SERVER_DOMAIN: &str = "example.com";
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36";

#[actix_web::main]
async fn main() -> std::io::Result<()>  {
    tracing_subscriber::fmt::init();

    HttpServer::new(move|| {
        App::new()
            .service(prove_route)
            // .app_data(state.clone())
            // .configure(server_config)
    })
        .bind(("127.0.0.1", 9000))?
        .run()
        .await


}





#[derive(Deserialize)]
struct Params {
    broker: String,
    trade_account:String,
}

#[derive(Deserialize,Serialize)]
struct ProveRequest {
    url: String,
}

#[derive(Deserialize,Serialize)]
struct ProveResponse {
    attestation: Vec<u8>,
    secret: Vec<u8>,
}

#[post("/prove")]
async fn prove_route(
    // state: web::Data<State>,
    // params: web::Query<Params>,
    // account:web::Json<ProveRequest>,
) -> actix_web::Result<impl Responder> {
    prove("https://api-fxpractice.oanda.com/v3/accounts/101-004-5845779-004/trades").await;
    Ok(web::Json(json!({})))
}



async fn prove(url:&str)  -> ProveResponse {

    use hyper::{Client, Request, Body};
    use hyper::http::header::{ACCEPT_ENCODING, CONNECTION, AUTHORIZATION};
    use hyper_tls::HttpsConnector;
    use std::error::Error;

    #[tokio::main]
    async fn main() -> Result<(), Box<dyn Error>> {
        // Create a new HTTPS client
        let https = HttpsConnector::new();
        let client = Client::builder().build::<_, hyper::Body>(https);

        // Build the request
        let req = Request::builder()
            .method("GET")
            .uri("https://api-fxpractice.oanda.com/v3/accounts/101-004-5845779-004/trades")
            .header(ACCEPT_ENCODING, "identity")
            .header(CONNECTION, "close")
            .header(AUTHORIZATION, "Bearer 3487192cc456d1584a5ba92ebc2692bf-bffe1410087f02fa96fbb13df93d2b59")
            .body(Body::empty())?;

        // Send the request and wait for the response
        let resp = client.request(req).await?;

        // Print the response status
        println!("Response status: {}", resp.status());

        // Print the response headers
        println!("Response headers: {:#?}", resp.headers());

        // Get the response body
        let body_bytes = hyper::body::to_bytes(resp.into_body()).await?;
        let body = String::from_utf8(body_bytes.to_vec())?;

        // Print the response body
        println!("Response body: {}", body);

        Ok(())
    }

}