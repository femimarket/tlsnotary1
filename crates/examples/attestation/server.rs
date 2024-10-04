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
use http_body_util::Empty;
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

    let url = Url::parse(url).unwrap();

    let (prover_socket, notary_socket) = tokio::io::duplex(1 << 16);

    // Start a local simple notary service
    tokio::spawn(run_notary(notary_socket.compat()));

    // Prover configuration.
    let config = ProverConfig::builder()
        .server_name(url.host_str().unwrap())
        .protocol_config(
            ProtocolConfig::builder()
                // We must configure the amount of data we expect to exchange beforehand, which will
                // be preprocessed prior to the connection. Reducing these limits will improve
                // performance.
                .max_sent_data(1024)
                .max_recv_data(16384)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    // Create a new prover and perform necessary setup.
    let prover = Prover::new(config).setup(prover_socket.compat()).await.unwrap();

    // Open a TCP connection to the server.
    let client_socket = tokio::net::TcpStream::connect((url.host_str().unwrap(), 443)).await.unwrap();

    // Bind the prover to the server connection.
    // The returned `mpc_tls_connection` is an MPC TLS connection to the server: all
    // data written to/read from it will be encrypted/decrypted using MPC with
    // the notary.
    let (mpc_tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());

    // Spawn the prover task to be run concurrently in the background.
    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the connection.
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection).await.unwrap();

    // Spawn the HTTP task to be run concurrently in the background.
    tokio::spawn(connection);

    // Build a simple HTTP request with common headers
    let request = Request::builder()
        .uri(url.path())
        .header("Host", url.host_str().unwrap())
        .header("Accept", "*/*")
        // Using "identity" instructs the Server not to use compression for its HTTP response.
        // TLSNotary tooling does not support compression.
        .header("Accept-Encoding", "identity")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", "3487192cc456d1584a5ba92ebc2692bf-bffe1410087f02fa96fbb13df93d2b59"))
        .header("Connection", "close")
        .header("User-Agent", USER_AGENT)
        .body(Empty::<Bytes>::new())
        .unwrap();

    println!("Starting an MPC TLS connection with the server");

    // Send the request to the server and wait for the response.
    let response = request_sender.try_send_request(request).await.unwrap();

    println!("Got a response from the server");

    assert!(response.status() == StatusCode::OK);

    // The prover task should be done now, so we can await it.
    let prover = prover_task.await.unwrap().unwrap();

    // Prepare for notarization.
    let mut prover = prover.start_notarize();

    // Parse the HTTP transcript.
    let transcript = HttpTranscript::parse(prover.transcript()).unwrap();

    // Commit to the transcript.
    let mut builder = TranscriptCommitConfig::builder(prover.transcript());

    DefaultHttpCommitter::default().commit_transcript(&mut builder, &transcript).unwrap();

    prover.transcript_commit(builder.build().unwrap());

    // Request an attestation.
    let config = RequestConfig::default();

    let (attestation, secrets) = prover.finalize(&config).await.unwrap();

    let attestation_bytes = serde_json::to_vec(&attestation).unwrap();
    let secrets_bytes = serde_json::to_vec(&secrets).unwrap();
    // Write the attestation to disk.
    // tokio::fs::write(
    //     "example.attestation.tlsn",
    //     bincode::serialize(&attestation).unwrap(),
    // )
    //     .await.unwrap();

    // Write the secrets to disk.
    // tokio::fs::write("example.secrets.tlsn", bincode::serialize(&secrets).unwrap()).await.unwrap();

    println!("Notarization completed successfully!");
    println!(
        "The attestation has been written to `example.attestation.tlsn` and the \
        corresponding secrets to `example.secrets.tlsn`."
    );

    ProveResponse {
        secret:secrets_bytes,
        attestation: attestation_bytes,
    }

}