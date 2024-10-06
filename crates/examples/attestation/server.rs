// This example demonstrates how to use the Prover to acquire an attestation for
// an HTTP request sent to example.com. The attestation and secrets are saved to
// disk.
use std::ops::Deref;
use std::str::FromStr;
use std::time::Duration;
use actix_cors::Cors;
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
use tlsn_core::{attestation, request::RequestConfig, transcript::TranscriptCommitConfig, CryptoProvider, Secrets};
use tlsn_core::attestation::Attestation;
use tlsn_core::presentation::{Presentation, PresentationOutput};
use tlsn_core::signing::VerifyingKey;
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
        let cors = Cors::permissive();

        App::new()
            .wrap(cors)
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
    secret:String,
}

#[derive(Deserialize,Serialize)]
struct ProveResponse {
    presentation: Vec<u8>,
    response:String
}

#[post("/prove-oanda")]
async fn prove_route(
    // state: web::Data<State>,
    // params: web::Query<Params>,
    body:web::Json<ProveRequest>,
) -> actix_web::Result<impl Responder> {
    let attestation = prove(&body.url,&body.secret).await;
    Ok(web::Json(attestation))
}



async fn prove(url:&str,secret:&str)  -> ProveResponse {
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
        .header("Authorization", format!("Bearer {secret}"))
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



    // Parse the HTTP transcript.
    let transcript = HttpTranscript::parse(secrets.transcript()).unwrap();

    // Build a transcript proof.
    let mut builder = secrets.transcript_proof_builder();

    let request = &transcript.requests[0];
    // Reveal the structure of the request without the headers or body.
    builder.reveal_sent(&request.without_data()).unwrap();
    // Reveal the request target.
    builder.reveal_sent(&request.request.target).unwrap();
    // Reveal all headers except the value of the User-Agent header.
    for header in &request.headers {
        if !header.name.as_str().eq_ignore_ascii_case("User-Agent") {
            builder.reveal_sent(header).unwrap();
        } else if !header.name.as_str().eq_ignore_ascii_case("authorization") {
            builder.reveal_sent(header).unwrap();
        } else {
            builder.reveal_sent(&header.without_value()).unwrap();
        }
    }
    // Reveal the entire response.
    builder.reveal_recv(&transcript.responses[0]).unwrap();

    let transcript_proof = builder.build().unwrap();

    // Use default crypto provider to build the presentation.
    let provider = CryptoProvider::default();

    let mut builder = attestation.presentation_builder(&provider);

    builder
        .identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof);

    let presentation: Presentation = builder.build().unwrap();

    let presentation_bytes = serde_json::to_vec(&presentation).unwrap();

    let provider = CryptoProvider::default();

    let VerifyingKey {
        alg,
        data: key_data,
    } = presentation.verifying_key();

    println!(
        "Verifying presentation with {alg} key: {}\n\n**Ask yourself, do you trust this key?**\n",
        hex::encode(key_data)
    );

    // Verify the presentation.
    let PresentationOutput {
        server_name,
        connection_info,
        transcript,
        ..
    } = presentation.verify(&provider).unwrap();

    // The time at which the connection was started.
    let time = chrono::DateTime::UNIX_EPOCH + Duration::from_secs(connection_info.time);
    let server_name = server_name.unwrap();
    let mut partial_transcript = transcript.unwrap();
    // Set the unauthenticated bytes so they are distinguishable.
    partial_transcript.set_unauthed(b'X');

    let sent = String::from_utf8_lossy(partial_transcript.sent_unsafe());
    let recv = String::from_utf8_lossy(partial_transcript.received_unsafe());

    let mut resp = "".to_string();
    println!("-------------------------------------------------------------------");
    resp.push_str("-------------------------------------------------------------------");
    println!(
        "Successfully verified that the data below came from a session with {server_name} at {time}.",
    );
    resp.push_str(
        "Successfully verified that the data below came from a session with {server_name} at {time}.",
    );
    println!("Note that the data which the Prover chose not to disclose are shown as X.\n");
    resp.push_str("Note that the data which the Prover chose not to disclose are shown as X.\n");
    println!("Data sent:\n");
    resp.push_str("Data sent:\n");
    println!("{}\n", sent);
    resp.push_str(&format!("{}\n", sent));
    println!("Data received:\n");
    resp.push_str("Data received:\n");
    println!("{}\n", recv);
    resp.push_str(&format!("{}\n", recv));
    println!("-------------------------------------------------------------------");
    resp.push_str("-------------------------------------------------------------------");


    ProveResponse {
        presentation:presentation_bytes,
        response:resp
    }
}

