use actix_web::{get, post, web, App, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[actix_web::main]
async fn main() -> std::io::Result<()>  {
    tracing_subscriber::fmt::init();

    HttpServer::new(move|| {
        App::new()
            .service(prove_route)
        // .app_data(state.clone())
        // .configure(server_config)
    })
        .bind(("127.0.0.1", 9001))?
        .run()
        .await


}


#[derive(Deserialize)]
struct Params {
    account: String,
}

#[derive(Deserialize,Serialize)]
struct ProveRequest {
    secret: String,
    account: String,
}

#[derive(Deserialize,Serialize)]
struct ProveResponse {
    attestation: Vec<u8>,
    secret: Vec<u8>,
}

#[post("/prove-oanda")]
async fn prove_route(
    // state: web::Data<State>,
    // params: web::Query<Params>,
    body:web::Json<ProveRequest>,
) -> actix_web::Result<impl Responder> {
    Ok(web::Json(json!({})))
}