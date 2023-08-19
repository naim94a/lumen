use std::net::SocketAddr;

use log::error;
use warp::{Filter, hyper::StatusCode, reply::Response};
use common::{SharedState, web::api::api_root};

pub async fn start_webserver<A: Into<SocketAddr> + 'static>(bind_addr: A, shared_state: SharedState) {
    let root = warp::get()
        .and(warp::path::end())
        .map(|| warp::reply::html(include_str!("home.html")));

    let shared_state1 = shared_state.clone();
    let api = warp::path("api")
        .and(api_root(shared_state1));

    let metrics = warp::get().and(warp::path("metrics")).and(warp::path::end())
        .map(move || {
            let mut res = String::new();
            if let Err(err) = prometheus_client::encoding::text::encode(&mut res, &shared_state.metrics.registry) {
                error!("failed to encode metrics: {err}");
                let mut r = Response::default();
                *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                r
            } else {
                warp::reply::Response::new(res.into())
            }
        });
    
    let routes = root
        .or(api)
        .or(metrics);
    
    warp::serve(routes)
        .run(bind_addr).await;
}
