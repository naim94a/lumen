use std::net::SocketAddr;

use warp::{self, Filter};
use common::{SharedState, web::api::api_root};

pub async fn start_webserver<A: Into<SocketAddr> + 'static>(bind_addr: A, shared_state: SharedState) {
    let root = warp::get()
        .and(warp::path::end())
        .map(|| warp::reply::html(include_str!("home.html")));
    
    let api = warp::path("api")
        .and(api_root(shared_state));
    
    let routes = root
        .or(api);
    
    warp::serve(routes)
        .run(bind_addr).await;
}
