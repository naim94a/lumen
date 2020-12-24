use crate::SharedState;
use warp::Filter;

pub mod api;

pub fn with_state(state: SharedState) -> impl Filter<Extract=(SharedState,), Error= std::convert::Infallible> + Clone {
    warp::any().map(move || state.clone())
}
