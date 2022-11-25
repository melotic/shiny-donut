use std::sync::Arc;

use actix_web::{dev::ServiceRequest, error, web::Data, Error};
use actix_web_httpauth::extractors::basic::BasicAuth;

use crate::cli;

pub async fn validator(
    req: ServiceRequest,
    credentials: BasicAuth,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let data = req.app_data::<Data<Arc<cli::Security>>>();

    let data = match data {
        Some(data) => data,
        None => return Err((error::ErrorInternalServerError("No security app data"), req)),
    };

    if data.password == credentials.user_id() {
        Ok(req)
    } else {
        Err((error::ErrorUnauthorized("Invalid credentials"), req))
    }
}
