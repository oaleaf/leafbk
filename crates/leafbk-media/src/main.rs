#[macro_use]
extern crate rocket;

#[launch]
fn rocket() -> _ {
    leafbk_media::build()
}
