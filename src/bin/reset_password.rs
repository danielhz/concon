//! Reset a user's password.
//! Usage: ./target/release/reset_password <username> <new_password>

use oxigraph::store::Store;

use concon::auth;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: reset_password <username> <new_password>");
        std::process::exit(1);
    }
    let username = &args[1];
    let new_password = &args[2];

    let store = Store::open("data/system").expect("Failed to open system store");

    // The username is matched as a literal value through the model API, so
    // an account whose name predates the username rule can still be reset.
    let Some((user_iri, _)) = auth::find_user_by_username(&store, username) else {
        eprintln!("User '{}' not found", username);
        std::process::exit(1);
    };
    let hash = auth::hash_password(new_password);
    auth::update_password_hash(&store, &user_iri, &hash).expect("update password");
    println!("Password reset for {}", username);
}
