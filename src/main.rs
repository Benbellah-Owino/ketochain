use ketochain::wallet::Wallet;
use tracing::{info,trace, debug,warn, error, span, Level };
use tracing::subscriber;
fn main() {
    // #region:     -- Setup 
    tracing_subscriber::fmt().with_max_level(Level::DEBUG).init();// stdout is now subscribed to our logs
    // #endregion:  -- Setup 

    info!("Welcome to Keto chain");

    let wallet = Wallet::new("password");
    let address = wallet.get_address();
    debug!("Address is {address}");
}

    // #region:     -- 
    // #endregion:  -- 
