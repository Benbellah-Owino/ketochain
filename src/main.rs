use ketochain::wallet::Wallet;
use tracing::{info,trace, debug,warn, error, span, Level };
use tracing::subscriber;
use tracing_subscriber::fmt::format::FmtSpan;
fn main() {
    // #region:     -- Setup 
    tracing_subscriber::fmt()
    .with_span_events(FmtSpan::FULL)
    .with_max_level(Level::DEBUG)
    .init();// stdout is now subscribed to our logs
    // #endregion:  -- Setup 


    let wallet = Wallet::new("password").unwrap();
    let address = wallet.get_address();
    info!("Welcome to Keto chain. Your new address is {address}");
    eprintln!("{:#?}",wallet )
}

    // #region:     -- 
    // #endregion:  -- 
