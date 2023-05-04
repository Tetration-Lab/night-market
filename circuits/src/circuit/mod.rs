/// The main circuit for the protocol, used to handle deposit, swap, lp, and withdraw.
pub mod main;

/// The migration circuit for the protocol, used to handle migration between the main circuit of
/// set of fixed asset to another set of fixed asset.
pub mod migration;

/// The helper gadgets used in the protocol.
pub mod gadgets;
