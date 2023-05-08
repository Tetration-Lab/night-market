//! Circuits and gadgets implementation

/// The main circuit for the protocol, used to handle deposit, swap, lp, and withdraw. (or other supported actions)
pub mod main;

/// The main circuit, but splitted into two parts.
pub mod main_splitted;

/// The migration circuit for the protocol, used to handle migration between the main circuit of
/// set of fixed asset to another set of fixed asset.
pub mod migration;

/// The helper gadgets used in the protocol.
pub mod gadgets;
