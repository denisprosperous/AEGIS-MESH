//! Messaging module — envelopes, channels, priority.

pub mod channel;
pub mod envelope;
pub mod priority;

pub use channel::{Channel, ChannelId, ChannelMembership, ChannelRole};
pub use envelope::{Envelope, EnvelopeFlags, EnvelopeId, EnvelopeType, Payload, MAX_ENVELOPE_SIZE};
pub use priority::Priority;
