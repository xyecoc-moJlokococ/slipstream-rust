pub(crate) mod acceptor;
mod callback;
mod command_dispatch;
mod invariants;
mod io_tasks;
mod state;

#[cfg(test)]
mod test_hooks;
#[cfg(test)]
mod tests;

pub(crate) use callback::client_callback;
pub(crate) use command_dispatch::{
    drain_commands, drain_stream_data, handle_command, reap_half_closed_tcp_streams,
};
pub(crate) use state::{ClientState, Command, PathEvent};
// Re-export for tests in this module.
#[cfg(test)]
pub(crate) use state::TCP_HALF_CLOSED_MAX_US;
