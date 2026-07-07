use slipstream_core::test_support::FailureCounter;
use std::sync::Mutex;

pub(super) const FORCED_ADD_TO_STREAM_ERROR: i32 = -1;
pub(super) const FORCED_MARK_ACTIVE_STREAM_ERROR: i32 = 0x400 + 36;
pub(super) static ADD_TO_STREAM_FAILS_LEFT: FailureCounter = FailureCounter::new();
pub(super) static MARK_ACTIVE_STREAM_FAILS_LEFT: FailureCounter = FailureCounter::new();
/// `ADD_TO_STREAM_FAILS_LEFT` is process-global; tests run on separate threads by default, so any
/// two tests that both call `set_add_to_stream_failures` can race and steal each other's forced
/// failure. Hold this for the whole set-up/exercise/assert span in any such test.
pub(super) static ADD_TO_STREAM_FAILS_TEST_LOCK: Mutex<()> = Mutex::new(());

pub(super) fn set_add_to_stream_failures(count: usize) {
    ADD_TO_STREAM_FAILS_LEFT.set(count);
}

pub(super) fn set_mark_active_stream_failures(count: usize) {
    MARK_ACTIVE_STREAM_FAILS_LEFT.set(count);
}

pub(super) fn take_add_to_stream_failure() -> bool {
    ADD_TO_STREAM_FAILS_LEFT.take()
}

pub(super) fn take_mark_active_stream_failure() -> bool {
    MARK_ACTIVE_STREAM_FAILS_LEFT.take()
}
