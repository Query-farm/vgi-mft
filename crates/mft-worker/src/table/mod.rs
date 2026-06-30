//! Table functions exposed by the `mft` worker.

mod read_mft;

use vgi::Worker;

/// Register every table function on the worker.
pub fn register(worker: &mut Worker) {
    worker.register_table(read_mft::ReadMft);
}
