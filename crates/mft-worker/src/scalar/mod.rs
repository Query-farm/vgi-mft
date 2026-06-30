//! Scalar functions exposed by the `mft` worker.

mod full_path;
mod mft_record;
mod record_header;
mod timestomp;
mod version;
mod well_formed;

use vgi::Worker;

/// Register every scalar function on the worker.
pub fn register(worker: &mut Worker) {
    worker.register_scalar(mft_record::MftRecord);
    worker.register_scalar(full_path::FullPath);
    worker.register_scalar(timestomp::Timestomp);
    worker.register_scalar(record_header::RecordHeaderFn);
    worker.register_scalar(well_formed::WellFormedFn);
    worker.register_scalar(version::MftVersion);
}
