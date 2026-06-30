//! Arrow type mapping for the `mft` worker: the §B `read_mft` timeline schema +
//! its row builder, and the nested `STRUCT` the `mft_record` scalar returns.

use std::collections::HashMap;
use std::sync::Arc;

use arrow_array::builder::{
    BinaryBuilder, BooleanBuilder, StringBuilder, TimestampMicrosecondBuilder, UInt16Builder,
    UInt32Builder, UInt64Builder,
};
use arrow_array::{ArrayRef, ListArray, RecordBatch, StructArray};
use arrow_buffer::OffsetBuffer;
use arrow_schema::{DataType, Field, Fields, Schema, SchemaRef, TimeUnit};
use mft_core::{timestomp, DecodedRecord, Macb};
use vgi_rpc::{Result, RpcError};

/// Microsecond timestamp type (DuckDB `TIMESTAMP`).
fn ts() -> DataType {
    DataType::Timestamp(TimeUnit::Microsecond, None)
}

/// A field carrying a `comment` (surfaced via `duckdb_columns().comment`).
fn commented(name: &str, dt: DataType, nullable: bool, comment: &str) -> Field {
    Field::new(name, dt, nullable).with_metadata(HashMap::from([(
        "comment".to_string(),
        comment.to_string(),
    )]))
}

/// The wide §B timeline schema returned by `read_mft` — one row per FILE record
/// (allocated and deleted-but-resident), with both MACB quads as first-class
/// columns so the timestomp hunt is pure SQL.
pub fn timeline_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        commented("host", DataType::Utf8, true, "Collection scope — the source host id supplied via `host :=` (or derived from `filename` under a glob); keeps paths and parents from colliding across hosts."),
        commented("entry", DataType::UInt64, false, "MFT record number (index into the table)."),
        commented("sequence", DataType::UInt16, false, "Record sequence (reuse counter); with `entry` forms the file reference."),
        commented("parent_entry", DataType::UInt64, true, "Parent directory's MFT entry, from the primary $FILE_NAME."),
        commented("full_path", DataType::Utf8, true, "Reconstructed path; `\\$Orphan\\…` / `\\$Cycle\\…` when unresolved."),
        commented("file_name", DataType::Utf8, true, "Primary (Win32) name component."),
        commented("is_dir", DataType::Boolean, false, "Header DIRECTORY flag (0x02)."),
        commented("is_allocated", DataType::Boolean, false, "Header IN_USE flag (0x01) set — a live file."),
        commented("is_deleted", DataType::Boolean, false, "NOT is_allocated — resident but slot freed (recoverable artifact)."),
        commented("si_created", ts(), true, "$STANDARD_INFORMATION Born (created)."),
        commented("si_modified", ts(), true, "$STANDARD_INFORMATION Modified."),
        commented("si_accessed", ts(), true, "$STANDARD_INFORMATION Accessed."),
        commented("si_mft_modified", ts(), true, "$STANDARD_INFORMATION Changed (MFT-modified)."),
        commented("fn_created", ts(), true, "$FILE_NAME Born (created)."),
        commented("fn_modified", ts(), true, "$FILE_NAME Modified."),
        commented("fn_accessed", ts(), true, "$FILE_NAME Accessed."),
        commented("fn_mft_modified", ts(), true, "$FILE_NAME Changed (MFT-modified)."),
        commented("logical_size", DataType::UInt64, false, "Actual data size (unnamed $DATA logical length)."),
        commented("physical_size", DataType::UInt64, false, "Allocated/on-disk size (cluster-rounded)."),
        commented("hard_link_count", DataType::UInt16, false, "Header hard-link count; >1 ⇒ multiple names/links."),
        commented("dos_attributes", DataType::UInt32, false, "SI DOS file-attribute bitmask (hidden/system/readonly/…)."),
        commented("ads_name", DataType::Utf8, true, "Name of a non-default $DATA stream (ADS); NULL for the primary stream."),
        commented("resident_data", DataType::Binary, true, "Inline content when the unnamed $DATA is resident; NULL if non-resident."),
        commented("is_timestomp_suspect", DataType::Boolean, false, "Convenience flag = timestomp(si, fn).suspect (§A.6)."),
        commented("diagnostics", DataType::Utf8, true, "NULL on a clean parse; else fixup-mismatch, baad, orphan-parent, cycle, attr-overflow, attr-overrun, truncated, decode-error:<detail>."),
    ]))
}

/// One emitted timeline row (the producer fans a record into 1..N of these,
/// per `mode`).
pub struct EmitRow {
    pub host: Option<String>,
    pub entry: u64,
    pub sequence: u16,
    pub parent_entry: Option<u64>,
    pub full_path: Option<String>,
    pub file_name: Option<String>,
    pub is_dir: bool,
    pub is_allocated: bool,
    pub si: Macb,
    pub fna: Macb,
    pub logical_size: u64,
    pub physical_size: u64,
    pub hard_link_count: u16,
    pub dos_attributes: u32,
    pub ads_name: Option<String>,
    pub resident_data: Option<Vec<u8>>,
    pub diagnostics: Option<String>,
}

/// Build a §B timeline `RecordBatch` from emitted rows.
pub fn build_timeline_batch(schema: &SchemaRef, rows: &[EmitRow]) -> Result<RecordBatch> {
    let n = rows.len();
    let mut host = StringBuilder::new();
    let mut entry = UInt64Builder::with_capacity(n);
    let mut sequence = UInt16Builder::with_capacity(n);
    let mut parent = UInt64Builder::with_capacity(n);
    let mut full_path = StringBuilder::new();
    let mut file_name = StringBuilder::new();
    let mut is_dir = BooleanBuilder::with_capacity(n);
    let mut is_alloc = BooleanBuilder::with_capacity(n);
    let mut is_del = BooleanBuilder::with_capacity(n);
    let mut si_c = TimestampMicrosecondBuilder::with_capacity(n);
    let mut si_m = TimestampMicrosecondBuilder::with_capacity(n);
    let mut si_a = TimestampMicrosecondBuilder::with_capacity(n);
    let mut si_r = TimestampMicrosecondBuilder::with_capacity(n);
    let mut fn_c = TimestampMicrosecondBuilder::with_capacity(n);
    let mut fn_m = TimestampMicrosecondBuilder::with_capacity(n);
    let mut fn_a = TimestampMicrosecondBuilder::with_capacity(n);
    let mut fn_r = TimestampMicrosecondBuilder::with_capacity(n);
    let mut logical = UInt64Builder::with_capacity(n);
    let mut physical = UInt64Builder::with_capacity(n);
    let mut hard_links = UInt16Builder::with_capacity(n);
    let mut dos = UInt32Builder::with_capacity(n);
    let mut ads = StringBuilder::new();
    let mut resident = BinaryBuilder::new();
    let mut suspect = BooleanBuilder::with_capacity(n);
    let mut diag = StringBuilder::new();

    for r in rows {
        host.append_option(r.host.as_deref());
        entry.append_value(r.entry);
        sequence.append_value(r.sequence);
        parent.append_option(r.parent_entry);
        full_path.append_option(r.full_path.as_deref());
        file_name.append_option(r.file_name.as_deref());
        is_dir.append_value(r.is_dir);
        is_alloc.append_value(r.is_allocated);
        is_del.append_value(!r.is_allocated);
        si_c.append_option(r.si.created);
        si_m.append_option(r.si.modified);
        si_a.append_option(r.si.accessed);
        si_r.append_option(r.si.mft_modified);
        fn_c.append_option(r.fna.created);
        fn_m.append_option(r.fna.modified);
        fn_a.append_option(r.fna.accessed);
        fn_r.append_option(r.fna.mft_modified);
        logical.append_value(r.logical_size);
        physical.append_value(r.physical_size);
        hard_links.append_value(r.hard_link_count);
        dos.append_value(r.dos_attributes);
        ads.append_option(r.ads_name.as_deref());
        match &r.resident_data {
            Some(b) => resident.append_value(b),
            None => resident.append_null(),
        }
        suspect.append_value(timestomp(&r.si, &r.fna).suspect);
        diag.append_option(r.diagnostics.as_deref());
    }

    let columns: Vec<ArrayRef> = vec![
        Arc::new(host.finish()),
        Arc::new(entry.finish()),
        Arc::new(sequence.finish()),
        Arc::new(parent.finish()),
        Arc::new(full_path.finish()),
        Arc::new(file_name.finish()),
        Arc::new(is_dir.finish()),
        Arc::new(is_alloc.finish()),
        Arc::new(is_del.finish()),
        Arc::new(si_c.finish()),
        Arc::new(si_m.finish()),
        Arc::new(si_a.finish()),
        Arc::new(si_r.finish()),
        Arc::new(fn_c.finish()),
        Arc::new(fn_m.finish()),
        Arc::new(fn_a.finish()),
        Arc::new(fn_r.finish()),
        Arc::new(logical.finish()),
        Arc::new(physical.finish()),
        Arc::new(hard_links.finish()),
        Arc::new(dos.finish()),
        Arc::new(ads.finish()),
        Arc::new(resident.finish()),
        Arc::new(suspect.finish()),
        Arc::new(diag.finish()),
    ];
    RecordBatch::try_new(schema.clone(), columns)
        .map_err(|e| RpcError::runtime_error(e.to_string()))
}

// ---------------------------------------------------------------------------
// mft_record STRUCT
// ---------------------------------------------------------------------------

fn si_fields() -> Fields {
    Fields::from(vec![
        Field::new("created", ts(), true),
        Field::new("modified", ts(), true),
        Field::new("accessed", ts(), true),
        Field::new("mft_modified", ts(), true),
        Field::new("dos_attr", DataType::UInt32, true),
        Field::new("usn", DataType::UInt64, true),
    ])
}

fn fn_item_fields() -> Fields {
    Fields::from(vec![
        Field::new("name", DataType::Utf8, true),
        Field::new("namespace", DataType::Utf8, true),
        Field::new("parent_entry", DataType::UInt64, true),
        Field::new("parent_seq", DataType::UInt16, true),
        Field::new("created", ts(), true),
        Field::new("modified", ts(), true),
        Field::new("accessed", ts(), true),
        Field::new("mft_modified", ts(), true),
        Field::new("logical_size", DataType::UInt64, true),
        Field::new("physical_size", DataType::UInt64, true),
    ])
}

fn data_fields() -> Fields {
    Fields::from(vec![
        Field::new("resident", DataType::Boolean, true),
        Field::new("logical_size", DataType::UInt64, true),
        Field::new("physical_size", DataType::UInt64, true),
        Field::new("resident_bytes", DataType::Binary, true),
    ])
}

fn ads_item_fields() -> Fields {
    Fields::from(vec![
        Field::new("name", DataType::Utf8, true),
        Field::new("logical_size", DataType::UInt64, true),
        Field::new("resident", DataType::Boolean, true),
    ])
}

fn attr_item_fields() -> Fields {
    Fields::from(vec![
        Field::new("type_id", DataType::UInt32, true),
        Field::new("type_name", DataType::Utf8, true),
        Field::new("resident", DataType::Boolean, true),
        Field::new("name", DataType::Utf8, true),
    ])
}

fn list_of(item: Fields) -> DataType {
    DataType::List(Arc::new(Field::new("item", DataType::Struct(item), true)))
}

/// The full `STRUCT` type the `mft_record` scalar returns.
pub fn mft_record_fields() -> Fields {
    Fields::from(vec![
        Field::new("entry", DataType::UInt64, false),
        Field::new("sequence", DataType::UInt16, false),
        Field::new("in_use", DataType::Boolean, false),
        Field::new("is_dir", DataType::Boolean, false),
        Field::new("base_ref", DataType::UInt64, false),
        Field::new("lsn", DataType::UInt64, false),
        Field::new("hard_links", DataType::UInt16, false),
        Field::new("si", DataType::Struct(si_fields()), true),
        Field::new("fn", list_of(fn_item_fields()), true),
        Field::new("data", DataType::Struct(data_fields()), true),
        Field::new("ads", list_of(ads_item_fields()), true),
        Field::new("attributes", list_of(attr_item_fields()), true),
    ])
}

pub fn mft_record_type() -> DataType {
    DataType::Struct(mft_record_fields())
}

/// Build the `mft_record` `StructArray` (one element per input row; `None` =
/// SQL `NULL` struct for an empty / unparseable slot).
pub fn build_mft_record_array(records: &[Option<DecodedRecord>]) -> Result<ArrayRef> {
    let n = records.len();
    let mut entry = UInt64Builder::with_capacity(n);
    let mut sequence = UInt16Builder::with_capacity(n);
    let mut in_use = BooleanBuilder::with_capacity(n);
    let mut is_dir = BooleanBuilder::with_capacity(n);
    let mut base_ref = UInt64Builder::with_capacity(n);
    let mut lsn = UInt64Builder::with_capacity(n);
    let mut hard_links = UInt16Builder::with_capacity(n);
    let mut struct_validity: Vec<bool> = Vec::with_capacity(n);

    // si child accumulators
    let (mut si_c, mut si_m, mut si_a, mut si_r) = (
        TimestampMicrosecondBuilder::new(),
        TimestampMicrosecondBuilder::new(),
        TimestampMicrosecondBuilder::new(),
        TimestampMicrosecondBuilder::new(),
    );
    let mut si_dos = UInt32Builder::new();
    let mut si_usn = UInt64Builder::new();
    let mut si_validity: Vec<bool> = Vec::with_capacity(n);

    // data child accumulators
    let mut d_res = BooleanBuilder::new();
    let mut d_log = UInt64Builder::new();
    let mut d_phy = UInt64Builder::new();
    let mut d_bytes = BinaryBuilder::new();
    let mut d_validity: Vec<bool> = Vec::with_capacity(n);

    // fn list flat accumulators
    let mut fn_flat = FnFlat::default();
    let mut fn_offsets: Vec<i32> = vec![0];
    let mut fn_validity: Vec<bool> = Vec::with_capacity(n);

    // ads list flat accumulators
    let mut ads_flat = AdsFlat::default();
    let mut ads_offsets: Vec<i32> = vec![0];
    let mut ads_validity: Vec<bool> = Vec::with_capacity(n);

    // attributes list flat accumulators
    let mut attr_flat = AttrFlat::default();
    let mut attr_offsets: Vec<i32> = vec![0];
    let mut attr_validity: Vec<bool> = Vec::with_capacity(n);

    for rec in records {
        match rec {
            None => {
                entry.append_value(0);
                sequence.append_value(0);
                in_use.append_value(false);
                is_dir.append_value(false);
                base_ref.append_value(0);
                lsn.append_value(0);
                hard_links.append_value(0);
                struct_validity.push(false);
                push_si(
                    &mut si_c,
                    &mut si_m,
                    &mut si_a,
                    &mut si_r,
                    &mut si_dos,
                    &mut si_usn,
                    None,
                );
                si_validity.push(false);
                push_data(&mut d_res, &mut d_log, &mut d_phy, &mut d_bytes, None);
                d_validity.push(false);
                fn_offsets.push(fn_flat.len());
                fn_validity.push(false);
                ads_offsets.push(ads_flat.len());
                ads_validity.push(false);
                attr_offsets.push(attr_flat.len());
                attr_validity.push(false);
            }
            Some(r) => {
                entry.append_value(r.entry);
                sequence.append_value(r.sequence);
                in_use.append_value(r.in_use);
                is_dir.append_value(r.is_dir);
                base_ref.append_value(r.base_ref);
                lsn.append_value(r.lsn);
                hard_links.append_value(r.hard_link_count);
                struct_validity.push(true);

                push_si(
                    &mut si_c,
                    &mut si_m,
                    &mut si_a,
                    &mut si_r,
                    &mut si_dos,
                    &mut si_usn,
                    r.standard_info.as_ref(),
                );
                si_validity.push(r.standard_info.is_some());

                push_data(
                    &mut d_res,
                    &mut d_log,
                    &mut d_phy,
                    &mut d_bytes,
                    r.data.primary.as_ref(),
                );
                d_validity.push(r.data.primary.is_some());

                for f in &r.file_names {
                    fn_flat.push(f);
                }
                fn_offsets.push(fn_flat.len());
                fn_validity.push(true);

                for a in &r.data.ads {
                    ads_flat.push(a);
                }
                ads_offsets.push(ads_flat.len());
                ads_validity.push(true);

                for a in &r.attributes {
                    attr_flat.push(a);
                }
                attr_offsets.push(attr_flat.len());
                attr_validity.push(true);
            }
        }
    }

    // Assemble the si child struct.
    let si_struct = StructArray::new(
        si_fields(),
        vec![
            Arc::new(si_c.finish()),
            Arc::new(si_m.finish()),
            Arc::new(si_a.finish()),
            Arc::new(si_r.finish()),
            Arc::new(si_dos.finish()),
            Arc::new(si_usn.finish()),
        ],
        Some(si_validity.into()),
    );

    let data_struct = StructArray::new(
        data_fields(),
        vec![
            Arc::new(d_res.finish()),
            Arc::new(d_log.finish()),
            Arc::new(d_phy.finish()),
            Arc::new(d_bytes.finish()),
        ],
        Some(d_validity.into()),
    );

    let fn_list = fn_flat.finish_list(fn_offsets, fn_validity);
    let ads_list = ads_flat.finish_list(ads_offsets, ads_validity);
    let attr_list = attr_flat.finish_list(attr_offsets, attr_validity);

    let top = StructArray::new(
        mft_record_fields(),
        vec![
            Arc::new(entry.finish()),
            Arc::new(sequence.finish()),
            Arc::new(in_use.finish()),
            Arc::new(is_dir.finish()),
            Arc::new(base_ref.finish()),
            Arc::new(lsn.finish()),
            Arc::new(hard_links.finish()),
            Arc::new(si_struct),
            fn_list,
            Arc::new(data_struct),
            ads_list,
            attr_list,
        ],
        Some(struct_validity.into()),
    );
    Ok(Arc::new(top))
}

#[allow(clippy::too_many_arguments)]
fn push_si(
    c: &mut TimestampMicrosecondBuilder,
    m: &mut TimestampMicrosecondBuilder,
    a: &mut TimestampMicrosecondBuilder,
    r: &mut TimestampMicrosecondBuilder,
    dos: &mut UInt32Builder,
    usn: &mut UInt64Builder,
    si: Option<&mft_core::StandardInfo>,
) {
    match si {
        Some(s) => {
            c.append_option(s.macb.created);
            m.append_option(s.macb.modified);
            a.append_option(s.macb.accessed);
            r.append_option(s.macb.mft_modified);
            dos.append_value(s.dos_attributes);
            usn.append_value(s.usn);
        }
        None => {
            c.append_null();
            m.append_null();
            a.append_null();
            r.append_null();
            dos.append_null();
            usn.append_null();
        }
    }
}

fn push_data(
    res: &mut BooleanBuilder,
    log: &mut UInt64Builder,
    phy: &mut UInt64Builder,
    bytes: &mut BinaryBuilder,
    d: Option<&mft_core::DataStream>,
) {
    match d {
        Some(s) => {
            res.append_value(s.resident);
            log.append_value(s.logical_size);
            phy.append_value(s.physical_size);
            match &s.data {
                Some(b) => bytes.append_value(b),
                None => bytes.append_null(),
            }
        }
        None => {
            res.append_null();
            log.append_null();
            phy.append_null();
            bytes.append_null();
        }
    }
}

#[derive(Default)]
struct FnFlat {
    name: StringBuilder,
    namespace: StringBuilder,
    parent: UInt64Builder,
    parent_seq: UInt16Builder,
    c: TimestampMicrosecondBuilder,
    m: TimestampMicrosecondBuilder,
    a: TimestampMicrosecondBuilder,
    r: TimestampMicrosecondBuilder,
    logical: UInt64Builder,
    physical: UInt64Builder,
    len: i32,
}

impl FnFlat {
    fn len(&self) -> i32 {
        self.len
    }
    fn push(&mut self, f: &mft_core::FileName) {
        self.name.append_value(&f.name);
        self.namespace.append_value(f.namespace.as_str());
        self.parent.append_value(f.parent_entry);
        self.parent_seq.append_value(f.parent_seq);
        self.c.append_option(f.macb.created);
        self.m.append_option(f.macb.modified);
        self.a.append_option(f.macb.accessed);
        self.r.append_option(f.macb.mft_modified);
        self.logical.append_value(f.logical_size);
        self.physical.append_value(f.physical_size);
        self.len += 1;
    }
    fn finish_list(mut self, offsets: Vec<i32>, validity: Vec<bool>) -> ArrayRef {
        let values = StructArray::new(
            fn_item_fields(),
            vec![
                Arc::new(self.name.finish()),
                Arc::new(self.namespace.finish()),
                Arc::new(self.parent.finish()),
                Arc::new(self.parent_seq.finish()),
                Arc::new(self.c.finish()),
                Arc::new(self.m.finish()),
                Arc::new(self.a.finish()),
                Arc::new(self.r.finish()),
                Arc::new(self.logical.finish()),
                Arc::new(self.physical.finish()),
            ],
            None,
        );
        list_from(fn_item_fields(), offsets, Arc::new(values), validity)
    }
}

#[derive(Default)]
struct AdsFlat {
    name: StringBuilder,
    logical: UInt64Builder,
    resident: BooleanBuilder,
    len: i32,
}

impl AdsFlat {
    fn len(&self) -> i32 {
        self.len
    }
    fn push(&mut self, a: &mft_core::DataStream) {
        self.name.append_option(a.name.as_deref());
        self.logical.append_value(a.logical_size);
        self.resident.append_value(a.resident);
        self.len += 1;
    }
    fn finish_list(mut self, offsets: Vec<i32>, validity: Vec<bool>) -> ArrayRef {
        let values = StructArray::new(
            ads_item_fields(),
            vec![
                Arc::new(self.name.finish()),
                Arc::new(self.logical.finish()),
                Arc::new(self.resident.finish()),
            ],
            None,
        );
        list_from(ads_item_fields(), offsets, Arc::new(values), validity)
    }
}

#[derive(Default)]
struct AttrFlat {
    type_id: UInt32Builder,
    type_name: StringBuilder,
    resident: BooleanBuilder,
    name: StringBuilder,
    len: i32,
}

impl AttrFlat {
    fn len(&self) -> i32 {
        self.len
    }
    fn push(&mut self, a: &mft_core::AttrInfo) {
        self.type_id.append_value(a.type_id);
        self.type_name.append_value(&a.type_name);
        self.resident.append_value(a.resident);
        self.name.append_option(a.name.as_deref());
        self.len += 1;
    }
    fn finish_list(mut self, offsets: Vec<i32>, validity: Vec<bool>) -> ArrayRef {
        let values = StructArray::new(
            attr_item_fields(),
            vec![
                Arc::new(self.type_id.finish()),
                Arc::new(self.type_name.finish()),
                Arc::new(self.resident.finish()),
                Arc::new(self.name.finish()),
            ],
            None,
        );
        list_from(attr_item_fields(), offsets, Arc::new(values), validity)
    }
}

/// Wrap a flat values `StructArray` + offsets into a `LIST<STRUCT>` array with
/// per-row null validity.
fn list_from(item: Fields, offsets: Vec<i32>, values: ArrayRef, validity: Vec<bool>) -> ArrayRef {
    let field = Arc::new(Field::new("item", DataType::Struct(item), true));
    let offsets = OffsetBuffer::new(offsets.into());
    Arc::new(ListArray::new(
        field,
        offsets,
        values,
        Some(validity.into()),
    ))
}
