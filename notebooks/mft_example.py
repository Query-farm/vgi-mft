"""Presentation for authored NTFS fixture review; all analysis stays in SQL."""

import hashlib
import json
from pathlib import Path

import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.colors import ListedColormap
from vgi_notebooks import finish

SOURCE = "Source: unchanged synthetic sample.mft · VGI MFT v0.4.0 · invented records, timestamps and contents"


def verify_fixture():
    """Require the recorded immutable synthetic input bytes."""
    provenance = json.loads(Path("fixtures/provenance.json").read_text())
    if hashlib.sha256(Path("fixtures/sample.mft").read_bytes()).hexdigest() != provenance["sha256"]:
        raise ValueError("MFT fixture differs from its recorded provenance.")


def validate_scope(value):
    """Validate the allocation-filter parameter."""
    if type(value) is not bool:
        raise ValueError("INCLUDE_DELETED must be True or False.")


def validate_entry(value):
    """Keep entry comparison within the two authored subjects."""
    if type(value) is not int or value not in (22, 25):
        raise ValueError("ENTRY must be 22 or 25 for this authored comparison.")


def timeline(data, include_deleted):
    """Keep paired UTC timestamp fields and allocation labels explicit."""
    data = data.dropna(subset=["si_created_utc", "fn_created_utc"])
    fig, ax = plt.subplots(figsize=(12, 6.4))
    for i, row in enumerate(data.itertuples()):
        ax.plot([row.si_created_utc, row.fn_created_utc], [i, i], color="#c08045", linewidth=2, zorder=1)
    ax.scatter(
        data.si_created_utc,
        range(len(data)),
        marker="o",
        s=65,
        facecolors="white",
        edgecolors="#267358",
        linewidths=1.8,
        label="SI created",
        zorder=3,
    )
    ax.scatter(data.fn_created_utc, range(len(data)), marker="x", s=48, color="#243e32", label="FN created", zorder=4)
    ax.set_yticks(
        range(len(data)),
        [f"{r.file_name} [entry {r.entry}]" + (" · deleted" if r.is_deleted else "") for r in data.itertuples()],
    )
    ax.invert_yaxis()
    ax.xaxis.set_major_locator(mdates.YearLocator(2))
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y"))
    ax.set_xlabel("Creation timestamp · UTC · connector is a difference, not a lifetime")
    ax.grid(axis="y", visible=False)
    ax.margins(x=0.05, y=0.12)
    fig.legend(*ax.get_legend_handles_labels(), loc="lower center", bbox_to_anchor=(0.60, 0.76), ncol=2)
    finish(
        fig,
        "Keep the two creation-time fields visible",
        f"Deleted records included: {include_deleted} · paired timestamp rows: {len(data)}",
        SOURCE,
        name="01-creation-timeline",
    )


def signals(data):
    """Keep independent clues separate from availability and allocation."""
    columns = {
        "is_timestomp_suspect": "Worker\nflag",
        "si_creation_before_fn": "SI created\nbefore FN",
        "si_modification_before_fn": "SI modified\nbefore FN",
        "whole_second_si": "Whole-\nsecond SI",
        "all_si_equal": "All four\nSI equal",
        "has_diagnostics": "Path\ndiagnostic",
        "has_named_stream": "Named\nstream",
        "is_deleted": "Deleted",
    }
    matrix = data[list(columns)].astype(int)
    fig, ax = plt.subplots(figsize=(12.5, 6.5))
    sns.heatmap(
        matrix,
        ax=ax,
        annot=matrix.map(lambda value: "yes" if value else "—"),
        fmt="",
        vmin=0,
        vmax=1,
        cmap=ListedColormap(["#f0f2ee", "#267358"]),
        cbar=False,
        linewidths=3,
        linecolor="white",
        xticklabels=list(columns.values()),
        yticklabels=[f"{r.file_name} [entry {r.entry}]" for r in data.itertuples()],
    )
    ax.tick_params(axis="x", rotation=0, labelsize=9)
    ax.tick_params(axis="y", rotation=0, labelsize=10)
    ax.set_xlabel("")
    ax.set_ylabel("")
    finish(
        fig,
        "Keep reasons separate from record availability",
        "yes = condition present · — = absent · independent clues, not a summed score",
        SOURCE,
        name="02-review-signals",
    )


def attributes(data, entry):
    """Count attribute instances, not records or stream content bytes."""
    fig, ax = plt.subplots(figsize=(11.5, 5.6))
    bars = ax.barh(data.reference_type, data.instances, color="#267358", height=0.48)
    ax.bar_label(bars, padding=6, fmt="%d", weight="bold")
    ax.set_xlim(0, 3)
    ax.set_xticks([0, 1, 2, 3])
    ax.invert_yaxis()
    ax.set_xlabel("Attribute instances in the selected record · count")
    ax.grid(axis="y", visible=False)
    finish(
        fig,
        "One record can contain repeated attribute types",
        f"Selected entry: {entry} · {int(data.instances.sum())} instances across {len(data)} observed types",
        SOURCE,
        name="03-attribute-instances",
    )
