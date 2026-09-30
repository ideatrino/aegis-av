"""
aegis.archives — recursive, bomb-guarded, model-aware archive scanning
(design doc S22, S23).

A dropper travels inside a release .zip or nested .tar.gz; to the byte
detectors an archive is one opaque blob whose contents were never examined.
This walker opens zip / tar(.gz/.bz2/.xz) / gzip and yields each member as its
own sample — recursing into nested archives — while defeating a decompression
bomb: a total-output cap, a per-member size cap, a nesting-depth limit and a
member-count cap. Nothing is written to disk; nothing is executed.

Model-aware (S23): a PyTorch/Lightning checkpoint (a .pt/.ckpt zip with a
data.pkl + numbered data/<n> storages) or an all-.npy .npz is NOT descended
into as files — its tensor storage is dense data, not scannable files (a
category error that produced ~150 false positives). Only its data.pkl is
yielded, so the ML-model RCE vector (the pickle) is scanned and the weights
are skipped.
"""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import tarfile
import zipfile
from typing import Iterator, Tuple

MAX_TOTAL = 256 * 1024 * 1024      # total inflated bytes across a scan
MAX_MEMBER = 64 * 1024 * 1024      # single member cap
MAX_DEPTH = 4                      # nesting depth
MAX_MEMBERS = 5000                 # member-count cap


class _Budget:
    def __init__(self):
        self.total = 0
        self.count = 0

    def take(self, n: int) -> bool:
        if self.count >= MAX_MEMBERS:
            return False
        if self.total + n > MAX_TOTAL:
            return False
        self.total += n
        self.count += 1
        return True


def is_archive(data: bytes) -> bool:
    return (data[:4] == b"PK\x03\x04" or data[:2] == b"\x1f\x8b"
            or data[:3] == b"BZh" or data[:6] == b"\xfd7zXZ\x00"
            or data[257:262] == b"ustar")


def _is_torch_checkpoint(zf: zipfile.ZipFile) -> bool:
    names = zf.namelist()
    has_pkl = any(n.endswith("data.pkl") or n.endswith(".pkl") for n in names)
    has_storage = any("/data/" in n and n.rsplit("/", 1)[-1].isdigit() for n in names)
    return has_pkl and has_storage


def iter_members(data: bytes, name: str = "<archive>",
                 depth: int = 0, budget: _Budget = None) -> Iterator[Tuple[str, bytes]]:
    """Yield (logical_path, bytes) for each scannable member."""
    if budget is None:
        budget = _Budget()
    if depth > MAX_DEPTH:
        return
    try:
        if data[:4] == b"PK\x03\x04":
            yield from _iter_zip(data, name, depth, budget)
        elif data[:2] == b"\x1f\x8b":
            yield from _iter_gzip(data, name, depth, budget)
        elif data[:3] == b"BZh":
            body = bz2.decompress(data)
            if budget.take(len(body)):
                yield from _maybe_recurse(f"{name}::bz2", body, depth, budget)
        elif data[:6] == b"\xfd7zXZ\x00":
            body = lzma.decompress(data)
            if budget.take(len(body)):
                yield from _maybe_recurse(f"{name}::xz", body, depth, budget)
        elif data[257:262] == b"ustar":
            yield from _iter_tar(data, name, depth, budget)
    except Exception:
        # corrupt archive: fall back to scanning it as one opaque blob (S22)
        yield (name, data)


def _iter_zip(data, name, depth, budget):
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        model_aware = _is_torch_checkpoint(zf)
        for info in zf.infolist():
            if info.is_dir():
                continue
            if info.file_size > MAX_MEMBER:
                yield (f"{name}::{info.filename} (skipped: {info.file_size}B > cap)", b"")
                continue
            if model_aware:
                # only the pickle is code; tensor storage is data (S23)
                if not (info.filename.endswith("data.pkl")
                        or info.filename.endswith(".pkl")):
                    continue
            try:
                body = zf.read(info)
            except Exception:
                continue
            if not budget.take(len(body)):
                return
            yield from _maybe_recurse(f"{name}::{info.filename}", body, depth, budget)


def _iter_gzip(data, name, depth, budget):
    try:
        body = gzip.decompress(data)
    except Exception:
        yield (name, data); return
    if budget.take(len(body)):
        yield from _maybe_recurse(f"{name}::gunzip", body, depth, budget)


def _iter_tar(data, name, depth, budget):
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            if member.size > MAX_MEMBER:
                yield (f"{name}::{member.name} (skipped: too large)", b"")
                continue
            f = tf.extractfile(member)
            if f is None:
                continue
            body = f.read()
            if not budget.take(len(body)):
                return
            yield from _maybe_recurse(f"{name}::{member.name}", body, depth, budget)


def _maybe_recurse(logical, body, depth, budget):
    if is_archive(body) and depth < MAX_DEPTH:
        yield from iter_members(body, logical, depth + 1, budget)
    else:
        yield (logical, body)
