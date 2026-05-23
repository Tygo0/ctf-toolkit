"""
Image metadata extractor — reads EXIF/IPTC/XMP tags from images using exifread.
Supports JPEG, TIFF, PNG, WebP, and RAW formats.
"""

from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
import struct


@dataclass
class ImageMetadata:
    file_name: str
    file_size: str
    file_type: str
    # EXIF core
    make: Optional[str]             = None
    model: Optional[str]            = None
    software: Optional[str]         = None
    datetime: Optional[str]         = None
    datetime_original: Optional[str]= None
    # Geo
    gps_latitude: Optional[str]     = None
    gps_longitude: Optional[str]    = None
    gps_altitude: Optional[str]     = None
    # Image properties
    width: Optional[str]            = None
    height: Optional[str]           = None
    orientation: Optional[str]      = None
    color_space: Optional[str]      = None
    # Camera settings
    exposure_time: Optional[str]    = None
    f_number: Optional[str]         = None
    iso: Optional[str]              = None
    focal_length: Optional[str]     = None
    flash: Optional[str]            = None
    # Author / copyright
    artist: Optional[str]           = None
    copyright: Optional[str]        = None
    image_description: Optional[str]= None
    # Raw tag dump
    raw_tags: dict                  = field(default_factory=dict)
    warnings: list[str]             = field(default_factory=list)


# ── GPS helpers ───────────────────────────────────────────────────────────────

def _gps_to_decimal(values, ref: str) -> Optional[str]:
    """Convert EXIF GPS IFDRational triplet to decimal degree string."""
    try:
        def to_float(v):
            return float(v.num) / float(v.den)
        d = to_float(values[0])
        m = to_float(values[1])
        s = to_float(values[2])
        decimal = d + m / 60 + s / 3600
        if ref in ("S", "W"):
            decimal = -decimal
        return f"{decimal:.6f}°"
    except Exception:
        return str(values)


def _tag_val(tags: dict, key: str) -> Optional[str]:
    """Safely extract a printable tag value."""
    tag = tags.get(key)
    if tag is None:
        return None
    try:
        val = str(tag.values)
        # exifread wraps strings in lists; clean them up
        if val.startswith("[") and val.endswith("]"):
            val = val[1:-1]
        return val.strip() or None
    except Exception:
        return None


# ── PNG chunk reader ──────────────────────────────────────────────────────────

def _read_png_text_chunks(path: Path) -> dict[str, str]:
    """Read tEXt and iTXt chunks from a PNG file for metadata."""
    chunks = {}
    try:
        with open(path, "rb") as f:
            sig = f.read(8)
            if sig != b"\x89PNG\r\n\x1a\n":
                return chunks
            while True:
                header = f.read(8)
                if len(header) < 8:
                    break
                length = struct.unpack(">I", header[:4])[0]
                chunk_type = header[4:8].decode("ascii", errors="replace")
                data = f.read(length)
                f.read(4)  # CRC
                if chunk_type == "tEXt":
                    try:
                        key, _, value = data.partition(b"\x00")
                        chunks[key.decode()] = value.decode("latin-1")
                    except Exception:
                        pass
                elif chunk_type == "iTXt":
                    try:
                        parts = data.split(b"\x00", 4)
                        if len(parts) >= 5:
                            chunks[parts[0].decode()] = parts[4].decode("utf-8", errors="replace")
                    except Exception:
                        pass
                elif chunk_type == "IEND":
                    break
    except Exception:
        pass
    return chunks


# ── Main extractor ────────────────────────────────────────────────────────────

def extract(path: Path) -> ImageMetadata:
    """Extract EXIF and other metadata from an image file."""
    import exifread
    from utils.helpers import file_size_str

    suffix = path.suffix.lower()
    meta = ImageMetadata(
        file_name=path.name,
        file_size=file_size_str(path),
        file_type=suffix.lstrip(".").upper() or "Unknown",
    )

    # ── EXIF via exifread ──────────────────────────────────────────────────────
    try:
        with open(path, "rb") as f:
            tags = exifread.process_file(f, details=False)

        meta.raw_tags = {k: str(v) for k, v in tags.items()}

        meta.make              = _tag_val(tags, "Image Make")
        meta.model             = _tag_val(tags, "Image Model")
        meta.software          = _tag_val(tags, "Image Software")
        meta.datetime          = _tag_val(tags, "Image DateTime")
        meta.datetime_original = _tag_val(tags, "EXIF DateTimeOriginal")
        meta.width             = _tag_val(tags, "EXIF ExifImageWidth") or _tag_val(tags, "Image ImageWidth")
        meta.height            = _tag_val(tags, "EXIF ExifImageLength") or _tag_val(tags, "Image ImageLength")
        meta.orientation       = _tag_val(tags, "Image Orientation")
        meta.color_space       = _tag_val(tags, "EXIF ColorSpace")
        meta.exposure_time     = _tag_val(tags, "EXIF ExposureTime")
        meta.f_number          = _tag_val(tags, "EXIF FNumber")
        meta.iso               = _tag_val(tags, "EXIF ISOSpeedRatings")
        meta.focal_length      = _tag_val(tags, "EXIF FocalLength")
        meta.flash             = _tag_val(tags, "EXIF Flash")
        meta.artist            = _tag_val(tags, "Image Artist")
        meta.copyright         = _tag_val(tags, "Image Copyright")
        meta.image_description = _tag_val(tags, "Image ImageDescription")

        # GPS
        gps_lat  = tags.get("GPS GPSLatitude")
        gps_lat_ref = _tag_val(tags, "GPS GPSLatitudeRef")
        gps_lon  = tags.get("GPS GPSLongitude")
        gps_lon_ref = _tag_val(tags, "GPS GPSLongitudeRef")
        gps_alt  = tags.get("GPS GPSAltitude")

        if gps_lat and gps_lat_ref:
            meta.gps_latitude = _gps_to_decimal(gps_lat.values, gps_lat_ref)
        if gps_lon and gps_lon_ref:
            meta.gps_longitude = _gps_to_decimal(gps_lon.values, gps_lon_ref)
        if gps_alt:
            try:
                v = gps_alt.values[0]
                meta.gps_altitude = f"{float(v.num)/float(v.den):.1f} m"
            except Exception:
                meta.gps_altitude = str(gps_alt.values)

    except Exception as e:
        meta.warnings.append(f"EXIF read error: {e}")

    # ── PNG text chunks (non-EXIF metadata) ───────────────────────────────────
    if suffix == ".png":
        chunks = _read_png_text_chunks(path)
        for key, val in chunks.items():
            if key.lower() in ("author", "artist"):
                meta.artist = meta.artist or val
            elif key.lower() in ("description", "comment"):
                meta.image_description = meta.image_description or val
            elif key.lower() == "software":
                meta.software = meta.software or val
            elif key.lower() == "creation time":
                meta.datetime = meta.datetime or val
            # Always dump into raw tags
            meta.raw_tags[f"PNG:{key}"] = val

    return meta
