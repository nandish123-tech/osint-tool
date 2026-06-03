# ─────────────────────────────────────────────────────────────
#  modules/avatar_fingerprint.py  —  Image OSINT (upgraded)
#
#  WHY EXIF SHOWS "NONE" FOR WEB IMAGES:
#    Web/blog/screenshot images are created digitally —
#    they were never taken by a camera, so they have no
#    EXIF data at all. Only photos taken by:
#      • Smartphone camera
#      • DSLR / mirrorless camera
#      • Action cameras (GoPro etc.)
#    ...have EXIF with camera make, model, GPS, datetime.
#
#    Also: Instagram, Facebook, Twitter STRIP EXIF before
#    displaying images. WhatsApp sometimes preserves it.
#    Images shared via email or direct download are safest.
#
#  WHAT THIS UPGRADED MODULE EXTRACTS:
#    EXIF Fields (when available):
#      • Camera make & model          (e.g. Samsung SM-G991B)
#      • Lens model                   (e.g. Rear Main Camera)
#      • Date & time photo was taken  (e.g. 2024:03:15 14:32:05)
#      • GPS latitude & longitude     (exact coordinates)
#      • GPS altitude                 (meters above sea level)
#      • GPS direction                (compass bearing)
#      • ISO speed                    (e.g. 50)
#      • Shutter speed / exposure     (e.g. 1/1000s)
#      • Aperture (f-number)          (e.g. f/1.8)
#      • Focal length                 (e.g. 26mm)
#      • Flash fired or not
#      • White balance
#      • Metering mode
#      • Scene type
#      • Color space
#      • Software / firmware version  (e.g. Android 13)
#      • Copyright / artist tag
#      • Image unique ID
#      • ALL raw EXIF fields dumped
#
#    File Analysis (always available):
#      • File format, dimensions, colour mode
#      • MD5 hash (exact duplicate detection)
#      • File size
#      • Creation / modification times from filesystem
#
#    Steganography:
#      • LSB analysis, file size ratio
#      • steghide, zsteg, binwalk
#
#    Fingerprinting:
#      • pHash, aHash, dHash
#
#    Reverse search links:
#      • Google Lens, TinEye, Yandex, Bing
# ─────────────────────────────────────────────────────────────

import os
import math
import struct
import hashlib
import requests
import subprocess
from datetime import datetime
from urllib.parse import quote

from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import imagehash

from utils.config import get_key
from utils.logger import (
    log_module, log_result, log_link,
    log_success, log_warning, log_error, log_info,
    print_summary_panel,
)


# ── GPS CONVERSION HELPER ─────────────────────────────────────
def _to_decimal(coord, ref) -> float | None:
    """
    Converts GPS EXIF tuple → decimal degrees float.
    e.g. ((12,1),(58,1),(3456,100)) + "N" → 12.976267
    """
    if not coord:
        return None
    try:
        def ratio(t):
            # Handle both IFDRational objects and plain tuples
            if hasattr(t, 'numerator'):
                return t.numerator / t.denominator
            return t[0] / t[1]

        deg = ratio(coord[0])
        mn  = ratio(coord[1])
        sec = ratio(coord[2])
        val = deg + mn / 60.0 + sec / 3600.0
        if ref in ("S", "W"):
            val = -val
        return round(val, 8)
    except Exception:
        return None


# ═════════════════════════════════════════════════════════════
#  EXIF EXTRACTION — Full deep extraction
# ═════════════════════════════════════════════════════════════

def extract_exif(image_path: str) -> dict:
    """
    Extracts ALL EXIF fields from an image.
    Organises them into categories for easy reading.
    """
    log_info("Extracting EXIF metadata (deep scan)...")

    result = {"has_exif": False}

    try:
        img = Image.open(image_path)

        # ── Try _getexif() first (standard JPEG EXIF) ─────────
        raw_exif = None
        if hasattr(img, "_getexif"):
            raw_exif = img._getexif()

        # ── Fallback: try getexif() (newer Pillow versions) ───
        if raw_exif is None and hasattr(img, "getexif"):
            raw_exif = img.getexif()

        if not raw_exif:
            log_warning("No EXIF data in this image.")
            log_info(
                "This is normal for:\n"
                "   • Web/blog/downloaded images (no camera involved)\n"
                "   • Screenshots\n"
                "   • Images processed by social media (they strip EXIF)\n"
                "   • PNG files created by software\n\n"
                "   To get EXIF data, test with a photo taken directly\n"
                "   by your phone camera and NOT uploaded to social media."
            )
            # Still return file-level info
            result["image_width"]  = img.width
            result["image_height"] = img.height
            result["image_mode"]   = img.mode
            result["file_format"]  = img.format or "Unknown"
            return result

        # ── Convert all tag numbers to names ──────────────────
        all_tags = {}
        for tag_id, value in raw_exif.items():
            name = TAGS.get(tag_id, f"Tag_{tag_id}")
            # Convert IFDRational / bytes to readable format
            if isinstance(value, bytes):
                try:    value = value.decode("utf-8", errors="replace")
                except: value = value.hex()
            all_tags[name] = value

        result["has_exif"]    = True
        result["total_fields"] = len(all_tags)
        result["all_tags"]    = {k: str(v) for k, v in all_tags.items()}

        log_success(f"EXIF found — {len(all_tags)} fields extracted")

        # ──────────────────────────────────────────────────────
        #  CATEGORY 1: CAMERA INFORMATION
        # ──────────────────────────────────────────────────────
        result["camera"] = {
            "make":          str(all_tags.get("Make",         "Unknown")).strip(),
            "model":         str(all_tags.get("Model",        "Unknown")).strip(),
            "lens_make":     str(all_tags.get("LensMake",     "Unknown")).strip(),
            "lens_model":    str(all_tags.get("LensModel",    "Unknown")).strip(),
            "lens_id":       str(all_tags.get("LensSpecification","Unknown")),
            "serial_number": str(all_tags.get("BodySerialNumber",
                             all_tags.get("CameraSerialNumber", "Unknown"))).strip(),
        }

        log_result("Camera make",   result["camera"]["make"])
        log_result("Camera model",  result["camera"]["model"])
        log_result("Lens model",    result["camera"]["lens_model"])

        # ──────────────────────────────────────────────────────
        #  CATEGORY 2: DATE & TIME
        # ──────────────────────────────────────────────────────

        # DateTimeOriginal = shutter press time (most reliable)
        # DateTimeDigitized = when digitised (same for phones)
        # DateTime = file modification time

        dt_original  = str(all_tags.get("DateTimeOriginal",  ""))
        dt_digitized = str(all_tags.get("DateTimeDigitized", ""))
        dt_modified  = str(all_tags.get("DateTime",          ""))
        subsec       = str(all_tags.get("SubsecTimeOriginal",
                      all_tags.get("SubSecTimeOriginal", "")))
        offset_time  = str(all_tags.get("OffsetTimeOriginal",
                      all_tags.get("OffsetTime", "")))

        result["datetime"] = {
            "taken":        dt_original  or "Not found",
            "digitized":    dt_digitized or "Not found",
            "modified":     dt_modified  or "Not found",
            "subseconds":   subsec,
            "timezone":     offset_time or "Not specified",
        }

        # Try to parse and show human-readable format
        if dt_original:
            try:
                parsed_dt = datetime.strptime(dt_original, "%Y:%m:%d %H:%M:%S")
                result["datetime"]["taken_readable"] = (
                    parsed_dt.strftime("%d %B %Y, %I:%M:%S %p")
                )
                log_success(f"Photo taken: {result['datetime']['taken_readable']}")
            except Exception:
                log_result("Date taken", dt_original)
        else:
            log_warning("No DateTimeOriginal in EXIF.")

        if offset_time:
            log_result("Timezone offset", offset_time)

        # ──────────────────────────────────────────────────────
        #  CATEGORY 3: GPS LOCATION
        # ──────────────────────────────────────────────────────

        gps_raw = all_tags.get("GPSInfo")

        if gps_raw:
            gps = {}
            if isinstance(gps_raw, dict):
                for k, v in gps_raw.items():
                    gps[GPSTAGS.get(k, k)] = v

            lat = _to_decimal(
                gps.get("GPSLatitude"),
                gps.get("GPSLatitudeRef", "N")
            )
            lon = _to_decimal(
                gps.get("GPSLongitude"),
                gps.get("GPSLongitudeRef", "E")
            )

            # Altitude is stored as a single IFDRational
            alt = None
            alt_raw = gps.get("GPSAltitude")
            if alt_raw:
                try:
                    if hasattr(alt_raw, 'numerator'):
                        alt = round(alt_raw.numerator / alt_raw.denominator, 2)
                    else:
                        alt = round(alt_raw[0] / alt_raw[1], 2)
                    alt_ref = gps.get("GPSAltitudeRef", 0)
                    if alt_ref == 1:
                        alt = -alt  # below sea level
                except Exception:
                    pass

            # GPS timestamp (UTC time from satellite)
            gps_time = gps.get("GPSTimeStamp")
            gps_date = str(gps.get("GPSDateStamp", ""))
            gps_timestamp = ""
            if gps_time and gps_date:
                try:
                    h = int(gps_time[0])
                    m = int(gps_time[1])
                    s = float(gps_time[2]) if hasattr(gps_time[2], '__float__') else 0
                    gps_timestamp = f"{gps_date} {h:02d}:{m:02d}:{s:05.2f} UTC"
                except Exception:
                    pass

            # Compass bearing direction
            img_dir = gps.get("GPSImgDirection")
            direction_val = None
            if img_dir:
                try:
                    direction_val = round(
                        img_dir.numerator / img_dir.denominator
                        if hasattr(img_dir, 'numerator')
                        else img_dir[0] / img_dir[1], 1
                    )
                    # Convert bearing to compass direction
                    dirs = ["N","NE","E","SE","S","SW","W","NW"]
                    compass = dirs[round(direction_val / 45) % 8]
                except Exception:
                    pass

            result["gps"] = {
                "latitude":   lat,
                "longitude":  lon,
                "altitude_m": alt,
                "timestamp":  gps_timestamp,
                "direction":  direction_val,
                "speed":      str(gps.get("GPSSpeed", "Unknown")),
                "raw_tags":   {k: str(v) for k, v in gps.items()},
            }

            if lat and lon:
                result["gps"]["coords_str"] = f"{lat}, {lon}"
                result["gps"]["google_maps"] = (
                    f"https://www.google.com/maps?q={lat},{lon}"
                )
                result["gps"]["google_maps_satellite"] = (
                    f"https://www.google.com/maps/@{lat},{lon},18z/data=!3m1!1e3"
                )
                result["gps"]["osm"] = (
                    f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}&zoom=16"
                )

                log_success(f"GPS COORDINATES FOUND!")
                log_result("Latitude",        str(lat))
                log_result("Longitude",       str(lon))
                log_result("Altitude",        f"{alt}m" if alt else "Unknown")
                log_result("GPS timestamp",   gps_timestamp or "N/A")
                if direction_val:
                    log_result("Camera direction", f"{direction_val}° ({compass})")
                log_link("Google Maps",       result["gps"]["google_maps"])
                log_link("Satellite view",    result["gps"]["google_maps_satellite"])
                log_link("OpenStreetMap",     result["gps"]["osm"])
            else:
                log_warning("GPS tags present but coordinates could not be decoded.")
        else:
            result["gps"] = {"coords_str": "No GPS in EXIF"}
            log_warning("No GPS data — photo may have location services OFF.")

        # ──────────────────────────────────────────────────────
        #  CATEGORY 4: SHOOTING SETTINGS
        # ──────────────────────────────────────────────────────

        def ratio_str(tag_name):
            """Convert IFDRational to readable fraction/decimal string."""
            val = all_tags.get(tag_name)
            if val is None: return "Unknown"
            try:
                if hasattr(val, 'numerator'):
                    n, d = val.numerator, val.denominator
                    if d == 0: return "Unknown"
                    if n < d:  return f"1/{int(d/n)}s"
                    return f"{round(n/d, 2)}"
                if isinstance(val, tuple):
                    n, d = val
                    if d == 0: return "Unknown"
                    if n < d:  return f"1/{int(d/n)}s"
                    return f"{round(n/d, 2)}"
                return str(val)
            except Exception:
                return str(val)

        # Flash codes
        flash_map = {
            0: "No flash",  1: "Flash fired",
            5: "Flash fired (strobe)",  7: "Flash fired (auto)",
            9: "Flash fired (compulsory)", 16: "Flash did not fire (compulsory off)",
            24: "No flash (auto)", 25: "Flash fired (auto)",
        }
        flash_val  = all_tags.get("Flash", 0)
        flash_str  = flash_map.get(flash_val, f"Code {flash_val}")

        # White balance
        wb_map = {0: "Auto", 1: "Manual"}
        wb_val = all_tags.get("WhiteBalance", "")
        wb_str = wb_map.get(wb_val, str(wb_val))

        # Metering mode
        meter_map = {
            0:"Unknown", 1:"Average", 2:"Center-weighted",
            3:"Spot", 4:"Multi-spot", 5:"Pattern", 6:"Partial"
        }
        meter_val = all_tags.get("MeteringMode", "")
        meter_str = meter_map.get(meter_val, str(meter_val))

        # Exposure program
        exp_map = {
            0:"Not defined", 1:"Manual", 2:"Auto",
            3:"Aperture priority", 4:"Shutter priority",
            5:"Creative", 6:"Action", 7:"Portrait", 8:"Landscape"
        }
        exp_val = all_tags.get("ExposureProgram", "")
        exp_str = exp_map.get(exp_val, str(exp_val))

        result["settings"] = {
            "iso":              str(all_tags.get("ISOSpeedRatings",
                                all_tags.get("ISO", "Unknown"))),
            "shutter_speed":    ratio_str("ExposureTime"),
            "aperture":         f"f/{ratio_str('FNumber')}",
            "focal_length":     ratio_str("FocalLength") + "mm",
            "focal_length_35":  ratio_str("FocalLengthIn35mmFilm") + "mm",
            "flash":            flash_str,
            "white_balance":    wb_str,
            "metering_mode":    meter_str,
            "exposure_program": exp_str,
            "exposure_bias":    ratio_str("ExposureBiasValue") + " EV",
            "brightness":       ratio_str("BrightnessValue"),
            "digital_zoom":     ratio_str("DigitalZoomRatio"),
            "scene_type":       str(all_tags.get("SceneCaptureType", "Unknown")),
            "contrast":         str(all_tags.get("Contrast",   "Normal")),
            "saturation":       str(all_tags.get("Saturation", "Normal")),
            "sharpness":        str(all_tags.get("Sharpness",  "Normal")),
        }

        s = result["settings"]
        log_result("ISO",             s["iso"])
        log_result("Shutter speed",   s["shutter_speed"])
        log_result("Aperture",        s["aperture"])
        log_result("Focal length",    s["focal_length"])
        log_result("Flash",           s["flash"])
        log_result("White balance",   s["white_balance"])
        log_result("Exposure mode",   s["exposure_program"])

        # ──────────────────────────────────────────────────────
        #  CATEGORY 5: SOFTWARE & DEVICE INFO
        # ──────────────────────────────────────────────────────

        result["device"] = {
            "software":        str(all_tags.get("Software",          "Unknown")).strip(),
            "firmware":        str(all_tags.get("FirmwareVersion",   "Unknown")).strip(),
            "artist":          str(all_tags.get("Artist",            "")).strip(),
            "copyright":       str(all_tags.get("Copyright",         "")).strip(),
            "image_unique_id": str(all_tags.get("ImageUniqueID",     "")).strip(),
            "color_space":     str(all_tags.get("ColorSpace",        "Unknown")),
            "orientation":     str(all_tags.get("Orientation",       "Unknown")),
            "x_resolution":    str(all_tags.get("XResolution",       "Unknown")),
            "y_resolution":    str(all_tags.get("YResolution",       "Unknown")),
            "resolution_unit": str(all_tags.get("ResolutionUnit",    "Unknown")),
        }

        d = result["device"]
        if d["software"]  != "Unknown": log_result("Software",   d["software"])
        if d["artist"]:                 log_result("Artist/Owner",d["artist"])
        if d["copyright"]:              log_result("Copyright",   d["copyright"])
        if d["image_unique_id"]:        log_result("Image UID",   d["image_unique_id"])

        # ──────────────────────────────────────────────────────
        #  CATEGORY 6: IMAGE PROPERTIES
        # ──────────────────────────────────────────────────────

        result["image_props"] = {
            "width":       img.width,
            "height":      img.height,
            "mode":        img.mode,
            "format":      img.format or "Unknown",
            "megapixels":  round((img.width * img.height) / 1_000_000, 2),
        }

        log_result("Dimensions",  f"{img.width} x {img.height} px")
        log_result("Megapixels",  f"{result['image_props']['megapixels']} MP")
        log_result("Color mode",  img.mode)

        return result

    except FileNotFoundError:
        log_error(f"File not found: {image_path}")
        return {}
    except Exception as e:
        log_error(f"EXIF extraction error: {e}")
        import traceback; traceback.print_exc()
        return {}


# ═════════════════════════════════════════════════════════════
#  STEGANOGRAPHY DETECTION
# ═════════════════════════════════════════════════════════════

def detect_steganography(image_path: str) -> dict:
    """Checks for hidden data using LSB analysis + external tools."""

    log_info("Steganography analysis...")
    result = {
        "steg_detected": False,
        "confidence":    "Low",
        "checks":        [],
        "tools":         {},
    }

    try:
        # ── File size ratio check ─────────────────────────────
        file_size   = os.path.getsize(image_path)
        img         = Image.open(image_path)
        pixels      = img.width * img.height
        expected    = pixels * 3
        ratio       = expected / file_size if file_size else 0

        log_result("File size check", f"{ratio:.1f}:1 compression ratio")
        if img.format == "JPEG" and ratio < 5:
            result["steg_detected"] = True
            result["checks"].append("Low compression ratio — possible hidden data")

        # ── LSB analysis ──────────────────────────────────────
        rgb     = img.convert("RGB")
        sample  = list(rgb.getdata())[::10]
        ones    = sum(ch & 1 for px in sample for ch in px)
        total   = len(sample) * 3
        ratio_l = ones / total if total else 0

        log_result("LSB analysis", f"{ratio_l:.3f} (ideal ~0.500)")
        if total > 10000 and 0.499 < ratio_l < 0.501:
            result["steg_detected"] = True
            result["confidence"]    = "Medium"
            result["checks"].append(f"LSB ratio {ratio_l:.3f} — suspiciously uniform")

        # ── steghide ──────────────────────────────────────────
        try:
            r = subprocess.run(
                ["steghide", "info", image_path, "-p", ""],
                capture_output=True, text=True, timeout=10
            )
            out = r.stdout + r.stderr
            result["tools"]["steghide"] = out.strip()
            if "embedded" in out.lower():
                result["steg_detected"] = True
                result["confidence"]    = "High"
                log_warning("STEGHIDE: Hidden data detected!")
            else:
                log_result("steghide", "No embedded data (empty password)")
        except FileNotFoundError:
            log_info("steghide not installed → sudo apt install steghide")

        # ── zsteg ─────────────────────────────────────────────
        try:
            if img.format == "PNG":
                r = subprocess.run(
                    ["zsteg", image_path],
                    capture_output=True, text=True, timeout=15
                )
                result["tools"]["zsteg"] = r.stdout[:500]
                if any(w in r.stdout.lower()
                       for w in ["text","flag","secret","password"]):
                    result["steg_detected"] = True
                    result["confidence"]    = "High"
                    log_warning("ZSTEG: Suspicious content found!")
                else:
                    log_result("zsteg", f"{len(r.stdout.splitlines())} output lines")
            else:
                log_info("zsteg skipped — PNG only")
        except FileNotFoundError:
            log_info("zsteg not installed → gem install zsteg")

        # ── binwalk ───────────────────────────────────────────
        try:
            r = subprocess.run(
                ["binwalk", image_path],
                capture_output=True, text=True, timeout=15
            )
            lines = [l for l in r.stdout.splitlines()
                     if l.strip() and not l.startswith("DECIMAL")]
            result["tools"]["binwalk"] = r.stdout[:500]

            if len(lines) > 2:
                result["steg_detected"] = True
                result["confidence"]    = "High"
                log_warning(f"BINWALK: {len(lines)} embedded signatures found!")
                for l in lines[:5]:
                    log_result("  binwalk", l.strip())
            else:
                log_result("binwalk", "No extra embedded files")
        except FileNotFoundError:
            log_info("binwalk not installed → sudo apt install binwalk")

    except Exception as e:
        log_warning(f"Steganography check error: {e}")

    if result["steg_detected"]:
        log_warning(f"STEGANOGRAPHY SUSPECTED — confidence: {result['confidence']}")
    else:
        log_success("No steganography detected")

    return result


# ═════════════════════════════════════════════════════════════
#  PHASH FINGERPRINTING
# ═════════════════════════════════════════════════════════════

def compute_phash(image_path: str) -> dict:
    try:
        img   = Image.open(image_path)
        ph    = imagehash.phash(img)
        ah    = imagehash.average_hash(img)
        dh    = imagehash.dhash(img)
        wh    = imagehash.whash(img)

        log_success("Perceptual hashes computed")
        log_result("pHash", str(ph))
        log_result("aHash", str(ah))
        log_result("dHash", str(dh))
        log_result("wHash", str(wh))
        log_info("Difference < 10 between two images = likely same photo")

        return {
            "phash": str(ph), "ahash": str(ah),
            "dhash": str(dh), "whash": str(wh),
            "phash_obj": ph,
        }
    except Exception as e:
        log_error(f"pHash failed: {e}")
        return {}


def compare_images(path1: str, path2: str) -> dict:
    try:
        h1 = imagehash.phash(Image.open(path1))
        h2 = imagehash.phash(Image.open(path2))
        d  = abs(h1 - h2)
        if d == 0:       v = "IDENTICAL"
        elif d <= 10:    v = "VERY SIMILAR — likely same person"
        elif d <= 20:    v = "SIMILAR — possibly related"
        else:            v = "DIFFERENT images"
        return {"distance": d, "verdict": v, "hash1": str(h1), "hash2": str(h2)}
    except Exception as e:
        log_error(f"Comparison failed: {e}")
        return {}


# ═════════════════════════════════════════════════════════════
#  REVERSE SEARCH LINKS
# ═════════════════════════════════════════════════════════════

def build_reverse_links(image_path: str) -> dict:
    is_url = image_path.startswith("http")
    if is_url:
        enc = quote(image_path, safe="")
        return {
            "google_lens": f"https://lens.google.com/uploadbyurl?url={enc}",
            "tineye":      f"https://tineye.com/search?url={enc}",
            "yandex":      f"https://yandex.com/images/search?url={enc}&rpt=imageview",
            "bing":        f"https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{enc}",
        }
    return {
        "google_lens": "https://lens.google.com/  ← drag & drop your image here",
        "tineye":      "https://tineye.com/  ← upload for exact copy search",
        "yandex":      "https://yandex.com/images/  ← BEST for finding faces",
        "bing":        "https://www.bing.com/visualsearch  ← upload image",
    }


# ═════════════════════════════════════════════════════════════
#  FILE INFO
# ═════════════════════════════════════════════════════════════

def get_file_info(image_path: str) -> dict:
    try:
        size = os.path.getsize(image_path)
        stat = os.stat(image_path)
        img  = Image.open(image_path)
        md5  = hashlib.md5(open(image_path,"rb").read()).hexdigest()
        sha1 = hashlib.sha1(open(image_path,"rb").read()).hexdigest()

        # Filesystem timestamps (NOT the photo date — the file date)
        ctime = datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S")
        mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")

        return {
            "filename":       os.path.basename(image_path),
            "full_path":      os.path.abspath(image_path),
            "file_size":      f"{size:,} bytes ({size//1024} KB)",
            "format":         img.format or "Unknown",
            "mode":           img.mode,
            "dimensions":     f"{img.width} x {img.height} px",
            "megapixels":     f"{img.width*img.height/1_000_000:.2f} MP",
            "md5":            md5,
            "sha1":           sha1,
            "fs_created":     ctime,
            "fs_modified":    mtime,
        }
    except Exception as e:
        log_error(f"File info error: {e}")
        return {}


# ═════════════════════════════════════════════════════════════
#  MAIN ENTRY POINT
# ═════════════════════════════════════════════════════════════

def analyze_image(image_path: str, config: dict,
                  compare_with: str = None) -> dict:

    log_module("Image OSINT + Deep EXIF Analysis")

    # ── Download if URL ───────────────────────────────────────
    is_url  = image_path.startswith("http")
    tmp     = None
    if is_url:
        log_info("Downloading image...")
        try:
            r    = requests.get(image_path, timeout=15)
            ext  = ".jpg"
            ct   = r.headers.get("Content-Type","")
            if "png"  in ct: ext = ".png"
            if "webp" in ct: ext = ".webp"
            tmp  = f"/tmp/osint_img{ext}"
            open(tmp,"wb").write(r.content)
            image_path = tmp
            log_success("Downloaded.")
        except Exception as e:
            log_error(f"Download failed: {e}"); return {}

    if not os.path.exists(image_path):
        log_error(f"File not found: {image_path}")
        log_info("Use full path like: /home/hacker/Downloads/photo.jpg")
        return {}

    result = {"input": image_path}

    # Run all parts
    file_info = get_file_info(image_path)
    result["file_info"] = file_info
    log_result("File",        file_info.get("filename",""))
    log_result("Size",        file_info.get("file_size",""))
    log_result("Format",      file_info.get("format",""))
    log_result("Dimensions",  file_info.get("dimensions",""))
    log_result("MD5",         file_info.get("md5",""))
    log_result("SHA1",        file_info.get("sha1",""))
    log_result("File created",file_info.get("fs_created",""))
    log_result("File modified",file_info.get("fs_modified",""))

    result["exif"]          = extract_exif(image_path)
    result["hashes"]        = compute_phash(image_path)
    result["steganography"] = detect_steganography(image_path)
    result["reverse_links"] = build_reverse_links(
        image_path if not is_url else image_path
    )

    if compare_with and os.path.exists(compare_with):
        result["comparison"] = compare_images(image_path, compare_with)
        c = result["comparison"]
        log_result("Image comparison", f"Distance: {c.get('distance')} — {c.get('verdict')}")

    # ── Build summary panel ───────────────────────────────────
    exif  = result["exif"]
    hsh   = result["hashes"]
    steg  = result["steganography"]
    links = result["reverse_links"]
    fi    = result["file_info"]

    rows = [
        # File
        ("── FILE INFO ──",     ""),
        ("Filename",            fi.get("filename",   "")),
        ("Format",              fi.get("format",     "")),
        ("Dimensions",          fi.get("dimensions", "")),
        ("Megapixels",          fi.get("megapixels", "")),
        ("File size",           fi.get("file_size",  "")),
        ("MD5",                 fi.get("md5",        "")),
        ("SHA1",                fi.get("sha1",       "")),
        ("Filesystem created",  fi.get("fs_created", "")),
        ("", ""),
    ]

    if exif.get("has_exif"):
        cam = exif.get("camera", {})
        dt  = exif.get("datetime", {})
        gps = exif.get("gps", {})
        s   = exif.get("settings", {})
        dev = exif.get("device", {})
        ip  = exif.get("image_props", {})

        rows += [
            ("── CAMERA ──",        ""),
            ("Make",                cam.get("make",         "Unknown")),
            ("Model",               cam.get("model",        "Unknown")),
            ("Lens",                cam.get("lens_model",   "Unknown")),
            ("Serial number",       cam.get("serial_number","Unknown")),
            ("", ""),
            ("── DATE & TIME ──",   ""),
            ("Photo taken",         dt.get("taken_readable",
                                    dt.get("taken","Not found"))),
            ("Timezone",            dt.get("timezone", "Not specified")),
            ("", ""),
            ("── GPS LOCATION ──",  ""),
            ("Coordinates",         gps.get("coords_str","Not found")),
            ("Altitude",            f"{gps.get('altitude_m')}m" if gps.get('altitude_m') else "N/A"),
            ("GPS timestamp",       gps.get("timestamp", "N/A")),
        ]
        if gps.get("google_maps"):
            rows.append(("Google Maps",    gps["google_maps"]))
            rows.append(("Satellite view", gps["google_maps_satellite"]))
            rows.append(("OpenStreetMap",  gps["osm"]))
        rows += [
            ("", ""),
            ("── SETTINGS ──",      ""),
            ("ISO",                 s.get("iso",              "Unknown")),
            ("Shutter speed",       s.get("shutter_speed",    "Unknown")),
            ("Aperture",            s.get("aperture",         "Unknown")),
            ("Focal length",        s.get("focal_length",     "Unknown")),
            ("Focal (35mm equiv)",  s.get("focal_length_35",  "Unknown")),
            ("Flash",               s.get("flash",            "Unknown")),
            ("White balance",       s.get("white_balance",    "Unknown")),
            ("Exposure mode",       s.get("exposure_program", "Unknown")),
            ("Metering mode",       s.get("metering_mode",    "Unknown")),
            ("", ""),
            ("── SOFTWARE ──",      ""),
            ("Software/OS",         dev.get("software",  "Unknown")),
            ("Artist/Owner",        dev.get("artist",    "") or "Not set"),
            ("Copyright",           dev.get("copyright", "") or "Not set"),
            ("Image unique ID",     dev.get("image_unique_id","") or "N/A"),
            ("", ""),
            ("Total EXIF fields",   str(exif.get("total_fields", 0))),
        ]
    else:
        rows += [
            ("EXIF data", "None found"),
            ("Why?",
             "Web/screenshot image — no camera involved.\n"
             "Test with a photo from your phone camera."),
        ]

    rows += [
        ("", ""),
        ("── FINGERPRINT ──",  ""),
        ("pHash",              hsh.get("phash","N/A")),
        ("aHash",              hsh.get("ahash","N/A")),
        ("dHash",              hsh.get("dhash","N/A")),
        ("", ""),
        ("── STEGANOGRAPHY ──",""),
        ("Detected",           "YES ⚠" if steg.get("steg_detected") else "No"),
        ("Confidence",         steg.get("confidence","N/A")),
        ("", ""),
        ("── REVERSE SEARCH ──",""),
        ("Google Lens",        links.get("google_lens","")),
        ("Yandex (faces)",     links.get("yandex","")),
        ("TinEye",             links.get("tineye","")),
    ]

    print_summary_panel("Image OSINT — Full Report", rows, color="yellow")

    if tmp and os.path.exists(tmp):
        os.remove(tmp)

    return result
