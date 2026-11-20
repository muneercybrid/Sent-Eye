"""Group ExifTool metadata keys into logical buckets for HTML reports."""

CATEGORIES = [
    ("location", "Location", {
        "prefixes": ["GPS"],
        "exact": {"City", "State", "Country", "Province-State",
                  "Country-PrimaryLocationName", "Location"},
    }),
    ("attribution", "Attribution", {
        "exact": {"Artist", "By-line", "By-lineTitle", "Creator",
                  "Copyright", "Credit", "Source", "CopyrightNotice",
                  "AuthorsPosition", "Rights", "OwnerName", "Marked"},
    }),
    ("description", "Description", {
        "exact": {"ImageDescription", "Description", "Caption-Abstract",
                  "ObjectName", "Headline", "XPTitle", "XPComment", "XPSubject"},
    }),
    ("dates", "Dates", {
        "exact": {"DateTimeOriginal", "CreateDate", "ModifyDate",
                  "DateCreated", "MetadataDate", "DateTimeCreated",
                  "SubSecDateTimeOriginal", "SubSecCreateDate", "SubSecModifyDate"},
    }),
    ("camera", "Camera", {
        "exact": {"Make", "Model", "Lens", "LensID", "LensInfo", "LensModel",
                  "SerialNumber", "Firmware", "Software", "HostComputer",
                  "ImageNumber", "BodySerialNumber"},
    }),
    ("exposure", "Exposure", {
        "exact": {"ISO", "FNumber", "ExposureTime", "ShutterSpeed",
                  "ShutterSpeedValue", "Aperture", "ApertureValue",
                  "FocalLength", "FocalLength35efl", "ExposureProgram",
                  "ExposureMode", "ExposureCompensation", "MeteringMode",
                  "WhiteBalance", "Flash", "LightValue", "MaxApertureValue",
                  "FlashCompensation", "ScaleFactor35efl", "FOV"},
    }),
    ("image", "Image", {
        "exact": {"ImageWidth", "ImageHeight", "ExifImageWidth",
                  "ExifImageHeight", "ImageSize", "BitsPerSample",
                  "ColorSpace", "ColorMode", "Compression", "Orientation",
                  "ResolutionUnit", "XResolution", "YResolution",
                  "YCbCrSubSampling", "Megapixels", "SamplesPerPixel"},
    }),
    ("file", "File", {
        "exact": {"FileName", "Directory", "FileSize", "FileType",
                  "FileTypeExtension", "MIMEType", "FilePermissions",
                  "FileModifyDate", "FileAccessDate", "FileInodeChangeDate",
                  "ExifToolVersion"},
    }),
]

HIGHLIGHT_KEYS = {
    "Artist", "By-line", "Creator",
    "DateTimeOriginal", "CreateDate",
    "City", "State", "Country",
    "GPSPosition", "GPSLatitude", "GPSLongitude",
    "ImageDescription", "Description", "Caption-Abstract",
    "Make", "Model", "Lens", "LensModel",
    "Copyright", "Credit", "Source",
    "FileSize", "MIMEType",
}


def categorize(metadata):
    """Return (highlights, categorized, other). Drops binary/empty values."""
    if not isinstance(metadata, dict):
        return {}, {}, {}

    highlights, categorized, other = {}, {k: {} for k, _, _ in CATEGORIES}, {}
    seen_long = {}

    def find_category(k):
        for cat_key, _, rules in CATEGORIES:
            if k in rules.get("exact", set()):
                return cat_key
            for prefix in rules.get("prefixes", []):
                if k.startswith(prefix):
                    return cat_key
        return None

    for k, v in metadata.items():
        if v is None or v == "" or v == []:
            continue
        if isinstance(v, str):
            if not v.strip():
                continue
            if "Binary data" in v:
                continue
            if len(v) > 150:
                key = v[:150]
                if key in seen_long:
                    continue
                seen_long[key] = k
        if k in HIGHLIGHT_KEYS:
            highlights[k] = v
        cat = find_category(k)
        if cat:
            categorized[cat][k] = v
        else:
            other[k] = v

    return highlights, categorized, other


def category_labels():
    return [(key, label) for key, label, _ in CATEGORIES]
