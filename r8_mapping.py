"""R8/ProGuard mapping file parser — de-obfuscates class paths for classification."""

import re


def parse_mapping_file(mapping_path):
    """Parse an R8/ProGuard mapping.txt file and return a dict mapping
    obfuscated class paths to their original class paths.

    mapping.txt format:
        com.example.myapp.CryptoHelper -> a.b.c:
            int field1 -> a
            void method1() -> b
        com.google.firebase.FirebaseAuth -> d.e.f:
            ...

    We only care about class-level mappings (lines ending with ':' that
    contain ' -> ').  Member mappings (indented lines) are skipped.

    Returns:
        dict: {obfuscated_slash_path: original_slash_path}
              e.g. {"a/b/c": "com/example/myapp/CryptoHelper"}
    """
    mapping = {}

    with open(mapping_path, "r", encoding="utf-8") as f:
        for line in f:
            # Skip comments and blank lines
            line = line.rstrip()
            if not line or line.startswith("#"):
                continue

            # Skip member mappings (indented lines)
            if line.startswith(" ") or line.startswith("\t"):
                continue

            # Class mapping: "original.Class -> obfuscated.Class:"
            if " -> " not in line:
                continue

            # Strip trailing ':'
            line = line.rstrip(":")
            parts = line.split(" -> ", 1)
            if len(parts) != 2:
                continue

            original_dotted = parts[0].strip()
            obfuscated_dotted = parts[1].strip()

            # Convert dot notation to slash notation (matching MobSF paths)
            original_slash = original_dotted.replace(".", "/")
            obfuscated_slash = obfuscated_dotted.replace(".", "/")

            mapping[obfuscated_slash] = original_slash

    return mapping


def deobfuscate_path(file_path, mapping):
    """Attempt to de-obfuscate a file path using the R8 mapping.

    Strips the file extension, looks up the base path in the mapping,
    and returns the original path with the extension re-appended.

    Args:
        file_path: Normalized file path (e.g. "a/b/c.java")
        mapping: Dict from parse_mapping_file()

    Returns:
        Original path if found in mapping (e.g. "com/example/myapp/CryptoHelper.java"),
        or None if no mapping exists.
    """
    # Strip extension for lookup
    base, ext = _split_extension(file_path)
    original = mapping.get(base)
    if original:
        return original + ext
    return None


def _split_extension(path):
    """Split a path into (base, extension) where extension includes the dot.

    Handles .java, .kt, .smali and similar extensions.
    """
    for ext in (".java", ".kt", ".smali"):
        if path.endswith(ext):
            return path[:-len(ext)], ext
    # Fallback: split on last dot
    dot_idx = path.rfind(".")
    if dot_idx > 0:
        return path[:dot_idx], path[dot_idx:]
    return path, ""
