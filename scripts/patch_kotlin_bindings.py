#!/usr/bin/env python3
"""
Patch UniFFI-generated Kotlin bindings for Android compatibility.

This script applies two fixes:
1. Forces JNA cleaner for Android API < 33 compatibility
2. Removes unused JavaLangRefCleaner classes

UniFFI 0.29 generates code that uses java.lang.ref.Cleaner when available,
but this is only available on Android API 33+. This script patches the
generated code to always use JNA cleaner for broader Android support.
"""

import argparse
import re
import sys
from pathlib import Path


def patch_kotlin_bindings(kotlin_file: Path) -> bool:
    """
    Patch the Kotlin bindings file for Android compatibility.

    Args:
        kotlin_file: Path to the Kotlin bindings file

    Returns:
        True if patches were applied successfully, False otherwise
    """
    if not kotlin_file.exists():
        print(f"Error: Kotlin file not found: {kotlin_file}", file=sys.stderr)
        return False

    with open(kotlin_file, "r") as f:
        content = f.read()

    # Pattern to match the cleaner selection function
    pattern = r"""// We decide at uniffi binding generation time whether we were
// using Android or not\.
// There are further runtime checks to chose the correct implementation
// of the cleaner\.
private fun UniffiCleaner\.Companion\.create\(\): UniffiCleaner =
    try \{
        // For safety's sake: if the library hasn't been run in android_cleaner = true
        // mode, but is being run on Android, then we still need to think about
        // Android API versions\.
        // So we check if java\.lang\.ref\.Cleaner is there, and use that…
        java\.lang\.Class\.forName\("java\.lang\.ref\.Cleaner"\)
        JavaLangRefCleaner\(\)
    \} catch \(e: ClassNotFoundException\) \{
        // … otherwise, fallback to the JNA cleaner\.
        UniffiJnaCleaner\(\)
    \}"""

    replacement = """// Force JNA cleaner for Android API < 33 compatibility
// (patched by CI - see uniffi.toml android_cleaner = false)
private fun UniffiCleaner.Companion.create(): UniffiCleaner = UniffiJnaCleaner()"""

    new_content = re.sub(pattern, replacement, content)

    # Remove unused JavaLangRefCleaner classes
    new_content = re.sub(
        r"private class JavaLangRefCleaner : UniffiCleaner \{[^}]+\}\n*", "", new_content
    )
    new_content = re.sub(
        r"private class JavaLangRefCleanable\([^)]+\)[^}]+\}\n*", "", new_content
    )

    with open(kotlin_file, "w") as f:
        f.write(new_content)

    print("Kotlin patches applied successfully")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Patch UniFFI-generated Kotlin bindings for Android compatibility"
    )
    parser.add_argument(
        "kotlin_file",
        type=Path,
        help="Path to the Kotlin bindings file to patch",
    )

    args = parser.parse_args()

    if patch_kotlin_bindings(args.kotlin_file):
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
