from pathlib import Path

VERSION_FILE = (
    Path(__file__)
    .resolve()
    .parent
    .parent
    / "VERSION"
)

print("Version file path:", VERSION_FILE)
print("Exists:", VERSION_FILE.exists())


def get_version() -> str:
    try:
        return VERSION_FILE.read_text(encoding="utf-8").strip()
    except Exception as e:
        print("Version error:", e)
        return "Unknown"