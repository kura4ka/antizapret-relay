"""Build the single-file deployable installer without third-party packages."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def build():
    sections = [
        (ROOT / 'lib/common.sh').read_text(encoding='utf-8').rstrip(),
        "\n# Embedded configuration validator; no files are downloaded at runtime.\n"
        "config_tool() {\n    python3 - \"$@\" <<'AZ_RELAY_CONFIG_PY'\n"
        + (ROOT / 'lib/config.py').read_text(encoding='utf-8').rstrip()
        + "\nAZ_RELAY_CONFIG_PY\n}\n",
    ]
    for name in ('server.sh', 'client.sh', 'main.sh'):
        sections.append((ROOT / 'lib' / name).read_text(encoding='utf-8').rstrip())
    result = '\n\n'.join(sections) + '\n'
    (ROOT / 'install.sh').write_text(result, encoding='utf-8', newline='\n')


if __name__ == '__main__':
    build()
