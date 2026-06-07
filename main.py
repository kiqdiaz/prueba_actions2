import subprocess
import json
import re
import sys
from pathlib import Path

# Regex para parsear la salida de `arp -a` en macOS
# Ejemplo: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
ARP_PATTERN = re.compile(
    r"^(?P<hostname>\S+)\s+\((?P<ip>[^)]+)\)\s+at\s+(?P<mac>\S+)"
    r"(?:\s+on\s+(?P<iface>\S+))?"
    r"(?:\s+ifscope)?"
    r"(?:\s+(?P<flags>[^\[]+))?"
    r"(?:\s+\[(?P<type>[^\]]+)\])?",
    re.IGNORECASE,
)


def get_arp_entries() -> list[dict]:
    result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error al ejecutar arp: {result.stderr}", file=sys.stderr)
        sys.exit(1)

    entries = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        m = ARP_PATTERN.match(line)
        if not m:
            continue
        entry = {
            "hostname": m.group("hostname"),
            "ip": m.group("ip"),
            "mac": m.group("mac"),
            "interface": m.group("iface") or "",
            "flags": (m.group("flags") or "").strip(),
            "type": m.group("type") or "",
        }
        entries.append(entry)

    return entries


def main():
    entries = get_arp_entries()
    output = {"arp": entries}

    output_path = Path("arp_entries.json")
    output_path.write_text(json.dumps(output, indent=2, ensure_ascii=False))

    print(f"Se encontraron {len(entries)} entradas ARP.")
    print(f"Archivo generado: {output_path.resolve()}")


if __name__ == "__main__":
    main()
