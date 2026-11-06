# ldrp

Local network file sharing. Pure Python, no dependencies, no internet.

Scan the QR code from your phone to upload/download files between devices on the same network.

## Usage

```bash
uv run ldrp
```

## Features

- Zero dependencies (Python stdlib only)
- Auto-detects Wi-Fi/LAN IP, ignores VPN and virtual adapters
- PIN-protected access (rotates on each launch, embedded in QR)
- Real-time file list sync via SSE
- Firewall rule auto-creation (Windows)
- Drag-and-drop upload with progress bar
- Works on any device with a browser

## Security

- Access requires a random PIN generated on each launch
- Only reachable from devices on the same local network
- Path traversal protection (restricted to shared folder)
- Firewall rule scoped to the Python executable
