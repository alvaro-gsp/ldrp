#!/usr/bin/env python3
"""
LocalDrop - AirDrop local y web para PC y móvil.
100% Python nativo (sin dependencias, sin internet, totalmente local).
"""

import sys
import os
import socket
import json
import urllib.parse
import mimetypes
import pathlib
import webbrowser
import threading
import subprocess
import argparse
import secrets
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

DEFAULT_FOLDER = pathlib.Path.cwd() / "temp"


def get_all_ips() -> list[str]:
    """Obtiene todas las IPs locales IPv4 de las interfaces activas."""
    ips = []
    try:
        for item in socket.getaddrinfo(socket.gethostname(), None):
            ip = item[4][0]
            if ":" not in ip and not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips


def get_local_ip() -> str:
    """
    Detecta la IP del Wi-Fi/LAN real, descartando VPN y adapters virtuales.
    Parsea ipconfig buscando interfaces con Default Gateway real (no vacío).
    """
    try:
        out = subprocess.check_output(
            ["ipconfig"], text=True, stderr=subprocess.DEVNULL
        )
        blocks = out.split("\n\n")
        candidates = []
        for block in blocks:
            lines = block.strip().splitlines()
            ip = gw = mask = None
            for line in lines:
                low = line.lower()
                if "ipv4" in low and ":" in line:
                    ip = line.split(":")[-1].strip()
                elif "default gateway" in low and ":" in line:
                    val = line.split(":")[-1].strip()
                    if val:
                        gw = val
                elif "subnet mask" in low and ":" in line:
                    mask = line.split(":")[-1].strip()
            if ip and gw and mask and mask != "255.255.255.255":
                candidates.append(ip)
        for ip in candidates:
            if ip.startswith("192.168."):
                return ip
        if candidates:
            return candidates[0]
    except Exception:
        pass

    ips = get_all_ips()
    for ip in ips:
        if ip.startswith("192.168."):
            return ip
    for ip in ips:
        if ip.startswith("10."):
            return ip
    return ips[0] if ips else "127.0.0.1"


def get_unique_filename(directory: pathlib.Path, filename: str) -> pathlib.Path:
    """Si el archivo ya existe, genera 'foto (1).jpg', 'foto (2).jpg', etc."""
    base = pathlib.Path(filename).stem
    suffix = pathlib.Path(filename).suffix
    dest = directory / filename
    counter = 1
    while dest.exists():
        dest = directory / f"{base} ({counter}){suffix}"
        counter += 1
    return dest


def ensure_firewall_rule(port: int, rule_name: str = "developer"):
    if sys.platform != "win32":
        return
    try:
        check = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule",
             f"name={rule_name}", "dir=in"],
            capture_output=True, text=True, timeout=8
        )
        if check.returncode == 0 and str(port) in check.stdout:
            return

        add_args = (
            f'advfirewall firewall add rule name="{rule_name}" '
            f"dir=in action=allow protocol=TCP localport={port} profile=any"
        )
        result = subprocess.run(
            f"netsh {add_args}", capture_output=True, text=True, timeout=8, shell=True
        )
        if result.returncode == 0:
            return
    except Exception as e:
        print(f"[firewall] No se pudo crear la regla '{rule_name}': {e}")


# ---------------------------------------------------------------------------
# Generador QR minimalista nativo (Versión 3-L, 29x29, ECC Level L)
# ---------------------------------------------------------------------------
class QRGeneratorV3:
    SIZE = 29
    TOTAL_CODEWORDS = 70
    DATA_CODEWORDS = 55
    EC_CODEWORDS = 15

    EXP = [0] * 512
    LOG = [0] * 256
    x = 1
    for i in range(255):
        EXP[i] = x
        EXP[i + 255] = x
        LOG[x] = i
        x = (x << 1) ^ (0x11D if (x & 0x80) else 0)

    @classmethod
    def gf_mul(cls, a, b):
        return 0 if a == 0 or b == 0 else cls.EXP[cls.LOG[a] + cls.LOG[b]]

    @classmethod
    def poly_mul(cls, p, q):
        r = [0] * (len(p) + len(q) - 1)
        for i, a in enumerate(p):
            for j, b in enumerate(q):
                r[i + j] ^= cls.gf_mul(a, b)
        return r

    @classmethod
    def get_generator_poly(cls, ec_count):
        g = [1]
        for i in range(ec_count):
            g = cls.poly_mul(g, [1, cls.EXP[i]])
        return g

    @classmethod
    def rs_encode(cls, data, ec_count):
        gen = cls.get_generator_poly(ec_count)
        msg = list(data) + [0] * ec_count
        for i in range(len(data)):
            coef = msg[i]
            if coef != 0:
                for j in range(len(gen)):
                    msg[i + j] ^= cls.gf_mul(gen[j], coef)
        return msg[len(data):]

    @classmethod
    def encode_text(cls, text: str):
        data = text.encode("iso-8859-1")
        if len(data) > 53:
            raise ValueError("Texto demasiado largo para V3-L (máximo 53 bytes)")

        bits = [0, 1, 0, 0]  # Modo Byte
        for i in range(7, -1, -1):
            bits.append((len(data) >> i) & 1)
        for b in data:
            for i in range(7, -1, -1):
                bits.append((b >> i) & 1)

        for _ in range(min(4, cls.DATA_CODEWORDS * 8 - len(bits))):
            bits.append(0)
        while len(bits) % 8 != 0:
            bits.append(0)

        pad_bytes = [0xEC, 0x11]
        pad_idx = 0
        while len(bits) < cls.DATA_CODEWORDS * 8:
            pb = pad_bytes[pad_idx % 2]
            for i in range(7, -1, -1):
                bits.append((pb >> i) & 1)
            pad_idx += 1

        codewords = []
        for i in range(0, len(bits), 8):
            b = 0
            for j in range(8):
                b = (b << 1) | bits[i + j]
            codewords.append(b)

        ec_bytes = cls.rs_encode(codewords, cls.EC_CODEWORDS)
        all_codewords = codewords + ec_bytes

        all_bits = []
        for b in all_codewords:
            for i in range(7, -1, -1):
                all_bits.append((b >> i) & 1)
        return all_bits

    @classmethod
    def make_matrix(cls, text: str):
        bits = cls.encode_text(text)
        mat = [[0] * cls.SIZE for _ in range(cls.SIZE)]
        is_func = [[False] * cls.SIZE for _ in range(cls.SIZE)]

        def set_finder(r0, c0):
            for r in range(r0, r0 + 7):
                for c in range(c0, c0 + 7):
                    mat[r][c] = 1 if (
                        r in (r0, r0 + 6)
                        or c in (c0, c0 + 6)
                        or (r0 + 2 <= r <= r0 + 4 and c0 + 2 <= c <= c0 + 4)
                    ) else 0
                    is_func[r][c] = True
            for r in range(r0 - 1, r0 + 8):
                for c in range(c0 - 1, c0 + 8):
                    if 0 <= r < cls.SIZE and 0 <= c < cls.SIZE and not is_func[r][c]:
                        mat[r][c] = 0
                        is_func[r][c] = True

        set_finder(0, 0)
        set_finder(0, cls.SIZE - 7)
        set_finder(cls.SIZE - 7, 0)

        # Alignment at (22, 22)
        ar, ac = 22, 22
        for r in range(ar - 2, ar + 3):
            for c in range(ac - 2, ac + 3):
                mat[r][c] = 1 if (
                    r in (ar - 2, ar + 2)
                    or c in (ac - 2, ac + 2)
                    or (r == ar and c == ac)
                ) else 0
                is_func[r][c] = True

        # Timing
        for i in range(8, cls.SIZE - 8):
            v = 1 if i % 2 == 0 else 0
            if not is_func[6][i]:
                mat[6][i] = v
                is_func[6][i] = True
            if not is_func[i][6]:
                mat[i][6] = v
                is_func[i][6] = True

        # Dark module
        mat[cls.SIZE - 8][8] = 1
        is_func[cls.SIZE - 8][8] = True

        # Format info (ECC L, Mask 0)
        fmt_bits = [1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0]

        # Top-left
        coords_tl = [
            (8, 0), (8, 1), (8, 2), (8, 3), (8, 4), (8, 5), (8, 7), (8, 8),
            (7, 8), (5, 8), (4, 8), (3, 8), (2, 8), (1, 8), (0, 8)
        ]
        for (r, c), bit in zip(coords_tl, fmt_bits):
            mat[r][c] = bit
            is_func[r][c] = True

        # Bottom-left (bits 0..6)
        for i in range(7):
            mat[cls.SIZE - 1 - i][8] = fmt_bits[i]
            is_func[cls.SIZE - 1 - i][8] = True

        # Top-right (bits 7..14)
        for i in range(8):
            mat[8][cls.SIZE - 8 + i] = fmt_bits[7 + i]
            is_func[8][cls.SIZE - 8 + i] = True

        # Place data bits with Mask 0
        bit_idx = 0
        c = cls.SIZE - 1
        upward = True
        while c > 0:
            if c == 6:
                c -= 1
            rows = range(cls.SIZE - 1, -1, -1) if upward else range(cls.SIZE)
            for r in rows:
                for col in (c, c - 1):
                    if not is_func[r][col]:
                        bit = bits[bit_idx] if bit_idx < len(bits) else 0
                        bit_idx += 1
                        if (r + col) % 2 == 0:
                            bit ^= 1
                        mat[r][col] = bit
            upward = not upward
            c -= 2

        return mat

    @classmethod
    def to_svg(cls, text: str, border: int = 3) -> str:
        mat = cls.make_matrix(text)
        size = cls.SIZE
        full_size = size + border * 2
        rects = []
        for r in range(size):
            for c in range(size):
                if mat[r][c] == 1:
                    rects.append(f'<rect x="{c + border}" y="{r + border}" width="1" height="1"/>')
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {full_size} {full_size}" '
            f'width="100%" height="100%" shape-rendering="crispEdges">\n'
            f'<rect width="{full_size}" height="{full_size}" fill="#ffffff" rx="1"/>\n'
            f'<g fill="#111827">\n{"".join(rects)}\n</g>\n</svg>'
        )

    @classmethod
    def to_terminal_ansi(cls, text: str) -> str:
        mat = cls.make_matrix(text)
        border = 2
        size = cls.SIZE
        full_size = size + border * 2
        grid = [[0] * full_size for _ in range(full_size)]
        for r in range(size):
            for c in range(size):
                grid[r + border][c + border] = mat[r][c]

        lines = []
        for r in range(0, full_size, 2):
            row_str = ['  ']
            for c in range(full_size):
                top = grid[r][c]
                bot = grid[r + 1][c] if r + 1 < full_size else 0
                if top == 1 and bot == 1:
                    row_str.append('█')
                elif top == 1 and bot == 0:
                    row_str.append('▀')
                elif top == 0 and bot == 1:
                    row_str.append('▄')
                else:
                    row_str.append(' ')
            lines.append(''.join(row_str))
        return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Plantilla HTML/CSS/JS (100% Autónoma, estilo Apple AirDrop, offline total)
# ---------------------------------------------------------------------------
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>ldrp</title>
<style>
:root {
  --bg: #f8fafc;
  --card-bg: #ffffff;
  --text: #0f172a;
  --text-muted: #64748b;
  --primary: #0284c7;
  --primary-hover: #0369a1;
  --accent: #38bdf8;
  --border: #e2e8f0;
  --success: #10b981;
  --danger: #ef4444;
  --radius: 16px;
  --shadow: 0 4px 6px -1px rgba(0,0,0,0.05), 0 2px 4px -2px rgba(0,0,0,0.05);
  --shadow-lg: 0 10px 15px -3px rgba(0,0,0,0.08), 0 4px 6px -4px rgba(0,0,0,0.04);
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0b0f17;
    --card-bg: #151c28;
    --text: #f1f5f9;
    --text-muted: #94a3b8;
    --primary: #38bdf8;
    --primary-hover: #7dd3fc;
    --border: #222f42;
    --shadow: 0 4px 6px -1px rgba(0,0,0,0.3);
    --shadow-lg: 0 10px 15px -3px rgba(0,0,0,0.4);
  }
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "Segoe UI", Roboto, sans-serif;
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  padding: 16px;
  display: flex;
  flex-direction: column;
  align-items: center;
}
.container {
  width: 100%;
  max-width: 720px;
  margin: 0 auto;
}
.upload-row {
  display: flex;
  gap: 16px;
  align-items: stretch;
}
.card {
  background: var(--card-bg);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 20px;
  margin-bottom: 20px;
  box-shadow: var(--shadow);
}
.dropzone {
  border: 2px dashed var(--border);
  border-radius: var(--radius);
  padding: 24px 20px;
  text-align: center;
  cursor: pointer;
  transition: all 0.2s ease;
  background: rgba(2, 132, 199, 0.02);
}
.dropzone.dragover {
  border-color: var(--primary);
  background: rgba(2, 132, 199, 0.08);
  transform: scale(1.01);
}
.drop-text {
  font-size: 15px;
  font-weight: 600;
  color: var(--text-muted);
}
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 10px 18px;
  font-size: 14px;
  font-weight: 600;
  border-radius: 12px;
  border: none;
  cursor: pointer;
  transition: all 0.15s ease;
  text-decoration: none;
}
.btn-primary {
  background: var(--primary);
  color: white;
  margin-top: 14px;
}
.btn-primary:hover {
  background: var(--primary-hover);
}
.btn-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  border-radius: 8px;
  border: 1px solid var(--border);
  background: var(--card-bg);
  color: var(--text);
  font-size: 18px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.15s ease;
  text-decoration: none;
  line-height: 1;
}
.btn-icon:hover {
  background: var(--border);
}
.btn-icon-danger {
  border: none;
  color: var(--danger);
  background: transparent;
  font-size: 20px;
}
.btn-icon-danger:hover {
  background: rgba(239, 68, 68, 0.1);
}

.file-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
.file-table th {
  text-align: left;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-muted);
  padding: 6px 10px;
  border-bottom: 1px solid var(--border);
}
.file-table td {
  padding: 8px 10px;
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.file-table tr:last-child td {
  border-bottom: none;
}
.file-table tr:hover td {
  background: rgba(148, 163, 184, 0.06);
}
.file-table .col-name {
  max-width: 260px;
  font-weight: 500;
}
.file-table .col-actions {
  text-align: right;
  white-space: nowrap;
}
.file-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 0;
  border-bottom: 1px solid var(--border);
  gap: 10px;
}
.file-row:last-child { border-bottom: none; }
.file-row-info {
  min-width: 0;
  flex: 1;
}
.file-row-name {
  font-size: 14px;
  font-weight: 500;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.file-row-meta {
  font-size: 12px;
  color: var(--text-muted);
  margin-top: 2px;
}
.file-row-actions {
  display: flex;
  gap: 6px;
  flex-shrink: 0;
}
.empty-state {
  text-align: center;
  padding: 32px 16px;
  color: var(--text-muted);
  font-size: 14px;
}
.progress-container {
  display: none;
  margin-top: 16px;
}
.progress-bar-bg {
  width: 100%;
  height: 8px;
  background: var(--border);
  border-radius: 999px;
  overflow: hidden;
}
.progress-bar-fill {
  height: 100%;
  background: var(--primary);
  width: 0%;
  transition: width 0.15s ease;
}
.progress-text {
  display: flex;
  justify-content: space-between;
  font-size: 12px;
  color: var(--text-muted);
  margin-top: 6px;
}
.qr-box {
  flex-shrink: 0;
  display: flex;
  align-items: center;
}
.qr-img {
  width: 110px;
  height: 110px;
  border-radius: 12px;
  border: 1px solid var(--border);
  padding: 6px;
  background: #ffffff;
  filter: blur(6px);
  transition: filter 0.15s ease;
  cursor: pointer;
  user-select: none;
  -webkit-user-select: none;
}
.qr-img.revealed {
  filter: none;
}
@media (max-width: 600px) {
  .qr-box { display: none; }
  .upload-row { display: block; }
}
.toast {
  position: fixed;
  bottom: 24px;
  left: 50%;
  transform: translateX(-50%) translateY(100px);
  background: #111827;
  color: #ffffff;
  padding: 12px 20px;
  border-radius: 999px;
  font-size: 14px;
  font-weight: 500;
  box-shadow: var(--shadow-lg);
  opacity: 0;
  transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
  z-index: 1000;
  pointer-events: none;
}
.toast.show {
  transform: translateX(-50%) translateY(0);
  opacity: 1;
}
</style>
</head>
<body>
<div class="container">
  <div class="card">
    <div class="upload-row">
      <div class="qr-box">
        <img src="/api/qr.svg" class="qr-img" id="qrImg" alt="QR Code">
      </div>
      <div style="flex:1">
        <div class="dropzone" id="dropzone">
          <div class="drop-text">Drop files here...</div>
          <button class="btn btn-primary" id="uploadBtn" type="button">Upload</button>
        </div>
        <input type="file" id="fileInput" multiple accept="*/*" style="display:none">
        <div class="progress-container" id="progressContainer">
          <div class="progress-bar-bg">
            <div class="progress-bar-fill" id="progressBar"></div>
          </div>
          <div class="progress-text">
            <span id="progressFileName">Uploading...</span>
            <span id="progressPercent">0%</span>
          </div>
        </div>
      </div>
    </div>
  </div>

  <div class="card">
    <div id="fileList">
      <div class="empty-state">Loading...</div>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
const dropzone = document.getElementById('dropzone');
const fileInput = document.getElementById('fileInput');
const progressContainer = document.getElementById('progressContainer');
const progressBar = document.getElementById('progressBar');
const progressFileName = document.getElementById('progressFileName');
const progressPercent = document.getElementById('progressPercent');
const fileList = document.getElementById('fileList');
const toastEl = document.getElementById('toast');

const qrImg = document.getElementById('qrImg');
let qrTimer = null;
qrImg.addEventListener('click', () => {
  qrImg.classList.add('revealed');
  clearTimeout(qrTimer);
  qrTimer = setTimeout(() => qrImg.classList.remove('revealed'), 5000);
});

function showToast(msg) {
  toastEl.textContent = msg;
  toastEl.classList.add('show');
  setTimeout(() => toastEl.classList.remove('show'), 3000);
}

function formatSize(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}


document.getElementById('uploadBtn').addEventListener('click', (e) => {
  e.stopPropagation();
  fileInput.click();
});
['dragenter', 'dragover'].forEach(name => {
  dropzone.addEventListener(name, (e) => { e.preventDefault(); dropzone.classList.add('dragover'); });
});
['dragleave', 'drop'].forEach(name => {
  dropzone.addEventListener(name, (e) => { e.preventDefault(); dropzone.classList.remove('dragover'); });
});
dropzone.addEventListener('drop', (e) => {
  if (e.dataTransfer.files.length) uploadFiles(Array.from(e.dataTransfer.files));
});
fileInput.addEventListener('change', (e) => {
  if (e.target.files.length) uploadFiles(Array.from(e.target.files));
  fileInput.value = '';
});

async function uploadFiles(files) {
  progressContainer.style.display = 'block';
  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    progressFileName.textContent = `[${i+1}/${files.length}] ${file.name}`;
    progressBar.style.width = '0%';
    progressPercent.textContent = '0%';

    await new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/upload?filename=' + encodeURIComponent(file.name));
      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) {
          const pct = Math.round((e.loaded / e.total) * 100);
          progressBar.style.width = pct + '%';
          progressPercent.textContent = pct + '%';
        }
      };
      xhr.onload = () => {
        if (xhr.status === 200) resolve();
        else reject(new Error('Upload failed'));
      };
      xhr.onerror = () => reject(new Error('Connection error'));
      xhr.send(file);
    });
  }
  setTimeout(() => {
    progressContainer.style.display = 'none';
    showToast('Upload complete');
    loadFiles();
  }, 500);
}

async function loadFiles() {
  try {
    const res = await fetch('/api/files');
    const files = await res.json();
    if (!files || files.length === 0) {
      fileList.innerHTML = '<div class="empty-state">No files</div>';
      return;
    }
    const isMobile = window.innerWidth < 600;
    if (isMobile) {
      fileList.innerHTML = files.map(f => `
        <div class="file-row">
          <div class="file-row-info">
            <div class="file-row-name" title="${f.name}">${f.name}</div>
            <div class="file-row-meta">${formatSize(f.size)} · ${f.date}${f.origin ? ' · ' + f.origin : ''}</div>
          </div>
          <div class="file-row-actions">
            <a class="btn-icon" href="/download/${encodeURIComponent(f.name)}" download="${f.name}" title="Download">↓</a>
            <button class="btn-icon btn-icon-danger" onclick="deleteFile('${encodeURIComponent(f.name)}')" title="Delete">×</button>
          </div>
        </div>
      `).join('');
    } else {
      fileList.innerHTML = `
        <table class="file-table">
          <thead><tr>
            <th>Filename</th><th>Date</th><th>Size</th><th>Source</th><th></th>
          </tr></thead>
          <tbody>${files.map(f => `
            <tr>
              <td class="col-name" title="${f.name}">${f.name}</td>
              <td>${f.date}</td>
              <td>${formatSize(f.size)}</td>
              <td>${f.origin || '—'}</td>
              <td class="col-actions">
                <a class="btn-icon" href="/download/${encodeURIComponent(f.name)}" download="${f.name}" title="Download">↓</a>
                <button class="btn-icon btn-icon-danger" onclick="deleteFile('${encodeURIComponent(f.name)}')" title="Delete">×</button>
              </td>
            </tr>
          `).join('')}</tbody>
        </table>`;
    }
  } catch (err) {
    fileList.innerHTML = '<div class="empty-state">Error loading files</div>';
  }
}

async function deleteFile(encodedName) {
  const name = decodeURIComponent(encodedName);
  if (!confirm(`Delete "${name}"?`)) return;
  try {
    await fetch('/api/delete?filename=' + encodedName, { method: 'POST' });
    showToast('File deleted');
    loadFiles();
  } catch (err) {
    alert('Error deleting file');
  }
}


loadFiles();

const sse = new EventSource('/api/events');
sse.onmessage = () => loadFiles();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Servidor HTTP Multihilo
# ---------------------------------------------------------------------------
_sse_clients: list = []
_sse_lock = threading.Lock()
_file_origins: dict[str, str] = {}


def _detect_device(user_agent: str) -> str:
    ua = user_agent.lower()
    if any(k in ua for k in ("iphone", "ipad", "android", "mobile")):
        return "remote"
    return "local"


def _broadcast_sse(event: str):
    with _sse_lock:
        dead = []
        for wfile in _sse_clients:
            try:
                wfile.write(f"data: {event}\n\n".encode())
                wfile.flush()
            except Exception:
                dead.append(wfile)
        for w in dead:
            _sse_clients.remove(w)


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionAbortedError, ConnectionResetError, BrokenPipeError)):
            return
        super().handle_error(request, client_address)


DENIED_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ldrp</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "Segoe UI", Roboto, sans-serif;
  background: #0b0f17; color: #f1f5f9;
  min-height: 100vh; display: flex; align-items: center; justify-content: center;
}
.card {
  text-align: center; padding: 48px 32px; max-width: 400px;
  background: #151c28; border: 1px solid #222f42; border-radius: 16px;
}
.icon { font-size: 56px; margin-bottom: 16px; }
h1 { font-size: 22px; margin-bottom: 8px; }
p { font-size: 14px; color: #94a3b8; line-height: 1.6; }
</style>
</head>
<body>
<div class="card">
  <div class="icon">🔒</div>
  <h1>Access denied</h1>
</div>
</body>
</html>
"""


class LocalDropHandler(BaseHTTPRequestHandler):
    upload_dir: pathlib.Path = DEFAULT_FOLDER
    server_url: str = ""
    access_pin: str = ""

    def log_message(self, format, *args):
        pass

    def _check_pin(self) -> bool:
        if not self.access_pin:
            return True
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        pin = params.get("pin", [""])[0]
        if pin == self.access_pin:
            return True
        cookies = self.headers.get("Cookie", "")
        if f"localdrop_pin={self.access_pin}" in cookies:
            return True
        return False

    def _send_denied(self):
        body = DENIED_HTML.encode("utf-8")
        self.send_response(403)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data, status: int = 200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self._check_pin():
            self._send_denied()
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            params = urllib.parse.parse_qs(parsed.query)
            pin_in_url = params.get("pin", [""])[0]
            body = HTML_TEMPLATE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            if pin_in_url == self.access_pin and self.access_pin:
                self.send_header("Set-Cookie", f"localdrop_pin={self.access_pin}; Path=/; SameSite=Strict")
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/api/qr.svg":
            svg = QRGeneratorV3.to_svg(self.server_url)
            body = svg.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "image/svg+xml; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/api/files":
            files = []
            if self.upload_dir.exists():
                for item in sorted(self.upload_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
                    if item.is_file():
                        stat = item.stat()
                        import time
                        date_str = time.strftime("%d/%m/%Y %H:%M", time.localtime(stat.st_mtime))
                        files.append({
                            "name": item.name,
                            "size": stat.st_size,
                            "date": date_str,
                            "origin": _file_origins.get(item.name, "")
                        })
            self.send_json(files)
            return

        if path == "/api/events":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            with _sse_lock:
                _sse_clients.append(self.wfile)
            try:
                while True:
                    threading.Event().wait(30)
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
            except Exception:
                pass
            finally:
                with _sse_lock:
                    if self.wfile in _sse_clients:
                        _sse_clients.remove(self.wfile)
            return

        if path.startswith("/download/"):
            raw_filename = path[len("/download/"):]
            filename = urllib.parse.unquote(raw_filename)
            target = (self.upload_dir / filename).resolve()

            if not target.is_relative_to(self.upload_dir) or not target.is_file():
                self.send_error(404, "Not found")
                return

            size = target.stat().st_size
            mime_type, _ = mimetypes.guess_type(str(target))
            if not mime_type:
                mime_type = "application/octet-stream"

            self.send_response(200)
            self.send_header("Content-Type", mime_type)
            self.send_header("Content-Length", str(size))
            safe_ascii_name = filename.encode("ascii", "replace").decode("ascii")
            self.send_header("Content-Disposition", f'attachment; filename="{safe_ascii_name}"; filename*=UTF-8\'\'{urllib.parse.quote(filename)}')
            self.end_headers()

            with open(target, "rb") as f:
                while chunk := f.read(65536):
                    try:
                        self.wfile.write(chunk)
                    except (BrokenPipeError, ConnectionResetError):
                        break
            return

        self.send_error(404, "Not found")

    def do_POST(self):
        if not self._check_pin():
            self._send_denied()
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        if path == "/api/upload":
            raw_name = params.get("filename", ["archivo"])[0]
            filename = urllib.parse.unquote(raw_name)
            safe_name = os.path.basename(filename).strip() or "unnamed"

            dest_path = get_unique_filename(self.upload_dir, safe_name)
            content_length = int(self.headers.get("Content-Length", 0))

            bytes_written = 0
            with open(dest_path, "wb") as f:
                remaining = content_length
                while remaining > 0:
                    chunk = self.rfile.read(min(remaining, 65536))
                    if not chunk:
                        break
                    f.write(chunk)
                    bytes_written += len(chunk)
                    remaining -= len(chunk)

            origin = _detect_device(self.headers.get("User-Agent", ""))
            _file_origins[dest_path.name] = origin
            self.send_json({"status": "ok", "filename": dest_path.name, "bytes": bytes_written})
            _broadcast_sse("refresh")
            return

        if path == "/api/delete":
            raw_name = params.get("filename", [""])[0]
            filename = urllib.parse.unquote(raw_name)
            target = (self.upload_dir / filename).resolve()
            if target.is_relative_to(self.upload_dir) and target.is_file():
                try:
                    target.unlink()
                    self.send_json({"status": "ok"})
                    _broadcast_sse("refresh")
                    return
                except Exception as e:
                    self.send_json({"status": "error", "message": str(e)}, status=500)
                    return
            self.send_error(404, "Not found")
            return

        self.send_error(404, "Not found")


def run_server(folder: pathlib.Path = DEFAULT_FOLDER, port: int = 8000, override_ip: str | None = None):
    folder.mkdir(parents=True, exist_ok=True)
    LocalDropHandler.upload_dir = folder

    pin = secrets.token_hex(3).upper()  # 6 chars hex, nuevo en cada arranque
    LocalDropHandler.access_pin = pin

    local_ip = override_ip if override_ip else get_local_ip()
    ensure_firewall_rule(port, "developer")

    while port < 8050:
        try:
            server = ThreadedHTTPServer(("0.0.0.0", port), LocalDropHandler)
            break
        except OSError:
            port += 1
    else:
        return
    url = f"http://{local_ip}:{port}?pin={pin}"
    LocalDropHandler.server_url = url

    print(f"Server listening on: http://{local_ip}:{port}")

    def open_pc_browser():
        try:
            webbrowser.open(f"http://localhost:{port}?pin={pin}")
        except Exception:
            pass

    threading.Timer(1.0, open_pc_browser).start()

    import shutil
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if folder.exists():
            shutil.rmtree(folder, ignore_errors=True)


if __name__ == "__main__":
    from ldrp.__main__ import main
    main()
