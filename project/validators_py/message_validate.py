import os
import re
import mimetypes
from datetime import datetime
from typing import Dict, List, Tuple
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename
from validators_py.file_validate import validate_file_security


# Allowed types and caps
MAX_ATTACHMENT_BYTES = 16 * 1024 * 1024  # 20 MB

ALLOWED_IMAGES = {'jpg', 'jpeg', 'png', 'gif', 'webp'}
ALLOWED_VIDEOS = {'mp4', 'webm'}
ALLOWED_DOCS   = {'pdf', 'txt', 'docx', 'xlsx', 'pptx'}
ALLOWED_ALL    = ALLOWED_IMAGES | ALLOWED_VIDEOS | ALLOWED_DOCS

# Simple, safe URL regex for http(s) links
URL_RE = re.compile(r'\b((?:https?://)[^\s<>"\'\)\]]+)', re.IGNORECASE)

def classify_kind(ext: str) -> str:
    ext = (ext or '').lower()
    if ext in ALLOWED_IMAGES: return 'image'
    if ext in ALLOWED_VIDEOS: return 'video'
    return 'document'

def guess_mime(filename: str) -> str:
    mime, _ = mimetypes.guess_type(filename)
    return mime or 'application/octet-stream'

def _safe_unique_name(user_id: int, original: str) -> str:
    base = secure_filename(original) or 'file'
    ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    return f"chat_{user_id}_{ts}_{base}"

def validate_attachment(file: FileStorage, max_bytes: int = MAX_ATTACHMENT_BYTES) -> Dict:
    if not file or not file.filename:
        return {'ok': False, 'error': 'No file provided'}
    name = file.filename
    ext = name.rsplit('.', 1)[-1].lower() if '.' in name else ''
    if ext not in ALLOWED_ALL:
        return {'ok': False, 'error': 'Unsupported file type'}

    # size
    file.stream.seek(0, os.SEEK_END)
    size = file.stream.tell()
    file.stream.seek(0)
    if size > max_bytes:
        return {'ok': False, 'error': f'File too large (>{max_bytes // (1024*1024)}MB)'}

    data = file.read()
    file.seek(0)

    # security scan
    result = validate_file_security(file_data=data, filename=name, max_size=max_bytes)
    if not result.get('is_safe', False):
        return {'ok': False, 'error': 'File failed security validation', 'issues': result.get('threats', [])}
    if result.get('risk_level') in ('high', 'critical'):
        return {'ok': False, 'error': 'High-risk content detected', 'issues': result.get('warnings', [])}

    kind = classify_kind(ext)
    return {
        'ok': True,
        'name': name,
        'size': size,
        'kind': kind,
        'mime': guess_mime(name),
        'warnings': result.get('warnings', []),
    }

def save_attachment(file: FileStorage, user_id: int) -> Tuple[str, str]:
    
    # Saves to project/static/uploads/chat, returns (rel_path_for_static, absolute_path)
    safe_name = _safe_unique_name(user_id, file.filename)
    rel_path = os.path.join('uploads', 'chat', safe_name).replace('\\', '/')
    abs_path = os.path.join(os.path.dirname(__file__), 'static', rel_path)
    os.makedirs(os.path.dirname(abs_path), exist_ok=True)
    file.save(abs_path)
    return rel_path, abs_path

def extract_links(text: str) -> List[str]:
    # Returns sanitized http(s) links found in text.
    if not text: return []
    matches = URL_RE.findall(text)
    links = []
    for url in matches:
        if url.lower().startswith(('http://', 'https://')) and len(url) <= 2048:
            links.append(url)
    return list(dict.fromkeys(links)) # dedupe while preserving order