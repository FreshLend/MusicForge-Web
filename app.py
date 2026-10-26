import os
import uuid
import math
import time
import shutil
import hashlib
import hmac
import secrets
import subprocess
import json
import threading
import asyncio
import logging
import re
from datetime import timedelta
from urllib.parse import urlparse, urlencode
from contextlib import asynccontextmanager
from typing import Optional

from dotenv import load_dotenv
load_dotenv()

import requests
from fastapi import (FastAPI, Request, Response, HTTPException, Depends, WebSocket,
                     WebSocketDisconnect, APIRouter, Form, File, Body, UploadFile)
from fastapi.responses import JSONResponse, RedirectResponse, FileResponse, HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.concurrency import run_in_threadpool

from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_, desc, func, and_, event
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import selectinload
from PIL import Image

from models import (
    db, Session, utcnow, _db_token,
    User, Track, Playlist, PlaylistTrack, Favorite,
    ListeningHistory, Rating, ListenEvent, Tag, TrackTag,
    TrackSimilarity, UserSimilarity, RefreshToken, OAuthAccount, Webhook,
)

Image.MAX_IMAGE_PIXELS = 40_000_000
MAX_PARALLEL_UPLOADS = 4
ACCESS_TOKEN_TTL = timedelta(days=int(os.environ.get('ACCESS_TOKEN_TTL_DAYS', '30')))
REFRESH_TOKEN_TTL = timedelta(days=int(os.environ.get('REFRESH_TOKEN_TTL_DAYS', '90')))
ENFORCE_TOKEN_EXPIRY = os.environ.get('ENFORCE_TOKEN_EXPIRY', '1') == '1'

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger('musicforge')

_desktop_codes = {}
_codes_lock = threading.Lock()
_main_loop = None

def generate_desktop_code(user_id):
    code = secrets.token_urlsafe(32)
    now = time.time()
    with _codes_lock:
        expired = [c for c, (_, ts) in _desktop_codes.items() if now - ts > 60]
        for c in expired:
            _desktop_codes.pop(c, None)
        _desktop_codes[code] = (user_id, now)
    return code

def _load_or_create_secret():
    env = os.environ.get('SECRET_KEY')
    if env:
        return env
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.secret_key')
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            key = f.read().strip()
        if key:
            return key
    key = secrets.token_hex(64)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(key)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass
    return key

SECRET_KEY = _load_or_create_secret()
COOKIE_SECURE = os.environ.get('COOKIE_SECURE', '0') == '1'
MAX_UPLOAD_MB = int(os.environ.get('MAX_UPLOAD_MB', '500'))
ALLOWED_ORIGINS = {o.strip() for o in os.environ.get('ALLOWED_ORIGINS', '').split(',') if o.strip()}
WIDGET_TOKEN_TTL_DAYS = int(os.environ.get('WIDGET_TOKEN_TTL_DAYS', '0'))

BASE_USER_DIR = os.path.join('static', 'users')
os.makedirs('static', exist_ok=True)
os.makedirs(BASE_USER_DIR, exist_ok=True)

OAUTH_PROVIDERS = {}

def _register_oauth():
    if os.environ.get('GOOGLE_CLIENT_ID') and os.environ.get('GOOGLE_CLIENT_SECRET'):
        OAUTH_PROVIDERS['google'] = {
            'client_id': os.environ['GOOGLE_CLIENT_ID'],
            'client_secret': os.environ['GOOGLE_CLIENT_SECRET'],
            'authorize_url': 'https://accounts.google.com/o/oauth2/v2/auth',
            'token_url': 'https://oauth2.googleapis.com/token',
            'userinfo_url': 'https://www.googleapis.com/oauth2/v2/userinfo',
            'scope': 'openid email profile',
        }
    if os.environ.get('GITHUB_CLIENT_ID') and os.environ.get('GITHUB_CLIENT_SECRET'):
        OAUTH_PROVIDERS['github'] = {
            'client_id': os.environ['GITHUB_CLIENT_ID'],
            'client_secret': os.environ['GITHUB_CLIENT_SECRET'],
            'authorize_url': 'https://github.com/login/oauth/authorize',
            'token_url': 'https://github.com/login/oauth/access_token',
            'userinfo_url': 'https://api.github.com/user',
            'emails_url': 'https://api.github.com/user/emails',
            'scope': 'read:user user:email',
            'accept_json': True,
        }

_register_oauth()
upload_semaphore = threading.Semaphore(MAX_PARALLEL_UPLOADS)

@event.listens_for(Engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    try:
        cur = dbapi_connection.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA busy_timeout=60000")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()
    except Exception:
        pass

def commit_with_retry(max_attempts=6, base_delay=0.3):
    for attempt in range(max_attempts):
        try:
            db.session.commit()
            return True
        except OperationalError as e:
            db.session.rollback()
            msg = str(e).lower()
            if 'database is locked' in msg and attempt < max_attempts - 1:
                time.sleep(base_delay * (attempt + 1))
                continue
            raise
    return False

ALLOWED_AUDIO_EXTENSIONS = {'mp3', 'wav', 'ogg', 'm4a'}
ALLOWED_VIDEO_EXTENSIONS = {'mp4', 'webm', 'mov', 'mkv', 'm4v', 'avi'}

def allowed_audio_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_AUDIO_EXTENSIONS

def is_video_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_VIDEO_EXTENSIONS

def sniff_audio(path):
    try:
        with open(path, 'rb') as f:
            head = f.read(16)
    except Exception:
        return None
    if head[:3] == b'ID3' or head[:2] in (b'\xff\xfb', b'\xff\xf3', b'\xff\xf2'):
        return 'mp3'
    if head[:4] == b'RIFF' and head[8:12] == b'WAVE':
        return 'wav'
    if head[:4] == b'OggS':
        return 'ogg'
    if len(head) >= 12 and head[4:8] == b'ftyp':
        return 'm4a'
    return None

def _token_hash(raw):
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()

def _make_token():
    return secrets.token_urlsafe(48)

def _make_widget_token():
    return secrets.token_urlsafe(40)

def issue_access_token(user):
    raw = _make_token()
    user.api_token_hash = _token_hash(raw)
    user.api_token_expires_at = utcnow() + ACCESS_TOKEN_TTL if ENFORCE_TOKEN_EXPIRY else None
    commit_with_retry()
    return raw

def issue_refresh_token(user):
    raw = _make_token()
    rt = RefreshToken(user_id=user.id, token_hash=_token_hash(raw),
                      expires_at=utcnow() + REFRESH_TOKEN_TTL)
    db.session.add(rt)
    commit_with_retry()
    return raw

def revoke_user_tokens(user):
    user.api_token_hash = None
    user.api_token_expires_at = None
    RefreshToken.query.filter_by(user_id=user.id).update({'revoked': True})
    commit_with_retry()

def find_user_by_token(raw):
    if not raw:
        return None
    user = User.query.filter_by(api_token_hash=_token_hash(raw)).first()
    if not user:
        return None
    if ENFORCE_TOKEN_EXPIRY and user.api_token_expires_at and user.api_token_expires_at < utcnow():
        return None
    return user

def ensure_widget_token(user):
    needs = not user.widget_token
    if WIDGET_TOKEN_TTL_DAYS > 0 and user.widget_token_created_at:
        if utcnow() - user.widget_token_created_at > timedelta(days=WIDGET_TOKEN_TTL_DAYS):
            needs = True
    if needs:
        token = _make_widget_token()
        while User.query.filter_by(widget_token=token).first():
            token = _make_widget_token()
        user.widget_token = token
        user.widget_token_created_at = utcnow()
        commit_with_retry()
    return user.widget_token

def generate_user_dir_id():
    return uuid.uuid4().hex

def generate_track_dir_id():
    return uuid.uuid4().hex[:16]

def generate_playlist_dir_id():
    return uuid.uuid4().hex[:16]

def convert_to_webp(input_path, output_path, size=(512, 512)):
    try:
        img = Image.open(input_path)
        img = img.convert('RGB')
        img = img.resize(size, Image.LANCZOS)
        img.save(output_path, 'webp', quality=75)
    except Exception as e:
        raise ValueError(f'Не удалось обработать изображение: {e}')

def get_user_dir(user):
    return os.path.join(BASE_USER_DIR, user.user_dir_id)

def get_track_dir(track):
    user = db.session.get(User, track.uploader_id)
    return os.path.join(get_user_dir(user), 'music', track.track_dir_id)

def get_avatar_path(user):
    return os.path.join(get_user_dir(user), f'{user.user_dir_id}.webp')

def get_cover_path(track):
    return os.path.join(get_track_dir(track), f'{track.track_dir_id}.webp')

def get_cover_video_path(track):
    return os.path.join(get_track_dir(track), f'{track.track_dir_id}.webm')

def has_cover_video(track):
    try:
        return os.path.exists(get_cover_video_path(track))
    except Exception:
        return False

def get_audio_path(track):
    return os.path.join(get_track_dir(track), f'{track.track_dir_id}.{track.audio_ext}')

def get_lyrics_path(track):
    if track.lyrics_filename:
        return os.path.join(get_track_dir(track), track.lyrics_filename)
    return None

def get_lyrics_content(track):
    path = get_lyrics_path(track)
    if path and os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception:
            return None
    return None

def safe_remove(path):
    if not path:
        return
    try:
        if os.path.exists(path):
            os.remove(path)
    except (PermissionError, OSError):
        pass

def safe_rmtree(path):
    if not path:
        return
    try:
        if os.path.exists(path):
            shutil.rmtree(path)
    except (PermissionError, OSError):
        pass

def safe_replace(src, dst):
    try:
        os.replace(src, dst)
        return True
    except (PermissionError, OSError):
        return False

def save_upload_to(upload: UploadFile, dst_path: str):
    try:
        upload.file.seek(0, os.SEEK_END)
        size = upload.file.tell()
        upload.file.seek(0)
    except Exception:
        size = 0
    if size > MAX_UPLOAD_MB * 1024 * 1024:
        raise ValueError(f'Файл слишком большой (макс. {MAX_UPLOAD_MB} МБ)')
    with open(dst_path, 'wb') as f:
        shutil.copyfileobj(upload.file, f)

def safe_convert_to_webp(input_file, output_path, size=(512, 512)):
    tmp = output_path + '.tmp'
    try:
        if isinstance(input_file, str):
            convert_to_webp(input_file, tmp, size)
        else:
            src = getattr(input_file, 'file', None)
            try:
                src.seek(0)
            except Exception:
                pass
            convert_to_webp(src, tmp, size)
    except Exception:
        safe_remove(tmp)
        raise
    if not safe_replace(tmp, output_path):
        safe_remove(tmp)
        raise RuntimeError('Не удалось заменить файл. Возможно, он воспроизводится.')

def save_lyrics_file(track, content):
    track_dir = get_track_dir(track)
    os.makedirs(track_dir, exist_ok=True)
    filename = f'{track.track_dir_id}.srt'
    filepath = os.path.join(track_dir, filename)
    with open(filepath, 'w', encoding='utf-8', newline='') as f:
        f.write(content)
    track.lyrics_filename = filename
    commit_with_retry()

def delete_lyrics_file(track):
    if track.lyrics_filename:
        safe_remove(get_lyrics_path(track))
        track.lyrics_filename = None
        commit_with_retry()

def ensure_default_cover(track):
    if has_cover_video(track):
        return
    cover_path = get_cover_path(track)
    if not os.path.exists(cover_path):
        default_cover = os.path.join('static', 'default_cover.webp')
        if os.path.exists(default_cover):
            try:
                shutil.copyfile(default_cover, cover_path)
            except (PermissionError, OSError):
                pass
        else:
            Image.new('RGB', (512, 512), color='#2a2a3a').save(cover_path, 'webp')

def _ffprobe_video(input_path):
    cmd = ['ffprobe', '-v', 'error', '-select_streams', 'v:0',
           '-show_entries', 'stream=r_frame_rate',
           '-show_entries', 'format=duration',
           '-of', 'json', input_path]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise Exception(f"ffprobe: {r.stderr.strip()}")
    data = json.loads(r.stdout)
    stream = (data.get('streams') or [{}])[0]
    fr = stream.get('r_frame_rate', '30/1')
    try:
        n, d = fr.split('/')
        fps = float(n) / float(d) if float(d) else 30.0
    except Exception:
        fps = 30.0
    try:
        duration = float(data.get('format', {}).get('duration', 0) or 0)
    except Exception:
        duration = 0.0
    return fps, duration

def convert_video_to_cover(input_path, track, size=(512, 512), max_fps=30, crf=32, make_poster=True):
    if not shutil.which('ffmpeg'):
        raise Exception("ffmpeg не установлен. Установите ffmpeg.")
    track_dir = get_track_dir(track)
    os.makedirs(track_dir, exist_ok=True)
    poster_path = get_cover_path(track)
    video_path = get_cover_video_path(track)
    try:
        src_fps, _ = _ffprobe_video(input_path)
    except Exception:
        src_fps = 30.0
    fps_part = f'fps={max_fps},' if src_fps > max_fps + 0.01 else ''
    vf = f"{fps_part}scale={size[0]}:{size[1]}:force_original_aspect_ratio=increase,crop={size[0]}:{size[1]}"
    if make_poster:
        r = subprocess.run(['ffmpeg', '-y', '-i', input_path, '-frames:v', '1', '-vf', vf,
                            '-c:v', 'libwebp', '-quality', '75', poster_path],
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise Exception(f"Ошибка постера: {r.stderr[-500:]}")
    tmp_video = video_path + '.tmp.webm'
    r = subprocess.run(['ffmpeg', '-y', '-i', input_path, '-vf', vf,
                        '-c:v', 'libvpx-vp9', '-b:v', '0', '-crf', str(crf),
                        '-row-mt', '1', '-threads', '0',
                        '-deadline', 'good', '-cpu-used', '5', '-an',
                        '-t', '600', tmp_video],
                       capture_output=True, text=True)
    if r.returncode != 0:
        safe_remove(tmp_video)
        raise Exception(f"Ошибка кодирования: {r.stderr[-500:]}")
    if not safe_replace(tmp_video, video_path):
        safe_remove(tmp_video)
        raise RuntimeError('Не удалось заменить видеофайл.')
    return poster_path, video_path

def format_count(n):
    if n >= 1_000_000:
        return f"{n // 1_000_000}M" if n % 1_000_000 == 0 else f"{n / 1_000_000:.2f}M"
    if n >= 1000:
        return f"{n // 1000}K" if n % 1000 == 0 else f"{n / 1000:.2f}K"
    return str(n)

def parse_tags(tags_string):
    if not tags_string:
        return []
    result, seen = [], set()
    for raw in tags_string.split(','):
        name = raw.strip().lower()
        if name and len(name) <= 80 and name not in seen:
            seen.add(name)
            result.append(name)
    return result

def sync_track_tags(track):
    TrackTag.query.filter_by(track_id=track.id).delete()
    for name in parse_tags(track.tags):
        tag = Tag.query.filter_by(name=name).first()
        if tag is None:
            tag = Tag(name=name)
            db.session.add(tag)
            db.session.flush()
        db.session.add(TrackTag(track_id=track.id, tag_id=tag.id))
    db.session.flush()

def validate_youtube_url(url):
    try:
        p = urlparse(url)
        host = (p.hostname or '').lower()
        return p.scheme in ('http', 'https') and host in {
            'youtube.com', 'www.youtube.com', 'm.youtube.com',
            'youtu.be', 'music.youtube.com'
        }
    except Exception:
        return False

def download_from_youtube(url, track_dir, track_dir_id):
    if not shutil.which('yt-dlp'):
        raise Exception("yt-dlp не установлен")
    if not validate_youtube_url(url):
        raise Exception("Недопустимый URL. Разрешены только youtube.com и youtu.be")
    abs_track_dir = os.path.abspath(track_dir)
    os.makedirs(abs_track_dir, exist_ok=True)
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ex = "youtube:player_client=android,web"
    common = ['--no-config', '--no-playlist', '--user-agent', ua,
              '--add-header', 'Referer: https://www.youtube.com/',
              '--add-header', 'Origin: https://www.youtube.com/',
              '--extractor-args', ex]
    info_cmd = ['yt-dlp', '--dump-json'] + common + [url]
    r = subprocess.run(info_cmd, capture_output=True, text=True, cwd=abs_track_dir, timeout=120)
    if r.returncode != 0:
        raise Exception(f"Ошибка получения информации: {r.stderr.strip()[-300:]}")
    info = json.loads(r.stdout.strip())
    title = info.get('title', 'Unknown Title')
    artist = info.get('uploader', 'Unknown Artist')
    thumb = info.get('thumbnail')
    tpl = os.path.join(abs_track_dir, f'{track_dir_id}.%(ext)s')
    audio_cmd = ['yt-dlp', '-x', '--audio-format', 'mp3', '--audio-quality', '0',
                 '-o', tpl, '--max-filesize', '200M'] + common + [url]
    r = subprocess.run(audio_cmd, capture_output=True, text=True, cwd=abs_track_dir, timeout=600)
    if r.returncode != 0:
        raise Exception(f"Ошибка скачивания: {r.stderr.strip()[-300:]}")
    audio_path = os.path.join(abs_track_dir, f'{track_dir_id}.mp3')
    for ext in ['mp3', 'm4a', 'opus', 'ogg', 'webm', 'aac']:
        candidate = os.path.join(abs_track_dir, f'{track_dir_id}.{ext}')
        if os.path.exists(candidate):
            if candidate != audio_path:
                os.rename(candidate, audio_path)
            break
    if not os.path.exists(audio_path):
        raise Exception("Аудиофайл не найден после скачивания")
    cover_path = os.path.join(abs_track_dir, f'{track_dir_id}.webp')
    if thumb:
        try:
            resp = requests.get(thumb, timeout=15, headers={'User-Agent': ua})
            resp.raise_for_status()
            tmp = os.path.join(abs_track_dir, f'{track_dir_id}_t.jpg')
            with open(tmp, 'wb') as f:
                f.write(resp.content)
            convert_to_webp(tmp, cover_path)
            os.remove(tmp)
        except Exception:
            Image.new('RGB', (512, 512), color='#2a2a3a').save(cover_path, 'webp')
    else:
        Image.new('RGB', (512, 512), color='#2a2a3a').save(cover_path, 'webp')
    return title, artist

def _canonical_pair(a, b):
    return (a, b) if a < b else (b, a)

def compute_user_similarities(min_score=0.05):
    user_items = {}
    for fav in Favorite.query.all():
        user_items.setdefault(fav.user_id, {})
        user_items[fav.user_id][fav.track_id] = user_items[fav.user_id].get(fav.track_id, 0.0) + 3.0
    for r in Rating.query.filter_by(value=1).all():
        user_items.setdefault(r.user_id, {})
        user_items[r.user_id][r.track_id] = user_items[r.user_id].get(r.track_id, 0.0) + 4.0
    for uid, tid, cnt in db.session.query(ListeningHistory.user_id, ListeningHistory.track_id, ListeningHistory.count).all():
        user_items.setdefault(uid, {})
        user_items[uid][tid] = user_items[uid].get(tid, 0.0) + min(cnt, 10) * 1.0
    user_norms = {uid: math.sqrt(sum(v * v for v in items.values())) for uid, items in user_items.items()}
    track_users = {}
    for uid, items in user_items.items():
        for tid in items:
            track_users.setdefault(tid, []).append(uid)
    pair_dots = {}
    for tid, users in track_users.items():
        for i in range(len(users)):
            for j in range(i + 1, len(users)):
                key = _canonical_pair(users[i], users[j])
                pair_dots[key] = pair_dots.get(key, 0.0) + user_items[users[i]][tid] * user_items[users[j]][tid]
    UserSimilarity.query.delete()
    rows = []
    for (u1, u2), dot in pair_dots.items():
        denom = user_norms.get(u1, 0.0) * user_norms.get(u2, 0.0)
        if denom <= 0:
            continue
        sim = dot / denom
        if sim >= min_score:
            rows.append(UserSimilarity(user_a_id=u1, user_b_id=u2, score=sim, updated_at=utcnow()))
    if rows:
        db.session.bulk_save_objects(rows)
    commit_with_retry()

def compute_track_similarities(top_n=30, min_score=1.0):
    pair_scores = {}
    def add(a, b, w):
        if a == b:
            return
        key = _canonical_pair(a, b)
        pair_scores[key] = pair_scores.get(key, 0.0) + w
    user_favs = {}
    for f in Favorite.query.all():
        user_favs.setdefault(f.user_id, []).append(f.track_id)
    for tracks in user_favs.values():
        for i in range(len(tracks)):
            for j in range(i + 1, len(tracks)):
                add(tracks[i], tracks[j], 2.0)
    user_likes = {}
    for r in Rating.query.filter_by(value=1).all():
        user_likes.setdefault(r.user_id, []).append(r.track_id)
    for tracks in user_likes.values():
        for i in range(len(tracks)):
            for j in range(i + 1, len(tracks)):
                add(tracks[i], tracks[j], 2.5)
    pls = {}
    for pt in PlaylistTrack.query.all():
        pls.setdefault(pt.playlist_id, []).append(pt.track_id)
    for tracks in pls.values():
        unique = list(set(tracks))
        for i in range(len(unique)):
            for j in range(i + 1, len(unique)):
                add(unique[i], unique[j], 3.0)
    tag_map = {}
    for tt in TrackTag.query.all():
        tag_map.setdefault(tt.tag_id, []).append(tt.track_id)
    for tracks in tag_map.values():
        for i in range(len(tracks)):
            for j in range(i + 1, len(tracks)):
                add(tracks[i], tracks[j], 1.0)
    per = {}
    for (a, b), s in pair_scores.items():
        if s < min_score:
            continue
        per.setdefault(a, []).append((b, s))
        per.setdefault(b, []).append((a, s))
    TrackSimilarity.query.delete()
    rows = []
    for tid, pairs in per.items():
        pairs.sort(key=lambda x: -x[1])
        for other, s in pairs[:top_n]:
            rows.append(TrackSimilarity(track_a_id=tid, track_b_id=other, score=s, updated_at=utcnow()))
    if rows:
        db.session.bulk_save_objects(rows)
    commit_with_retry()

def recompute_all_similarities():
    try:
        compute_user_similarities()
    except Exception as e:
        log.error(f"user_sim failed: {e}")
        db.session.rollback()
    try:
        compute_track_similarities()
    except Exception as e:
        log.error(f"track_sim failed: {e}")
        db.session.rollback()

def _popularity_window(days):
    since = utcnow() - timedelta(days=days)
    rows = db.session.query(ListenEvent.track_id, func.count(ListenEvent.id)) \
        .filter(ListenEvent.listened_at >= since) \
        .group_by(ListenEvent.track_id) \
        .order_by(desc(func.count(ListenEvent.id))).all()
    return {tid: c for tid, c in rows}

def _build_user_profile(user_id):
    tag_w, art_w = {}, {}
    seen, liked, disliked = set(), set(), set()
    for h in ListeningHistory.query.filter_by(user_id=user_id).all():
        seen.add(h.track_id)
        t = db.session.get(Track, h.track_id)
        if not t:
            continue
        w = math.log1p(h.count)
        a = t.artist_name or t.uploader.display_name
        art_w[a] = art_w.get(a, 0.0) + w
        for tag in parse_tags(t.tags):
            tag_w[tag] = tag_w.get(tag, 0.0) + w * 0.5
    for r in Rating.query.filter_by(user_id=user_id).all():
        t = db.session.get(Track, r.track_id)
        if not t:
            continue
        a = t.artist_name or t.uploader.display_name
        if r.value == 1:
            liked.add(t.id)
            art_w[a] = art_w.get(a, 0.0) + 2.0
            for tag in parse_tags(t.tags):
                tag_w[tag] = tag_w.get(tag, 0.0) + 1.0
        else:
            disliked.add(t.id)
            art_w[a] = art_w.get(a, 0.0) - 1.5
            for tag in parse_tags(t.tags):
                tag_w[tag] = tag_w.get(tag, 0.0) - 1.0
    for f in Favorite.query.filter_by(user_id=user_id).all():
        t = db.session.get(Track, f.track_id)
        if not t:
            continue
        liked.add(t.id)
        seen.add(t.id)
        a = t.artist_name or t.uploader.display_name
        art_w[a] = art_w.get(a, 0.0) + 2.5
        for tag in parse_tags(t.tags):
            tag_w[tag] = tag_w.get(tag, 0.0) + 1.2
    return {'tag_weights': tag_w, 'artist_weights': art_w, 'seen_tracks': seen,
            'liked_ids': liked, 'disliked_ids': disliked}

def _user_cf_candidates(user_id, top_neighbors=20):
    sims = UserSimilarity.query.filter(
        or_(UserSimilarity.user_a_id == user_id, UserSimilarity.user_b_id == user_id)
    ).order_by(UserSimilarity.score.desc()).limit(top_neighbors).all()
    if not sims:
        return {}
    w = {}
    for s in sims:
        other = s.user_b_id if s.user_a_id == user_id else s.user_a_id
        w[other] = s.score
    nids = list(w.keys())
    result = {}
    for tid, uid in db.session.query(Favorite.track_id, Favorite.user_id).filter(Favorite.user_id.in_(nids)).all():
        result[tid] = result.get(tid, 0.0) + w.get(uid, 0.0) * 2.0
    for tid, uid in db.session.query(Rating.track_id, Rating.user_id).filter(Rating.user_id.in_(nids), Rating.value == 1).all():
        result[tid] = result.get(tid, 0.0) + w.get(uid, 0.0) * 2.5
    for tid, uid, c in db.session.query(ListeningHistory.track_id, ListeningHistory.user_id, ListeningHistory.count).filter(ListeningHistory.user_id.in_(nids)).all():
        result[tid] = result.get(tid, 0.0) + w.get(uid, 0.0) * min(c, 10) * 0.4
    return result

def _item_cf_candidates(liked_ids, top_n=500):
    if not liked_ids:
        return {}
    src = list(liked_ids)[:50]
    result = {}
    for _, b, s in db.session.query(TrackSimilarity.track_a_id, TrackSimilarity.track_b_id, TrackSimilarity.score) \
            .filter(TrackSimilarity.track_a_id.in_(src)).order_by(TrackSimilarity.score.desc()).limit(top_n).all():
        result[b] = result.get(b, 0.0) + s
    for _, a, s in db.session.query(TrackSimilarity.track_b_id, TrackSimilarity.track_a_id, TrackSimilarity.score) \
            .filter(TrackSimilarity.track_b_id.in_(src)).order_by(TrackSimilarity.score.desc()).limit(top_n).all():
        result[a] = result.get(a, 0.0) + s
    return result

def get_recommendations(user, limit=16):
    user_id = user.id if (user is not None and getattr(user, 'is_authenticated', False)) else None
    if user_id:
        profile = _build_user_profile(user_id)
    else:
        profile = {'tag_weights': {}, 'artist_weights': {}, 'seen_tracks': set(),
                   'liked_ids': set(), 'disliked_ids': set()}
    candidates = set()
    pos_tags = [tag for tag, w in sorted(profile['tag_weights'].items(), key=lambda x: -x[1])[:8] if w > 0]
    if pos_tags:
        tids = [t.id for t in Tag.query.filter(Tag.name.in_(pos_tags)).all()]
        if tids:
            for (tid,) in db.session.query(TrackTag.track_id).filter(TrackTag.tag_id.in_(tids)).distinct().limit(800).all():
                candidates.add(tid)
    pos_artists = [a for a, w in sorted(profile['artist_weights'].items(), key=lambda x: -x[1])[:8] if w > 0]
    if pos_artists:
        for (tid,) in db.session.query(Track.id).filter(or_(
                Track.artist_name.in_(pos_artists),
                Track.uploader.has(User.display_name.in_(pos_artists)))).limit(800).all():
            candidates.add(tid)
    ucf = _user_cf_candidates(user_id) if user_id else {}
    candidates.update(ucf.keys())
    icf = _item_cf_candidates(profile['liked_ids']) if user_id else {}
    candidates.update(icf.keys())
    pop = _popularity_window(30)
    for pid, _ in sorted(pop.items(), key=lambda x: -x[1])[:150]:
        candidates.add(pid)
    for tr in Track.query.filter(Track.uploaded_at >= utcnow() - timedelta(days=7)) \
            .order_by(Track.uploaded_at.desc()).limit(120).all():
        candidates.add(tr.id)
    if user_id and user.current_track_id:
        candidates.discard(user.current_track_id)
    candidates -= profile['disliked_ids']
    if not candidates:
        return Track.query.order_by(Track.play_count.desc()).limit(limit).all()
    tracks = Track.query.filter(Track.id.in_(list(candidates))).all()
    if not tracks:
        return []
    max_tag = max([abs(v) for v in profile['tag_weights'].values()] + [1.0])
    max_art = max([abs(v) for v in profile['artist_weights'].values()] + [1.0])
    max_pop = max(pop.values()) if pop else 1
    max_ucf = max(ucf.values()) if ucf else 1.0
    max_icf = max(icf.values()) if icf else 1.0
    now = utcnow()
    scored = []
    for tr in tracks:
        content = 0.0
        if tr.tags:
            for tag in parse_tags(tr.tags):
                if tag in profile['tag_weights']:
                    content += profile['tag_weights'][tag] / max_tag * 0.5
        a = tr.artist_name or tr.uploader.display_name
        if a in profile['artist_weights']:
            content += profile['artist_weights'][a] / max_art * 0.5
        p = (pop.get(tr.id, 0) / max_pop) * 0.4 if max_pop else 0.0
        fresh = 0.0
        if tr.uploaded_at:
            d = max(0, (now - tr.uploaded_at).days)
            fresh = max(0, 14 - d) / 14.0 * 0.3
        u = (ucf.get(tr.id, 0.0) / max_ucf) * 0.7 if max_ucf else 0.0
        i = (icf.get(tr.id, 0.0) / max_icf) * 0.8 if max_icf else 0.0
        personal = 0.0
        if user_id and tr.id in profile['liked_ids']:
            personal += 0.5
        if user_id and tr.id in profile['seen_tracks']:
            personal -= 0.4
        scored.append((content + p + fresh + u + i + personal, tr.uploaded_at or now, tr.id, tr))
    scored.sort(key=lambda x: (x[0], x[1], x[2]), reverse=True)
    cnt = {}
    result = []
    for _, _, _, tr in scored:
        a = tr.artist_name or tr.uploader.display_name
        if cnt.get(a, 0) >= 2:
            continue
        cnt[a] = cnt.get(a, 0) + 1
        result.append(tr)
        if len(result) >= limit:
            break
    if len(result) < limit:
        ids = {tr.id for tr in result}
        for _, _, _, tr in scored:
            if tr.id in ids:
                continue
            result.append(tr)
            ids.add(tr.id)
            if len(result) >= limit:
                break
    return result

def get_track_recommendations(track, user=None, limit=6):
    tags = set(parse_tags(track.tags))
    artist = track.artist_name or track.uploader.display_name
    is_ai = bool(track.is_ai)
    user_id = user.id if (user is not None and getattr(user, 'is_authenticated', False)) else None
    profile = _build_user_profile(user_id) if user_id else {
        'liked_ids': set(), 'disliked_ids': set(), 'seen_tracks': set()
    }
    candidates = set()
    if tags:
        tids = [t.id for t in Tag.query.filter(Tag.name.in_(list(tags))).all()]
        if tids:
            for (tid,) in db.session.query(TrackTag.track_id).filter(
                    TrackTag.tag_id.in_(tids), TrackTag.track_id != track.id).distinct().limit(400).all():
                candidates.add(tid)
    for (tid,) in db.session.query(Track.id).filter(
            or_(Track.artist_name == artist,
                Track.uploader.has(User.display_name == artist)),
            Track.id != track.id).limit(200).all():
        candidates.add(tid)
    for tid, _ in db.session.query(TrackSimilarity.track_b_id, TrackSimilarity.score) \
            .filter(TrackSimilarity.track_a_id == track.id).order_by(TrackSimilarity.score.desc()).limit(80).all():
        candidates.add(tid)
    for tid, _ in db.session.query(TrackSimilarity.track_a_id, TrackSimilarity.score) \
            .filter(TrackSimilarity.track_b_id == track.id).order_by(TrackSimilarity.score.desc()).limit(80).all():
        candidates.add(tid)
    for t in Track.query.filter(Track.is_ai == is_ai, Track.id != track.id) \
            .order_by(Track.play_count.desc()).limit(80).all():
        candidates.add(t.id)
    pop = _popularity_window(30)
    for t_id in [pid for pid, _ in sorted(pop.items(), key=lambda x: -x[1])[:120] if pid != track.id]:
        candidates.add(t_id)
    for t in Track.query.filter(Track.uploaded_at >= utcnow() - timedelta(days=7), Track.id != track.id) \
            .order_by(Track.uploaded_at.desc()).limit(80).all():
        candidates.add(t.id)
    candidates.discard(track.id)
    candidates -= profile['disliked_ids']
    if not candidates:
        return Track.query.filter(Track.id != track.id).order_by(Track.play_count.desc()).limit(limit).all()
    tracks = Track.query.filter(Track.id.in_(list(candidates))).all()
    if not tracks:
        return []
    max_pop = max(pop.values()) if pop else 1
    now = utcnow()
    scored = []
    for t in tracks:
        s = 0.0
        s += len(tags & set(parse_tags(t.tags))) * 1.2
        ta = t.artist_name or t.uploader.display_name
        if ta == artist:
            s += 3.0
        if bool(t.is_ai) == is_ai:
            s += 1.0
        s += (pop.get(t.id, 0) / max_pop) * 0.8 if max_pop else 0.0
        if t.uploaded_at:
            d = max(0, (now - t.uploaded_at).days)
            s += max(0, 14 - d) / 14.0 * 0.4
        if user_id:
            if t.id in profile['liked_ids']:
                s += 1.5
            if t.id in profile['seen_tracks']:
                s -= 0.3
        scored.append((s, t.uploaded_at or now, t.id, t))
    scored.sort(key=lambda x: (x[0], x[1], x[2]), reverse=True)
    cnt, result = {}, []
    for _, _, _, t in scored:
        a = t.artist_name or t.uploader.display_name
        if cnt.get(a, 0) >= 2:
            continue
        cnt[a] = cnt.get(a, 0) + 1
        result.append(t)
        if len(result) >= limit:
            break
    if len(result) < limit:
        ids = {t.id for t in result}
        for _, _, _, t in scored:
            if t.id in ids:
                continue
            result.append(t)
            ids.add(t.id)
            if len(result) >= limit:
                break
    return result

def get_user_stats(user):
    res = db.session.query(
        func.count(Track.id),
        func.sum(Track.likes_count),
        func.sum(Track.play_count)
    ).filter(Track.uploader_id == user.id).first()
    return {'tracks_count': res[0] or 0,
            'total_likes': res[1] or 0,
            'total_plays': res[2] or 0}

def _json_error(code, message, status=400):
    return JSONResponse({'ok': False, 'error': {'code': code, 'message': message}}, status_code=status)

def _json_ok(data):
    return JSONResponse({'ok': True, 'data': data})

def _get_ip(request: Request):
    xff = request.headers.get('x-forwarded-for', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.client.host if request.client else 'unknown'

def _get_api_user(request: Request):
    auth = request.headers.get('authorization', '')
    if auth.startswith('Bearer '):
        return find_user_by_token(auth[7:].strip())
    token = request.query_params.get('token') or request.query_params.get('access_token')
    if token:
        return find_user_by_token(token)
    return None

def first_or_404(query):
    obj = query.first()
    if obj is None:
        raise HTTPException(status_code=404)
    return obj

def _track_cover_url(track):
    return f'/static/users/{track.uploader.user_dir_id}/music/{track.track_dir_id}/{track.track_dir_id}.webp'

def _track_video_url(track):
    try:
        if has_cover_video(track):
            return f'/static/users/{track.uploader.user_dir_id}/music/{track.track_dir_id}/{track.track_dir_id}.webm'
    except Exception:
        pass
    return None

def serialize_track(track, include_lyrics=False):
    r = {
        'id': track.track_dir_id,
        'title': track.title,
        'artist': track.artist_name or track.uploader.display_name,
        'artist_id': track.uploader.user_dir_id,
        'artist_username': track.uploader.login,
        'is_ai': bool(track.is_ai),
        'tags': parse_tags(track.tags),
        'release_date': track.uploaded_at.isoformat() if track.uploaded_at else None,
        'cover_url': _track_cover_url(track),
        'video_url': _track_video_url(track),
        'audio_url': f'/api/v1/tracks/{track.track_dir_id}/stream',
        'play_count': track.play_count or 0,
        'likes': track.likes_count or 0,
        'dislikes': track.dislikes_count or 0,
        'web_url': f'/track/{track.track_dir_id}',
    }
    if include_lyrics:
        r['lyrics'] = get_lyrics_content(track)
    return r

def serialize_playlist(pl, include_tracks=False):
    r = {
        'id': pl.playlist_dir_id,
        'name': pl.name,
        'owner': pl.owner.display_name,
        'owner_id': pl.owner.user_dir_id,
        'is_public': bool(pl.is_public),
        'track_count': pl.tracks.count(),
        'web_url': f'/playlist/{pl.playlist_dir_id}',
    }
    if include_tracks:
        tracks = db.session.query(Track).join(PlaylistTrack) \
            .filter(PlaylistTrack.playlist_id == pl.id) \
            .order_by(PlaylistTrack.position).all()
        r['tracks'] = [serialize_track(t) for t in tracks]
    return r

def serialize_user(user, include_stats=False):
    r = {
        'id': user.user_dir_id,
        'login': user.login,
        'display_name': user.display_name,
        'bio': user.bio or '',
        'is_admin': bool(user.is_admin),
        'avatar_url': f'/static/users/{user.user_dir_id}/{user.user_dir_id}.webp',
        'web_url': f'/user/{user.user_dir_id}',
    }
    if include_stats:
        r.update(get_user_stats(user))
    return r

_ws_clients = {}
_ws_lock = threading.Lock()

def ws_broadcast_now_playing(user_id, track_id, stopped=False):
    with _ws_lock:
        conns = list(_ws_clients.get(user_id, []))
    if not conns:
        return
    if stopped:
        payload = json.dumps({'type': 'now_playing', 'playing': False})
    else:
        track = db.session.get(Track, track_id)
        if not track:
            return
        payload = json.dumps({'type': 'now_playing', 'playing': True, 'track': serialize_track(track)})
    if _main_loop is None:
        return
    for ws in conns:
        try:
            asyncio.run_coroutine_threadsafe(ws.send_text(payload), _main_loop)
        except Exception:
            pass

def _dispatch_webhooks(user_id, event, payload):
    hooks = Webhook.query.filter_by(user_id=user_id, active=True).all()
    matching = [h for h in hooks if event in (h.event_types or '').split(',')]
    if not matching:
        return
    body = json.dumps({'event': event, 'data': payload})

    def send(h):
        try:
            sig = hmac.new(h.secret.encode(), body.encode(), hashlib.sha256).hexdigest()
            requests.post(h.url, data=body, timeout=8,
                          headers={'Content-Type': 'application/json',
                                   'X-MusicForge-Event': event,
                                   'X-MusicForge-Signature': sig})
        except Exception as e:
            log.warning(f'webhook {h.id} failed: {e}')

    for h in matching:
        threading.Thread(target=send, args=(h,), daemon=True).start()

class RateLimiter:
    def __init__(self):
        self._buckets = {}
        self._lock = threading.Lock()

    def check(self, key, limit_str):
        if not limit_str:
            return True
        limits = []
        for part in limit_str.split(','):
            part = part.strip()
            m = re.match(r'^(\d+)/(\w+)$', part)
            if m:
                n = int(m.group(1))
                unit = m.group(2).rstrip('s')
                period = {'second': 1, 'minute': 60, 'hour': 3600, 'day': 86400, 'month': 2592000}.get(unit, 60)
                limits.append((n, period))
        if not limits:
            return True
        now = time.time()
        with self._lock:
            for limit, period in limits:
                bkey = (key, period)
                bucket = [(t, c) for t, c in self._buckets.get(bkey, []) if now - t < period]
                total = sum(c for _, c in bucket)
                if total >= limit:
                    self._buckets[bkey] = bucket
                    return False
                bucket.append((now, 1))
                self._buckets[bkey] = bucket
        return True

_limiter = RateLimiter()

def rl(limit_str):
    def deco(func):
        import inspect
        if inspect.iscoroutinefunction(func):
            from functools import wraps
            @wraps(func)
            async def wrapper(request: Request, *args, **kwargs):
                if not _limiter.check(f"{_get_ip(request)}:{func.__name__}", limit_str):
                    return JSONResponse({'error': 'rate limit exceeded'}, status_code=429)
                return await func(request, *args, **kwargs)
            return wrapper
        from functools import wraps
        @wraps(func)
        def wrapper(request: Request, *args, **kwargs):
            if not _limiter.check(f"{_get_ip(request)}:{func.__name__}", limit_str):
                return JSONResponse({'error': 'rate limit exceeded'}, status_code=429)
            return func(request, *args, **kwargs)
        return wrapper
    return deco

def flash(request: Request, message: str, category: str = 'message'):
    try:
        flashes = list(request.session.get('_flashes', []))
    except Exception:
        flashes = []
    flashes.append([category, message])
    request.session['_flashes'] = flashes

def get_flashed_messages(request: Request, with_categories: bool = False, category_filter=()):
    try:
        flashes = list(request.session.pop('_flashes', []))
    except Exception:
        flashes = []
    if category_filter:
        flashes = [f for f in flashes if f[0] in category_filter]
    if with_categories:
        return [(c, m) for c, m in flashes]
    return [m for c, m in flashes]

def get_csrf_token(request: Request) -> str:
    token = request.session.get('_csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        request.session['_csrf_token'] = token
    return token

def make_url_for(request: Request):
    def _url_for(name, **params):
        is_external = params.pop('_external', False)
        if name == 'static' and 'filename' in params and 'path' not in params:
            params['path'] = params.pop('filename')
        try:
            url = request.app.url_path_for(name, **params)
            if is_external:
                return str(request.base_url).rstrip('/') + str(url)
            return str(url)
        except Exception:
            return '#'
    return _url_for

def require_user(request: Request) -> User:
    u = getattr(request.state, 'current_user', None)
    if not u:
        raise HTTPException(status_code=401, detail='Login required')
    return u

def require_api_user(request: Request) -> User:
    u = getattr(request.state, 'api_user', None)
    if not u:
        raise HTTPException(status_code=401, detail='Bearer token required')
    return u

class DBTokenMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        _db_token.set(uuid.uuid4())
        try:
            return await call_next(request)
        finally:
            try:
                Session.remove()
            except Exception:
                pass

class SessionCSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method in ('GET', 'HEAD', 'OPTIONS'):
            return await call_next(request)

        path = request.url.path
        if path.startswith('/api/v1/'):
            return await call_next(request)
        if path.startswith('/api/widget/') and (path.endswith('/listen') or path.endswith('/stop')):
            return await call_next(request)

        expected = request.session.get('_csrf_token') if hasattr(request, 'session') else None
        if not expected:
            if path.startswith('/api/'):
                return _json_error('csrf', 'CSRF token missing', 400)
            flash(request, 'Сессия истекла, попробуйте снова', 'danger')
            return RedirectResponse(str(request.app.url_path_for('index')), status_code=302)

        token = (request.headers.get('x-csrftoken') or
                 request.headers.get('x-csrf-token') or
                 request.query_params.get('csrf_token'))

        if not token:
            content_type = request.headers.get('content-type', '').lower()
            if 'application/x-www-form-urlencoded' in content_type or 'application/json' in content_type:
                try:
                    body = await request.body()
                    if 'json' in content_type:
                        data = json.loads(body.decode('utf-8'))
                        if isinstance(data, dict):
                            token = data.get('csrf_token')
                    else:
                        import urllib.parse
                        form_data = urllib.parse.parse_qs(body.decode('utf-8'))
                        token_list = form_data.get('csrf_token')
                        if token_list:
                            token = token_list[0]
                except Exception:
                    pass

        if not token or not hmac.compare_digest(str(token), str(expected)):
            if path.startswith('/api/'):
                return _json_error('csrf', 'CSRF token missing or invalid', 400)
            flash(request, 'Ошибка безопасности (CSRF). Попробуйте снова.', 'danger')
            return RedirectResponse(str(request.app.url_path_for('index')), status_code=302)

        return await call_next(request)

class UserLoaderMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        uid = request.session.get('user_id') if hasattr(request, 'session') else None
        if uid:
            def _load():
                return Session.get(User, int(uid))
            try:
                request.state.current_user = await run_in_threadpool(_load)
            except Exception:
                request.state.current_user = None
        else:
            request.state.current_user = None
        try:
            request.state.api_user = await run_in_threadpool(_get_api_user, request)
        except Exception:
            request.state.api_user = None
        if request.state.current_user is None and request.state.api_user is not None:
            request.state.current_user = request.state.api_user
        return await call_next(request)

class HeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        if request.url.path.startswith('/static/'):
            response.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
        response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
        response.headers.setdefault('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
        return response

def generate_sitemap_sync():
    _db_token.set(uuid.uuid4())
    try:
        base_url = os.environ.get('SITE_URL', 'https://127.0.0.1:5000')
        urls = [f"{base_url}/", f"{base_url}/releases"]

        tracks = Track.query.order_by(Track.uploaded_at.desc()).limit(2000).all()
        for t in tracks:
            urls.append(f"{base_url}/track/{t.track_dir_id}")

        users = User.query.limit(1000).all()
        for u in users:
            urls.append(f"{base_url}/user/{u.user_dir_id}")

        playlists = Playlist.query.filter_by(is_public=True).limit(1000).all()
        for pl in playlists:
            urls.append(f"{base_url}/playlist/{pl.playlist_dir_id}")

        xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
        xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        for url in urls:
            xml += f'  <url><loc>{url}</loc></url>\n'
        xml += '</urlset>'

        os.makedirs('static', exist_ok=True)
        sitemap_path = os.path.join('static', 'sitemap.xml')
        with open(sitemap_path, 'w', encoding='utf-8') as f:
            f.write(xml)

        log.info(f"[SITEMAP] Успешно обновлен. Ссылок: {len(urls)}")
    except Exception as e:
        log.error(f"[SITEMAP] Ошибка генерации: {e}")
    finally:
        Session.remove()

async def sitemap_worker():
    await asyncio.sleep(5)
    while True:
        await run_in_threadpool(generate_sitemap_sync)
        await asyncio.sleep(6 * 3600)

@asynccontextmanager
async def lifespan(app_: FastAPI):
    global _main_loop
    _main_loop = asyncio.get_running_loop()

    os.makedirs('static', exist_ok=True)
    os.makedirs(BASE_USER_DIR, exist_ok=True)
    try:
        db.create_all()
    except Exception as e:
        log.warning(f'create_all failed: {e}')

    default_cover = os.path.join('static', 'default_cover.webp')
    if not os.path.exists(default_cover):
        try:
            Image.new('RGB', (512, 512), color='#2a2a3a').save(default_cover, 'webp')
        except Exception:
            pass

    asyncio.create_task(sitemap_worker())

    yield

app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

app.add_middleware(SessionCSRFMiddleware)
app.add_middleware(UserLoaderMiddleware)
app.add_middleware(DBTokenMiddleware)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, session_cookie='session',
                   max_age=7 * 24 * 3600, same_site='lax', https_only=COOKIE_SECURE)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(ALLOWED_ORIGINS) if ALLOWED_ORIGINS else ['*'],
    allow_credentials=bool(ALLOWED_ORIGINS),
    allow_methods=['*'],
    allow_headers=['*'],
)
app.add_middleware(HeadersMiddleware)

app.mount('/static', StaticFiles(directory='static'), name='static')
templates = Jinja2Templates(directory='templates')

def render(request: Request, name: str, **context):
    context.setdefault('current_user', getattr(request.state, 'current_user', None))
    context.setdefault('csrf_token', lambda: get_csrf_token(request))
    context.setdefault('get_flashed_messages',
                       lambda with_categories=False, category_filter=():
                       get_flashed_messages(request, with_categories, category_filter))
    context.setdefault('url_for', make_url_for(request))
    context.setdefault('has_cover_video', has_cover_video)
    context.setdefault('get_cover_video_url',
                       lambda t: f'/static/users/{t.uploader.user_dir_id}/music/{t.track_dir_id}/{t.track_dir_id}.webm')
    context.setdefault('oauth_providers', list(OAUTH_PROVIDERS.keys()))
    context.setdefault('format_count', format_count)
    return templates.TemplateResponse(request, name, context)

@app.get('/health')
def health():
    return JSONResponse({'status': 'ok', 'time': utcnow().isoformat()})

@app.get('/favicon.ico')
def favicon():
    ico = os.path.join('static', 'favicon.ico')
    if os.path.exists(ico):
        return FileResponse(ico, media_type='image/x-icon')
    return Response(status_code=204)

@app.get('/robots.txt', response_class=PlainTextResponse)
def serve_robots():
    file_path = os.path.join('static', 'robots.txt')
    if os.path.exists(file_path):
        return FileResponse(file_path, media_type='text/plain',
                            headers={'Cache-Control': 'public, max-age=86400'})
    return PlainTextResponse("User-agent: *\nDisallow: /",
                             headers={'Cache-Control': 'public, max-age=86400'})

@app.get('/sitemap.xml')
def serve_sitemap():
    sitemap_path = os.path.join('static', 'sitemap.xml')
    if not os.path.exists(sitemap_path):
        return Response("Sitemap not generated yet", status_code=404)
    return FileResponse(sitemap_path, media_type='application/xml',
                        headers={'Cache-Control': 'public, max-age=3600'})

@app.get('/', name='index')
def index(request: Request):
    week_ago = utcnow() - timedelta(days=7)
    new_releases = Track.query.options(selectinload(Track.uploader)) \
        .filter(Track.uploaded_at >= week_ago) \
        .order_by(Track.uploaded_at.desc()).limit(8).all()
    month_ago = utcnow() - timedelta(days=30)
    popular = db.session.query(Track, func.count(ListenEvent.id).label('cnt')) \
        .join(ListenEvent, ListenEvent.track_id == Track.id) \
        .options(selectinload(Track.uploader)) \
        .filter(ListenEvent.listened_at >= month_ago) \
        .group_by(Track.id).order_by(desc('cnt')).limit(8).all()
    cu = getattr(request.state, 'current_user', None)
    recs = get_recommendations(cu) if cu else []
    return render(request, 'index.html', new_releases=new_releases,
                  popular_tracks=[r[0] for r in popular], recommendations=recs)

@app.get('/releases', name='releases')
def releases(request: Request):
    page = int(request.query_params.get('page', 1))
    tracks = Track.query.order_by(Track.uploaded_at.desc()).paginate(page=page, per_page=20)
    return render(request, 'releases.html', tracks=tracks)

@app.get('/all_new', name='all_new')
def all_new(request: Request):
    tracks = Track.query.filter(Track.uploaded_at >= utcnow() - timedelta(days=7)) \
        .order_by(Track.uploaded_at.desc()).all()
    return render(request, 'all_new.html', tracks=tracks)

@app.get('/all_chart', name='all_chart')
def all_chart(request: Request):
    rows = db.session.query(Track, func.count(ListenEvent.id).label('cnt')) \
        .join(ListenEvent, ListenEvent.track_id == Track.id) \
        .filter(ListenEvent.listened_at >= utcnow() - timedelta(days=30)) \
        .group_by(Track.id).order_by(desc('cnt')).all()
    return render(request, 'all_chart.html', tracks=[r[0] for r in rows])

@app.get('/app', name='app_info')
def app_info(request: Request):
    return render(request, 'app_info.html')

@app.get('/random', name='random_track')
def random_track(request: Request):
    t = Track.query.order_by(func.random()).first()
    if not t:
        flash(request, 'Нет треков', 'danger')
        return RedirectResponse(str(request.app.url_path_for('index')), status_code=302)
    return RedirectResponse(str(request.app.url_path_for('track', track_dir_id=t.track_dir_id)), status_code=302)

@app.get('/search', name='search')
def search(request: Request):
    q = request.query_params.get('q', '')
    tracks = []
    if q:
        tracks = Track.query.filter(or_(
            Track.title.ilike(f'%{q}%'),
            Track.artist_name.ilike(f'%{q}%'),
            Track.uploader.has(User.display_name.ilike(f'%{q}%'))
        )).all()
    return render(request, 'search.html', tracks=tracks, query=q)

@app.get('/advanced_search', name='advanced_search')
def advanced_search(request: Request):
    title = request.query_params.get('title', '')
    artist = request.query_params.get('artist', '')
    tag = request.query_params.get('tag', '')
    is_ai = request.query_params.get('is_ai')
    q = Track.query
    if title:
        q = q.filter(Track.title.ilike(f'%{title}%'))
    if artist:
        q = q.filter(or_(Track.artist_name.ilike(f'%{artist}%'),
                         Track.uploader.has(User.display_name.ilike(f'%{artist}%'))))
    if tag:
        t_obj = Tag.query.filter_by(name=tag.strip().lower()).first()
        if t_obj:
            q = q.filter(Track.id.in_(db.session.query(TrackTag.track_id).filter(TrackTag.tag_id == t_obj.id)))
        else:
            q = q.filter(Track.id == -1)
    if is_ai == 'yes':
        q = q.filter(Track.is_ai.is_(True))
    elif is_ai == 'no':
        q = q.filter(Track.is_ai.is_(False))
    tracks = q.order_by(Track.uploaded_at.desc()).all()
    return render(request, 'advanced_search.html', tracks=tracks, request_args=request.query_params)

@app.get('/track/{track_dir_id}', name='track')
def track_page(request: Request, track_dir_id: str):
    t = first_or_404(Track.query.filter_by(track_dir_id=track_dir_id))
    cu = getattr(request.state, 'current_user', None)
    is_fav = False
    user_rating = 0
    pl_ids = []
    if cu:
        is_fav = Favorite.query.filter_by(user_id=cu.id, track_id=t.id).first() is not None
        r = Rating.query.filter_by(user_id=cu.id, track_id=t.id).first()
        if r:
            user_rating = r.value
        pl_ids = [pt.playlist_id for pt in PlaylistTrack.query.filter(
            PlaylistTrack.track_id == t.id,
            PlaylistTrack.playlist_id.in_(
                db.session.query(Playlist.id).filter_by(user_id=cu.id))).all()]
    recs = get_track_recommendations(t, cu)
    return render(request, 'track.html', track=t, is_favorite=is_fav,
                  user_rating=user_rating, recommendations=recs,
                  user_playlist_ids_with_track=pl_ids,
                  track_lyrics=get_lyrics_content(t),
                  has_video=has_cover_video(t))

@app.api_route('/track/{track_dir_id}/edit', methods=['GET', 'POST'], name='edit_track')
def edit_track(request: Request, track_dir_id: str, user: User = Depends(require_user),
               title: str = Form(None), artist_name: str = Form(None), tags: str = Form(None),
               is_ai: bool = Form(False), delete_lyrics: bool = Form(False),
               delete_cover_video: bool = Form(False),
               cover_file: Optional[UploadFile] = File(None),
               cover_video_file: Optional[UploadFile] = File(None),
               lyrics_file: Optional[UploadFile] = File(None)):
    t = first_or_404(Track.query.filter_by(track_dir_id=track_dir_id))
    if t.uploader_id != user.id and not user.is_admin:
        flash(request, 'Нет доступа', 'danger')
        return RedirectResponse(str(request.app.url_path_for('track', track_dir_id=t.track_dir_id)), status_code=302)
    if request.method == 'GET':
        return render(request, 'edit_track.html', track=t)
    with upload_semaphore:
        if title:
            t.title = title
        if artist_name is not None:
            t.artist_name = artist_name or None
        if tags is not None:
            t.tags = tags
        t.is_ai = is_ai
        db.session.flush()
        sync_track_tags(t)
        track_dir = get_track_dir(t)
        os.makedirs(track_dir, exist_ok=True)
        if cover_file and cover_file.filename:
            if is_video_file(cover_file.filename):
                ext = cover_file.filename.rsplit('.', 1)[1].lower()
                tmp = os.path.join(track_dir, f'_tmp_{uuid.uuid4().hex}.{ext}')
                try:
                    save_upload_to(cover_file, tmp)
                except ValueError as e:
                    flash(request, str(e), 'danger')
                    return RedirectResponse(str(request.app.url_path_for('edit_track', track_dir_id=t.track_dir_id)), status_code=302)
                try:
                    convert_video_to_cover(tmp, t, make_poster=True)
                except Exception as e:
                    flash(request, f'Ошибка: {e}', 'danger')
                    return RedirectResponse(str(request.app.url_path_for('edit_track', track_dir_id=t.track_dir_id)), status_code=302)
                finally:
                    safe_remove(tmp)
            else:
                try:
                    safe_convert_to_webp(cover_file, get_cover_path(t), (512, 512))
                except Exception as e:
                    flash(request, str(e), 'danger')
                    return RedirectResponse(str(request.app.url_path_for('edit_track', track_dir_id=t.track_dir_id)), status_code=302)
        if cover_video_file and cover_video_file.filename and is_video_file(cover_video_file.filename):
            ext = cover_video_file.filename.rsplit('.', 1)[1].lower()
            tmp = os.path.join(track_dir, f'_tmp_{uuid.uuid4().hex}.{ext}')
            try:
                save_upload_to(cover_video_file, tmp)
            except ValueError as e:
                flash(request, str(e), 'danger')
                return RedirectResponse(str(request.app.url_path_for('edit_track', track_dir_id=t.track_dir_id)), status_code=302)
            try:
                convert_video_to_cover(tmp, t, make_poster=False)
            except Exception as e:
                flash(request, f'Ошибка: {e}', 'danger')
                return RedirectResponse(str(request.app.url_path_for('edit_track', track_dir_id=t.track_dir_id)), status_code=302)
            finally:
                safe_remove(tmp)
        if lyrics_file and lyrics_file.filename:
            try:
                lyrics_file.file.seek(0)
                save_lyrics_file(t, lyrics_file.file.read().decode('utf-8'))
            except Exception:
                flash(request, 'Ошибка чтения субтитров', 'danger')
                return RedirectResponse(str(request.app.url_path_for('edit_track', track_dir_id=t.track_dir_id)), status_code=302)
        elif delete_lyrics:
            delete_lyrics_file(t)
        if delete_cover_video:
            safe_remove(get_cover_video_path(t))
            ensure_default_cover(t)
        commit_with_retry()
    flash(request, 'Трек обновлён', 'success')
    return RedirectResponse(str(request.app.url_path_for('track', track_dir_id=t.track_dir_id)), status_code=302)

@app.post('/track/{track_dir_id}/delete', name='delete_track')
def delete_track(request: Request, track_dir_id: str, user: User = Depends(require_user)):
    t = first_or_404(Track.query.filter_by(track_dir_id=track_dir_id))
    if t.uploader_id != user.id and not user.is_admin:
        flash(request, 'Нет доступа', 'danger')
        return RedirectResponse(str(request.app.url_path_for('track', track_dir_id=t.track_dir_id)), status_code=302)
    safe_rmtree(get_track_dir(t))
    db.session.delete(t)
    commit_with_retry()
    flash(request, 'Трек удалён', 'success')
    return RedirectResponse(str(request.app.url_path_for('index')), status_code=302)

@app.get('/widgets', name='widgets')
def widgets(request: Request, user: User = Depends(require_user)):
    ensure_widget_token(user)
    now_playing_url = str(request.url_for('widget_now_playing', token=user.widget_token))
    search_url = str(request.url_for('widget_search', token=user.widget_token))
    return render(request, 'widgets.html', now_playing_url=now_playing_url, search_url=search_url)

@app.get('/widget/{token}', name='widget_now_playing')
def widget_now_playing(request: Request, token: str):
    first_or_404(User.query.filter_by(widget_token=token))
    return render(request, 'widget.html', token=token)

@app.get('/widget/search/{token}', name='widget_search')
def widget_search(request: Request, token: str):
    first_or_404(User.query.filter_by(widget_token=token))
    return render(request, 'widget_search.html', token=token)

@app.api_route('/login', methods=['GET', 'POST'], name='login')
@rl('30/minute')
def login(request: Request, login: str = Form(None), password: str = Form(None)):
    if request.method == 'POST':
        u = User.query.filter(or_(User.login == login, User.email == login)).first()
        if u and check_password_hash(u.password_hash, password or ''):
            request.session['user_id'] = u.id
            desktop_redirect = request.session.pop('desktop_redirect', None)
            desktop_state = request.session.pop('desktop_state', None)
            if desktop_redirect and re.match(r'^http://127\.0\.0\.1:\d+/callback$', desktop_redirect):
                code = generate_desktop_code(u.id)
                return RedirectResponse(f"{desktop_redirect}?code={code}&state={desktop_state}", status_code=302)
            return RedirectResponse(str(request.app.url_path_for('index')), status_code=302)
        flash(request, 'Неверный логин/email или пароль', 'danger')
    return render(request, 'login.html')

@app.api_route('/register', methods=['GET', 'POST'], name='register')
@rl('10/hour')
def register(request: Request, login: str = Form(None), email: str = Form(None),
             password: str = Form(None), password2: str = Form(None)):
    if request.method == 'POST':
        login_val = (login or '').strip()
        email_val = (email or '').strip()
        pw = password or ''
        if not login_val or not email_val or not pw:
            flash(request, 'Заполните все поля', 'danger')
            return render(request, 'register.html')
        if len(pw) < 8:
            flash(request, 'Пароль минимум 8 символов', 'danger')
            return render(request, 'register.html')
        if pw != (password2 or ''):
            flash(request, 'Пароли не совпадают', 'danger')
            return render(request, 'register.html')
        if User.query.filter_by(login=login_val).first():
            flash(request, 'Логин занят', 'danger')
            return render(request, 'register.html')
        if User.query.filter_by(email=email_val).first():
            flash(request, 'Email занят', 'danger')
            return render(request, 'register.html')
        u = User(user_dir_id=generate_user_dir_id(), login=login_val, email=email_val,
                 password_hash=generate_password_hash(pw), display_name=login_val)
        db.session.add(u)
        commit_with_retry()
        os.makedirs(get_user_dir(u), exist_ok=True)
        request.session['user_id'] = u.id
        desktop_redirect = request.session.pop('desktop_redirect', None)
        desktop_state = request.session.pop('desktop_state', None)
        if desktop_redirect and re.match(r'^http://127\.0\.0\.1:\d+/callback$', desktop_redirect):
            code = generate_desktop_code(u.id)
            return RedirectResponse(f"{desktop_redirect}?code={code}&state={desktop_state}", status_code=302)
        return RedirectResponse(str(request.app.url_path_for('index')), status_code=302)
    return render(request, 'register.html')

@app.get('/logout', name='logout')
def logout(request: Request, user: User = Depends(require_user)):
    request.session.pop('user_id', None)
    return RedirectResponse(str(request.app.url_path_for('index')), status_code=302)

@app.api_route('/upload', methods=['GET', 'POST'], name='upload')
@rl('20/hour')
def upload(request: Request, user: User = Depends(require_user),
           upload_type: str = Form('file'),
           title: str = Form(''),
           tags: str = Form(''),
           is_ai: bool = Form(False),
           artist_name: str = Form(''),
           youtube_url: str = Form(''),
           audio_file: Optional[UploadFile] = File(None),
           cover_file: Optional[UploadFile] = File(None),
           cover_video_file: Optional[UploadFile] = File(None),
           lyrics_file: Optional[UploadFile] = File(None)):
    if request.method == 'GET':
        return render(request, 'upload.html')
    with upload_semaphore:
        lyrics_content = None
        if lyrics_file and lyrics_file.filename:
            try:
                lyrics_file.file.seek(0)
                lyrics_content = lyrics_file.file.read().decode('utf-8')
            except Exception:
                flash(request, 'Ошибка чтения субтитров', 'danger')
                return render(request, 'upload.html')
        artist_val = (artist_name or '').strip() or None
        if upload_type == 'youtube':
            url = (youtube_url or '').strip()
            if not url:
                flash(request, 'Введите ссылку', 'danger')
                return render(request, 'upload.html')
            if not validate_youtube_url(url):
                flash(request, 'Разрешены только youtube.com / youtu.be', 'danger')
                return render(request, 'upload.html')
            tdid = generate_track_dir_id()
            t = Track(track_dir_id=tdid, title='YouTube Import', audio_ext='mp3',
                      tags=tags or '', is_ai=is_ai, uploader_id=user.id,
                      uploaded_at=utcnow(), artist_name=artist_val)
            db.session.add(t)
            db.session.flush()
            sync_track_tags(t)
            commit_with_retry()
            td = get_track_dir(t)
            os.makedirs(td, exist_ok=True)
            try:
                vt, va = download_from_youtube(url, td, tdid)
                t.title = vt
                if not artist_val:
                    t.artist_name = va
                if lyrics_content:
                    save_lyrics_file(t, lyrics_content)
                commit_with_retry()
                _dispatch_webhooks(user.id, 'upload', {'track_id': t.track_dir_id})
                flash(request, 'Загружено', 'success')
                return RedirectResponse(str(request.app.url_path_for('track', track_dir_id=t.track_dir_id)), status_code=302)
            except Exception as e:
                db.session.delete(t)
                commit_with_retry()
                safe_rmtree(td)
                flash(request, f'Ошибка: {e}', 'danger')
                return render(request, 'upload.html')
        if not title or not audio_file or not audio_file.filename:
            flash(request, 'Название и аудио обязательны', 'danger')
            return render(request, 'upload.html')
        if not allowed_audio_file(audio_file.filename):
            flash(request, 'Формат не поддерживается', 'danger')
            return render(request, 'upload.html')
        tdid = generate_track_dir_id()
        t = Track(track_dir_id=tdid, title=title,
                  audio_ext=audio_file.filename.rsplit('.', 1)[1].lower(),
                  tags=tags or '', is_ai=is_ai, uploader_id=user.id,
                  uploaded_at=utcnow(), artist_name=artist_val)
        db.session.add(t)
        db.session.flush()
        sync_track_tags(t)
        commit_with_retry()
        td = get_track_dir(t)
        os.makedirs(td, exist_ok=True)
        audio_path = get_audio_path(t)
        try:
            save_upload_to(audio_file, audio_path)
        except ValueError as e:
            db.session.delete(t)
            commit_with_retry()
            safe_rmtree(td)
            flash(request, str(e), 'danger')
            return render(request, 'upload.html')
        sniffed = sniff_audio(audio_path)
        if not sniffed:
            db.session.delete(t)
            commit_with_retry()
            safe_rmtree(td)
            flash(request, 'Файл не похож на аудио', 'danger')
            return render(request, 'upload.html')
        t.audio_ext = sniffed
        if cover_file and cover_file.filename:
            if is_video_file(cover_file.filename):
                ext = cover_file.filename.rsplit('.', 1)[1].lower()
                tmp = os.path.join(td, f'_tmp_{uuid.uuid4().hex}.{ext}')
                try:
                    save_upload_to(cover_file, tmp)
                except ValueError as e:
                    db.session.delete(t)
                    commit_with_retry()
                    safe_rmtree(td)
                    flash(request, str(e), 'danger')
                    return render(request, 'upload.html')
                try:
                    convert_video_to_cover(tmp, t, make_poster=True)
                except Exception as e:
                    db.session.delete(t)
                    commit_with_retry()
                    safe_rmtree(td)
                    flash(request, f'Ошибка: {e}', 'danger')
                    return render(request, 'upload.html')
                finally:
                    safe_remove(tmp)
            else:
                try:
                    safe_convert_to_webp(cover_file, get_cover_path(t), (512, 512))
                except Exception as e:
                    db.session.delete(t)
                    commit_with_retry()
                    safe_rmtree(td)
                    flash(request, str(e), 'danger')
                    return render(request, 'upload.html')
        if cover_video_file and cover_video_file.filename and is_video_file(cover_video_file.filename):
            ext = cover_video_file.filename.rsplit('.', 1)[1].lower()
            tmp = os.path.join(td, f'_tmp_{uuid.uuid4().hex}.{ext}')
            try:
                save_upload_to(cover_video_file, tmp)
            except ValueError as e:
                db.session.delete(t)
                commit_with_retry()
                safe_rmtree(td)
                flash(request, str(e), 'danger')
                return render(request, 'upload.html')
            try:
                convert_video_to_cover(tmp, t, make_poster=False)
            except Exception as e:
                db.session.delete(t)
                commit_with_retry()
                safe_rmtree(td)
                flash(request, f'Ошибка: {e}', 'danger')
                return render(request, 'upload.html')
            finally:
                safe_remove(tmp)
        ensure_default_cover(t)
        if lyrics_content:
            save_lyrics_file(t, lyrics_content)
        commit_with_retry()
        _dispatch_webhooks(user.id, 'upload', {'track_id': t.track_dir_id})
    flash(request, 'Трек опубликован', 'success')
    return RedirectResponse(str(request.app.url_path_for('track', track_dir_id=t.track_dir_id)), status_code=302)

@app.get('/favorites', name='favorites')
def favorites(request: Request, user: User = Depends(require_user)):
    favs = Favorite.query.filter_by(user_id=user.id).all()
    tracks = [db.session.get(Track, f.track_id) for f in favs]
    return render(request, 'favorites.html', tracks=[t for t in tracks if t])

@app.get('/history', name='listening_history')
def listening_history(request: Request, user: User = Depends(require_user)):
    subq = db.session.query(
        ListeningHistory.track_id,
        func.max(ListeningHistory.listened_at).label('max_time')
    ).filter_by(user_id=user.id).group_by(ListeningHistory.track_id).subquery()
    items = db.session.query(ListeningHistory).join(
        subq, and_(ListeningHistory.track_id == subq.c.track_id,
                   ListeningHistory.listened_at == subq.c.max_time)) \
        .filter(ListeningHistory.user_id == user.id) \
        .order_by(desc(subq.c.max_time)).all()
    return render(request, 'history.html', history=items)

@app.post('/history/delete/{track_dir_id}', name='delete_history_item')
def delete_history_item(request: Request, track_dir_id: str, user: User = Depends(require_user)):
    t = first_or_404(Track.query.filter_by(track_dir_id=track_dir_id))
    ListeningHistory.query.filter_by(user_id=user.id, track_id=t.id).delete()
    ListenEvent.query.filter_by(user_id=user.id, track_id=t.id).delete()
    commit_with_retry()
    flash(request, 'Удалено', 'success')
    return RedirectResponse(str(request.app.url_path_for('listening_history')), status_code=302)

@app.get('/user/{user_dir_id}', name='user_profile')
def user_profile(request: Request, user_dir_id: str):
    u = first_or_404(User.query.filter_by(user_dir_id=user_dir_id))
    tracks = Track.query.filter_by(uploader_id=u.id).order_by(Track.uploaded_at.desc()).paginate(page=1, per_page=20)
    cu = getattr(request.state, 'current_user', None)
    if cu and (cu.id == u.id or cu.is_admin):
        pls = Playlist.query.filter_by(user_id=u.id).order_by(Playlist.name).all()
    else:
        pls = Playlist.query.filter_by(user_id=u.id, is_public=True).order_by(Playlist.name).all()
    return render(request, 'user_profile.html', user=u, tracks=tracks,
                  playlists=pls, stats=get_user_stats(u))

@app.get('/playlists', name='playlists')
def playlists(request: Request, user: User = Depends(require_user)):
    return render(request, 'playlists.html',
                  playlists=Playlist.query.filter_by(user_id=user.id).all())

@app.post('/playlist/new', name='create_playlist')
def create_playlist(request: Request, user: User = Depends(require_user), name: str = Form('')):
    name_val = (name or '').strip()
    if name_val:
        db.session.add(Playlist(playlist_dir_id=generate_playlist_dir_id(),
                                name=name_val, user_id=user.id))
        commit_with_retry()
        flash(request, f'Плейлист "{name_val}" создан', 'success')
    ref = request.headers.get('referer')
    if ref:
        try:
            p = urlparse(ref)
            if p.netloc == request.headers.get('host', ''):
                return RedirectResponse(ref, status_code=302)
        except Exception:
            pass
    return RedirectResponse(str(request.app.url_path_for('playlists')), status_code=302)

@app.post('/playlist/{playlist_dir_id}/delete', name='delete_playlist')
def delete_playlist(request: Request, playlist_dir_id: str, user: User = Depends(require_user)):
    pl = first_or_404(Playlist.query.filter_by(playlist_dir_id=playlist_dir_id))
    if pl.user_id != user.id and not user.is_admin:
        flash(request, 'Нет доступа', 'danger')
        return RedirectResponse(str(request.app.url_path_for('playlists')), status_code=302)
    db.session.delete(pl)
    commit_with_retry()
    flash(request, 'Удалён', 'success')
    return RedirectResponse(str(request.app.url_path_for('playlists')), status_code=302)

@app.api_route('/playlist/{playlist_dir_id}/edit', methods=['GET', 'POST'], name='edit_playlist')
def edit_playlist(request: Request, playlist_dir_id: str, user: User = Depends(require_user),
                  name: str = Form(None)):
    pl = first_or_404(Playlist.query.filter_by(playlist_dir_id=playlist_dir_id))
    if pl.user_id != user.id and not user.is_admin:
        flash(request, 'Нет доступа', 'danger')
        return RedirectResponse(str(request.app.url_path_for('playlists')), status_code=302)
    if request.method == 'POST':
        if name:
            pl.name = name
        commit_with_retry()
        flash(request, 'Обновлён', 'success')
        return RedirectResponse(str(request.app.url_path_for('view_playlist', playlist_dir_id=pl.playlist_dir_id)), status_code=302)
    return render(request, 'edit_playlist.html', playlist=pl)

@app.get('/playlist/{playlist_dir_id}', name='view_playlist')
def view_playlist(request: Request, playlist_dir_id: str):
    pl = first_or_404(Playlist.query.filter_by(playlist_dir_id=playlist_dir_id))
    cu = getattr(request.state, 'current_user', None)
    if not pl.is_public and (not cu or (pl.user_id != cu.id and not cu.is_admin)):
        flash(request, 'Нет доступа', 'danger')
        return RedirectResponse(str(request.app.url_path_for('index')), status_code=302)
    tracks = db.session.query(Track).join(PlaylistTrack) \
        .filter(PlaylistTrack.playlist_id == pl.id).order_by(PlaylistTrack.position).all()
    is_owner = cu and pl.user_id == cu.id
    for t in tracks:
        t.lyrics_content = get_lyrics_content(t)
    return render(request, 'playlist.html', playlist=pl, tracks=tracks, is_owner=is_owner)

@app.api_route('/settings', methods=['GET', 'POST'], name='settings')
def settings(request: Request, user: User = Depends(require_user),
             action: str = Form(None),
             new_login: str = Form(None),
             new_password: str = Form(None),
             confirm_password: str = Form(None),
             current_password: str = Form(None),
             provider: str = Form(None),
             display_name: str = Form(None),
             email: str = Form(None),
             bio: str = Form(None),
             avatar: Optional[UploadFile] = File(None)):
    if request.method == 'POST':
        if action == 'change_username':
            val = (new_login or '').strip()
            if not val:
                flash(request, 'Логин не может быть пустым', 'danger')
            elif len(val) < 3:
                flash(request, 'Логин должен быть не менее 3 символов', 'danger')
            elif val == user.login:
                flash(request, 'Это ваш текущий логин', 'info')
            elif user.last_username_change and (utcnow() - user.last_username_change) < timedelta(days=7):
                days_left = 7 - (utcnow() - user.last_username_change).days
                flash(request, f'Вы можете менять логин раз в неделю. Осталось дней: {days_left}', 'danger')
            elif User.query.filter_by(login=val).first():
                flash(request, 'Этот логин уже занят', 'danger')
            else:
                user.login = val
                user.last_username_change = utcnow()
                commit_with_retry()
                flash(request, 'Логин успешно изменён', 'success')
            return RedirectResponse(str(request.app.url_path_for('settings')), status_code=302)

        if action == 'set_password':
            n = new_password or ''
            c = confirm_password or ''
            if user.has_custom_password:
                flash(request, 'У вас уже установлен пароль', 'info')
            elif len(n) < 8:
                flash(request, 'Минимум 8 символов', 'danger')
            elif n != c:
                flash(request, 'Пароли не совпадают', 'danger')
            else:
                user.password_hash = generate_password_hash(n)
                user.has_custom_password = True
                commit_with_retry()
                flash(request, 'Пароль успешно установлен', 'success')
            return RedirectResponse(str(request.app.url_path_for('settings')), status_code=302)

        if action == 'unlink_oauth':
            linked = OAuthAccount.query.filter_by(user_id=user.id).all()
            if len(linked) <= 1 and not user.has_custom_password:
                flash(request, 'Вы не можете отвязать последний способ входа, так как у вас нет пароля', 'danger')
                return RedirectResponse(str(request.app.url_path_for('settings')), status_code=302)
            acc = OAuthAccount.query.filter_by(user_id=user.id, provider=provider).first()
            if acc:
                db.session.delete(acc)
                commit_with_retry()
                flash(request, f'Аккаунт {provider} успешно отвязан', 'success')
            return RedirectResponse(str(request.app.url_path_for('settings')), status_code=302)

        if action == 'regenerate_widget_token':
            user.widget_token = _make_widget_token()
            user.widget_token_created_at = utcnow()
            commit_with_retry()
            flash(request, 'Токен виджетов обновлён', 'success')
            return RedirectResponse(str(request.app.url_path_for('settings')), status_code=302)

        if action == 'regenerate_api_token':
            revoke_user_tokens(user)
            raw = issue_access_token(user)
            rraw = issue_refresh_token(user)
            request.session['one_time_token'] = raw
            request.session['one_time_refresh'] = rraw
            flash(request, 'Токен обновлён. Скопируйте его — он больше не будет показан.', 'success')
            return RedirectResponse(str(request.app.url_path_for('settings')), status_code=302)

        if action == 'password':
            n = new_password or ''
            c = confirm_password or ''
            if not check_password_hash(user.password_hash, current_password or ''):
                flash(request, 'Текущий пароль неверен', 'danger')
            elif len(n) < 8:
                flash(request, 'Минимум 8 символов', 'danger')
            elif n != c:
                flash(request, 'Пароли не совпадают', 'danger')
            else:
                user.password_hash = generate_password_hash(n)
                user.has_custom_password = True
                user.api_token_hash = None
                user.api_token_expires_at = None
                RefreshToken.query.filter_by(user_id=user.id).update({'revoked': True})
                commit_with_retry()
                request.session.pop('user_id', None)
                flash(request, 'Пароль изменён. Войдите заново.', 'success')
                return RedirectResponse(str(request.app.url_path_for('login')), status_code=302)
            return RedirectResponse(str(request.app.url_path_for('settings')), status_code=302)

        if action == 'profile':
            if display_name:
                user.display_name = display_name
            user.bio = bio or ''
            if email and email != user.email:
                if User.query.filter_by(email=email).first():
                    flash(request, 'Email занят', 'danger')
                else:
                    user.email = email
            if avatar and avatar.filename:
                try:
                    ap = get_avatar_path(user)
                    tmp = ap + '.tmp'
                    tmp_src = tmp + '.src'
                    save_upload_to(avatar, tmp_src)
                    try:
                        convert_to_webp(tmp_src, tmp, (256, 256))
                    finally:
                        safe_remove(tmp_src)
                    if not safe_replace(tmp, ap):
                        safe_remove(tmp)
                        flash(request, 'Не удалось заменить аватар', 'danger')
                        return RedirectResponse(str(request.app.url_path_for('settings')), status_code=302)
                except ValueError as e:
                    flash(request, str(e), 'danger')
                    return RedirectResponse(str(request.app.url_path_for('settings')), status_code=302)
            commit_with_retry()
            flash(request, 'Профиль обновлён', 'success')
            return RedirectResponse(str(request.app.url_path_for('settings')), status_code=302)
        return RedirectResponse(str(request.app.url_path_for('settings')), status_code=302)

    one_time = request.session.pop('one_time_token', None)
    one_time_r = request.session.pop('one_time_refresh', None)
    linked_providers = [acc.provider for acc in OAuthAccount.query.filter_by(user_id=user.id).all()]
    days_until = 0
    if user.last_username_change:
        delta = utcnow() - user.last_username_change
        if delta.days < 7:
            days_until = 7 - delta.days
    return render(request, 'settings.html', one_time_token=one_time,
                  one_time_refresh=one_time_r,
                  linked_providers=linked_providers,
                  days_until_username_change=days_until)

@app.get('/auth/quick', name='auth_quick')
def auth_quick(request: Request):
    desktop_redirect = request.query_params.get('desktop_redirect')
    state = request.query_params.get('state')
    if not desktop_redirect or not re.match(r'^http://127\.0\.0\.1:\d+/callback$', desktop_redirect):
        flash(request, 'Некорректный запрос от приложения', 'danger')
        return RedirectResponse(str(request.app.url_path_for('index')), status_code=302)
    cu = getattr(request.state, 'current_user', None)
    if cu:
        code = generate_desktop_code(cu.id)
        return RedirectResponse(f"{desktop_redirect}?code={code}&state={state}", status_code=302)
    request.session['desktop_redirect'] = desktop_redirect
    request.session['desktop_state'] = state
    flash(request, 'Войдите в аккаунт, чтобы вернуться в приложение', 'info')
    return RedirectResponse(str(request.app.url_path_for('login')), status_code=302)

@app.get('/auth/{provider}/login', name='oauth_start')
@rl('20/minute')
def oauth_start(request: Request, provider: str):
    if provider not in OAUTH_PROVIDERS:
        flash(request, 'OAuth провайдер не настроен', 'danger')
        return RedirectResponse(str(request.app.url_path_for('login')), status_code=302)
    link_mode = request.query_params.get('link') == '1'
    cu = getattr(request.state, 'current_user', None)
    if link_mode:
        if not cu:
            flash(request, 'Войдите, чтобы привязать аккаунт', 'danger')
            return RedirectResponse(str(request.app.url_path_for('login')), status_code=302)
        request.session['oauth_link_user_id'] = cu.id
    else:
        request.session.pop('oauth_link_user_id', None)
    cfg = OAUTH_PROVIDERS[provider]
    state = secrets.token_urlsafe(24)
    request.session['oauth_state'] = state
    request.session['oauth_provider'] = provider
    desktop_redirect = request.query_params.get('desktop_redirect')
    desktop_state = request.query_params.get('state')
    if desktop_redirect and re.match(r'^http://127\.0\.0\.1:\d+/callback$', desktop_redirect):
        request.session['desktop_redirect'] = desktop_redirect
        request.session['desktop_state'] = desktop_state
    else:
        request.session['desktop_redirect'] = None
        request.session['desktop_state'] = None
    params = {
        'client_id': cfg['client_id'],
        'redirect_uri': str(request.url_for('oauth_callback', provider=provider)),
        'scope': cfg['scope'],
        'state': state,
        'response_type': 'code',
    }
    if provider == 'google':
        params['access_type'] = 'online'
        params['prompt'] = 'select_account'
    return RedirectResponse(cfg['authorize_url'] + '?' + urlencode(params), status_code=302)

@app.get('/auth/{provider}/callback', name='oauth_callback')
def oauth_callback(request: Request, provider: str):
    if provider not in OAUTH_PROVIDERS:
        flash(request, 'OAuth провайдер не настроен', 'danger')
        return RedirectResponse(str(request.app.url_path_for('login')), status_code=302)
    state = request.query_params.get('state', '')
    expected = request.session.pop('oauth_state', None)
    link_user_id = request.session.pop('oauth_link_user_id', None)
    if not expected or state != expected:
        flash(request, 'Неверный state OAuth', 'danger')
        return RedirectResponse(str(request.app.url_path_for('login')), status_code=302)
    code = request.query_params.get('code', '')
    if not code:
        flash(request, 'OAuth отказано', 'danger')
        return RedirectResponse(str(request.app.url_path_for('login')), status_code=302)
    cfg = OAUTH_PROVIDERS[provider]
    headers = {'Accept': 'application/json'}
    try:
        r = requests.post(cfg['token_url'], data={
            'client_id': cfg['client_id'],
            'client_secret': cfg['client_secret'],
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': str(request.url_for('oauth_callback', provider=provider)),
        }, headers=headers, timeout=15)
        r.raise_for_status()
        tok = r.json()
        at = tok.get('access_token')
        if not at:
            raise Exception('no access_token in response')
        auth = {'Authorization': f'Bearer {at}', 'Accept': 'application/json'}
        r = requests.get(cfg['userinfo_url'], headers=auth, timeout=15)
        r.raise_for_status()
        info = r.json()
    except Exception as e:
        flash(request, f'OAuth ошибка: {e}', 'danger')
        return RedirectResponse(str(request.app.url_path_for('login')), status_code=302)
    if provider == 'google':
        pid = str(info.get('id') or info.get('sub') or '')
        email = (info.get('email') or '').strip()
        name = (info.get('name') or info.get('given_name') or email.split('@')[0]).strip()
    else:
        pid = str(info.get('id') or '')
        email = (info.get('email') or '').strip()
        name = (info.get('name') or info.get('login') or email.split('@')[0]).strip()
        if not email:
            try:
                r = requests.get(cfg['emails_url'], headers=auth, timeout=10)
                r.raise_for_status()
                for e in r.json():
                    if e.get('primary') and e.get('verified'):
                        email = e.get('email')
                        break
            except Exception:
                pass
    if not pid:
        flash(request, 'OAuth: не удалось получить provider user id', 'danger')
        return RedirectResponse(str(request.app.url_path_for('login')), status_code=302)
    acct = OAuthAccount.query.filter_by(provider=provider, provider_user_id=pid).first()
    if link_user_id:
        u = db.session.get(User, link_user_id)
        if not u:
            flash(request, 'Пользователь не найден', 'danger')
            return RedirectResponse(str(request.app.url_path_for('settings')), status_code=302)
        if acct:
            if acct.user_id == u.id:
                flash(request, f'Аккаунт {provider} уже привязан', 'info')
            else:
                flash(request, f'Этот {provider} аккаунт уже привязан к другому пользователю', 'danger')
            return RedirectResponse(str(request.app.url_path_for('settings')), status_code=302)
        db.session.add(OAuthAccount(user_id=u.id, provider=provider, provider_user_id=pid))
        commit_with_retry()
        flash(request, f'Аккаунт {provider} привязан', 'success')
        return RedirectResponse(str(request.app.url_path_for('settings')), status_code=302)
    if not email:
        flash(request, 'OAuth: не удалось получить email', 'danger')
        return RedirectResponse(str(request.app.url_path_for('login')), status_code=302)
    if acct:
        u = db.session.get(User, acct.user_id)
    else:
        u = User.query.filter_by(email=email).first()
        if not u:
            base = email.split('@')[0][:20] or 'user'
            login_candidate = base
            n = 0
            while User.query.filter_by(login=login_candidate).first():
                n += 1
                login_candidate = f'{base}{n}'
            u = User(user_dir_id=generate_user_dir_id(), login=login_candidate,
                     email=email, password_hash=generate_password_hash(secrets.token_hex(16)),
                     display_name=name or login_candidate, has_custom_password=False)
            db.session.add(u)
            commit_with_retry()
            os.makedirs(get_user_dir(u), exist_ok=True)
        db.session.add(OAuthAccount(user_id=u.id, provider=provider, provider_user_id=pid))
        commit_with_retry()
    if not u:
        flash(request, 'OAuth: пользователь не найден', 'danger')
        return RedirectResponse(str(request.app.url_path_for('login')), status_code=302)
    request.session['user_id'] = u.id
    desktop_redirect = request.session.pop('desktop_redirect', None)
    desktop_state = request.session.pop('desktop_state', None)
    if desktop_redirect and re.match(r'^http://127\.0\.0\.1:\d+/callback$', desktop_redirect):
        desktop_code = generate_desktop_code(u.id)
        return RedirectResponse(f"{desktop_redirect}?code={desktop_code}&state={desktop_state}", status_code=302)
    return RedirectResponse(str(request.app.url_path_for('index')), status_code=302)

api_v1 = APIRouter(prefix='/api/v1')

@api_v1.post('/auth/register')
@rl('10/hour')
def api_register(request: Request, data: dict = Body(...)):
    login_val = (data.get('login') or '').strip()
    email = (data.get('email') or '').strip()
    pw = data.get('password') or ''
    dn = (data.get('display_name') or login_val).strip()
    if not login_val or not email or not pw:
        return _json_error('bad_request', 'login, email and password are required')
    if len(pw) < 8:
        return _json_error('bad_request', 'password must be at least 8 characters')
    if User.query.filter_by(login=login_val).first():
        return _json_error('conflict', 'Login already taken', 409)
    if User.query.filter_by(email=email).first():
        return _json_error('conflict', 'Email already taken', 409)
    u = User(user_dir_id=generate_user_dir_id(), login=login_val, email=email,
             password_hash=generate_password_hash(pw), display_name=dn or login_val)
    db.session.add(u)
    commit_with_retry()
    os.makedirs(get_user_dir(u), exist_ok=True)
    access = issue_access_token(u)
    refresh = issue_refresh_token(u)
    return _json_ok({'access_token': access, 'refresh_token': refresh,
                     'token_type': 'Bearer', 'user': serialize_user(u)})

@api_v1.post('/auth/login')
@rl('20/minute')
def api_login(request: Request, data: dict = Body(...)):
    ident = data.get('login') or ''
    pw = data.get('password') or ''
    u = User.query.filter(or_(User.login == ident, User.email == ident)).first()
    if not u or not check_password_hash(u.password_hash, pw):
        return _json_error('unauthorized', 'Invalid credentials', 401)
    access = issue_access_token(u)
    refresh = issue_refresh_token(u)
    return _json_ok({'access_token': access, 'refresh_token': refresh,
                     'token_type': 'Bearer', 'user': serialize_user(u)})

@api_v1.post('/auth/exchange')
@rl('10/minute')
def desktop_exchange(request: Request, data: dict = Body(...)):
    code = data.get('code')
    if not code:
        return _json_error('bad_request', 'Code required')
    with _codes_lock:
        payload = _desktop_codes.pop(code, None)
    if not payload:
        return _json_error('unauthorized', 'Invalid or expired code', 401)
    user_id, created_at = payload
    if time.time() - created_at > 30:
        return _json_error('unauthorized', 'Code expired', 401)
    u = db.session.get(User, user_id)
    if not u:
        return _json_error('unauthorized', 'User not found', 401)
    access = issue_access_token(u)
    refresh = issue_refresh_token(u)
    return _json_ok({'access_token': access, 'refresh_token': refresh,
                     'token_type': 'Bearer', 'user': serialize_user(u)})

@api_v1.post('/auth/refresh')
@rl('30/minute')
def api_refresh(request: Request, data: dict = Body(...)):
    raw = data.get('refresh_token') or ''
    if not raw:
        return _json_error('bad_request', 'refresh_token is required')
    rt = RefreshToken.query.filter_by(token_hash=_token_hash(raw), revoked=False).first()
    if not rt or rt.expires_at < utcnow():
        return _json_error('unauthorized', 'Invalid or expired refresh token', 401)
    u = db.session.get(User, rt.user_id)
    if not u:
        return _json_error('unauthorized', 'Invalid refresh token', 401)
    rt.revoked = True
    access = issue_access_token(u)
    new_refresh = issue_refresh_token(u)
    commit_with_retry()
    return _json_ok({'access_token': access, 'refresh_token': new_refresh,
                     'token_type': 'Bearer', 'user': serialize_user(u)})

@api_v1.post('/auth/logout')
def api_logout(request: Request, user: User = Depends(require_api_user)):
    revoke_user_tokens(user)
    return _json_ok({})

@api_v1.get('/auth/me')
def api_me(request: Request, user: User = Depends(require_api_user)):
    return _json_ok(serialize_user(user, include_stats=True))

@api_v1.patch('/users/me')
def api_update_me(request: Request, user: User = Depends(require_api_user),
                  display_name: str = Form(None), bio: str = Form(None),
                  avatar_file: Optional[UploadFile] = File(None)):
    if display_name:
        user.display_name = display_name
    if bio is not None:
        user.bio = bio
    if avatar_file and avatar_file.filename:
        try:
            ap = get_avatar_path(user)
            tmp = ap + '.tmp'
            tmp_src = tmp + '.src'
            save_upload_to(avatar_file, tmp_src)
            try:
                convert_to_webp(tmp_src, tmp, (256, 256))
            finally:
                safe_remove(tmp_src)
            if not safe_replace(tmp, ap):
                safe_remove(tmp)
                return _json_error('internal_error', 'Не удалось сохранить аватар', 500)
        except Exception as e:
            return _json_error('internal_error', str(e), 500)
    commit_with_retry()
    return _json_ok(serialize_user(user, include_stats=True))

@api_v1.get('/tracks')
def api_list_tracks(request: Request, response: Response):
    response.headers['Cache-Control'] = 'public, max-age=20, stale-while-revalidate=40'
    page = int(request.query_params.get('page', 1))
    pp = min(int(request.query_params.get('per_page', 20)), 100)
    sort = request.query_params.get('sort', 'new')
    q = Track.query.options(selectinload(Track.uploader))
    if sort == 'popular':
        q = q.order_by(Track.play_count.desc())
    elif sort == 'likes':
        q = q.order_by(Track.likes_count.desc())
    else:
        q = q.order_by(Track.uploaded_at.desc())
    pg = q.paginate(page=page, per_page=pp, error_out=False)
    return _json_ok({'items': [serialize_track(t) for t in pg.items],
                     'page': pg.page, 'per_page': pg.per_page,
                     'total': pg.total, 'pages': pg.pages})

@api_v1.post('/tracks')
@rl('20/hour')
def api_create_track(request: Request, user: User = Depends(require_api_user),
                     upload_type: str = Form('file'), title: str = Form(''),
                     tags: str = Form(''), is_ai: str = Form(''), artist_name: str = Form(''),
                     youtube_url: str = Form(''),
                     audio_file: Optional[UploadFile] = File(None),
                     cover_file: Optional[UploadFile] = File(None),
                     cover_video_file: Optional[UploadFile] = File(None),
                     lyrics_file: Optional[UploadFile] = File(None)):
    is_ai_val = (is_ai or '').lower() in ('1', 'true', 'yes', 'on')
    artist_val = (artist_name or '').strip() or None
    lyrics = None
    if lyrics_file and lyrics_file.filename:
        try:
            lyrics_file.file.seek(0)
            lyrics = lyrics_file.file.read().decode('utf-8')
        except Exception:
            return _json_error('bad_request', 'Bad lyrics file')
    with upload_semaphore:
        if upload_type == 'youtube':
            url = (youtube_url or '').strip()
            if not url or not validate_youtube_url(url):
                return _json_error('bad_request', 'youtube_url invalid')
            tdid = generate_track_dir_id()
            t = Track(track_dir_id=tdid, title='YouTube Import', audio_ext='mp3',
                      tags=tags or '', is_ai=is_ai_val, uploader_id=user.id,
                      uploaded_at=utcnow(), artist_name=artist_val)
            db.session.add(t)
            db.session.flush()
            sync_track_tags(t)
            commit_with_retry()
            td = get_track_dir(t)
            os.makedirs(td, exist_ok=True)
            try:
                vt, va = download_from_youtube(url, td, tdid)
                t.title = vt
                if not artist_val:
                    t.artist_name = va
                if lyrics:
                    save_lyrics_file(t, lyrics)
                commit_with_retry()
                _dispatch_webhooks(user.id, 'upload', {'track_id': t.track_dir_id})
                return _json_ok(serialize_track(t))
            except Exception as e:
                db.session.delete(t)
                commit_with_retry()
                safe_rmtree(td)
                return _json_error('internal_error', str(e), 500)
        if not audio_file or not audio_file.filename or not allowed_audio_file(audio_file.filename):
            return _json_error('bad_request', 'Valid audio_file required')
        if not title:
            return _json_error('bad_request', 'title required')
        tdid = generate_track_dir_id()
        t = Track(track_dir_id=tdid, title=title,
                  audio_ext=audio_file.filename.rsplit('.', 1)[1].lower(),
                  tags=tags or '', is_ai=is_ai_val, uploader_id=user.id,
                  uploaded_at=utcnow(), artist_name=artist_val)
        db.session.add(t)
        db.session.flush()
        sync_track_tags(t)
        commit_with_retry()
        td = get_track_dir(t)
        os.makedirs(td, exist_ok=True)
        ap = get_audio_path(t)
        try:
            save_upload_to(audio_file, ap)
        except ValueError as e:
            db.session.delete(t)
            commit_with_retry()
            safe_rmtree(td)
            return _json_error('bad_request', str(e))
        sn = sniff_audio(ap)
        if not sn:
            db.session.delete(t)
            commit_with_retry()
            safe_rmtree(td)
            return _json_error('bad_request', 'Audio signature not recognized')
        t.audio_ext = sn
        if cover_file and cover_file.filename:
            if is_video_file(cover_file.filename):
                ext = cover_file.filename.rsplit('.', 1)[1].lower()
                tmp = os.path.join(td, f'_t_{uuid.uuid4().hex}.{ext}')
                try:
                    save_upload_to(cover_file, tmp)
                except ValueError as e:
                    db.session.delete(t)
                    commit_with_retry()
                    safe_rmtree(td)
                    return _json_error('bad_request', str(e))
                try:
                    convert_video_to_cover(tmp, t, make_poster=True)
                except Exception as e:
                    db.session.delete(t)
                    commit_with_retry()
                    safe_rmtree(td)
                    return _json_error('internal_error', str(e), 500)
                finally:
                    safe_remove(tmp)
            else:
                try:
                    safe_convert_to_webp(cover_file, get_cover_path(t), (512, 512))
                except Exception as e:
                    db.session.delete(t)
                    commit_with_retry()
                    safe_rmtree(td)
                    return _json_error('internal_error', str(e), 500)
        if cover_video_file and cover_video_file.filename and is_video_file(cover_video_file.filename):
            ext = cover_video_file.filename.rsplit('.', 1)[1].lower()
            tmp = os.path.join(td, f'_t_{uuid.uuid4().hex}.{ext}')
            try:
                save_upload_to(cover_video_file, tmp)
            except ValueError as e:
                db.session.delete(t)
                commit_with_retry()
                safe_rmtree(td)
                return _json_error('bad_request', str(e))
            try:
                convert_video_to_cover(tmp, t, make_poster=False)
            except Exception as e:
                db.session.delete(t)
                commit_with_retry()
                safe_rmtree(td)
                return _json_error('internal_error', str(e), 500)
            finally:
                safe_remove(tmp)
        ensure_default_cover(t)
        if lyrics:
            save_lyrics_file(t, lyrics)
        commit_with_retry()
        _dispatch_webhooks(user.id, 'upload', {'track_id': t.track_dir_id})
    return _json_ok(serialize_track(t))

@api_v1.get('/tracks/{track_dir_id}')
def api_get_track(request: Request, track_dir_id: str):
    t = Track.query.filter_by(track_dir_id=track_dir_id).first()
    if not t:
        return _json_error('not_found', 'Track not found', 404)
    data = serialize_track(t, include_lyrics=True)
    api_user = getattr(request.state, 'api_user', None)
    if api_user:
        fav = Favorite.query.filter_by(user_id=api_user.id, track_id=t.id).first()
        r = Rating.query.filter_by(user_id=api_user.id, track_id=t.id).first()
        pls = db.session.query(PlaylistTrack, Playlist).join(
            Playlist, Playlist.id == PlaylistTrack.playlist_id).filter(
            PlaylistTrack.track_id == t.id, Playlist.user_id == api_user.id).all()
        data['is_favorite'] = fav is not None
        data['user_rating'] = r.value if r else 0
        data['in_playlists'] = [pl.playlist_dir_id for _, pl in pls]
    else:
        data['is_favorite'] = False
        data['user_rating'] = 0
        data['in_playlists'] = []
    return _json_ok(data)

@api_v1.api_route('/tracks/{track_dir_id}', methods=['PATCH', 'DELETE'])
def api_modify_track(request: Request, track_dir_id: str, user: User = Depends(require_api_user),
                     title: str = Form(None), artist_name: str = Form(None), tags: str = Form(None),
                     is_ai: Optional[str] = Form(None),
                     cover_file: Optional[UploadFile] = File(None),
                     lyrics_file: Optional[UploadFile] = File(None)):
    t = Track.query.filter_by(track_dir_id=track_dir_id).first()
    if not t:
        return _json_error('not_found', 'Track not found', 404)
    if t.uploader_id != user.id and not user.is_admin:
        return _json_error('forbidden', 'Access denied', 403)
    if request.method == 'DELETE':
        safe_rmtree(get_track_dir(t))
        db.session.delete(t)
        commit_with_retry()
        return _json_ok({})
    if title:
        t.title = title
    if artist_name is not None:
        t.artist_name = artist_name or None
    if tags is not None:
        t.tags = tags
        db.session.flush()
        sync_track_tags(t)
    if is_ai is not None:
        t.is_ai = is_ai.lower() in ('1', 'true', 'yes', 'on')
    if cover_file and cover_file.filename:
        if is_video_file(cover_file.filename):
            ext = cover_file.filename.rsplit('.', 1)[1].lower()
            tmp_path = os.path.join(get_track_dir(t), f'_tmp_{uuid.uuid4().hex}.{ext}')
            try:
                save_upload_to(cover_file, tmp_path)
            except ValueError as e:
                return _json_error('bad_request', str(e))
            try:
                convert_video_to_cover(tmp_path, t, make_poster=True)
            except Exception as e:
                return _json_error('internal_error', str(e), 500)
            finally:
                safe_remove(tmp_path)
        else:
            try:
                safe_convert_to_webp(cover_file, get_cover_path(t), (512, 512))
            except Exception as e:
                return _json_error('internal_error', str(e), 500)
    if lyrics_file and lyrics_file.filename:
        try:
            lyrics_file.file.seek(0)
            save_lyrics_file(t, lyrics_file.file.read().decode('utf-8'))
        except Exception as e:
            return _json_error('internal_error', str(e), 500)
    commit_with_retry()
    return _json_ok(serialize_track(t))

@api_v1.get('/tracks/{track_dir_id}/stream', name='api_v1.api_stream_track')
def api_stream_track(track_dir_id: str):
    t = Track.query.filter_by(track_dir_id=track_dir_id).first()
    if not t:
        return _json_error('not_found', 'Track not found', 404)
    path = get_audio_path(t)
    if not os.path.exists(path):
        return _json_error('not_found', 'Audio not found', 404)
    mime = {'mp3': 'audio/mpeg', 'wav': 'audio/wav', 'ogg': 'audio/ogg', 'm4a': 'audio/mp4'}.get(t.audio_ext, 'audio/mpeg')
    return FileResponse(path, media_type=mime, headers={'Accept-Ranges': 'bytes', 'Cache-Control': 'private, max-age=3600'})

@api_v1.get('/tracks/{track_dir_id}/similar')
def api_similar_tracks(request: Request, track_dir_id: str):
    t = Track.query.filter_by(track_dir_id=track_dir_id).first()
    if not t:
        return _json_error('not_found', 'Track not found', 404)
    limit = min(int(request.query_params.get('limit', 6)), 30)
    api_user = getattr(request.state, 'api_user', None)
    return _json_ok({'items': [serialize_track(x) for x in get_track_recommendations(t, api_user, limit=limit)]})

@api_v1.get('/tracks/{track_dir_id}/lyrics')
def api_get_lyrics(track_dir_id: str):
    t = Track.query.filter_by(track_dir_id=track_dir_id).first()
    if not t:
        return _json_error('not_found', 'Track not found', 404)
    return _json_ok({'lyrics': get_lyrics_content(t)})

@api_v1.get('/tracks/{track_dir_id}/status')
def api_track_status(request: Request, track_dir_id: str, user: User = Depends(require_user)):
    t = first_or_404(Track.query.filter_by(track_dir_id=track_dir_id))
    is_fav = Favorite.query.filter_by(user_id=user.id, track_id=t.id).first() is not None
    pl_ids = [row[0] for row in db.session.query(Playlist.playlist_dir_id).join(
        PlaylistTrack, PlaylistTrack.playlist_id == Playlist.id
    ).filter(
        Playlist.user_id == user.id,
        PlaylistTrack.track_id == t.id
    ).all()]
    r = Rating.query.filter_by(user_id=user.id, track_id=t.id).first()
    return JSONResponse({
        'is_favorite': is_fav,
        'playlist_ids': pl_ids,
        'user_rating': r.value if r else 0,
        'likes': t.likes_count,
        'dislikes': t.dislikes_count,
        'plays': t.play_count,
    })

@api_v1.post('/tracks/{track_dir_id}/rate')
@rl('60/minute')
def api_rate_track(request: Request, track_dir_id: str, user: User = Depends(require_user),
                   value: int = Body(..., embed=True)):
    t = first_or_404(Track.query.filter_by(track_dir_id=track_dir_id))
    if value not in (1, -1):
        return JSONResponse({'error': 'Invalid value'}, status_code=400)
    existing = Rating.query.filter_by(user_id=user.id, track_id=t.id).first()
    try:
        if existing:
            if existing.value == value:
                db.session.delete(existing)
                if value == 1:
                    t.likes_count = max(0, t.likes_count - 1)
                else:
                    t.dislikes_count = max(0, t.dislikes_count - 1)
                commit_with_retry()
                return JSONResponse({'likes': t.likes_count, 'dislikes': t.dislikes_count, 'user_rating': 0})
            if existing.value == 1:
                t.likes_count = max(0, t.likes_count - 1)
                t.dislikes_count += 1
            else:
                t.dislikes_count = max(0, t.dislikes_count - 1)
                t.likes_count += 1
            existing.value = value
            commit_with_retry()
            return JSONResponse({'likes': t.likes_count, 'dislikes': t.dislikes_count, 'user_rating': value})
        db.session.add(Rating(user_id=user.id, track_id=t.id, value=value))
        if value == 1:
            t.likes_count += 1
        else:
            t.dislikes_count += 1
        commit_with_retry()
        return JSONResponse({'likes': t.likes_count, 'dislikes': t.dislikes_count, 'user_rating': value})
    except Exception:
        db.session.rollback()
        return JSONResponse({'error': 'Retry'}, status_code=503)

@api_v1.post('/tracks/{track_dir_id}/listen')
@rl('120/minute')
def api_listen_v1(request: Request, track_dir_id: str, user: User = Depends(require_api_user)):
    t = Track.query.filter_by(track_dir_id=track_dir_id).first()
    if not t:
        return _json_error('not_found', 'Track not found', 404)
    now = utcnow()
    try:
        if ListenEvent.query.filter(ListenEvent.user_id == user.id, ListenEvent.track_id == t.id,
                                    ListenEvent.listened_at >= now - timedelta(seconds=60)).first():
            return _json_ok({'status': 'throttled'})
        db.session.add(ListenEvent(user_id=user.id, track_id=t.id, listened_at=now))
        with db.session.no_autoflush:
            h = ListeningHistory.query.filter_by(user_id=user.id, track_id=t.id).first()
        if h:
            h.count += 1
            h.listened_at = now
        else:
            db.session.add(ListeningHistory(user_id=user.id, track_id=t.id, count=1, listened_at=now))
        user.current_track_id = t.id
        user.current_track_started_at = now
        t.play_count = (t.play_count or 0) + 1
        commit_with_retry()
        ws_broadcast_now_playing(user.id, t.id)
        _dispatch_webhooks(user.id, 'listen', {'track_id': t.track_dir_id, 'at': now.isoformat()})
        return _json_ok({'status': 'ok'})
    except Exception:
        db.session.rollback()
        return _json_error('internal_error', 'Failed', 500)

@api_v1.api_route('/tracks/{track_dir_id}/favorite', methods=['POST', 'DELETE'])
def api_favorite(request: Request, track_dir_id: str, user: User = Depends(require_user)):
    t = Track.query.filter_by(track_dir_id=track_dir_id).first()
    if not t:
        return _json_error('not_found', 'Track not found', 404)
    fav = Favorite.query.filter_by(user_id=user.id, track_id=t.id).first()
    if request.method == 'DELETE':
        if fav:
            db.session.delete(fav)
            commit_with_retry()
        return JSONResponse({'status': 'removed', 'ok': True, 'is_favorite': False,
                             'data': {'is_favorite': False}})
    if fav:
        db.session.delete(fav)
        commit_with_retry()
        return JSONResponse({'status': 'removed', 'ok': True, 'is_favorite': False,
                             'data': {'is_favorite': False}})
    db.session.add(Favorite(user_id=user.id, track_id=t.id))
    commit_with_retry()
    return JSONResponse({'status': 'added', 'ok': True, 'is_favorite': True,
                         'data': {'is_favorite': True}})

@api_v1.get('/recommendations')
def api_recommendations(request: Request):
    limit = min(int(request.query_params.get('limit', 16)), 50)
    api_user = getattr(request.state, 'api_user', None)
    return _json_ok({'items': [serialize_track(t) for t in get_recommendations(api_user, limit)]})

@api_v1.get('/charts')
def api_charts(request: Request, response: Response):
    response.headers['Cache-Control'] = 'public, max-age=60, stale-while-revalidate=120'
    days = int(request.query_params.get('period', 30))
    limit = min(int(request.query_params.get('limit', 50)), 200)
    rows = db.session.query(Track, func.count(ListenEvent.id).label('cnt')) \
        .join(ListenEvent, ListenEvent.track_id == Track.id) \
        .options(selectinload(Track.uploader)) \
        .filter(ListenEvent.listened_at >= utcnow() - timedelta(days=days)) \
        .group_by(Track.id).order_by(desc('cnt')).limit(limit).all()
    return _json_ok({'period_days': days, 'items': [serialize_track(r[0]) for r in rows]})

@api_v1.get('/new-releases')
def api_new_releases(request: Request, response: Response):
    response.headers['Cache-Control'] = 'public, max-age=60, stale-while-revalidate=120'
    days = int(request.query_params.get('days', 7))
    limit = min(int(request.query_params.get('limit', 20)), 100)
    rows = Track.query.options(selectinload(Track.uploader)) \
        .filter(Track.uploaded_at >= utcnow() - timedelta(days=days)) \
        .order_by(Track.uploaded_at.desc()).limit(limit).all()
    return _json_ok({'items': [serialize_track(t) for t in rows]})

@api_v1.get('/search')
def api_search_v1(request: Request):
    q = request.query_params.get('q', '').strip()
    kind = request.query_params.get('type', 'tracks')
    limit = min(int(request.query_params.get('limit', 20)), 100)
    if not q:
        return _json_ok({'type': kind, 'items': []})
    if kind == 'playlists':
        rows = Playlist.query.filter(Playlist.is_public.is_(True), Playlist.name.ilike(f'%{q}%')) \
            .order_by(Playlist.id.desc()).limit(limit).all()
        return _json_ok({'type': 'playlists', 'items': [serialize_playlist(p) for p in rows]})
    if kind == 'users':
        rows = User.query.filter(or_(User.login.ilike(f'%{q}%'), User.display_name.ilike(f'%{q}%'))).limit(limit).all()
        return _json_ok({'type': 'users', 'items': [serialize_user(u) for u in rows]})
    if kind == 'tags':
        rows = Tag.query.filter(Tag.name.ilike(f'%{q}%')).limit(limit).all()
        return _json_ok({'type': 'tags', 'items': [{'name': t.name} for t in rows]})
    rows = Track.query.filter(or_(
        Track.title.ilike(f'%{q}%'),
        Track.artist_name.ilike(f'%{q}%'),
        Track.uploader.has(User.display_name.ilike(f'%{q}%'))
    )).order_by(Track.play_count.desc()).limit(limit).all()
    return _json_ok({'type': 'tracks', 'items': [serialize_track(t) for t in rows]})

@api_v1.get('/advanced-search')
def api_advanced(request: Request):
    title = request.query_params.get('title', '')
    artist = request.query_params.get('artist', '')
    tag = request.query_params.get('tag', '')
    is_ai = request.query_params.get('is_ai')
    limit = min(int(request.query_params.get('limit', 50)), 200)
    q = Track.query
    if title:
        q = q.filter(Track.title.ilike(f'%{title}%'))
    if artist:
        q = q.filter(or_(Track.artist_name.ilike(f'%{artist}%'),
                         Track.uploader.has(User.display_name.ilike(f'%{artist}%'))))
    if tag:
        t_obj = Tag.query.filter_by(name=tag.strip().lower()).first()
        if t_obj:
            q = q.filter(Track.id.in_(db.session.query(TrackTag.track_id).filter(TrackTag.tag_id == t_obj.id)))
        else:
            q = q.filter(Track.id == -1)
    if is_ai == 'yes':
        q = q.filter(Track.is_ai.is_(True))
    elif is_ai == 'no':
        q = q.filter(Track.is_ai.is_(False))
    return _json_ok({'items': [serialize_track(t) for t in q.order_by(Track.uploaded_at.desc()).limit(limit).all()]})

@api_v1.get('/tags')
def api_tags(request: Request):
    q = request.query_params.get('q', '').strip()
    limit = min(int(request.query_params.get('limit', 20)), 100)
    query = Tag.query
    if q:
        query = query.filter(Tag.name.ilike(f'%{q}%'))
    return _json_ok({'items': [{'name': t.name} for t in query.order_by(Tag.name).limit(limit).all()]})

@api_v1.get('/users/{user_dir_id}')
def api_get_user(user_dir_id: str):
    u = User.query.filter_by(user_dir_id=user_dir_id).first()
    if not u:
        return _json_error('not_found', 'User not found', 404)
    return _json_ok(serialize_user(u, include_stats=True))

@api_v1.get('/users/{user_dir_id}/tracks')
def api_user_tracks(request: Request, user_dir_id: str):
    u = User.query.filter_by(user_dir_id=user_dir_id).first()
    if not u:
        return _json_error('not_found', 'User not found', 404)
    page = int(request.query_params.get('page', 1))
    pp = min(int(request.query_params.get('per_page', 20)), 100)
    sort = request.query_params.get('sort', 'new')
    q = Track.query.options(selectinload(Track.uploader)).filter_by(uploader_id=u.id)
    if sort == 'popular':
        q = q.order_by(Track.play_count.desc())
    elif sort == 'old':
        q = q.order_by(Track.uploaded_at.asc())
    else:
        q = q.order_by(Track.uploaded_at.desc())
    pg = q.paginate(page=page, per_page=pp, error_out=False)
    return _json_ok({'items': [serialize_track(t) for t in pg.items],
                     'page': pg.page, 'per_page': pg.per_page,
                     'total': pg.total, 'pages': pg.pages})

@api_v1.get('/users/{user_dir_id}/playlists')
def api_user_playlists(request: Request, user_dir_id: str):
    u = User.query.filter_by(user_dir_id=user_dir_id).first()
    if not u:
        return _json_error('not_found', 'User not found', 404)
    api_user = getattr(request.state, 'api_user', None)
    if api_user and api_user.id == u.id:
        rows = Playlist.query.filter_by(user_id=u.id).order_by(Playlist.name).all()
    else:
        rows = Playlist.query.filter_by(user_id=u.id, is_public=True).order_by(Playlist.name).all()
    return _json_ok({'items': [serialize_playlist(p) for p in rows]})

@api_v1.get('/favorites')
def api_favorites(request: Request, user: User = Depends(require_api_user)):
    page = int(request.query_params.get('page', 1))
    pp = min(int(request.query_params.get('per_page', 50)), 100)
    q = Favorite.query.filter_by(user_id=user.id).order_by(Favorite.created_at.desc())
    pg = q.paginate(page=page, per_page=pp, error_out=False)
    track_ids = [f.track_id for f in pg.items]
    tracks_map = {}
    if track_ids:
        tracks = Track.query.options(selectinload(Track.uploader)).filter(Track.id.in_(track_ids)).all()
        tracks_map = {t.id: t for t in tracks}
    items = [tracks_map[tid] for tid in track_ids if tid in tracks_map]
    return _json_ok({'items': [serialize_track(t) for t in items],
                     'page': pg.page, 'per_page': pg.per_page,
                     'total': pg.total, 'pages': pg.pages})

@api_v1.get('/history')
def api_history(request: Request, user: User = Depends(require_api_user)):
    page = int(request.query_params.get('page', 1))
    pp = min(int(request.query_params.get('per_page', 50)), 100)
    subq = db.session.query(
        ListeningHistory.track_id,
        func.max(ListeningHistory.listened_at).label('max_time')
    ).filter_by(user_id=user.id).group_by(ListeningHistory.track_id).subquery()
    q = db.session.query(ListeningHistory).join(
        subq, and_(ListeningHistory.track_id == subq.c.track_id,
                   ListeningHistory.listened_at == subq.c.max_time)) \
        .filter(ListeningHistory.user_id == user.id) \
        .order_by(desc(subq.c.max_time))
    pg = q.paginate(page=page, per_page=pp, error_out=False)
    track_ids = [row.track_id for row in pg.items]
    tracks_map = {}
    if track_ids:
        tracks = Track.query.options(selectinload(Track.uploader)).filter(Track.id.in_(track_ids)).all()
        tracks_map = {t.id: t for t in tracks}
    items = []
    for row in pg.items:
        t = tracks_map.get(row.track_id)
        if t:
            items.append({'track': serialize_track(t),
                          'listened_at': row.listened_at.isoformat() if row.listened_at else None,
                          'count': row.count})
    return _json_ok({'items': items,
                     'page': pg.page, 'per_page': pg.per_page,
                     'total': pg.total, 'pages': pg.pages})

@api_v1.delete('/history/{track_dir_id}')
def api_history_delete(request: Request, track_dir_id: str, user: User = Depends(require_api_user)):
    t = Track.query.filter_by(track_dir_id=track_dir_id).first()
    if not t:
        return _json_error('not_found', 'Track not found', 404)
    ListeningHistory.query.filter_by(user_id=user.id, track_id=t.id).delete()
    ListenEvent.query.filter_by(user_id=user.id, track_id=t.id).delete()
    commit_with_retry()
    return _json_ok({})

@api_v1.get('/playlists')
def api_playlists_list(request: Request, user: User = Depends(require_api_user)):
    rows = Playlist.query.filter_by(user_id=user.id).order_by(Playlist.name).all()
    return _json_ok({'items': [serialize_playlist(p) for p in rows]})

@api_v1.post('/playlists')
def api_playlists_create(request: Request, user: User = Depends(require_api_user), data: dict = Body(...)):
    name = (data.get('name') or '').strip()
    if not name:
        return _json_error('bad_request', 'name required')
    pl = Playlist(playlist_dir_id=generate_playlist_dir_id(), name=name,
                  user_id=user.id, is_public=bool(data.get('is_public', False)))
    db.session.add(pl)
    commit_with_retry()
    return _json_ok(serialize_playlist(pl))

@api_v1.get('/playlists/{playlist_dir_id}')
def api_playlist_get(request: Request, playlist_dir_id: str):
    pl = Playlist.query.filter_by(playlist_dir_id=playlist_dir_id).first()
    if not pl:
        return _json_error('not_found', 'Playlist not found', 404)
    api_user = getattr(request.state, 'api_user', None)
    if not pl.is_public and (not api_user or (api_user.id != pl.user_id and not api_user.is_admin)):
        return _json_error('forbidden', 'Access denied', 403)
    return _json_ok(serialize_playlist(pl, include_tracks=True))

@api_v1.api_route('/playlists/{playlist_dir_id}', methods=['PATCH', 'DELETE'])
def api_playlist_modify(request: Request, playlist_dir_id: str,
                        user: User = Depends(require_api_user), data: dict = Body(None)):
    pl = Playlist.query.filter_by(playlist_dir_id=playlist_dir_id).first()
    if not pl:
        return _json_error('not_found', 'Playlist not found', 404)
    if pl.user_id != user.id and not user.is_admin:
        return _json_error('forbidden', 'Access denied', 403)
    if request.method == 'DELETE':
        db.session.delete(pl)
        commit_with_retry()
        return _json_ok({})
    data = data or {}
    if 'name' in data and (data['name'] or '').strip():
        pl.name = data['name'].strip()
    if 'is_public' in data:
        pl.is_public = bool(data['is_public'])
    commit_with_retry()
    return _json_ok(serialize_playlist(pl))

@api_v1.get('/playlists/{playlist_dir_id}/tracks')
def api_playlist_tracks(request: Request, playlist_dir_id: str, user: User = Depends(require_user)):
    pl = first_or_404(Playlist.query.filter_by(playlist_dir_id=playlist_dir_id))
    if pl.user_id != user.id and not user.is_admin:
        return JSONResponse({'error': 'Access denied'}, status_code=403)
    tracks = db.session.query(Track).join(PlaylistTrack) \
        .filter(PlaylistTrack.playlist_id == pl.id).order_by(PlaylistTrack.position).all()
    return JSONResponse({'tracks': [{
        'track_dir_id': t.track_dir_id, 'title': t.title,
        'display_name': t.artist_name or t.uploader.display_name,
        'is_ai': t.is_ai, 'cover_url': _track_cover_url(t)
    } for t in tracks], 'playlist_name': pl.name, 'playlist_dir_id': pl.playlist_dir_id})

@api_v1.post('/playlists/{playlist_dir_id}/tracks')
def api_playlist_add_track(request: Request, playlist_dir_id: str, user: User = Depends(require_user), data: dict = Body(...)):
    pl = Playlist.query.filter_by(playlist_dir_id=playlist_dir_id).first()
    if not pl:
        return _json_error('not_found', 'Playlist not found', 404)
    if pl.user_id != user.id and not user.is_admin:
        return _json_error('forbidden', 'Access denied', 403)
    td = data.get('track_id') or data.get('track_dir_id')
    if not td:
        return _json_error('bad_request', 'track_id required')
    t = Track.query.filter_by(track_dir_id=td).first()
    if not t:
        return _json_error('not_found', 'Track not found', 404)
    if not PlaylistTrack.query.filter_by(playlist_id=pl.id, track_id=t.id).first():
        mp = db.session.query(func.max(PlaylistTrack.position)).filter_by(playlist_id=pl.id).scalar() or 0
        db.session.add(PlaylistTrack(playlist_id=pl.id, track_id=t.id, position=mp + 1))
        commit_with_retry()
    return _json_ok({'track_count': pl.tracks.count()})

@api_v1.delete('/playlists/{playlist_dir_id}/tracks/{track_dir_id}')
def api_playlist_remove_track(request: Request, playlist_dir_id: str, track_dir_id: str,
                              user: User = Depends(require_user)):
    pl = first_or_404(Playlist.query.filter_by(playlist_dir_id=playlist_dir_id))
    t = first_or_404(Track.query.filter_by(track_dir_id=track_dir_id))
    if pl.user_id != user.id and not user.is_admin:
        return JSONResponse({'error': 'Access denied'}, status_code=403)
    pt = PlaylistTrack.query.filter_by(playlist_id=pl.id, track_id=t.id).first()
    if pt:
        db.session.delete(pt)
        commit_with_retry()
    return JSONResponse({'status': 'ok'})

@api_v1.post('/playlists/{playlist_dir_id}/reorder')
def api_playlist_reorder(request: Request, playlist_dir_id: str,
                         user: User = Depends(require_user), order: list = Body(..., embed=True)):
    pl = first_or_404(Playlist.query.filter_by(playlist_dir_id=playlist_dir_id))
    if pl.user_id != user.id and not user.is_admin:
        return JSONResponse({'error': 'Access denied'}, status_code=403)
    for idx, td in enumerate(order):
        t = Track.query.filter_by(track_dir_id=td).first()
        if t:
            pt = PlaylistTrack.query.filter_by(playlist_id=pl.id, track_id=t.id).first()
            if pt:
                pt.position = idx
    commit_with_retry()
    return JSONResponse({'status': 'ok'})

@api_v1.post('/admin/toggle/{user_dir_id}')
def api_toggle_admin(request: Request, user_dir_id: str, user: User = Depends(require_user)):
    if not user.is_admin:
        return JSONResponse({'error': 'Access denied'}, status_code=403)
    u = first_or_404(User.query.filter_by(user_dir_id=user_dir_id))
    if u.id == user.id:
        return JSONResponse({'error': 'Cannot change own'}, status_code=400)
    u.is_admin = not u.is_admin
    commit_with_retry()
    return JSONResponse({'status': 'ok', 'is_admin': u.is_admin})

@api_v1.post('/admin/recompute')
def api_admin_recompute(request: Request, user: User = Depends(require_user)):
    if not user.is_admin:
        return JSONResponse({'error': 'Access denied'}, status_code=403)
    recompute_all_similarities()
    return JSONResponse({'status': 'ok'})

@api_v1.get('/webhooks')
def api_webhooks_list(request: Request, user: User = Depends(require_api_user)):
    rows = Webhook.query.filter_by(user_id=user.id).all()
    return _json_ok({'items': [{'id': w.id, 'url': w.url,
                                 'events': w.event_types.split(','),
                                 'active': w.active} for w in rows]})

@api_v1.post('/webhooks')
def api_webhooks_create(request: Request, user: User = Depends(require_api_user), data: dict = Body(...)):
    url = (data.get('url') or '').strip()
    events = data.get('events') or 'listen,upload'
    if not url.startswith(('http://', 'https://')):
        return _json_error('bad_request', 'url must be http(s)')
    secret = secrets.token_hex(32)
    w = Webhook(user_id=user.id, url=url, secret=secret,
                event_types=','.join(events) if isinstance(events, list) else events)
    db.session.add(w)
    commit_with_retry()
    return _json_ok({'id': w.id, 'url': w.url, 'secret': secret,
                     'events': w.event_types.split(',')})

@api_v1.delete('/webhooks/{wid}')
def api_webhooks_delete(request: Request, wid: int, user: User = Depends(require_api_user)):
    w = db.session.get(Webhook, wid)
    if not w or w.user_id != user.id:
        return _json_error('not_found', 'Webhook not found', 404)
    db.session.delete(w)
    commit_with_retry()
    return _json_ok({})

app.include_router(api_v1)

@app.get('/api/web/tracks', response_class=HTMLResponse)
async def web_tracks(request: Request, page: int = 1, per_page: int = 20, sort: str = 'new', q: str = '', user_dir_id: str = None):
    if user_dir_id:
        u = User.query.filter_by(user_dir_id=user_dir_id).first()
        if not u:
            return HTMLResponse(content="", headers={'X-Has-More': 'false'})
        query = Track.query.filter_by(uploader_id=u.id)
    elif q:
        query = Track.query.filter(or_(
            Track.title.ilike(f'%{q}%'),
            Track.artist_name.ilike(f'%{q}%'),
            Track.uploader.has(User.display_name.ilike(f'%{q}%'))
        ))
    else:
        query = Track.query
    if sort == 'popular':
        query = query.order_by(Track.play_count.desc())
    elif sort == 'old':
        query = query.order_by(Track.uploaded_at.asc())
    elif sort == 'likes':
        query = query.order_by(Track.likes_count.desc())
    else:
        query = query.order_by(Track.uploaded_at.desc())
    pg = query.paginate(page=page, per_page=per_page, error_out=False)
    html_content = ""
    for i, t in enumerate(pg.items):
        html_content += templates.get_template('_track_card.html').render(
            track=t, request=request, url_for=make_url_for(request), priority=(i < 2)
        )
    response = HTMLResponse(content=html_content)
    response.headers['X-Has-More'] = "true" if pg.page < pg.pages else "false"
    return response

@app.get('/api/widget/{token}')
def api_widget_now_playing(token: str):
    u = first_or_404(User.query.filter_by(widget_token=token))
    playing = False
    track = None
    if u.current_track_id and u.current_track_started_at:
        if u.current_track_started_at <= utcnow() and utcnow() - u.current_track_started_at < timedelta(minutes=5):
            track = db.session.get(Track, u.current_track_id)
            if track:
                playing = True
    if not playing:
        return JSONResponse({'playing': False})
    return JSONResponse({'playing': True, 'track': {
        'title': track.title,
        'artist': track.artist_name or track.uploader.display_name,
        'cover_url': _track_cover_url(track),
        'cover_video_url': _track_video_url(track),
        'track_url': f'/track/{track.track_dir_id}',
    }})

@app.get('/api/widget/{token}/search')
def api_widget_search(token: str, request: Request):
    first_or_404(User.query.filter_by(widget_token=token))
    q = request.query_params.get('q', '').strip()
    kind = request.query_params.get('type', 'tracks')
    if not q:
        return JSONResponse({'results': []})
    if kind == 'playlists':
        rows = Playlist.query.filter(Playlist.is_public.is_(True), Playlist.name.ilike(f'%{q}%')) \
            .order_by(Playlist.id.desc()).limit(20).all()
        return JSONResponse({'results': [{'playlist_dir_id': p.playlist_dir_id, 'name': p.name,
                                          'owner': p.owner.display_name, 'track_count': p.tracks.count()} for p in rows]})
    rows = Track.query.filter(or_(Track.title.ilike(f'%{q}%'), Track.artist_name.ilike(f'%{q}%'),
                                  Track.uploader.has(User.display_name.ilike(f'%{q}%')))) \
        .order_by(Track.play_count.desc()).limit(30).all()
    return JSONResponse({'results': [{
        'track_dir_id': t.track_dir_id, 'title': t.title,
        'artist': t.artist_name or t.uploader.display_name, 'is_ai': bool(t.is_ai),
        'cover_url': _track_cover_url(t),
        'audio_url': f'/static/users/{t.uploader.user_dir_id}/music/{t.track_dir_id}/{t.track_dir_id}.{t.audio_ext}'
    } for t in rows]})

@app.get('/api/widget/{token}/playlist/{playlist_dir_id}')
def api_widget_playlist_tracks(token: str, playlist_dir_id: str):
    u = first_or_404(User.query.filter_by(widget_token=token))
    pl = first_or_404(Playlist.query.filter_by(playlist_dir_id=playlist_dir_id))
    if not pl.is_public and pl.user_id != u.id and not u.is_admin:
        return JSONResponse({'error': 'Access denied'}, status_code=403)
    rows = db.session.query(Track).join(PlaylistTrack) \
        .filter(PlaylistTrack.playlist_id == pl.id).order_by(PlaylistTrack.position).all()
    return JSONResponse({'name': pl.name, 'tracks': [{
        'track_dir_id': t.track_dir_id, 'title': t.title,
        'artist': t.artist_name or t.uploader.display_name, 'is_ai': bool(t.is_ai),
        'cover_url': _track_cover_url(t),
        'audio_url': f'/static/users/{t.uploader.user_dir_id}/music/{t.track_dir_id}/{t.track_dir_id}.{t.audio_ext}'
    } for t in rows]})

@app.post('/api/widget/{token}/listen/{track_dir_id}')
@rl('120/minute')
def api_widget_listen(token: str, track_dir_id: str):
    u = first_or_404(User.query.filter_by(widget_token=token))
    t = first_or_404(Track.query.filter_by(track_dir_id=track_dir_id))
    now = utcnow()
    try:
        u.current_track_id = t.id
        u.current_track_started_at = now
        if ListenEvent.query.filter(ListenEvent.user_id == u.id, ListenEvent.track_id == t.id,
                                    ListenEvent.listened_at >= now - timedelta(seconds=60)).first():
            commit_with_retry()
            return JSONResponse({'status': 'throttled'})
        t.play_count = (t.play_count or 0) + 1
        db.session.add(ListenEvent(user_id=u.id, track_id=t.id, listened_at=now))
        with db.session.no_autoflush:
            h = ListeningHistory.query.filter_by(user_id=u.id, track_id=t.id).first()
        if h:
            h.count += 1
            h.listened_at = now
        else:
            db.session.add(ListeningHistory(user_id=u.id, track_id=t.id, count=1, listened_at=now))
        commit_with_retry()
        ws_broadcast_now_playing(u.id, t.id)
    except Exception as e:
        db.session.rollback()
        log.warning(f"widget listen failed: {e}")
        return JSONResponse({'status': 'error'}, status_code=500)
    return JSONResponse({'status': 'ok'})

@app.post('/api/widget/{token}/stop')
def api_widget_stop(token: str):
    u = first_or_404(User.query.filter_by(widget_token=token))
    u.current_track_id = None
    u.current_track_started_at = None
    commit_with_retry()
    ws_broadcast_now_playing(u.id, None, stopped=True)
    return JSONResponse({'status': 'ok'})

@app.websocket('/ws/now-playing')
async def ws_now_playing(ws: WebSocket):
    token = ws.query_params.get('token', '')
    user = await run_in_threadpool(find_user_by_token, token) if token else None
    if not user:
        await ws.close()
        return
    await ws.accept()
    uid = user.id
    with _ws_lock:
        _ws_clients.setdefault(uid, []).append(ws)
    try:
        def _get_current_data():
            current = None
            if user.current_track_id and user.current_track_started_at:
                if utcnow() - user.current_track_started_at < timedelta(minutes=5):
                    current = db.session.get(Track, user.current_track_id)
                    if current:
                        return serialize_track(current)
            return None
        current_data = await run_in_threadpool(_get_current_data)
        if current_data:
            await ws.send_text(json.dumps({'type': 'now_playing', 'playing': True, 'track': current_data}))
        else:
            await ws.send_text(json.dumps({'type': 'now_playing', 'playing': False}))
        while True:
            try:
                await asyncio.wait_for(ws.receive_text(), timeout=60)
            except asyncio.TimeoutError:
                await ws.send_text(json.dumps({'type': 'ping'}))
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        with _ws_lock:
            lst = _ws_clients.get(uid, [])
            if ws in lst:
                lst.remove(ws)
            if not lst:
                _ws_clients.pop(uid, None)
        try:
            Session.remove()
        except Exception:
            pass


def _schema_ref(name):
    return {'$ref': f'#/components/schemas/{name}'}

def _q(name, schema, desc='', example=None):
    p = {'name': name, 'in': 'query', 'schema': schema, 'description': desc}
    if example is not None:
        p['example'] = example
    return p

def _path(name, desc=''):
    return {'name': name, 'in': 'path', 'required': True, 'schema': {'type': 'string'}, 'description': desc}

def _json_body(schema, required=True, example=None):
    media = {'schema': schema}
    if example is not None:
        media['example'] = example
    return {'required': required, 'content': {'application/json': media}}

def _multipart_body(schema, required=True):
    return {'required': required, 'content': {'multipart/form-data': {'schema': schema}}}

def _ok(schema=None, desc='OK', example=None):
    r = {'description': desc}
    if schema is not None:
        media = {'schema': schema}
        if example is not None:
            media['example'] = example
        r['content'] = {'application/json': media}
    return r

def _err(desc):
    return {'description': desc, 'content': {'application/json': {'schema': _schema_ref('Error')}}}

def _envelope(data_schema):
    return {'type': 'object', 'properties': {
        'ok': {'type': 'boolean', 'enum': [True]},
        'data': data_schema,
    }}

def _items_envelope(item_schema):
    return _envelope({'type': 'object', 'properties': {
        'items': {'type': 'array', 'items': item_schema},
    }})

def _op(summary, tag, responses, body=None, params=None, security=True, description=''):
    op = {'summary': summary, 'tags': [tag], 'responses': responses}
    if description:
        op['description'] = description
    if params:
        op['parameters'] = params
    if body is not None:
        op['requestBody'] = body
    op['security'] = [{'bearer': []}] if security else []
    return op

def _track_list_schema():
    return _envelope({
        'type': 'object',
        'properties': {
            'items': {'type': 'array', 'items': _schema_ref('Track')},
            'page': {'type': 'integer'},
            'per_page': {'type': 'integer'},
            'total': {'type': 'integer'},
            'pages': {'type': 'integer'},
        },
    })

def _track_envelope():
    return _envelope(_schema_ref('Track'))

def _playlist_envelope():
    return _envelope(_schema_ref('Playlist'))

def _user_envelope():
    return _envelope(_schema_ref('User'))

def _auth_tokens_schema():
    return _envelope({
        'type': 'object',
        'properties': {
            'access_token': {'type': 'string'},
            'refresh_token': {'type': 'string'},
            'token_type': {'type': 'string', 'enum': ['Bearer']},
            'user': _schema_ref('User'),
        },
        'required': ['access_token', 'refresh_token', 'token_type', 'user'],
    })

_TAGS = [
    {'name': 'auth', 'description': 'Регистрация, вход, refresh/logout токенов'},
    {'name': 'tracks', 'description': 'Загрузка, редактирование, воспроизведение треков'},
    {'name': 'discovery', 'description': 'Рекомендации, чарты, новинки, поиск'},
    {'name': 'playlists', 'description': 'Плейлисты'},
    {'name': 'users', 'description': 'Профили пользователей'},
    {'name': 'social', 'description': 'Избранное и история прослушиваний'},
    {'name': 'webhooks', 'description': 'Уведомления на внешние URL'},
]

_FAVORITE_RESPONSE = {
    'type': 'object',
    'properties': {
        'status': {'type': 'string', 'enum': ['added', 'removed']},
        'ok': {'type': 'boolean', 'enum': [True]},
        'is_favorite': {'type': 'boolean'},
        'data': {
            'type': 'object',
            'properties': {'is_favorite': {'type': 'boolean'}},
        },
    },
}

_HISTORY_ITEM = {
    'type': 'object',
    'properties': {
        'track': _schema_ref('Track'),
        'listened_at': {'type': 'string', 'format': 'date-time'},
        'count': {'type': 'integer'},
    },
}


OPENAPI = {
    'openapi': '3.1.0',
    'info': {
        'title': 'MusicForge API',
        'version': '1.0.0',
        'description': (
            'REST API для MusicForge. Все защищённые эндпоинты требуют Bearer-токен '
            '(получается через /auth/login или /auth/register). '
            'Файлы загружаются через multipart/form-data. '
            'Ответы без `ok`-обёртки (например, /tracks/{id}/rate) возвращают данные напрямую.'
        ),
    },
    'servers': [{'url': '/api/v1'}],
    'tags': _TAGS,
    'components': {
        'securitySchemes': {
            'bearer': {'type': 'http', 'scheme': 'bearer', 'bearerFormat': 'opaque'}
        },
        'schemas': {
            'Error': {
                'type': 'object',
                'properties': {
                    'ok': {'type': 'boolean', 'enum': [False]},
                    'error': {
                        'type': 'object',
                        'properties': {
                            'code': {'type': 'string'},
                            'message': {'type': 'string'},
                        },
                        'required': ['code', 'message'],
                    },
                },
                'required': ['ok', 'error'],
            },
            'User': {
                'type': 'object',
                'properties': {
                    'id': {'type': 'string', 'description': 'user_dir_id'},
                    'login': {'type': 'string'},
                    'display_name': {'type': 'string'},
                    'bio': {'type': 'string'},
                    'is_admin': {'type': 'boolean'},
                    'avatar_url': {'type': 'string'},
                    'web_url': {'type': 'string'},
                    'tracks_count': {'type': 'integer'},
                    'total_likes': {'type': 'integer'},
                    'total_plays': {'type': 'integer'},
                },
            },
            'Track': {
                'type': 'object',
                'properties': {
                    'id': {'type': 'string', 'description': 'track_dir_id'},
                    'title': {'type': 'string'},
                    'artist': {'type': 'string'},
                    'artist_id': {'type': 'string'},
                    'artist_username': {'type': 'string'},
                    'is_ai': {'type': 'boolean'},
                    'tags': {'type': 'array', 'items': {'type': 'string'}},
                    'release_date': {'type': 'string', 'format': 'date-time'},
                    'cover_url': {'type': 'string'},
                    'video_url': {'type': ['string', 'null']},
                    'audio_url': {'type': 'string'},
                    'play_count': {'type': 'integer'},
                    'likes': {'type': 'integer'},
                    'dislikes': {'type': 'integer'},
                    'web_url': {'type': 'string'},
                    'lyrics': {'type': ['string', 'null']},
                    'is_favorite': {'type': 'boolean'},
                    'user_rating': {'type': 'integer', 'enum': [-1, 0, 1]},
                    'in_playlists': {'type': 'array', 'items': {'type': 'string'}},
                },
            },
            'Playlist': {
                'type': 'object',
                'properties': {
                    'id': {'type': 'string', 'description': 'playlist_dir_id'},
                    'name': {'type': 'string'},
                    'owner': {'type': 'string'},
                    'owner_id': {'type': 'string'},
                    'is_public': {'type': 'boolean'},
                    'track_count': {'type': 'integer'},
                    'web_url': {'type': 'string'},
                    'tracks': {'type': 'array', 'items': _schema_ref('Track')},
                },
            },
            'Webhook': {
                'type': 'object',
                'properties': {
                    'id': {'type': 'integer'},
                    'url': {'type': 'string', 'format': 'uri'},
                    'events': {'type': 'array', 'items': {'type': 'string'}},
                    'active': {'type': 'boolean'},
                    'secret': {'type': 'string'},
                },
            },
            'RegisterRequest': {
                'type': 'object',
                'required': ['login', 'email', 'password'],
                'properties': {
                    'login': {'type': 'string', 'minLength': 3},
                    'email': {'type': 'string', 'format': 'email'},
                    'password': {'type': 'string', 'minLength': 8},
                    'display_name': {'type': 'string'},
                },
            },
            'LoginRequest': {
                'type': 'object',
                'required': ['login', 'password'],
                'properties': {
                    'login': {'type': 'string', 'description': 'Логин или email'},
                    'password': {'type': 'string'},
                },
            },
            'RefreshRequest': {
                'type': 'object',
                'required': ['refresh_token'],
                'properties': {'refresh_token': {'type': 'string'}},
            },
            'ExchangeRequest': {
                'type': 'object',
                'required': ['code'],
                'properties': {'code': {'type': 'string', 'description': 'Одноразовый desktop-код'}},
            },
            'RateRequest': {
                'type': 'object',
                'required': ['value'],
                'properties': {'value': {'type': 'integer', 'enum': [1, -1]}},
            },
            'ReorderRequest': {
                'type': 'object',
                'required': ['order'],
                'properties': {'order': {'type': 'array', 'items': {'type': 'string'}}},
            },
            'PlaylistCreateRequest': {
                'type': 'object',
                'required': ['name'],
                'properties': {
                    'name': {'type': 'string'},
                    'is_public': {'type': 'boolean', 'default': False},
                },
            },
            'PlaylistUpdateRequest': {
                'type': 'object',
                'properties': {
                    'name': {'type': 'string'},
                    'is_public': {'type': 'boolean'},
                },
            },
            'PlaylistAddTrackRequest': {
                'type': 'object',
                'properties': {
                    'track_id': {'type': 'string', 'description': 'track_dir_id'},
                    'track_dir_id': {'type': 'string'},
                },
            },
            'WebhookCreateRequest': {
                'type': 'object',
                'required': ['url'],
                'properties': {
                    'url': {'type': 'string', 'format': 'uri'},
                    'events': {
                        'oneOf': [
                            {'type': 'string', 'description': 'Через запятую, например listen,upload'},
                            {'type': 'array', 'items': {'type': 'string'}},
                        ],
                    },
                },
            },
            'UploadTrack': {
                'type': 'object',
                'properties': {
                    'upload_type': {'type': 'string', 'enum': ['file', 'youtube'], 'default': 'file'},
                    'title': {'type': 'string'},
                    'tags': {'type': 'string', 'description': 'Через запятую'},
                    'is_ai': {'type': 'string', 'enum': ['', 'true', 'false', '1', '0', 'yes', 'no', 'on']},
                    'artist_name': {'type': 'string'},
                    'youtube_url': {'type': 'string', 'format': 'uri'},
                    'audio_file': {'type': 'string', 'format': 'binary'},
                    'cover_file': {'type': 'string', 'format': 'binary'},
                    'cover_video_file': {'type': 'string', 'format': 'binary'},
                    'lyrics_file': {'type': 'string', 'format': 'binary'},
                },
            },
            'UpdateTrack': {
                'type': 'object',
                'properties': {
                    'title': {'type': 'string'},
                    'artist_name': {'type': 'string'},
                    'tags': {'type': 'string'},
                    'is_ai': {'type': 'string', 'enum': ['', 'true', 'false', '1', '0', 'yes', 'no', 'on']},
                    'cover_file': {'type': 'string', 'format': 'binary'},
                    'lyrics_file': {'type': 'string', 'format': 'binary'},
                },
            },
            'UpdateMe': {
                'type': 'object',
                'properties': {
                    'display_name': {'type': 'string'},
                    'bio': {'type': 'string'},
                    'avatar_file': {'type': 'string', 'format': 'binary'},
                },
            },
        },
    },
    'paths': {
        '/auth/register': {
            'post': _op(
                'Регистрация', 'auth',
                {'201': _ok(_auth_tokens_schema(), 'Пользователь создан'),
                 '400': _err('Некорректные данные'),
                 '409': _err('Логин или email заняты')},
                body=_json_body(_schema_ref('RegisterRequest')),
                security=False,
            )
        },
        '/auth/login': {
            'post': _op(
                'Вход', 'auth',
                {'200': _ok(_auth_tokens_schema(), 'Успешный вход'),
                 '401': _err('Неверные учётные данные')},
                body=_json_body(_schema_ref('LoginRequest'),
                                example={'login': 'alice', 'password': 'secret123'}),
                security=False,
            )
        },
        '/auth/exchange': {
            'post': _op(
                'Обмен desktop-кода на токены', 'auth',
                {'200': _ok(_auth_tokens_schema(), 'Токены выданы'),
                 '401': _err('Код неверен или истёк')},
                body=_json_body(_schema_ref('ExchangeRequest')),
                security=False,
            )
        },
        '/auth/refresh': {
            'post': _op(
                'Обновить access/refresh токены', 'auth',
                {'200': _ok(_auth_tokens_schema(), 'Новые токены'),
                 '401': _err('Refresh-токен недействителен')},
                body=_json_body(_schema_ref('RefreshRequest')),
                security=False,
            )
        },
        '/auth/logout': {
            'post': _op(
                'Отозвать токены', 'auth',
                {'200': _ok(None, 'Токены отозваны')},
            )
        },
        '/auth/me': {
            'get': _op(
                'Текущий пользователь', 'auth',
                {'200': _ok(_user_envelope(), 'Информация о пользователе'),
                 '401': _err('Не авторизован')},
            )
        },
        '/users/me': {
            'patch': _op(
                'Обновить профиль', 'auth',
                {'200': _ok(_user_envelope(), 'Обновлено'),
                 '500': _err('Ошибка сохранения')},
                body=_multipart_body(_schema_ref('UpdateMe')),
            )
        },
        '/tracks': {
            'get': _op(
                'Список треков', 'tracks',
                {'200': _ok(_track_list_schema(), 'OK')},
                params=[
                    _q('page', {'type': 'integer', 'default': 1}),
                    _q('per_page', {'type': 'integer', 'default': 20, 'maximum': 100}),
                    _q('sort', {'type': 'string', 'enum': ['new', 'popular', 'likes'], 'default': 'new'}),
                ],
                security=False,
            ),
            'post': _op(
                'Загрузить трек (файл или YouTube)', 'tracks',
                {'200': _ok(_track_envelope(), 'Трек создан'),
                 '400': _err('Некорректный запрос'),
                 '500': _err('Ошибка сервера')},
                body=_multipart_body(_schema_ref('UploadTrack')),
            ),
        },
        '/tracks/{track_dir_id}': {
            'get': _op(
                'Трек по id', 'tracks',
                {'200': _ok(_track_envelope(), 'OK'),
                 '404': _err('Не найден')},
                params=[_path('track_dir_id')],
                security=False,
            ),
            'patch': _op(
                'Обновить трек', 'tracks',
                {'200': _ok(_track_envelope(), 'Обновлено'),
                 '403': _err('Нет доступа'),
                 '404': _err('Не найден')},
                params=[_path('track_dir_id')],
                body=_multipart_body(_schema_ref('UpdateTrack')),
            ),
            'delete': _op(
                'Удалить трек', 'tracks',
                {'200': _ok(None, 'Удалено'),
                 '403': _err('Нет доступа'),
                 '404': _err('Не найден')},
                params=[_path('track_dir_id')],
            ),
        },
        '/tracks/{track_dir_id}/stream': {
            'get': _op(
                'Аудиопоток', 'tracks',
                {'200': {'description': 'Бинарный аудио-поток', 'content': {
                    'audio/mpeg': {'schema': {'type': 'string', 'format': 'binary'}},
                    'audio/wav': {'schema': {'type': 'string', 'format': 'binary'}},
                    'audio/ogg': {'schema': {'type': 'string', 'format': 'binary'}},
                    'audio/mp4': {'schema': {'type': 'string', 'format': 'binary'}},
                }},
                 '404': _err('Не найден')},
                params=[_path('track_dir_id')],
                security=False,
            )
        },
        '/tracks/{track_dir_id}/similar': {
            'get': _op(
                'Похожие треки', 'discovery',
                {'200': _ok(_items_envelope(_schema_ref('Track')), 'OK'),
                 '404': _err('Не найден')},
                params=[
                    _path('track_dir_id'),
                    _q('limit', {'type': 'integer', 'default': 6, 'maximum': 30}),
                ],
                security=False,
            )
        },
        '/tracks/{track_dir_id}/lyrics': {
            'get': _op(
                'SRT-субтитры', 'tracks',
                {'200': _ok(_envelope({
                    'type': 'object',
                    'properties': {'lyrics': {'type': ['string', 'null']}},
                }), 'OK'),
                 '404': _err('Не найден')},
                params=[_path('track_dir_id')],
                security=False,
            )
        },
        '/tracks/{track_dir_id}/status': {
            'get': _op(
                'Статус трека для текущего пользователя', 'tracks',
                {'200': _ok({
                    'type': 'object',
                    'properties': {
                        'is_favorite': {'type': 'boolean'},
                        'playlist_ids': {'type': 'array', 'items': {'type': 'string'}},
                        'user_rating': {'type': 'integer', 'enum': [-1, 0, 1]},
                        'likes': {'type': 'integer'},
                        'dislikes': {'type': 'integer'},
                        'plays': {'type': 'integer'},
                    },
                }, 'OK'),
                 '401': _err('Не авторизован'),
                 '404': _err('Не найден')},
                params=[_path('track_dir_id')],
            )
        },
        '/tracks/{track_dir_id}/rate': {
            'post': _op(
                'Лайк/дизлайк', 'tracks',
                {'200': _ok({
                    'type': 'object',
                    'properties': {
                        'likes': {'type': 'integer'},
                        'dislikes': {'type': 'integer'},
                        'user_rating': {'type': 'integer', 'enum': [-1, 0, 1]},
                    },
                }, 'OK'),
                 '400': _err('Неверное значение'),
                 '401': _err('Не авторизован'),
                 '404': _err('Не найден')},
                params=[_path('track_dir_id')],
                body=_json_body(_schema_ref('RateRequest'), example={'value': 1}),
            )
        },
        '/tracks/{track_dir_id}/listen': {
            'post': _op(
                'Записать прослушивание', 'tracks',
                {'200': _ok(None, 'OK (или status=throttled)'),
                 '401': _err('Не авторизован'),
                 '404': _err('Не найден')},
                params=[_path('track_dir_id')],
            )
        },
        '/tracks/{track_dir_id}/favorite': {
            'post': _op(
                'Добавить/переключить избранное', 'social',
                {'200': _ok(_FAVORITE_RESPONSE, 'OK'),
                 '401': _err('Не авторизован'),
                 '404': _err('Не найден')},
                params=[_path('track_dir_id')],
            ),
            'delete': _op(
                'Убрать из избранного', 'social',
                {'200': _ok(_FAVORITE_RESPONSE, 'OK'),
                 '401': _err('Не авторизован'),
                 '404': _err('Не найден')},
                params=[_path('track_dir_id')],
            ),
        },
        '/recommendations': {
            'get': _op(
                'Рекомендации', 'discovery',
                {'200': _ok(_items_envelope(_schema_ref('Track')), 'OK')},
                params=[_q('limit', {'type': 'integer', 'default': 16, 'maximum': 50})],
                security=False,
            )
        },
        '/charts': {
            'get': _op(
                'Популярные треки', 'discovery',
                {'200': _ok(_items_envelope(_schema_ref('Track')), 'OK')},
                params=[
                    _q('period', {'type': 'integer', 'default': 30, 'description': 'Дней'}),
                    _q('limit', {'type': 'integer', 'default': 50, 'maximum': 200}),
                ],
                security=False,
            )
        },
        '/new-releases': {
            'get': _op(
                'Новинки', 'discovery',
                {'200': _ok(_items_envelope(_schema_ref('Track')), 'OK')},
                params=[
                    _q('days', {'type': 'integer', 'default': 7}),
                    _q('limit', {'type': 'integer', 'default': 20, 'maximum': 100}),
                ],
                security=False,
            )
        },
        '/search': {
            'get': _op(
                'Поиск', 'discovery',
                {'200': _ok(None, 'OK')},
                params=[
                    _q('q', {'type': 'string'}),
                    _q('type', {'type': 'string', 'enum': ['tracks', 'playlists', 'users', 'tags'], 'default': 'tracks'}),
                    _q('limit', {'type': 'integer', 'default': 20, 'maximum': 100}),
                ],
                security=False,
            )
        },
        '/advanced-search': {
            'get': _op(
                'Расширенный фильтр', 'discovery',
                {'200': _ok(_items_envelope(_schema_ref('Track')), 'OK')},
                params=[
                    _q('title', {'type': 'string'}),
                    _q('artist', {'type': 'string'}),
                    _q('tag', {'type': 'string'}),
                    _q('is_ai', {'type': 'string', 'enum': ['yes', 'no']}),
                    _q('limit', {'type': 'integer', 'default': 50, 'maximum': 200}),
                ],
                security=False,
            )
        },
        '/tags': {
            'get': _op(
                'Автодополнение тегов', 'discovery',
                {'200': _ok(_items_envelope({
                    'type': 'object',
                    'properties': {'name': {'type': 'string'}},
                }), 'OK')},
                params=[
                    _q('q', {'type': 'string'}),
                    _q('limit', {'type': 'integer', 'default': 20, 'maximum': 100}),
                ],
                security=False,
            )
        },
        '/users/{user_dir_id}': {
            'get': _op(
                'Профиль пользователя', 'users',
                {'200': _ok(_user_envelope(), 'OK'),
                 '404': _err('Не найден')},
                params=[_path('user_dir_id')],
                security=False,
            )
        },
        '/users/{user_dir_id}/tracks': {
            'get': _op(
                'Треки пользователя', 'users',
                {'200': _ok(_track_list_schema(), 'OK'),
                 '404': _err('Не найден')},
                params=[
                    _path('user_dir_id'),
                    _q('page', {'type': 'integer', 'default': 1}),
                    _q('per_page', {'type': 'integer', 'default': 20, 'maximum': 100}),
                    _q('sort', {'type': 'string', 'enum': ['new', 'popular', 'old'], 'default': 'new'}),
                ],
                security=False,
            )
        },
        '/users/{user_dir_id}/playlists': {
            'get': _op(
                'Плейлисты пользователя', 'users',
                {'200': _ok(_items_envelope(_schema_ref('Playlist')), 'OK'),
                 '404': _err('Не найден')},
                params=[_path('user_dir_id')],
                security=False,
            )
        },
        '/favorites': {
            'get': _op(
                'Моё избранное', 'social',
                {'200': _ok(_track_list_schema(), 'OK'),
                 '401': _err('Не авторизован')},
                params=[
                    _q('page', {'type': 'integer', 'default': 1}),
                    _q('per_page', {'type': 'integer', 'default': 50, 'maximum': 100}),
                ],
            )
        },
        '/history': {
            'get': _op(
                'История прослушиваний', 'social',
                {'200': _ok(_envelope({
                    'type': 'object',
                    'properties': {
                        'items': {'type': 'array', 'items': _HISTORY_ITEM},
                        'page': {'type': 'integer'},
                        'per_page': {'type': 'integer'},
                        'total': {'type': 'integer'},
                        'pages': {'type': 'integer'},
                    },
                }), 'OK'),
                 '401': _err('Не авторизован')},
                params=[
                    _q('page', {'type': 'integer', 'default': 1}),
                    _q('per_page', {'type': 'integer', 'default': 50, 'maximum': 100}),
                ],
            )
        },
        '/history/{track_dir_id}': {
            'delete': _op(
                'Удалить из истории', 'social',
                {'200': _ok(None, 'Удалено'),
                 '401': _err('Не авторизован'),
                 '404': _err('Не найден')},
                params=[_path('track_dir_id')],
            )
        },
        '/playlists': {
            'get': _op(
                'Мои плейлисты', 'playlists',
                {'200': _ok(_items_envelope(_schema_ref('Playlist')), 'OK'),
                 '401': _err('Не авторизован')},
            ),
            'post': _op(
                'Создать плейлист', 'playlists',
                {'200': _ok(_playlist_envelope(), 'Создан'),
                 '400': _err('Некорректное имя'),
                 '401': _err('Не авторизован')},
                body=_json_body(_schema_ref('PlaylistCreateRequest'),
                                example={'name': 'Road trip', 'is_public': False}),
            ),
        },
        '/playlists/{playlist_dir_id}': {
            'get': _op(
                'Получить плейлист', 'playlists',
                {'200': _ok(_playlist_envelope(), 'OK'),
                 '403': _err('Нет доступа'),
                 '404': _err('Не найден')},
                params=[_path('playlist_dir_id')],
                security=False,
            ),
            'patch': _op(
                'Обновить плейлист', 'playlists',
                {'200': _ok(_playlist_envelope(), 'OK'),
                 '403': _err('Нет доступа'),
                 '404': _err('Не найден')},
                params=[_path('playlist_dir_id')],
                body=_json_body(_schema_ref('PlaylistUpdateRequest'), required=False),
            ),
            'delete': _op(
                'Удалить плейлист', 'playlists',
                {'200': _ok(None, 'Удалён'),
                 '403': _err('Нет доступа'),
                 '404': _err('Не найден')},
                params=[_path('playlist_dir_id')],
            ),
        },
        '/playlists/{playlist_dir_id}/tracks': {
            'post': _op(
                'Добавить трек в плейлист', 'playlists',
                {'200': _ok(None, 'OK (track_count)'),
                 '400': _err('Нет track_id'),
                 '403': _err('Нет доступа'),
                 '404': _err('Не найден')},
                params=[_path('playlist_dir_id')],
                body=_json_body(_schema_ref('PlaylistAddTrackRequest'),
                                example={'track_id': 'abc123def456'}),
            )
        },
        '/playlists/{playlist_dir_id}/tracks/{track_dir_id}': {
            'delete': _op(
                'Убрать трек из плейлиста', 'playlists',
                {'200': _ok(None, 'OK'),
                 '403': _err('Нет доступа'),
                 '404': _err('Не найден')},
                params=[_path('playlist_dir_id'), _path('track_dir_id')],
            )
        },
        '/playlists/{playlist_dir_id}/reorder': {
            'post': _op(
                'Переупорядочить треки', 'playlists',
                {'200': _ok(None, 'OK'),
                 '403': _err('Нет доступа'),
                 '404': _err('Не найден')},
                params=[_path('playlist_dir_id')],
                body=_json_body(_schema_ref('ReorderRequest'),
                                example={'order': ['abc123def456', 'fed321cba654']}),
            )
        },
        '/webhooks': {
            'get': _op(
                'Мои webhooks', 'webhooks',
                {'200': _ok(_items_envelope(_schema_ref('Webhook')), 'OK'),
                 '401': _err('Не авторизован')},
            ),
            'post': _op(
                'Создать webhook', 'webhooks',
                {'200': _ok(_schema_ref('Webhook'), 'Создан (с secret)'),
                 '400': _err('Некорректный URL'),
                 '401': _err('Не авторизован')},
                body=_json_body(_schema_ref('WebhookCreateRequest'),
                                example={'url': 'https://example.com/hook', 'events': ['listen', 'upload']}),
            ),
        },
        '/webhooks/{wid}': {
            'delete': _op(
                'Удалить webhook', 'webhooks',
                {'200': _ok(None, 'Удалён'),
                 '401': _err('Не авторизован'),
                 '404': _err('Не найден')},
                params=[{'name': 'wid', 'in': 'path', 'required': True, 'schema': {'type': 'integer'}}],
            )
        },
    },
}


@app.get('/api/v1/openapi.json')
def openapi_spec():
    return JSONResponse(OPENAPI)

@app.get('/api/v1/docs')
def openapi_docs():
    html = '''<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>MusicForge API</title>
<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"></head>
<body><div id="ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>SwaggerUIBundle({
  url: '/api/v1/openapi.json',
  dom_id: '#ui',
  persistAuthorization: true,
  tryItOutEnabled: true,
  displayRequestDuration: true,
  filter: true
});</script>
</body></html>'''
    return HTMLResponse(html)

@app.exception_handler(HTTPException)
async def http_exc_handler(request: Request, exc: HTTPException):
    if exc.status_code == 401 and not request.url.path.startswith('/api/'):
        return RedirectResponse(str(request.app.url_path_for('login')), status_code=302)
    if request.url.path.startswith('/api/'):
        code = 'unauthorized' if exc.status_code == 401 else 'error'
        return JSONResponse({'ok': False, 'error': {'code': code, 'message': exc.detail}},
                            status_code=exc.status_code)
    return Response(content=f'<h1>{exc.status_code}</h1>', status_code=exc.status_code, media_type='text/html')

if __name__ == '__main__':
    import uvicorn
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', '5000'))
    log.info(f'MusicForge на http://{host}:{port}')
    uvicorn.run(app, host=host, port=port, proxy_headers=True, forwarded_allow_ips='*')