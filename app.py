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
import requests
import logging
from datetime import timedelta
from functools import wraps
from urllib.parse import urlparse

from flask import (Flask, render_template, request, redirect, url_for, flash,
                   jsonify, g, send_file, Blueprint, abort, session as flask_session)
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sock import Sock
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_, desc, func, and_, event
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.pool import NullPool
from PIL import Image

from models import (db, utcnow, User, Track, Playlist, PlaylistTrack, Favorite,
                    ListeningHistory, Rating, ListenEvent, Tag, TrackTag,
                    TrackSimilarity, UserSimilarity, RefreshToken,
                    OAuthAccount, Webhook)


Image.MAX_IMAGE_PIXELS = 40_000_000
MAX_PARALLEL_UPLOADS = 4
ACCESS_TOKEN_TTL = timedelta(days=int(os.environ.get('ACCESS_TOKEN_TTL_DAYS', '30')))
REFRESH_TOKEN_TTL = timedelta(days=int(os.environ.get('REFRESH_TOKEN_TTL_DAYS', '90')))
ENFORCE_TOKEN_EXPIRY = os.environ.get('ENFORCE_TOKEN_EXPIRY', '1') == '1'

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger('musicforge')


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


app = Flask(__name__)
app.config['SECRET_KEY'] = _load_or_create_secret()
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', 'sqlite:///musicforge.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_UPLOAD_MB', '500')) * 1024 * 1024
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'connect_args': {'timeout': 60, 'check_same_thread': False},
    'poolclass': NullPool,
    'pool_pre_ping': True,
}
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('COOKIE_SECURE', '0') == '1'
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SAMESITE'] = 'Lax'
app.config['REMEMBER_COOKIE_SECURE'] = os.environ.get('COOKIE_SECURE', '0') == '1'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['WTF_CSRF_TIME_LIMIT'] = None

BASE_USER_DIR = os.path.join('static', 'users')
os.makedirs(BASE_USER_DIR, exist_ok=True)

db.init_app(app)

csrf = CSRFProtect(app)

try:
    _storage = os.environ.get('RATELIMIT_STORAGE_URI', 'memory://')
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=['600/minute', '20000/day'],
        storage_uri=_storage,
        headers_enabled=True,
    )
except Exception as e:
    log.warning(f'Rate limiter disabled: {e}')
    limiter = None


def _rl(limit_str):
    def deco(f):
        if limiter is None:
            return f
        return limiter.limit(limit_str)(f)
    return deco


sock = Sock(app)

ALLOWED_ORIGINS = {o.strip() for o in os.environ.get('ALLOWED_ORIGINS', '').split(',') if o.strip()}
WIDGET_TOKEN_TTL_DAYS = int(os.environ.get('WIDGET_TOKEN_TTL_DAYS', '0'))

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


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

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
    rt = RefreshToken(
        user_id=user.id,
        token_hash=_token_hash(raw),
        expires_at=utcnow() + REFRESH_TOKEN_TTL,
    )
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
    h = _token_hash(raw)
    user = User.query.filter_by(api_token_hash=h).first()
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
        img.save(output_path, 'webp', quality=90)
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


def safe_convert_to_webp(input_file, output_path, size=(512, 512)):
    tmp = output_path + '.tmp'
    try:
        convert_to_webp(input_file, tmp, size)
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
                            '-c:v', 'libwebp', '-quality', '90', poster_path],
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
                u1, u2 = users[i], users[j]
                key = _canonical_pair(u1, u2)
                pair_dots[key] = pair_dots.get(key, 0.0) + user_items[u1][tid] * user_items[u2][tid]
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
    tracks = Track.query.filter_by(uploader_id=user.id) \
        .filter((Track.artist_name.is_(None)) | (Track.artist_name == '')).all()
    return {'tracks_count': len(tracks),
            'total_likes': sum(t.likes_count for t in tracks),
            'total_plays': sum(t.play_count for t in tracks)}


def _json_error(code, message, status=400):
    return jsonify(ok=False, error={'code': code, 'message': message}), status


def _json_ok(data):
    return jsonify(ok=True, data=data)


def _get_api_user():
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        return find_user_by_token(auth[7:].strip())
    token = request.args.get('token') or request.args.get('access_token')
    if token:
        return find_user_by_token(token)
    return None


def api_login_required(f):
    @wraps(f)
    def deco(*a, **kw):
        user = _get_api_user()
        if not user:
            return _json_error('unauthorized', 'Bearer token required', 401)
        g.api_user = user
        return f(*a, **kw)
    return deco


def api_user_optional(f):
    @wraps(f)
    def deco(*a, **kw):
        g.api_user = _get_api_user()
        return f(*a, **kw)
    return deco


def _safe_next(default_endpoint='playlists'):
    ref = request.referrer
    if ref:
        try:
            p = urlparse(ref)
            if p.netloc == request.host:
                return ref
        except Exception:
            pass
    return url_for(default_endpoint)


def _track_cover_url(track):
    return url_for('static', filename=f'users/{track.uploader.user_dir_id}/music/{track.track_dir_id}/{track.track_dir_id}.webp')


def _track_video_url(track):
    try:
        if has_cover_video(track):
            return url_for('static', filename=f'users/{track.uploader.user_dir_id}/music/{track.track_dir_id}/{track.track_dir_id}.webm')
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
        'audio_url': url_for('api_v1.stream_track', track_dir_id=track.track_dir_id, _external=True),
        'play_count': track.play_count or 0,
        'likes': track.likes_count or 0,
        'dislikes': track.dislikes_count or 0,
        'web_url': url_for('track', track_dir_id=track.track_dir_id, _external=True),
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
        'web_url': url_for('view_playlist', playlist_dir_id=pl.playlist_dir_id, _external=True),
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
        'avatar_url': url_for('static', filename=f'users/{user.user_dir_id}/{user.user_dir_id}.webp'),
        'web_url': url_for('user_profile', user_dir_id=user.user_dir_id, _external=True),
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
    for ws in conns:
        try:
            ws.send(payload)
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


@app.before_request
def _api_preflight():
    if request.method == 'OPTIONS' and request.path.startswith('/api/'):
        return ('', 204, {})


@app.after_request
def _apply_headers(response):
    if request.path.startswith('/api/'):
        origin = request.headers.get('Origin', '')
        if ALLOWED_ORIGINS:
            if origin in ALLOWED_ORIGINS:
                response.headers['Access-Control-Allow-Origin'] = origin
                response.headers['Vary'] = 'Origin'
        else:
            response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type, X-CSRFToken'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PATCH, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Max-Age'] = '86400'
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    response.headers.setdefault('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
    return response


@app.errorhandler(CSRFError)
def _csrf_error(e):
    if request.path.startswith('/api/'):
        return _json_error('csrf', 'CSRF token missing or invalid', 400)
    flash('Сессия истекла, попробуйте снова', 'danger')
    return redirect(url_for('index'))


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.context_processor
def inject_helpers():
    def cover_video_url(track):
        return url_for('static', filename=f'users/{track.uploader.user_dir_id}/music/{track.track_dir_id}/{track.track_dir_id}.webm')
    return dict(has_cover_video=has_cover_video, get_cover_video_url=cover_video_url,
                oauth_providers=list(OAUTH_PROVIDERS.keys()))


@app.route('/health')
def health():
    return jsonify(status='ok', time=utcnow().isoformat())


@app.route('/favicon.ico')
def favicon():
    ico = os.path.join(app.root_path, 'static', 'favicon.ico')
    if os.path.exists(ico):
        return send_file(ico, mimetype='image/x-icon')
    return ('', 204)


@app.route('/')
def index():
    week_ago = utcnow() - timedelta(days=7)
    new_releases = Track.query.filter(Track.uploaded_at >= week_ago) \
        .order_by(Track.uploaded_at.desc()).limit(8).all()
    month_ago = utcnow() - timedelta(days=30)
    popular = db.session.query(Track, func.count(ListenEvent.id).label('cnt')) \
        .join(ListenEvent, ListenEvent.track_id == Track.id) \
        .filter(ListenEvent.listened_at >= month_ago) \
        .group_by(Track.id).order_by(desc('cnt')).limit(8).all()
    recommendations = get_recommendations(current_user) if current_user.is_authenticated else []
    return render_template('index.html', new_releases=new_releases,
                           popular_tracks=[r[0] for r in popular],
                           recommendations=recommendations)


@app.route('/releases')
def releases():
    page = request.args.get('page', 1, type=int)
    tracks = Track.query.order_by(Track.uploaded_at.desc()).paginate(page=page, per_page=20)
    return render_template('releases.html', tracks=tracks)


@app.route('/all_new')
def all_new():
    tracks = Track.query.filter(Track.uploaded_at >= utcnow() - timedelta(days=7)) \
        .order_by(Track.uploaded_at.desc()).all()
    return render_template('all_new.html', tracks=tracks)


@app.route('/all_chart')
def all_chart():
    rows = db.session.query(Track, func.count(ListenEvent.id).label('cnt')) \
        .join(ListenEvent, ListenEvent.track_id == Track.id) \
        .filter(ListenEvent.listened_at >= utcnow() - timedelta(days=30)) \
        .group_by(Track.id).order_by(desc('cnt')).all()
    return render_template('all_chart.html', tracks=[r[0] for r in rows])


@app.route('/app')
def app_info():
    return render_template('app_info.html')


@app.route('/random')
def random_track():
    t = Track.query.order_by(func.random()).first()
    if not t:
        flash('Нет треков', 'danger')
        return redirect(url_for('index'))
    return redirect(url_for('track', track_dir_id=t.track_dir_id))


@app.route('/search')
def search():
    q = request.args.get('q', '')
    tracks = []
    if q:
        tracks = Track.query.filter(or_(
            Track.title.ilike(f'%{q}%'),
            Track.artist_name.ilike(f'%{q}%'),
            Track.uploader.has(User.display_name.ilike(f'%{q}%'))
        )).all()
    return render_template('search.html', tracks=tracks, query=q)


@app.route('/advanced_search')
def advanced_search():
    title = request.args.get('title', '')
    artist = request.args.get('artist', '')
    tag = request.args.get('tag', '')
    is_ai = request.args.get('is_ai')
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
    return render_template('advanced_search.html', tracks=tracks, request_args=request.args)


@app.route('/track/<string:track_dir_id>')
def track(track_dir_id):
    t = Track.query.filter_by(track_dir_id=track_dir_id).first_or_404()
    is_fav = False
    user_rating = 0
    pl_ids = []
    if current_user.is_authenticated:
        is_fav = Favorite.query.filter_by(user_id=current_user.id, track_id=t.id).first() is not None
        r = Rating.query.filter_by(user_id=current_user.id, track_id=t.id).first()
        if r:
            user_rating = r.value
        pl_ids = [pt.playlist_id for pt in PlaylistTrack.query.filter(
            PlaylistTrack.track_id == t.id,
            PlaylistTrack.playlist_id.in_(
                db.session.query(Playlist.id).filter_by(user_id=current_user.id))).all()]
    recs = get_track_recommendations(t, current_user)
    return render_template('track.html', track=t, is_favorite=is_fav,
                           user_rating=user_rating, recommendations=recs,
                           user_playlist_ids_with_track=pl_ids,
                           format_count=format_count,
                           track_lyrics=get_lyrics_content(t),
                           has_video=has_cover_video(t))


@app.route('/track/<string:track_dir_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_track(track_dir_id):
    t = Track.query.filter_by(track_dir_id=track_dir_id).first_or_404()
    if t.uploader_id != current_user.id and not current_user.is_admin:
        flash('Нет доступа', 'danger')
        return redirect(url_for('track', track_dir_id=t.track_dir_id))
    if request.method == 'POST':
        with upload_semaphore:
            return _handle_edit_track(t)
    return render_template('edit_track.html', track=t)


def _handle_edit_track(track):
    track.title = request.form.get('title', track.title)
    track.artist_name = request.form.get('artist_name', track.artist_name) or None
    track.tags = request.form.get('tags', track.tags or '')
    track.is_ai = 'is_ai' in request.form
    db.session.flush()
    sync_track_tags(track)
    cover_file = request.files.get('cover_file')
    cover_video = request.files.get('cover_video_file')
    track_dir = get_track_dir(track)
    os.makedirs(track_dir, exist_ok=True)
    if cover_file and cover_file.filename:
        if is_video_file(cover_file.filename):
            ext = cover_file.filename.rsplit('.', 1)[1].lower()
            tmp = os.path.join(track_dir, f'_tmp_{uuid.uuid4().hex}.{ext}')
            cover_file.save(tmp)
            try:
                convert_video_to_cover(tmp, track, make_poster=True)
            except Exception as e:
                flash(f'Ошибка: {e}', 'danger')
                return redirect(url_for('edit_track', track_dir_id=track.track_dir_id))
            finally:
                safe_remove(tmp)
        else:
            try:
                safe_convert_to_webp(cover_file, get_cover_path(track), (512, 512))
            except Exception as e:
                flash(str(e), 'danger')
                return redirect(url_for('edit_track', track_dir_id=track.track_dir_id))
    if cover_video and cover_video.filename and is_video_file(cover_video.filename):
        ext = cover_video.filename.rsplit('.', 1)[1].lower()
        tmp = os.path.join(track_dir, f'_tmp_{uuid.uuid4().hex}.{ext}')
        cover_video.save(tmp)
        try:
            convert_video_to_cover(tmp, track, make_poster=False)
        except Exception as e:
            flash(f'Ошибка: {e}', 'danger')
            return redirect(url_for('edit_track', track_dir_id=track.track_dir_id))
        finally:
            safe_remove(tmp)
    lyrics_file = request.files.get('lyrics_file')
    if lyrics_file and lyrics_file.filename:
        try:
            save_lyrics_file(track, lyrics_file.read().decode('utf-8'))
        except Exception:
            flash('Ошибка чтения субтитров', 'danger')
            return redirect(url_for('edit_track', track_dir_id=track.track_dir_id))
    elif 'delete_lyrics' in request.form:
        delete_lyrics_file(track)
    if 'delete_cover_video' in request.form:
        safe_remove(get_cover_video_path(track))
        ensure_default_cover(track)
    commit_with_retry()
    flash('Трек обновлён', 'success')
    return redirect(url_for('track', track_dir_id=track.track_dir_id))


@app.route('/track/<string:track_dir_id>/delete', methods=['POST'])
@login_required
def delete_track(track_dir_id):
    t = Track.query.filter_by(track_dir_id=track_dir_id).first_or_404()
    if t.uploader_id != current_user.id and not current_user.is_admin:
        flash('Нет доступа', 'danger')
        return redirect(url_for('track', track_dir_id=t.track_dir_id))
    safe_rmtree(get_track_dir(t))
    db.session.delete(t)
    commit_with_retry()
    flash('Трек удалён', 'success')
    return redirect(url_for('index'))


@app.route('/api/track/<string:track_dir_id>/status')
@login_required
def track_status(track_dir_id):
    t = Track.query.filter_by(track_dir_id=track_dir_id).first_or_404()
    is_fav = Favorite.query.filter_by(user_id=current_user.id, track_id=t.id).first() is not None
    pl_ids = [pt.playlist_id for pt in PlaylistTrack.query.filter_by(track_id=t.id).all()]
    r = Rating.query.filter_by(user_id=current_user.id, track_id=t.id).first()
    return jsonify(is_favorite=is_fav, playlist_ids=pl_ids,
                   user_rating=r.value if r else 0,
                   likes=t.likes_count, dislikes=t.dislikes_count, plays=t.play_count)


@app.route('/api/rate/<string:track_dir_id>', methods=['POST'])
@login_required
@_rl('60/minute')
def rate_track(track_dir_id):
    t = Track.query.filter_by(track_dir_id=track_dir_id).first_or_404()
    try:
        value = int(request.form.get('value', 0))
    except Exception:
        return jsonify(error='Invalid value'), 400
    if value not in (1, -1):
        return jsonify(error='Invalid value'), 400
    existing = Rating.query.filter_by(user_id=current_user.id, track_id=t.id).first()
    try:
        if existing:
            if existing.value == value:
                db.session.delete(existing)
                if value == 1:
                    t.likes_count = max(0, t.likes_count - 1)
                else:
                    t.dislikes_count = max(0, t.dislikes_count - 1)
                commit_with_retry()
                return jsonify(likes=t.likes_count, dislikes=t.dislikes_count, user_rating=0)
            if existing.value == 1:
                t.likes_count = max(0, t.likes_count - 1)
                t.dislikes_count += 1
            else:
                t.dislikes_count = max(0, t.dislikes_count - 1)
                t.likes_count += 1
            existing.value = value
            commit_with_retry()
            return jsonify(likes=t.likes_count, dislikes=t.dislikes_count, user_rating=value)
        db.session.add(Rating(user_id=current_user.id, track_id=t.id, value=value))
        if value == 1:
            t.likes_count += 1
        else:
            t.dislikes_count += 1
        commit_with_retry()
        return jsonify(likes=t.likes_count, dislikes=t.dislikes_count, user_rating=value)
    except Exception:
        db.session.rollback()
        return jsonify(error='Retry'), 503


@app.route('/api/listen/<string:track_dir_id>', methods=['POST'])
@_rl('120/minute')
def api_listen(track_dir_id):
    t = Track.query.filter_by(track_dir_id=track_dir_id).first_or_404()
    now = utcnow()
    try:
        if current_user.is_authenticated:
            cutoff = now - timedelta(seconds=60)
            if ListenEvent.query.filter(ListenEvent.user_id == current_user.id,
                                        ListenEvent.track_id == t.id,
                                        ListenEvent.listened_at >= cutoff).first():
                return jsonify(status='throttled')
            db.session.add(ListenEvent(user_id=current_user.id, track_id=t.id, listened_at=now))
            with db.session.no_autoflush:
                h = ListeningHistory.query.filter_by(user_id=current_user.id, track_id=t.id).first()
            if h:
                h.count += 1
                h.listened_at = now
            else:
                db.session.add(ListeningHistory(user_id=current_user.id, track_id=t.id, count=1, listened_at=now))
            current_user.current_track_id = t.id
            current_user.current_track_started_at = now
            t.play_count = (t.play_count or 0) + 1
            uid = current_user.id
        else:
            t.play_count = (t.play_count or 0) + 1
            uid = None
        commit_with_retry()
        if uid:
            ws_broadcast_now_playing(uid, t.id)
            _dispatch_webhooks(uid, 'listen', {'track_id': t.track_dir_id, 'at': now.isoformat()})
    except Exception as e:
        db.session.rollback()
        log.warning(f"listen failed: {e}")
        return jsonify(status='error'), 500
    return jsonify(status='ok')


@app.route('/widgets')
@login_required
def widgets():
    ensure_widget_token(current_user)
    return render_template('widgets.html',
                           now_playing_url=url_for('widget_now_playing', token=current_user.widget_token, _external=True),
                           search_url=url_for('widget_search', token=current_user.widget_token, _external=True))


@app.route('/widget/<string:token>')
def widget_now_playing(token):
    User.query.filter_by(widget_token=token).first_or_404()
    return render_template('widget.html', token=token)


@app.route('/api/widget/<string:token>')
def api_widget_now_playing(token):
    u = User.query.filter_by(widget_token=token).first_or_404()
    playing = False
    track = None
    if u.current_track_id and u.current_track_started_at:
        if u.current_track_started_at <= utcnow() and utcnow() - u.current_track_started_at < timedelta(minutes=5):
            track = db.session.get(Track, u.current_track_id)
            if track:
                playing = True
    if not playing:
        return jsonify(playing=False)
    return jsonify(playing=True, track={
        'title': track.title,
        'artist': track.artist_name or track.uploader.display_name,
        'cover_url': _track_cover_url(track),
        'cover_video_url': _track_video_url(track),
        'track_url': url_for('track', track_dir_id=track.track_dir_id),
    })


@app.route('/widget/search/<string:token>')
def widget_search(token):
    User.query.filter_by(widget_token=token).first_or_404()
    return render_template('widget_search.html', token=token)


@app.route('/api/widget/<string:token>/search')
def api_widget_search(token):
    User.query.filter_by(widget_token=token).first_or_404()
    q = request.args.get('q', '').strip()
    kind = request.args.get('type', 'tracks')
    if not q:
        return jsonify(results=[])
    if kind == 'playlists':
        rows = Playlist.query.filter(Playlist.is_public.is_(True), Playlist.name.ilike(f'%{q}%')) \
            .order_by(Playlist.id.desc()).limit(20).all()
        return jsonify(results=[{'playlist_dir_id': p.playlist_dir_id, 'name': p.name,
                                 'owner': p.owner.display_name, 'track_count': p.tracks.count()} for p in rows])
    rows = Track.query.filter(or_(Track.title.ilike(f'%{q}%'), Track.artist_name.ilike(f'%{q}%'),
                                  Track.uploader.has(User.display_name.ilike(f'%{q}%')))) \
        .order_by(Track.play_count.desc()).limit(30).all()
    return jsonify(results=[{
        'track_dir_id': t.track_dir_id, 'title': t.title,
        'artist': t.artist_name or t.uploader.display_name, 'is_ai': bool(t.is_ai),
        'cover_url': _track_cover_url(t),
        'audio_url': url_for('static', filename=f'users/{t.uploader.user_dir_id}/music/{t.track_dir_id}/{t.track_dir_id}.{t.audio_ext}')
    } for t in rows])


@app.route('/api/widget/<string:token>/playlist/<string:playlist_dir_id>')
def api_widget_playlist_tracks(token, playlist_dir_id):
    u = User.query.filter_by(widget_token=token).first_or_404()
    pl = Playlist.query.filter_by(playlist_dir_id=playlist_dir_id).first_or_404()
    if not pl.is_public and pl.user_id != u.id and not u.is_admin:
        return jsonify(error='Access denied'), 403
    rows = db.session.query(Track).join(PlaylistTrack) \
        .filter(PlaylistTrack.playlist_id == pl.id).order_by(PlaylistTrack.position).all()
    return jsonify(name=pl.name, tracks=[{
        'track_dir_id': t.track_dir_id, 'title': t.title,
        'artist': t.artist_name or t.uploader.display_name, 'is_ai': bool(t.is_ai),
        'cover_url': _track_cover_url(t),
        'audio_url': url_for('static', filename=f'users/{t.uploader.user_dir_id}/music/{t.track_dir_id}/{t.track_dir_id}.{t.audio_ext}')
    } for t in rows])


@app.route('/api/widget/<string:token>/listen/<string:track_dir_id>', methods=['POST'])
@_rl('120/minute')
def api_widget_listen(token, track_dir_id):
    u = User.query.filter_by(widget_token=token).first_or_404()
    t = Track.query.filter_by(track_dir_id=track_dir_id).first_or_404()
    now = utcnow()
    try:
        u.current_track_id = t.id
        u.current_track_started_at = now
        if ListenEvent.query.filter(ListenEvent.user_id == u.id, ListenEvent.track_id == t.id,
                                    ListenEvent.listened_at >= now - timedelta(seconds=60)).first():
            commit_with_retry()
            return jsonify(status='throttled')
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
        return jsonify(status='error'), 500
    return jsonify(status='ok')


@app.route('/api/widget/<string:token>/stop', methods=['POST'])
def api_widget_stop(token):
    u = User.query.filter_by(widget_token=token).first_or_404()
    u.current_track_id = None
    u.current_track_started_at = None
    commit_with_retry()
    ws_broadcast_now_playing(u.id, None, stopped=True)
    return jsonify(status='ok')


@app.route('/login', methods=['GET', 'POST'])
@_rl('30/minute')
def login():
    if request.method == 'POST':
        ident = request.form.get('login', '')
        pw = request.form.get('password', '')
        u = User.query.filter(or_(User.login == ident, User.email == ident)).first()
        if u and check_password_hash(u.password_hash, pw):
            login_user(u)
            return redirect(url_for('index'))
        flash('Неверный логин/email или пароль', 'danger')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
@_rl('10/hour')
def register():
    if request.method == 'POST':
        login = request.form.get('login', '').strip()
        email = request.form.get('email', '').strip()
        pw = request.form.get('password', '')
        pw2 = request.form.get('password2', '')
        if not login or not email or not pw:
            flash('Заполните все поля', 'danger')
            return render_template('register.html')
        if len(pw) < 8:
            flash('Пароль минимум 8 символов', 'danger')
            return render_template('register.html')
        if pw != pw2:
            flash('Пароли не совпадают', 'danger')
            return render_template('register.html')
        if User.query.filter_by(login=login).first():
            flash('Логин занят', 'danger')
            return render_template('register.html')
        if User.query.filter_by(email=email).first():
            flash('Email занят', 'danger')
            return render_template('register.html')
        u = User(user_dir_id=generate_user_dir_id(), login=login, email=email,
                 password_hash=generate_password_hash(pw), display_name=login)
        db.session.add(u)
        commit_with_retry()
        os.makedirs(get_user_dir(u), exist_ok=True)
        login_user(u)
        return redirect(url_for('index'))
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/upload', methods=['GET', 'POST'])
@login_required
@_rl('20/hour')
def upload():
    if request.method == 'POST':
        with upload_semaphore:
            return _handle_upload()
    return render_template('upload.html')


def _handle_upload():
    upload_type = request.form.get('upload_type', 'file')
    title = request.form.get('title', '').strip()
    tags = request.form.get('tags', '')
    is_ai = 'is_ai' in request.form
    artist_name = request.form.get('artist_name', '').strip() or None
    lyrics_file = request.files.get('lyrics_file')
    lyrics_content = None
    if lyrics_file and lyrics_file.filename:
        try:
            lyrics_content = lyrics_file.read().decode('utf-8')
        except Exception:
            flash('Ошибка чтения субтитров', 'danger')
            return render_template('upload.html')
    if upload_type == 'youtube':
        youtube_url = request.form.get('youtube_url', '').strip()
        if not youtube_url:
            flash('Введите ссылку', 'danger')
            return render_template('upload.html')
        if not validate_youtube_url(youtube_url):
            flash('Разрешены только youtube.com / youtu.be', 'danger')
            return render_template('upload.html')
        tdid = generate_track_dir_id()
        t = Track(track_dir_id=tdid, title='YouTube Import', audio_ext='mp3',
                  tags=tags or '', is_ai=is_ai, uploader_id=current_user.id,
                  uploaded_at=utcnow(), artist_name=artist_name)
        db.session.add(t)
        db.session.flush()
        sync_track_tags(t)
        commit_with_retry()
        td = get_track_dir(t)
        os.makedirs(td, exist_ok=True)
        try:
            vt, va = download_from_youtube(youtube_url, td, tdid)
            t.title = vt
            if not artist_name:
                t.artist_name = va
            if lyrics_content:
                save_lyrics_file(t, lyrics_content)
            commit_with_retry()
            _dispatch_webhooks(current_user.id, 'upload', {'track_id': t.track_dir_id})
            flash('Загружено', 'success')
            return redirect(url_for('track', track_dir_id=t.track_dir_id))
        except Exception as e:
            db.session.delete(t)
            commit_with_retry()
            safe_rmtree(td)
            flash(f'Ошибка: {e}', 'danger')
            return render_template('upload.html')
    audio_file = request.files.get('audio_file')
    cover_file = request.files.get('cover_file')
    cover_video_file = request.files.get('cover_video_file')
    if not title or not audio_file:
        flash('Название и аудио обязательны', 'danger')
        return render_template('upload.html')
    if not allowed_audio_file(audio_file.filename):
        flash('Формат не поддерживается', 'danger')
        return render_template('upload.html')
    tdid = generate_track_dir_id()
    t = Track(track_dir_id=tdid, title=title,
              audio_ext=audio_file.filename.rsplit('.', 1)[1].lower(),
              tags=tags or '', is_ai=is_ai, uploader_id=current_user.id,
              uploaded_at=utcnow(), artist_name=artist_name)
    db.session.add(t)
    db.session.flush()
    sync_track_tags(t)
    commit_with_retry()
    td = get_track_dir(t)
    os.makedirs(td, exist_ok=True)
    audio_path = get_audio_path(t)
    audio_file.save(audio_path)
    sniffed = sniff_audio(audio_path)
    if not sniffed:
        db.session.delete(t)
        commit_with_retry()
        safe_rmtree(td)
        flash('Файл не похож на аудио', 'danger')
        return render_template('upload.html')
    t.audio_ext = sniffed
    if cover_file and cover_file.filename:
        if is_video_file(cover_file.filename):
            ext = cover_file.filename.rsplit('.', 1)[1].lower()
            tmp = os.path.join(td, f'_tmp_{uuid.uuid4().hex}.{ext}')
            cover_file.save(tmp)
            try:
                convert_video_to_cover(tmp, t, make_poster=True)
            except Exception as e:
                db.session.delete(t)
                commit_with_retry()
                safe_rmtree(td)
                flash(f'Ошибка: {e}', 'danger')
                return render_template('upload.html')
            finally:
                safe_remove(tmp)
        else:
            try:
                safe_convert_to_webp(cover_file, get_cover_path(t), (512, 512))
            except Exception as e:
                db.session.delete(t)
                commit_with_retry()
                safe_rmtree(td)
                flash(str(e), 'danger')
                return render_template('upload.html')
    if cover_video_file and cover_video_file.filename and is_video_file(cover_video_file.filename):
        ext = cover_video_file.filename.rsplit('.', 1)[1].lower()
        tmp = os.path.join(td, f'_tmp_{uuid.uuid4().hex}.{ext}')
        cover_video_file.save(tmp)
        try:
            convert_video_to_cover(tmp, t, make_poster=False)
        except Exception as e:
            db.session.delete(t)
            commit_with_retry()
            safe_rmtree(td)
            flash(f'Ошибка: {e}', 'danger')
            return render_template('upload.html')
        finally:
            safe_remove(tmp)
    ensure_default_cover(t)
    if lyrics_content:
        save_lyrics_file(t, lyrics_content)
    commit_with_retry()
    _dispatch_webhooks(current_user.id, 'upload', {'track_id': t.track_dir_id})
    flash('Трек опубликован', 'success')
    return redirect(url_for('track', track_dir_id=t.track_dir_id))


@app.route('/favorites')
@login_required
def favorites():
    favs = Favorite.query.filter_by(user_id=current_user.id).all()
    tracks = [db.session.get(Track, f.track_id) for f in favs]
    return render_template('favorites.html', tracks=[t for t in tracks if t])


@app.route('/favorite/toggle/<string:track_dir_id>', methods=['POST'])
@login_required
@_rl('120/minute')
def toggle_favorite(track_dir_id):
    t = Track.query.filter_by(track_dir_id=track_dir_id).first_or_404()
    fav = Favorite.query.filter_by(user_id=current_user.id, track_id=t.id).first()
    if fav:
        db.session.delete(fav)
        commit_with_retry()
        return jsonify(status='removed')
    db.session.add(Favorite(user_id=current_user.id, track_id=t.id))
    commit_with_retry()
    return jsonify(status='added')


@app.route('/history')
@login_required
def listening_history():
    subq = db.session.query(
        ListeningHistory.track_id,
        func.max(ListeningHistory.listened_at).label('max_time'),
        func.max(ListeningHistory.count).label('count')
    ).filter_by(user_id=current_user.id).group_by(ListeningHistory.track_id).subquery()
    items = db.session.query(ListeningHistory).join(
        subq, and_(ListeningHistory.track_id == subq.c.track_id,
                   ListeningHistory.listened_at == subq.c.max_time)) \
        .filter(ListeningHistory.user_id == current_user.id) \
        .order_by(desc(subq.c.max_time)).all()
    return render_template('history.html', history=items)


@app.route('/history/delete/<string:track_dir_id>', methods=['POST'])
@login_required
def delete_history_item(track_dir_id):
    t = Track.query.filter_by(track_dir_id=track_dir_id).first_or_404()
    ListeningHistory.query.filter_by(user_id=current_user.id, track_id=t.id).delete()
    ListenEvent.query.filter_by(user_id=current_user.id, track_id=t.id).delete()
    commit_with_retry()
    flash('Удалено', 'success')
    return redirect(url_for('listening_history'))


@app.route('/user/<string:user_dir_id>')
def user_profile(user_dir_id):
    u = User.query.filter_by(user_dir_id=user_dir_id).first_or_404()
    tracks = Track.query.filter_by(uploader_id=u.id) \
        .filter((Track.artist_name.is_(None)) | (Track.artist_name == '')) \
        .order_by(Track.uploaded_at.desc()).all()
    if current_user.is_authenticated and (current_user.id == u.id or current_user.is_admin):
        pls = Playlist.query.filter_by(user_id=u.id).order_by(Playlist.name).all()
    else:
        pls = Playlist.query.filter_by(user_id=u.id, is_public=True).order_by(Playlist.name).all()
    return render_template('user_profile.html', user=u, tracks=tracks,
                           playlists=pls, stats=get_user_stats(u),
                           format_count=format_count)


@app.route('/playlists')
@login_required
def playlists():
    return render_template('playlists.html',
                           playlists=Playlist.query.filter_by(user_id=current_user.id).all())


@app.route('/playlist/new', methods=['POST'])
@login_required
def create_playlist():
    name = request.form.get('name', '').strip()
    if name:
        db.session.add(Playlist(playlist_dir_id=generate_playlist_dir_id(),
                                name=name, user_id=current_user.id))
        commit_with_retry()
        flash(f'Плейлист "{name}" создан', 'success')
    return redirect(_safe_next())


@app.route('/playlist/<string:playlist_dir_id>/delete', methods=['POST'])
@login_required
def delete_playlist(playlist_dir_id):
    pl = Playlist.query.filter_by(playlist_dir_id=playlist_dir_id).first_or_404()
    if pl.user_id != current_user.id and not current_user.is_admin:
        flash('Нет доступа', 'danger')
        return redirect(url_for('playlists'))
    db.session.delete(pl)
    commit_with_retry()
    flash('Удалён', 'success')
    return redirect(url_for('playlists'))


@app.route('/playlist/<string:playlist_dir_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_playlist(playlist_dir_id):
    pl = Playlist.query.filter_by(playlist_dir_id=playlist_dir_id).first_or_404()
    if pl.user_id != current_user.id and not current_user.is_admin:
        flash('Нет доступа', 'danger')
        return redirect(url_for('playlists'))
    if request.method == 'POST':
        pl.name = request.form.get('name', pl.name)
        commit_with_retry()
        flash('Обновлён', 'success')
        return redirect(url_for('view_playlist', playlist_dir_id=pl.playlist_dir_id))
    return render_template('edit_playlist.html', playlist=pl)


@app.route('/api/playlist/<string:playlist_dir_id>/tracks')
@login_required
def api_playlist_tracks(playlist_dir_id):
    pl = Playlist.query.filter_by(playlist_dir_id=playlist_dir_id).first_or_404()
    if pl.user_id != current_user.id and not current_user.is_admin:
        return jsonify(error='Access denied'), 403
    tracks = db.session.query(Track).join(PlaylistTrack) \
        .filter(PlaylistTrack.playlist_id == pl.id).order_by(PlaylistTrack.position).all()
    return jsonify(tracks=[{
        'track_dir_id': t.track_dir_id, 'title': t.title,
        'display_name': t.artist_name or t.uploader.display_name,
        'is_ai': t.is_ai, 'cover_url': _track_cover_url(t)
    } for t in tracks], playlist_name=pl.name, playlist_dir_id=pl.playlist_dir_id)


@app.route('/playlist/<string:playlist_dir_id>')
def view_playlist(playlist_dir_id):
    pl = Playlist.query.filter_by(playlist_dir_id=playlist_dir_id).first_or_404()
    if not pl.is_public and (not current_user.is_authenticated or
                             (pl.user_id != current_user.id and not current_user.is_admin)):
        flash('Нет доступа', 'danger')
        return redirect(url_for('index'))
    tracks = db.session.query(Track).join(PlaylistTrack) \
        .filter(PlaylistTrack.playlist_id == pl.id).order_by(PlaylistTrack.position).all()
    is_owner = current_user.is_authenticated and pl.user_id == current_user.id
    for t in tracks:
        t.lyrics_content = get_lyrics_content(t)
    return render_template('playlist.html', playlist=pl, tracks=tracks, is_owner=is_owner)


@app.route('/playlist/<string:playlist_dir_id>/settings', methods=['POST'])
@login_required
def update_playlist_settings(playlist_dir_id):
    pl = Playlist.query.filter_by(playlist_dir_id=playlist_dir_id).first_or_404()
    if pl.user_id != current_user.id and not current_user.is_admin:
        return jsonify(error='Access denied'), 403
    pl.is_public = request.form.get('is_public', 'false') == 'true'
    commit_with_retry()
    return jsonify(status='ok', is_public=pl.is_public)


@app.route('/playlist/<string:playlist_dir_id>/add/<string:track_dir_id>', methods=['POST'])
@login_required
def toggle_track_playlist(playlist_dir_id, track_dir_id):
    pl = Playlist.query.filter_by(playlist_dir_id=playlist_dir_id).first_or_404()
    t = Track.query.filter_by(track_dir_id=track_dir_id).first_or_404()
    if pl.user_id != current_user.id and not current_user.is_admin:
        return jsonify(error='Access denied'), 403
    ex = PlaylistTrack.query.filter_by(playlist_id=pl.id, track_id=t.id).first()
    if ex:
        db.session.delete(ex)
        commit_with_retry()
        return jsonify(status='removed')
    maxpos = db.session.query(func.max(PlaylistTrack.position)).filter_by(playlist_id=pl.id).scalar() or 0
    db.session.add(PlaylistTrack(playlist_id=pl.id, track_id=t.id, position=maxpos + 1))
    commit_with_retry()
    return jsonify(status='added')


@app.route('/playlist/<string:playlist_dir_id>/remove/<string:track_dir_id>', methods=['POST'])
@login_required
def remove_from_playlist(playlist_dir_id, track_dir_id):
    pl = Playlist.query.filter_by(playlist_dir_id=playlist_dir_id).first_or_404()
    t = Track.query.filter_by(track_dir_id=track_dir_id).first_or_404()
    if pl.user_id != current_user.id and not current_user.is_admin:
        return jsonify(error='Access denied'), 403
    pt = PlaylistTrack.query.filter_by(playlist_id=pl.id, track_id=t.id).first()
    if pt:
        db.session.delete(pt)
        commit_with_retry()
    return jsonify(status='ok')


@app.route('/api/playlist/<string:playlist_dir_id>/reorder', methods=['POST'])
@login_required
def reorder_playlist(playlist_dir_id):
    pl = Playlist.query.filter_by(playlist_dir_id=playlist_dir_id).first_or_404()
    if pl.user_id != current_user.id and not current_user.is_admin:
        return jsonify(error='Access denied'), 403
    data = request.get_json() or {}
    order = data.get('order') or []
    for idx, td in enumerate(order):
        t = Track.query.filter_by(track_dir_id=td).first()
        if t:
            pt = PlaylistTrack.query.filter_by(playlist_id=pl.id, track_id=t.id).first()
            if pt:
                pt.position = idx
    commit_with_retry()
    return jsonify(status='ok')


@app.route('/api/admin/toggle/<string:user_dir_id>', methods=['POST'])
@login_required
def toggle_admin(user_dir_id):
    if not current_user.is_admin:
        return jsonify(error='Access denied'), 403
    u = User.query.filter_by(user_dir_id=user_dir_id).first_or_404()
    if u.id == current_user.id:
        return jsonify(error='Cannot change own'), 400
    u.is_admin = not u.is_admin
    commit_with_retry()
    return jsonify(status='ok', is_admin=u.is_admin)


@app.route('/api/admin/recompute', methods=['POST'])
@login_required
def admin_recompute():
    if not current_user.is_admin:
        return jsonify(error='Access denied'), 403
    recompute_all_similarities()
    return jsonify(status='ok')


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'regenerate_widget_token':
            current_user.widget_token = _make_widget_token()
            current_user.widget_token_created_at = utcnow()
            commit_with_retry()
            flash('Токен виджетов обновлён', 'success')
            return redirect(url_for('settings'))
        if action == 'regenerate_api_token':
            revoke_user_tokens(current_user)
            raw = issue_access_token(current_user)
            rraw = issue_refresh_token(current_user)
            flask_session['one_time_token'] = raw
            flask_session['one_time_refresh'] = rraw
            flash('Токен обновлён. Скопируйте его — он больше не будет показан.', 'success')
            return redirect(url_for('settings'))
        if action == 'password':
            cur = request.form.get('current_password', '')
            new = request.form.get('new_password', '')
            cf = request.form.get('confirm_password', '')
            if not check_password_hash(current_user.password_hash, cur):
                flash('Текущий пароль неверен', 'danger')
            elif len(new) < 8:
                flash('Минимум 8 символов', 'danger')
            elif new != cf:
                flash('Пароли не совпадают', 'danger')
            else:
                current_user.password_hash = generate_password_hash(new)
                current_user.api_token_hash = None
                current_user.api_token_expires_at = None
                RefreshToken.query.filter_by(user_id=current_user.id).update({'revoked': True})
                commit_with_retry()
                logout_user()
                flash('Пароль изменён. Войдите заново.', 'success')
                return redirect(url_for('login'))
        elif action == 'profile':
            current_user.display_name = request.form.get('display_name', current_user.display_name)
            current_user.bio = request.form.get('bio', '')
            email = request.form.get('email', '')
            if email and email != current_user.email:
                if User.query.filter_by(email=email).first():
                    flash('Email занят', 'danger')
                else:
                    current_user.email = email
            av = request.files.get('avatar')
            if av and av.filename:
                try:
                    ap = get_avatar_path(current_user)
                    tmp = ap + '.tmp'
                    convert_to_webp(av, tmp, (256, 256))
                    if not safe_replace(tmp, ap):
                        safe_remove(tmp)
                        flash('Не удалось заменить аватар', 'danger')
                        return redirect(url_for('settings'))
                except ValueError as e:
                    flash(str(e), 'danger')
                    return redirect(url_for('settings'))
            commit_with_retry()
            flash('Профиль обновлён', 'success')
        return redirect(url_for('settings'))
    one_time = flask_session.pop('one_time_token', None)
    one_time_r = flask_session.pop('one_time_refresh', None)
    return render_template('settings.html', one_time_token=one_time,
                           one_time_refresh=one_time_r)


api_v1 = Blueprint('api_v1', __name__, url_prefix='/api/v1')
csrf.exempt(api_v1)


@api_v1.route('/auth/register', methods=['POST'])
@_rl('10/hour')
def register():
    data = request.get_json(silent=True) or {}
    login = (data.get('login') or '').strip()
    email = (data.get('email') or '').strip()
    pw = data.get('password') or ''
    dn = (data.get('display_name') or login).strip()
    if not login or not email or not pw:
        return _json_error('bad_request', 'login, email and password are required')
    if len(pw) < 8:
        return _json_error('bad_request', 'password must be at least 8 characters')
    if User.query.filter_by(login=login).first():
        return _json_error('conflict', 'Login already taken', 409)
    if User.query.filter_by(email=email).first():
        return _json_error('conflict', 'Email already taken', 409)
    u = User(user_dir_id=generate_user_dir_id(), login=login, email=email,
             password_hash=generate_password_hash(pw), display_name=dn or login)
    db.session.add(u)
    commit_with_retry()
    os.makedirs(get_user_dir(u), exist_ok=True)
    access = issue_access_token(u)
    refresh = issue_refresh_token(u)
    return jsonify(ok=True, data={
        'access_token': access, 'refresh_token': refresh,
        'token_type': 'Bearer', 'user': serialize_user(u),
    })


@api_v1.route('/auth/login', methods=['POST'])
@_rl('20/minute')
def login():
    data = request.get_json(silent=True) or {}
    ident = data.get('login') or ''
    pw = data.get('password') or ''
    u = User.query.filter(or_(User.login == ident, User.email == ident)).first()
    if not u or not check_password_hash(u.password_hash, pw):
        return _json_error('unauthorized', 'Invalid credentials', 401)
    access = issue_access_token(u)
    refresh = issue_refresh_token(u)
    return jsonify(ok=True, data={
        'access_token': access, 'refresh_token': refresh,
        'token_type': 'Bearer', 'user': serialize_user(u),
    })


@api_v1.route('/auth/refresh', methods=['POST'])
@_rl('30/minute')
def refresh():
    data = request.get_json(silent=True) or {}
    raw = data.get('refresh_token') or ''
    if not raw:
        return _json_error('bad_request', 'refresh_token is required')
    h = _token_hash(raw)
    rt = RefreshToken.query.filter_by(token_hash=h, revoked=False).first()
    if not rt or rt.expires_at < utcnow():
        return _json_error('unauthorized', 'Invalid or expired refresh token', 401)
    u = db.session.get(User, rt.user_id)
    if not u:
        return _json_error('unauthorized', 'Invalid refresh token', 401)
    rt.revoked = True
    access = issue_access_token(u)
    new_refresh = issue_refresh_token(u)
    commit_with_retry()
    return jsonify(ok=True, data={
        'access_token': access, 'refresh_token': new_refresh,
        'token_type': 'Bearer', 'user': serialize_user(u),
    })


@api_v1.route('/auth/logout', methods=['POST'])
@api_login_required
def logout():
    revoke_user_tokens(g.api_user)
    return jsonify(ok=True)


@api_v1.route('/auth/me')
@api_login_required
def me():
    return jsonify(ok=True, data=serialize_user(g.api_user, include_stats=True))


@api_v1.route('/users/me', methods=['PATCH'])
@api_login_required
def update_me():
    u = g.api_user
    data = request.form if request.form else (request.get_json(silent=True) or {})
    if 'display_name' in data:
        dn = (data.get('display_name') or '').strip()
        if dn:
            u.display_name = dn
    if 'bio' in data:
        u.bio = (data.get('bio') or '').strip()
    av = request.files.get('avatar_file')
    if av and av.filename:
        try:
            ap = get_avatar_path(u)
            tmp = ap + '.tmp'
            convert_to_webp(av, tmp, (256, 256))
            if not safe_replace(tmp, ap):
                safe_remove(tmp)
                return _json_error('internal_error', 'Не удалось сохранить аватар', 500)
        except Exception as e:
            return _json_error('internal_error', str(e), 500)
    commit_with_retry()
    return jsonify(ok=True, data=serialize_user(u, include_stats=True))


@api_v1.route('/tracks')
@api_user_optional
def list_tracks():
    page = request.args.get('page', 1, type=int)
    pp = min(request.args.get('per_page', 20, type=int), 100)
    sort = request.args.get('sort', 'new')
    q = Track.query
    if sort == 'popular':
        q = q.order_by(Track.play_count.desc())
    elif sort == 'likes':
        q = q.order_by(Track.likes_count.desc())
    else:
        q = q.order_by(Track.uploaded_at.desc())
    pg = q.paginate(page=page, per_page=pp, error_out=False)
    return jsonify(ok=True, data={'items': [serialize_track(t) for t in pg.items],
                                   'page': pg.page, 'per_page': pg.per_page,
                                   'total': pg.total, 'pages': pg.pages})


@api_v1.route('/tracks', methods=['POST'])
@api_login_required
@_rl('20/hour')
def create_track():
    upload_type = request.form.get('upload_type', 'file')
    title = request.form.get('title', '').strip()
    tags = request.form.get('tags', '')
    is_ai = request.form.get('is_ai', '').lower() in ('1', 'true', 'yes', 'on')
    artist_name = request.form.get('artist_name', '').strip() or None
    lyrics_file = request.files.get('lyrics_file')
    lyrics = None
    if lyrics_file and lyrics_file.filename:
        try:
            lyrics = lyrics_file.read().decode('utf-8')
        except Exception:
            return _json_error('bad_request', 'Bad lyrics file')
    with upload_semaphore:
        if upload_type == 'youtube':
            url = request.form.get('youtube_url', '').strip()
            if not url or not validate_youtube_url(url):
                return _json_error('bad_request', 'youtube_url invalid')
            tdid = generate_track_dir_id()
            t = Track(track_dir_id=tdid, title='YouTube Import', audio_ext='mp3',
                      tags=tags or '', is_ai=is_ai, uploader_id=g.api_user.id,
                      uploaded_at=utcnow(), artist_name=artist_name)
            db.session.add(t)
            db.session.flush()
            sync_track_tags(t)
            commit_with_retry()
            td = get_track_dir(t)
            os.makedirs(td, exist_ok=True)
            try:
                vt, va = download_from_youtube(url, td, tdid)
                t.title = vt
                if not artist_name:
                    t.artist_name = va
                if lyrics:
                    save_lyrics_file(t, lyrics)
                commit_with_retry()
                _dispatch_webhooks(g.api_user.id, 'upload', {'track_id': t.track_dir_id})
                return jsonify(ok=True, data=serialize_track(t))
            except Exception as e:
                db.session.delete(t)
                commit_with_retry()
                safe_rmtree(td)
                return _json_error('internal_error', str(e), 500)
        audio = request.files.get('audio_file')
        if not audio or not allowed_audio_file(audio.filename):
            return _json_error('bad_request', 'Valid audio_file required')
        if not title:
            return _json_error('bad_request', 'title required')
        tdid = generate_track_dir_id()
        t = Track(track_dir_id=tdid, title=title,
                  audio_ext=audio.filename.rsplit('.', 1)[1].lower(),
                  tags=tags or '', is_ai=is_ai, uploader_id=g.api_user.id,
                  uploaded_at=utcnow(), artist_name=artist_name)
        db.session.add(t)
        db.session.flush()
        sync_track_tags(t)
        commit_with_retry()
        td = get_track_dir(t)
        os.makedirs(td, exist_ok=True)
        ap = get_audio_path(t)
        audio.save(ap)
        sn = sniff_audio(ap)
        if not sn:
            db.session.delete(t)
            commit_with_retry()
            safe_rmtree(td)
            return _json_error('bad_request', 'Audio signature not recognized')
        t.audio_ext = sn
        cover = request.files.get('cover_file')
        if cover and cover.filename:
            if is_video_file(cover.filename):
                ext = cover.filename.rsplit('.', 1)[1].lower()
                tmp = os.path.join(td, f'_t_{uuid.uuid4().hex}.{ext}')
                cover.save(tmp)
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
                    safe_convert_to_webp(cover, get_cover_path(t), (512, 512))
                except Exception as e:
                    db.session.delete(t)
                    commit_with_retry()
                    safe_rmtree(td)
                    return _json_error('internal_error', str(e), 500)
        cv = request.files.get('cover_video_file')
        if cv and cv.filename and is_video_file(cv.filename):
            ext = cv.filename.rsplit('.', 1)[1].lower()
            tmp = os.path.join(td, f'_t_{uuid.uuid4().hex}.{ext}')
            cv.save(tmp)
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
        _dispatch_webhooks(g.api_user.id, 'upload', {'track_id': t.track_dir_id})
        return jsonify(ok=True, data=serialize_track(t))


@api_v1.route('/tracks/<string:track_dir_id>')
@api_user_optional
def get_track(track_dir_id):
    t = Track.query.filter_by(track_dir_id=track_dir_id).first()
    if not t:
        return _json_error('not_found', 'Track not found', 404)
    data = serialize_track(t, include_lyrics=True)
    if g.api_user:
        fav = Favorite.query.filter_by(user_id=g.api_user.id, track_id=t.id).first()
        r = Rating.query.filter_by(user_id=g.api_user.id, track_id=t.id).first()
        pls = db.session.query(PlaylistTrack, Playlist).join(
            Playlist, Playlist.id == PlaylistTrack.playlist_id).filter(
            PlaylistTrack.track_id == t.id, Playlist.user_id == g.api_user.id).all()
        data['is_favorite'] = fav is not None
        data['user_rating'] = r.value if r else 0
        data['in_playlists'] = [pl.playlist_dir_id for _, pl in pls]
    else:
        data['is_favorite'] = False
        data['user_rating'] = 0
        data['in_playlists'] = []
    return jsonify(ok=True, data=data)


@api_v1.route('/tracks/<string:track_dir_id>', methods=['PATCH', 'DELETE'])
@api_login_required
def modify_track(track_dir_id):
    t = Track.query.filter_by(track_dir_id=track_dir_id).first()
    if not t:
        return _json_error('not_found', 'Track not found', 404)
    if t.uploader_id != g.api_user.id and not g.api_user.is_admin:
        return _json_error('forbidden', 'Access denied', 403)
        
    if request.method == 'DELETE':
        safe_rmtree(get_track_dir(t))
        db.session.delete(t)
        commit_with_retry()
        return jsonify(ok=True)
        
    data = request.form if request.form else (request.get_json(silent=True) or {})
    if 'title' in data and (data.get('title') or '').strip():
        t.title = data['title'].strip()
    if 'artist_name' in data:
        t.artist_name = (data.get('artist_name') or '').strip() or None
    if 'tags' in data:
        t.tags = data.get('tags') or ''
        db.session.flush()
        sync_track_tags(t)
    if 'is_ai' in data:
        val = data['is_ai']
        if isinstance(val, str):
            t.is_ai = val.lower() in ('true', '1', 'yes', 'on')
        else:
            t.is_ai = bool(val)
            
    cover_file = request.files.get('cover_file')
    if cover_file and cover_file.filename:
        if is_video_file(cover_file.filename):
            ext = cover_file.filename.rsplit('.', 1)[1].lower()
            tmp_path = os.path.join(get_track_dir(t), f'_tmp_{uuid.uuid4().hex}.{ext}')
            cover_file.save(tmp_path)
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

    lyrics_file = request.files.get('lyrics_file')
    if lyrics_file and lyrics_file.filename:
        try:
            save_lyrics_file(t, lyrics_file.read().decode('utf-8'))
        except Exception as e:
            return _json_error('internal_error', str(e), 500)
            
    commit_with_retry()
    return jsonify(ok=True, data=serialize_track(t))


@api_v1.route('/tracks/<string:track_dir_id>/stream')
def stream_track(track_dir_id):
    t = Track.query.filter_by(track_dir_id=track_dir_id).first()
    if not t:
        return _json_error('not_found', 'Track not found', 404)
    path = get_audio_path(t)
    if not os.path.exists(path):
        return _json_error('not_found', 'Audio not found', 404)
    mime = {'mp3': 'audio/mpeg', 'wav': 'audio/wav', 'ogg': 'audio/ogg', 'm4a': 'audio/mp4'}.get(t.audio_ext, 'audio/mpeg')
    resp = send_file(path, conditional=True, as_attachment=False, mimetype=mime)
    resp.headers['Accept-Ranges'] = 'bytes'
    resp.headers['Cache-Control'] = 'private, max-age=3600'
    return resp


@api_v1.route('/tracks/<string:track_dir_id>/similar')
@api_user_optional
def similar_tracks(track_dir_id):
    t = Track.query.filter_by(track_dir_id=track_dir_id).first()
    if not t:
        return _json_error('not_found', 'Track not found', 404)
    limit = min(request.args.get('limit', 6, type=int), 30)
    user = g.api_user
    if user and not getattr(user, 'is_authenticated', True):
        user = None
    return jsonify(ok=True, data={'items': [serialize_track(x) for x in get_track_recommendations(t, user, limit=limit)]})


@api_v1.route('/tracks/<string:track_dir_id>/lyrics')
def get_lyrics(track_dir_id):
    t = Track.query.filter_by(track_dir_id=track_dir_id).first()
    if not t:
        return _json_error('not_found', 'Track not found', 404)
    return jsonify(ok=True, data={'lyrics': get_lyrics_content(t)})


@api_v1.route('/tracks/<string:track_dir_id>/rate', methods=['POST'])
@api_login_required
@_rl('60/minute')
def rate(track_dir_id):
    t = Track.query.filter_by(track_dir_id=track_dir_id).first()
    if not t:
        return _json_error('not_found', 'Track not found', 404)
    data = request.get_json(silent=True) or {}
    try:
        v = int(data.get('value'))
    except Exception:
        return _json_error('bad_request', 'value must be 1 or -1')
    if v not in (1, -1):
        return _json_error('bad_request', 'value must be 1 or -1')
    try:
        ex = Rating.query.filter_by(user_id=g.api_user.id, track_id=t.id).first()
        if ex:
            if ex.value == v:
                db.session.delete(ex)
                if v == 1:
                    t.likes_count = max(0, t.likes_count - 1)
                else:
                    t.dislikes_count = max(0, t.dislikes_count - 1)
                commit_with_retry()
                return jsonify(ok=True, data={'likes': t.likes_count, 'dislikes': t.dislikes_count, 'user_rating': 0})
            if ex.value == 1:
                t.likes_count = max(0, t.likes_count - 1)
                t.dislikes_count += 1
            else:
                t.dislikes_count = max(0, t.dislikes_count - 1)
                t.likes_count += 1
            ex.value = v
            commit_with_retry()
            return jsonify(ok=True, data={'likes': t.likes_count, 'dislikes': t.dislikes_count, 'user_rating': v})
        db.session.add(Rating(user_id=g.api_user.id, track_id=t.id, value=v))
        if v == 1:
            t.likes_count += 1
        else:
            t.dislikes_count += 1
        commit_with_retry()
        return jsonify(ok=True, data={'likes': t.likes_count, 'dislikes': t.dislikes_count, 'user_rating': v})
    except Exception:
        db.session.rollback()
        return _json_error('internal_error', 'Retry', 503)


@api_v1.route('/tracks/<string:track_dir_id>/listen', methods=['POST'])
@api_login_required
@_rl('120/minute')
def listen(track_dir_id):
    t = Track.query.filter_by(track_dir_id=track_dir_id).first()
    if not t:
        return _json_error('not_found', 'Track not found', 404)
    u = g.api_user
    now = utcnow()
    try:
        if ListenEvent.query.filter(ListenEvent.user_id == u.id, ListenEvent.track_id == t.id,
                                    ListenEvent.listened_at >= now - timedelta(seconds=60)).first():
            return jsonify(ok=True, data={'status': 'throttled'})
        db.session.add(ListenEvent(user_id=u.id, track_id=t.id, listened_at=now))
        with db.session.no_autoflush:
            h = ListeningHistory.query.filter_by(user_id=u.id, track_id=t.id).first()
        if h:
            h.count += 1
            h.listened_at = now
        else:
            db.session.add(ListeningHistory(user_id=u.id, track_id=t.id, count=1, listened_at=now))
        u.current_track_id = t.id
        u.current_track_started_at = now
        t.play_count = (t.play_count or 0) + 1
        commit_with_retry()
        ws_broadcast_now_playing(u.id, t.id)
        _dispatch_webhooks(u.id, 'listen', {'track_id': t.track_dir_id, 'at': now.isoformat()})
        return jsonify(ok=True, data={'status': 'ok'})
    except Exception:
        db.session.rollback()
        return _json_error('internal_error', 'Failed', 500)


@api_v1.route('/tracks/<string:track_dir_id>/favorite', methods=['POST', 'DELETE'])
@api_login_required
def favorite(track_dir_id):
    t = Track.query.filter_by(track_dir_id=track_dir_id).first()
    if not t:
        return _json_error('not_found', 'Track not found', 404)
    fav = Favorite.query.filter_by(user_id=g.api_user.id, track_id=t.id).first()
    if request.method == 'DELETE':
        if fav:
            db.session.delete(fav)
            commit_with_retry()
        return jsonify(ok=True, data={'is_favorite': False})
    if not fav:
        db.session.add(Favorite(user_id=g.api_user.id, track_id=t.id))
        commit_with_retry()
    return jsonify(ok=True, data={'is_favorite': True})


@api_v1.route('/recommendations')
@api_user_optional
def recommendations():
    limit = min(request.args.get('limit', 16, type=int), 50)
    user = g.api_user
    if user and not getattr(user, 'is_authenticated', True):
        user = None
    return jsonify(ok=True, data={'items': [serialize_track(t) for t in get_recommendations(user, limit)]})


@api_v1.route('/charts')
def charts():
    days = request.args.get('period', 30, type=int)
    limit = min(request.args.get('limit', 50, type=int), 200)
    rows = db.session.query(Track, func.count(ListenEvent.id).label('cnt')) \
        .join(ListenEvent, ListenEvent.track_id == Track.id) \
        .filter(ListenEvent.listened_at >= utcnow() - timedelta(days=days)) \
        .group_by(Track.id).order_by(desc('cnt')).limit(limit).all()
    return jsonify(ok=True, data={'period_days': days, 'items': [serialize_track(r[0]) for r in rows]})


@api_v1.route('/new-releases')
def new_releases():
    days = request.args.get('days', 7, type=int)
    limit = min(request.args.get('limit', 20, type=int), 100)
    rows = Track.query.filter(Track.uploaded_at >= utcnow() - timedelta(days=days)) \
        .order_by(Track.uploaded_at.desc()).limit(limit).all()
    return jsonify(ok=True, data={'items': [serialize_track(t) for t in rows]})


@api_v1.route('/search')
def search_v1():
    q = request.args.get('q', '').strip()
    kind = request.args.get('type', 'tracks')
    limit = min(request.args.get('limit', 20, type=int), 100)
    if not q:
        return jsonify(ok=True, data={'type': kind, 'items': []})
    if kind == 'playlists':
        rows = Playlist.query.filter(Playlist.is_public.is_(True), Playlist.name.ilike(f'%{q}%')) \
            .order_by(Playlist.id.desc()).limit(limit).all()
        return jsonify(ok=True, data={'type': 'playlists', 'items': [serialize_playlist(p) for p in rows]})
    if kind == 'users':
        rows = User.query.filter(or_(User.login.ilike(f'%{q}%'), User.display_name.ilike(f'%{q}%'))).limit(limit).all()
        return jsonify(ok=True, data={'type': 'users', 'items': [serialize_user(u) for u in rows]})
    if kind == 'tags':
        rows = Tag.query.filter(Tag.name.ilike(f'%{q}%')).limit(limit).all()
        return jsonify(ok=True, data={'type': 'tags', 'items': [{'name': t.name} for t in rows]})
    rows = Track.query.filter(or_(
        Track.title.ilike(f'%{q}%'),
        Track.artist_name.ilike(f'%{q}%'),
        Track.uploader.has(User.display_name.ilike(f'%{q}%'))
    )).order_by(Track.play_count.desc()).limit(limit).all()
    return jsonify(ok=True, data={'type': 'tracks', 'items': [serialize_track(t) for t in rows]})


@api_v1.route('/advanced-search')
def advanced():
    title = request.args.get('title', '')
    artist = request.args.get('artist', '')
    tag = request.args.get('tag', '')
    is_ai = request.args.get('is_ai')
    limit = min(request.args.get('limit', 50, type=int), 200)
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
    return jsonify(ok=True, data={'items': [serialize_track(t) for t in q.order_by(Track.uploaded_at.desc()).limit(limit).all()]})


@api_v1.route('/tags')
def tags():
    q = request.args.get('q', '').strip()
    limit = min(request.args.get('limit', 20, type=int), 100)
    query = Tag.query
    if q:
        query = query.filter(Tag.name.ilike(f'%{q}%'))
    return jsonify(ok=True, data={'items': [{'name': t.name} for t in query.order_by(Tag.name).limit(limit).all()]})


@api_v1.route('/users/<string:user_dir_id>')
def user_get(user_dir_id):
    u = User.query.filter_by(user_dir_id=user_dir_id).first()
    if not u:
        return _json_error('not_found', 'User not found', 404)
    return jsonify(ok=True, data=serialize_user(u, include_stats=True))


@app.route('/api/v1/users/<string:user_dir_id>/tracks')
def user_tracks(user_dir_id):
    u = User.query.filter_by(user_dir_id=user_dir_id).first()
    if not u:
        return _json_error('not_found', 'User not found', 404)
    page = request.args.get('page', 1, type=int)
    pp = min(request.args.get('per_page', 20, type=int), 100)
    
    q = Track.query.filter_by(uploader_id=u.id)
    if request.args.get('own') == '1':
        q = q.filter((Track.artist_name.is_(None)) | (Track.artist_name == ''))
        
    pg = q.order_by(Track.uploaded_at.desc()).paginate(page=page, per_page=pp, error_out=False)
    return jsonify(ok=True, data={
        'items': [serialize_track(t) for t in pg.items],
        'page': pg.page,
        'per_page': pg.per_page,
        'total': pg.total,
        'pages': pg.pages,
    })


@api_v1.route('/users/<string:user_dir_id>/playlists')
@api_user_optional
def user_playlists(user_dir_id):
    u = User.query.filter_by(user_dir_id=user_dir_id).first()
    if not u:
        return _json_error('not_found', 'User not found', 404)
    if g.api_user and g.api_user.id == u.id:
        rows = Playlist.query.filter_by(user_id=u.id).order_by(Playlist.name).all()
    else:
        rows = Playlist.query.filter_by(user_id=u.id, is_public=True).order_by(Playlist.name).all()
    return jsonify(ok=True, data={'items': [serialize_playlist(p) for p in rows]})


@api_v1.route('/favorites')
@api_login_required
def favorites_v1():
    favs = Favorite.query.filter_by(user_id=g.api_user.id).order_by(Favorite.created_at.desc()).all()
    tracks = [db.session.get(Track, f.track_id) for f in favs]
    return jsonify(ok=True, data={'items': [serialize_track(t) for t in tracks if t]})


@api_v1.route('/history')
@api_login_required
def history_v1():
    subq = db.session.query(
        ListeningHistory.track_id,
        func.max(ListeningHistory.listened_at).label('max_time')
    ).filter_by(user_id=g.api_user.id).group_by(ListeningHistory.track_id).subquery()
    rows = db.session.query(ListeningHistory).join(
        subq, and_(ListeningHistory.track_id == subq.c.track_id,
                   ListeningHistory.listened_at == subq.c.max_time)) \
        .filter(ListeningHistory.user_id == g.api_user.id) \
        .order_by(desc(subq.c.max_time)).all()
    items = []
    for row in rows:
        t = db.session.get(Track, row.track_id)
        if t:
            items.append({'track': serialize_track(t),
                          'listened_at': row.listened_at.isoformat() if row.listened_at else None,
                          'count': row.count})
    return jsonify(ok=True, data={'items': items})


@api_v1.route('/history/<string:track_dir_id>', methods=['DELETE'])
@api_login_required
def history_delete(track_dir_id):
    t = Track.query.filter_by(track_dir_id=track_dir_id).first()
    if not t:
        return _json_error('not_found', 'Track not found', 404)
    ListeningHistory.query.filter_by(user_id=g.api_user.id, track_id=t.id).delete()
    ListenEvent.query.filter_by(user_id=g.api_user.id, track_id=t.id).delete()
    commit_with_retry()
    return jsonify(ok=True)


@api_v1.route('/playlists')
@api_login_required
def playlists_list():
    rows = Playlist.query.filter_by(user_id=g.api_user.id).order_by(Playlist.name).all()
    return jsonify(ok=True, data={'items': [serialize_playlist(p) for p in rows]})


@api_v1.route('/playlists', methods=['POST'])
@api_login_required
def playlists_create():
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    if not name:
        return _json_error('bad_request', 'name required')
    pl = Playlist(playlist_dir_id=generate_playlist_dir_id(), name=name,
                  user_id=g.api_user.id, is_public=bool(data.get('is_public', False)))
    db.session.add(pl)
    commit_with_retry()
    return jsonify(ok=True, data=serialize_playlist(pl))


@api_v1.route('/playlists/<string:playlist_dir_id>')
@api_user_optional
def playlist_get(playlist_dir_id):
    pl = Playlist.query.filter_by(playlist_dir_id=playlist_dir_id).first()
    if not pl:
        return _json_error('not_found', 'Playlist not found', 404)
    if not pl.is_public and (not g.api_user or (g.api_user.id != pl.user_id and not g.api_user.is_admin)):
        return _json_error('forbidden', 'Access denied', 403)
    return jsonify(ok=True, data=serialize_playlist(pl, include_tracks=True))


@api_v1.route('/playlists/<string:playlist_dir_id>', methods=['PATCH', 'DELETE'])
@api_login_required
def playlist_modify(playlist_dir_id):
    pl = Playlist.query.filter_by(playlist_dir_id=playlist_dir_id).first()
    if not pl:
        return _json_error('not_found', 'Playlist not found', 404)
    if pl.user_id != g.api_user.id and not g.api_user.is_admin:
        return _json_error('forbidden', 'Access denied', 403)
    if request.method == 'DELETE':
        db.session.delete(pl)
        commit_with_retry()
        return jsonify(ok=True)
    data = request.get_json(silent=True) or {}
    if 'name' in data and (data['name'] or '').strip():
        pl.name = data['name'].strip()
    if 'is_public' in data:
        pl.is_public = bool(data['is_public'])
    commit_with_retry()
    return jsonify(ok=True, data=serialize_playlist(pl))


@api_v1.route('/playlists/<string:playlist_dir_id>/tracks', methods=['POST'])
@api_login_required
def playlist_add_track(playlist_dir_id):
    pl = Playlist.query.filter_by(playlist_dir_id=playlist_dir_id).first()
    if not pl:
        return _json_error('not_found', 'Playlist not found', 404)
    if pl.user_id != g.api_user.id and not g.api_user.is_admin:
        return _json_error('forbidden', 'Access denied', 403)
    data = request.get_json(silent=True) or {}
    td = data.get('track_id')
    if not td:
        return _json_error('bad_request', 'track_id required')
    t = Track.query.filter_by(track_dir_id=td).first()
    if not t:
        return _json_error('not_found', 'Track not found', 404)
    if not PlaylistTrack.query.filter_by(playlist_id=pl.id, track_id=t.id).first():
        mp = db.session.query(func.max(PlaylistTrack.position)).filter_by(playlist_id=pl.id).scalar() or 0
        db.session.add(PlaylistTrack(playlist_id=pl.id, track_id=t.id, position=mp + 1))
        commit_with_retry()
    return jsonify(ok=True, data={'track_count': pl.tracks.count()})


@api_v1.route('/playlists/<string:playlist_dir_id>/tracks/<string:track_dir_id>', methods=['DELETE'])
@api_login_required
def playlist_remove_track(playlist_dir_id, track_dir_id):
    pl = Playlist.query.filter_by(playlist_dir_id=playlist_dir_id).first()
    if not pl:
        return _json_error('not_found', 'Playlist not found', 404)
    if pl.user_id != g.api_user.id and not g.api_user.is_admin:
        return _json_error('forbidden', 'Access denied', 403)
    t = Track.query.filter_by(track_dir_id=track_dir_id).first()
    if not t:
        return _json_error('not_found', 'Track not found', 404)
    pt = PlaylistTrack.query.filter_by(playlist_id=pl.id, track_id=t.id).first()
    if pt:
        db.session.delete(pt)
        commit_with_retry()
    return jsonify(ok=True, data={'track_count': pl.tracks.count()})


@api_v1.route('/playlists/<string:playlist_dir_id>/reorder', methods=['POST'])
@api_login_required
def playlist_reorder(playlist_dir_id):
    pl = Playlist.query.filter_by(playlist_dir_id=playlist_dir_id).first()
    if not pl:
        return _json_error('not_found', 'Playlist not found', 404)
    if pl.user_id != g.api_user.id and not g.api_user.is_admin:
        return _json_error('forbidden', 'Access denied', 403)
    data = request.get_json(silent=True) or {}
    order = data.get('order')
    if not isinstance(order, list):
        return _json_error('bad_request', 'order must be list')
    for idx, td in enumerate(order):
        t = Track.query.filter_by(track_dir_id=td).first()
        if t:
            pt = PlaylistTrack.query.filter_by(playlist_id=pl.id, track_id=t.id).first()
            if pt:
                pt.position = idx
    commit_with_retry()
    return jsonify(ok=True)


@api_v1.route('/webhooks')
@api_login_required
def webhooks_list():
    rows = Webhook.query.filter_by(user_id=g.api_user.id).all()
    return jsonify(ok=True, data={'items': [{'id': w.id, 'url': w.url,
                                              'events': w.event_types.split(','),
                                              'active': w.active} for w in rows]})


@api_v1.route('/webhooks', methods=['POST'])
@api_login_required
def webhooks_create():
    data = request.get_json(silent=True) or {}
    url = (data.get('url') or '').strip()
    events = data.get('events') or 'listen,upload'
    if not url.startswith(('http://', 'https://')):
        return _json_error('bad_request', 'url must be http(s)')
    secret = secrets.token_hex(32)
    w = Webhook(user_id=g.api_user.id, url=url, secret=secret,
                event_types=','.join(events) if isinstance(events, list) else events)
    db.session.add(w)
    commit_with_retry()
    return jsonify(ok=True, data={'id': w.id, 'url': w.url, 'secret': secret,
                                   'events': w.event_types.split(',')})


@api_v1.route('/webhooks/<int:wid>', methods=['DELETE'])
@api_login_required
def webhooks_delete(wid):
    w = db.session.get(Webhook, wid)
    if not w or w.user_id != g.api_user.id:
        return _json_error('not_found', 'Webhook not found', 404)
    db.session.delete(w)
    commit_with_retry()
    return jsonify(ok=True)


@sock.route('/ws/now-playing')
def ws_now_playing(ws):
    token = request.args.get('token', '')
    user = find_user_by_token(token) if token else None
    if not user:
        try:
            ws.send(json.dumps({'type': 'error', 'message': 'unauthorized'}))
        except Exception:
            pass
        return
    uid = user.id
    with _ws_lock:
        _ws_clients.setdefault(uid, []).append(ws)
    try:
        current = None
        if user.current_track_id and user.current_track_started_at:
            if utcnow() - user.current_track_started_at < timedelta(minutes=5):
                current = db.session.get(Track, user.current_track_id)
        if current:
            ws.send(json.dumps({'type': 'now_playing', 'playing': True, 'track': serialize_track(current)}))
        else:
            ws.send(json.dumps({'type': 'now_playing', 'playing': False}))
        while True:
            msg = ws.receive(timeout=60)
            if msg is None:
                ws.send(json.dumps({'type': 'ping'}))
    except Exception:
        pass
    finally:
        with _ws_lock:
            lst = _ws_clients.get(uid, [])
            if ws in lst:
                lst.remove(ws)
            if not lst:
                _ws_clients.pop(uid, None)


def _oauth_redirect_uri(provider):
    return url_for('oauth_callback', provider=provider, _external=True)


@app.route('/auth/<string:provider>/login')
@_rl('20/minute')
def oauth_start(provider):
    if provider not in OAUTH_PROVIDERS:
        flash('OAuth провайдер не настроен', 'danger')
        return redirect(url_for('login'))
    cfg = OAUTH_PROVIDERS[provider]
    state = secrets.token_urlsafe(24)
    flask_session['oauth_state'] = state
    flask_session['oauth_provider'] = provider
    from urllib.parse import urlencode
    params = {
        'client_id': cfg['client_id'],
        'redirect_uri': _oauth_redirect_uri(provider),
        'scope': cfg['scope'],
        'state': state,
        'response_type': 'code',
    }
    if provider == 'google':
        params['access_type'] = 'online'
        params['prompt'] = 'select_account'
    return redirect(cfg['authorize_url'] + '?' + urlencode(params))


@app.route('/auth/<string:provider>/callback')
def oauth_callback(provider):
    if provider not in OAUTH_PROVIDERS:
        flash('OAuth провайдер не настроен', 'danger')
        return redirect(url_for('login'))
    state = request.args.get('state', '')
    expected = flask_session.pop('oauth_state', None)
    if not expected or state != expected:
        flash('Неверный state OAuth', 'danger')
        return redirect(url_for('login'))
    code = request.args.get('code', '')
    if not code:
        flash('OAuth отказано', 'danger')
        return redirect(url_for('login'))
    cfg = OAUTH_PROVIDERS[provider]
    headers = {'Accept': 'application/json'}
    try:
        r = requests.post(cfg['token_url'], data={
            'client_id': cfg['client_id'],
            'client_secret': cfg['client_secret'],
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': _oauth_redirect_uri(provider),
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
        flash(f'OAuth ошибка: {e}', 'danger')
        return redirect(url_for('login'))
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
    if not pid or not email:
        flash('OAuth: не удалось получить email', 'danger')
        return redirect(url_for('login'))
    acct = OAuthAccount.query.filter_by(provider=provider, provider_user_id=pid).first()
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
                     display_name=name or login_candidate)
            db.session.add(u)
            commit_with_retry()
            os.makedirs(get_user_dir(u), exist_ok=True)
        db.session.add(OAuthAccount(user_id=u.id, provider=provider, provider_user_id=pid))
        commit_with_retry()
    if not u:
        flash('OAuth: пользователь не найден', 'danger')
        return redirect(url_for('login'))
    login_user(u)
    return redirect(url_for('index'))


OPENAPI = {
    'openapi': '3.1.0',
    'info': {'title': 'MusicForge API', 'version': '1.0.0'},
    'servers': [{'url': '/api/v1'}],
    'components': {'securitySchemes': {
        'bearer': {'type': 'http', 'scheme': 'bearer'}
    }},
    'security': [{'bearer': []}],
    'paths': {
        '/auth/register': {'post': {'summary': 'Register', 'security': []}},
        '/auth/login': {'post': {'summary': 'Login', 'security': []}},
        '/auth/refresh': {'post': {'summary': 'Refresh tokens', 'security': []}},
        '/auth/logout': {'post': {'summary': 'Revoke tokens'}},
        '/auth/me': {'get': {'summary': 'Current user'}},
        '/tracks': {'get': {'summary': 'List tracks'}, 'post': {'summary': 'Upload track (multipart)'}},
        '/tracks/{id}': {'get': {'summary': 'Track by id'}, 'patch': {'summary': 'Update track'}, 'delete': {'summary': 'Delete track'}},
        '/tracks/{id}/stream': {'get': {'summary': 'Stream audio (Range supported)', 'security': []}},
        '/tracks/{id}/similar': {'get': {'summary': 'Similar tracks'}},
        '/tracks/{id}/lyrics': {'get': {'summary': 'SRT lyrics'}},
        '/tracks/{id}/rate': {'post': {'summary': 'Like/dislike'}},
        '/tracks/{id}/listen': {'post': {'summary': 'Record listen'}},
        '/tracks/{id}/favorite': {'post': {'summary': 'Add favorite'}, 'delete': {'summary': 'Remove favorite'}},
        '/recommendations': {'get': {'summary': 'Personal recommendations'}},
        '/charts': {'get': {'summary': 'Popular tracks'}},
        '/new-releases': {'get': {'summary': 'Recent tracks'}},
        '/search': {'get': {'summary': 'Search tracks/playlists/users/tags'}},
        '/advanced-search': {'get': {'summary': 'Advanced filter'}},
        '/tags': {'get': {'summary': 'Tag autocomplete'}},
        '/users/{id}': {'get': {'summary': 'User profile'}},
        '/users/{id}/tracks': {'get': {'summary': 'User tracks'}},
        '/users/{id}/playlists': {'get': {'summary': 'User playlists'}},
        '/favorites': {'get': {'summary': 'My favorites'}},
        '/history': {'get': {'summary': 'My history'}},
        '/history/{id}': {'delete': {'summary': 'Delete history entry'}},
        '/playlists': {'get': {'summary': 'My playlists'}, 'post': {'summary': 'Create playlist'}},
        '/playlists/{id}': {'get': {'summary': 'Get playlist'}, 'patch': {'summary': 'Update'}, 'delete': {'summary': 'Delete'}},
        '/playlists/{id}/tracks': {'post': {'summary': 'Add track'}},
        '/playlists/{id}/tracks/{tid}': {'delete': {'summary': 'Remove track'}},
        '/playlists/{id}/reorder': {'post': {'summary': 'Reorder tracks'}},
        '/webhooks': {'get': {'summary': 'List webhooks'}, 'post': {'summary': 'Create webhook'}},
        '/webhooks/{id}': {'delete': {'summary': 'Delete webhook'}},
    },
}


@app.route('/api/v1/openapi.json')
def openapi_spec():
    return jsonify(OPENAPI)


@app.route('/api/v1/docs')
def openapi_docs():
    return '''<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>MusicForge API</title>
<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"></head>
<body><div id="ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>SwaggerUIBundle({url:'/api/v1/openapi.json',dom_id:'#ui'});</script>
</body></html>'''


app.register_blueprint(api_v1)


if __name__ == '__main__':
    with app.app_context():
        os.makedirs('static', exist_ok=True)
        os.makedirs(BASE_USER_DIR, exist_ok=True)
        db.create_all()
        default_cover = os.path.join('static', 'default_cover.webp')
        if not os.path.exists(default_cover):
            Image.new('RGB', (512, 512), color='#2a2a3a').save(default_cover, 'webp')
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', '5000'))
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    log.info(f'MusicForge на http://{host}:{port}')
    app.run(host=host, port=port, debug=debug, threaded=True, use_reloader=False)
