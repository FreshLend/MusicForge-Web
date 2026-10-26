import os
import uuid
import contextvars
from datetime import datetime, timezone

from sqlalchemy import (
    Column, Integer, String, Text, Boolean, DateTime, Float, ForeignKey,
    Index, UniqueConstraint, create_engine,
)
from sqlalchemy.orm import (
    DeclarativeBase, scoped_session, sessionmaker, relationship, Query,
)
from sqlalchemy.pool import NullPool
from fastapi import HTTPException


DATABASE_URI = os.environ.get('DATABASE_URI', 'sqlite:///musicforge.db')

_is_sqlite = DATABASE_URI.startswith('sqlite')
_connect_args = {}
_pool_kwargs = {}

if _is_sqlite:
    _connect_args = {'timeout': 60, 'check_same_thread': False}
    _pool_kwargs = {'poolclass': NullPool, 'pool_pre_ping': True}
else:
    _pool_kwargs = {
        'pool_pre_ping': True,
        'pool_size': int(os.environ.get('DB_POOL_SIZE', '10')),
        'max_overflow': int(os.environ.get('DB_MAX_OVERFLOW', '20')),
        'pool_recycle': 1800,
    }

engine = create_engine(
    DATABASE_URI,
    connect_args=_connect_args,
    **_pool_kwargs,
)


class Pagination:
    def __init__(self, page, per_page, total, items, pages):
        self.page = page
        self.per_page = per_page
        self.total = total
        self.items = items
        self.pages = pages
        self.has_prev = page > 1
        self.has_next = page < pages
        self.prev_num = page - 1 if page > 1 else None
        self.next_num = page + 1 if page < pages else None

    def iter_pages(self, left_edge=2, left_current=2, right_current=2, right_edge=2):
        last = 0
        for num in range(1, self.pages + 1):
            if (num <= left_edge or
                    (self.page - left_current - 1 < num < self.page + right_current) or
                    num > self.pages - right_edge):
                if last + 1 != num:
                    yield None
                yield num
                last = num


class PaginatedQuery(Query):
    def paginate(self, page=None, per_page=None, error_out=True, max_per_page=None):
        if page is None:
            page = 1
        try:
            page = int(page)
        except (TypeError, ValueError):
            if error_out:
                raise HTTPException(status_code=404)
            page = 1
        if per_page is None:
            per_page = 20
        try:
            per_page = int(per_page)
        except (TypeError, ValueError):
            per_page = 20
        if max_per_page is not None:
            per_page = min(per_page, max_per_page)
        if page < 1:
            if error_out:
                raise HTTPException(status_code=404)
            page = 1
        if per_page < 1:
            if error_out:
                raise HTTPException(status_code=404)
            per_page = 20
        total = self.order_by(None).count()
        items = self.limit(per_page).offset((page - 1) * per_page).all()
        if not items and page != 1 and error_out:
            raise HTTPException(status_code=404)
        pages = (total + per_page - 1) // per_page if per_page else 0
        return Pagination(page, per_page, total, items, pages)


_db_token = contextvars.ContextVar('musicforge_db_token', default=None)


def _scopefunc():
    token = _db_token.get()
    if token is None:
        token = uuid.uuid4()
        _db_token.set(token)
    return token


Session = scoped_session(
    sessionmaker(
        bind=engine,
        query_cls=PaginatedQuery,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    ),
    scopefunc=_scopefunc,
)


class _QueryDescriptor:
    def __get__(self, obj, cls):
        return Session.query(cls)


class Base(DeclarativeBase):
    query = _QueryDescriptor()


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class _DB:
    Model = Base
    session = Session

    def create_all(self):
        Base.metadata.create_all(engine)


db = _DB()


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    user_dir_id = Column(String(32), unique=True, nullable=False, index=True)
    login = Column(String(80), unique=True, nullable=False, index=True)
    email = Column(String(120), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    has_custom_password = Column(Boolean, default=True, nullable=False)
    display_name = Column(String(120), nullable=False)
    bio = Column(Text, default='')
    current_track_id = Column(Integer, ForeignKey('track.id', ondelete='SET NULL'), nullable=True)
    current_track_started_at = Column(DateTime, nullable=True)
    is_admin = Column(Boolean, default=False, nullable=False)
    widget_token = Column(String(64), unique=True, nullable=True, index=True)
    widget_token_created_at = Column(DateTime, nullable=True)
    api_token_hash = Column(String(128), unique=True, nullable=True, index=True)
    api_token_expires_at = Column(DateTime, nullable=True)
    last_username_change = Column(DateTime, nullable=True)

    playlists = relationship('Playlist', backref='owner', lazy='dynamic',
                             cascade='all, delete-orphan')
    tracks = relationship('Track', backref='uploader', lazy='dynamic',
                          foreign_keys='Track.uploader_id',
                          cascade='all, delete-orphan')
    current_track = relationship('Track', foreign_keys=[current_track_id], post_update=True)
    oauth_accounts = relationship('OAuthAccount', backref='user', lazy='dynamic',
                                  cascade='all, delete-orphan')

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    @property
    def is_active(self):
        return True

    def get_id(self):
        return str(self.id)


class Track(Base):
    __tablename__ = 'track'
    id = Column(Integer, primary_key=True)
    track_dir_id = Column(String(16), unique=True, nullable=False, index=True)
    title = Column(String(200), nullable=False)
    audio_ext = Column(String(5), nullable=False)
    tags = Column(String(500), default='')
    is_ai = Column(Boolean, default=False, nullable=False)
    uploader_id = Column(Integer, ForeignKey('user.id', ondelete='CASCADE'),
                         nullable=False, index=True)
    uploaded_at = Column(DateTime, default=utcnow, nullable=False, index=True)
    play_count = Column(Integer, default=0, nullable=False)
    likes_count = Column(Integer, default=0, nullable=False)
    dislikes_count = Column(Integer, default=0, nullable=False)
    artist_name = Column(String(200), nullable=True, index=True)
    lyrics_filename = Column(String(64), nullable=True)
    __table_args__ = (
        Index('ix_track_ai_uploaded', 'is_ai', 'uploaded_at'),
        Index('ix_track_uploader_uploaded', 'uploader_id', 'uploaded_at'),
    )


class Playlist(Base):
    __tablename__ = 'playlist'
    id = Column(Integer, primary_key=True)
    playlist_dir_id = Column(String(16), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id', ondelete='CASCADE'),
                     nullable=False, index=True)
    is_public = Column(Boolean, default=False, nullable=False)
    tracks = relationship('PlaylistTrack', backref='playlist', lazy='dynamic',
                          cascade='all, delete-orphan')


class PlaylistTrack(Base):
    __tablename__ = 'playlist_track'
    id = Column(Integer, primary_key=True)
    playlist_id = Column(Integer, ForeignKey('playlist.id', ondelete='CASCADE'), nullable=False)
    track_id = Column(Integer, ForeignKey('track.id', ondelete='CASCADE'), nullable=False)
    position = Column(Integer, default=0, nullable=False)
    __table_args__ = (
        UniqueConstraint('playlist_id', 'track_id', name='_playlist_track_uc'),
        Index('ix_pt_playlist_pos', 'playlist_id', 'position'),
        Index('ix_pt_track', 'track_id'),
    )


class Favorite(Base):
    __tablename__ = 'favorite'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    track_id = Column(Integer, ForeignKey('track.id', ondelete='CASCADE'), nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    __table_args__ = (
        UniqueConstraint('user_id', 'track_id', name='_favorite_uc'),
        Index('ix_fav_user', 'user_id'),
        Index('ix_fav_track', 'track_id'),
    )


class Rating(Base):
    __tablename__ = 'rating'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    track_id = Column(Integer, ForeignKey('track.id', ondelete='CASCADE'), nullable=False)
    value = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    __table_args__ = (
        UniqueConstraint('user_id', 'track_id', name='_rating_uc'),
        Index('ix_rating_user', 'user_id'),
        Index('ix_rating_track', 'track_id'),
    )


class ListenEvent(Base):
    __tablename__ = 'listen_event'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    track_id = Column(Integer, ForeignKey('track.id', ondelete='CASCADE'), nullable=False)
    listened_at = Column(DateTime, default=utcnow, nullable=False)
    __table_args__ = (
        Index('ix_listen_user_time', 'user_id', 'listened_at'),
        Index('ix_listen_track_time', 'track_id', 'listened_at'),
        Index('ix_listen_user_track', 'user_id', 'track_id'),
    )


class ListeningHistory(Base):
    __tablename__ = 'listening_history'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    track_id = Column(Integer, ForeignKey('track.id', ondelete='CASCADE'), nullable=False)
    listened_at = Column(DateTime, default=utcnow, nullable=False)
    count = Column(Integer, default=1, nullable=False)
    track = relationship('Track', backref='listening_history')
    __table_args__ = (
        UniqueConstraint('user_id', 'track_id', name='_user_track_uc'),
        Index('ix_lh_user', 'user_id'),
        Index('ix_lh_track', 'track_id'),
    )


class Tag(Base):
    __tablename__ = 'tag'
    id = Column(Integer, primary_key=True)
    name = Column(String(80), unique=True, nullable=False, index=True)


class TrackTag(Base):
    __tablename__ = 'track_tag'
    track_id = Column(Integer, ForeignKey('track.id', ondelete='CASCADE'), primary_key=True)
    tag_id = Column(Integer, ForeignKey('tag.id', ondelete='CASCADE'), primary_key=True)
    __table_args__ = (Index('ix_tt_tag', 'tag_id'),)


class TrackSimilarity(Base):
    __tablename__ = 'track_similarity'
    track_a_id = Column(Integer, ForeignKey('track.id', ondelete='CASCADE'), primary_key=True)
    track_b_id = Column(Integer, ForeignKey('track.id', ondelete='CASCADE'), primary_key=True)
    score = Column(Float, nullable=False, default=0.0)
    updated_at = Column(DateTime, default=utcnow, nullable=False)
    __table_args__ = (
        Index('ix_sim_a_score', 'track_a_id', 'score'),
        Index('ix_sim_b_score', 'track_b_id', 'score'),
    )


class UserSimilarity(Base):
    __tablename__ = 'user_similarity'
    user_a_id = Column(Integer, ForeignKey('user.id', ondelete='CASCADE'), primary_key=True)
    user_b_id = Column(Integer, ForeignKey('user.id', ondelete='CASCADE'), primary_key=True)
    score = Column(Float, nullable=False, default=0.0)
    updated_at = Column(DateTime, default=utcnow, nullable=False)
    __table_args__ = (
        Index('ix_usim_a_score', 'user_a_id', 'score'),
        Index('ix_usim_b_score', 'user_b_id', 'score'),
    )


class RefreshToken(Base):
    __tablename__ = 'refresh_token'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id', ondelete='CASCADE'), nullable=False, index=True)
    token_hash = Column(String(128), unique=True, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)


class OAuthAccount(Base):
    __tablename__ = 'oauth_account'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id', ondelete='CASCADE'), nullable=False, index=True)
    provider = Column(String(32), nullable=False)
    provider_user_id = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    __table_args__ = (
        UniqueConstraint('provider', 'provider_user_id', name='_oauth_provider_uid_uc'),
    )


class Webhook(Base):
    __tablename__ = 'webhook'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id', ondelete='CASCADE'), nullable=False, index=True)
    url = Column(String(500), nullable=False)
    secret = Column(String(128), nullable=False)
    event_types = Column(String(200), default='listen,upload', nullable=False)
    active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)