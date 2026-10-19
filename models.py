from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timezone


db = SQLAlchemy()


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    user_dir_id = db.Column(db.String(32), unique=True, nullable=False, index=True)
    login = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    display_name = db.Column(db.String(120), nullable=False)
    bio = db.Column(db.Text, default='')
    current_track_id = db.Column(db.Integer, db.ForeignKey('track.id', ondelete='SET NULL'), nullable=True)
    current_track_started_at = db.Column(db.DateTime, nullable=True)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    widget_token = db.Column(db.String(64), unique=True, nullable=True, index=True)
    widget_token_created_at = db.Column(db.DateTime, nullable=True)
    api_token_hash = db.Column(db.String(128), unique=True, nullable=True, index=True)
    api_token_expires_at = db.Column(db.DateTime, nullable=True)

    playlists = db.relationship('Playlist', backref='owner', lazy='dynamic',
                                cascade='all, delete-orphan')
    tracks = db.relationship('Track', backref='uploader', lazy='dynamic',
                             foreign_keys='Track.uploader_id',
                             cascade='all, delete-orphan')
    current_track = db.relationship('Track', foreign_keys=[current_track_id], post_update=True)

    def set_password(self, password):
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, password)


class Track(db.Model):
    __tablename__ = 'track'
    id = db.Column(db.Integer, primary_key=True)
    track_dir_id = db.Column(db.String(16), unique=True, nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    audio_ext = db.Column(db.String(5), nullable=False)
    tags = db.Column(db.String(500), default='')
    is_ai = db.Column(db.Boolean, default=False, nullable=False)
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'),
                            nullable=False, index=True)
    uploaded_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)
    play_count = db.Column(db.Integer, default=0, nullable=False)
    likes_count = db.Column(db.Integer, default=0, nullable=False)
    dislikes_count = db.Column(db.Integer, default=0, nullable=False)
    artist_name = db.Column(db.String(200), nullable=True, index=True)
    lyrics_filename = db.Column(db.String(64), nullable=True)

    __table_args__ = (db.Index('ix_track_ai_uploaded', 'is_ai', 'uploaded_at'),)


class Playlist(db.Model):
    __tablename__ = 'playlist'
    id = db.Column(db.Integer, primary_key=True)
    playlist_dir_id = db.Column(db.String(16), unique=True, nullable=False, index=True)
    name = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'),
                        nullable=False, index=True)
    is_public = db.Column(db.Boolean, default=False, nullable=False)
    tracks = db.relationship('PlaylistTrack', backref='playlist', lazy='dynamic',
                             cascade='all, delete-orphan')


class PlaylistTrack(db.Model):
    __tablename__ = 'playlist_track'
    id = db.Column(db.Integer, primary_key=True)
    playlist_id = db.Column(db.Integer, db.ForeignKey('playlist.id', ondelete='CASCADE'), nullable=False)
    track_id = db.Column(db.Integer, db.ForeignKey('track.id', ondelete='CASCADE'), nullable=False)
    position = db.Column(db.Integer, default=0, nullable=False)

    __table_args__ = (
        db.UniqueConstraint('playlist_id', 'track_id', name='_playlist_track_uc'),
        db.Index('ix_pt_playlist_pos', 'playlist_id', 'position'),
        db.Index('ix_pt_track', 'track_id'),
    )


class Favorite(db.Model):
    __tablename__ = 'favorite'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    track_id = db.Column(db.Integer, db.ForeignKey('track.id', ondelete='CASCADE'), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    __table_args__ = (
        db.UniqueConstraint('user_id', 'track_id', name='_favorite_uc'),
        db.Index('ix_fav_user', 'user_id'),
        db.Index('ix_fav_track', 'track_id'),
    )


class Rating(db.Model):
    __tablename__ = 'rating'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    track_id = db.Column(db.Integer, db.ForeignKey('track.id', ondelete='CASCADE'), nullable=False)
    value = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    __table_args__ = (
        db.UniqueConstraint('user_id', 'track_id', name='_rating_uc'),
        db.Index('ix_rating_user', 'user_id'),
        db.Index('ix_rating_track', 'track_id'),
    )


class ListenEvent(db.Model):
    __tablename__ = 'listen_event'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    track_id = db.Column(db.Integer, db.ForeignKey('track.id', ondelete='CASCADE'), nullable=False)
    listened_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    __table_args__ = (
        db.Index('ix_listen_user_time', 'user_id', 'listened_at'),
        db.Index('ix_listen_track_time', 'track_id', 'listened_at'),
        db.Index('ix_listen_user_track', 'user_id', 'track_id'),
    )


class ListeningHistory(db.Model):
    __tablename__ = 'listening_history'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    track_id = db.Column(db.Integer, db.ForeignKey('track.id', ondelete='CASCADE'), nullable=False)
    listened_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    count = db.Column(db.Integer, default=1, nullable=False)
    track = db.relationship('Track', backref='listening_history')

    __table_args__ = (
        db.UniqueConstraint('user_id', 'track_id', name='_user_track_uc'),
        db.Index('ix_lh_user', 'user_id'),
        db.Index('ix_lh_track', 'track_id'),
    )


class Tag(db.Model):
    __tablename__ = 'tag'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False, index=True)


class TrackTag(db.Model):
    __tablename__ = 'track_tag'
    track_id = db.Column(db.Integer, db.ForeignKey('track.id', ondelete='CASCADE'), primary_key=True)
    tag_id = db.Column(db.Integer, db.ForeignKey('tag.id', ondelete='CASCADE'), primary_key=True)
    __table_args__ = (db.Index('ix_tt_tag', 'tag_id'),)


class TrackSimilarity(db.Model):
    __tablename__ = 'track_similarity'
    track_a_id = db.Column(db.Integer, db.ForeignKey('track.id', ondelete='CASCADE'), primary_key=True)
    track_b_id = db.Column(db.Integer, db.ForeignKey('track.id', ondelete='CASCADE'), primary_key=True)
    score = db.Column(db.Float, nullable=False, default=0.0)
    updated_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    __table_args__ = (
        db.Index('ix_sim_a_score', 'track_a_id', 'score'),
        db.Index('ix_sim_b_score', 'track_b_id', 'score'),
    )


class UserSimilarity(db.Model):
    __tablename__ = 'user_similarity'
    user_a_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), primary_key=True)
    user_b_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), primary_key=True)
    score = db.Column(db.Float, nullable=False, default=0.0)
    updated_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    __table_args__ = (
        db.Index('ix_usim_a_score', 'user_a_id', 'score'),
        db.Index('ix_usim_b_score', 'user_b_id', 'score'),
    )


class RefreshToken(db.Model):
    __tablename__ = 'refresh_token'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False, index=True)
    token_hash = db.Column(db.String(128), unique=True, nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    revoked = db.Column(db.Boolean, default=False, nullable=False)


class OAuthAccount(db.Model):
    __tablename__ = 'oauth_account'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False, index=True)
    provider = db.Column(db.String(32), nullable=False)
    provider_user_id = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    __table_args__ = (
        db.UniqueConstraint('provider', 'provider_user_id', name='_oauth_provider_uid_uc'),
    )


class Webhook(db.Model):
    __tablename__ = 'webhook'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False, index=True)
    url = db.Column(db.String(500), nullable=False)
    secret = db.Column(db.String(128), nullable=False)
    event_types = db.Column(db.String(200), default='listen,upload', nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)