from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import uuid
import json

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(256), nullable=True)  # Nullable for OAuth users
    google_id = db.Column(db.String(100), unique=True, nullable=True, index=True)  # Google OAuth ID
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    studies = db.relationship('Study', backref='owner', lazy='dynamic', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<User {self.email}>'

    @property
    def has_password(self):
        """Check if user has a password set (not OAuth-only user)."""
        return self.password_hash is not None


class Study(db.Model):
    __tablename__ = 'studies'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, default='')
    question_text = db.Column(db.String(500), default='Choose the Best and Worst from the following items')
    best_label = db.Column(db.String(50), default='Best')
    worst_label = db.Column(db.String(50), default='Worst')
    items_per_set = db.Column(db.Integer, default=4)
    sets_per_respondent = db.Column(db.Integer, default=10)
    status = db.Column(db.String(20), default='DRAFT')  # DRAFT, ACTIVE, CLOSED
    share_token = db.Column(db.String(32), unique=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    items = db.relationship('Item', backref='study', lazy='dynamic', cascade='all, delete-orphan', order_by='Item.order')
    responses = db.relationship('Response', backref='study', lazy='dynamic', cascade='all, delete-orphan')

    def __init__(self, **kwargs):
        super(Study, self).__init__(**kwargs)
        if not self.share_token:
            self.share_token = uuid.uuid4().hex

    def __repr__(self):
        return f'<Study {self.name}>'

    @property
    def item_count(self):
        return self.items.count()

    @property
    def response_count(self):
        """Count of non-preview responses."""
        return self.responses.filter_by(is_preview=False).count()

    @property
    def completed_response_count(self):
        """Count of completed non-preview responses."""
        return self.responses.filter_by(is_preview=False).filter(Response.completed_at != None).count()

    def can_publish(self):
        return self.item_count >= 5 and self.status == 'DRAFT'

    def is_accepting_responses(self):
        """Check if study is currently accepting new responses."""
        return self.status == 'ACTIVE'


class Item(db.Model):
    __tablename__ = 'items'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)  # Required: short item name
    description = db.Column(db.Text, nullable=True)   # Optional: longer description
    order = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    study_id = db.Column(db.Integer, db.ForeignKey('studies.id'), nullable=False)

    def __repr__(self):
        return f'<Item {self.name[:30]}>'

    @property
    def display_text(self):
        """Return name with description if available."""
        if self.description:
            return f"{self.name}: {self.description}"
        return self.name


class Response(db.Model):
    __tablename__ = 'responses'

    id = db.Column(db.Integer, primary_key=True)
    respondent_id = db.Column(db.String(36), nullable=False, index=True)  # UUID for anonymous tracking
    is_preview = db.Column(db.Boolean, default=False)  # True if this is a preview response
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)

    study_id = db.Column(db.Integer, db.ForeignKey('studies.id'), nullable=False)

    answers = db.relationship('Answer', backref='response', lazy='dynamic', cascade='all, delete-orphan', order_by='Answer.set_index')

    def __init__(self, **kwargs):
        super(Response, self).__init__(**kwargs)
        if not self.respondent_id:
            self.respondent_id = str(uuid.uuid4())

    def __repr__(self):
        return f'<Response {self.respondent_id[:8]}>'

    @property
    def is_complete(self):
        return self.completed_at is not None


class Answer(db.Model):
    __tablename__ = 'answers'

    id = db.Column(db.Integer, primary_key=True)
    set_index = db.Column(db.Integer, nullable=False)
    item_ids_json = db.Column(db.Text, nullable=False)  # JSON array of item IDs shown
    best_item_id = db.Column(db.Integer, db.ForeignKey('items.id'), nullable=False)
    worst_item_id = db.Column(db.Integer, db.ForeignKey('items.id'), nullable=False)
    answered_at = db.Column(db.DateTime, default=datetime.utcnow)

    response_id = db.Column(db.Integer, db.ForeignKey('responses.id'), nullable=False)

    best_item = db.relationship('Item', foreign_keys=[best_item_id])
    worst_item = db.relationship('Item', foreign_keys=[worst_item_id])

    @property
    def item_ids(self):
        return json.loads(self.item_ids_json)

    @item_ids.setter
    def item_ids(self, value):
        self.item_ids_json = json.dumps(value)

    def __repr__(self):
        return f'<Answer set={self.set_index}>'
