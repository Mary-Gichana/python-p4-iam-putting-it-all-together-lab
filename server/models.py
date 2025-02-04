from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)
    _password_hash = db.Column(db.String, nullable=False)
    image_url = db.Column(db.String, nullable=False, default='default.jpg')
    bio = db.Column(db.String)

    # Relationship with Recipe model
    recipes = db.relationship('Recipe', back_populates='user', cascade='all, delete-orphan')

    @property
    def password_hash(self):
        raise AttributeError("Password hash is not accessible.")
    
    @password_hash.setter
    def password_hash(self, password):
        if not password:
            raise ValueError("Password cannot be empty.")
        self._password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self._password_hash, password)

    @validates('username')
    def validate_username(self, key, value):
        if not value or value.strip() == "":
            raise ValueError("Username cannot be empty.")
        if User.query.filter_by(username=value).first():
            raise ValueError("Username must be unique.")
        return value

    def __repr__(self):
        return f"<User id={self.id} username={self.username}>"

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer, nullable=False)

    # Relationship with the User model
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('User', back_populates='recipes')

    @validates('title')
    def validate_title(self, key, value):
        if not value or value.strip() == "":
            raise ValueError("Title cannot be empty.")
        return value

    @validates('instructions')
    def validate_instructions(self, key, value):
        if len(value) < 50:
            raise ValueError("Instructions must be at least 50 characters long.")
        return value

    @validates('minutes_to_complete')
    def validate_minutes_to_complete(self, key, value):
        if value <= 0:
            raise ValueError("Minutes to complete must be a positive integer.")
        return value

    def __repr__(self):
        return f"<Recipe id={self.id} title={self.title}>"
