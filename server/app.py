#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash

from config import app, db, api
from models import User, Recipe


class Signup(Resource):
    def post(self):
        '''Create a new user account.'''
        data = request.get_json()
        user = User(
            username=data['username'],
            password_hash=generate_password_hash(data['password']),
            bio=data['bio'],
            image_url=data['image_url']
        )
        try:
            db.session.add(user)
            db.session.commit()
            return {'id': user.id}, 201
        except IntegrityError:
            return {'message': 'Username already taken'}, 400



class CheckSession(Resource):
    def get(self):
        '''Check if the user is logged in (i.e., has an active session).'''
        if 'user_id' not in session:
            return {'message': 'Unauthorized'}, 401

        user = User.query.get(session['user_id'])
        return jsonify({
            'id': user.id,
            'username': user.username,
            'bio': user.bio,
            'image_url': user.image_url
        })


class Login(Resource):
    def post(self):
        '''Login the user.'''
        data = request.get_json()
        
        # Find user by username
        user = User.query.filter_by(username=data['username']).first()
        
        if user and check_password_hash(user.password_hash, data['password']):
            session['user_id'] = user.id
            return {'username': user.username}, 200
        return {'message': 'Invalid credentials'}, 401


class Logout(Resource):
    def delete(self):
        '''Logout the user.'''
        session.pop('user_id', None)
        return {'message': 'Logged out successfully'}, 200


class RecipeIndex(Resource):
    def get(self):
        '''Get all recipes associated with the logged-in user.'''
        if 'user_id' not in session:
            return {'message': 'Unauthorized'}, 401

        user = User.query.get(session['user_id'])
        recipes = Recipe.query.filter_by(user_id=user.id).all()

        recipes_list = [
            {'title': recipe.title, 'instructions': recipe.instructions, 'minutes_to_complete': recipe.minutes_to_complete}
            for recipe in recipes
        ]
        return jsonify(recipes_list)

    def post(self):
        '''Create a new recipe.'''
        if 'user_id' not in session:
            return {'message': 'Unauthorized'}, 401
        
        data = request.get_json()
        
        if not data.get('title') or not data.get('instructions') or not data.get('minutes_to_complete'):
            return {'message': 'Title, instructions, and minutes to complete are required'}, 422

        user = User.query.get(session['user_id'])
        new_recipe = Recipe(
            title=data['title'],
            instructions=data['instructions'],
            minutes_to_complete=data['minutes_to_complete'],
            user_id=user.id
        )
        db.session.add(new_recipe)
        db.session.commit()

        return {'title': new_recipe.title, 'instructions': new_recipe.instructions, 'minutes_to_complete': new_recipe.minutes_to_complete}, 201


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
