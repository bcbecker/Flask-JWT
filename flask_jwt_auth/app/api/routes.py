import uuid
from flask import request, jsonify, make_response, Blueprint
from flask_jwt_extended import (
        create_access_token, get_jwt_identity, jwt_required,
        set_access_cookies, unset_jwt_cookies
        )
from . import db, bcrypt
from .models import User


auth = Blueprint('auth', __name__)

  
@auth.route('/signup', methods =['POST'])
def signup():
    """
    Recieves form input and creates user, if it doesn't exist
    """
    # creates a dictionary of the form data
    data = request.form
    name, email = data.get('name'), data.get('email')
    password = data.get('password')
  
    # checking for existing user
    user = User.query.filter_by(email = email).first()

    if not user:
        user = User(
            public_id = str(uuid.uuid4()),
            name = name,
            email = email,
            password = bcrypt.generate_password_hash(password),
            active_jwt = None
        )
        
        db.session.add(user)
        db.session.commit()

        return make_response('Successfully registered.', 201)
    else:
        # returns 202 if user already exists
        return make_response('User already exists. Please Log in.', 202)


@auth.route('/login', methods =['POST'])
def login():
    """
    Verifies credentials and creates JWT, if valid user
    """
    # creates dictionary of form data
    auth = request.form
  
    if not auth or not auth.get('email') or not auth.get('password'):
        # returns 401 if any email and/or password is missing
        return make_response('Could not verify', 401)
  
    user = User.query.filter_by(email = auth.get('email')).first()
  
    if not user:
        # returns 401 if user does not exist
        return make_response('Could not verify', 401)
  
    if bcrypt.check_password_hash(user.password, auth.get('password')):
        # generates the JWT, sets in db
        token = create_access_token(identity=user.email) # should be public_id
        user.active_jwt = token
        db.session.commit()

        return make_response(jsonify({'token' : token}), 201)

    # returns 403 if password is wrong
    return make_response('Could not verify', 403)


@auth.route('/user', methods =['GET'])
@jwt_required()
def get_all_users():
    """
    Requires JWT auth to query list of all users
    """
    users = User.query.all()
    output = []

    for user in users:
        output.append({
            'public_id': user.public_id,
            'name' : user.name,
            'email' : user.email
        })
  
    return jsonify({'users': output})


@auth.route('/whoami', methods=['GET'])
@jwt_required()
def whoami():
    """
    Requires JWT auth and returns user's identity based on token
    """
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return make_response(jsonify({'logged_in_as' : current_user}), 200)


@auth.route('/login_with_cookie', methods=['POST'])
def login_with_cookie():
    """
    Mock login using JWT cookie instead of header
    """
    # creates dictionary of form data
    auth = request.form
  
    if not auth or not auth.get('email') or not auth.get('password'):
        # returns 401 if any email and/or password is missing
        return make_response('Could not verify', 401)
  
    user = User.query.filter_by(email = auth.get('email')).first()
  
    if not user:
        # returns 401 if user does not exist
        return make_response('Could not verify', 401)
  
    if bcrypt.check_password_hash(user.password, auth.get('password')):
        # generates the JWT, sets in db
        token = create_access_token(identity=user.email)
        user.active_jwt = token
        db.session.commit()

        response = jsonify({'user': user.email, 'msg': 'login successful'})
        set_access_cookies(response, token)
        return response

    # returns 403 if password is wrong
    return make_response('Could not verify', 403)


@auth.route('/logout_with_cookie', methods=['POST'])
@jwt_required(locations=['cookies'])
def logout_with_cookie():
    """
    Mock logout using JWT cookie unset
    """
    #regen public_id for user
    current_user = get_jwt_identity()
    user = User.query.filter_by(email = current_user).first()
    user.public_id = str(uuid.uuid4())
    user.active_jwt = None
    db.session.commit()
    
    #unset JWT cookie
    response = jsonify({'user': user.email, 'msg': 'logout successful'})
    unset_jwt_cookies(response)

    return response