from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Store, Ornament, User
# Import Login session
from flask import session as login_session
import random
import string
# imports for gconnect
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
# import login decorator
from functools import wraps
from flask import Flask, render_template
from flask import request, redirect, jsonify, url_for, flash
app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json',
                            'r').read())['web']['client_id']
APPLICATION_NAME = "itemcatalog"

engine = create_engine('sqlite:///store.db')
Base.metadata.bind = engine


DBSession = sessionmaker(bind=engine)
session = DBSession()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_name' in login_session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
@app.route('/login')
def showlogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application-json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # upgrade the authorization code in credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps('Failed to upgrade\
                                            the authorization code'), 401)
        response.headers['Content-Type'] = 'application-json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1].decode("utf-8"))
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response
    # Access token within the app
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user\
                                            is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.

    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id
    response = make_response(json.dumps('Succesfully connected users'), 200)

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # See if user exists or if it doesn't make a new one
    print('User email is' + str(login_session['email']))
    user_id = getUserID(login_session['email'])
    if user_id:
        print('Existing user#' + str(user_id) + 'matches this email')
    else:
        user_id = createUser(login_session)
        print('New user_id#' + str(user_id) + 'created')
        login_session['user_id'] = user_id
        print('Login session is tied to :id#' + str(login_session['user_id']))

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 200px; height: 200px;border-radius:100px;- \
      webkit-border-radius:100px;-moz-border-radius: 100px;">'
    flash("you are now logged in as %s" % login_session['username'])
    print("done!")
    return output

# Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).first()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).first()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).first()
        return user.id
    except:
        return None


# DISCONNECT - Revoke a current user's token and reset their login_session.
@app.route('/gdisconnect')
def gdisconnect():
    # only disconnect a connected User
    access_token = login_session.get('access_token')
    print('In gdisconnect access token is %s', access_token)
    print('User name is: ')
    print(login_session['username'])
    if access_token is None:
        print('Access Token is None')
        response = make_response(json.dumps('Current user not connected'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.c\
           om/o/oauth2/revoke?token = %s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print('result is')
    print(result)
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke\
                                            token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/logout')
def logout():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
            del login_session['username']
            del login_session['email']
            del login_session['picture']
            del login_session['user_id']
            del login_session['provider']
            flash("you have succesfully been logout")
            return redirect(url_for('showStores'))
    else:
        flash("you were not logged in")
        return redirect(url_for('showStores'))


@app.route('/store/<int:store_id>/ornament/JSON')
def storeOrnamentJSON(brand_id):
    store = session.query(Store).filter_by(id=store_id).one()
    details = session.query(Ornament).filter_by(
        store_id=store_id).all()
    return jsonify(Ornament=[i.serialize for i in details])


@app.route('/store/<int:store_id>/details/<int:details_id>/JSON')
def ornamentsJSON(store_id, details_id):
    Ornament_Details = session.query(Ornament).filter_by(id=details_id).one()
    return jsonify(Ornament_Details=Ornament_Details.serialize)


@app.route('/store/JSON')
def storesJSON():
    stores = session.query(Store).all()
    return jsonify(stores=[r.serialize for r in stores])
# Show all stores


@app.route('/')
@app.route('/store/')
def showStores():
    session1 = DBSession()
    stores = session1.query(Store).all()
    # return "This page will show all my stores"
    session1.close()
    return render_template('stores.html', stores=stores)


# Create a new store
@app.route('/store/new/', methods=['GET', 'POST'])
def newStore():
    session2 = DBSession()
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newStore = Store(name=request.form['name'])
        session2.add(newStore)
        session2.commit()
        session2.close()
        return redirect(url_for('showStores'))
    else:
        session2.close()
        return render_template('newStore.html')
    # return "This page will be for making a new store"

# Edit a store


@app.route('/store/<int:store_id>/edit/', methods=['GET', 'POST'])
def editStore(store_id):
    session3 = DBSession()
    editStore = session3.query(Store).filter_by(id=store_id).one()
    if 'username' not in login_session:
        return redirect('/login')
        if editStore.user_id != login_session['user_id']:
            if editStore.user_id != login_session['user_id']:
                return "<script>function myFunction() {alert('You \
            are not authorized to edit this Store.\
            Please create your own entry in order \
            to edit/delete.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        if request.form['name']:
            print(editStore.name)
            editStore.name = request.form['name']
            session3.add(editStore)
            session3.commit()
            session3.close()
            return redirect(url_for('showStores'))
    else:
        session3.close()
        return render_template(
            'editStore.html', store=editStore)

    # return 'This page will be for editing store %s' % store_id

# Delete a store


@app.route('/store/<int:store_id>/delete/', methods=['GET', 'POST'])
def deleteStore(store_id):
    session4 = DBSession()
    deleteStore = session4.query(
        Store).filter_by(id=store_id).one()
    if 'username' not in login_session:
        return redirect('/login')
        if deleteStore.user_id != login_session['user_id']:
            if deleteStore.user_id != login_session['user_id']:
                return "<script>function myFunction() {alert('You \
                sare not authorized to delete this Store.\
                Please create your own entry in order \
                to edit/delete.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        session4.delete(deleteStore)
        session4.commit()
        session4.close()
        return redirect(
            url_for('showStores', store_id=store_id))
    else:
        session4.close()
        return render_template(
            'deleteStore.html', store=deleteStore)
    # return 'This page will be for deleting store %s' % store_id


# Show a store ornament
@app.route('/store/<int:store_id>/')
@app.route('/store/<int:store_id>/ornament/')
def showOrnament(store_id):
    session5 = DBSession()
    store = session5.query(Store).filter_by(id=store_id).one()
    details = session5.query(Ornament).filter_by(store_id=store_id).all()
    session5.close()
    for d in details:
        print(d.name)
    return render_template('ornament.html', details=details, store=store)
    # return 'This page is the product for store %s' % store_id

# Create a new ornament details


@app.route(
    '/store/<int:store_id>/ornament/new/', methods=['GET', 'POST'])
def newOrnament(store_id):
    session6 = DBSession()
    if 'username' not in login_session:
        return redirect('/login')
    store = session6.query(Store).filter_by(id=store_id).one()
    if login_session['user_id'] != store.user_id:
        if deleteStore.user_id != login_session['user_id']:
            return "<script>function myFunction() {alert('You \
            are not authorized to delete this Store.\
            Please create your own entry in order \
            to edit/delete.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        newOrnament = Ornament(name=request.form['name'],
                             description=request.form[
                             'description'], price=request.form['price'],
                             ornamenttype=request.form['ornamenttype'],
                             store_id=store_id)
        session6.add(newOrnament)
        session6.commit()
        session6.close()

        return redirect(url_for('showOrnament', store_id=store_id))
    else:
        session6.close()
        return render_template('newOrnament.html', store_id=store_id)

    return render_template('newOrnament.html', store=store)
    # return 'This page is for making a new ornament details for store %s'
    # %store_id

# Edit a ornament details


@app.route('/store/<int:store_id>/ornament/<int:ornament_id>/edit',
           methods=['GET', 'POST'])
def editOrnament(store_id, ornament_id):
    session7 = DBSession()
    if 'username' not in login_session:
        return redirect('/login')
    editOrnament = session7.query(Ornament).filter_by(id=ornament_id).one()
    store = session7.query(Store).filter_by(id=store_id).one()
    if login_session['user_id'] != store.user_id:
        if deleteStore.user_id != login_session['user_id']:
            return "<script>function myFunction() {alert('You \
            are not authorized to edit this Store.\
            Please create your own entry in order \
            to edit/delete.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        if request.form['name']:
            editOrnament.name = request.form['name']
        if request.form['description']:
            editOrnament.description = request.form['name']
        if request.form['price']:
            editOrnament.price = request.form['price']
        if request.form['ornamenttype']:
            editOrnament.ornamenttype = request.form['ornamenttype']
        session7.add(editOrnament)
        session7.commit()
        session7.close()
        return redirect(url_for('showOrnament', store_id=store_id))
    else:
        session7.close()

        return render_template('editOrnament.html', store_id=store_id,
                               ornament_id=ornament_id, details=editOrnament)

    # return 'This page is for editing ornament details %s' % ornament_id

# Delete a ornament details


@app.route('/store/<int:store_id>/ornament/<int:ornament_id>/delete',
           methods=['GET', 'POST'])
def deleteOrnament(store_id, ornament_id):
    session8 = DBSession()
    if 'username' not in login_session:
        return redirect('/login')
    editOrnament = session8.query(Ornament).filter_by(id=ornament_id).one()
    store = session8.query(Store).filter_by(id=store_id).one()
    deleteOrnament = session8.query(Ornament).filter_by(id=ornament_id).one()
    if login_session['user_id'] != store.user_id:
        if deleteStore.user_id != login_session['user_id']:
            return "<script>function myFunction() {alert('You \
            are not authorized to delete this Store.\
            Please create your own entry in order \
            to edit/delete.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        session8.delete(deleteOrnament)
        session8.commit()
        session8.close()
        return redirect(url_for('showOrnament', store_id=store_id))
    else:
        session8.close()
        return render_template('deleteOrnament.html', details=deleteOrnament)
    # return "This page is for deleting Ornament details %s" % ornament_id


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
