from authlib.oauth2 import OAuth2Error
from flask import Blueprint, request, session, url_for
from flask import render_template, redirect

from .models import User
from .oauth2 import authorization

bp = Blueprint('home', __name__)


def current_user():
    if 'id' in session:
        uid = session['id']
        return User.query.get(uid)
    return None


def split_by_crlf(s):
    return [v for v in s.splitlines() if v]


@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['id'] = user.id

            # if user is not just to log in, but need to head back to the auth page, then go for it
            next_page = request.args.get('next')

            if next_page:
                return redirect(next_page)
            return redirect('/')

    return render_template('login.html')


@bp.route('/logout')
def logout():
    del session['id']
    return redirect('/')


@bp.route('/oauth/authorize', methods=['GET', 'POST'])
def authorize():
    user = current_user()

    # if user log status is not true (Auth server), then to log it in
    if not user:
        return redirect(url_for('home.login', next=request.url))

    if request.method == 'GET':
        try:
            grant = authorization.get_consent_grant(end_user=user)
        except OAuth2Error as error:
            return error.error
        return render_template('authorize.html', user=user, grant=grant)

    if request.form['confirm']:
        grant_user = user
    else:
        grant_user = None

    return authorization.create_authorization_response(grant_user=grant_user)


@bp.route('/oauth/token', methods=['POST'])
def issue_token():
    return authorization.create_token_response()


@bp.route('/oauth/revoke', methods=['POST'])
def revoke_token():
    return authorization.create_endpoint_response('revocation')
