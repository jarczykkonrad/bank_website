from os import error
import re
import flask
import datetime
import flask_login
from flask import session
from flask import current_app
from flask import Blueprint, render_template, request, flash, redirect
from flask.helpers import url_for
from sqlalchemy import literal
from website.db import User, init_db, db, Transaction, AddMoney
from flask_wtf.recaptcha.validators import Recaptcha
from website.forms import RegisterForm, LoginForm, TransactionForm, AddMoneyForm
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import math
import os
from . import login_manager
from flask_login import login_required, logout_user, current_user, login_user

auth = Blueprint('auth', __name__)


#Timeout user when inactive in 5 min
@auth.before_request
def before_request():
    flask.session.permanent = True
    current_app.permanent_session_lifetime = datetime.timedelta(minutes=5)
    flask.session.modified = True
    flask.g.user = flask_login.current_user


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if current_user.is_authenticated:
        flash("You are already logged in")
        return redirect(url_for('auth.home_login'))
    form = RegisterForm()
    if form.validate_on_submit():
        init_db()

        # Correct input, now check database
        success = True
        user_by_username = User.query.filter_by(username = form.username.data).first()
        user_by_email = User.query.filter_by(email = form.email.data).first()
        if user_by_username:
            flash("Username taken!", category='error')
            success = False
        if user_by_email:
            flash("Email taken!", category='error')
            success = False
        if success:
            userName = form.username.data
            email = form.email.data
            password1 = form.password1.data
            hashedPassword = generate_password_hash(password1, method="sha256")
            password2 = form.password2.data  # Prob redundant, unless we don't validate password in "form.validate_on_submit"
            user = User(username=userName, email=email, password=hashedPassword)
            db.session.add(user)
            db.session.commit()
            flash('Account Created', category='success')
            session['user'] = email
            session.permanent = True

            ##### Print statements to test values in database, comment away if not needed#########
            #print("Username: ", User.query.filter_by(username=form.username.data).first().username)
            #print("Email: ", User.query.filter_by(username=form.username.data).first().email)
            #print("Password: ", User.query.filter_by(username=form.username.data).first().password)
            ######################################################################################

            return redirect(url_for('auth.two_factor_view', email=email))
    return render_template('signup.html', form=form)


@auth.route('/homelogin', methods=['GET', 'POST'])
@login_required
def home_login():
    queried_from_user = User.query.filter_by(username=current_user.username).first()
    amount_in_database: int = queried_from_user.get_money()
    return render_template('homelogin.html', current_user=current_user.username, saldo = amount_in_database)

@auth.route('/add_money', methods=['GET', 'POST'])
@login_required
def add_money():
    form = AddMoneyForm()
    if form.validate_on_submit():
        init_db()
        amount = form.amount.data
        cardholder = form.cardholder.data
        cardnumber = form.cardnumber.data
        succes = True

        if cardnumber != math.nan:
            succes = False
            flash('Invalid cardnumber. Must contain only digits', category='error')

        if amount<1 or amount>200000:
            succes = False
            flash('Amount needs to be between 1 and 200 000', category='error')

        if succes == True:
            new_topup = AddMoney(amount=amount, cardholder=cardholder, cardnumber=cardnumber)
            db.session.add(new_topup)
            db.session.commit()
            return redirect(url_for('auth.home_login'))


    return render_template('add_money.html', form=form)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash("You are already logged in")
        return redirect(url_for('auth.home_login'))
    form = LoginForm()
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(email=form.email.data).first()
            if user is not None and check_password_hash(user.password, form.password.data):
                login_user(user)
                session['logged_in']=True
                return redirect(url_for('auth.home_login'))
            flash("Email or password does not match!", category="error")
        except:
            flash("Something went wrong. Please try again", category="error")
    return render_template('login.html', form=form)


@auth.route('/two_factor_setup', methods=['GET'])
def two_factor_view():
    try:
        email = request.args['email']
    except KeyError:
        flash("You don't have access to this page", category='error')
        return redirect(url_for('auth.sign_up'))
    secret = pyotp.random_base32()
    intizalize = pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name='BankDat250')
    session['secret'] = secret
    return render_template('two-factor-setup.html', qr_link = intizalize )

@auth.route('/transaction', methods=['GET', 'POST'])
@login_required
def transaction():
    form = TransactionForm()
    if form.validate_on_submit():
        amount = form.amount.data
        from_user_name = form.from_user_name.data
        to_user_name = form.to_user_name.data
        message = form.message.data

        ATM_transaction = False # TODO, if an ATM Transaction, then we dont need & shouldnt have both from & to
        success = True

        # Check if money amount is legal (between 1-200000)
        if amount < 1 or amount > 200000:
            success = False
            flash("Money amount has to be a value between 1 and 200'000", category="error")
            #return render_template('transaction.html', form=form)

        # From ID and To ID exist
        queried_from_user = User.query.filter_by(username = from_user_name).first()
        queried_to_user = User.query.filter_by(username=to_user_name).first()
        if not queried_from_user:
            success = False
            flash(f"User with username {from_user_name} doesn't exist", category="error")
            #return render_template('transaction.html', form=form)
        if not queried_to_user:
            success = False
            flash(f"User with username {to_user_name} doesn't exist", category="error")
            #return render_template('transaction.html', form=form)

        # Trying to send money to himself
        if queried_from_user and current_user.username == queried_to_user.username:
            success = False
            flash("Can't send money to yourself", category="error")

        # TODO Finish has enough money
        amount_in_database:int = queried_from_user.get_money()

        flash("Money " + str(amount_in_database))
        if amount >= amount_in_database:
            success = False
            flash(f"Not enough money to send you have {amount_in_database} and you tried to send {amount}")

        # Is logged in on "from ID"
        if queried_from_user and queried_to_user and \
                (current_user.id != queried_from_user.id or current_user.username != queried_from_user.username):
            success = False
            flash("Can't transfer money from an account you don't own", category="error")

        if not success:
            flash("Unsuccessful transaction", category="error")
            return render_template('transaction.html', form=form)

        # TODO If everything is correct, register a transaction, and add it to the database
        #  Update (calculate) saldo if it's on the screen
        new_transaction = Transaction(out_money=amount, from_user_id=from_user_name, to_user_id=to_user_name, message=message)
        db.session.add(new_transaction)
        db.session.commit()

        return redirect(url_for('views.home'))

    return render_template('transaction.html', form=form)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    session['logged_in']=False
    return redirect(url_for('auth.login'))

### Don't think this is necessary for our soloution with login users
"""
@login_manager.user_loader
def load_user(user_id):
    # Check if user is logged-in on every page load - didn't work with it yet
    if user_id is not None:
        return User.query.get(user_id)
    return None
"""
