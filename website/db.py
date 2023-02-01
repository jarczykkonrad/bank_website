import decimal

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy import or_
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)  # main.get_app()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
db = SQLAlchemy(app)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(100), unique=False, nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username

    def set_password(self, password):
        # Create hashed password
        self.password = generate_password_hash(
            password,
            method='sha256'
        )

    def check_password(self, password):
        # return check_password_hash(self.password, password)
        if self.password == password:
            return True

    def get_money(self):
        return get_money_from_user(self.username)


class Transaction(db.Model):
    transaction_id = db.Column(db.Integer, primary_key=True)
    # Out Id & Money can be null because we might put in (or take out) money through an ATM
    from_user_id = db.Column(db.Integer, nullable=True)  # TODO ForeignKey?
    out_money = db.Column(db.String(40), nullable=True)
    to_user_id = db.Column(db.Integer)  # TODO ForeignKey?
    in_money = db.Column(db.String(40))
    message = db.Column(db.String(120))

    # TimeStamp?

    def contains_user(self, username):
        return username != "" and (self.from_user_id == username or self.to_user_id == username)

    def get_out_money_decimal(self):
        return decimal.Decimal(self.out_money)

    def get_in_money_decimal(self):
        return decimal.Decimal(self.in_money)

    def __eq__(self, other):
        return self.transaction_id == other.transaction_id

class AddMoney(db.Model):
    add_money_id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Integer, nullable=False)
    cardholder = db.Column(db.String(40), nullable=False)
    cardnumber = db.Column(db.Integer, nullable=False)

    def get_amount(self):
        return decimal.Decimal(self.amount)

def get_money_from_user(username):
    money = 0
    user = User.query.filter_by(username=username).first()
    if not user:
        print(f"Couldn't find user with username {username}")
        return money

    # transactions = Transaction.query.filter(Transaction.contains_user(username=username)).all()
    queryTest = Transaction.query.filter(or_(Transaction.from_user_id == username, Transaction.to_user_id == username))
    for transaction in queryTest:
        # If from_user_id; substract money
        if transaction.from_user_id == username:
            money -= transaction.get_out_money_decimal()
        # If to_user_id; add money
        elif transaction.to_user_id == username:
            money += transaction.get_in_money_decimal()

    amounts = AddMoney.query
    for each_topup in amounts:
       money += each_topup.get_amount()

    return money


def init_db():
    db.create_all()
