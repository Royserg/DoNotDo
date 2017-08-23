from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from sqlalchemy.sql import func, label

import forms
# import models

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.secret_key = "ThisIsASecret1"
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


DEBUG = True


# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(80))
    expenses = db.relationship('Expense', backref='owner', lazy='dynamic')
    
    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = password

    def __repr__(self):
        return '<User %r>' % self.username

    
# Model Expenses
class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cost = db.Column(db.Float)
    description = db.Column(db.String(80))
    date = db.Column(db.DateTime)
    is_paid = db.Column(db.Boolean)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    def __init__(self, cost, description, owner_id, date=None, is_paid=None):
        self.cost = cost
        self.description = description
        if date is None:
            date = datetime.datetime.today()
        self.date = date
        self.owner_id = owner_id
        self.is_paid = is_paid
    

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))


# Index Route
@app.route('/', methods=['GET', 'POST'])
def index():
	form = forms.NotDoForm()
	if form.validate_on_submit():
		return "Added"

	return render_template('index.html', form=form)


# Dashboard Route
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
	return render_template('dashboard.html', name=current_user.username)


# Expenses Route
@app.route('/expenses', methods=['GET', 'POST'])
@login_required
def expenses():
    form = forms.ExpenseForm()
    expenses = Expense.query.filter_by(owner_id = current_user.id).all()
    expenses_sum = db.session.query(Expense,
                    func.sum(Expense.cost).label("total")).filter_by(owner_id = current_user.id).first()
                                    
    
    if form.validate_on_submit():
        new_expense = Expense(
            cost = form.cost.data,
            description = form.description.data,
            date = form.date.data,
            is_paid = form.is_paid.data,
            owner_id = current_user.id
        )
        db.session.add(new_expense)
        db.session.commit()
        flash('Expense Added', 'success')
        return redirect(url_for('expenses'))
    return render_template('expenses.html', form=form, expenses=expenses, expenses_sum=expenses_sum)



# Sign Up Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
	form = forms.SignUpForm()
	if form.validate_on_submit():
		hashed_password = generate_password_hash(form.password.data, method='sha256')
		new_user = User(
				username = form.username.data,
				email = form.email.data,
				password = hashed_password
			)
		db.session.add(new_user)
		db.session.commit()

		flash("You've successfully Signed Up", 'success')
		return redirect(url_for("login"))
	return render_template('signup.html', form=form)


# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
	form = forms.LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(username=form.username.data).first()
		if user:
			if check_password_hash(user.password ,form.password.data):
				flash("You've logged in", "success")
				login_user(user, remember=form.remember.data)
				return redirect(url_for('dashboard'))

		flash('Invalid Username or Password', 'danger')
		return redirect(url_for('login'))

	return render_template('login.html', form=form)


# Logout Route
@app.route('/logout', methods=['GET','POST'])
@login_required
def logout():
	logout_user()
	flash("You've been successfully logged out", 'success')
	return redirect(url_for("index"))



if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)