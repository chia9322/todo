from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy

from flask_bootstrap import Bootstrap

from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship

from forms import TaskForm, RegisterForm, LoginForm

import os

app = Flask(__name__)
bootstrap = Bootstrap(app)


# Connect to Database
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL?sslmode=require", "sqlite:///todo.db")
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Task DB
class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    category = db.Column(db.String(250), nullable=True)
    done = db.Column(db.Boolean, nullable=False)

    # Relationship with User
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = relationship('User', back_populates='tasks')

#
# User DB
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

    # Relationship with Task
    tasks = relationship("Task", back_populates='user')

# db.create_all()


# LOGIN
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
  return User.query.get(int(user_id))




@app.route('/')
def home():
    if current_user.is_active:
        return redirect(url_for('task_list', status='todo'))
    else:
        return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # Check if email has already been used
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            flash("You've already signed up with this email. Please log in.")
            return redirect(url_for('login'))
        else:
            hash_and_salted_password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
            new_user = User(
                email=form.email.data,
                password=hash_and_salted_password,
                name=form.name.data
            )
        db.session.add(new_user)
        db.session.commit()
        # Login User
        login_user(new_user)
        return redirect(url_for('home'))
    return render_template('register.html', form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        # Email is not exist
        if not user:
            print("no gegister")
            flash("This email hasn't been registered.")
            return redirect(url_for('login'))
        else:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('home'))
            # Password Incorrect
            else:
                flash("Incorrect password. Please try again.")
                return redirect(url_for('login'))
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/tasks/<string:status>', methods=('GET', 'POST'))
def task_list(status):
    to_do_tasks = Task.query.filter_by(user=current_user, done=False)
    done_tasks = Task.query.filter_by(user=current_user, done=True)
    form = TaskForm()
    if form.validate_on_submit():
        new_task = Task(
            name=form.name.data,
            done=False,
            user=current_user
        )
        print(current_user)
        db.session.add(new_task)
        db.session.commit()
        return redirect(url_for('task_list', status='todo'))
    return render_template('tasks.html', to_do_tasks=to_do_tasks, done_tasks=done_tasks, status=status, form=form)

@app.route('/check/<int:task_id>/')
def check(task_id):
    status = request.args.get('status')
    task_to_update = Task.query.get(task_id)
    task_to_update.done = not task_to_update.done
    db.session.commit()
    return redirect(url_for('task_list', status=status))

@app.route("/delete")
def delete():
    task_id = request.args.get('id')
    status = request.args.get('status')
    task_to_delete = Task.query.get(task_id)
    db.session.delete(task_to_delete)
    db.session.commit()
    return redirect(url_for('task_list', status=status))

if __name__ == '__main__':
    app.run(debug=True)
