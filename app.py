from flask import Flask, render_template, request, flash, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import pyad
from pyad import *
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev')

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# Configure PyAD
pyad.set_defaults(ldap_server=os.getenv('LDAP_SERVER', 'localhost'),
                 username=os.getenv('LDAP_USERNAME'),
                 password=os.getenv('LDAP_PASSWORD'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        try:
            # Verify credentials against AD
            user = pyad.aduser.ADUser.from_cn(username)
            if user.verify_password(password):
                login_user(User(username))
                return redirect(url_for('index'))
            else:
                flash('Invalid credentials')
        except:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/users')
@login_required
def users():
    users = pyad.aduser.ADUser.get_all()
    return render_template('users.html', users=users)

@app.route('/user/add', methods=['GET', 'POST'])
@login_required
def add_user():
    if request.method == 'POST':
        try:
            # Create new AD user
            user = pyad.aduser.ADUser.create(
                request.form['username'],
                container_object=pyad.adcontainer.ADContainer.from_dn(request.form['ou']),
                password=request.form['password'],
                optional_attributes={
                    'givenName': request.form['firstname'],
                    'sn': request.form['lastname'],
                    'mail': request.form['email']
                }
            )
            flash('User created successfully')
            return redirect(url_for('users'))
        except Exception as e:
            flash(f'Error creating user: {str(e)}')
    
    # Get all OUs for the form
    ous = pyad.adcontainer.ADContainer.get_all()
    return render_template('add_user.html', ous=ous)

@app.route('/groups')
@login_required
def groups():
    groups = pyad.adgroup.ADGroup.get_all()
    return render_template('groups.html', groups=groups)

@app.route('/group/add', methods=['GET', 'POST'])
@login_required
def add_group():
    if request.method == 'POST':
        try:
            group = pyad.adgroup.ADGroup.create(
                request.form['name'],
                security_enabled=True,
                scope='GLOBAL',
                optional_attributes={
                    'description': request.form['description']
                }
            )
            flash('Group created successfully')
            return redirect(url_for('groups'))
        except Exception as e:
            flash(f'Error creating group: {str(e)}')
    return render_template('add_group.html')

if __name__ == '__main__':
    app.run(debug=True) 