from flask import Flask, flash, render_template, redirect, url_for,request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField,SelectField,PasswordField, BooleanField
from forms import RestaurantSearchForm
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
#from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

import json
import requests
import os

  






app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dinertable.db'

#SQLALCHEMY_BINDS = { 'preferences':  'sqlite:///preferences.db'}



bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20),unique=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    seating = db.Column(db.String(10))
    take_out = db.Column(db.String(10))
    delivery = db.Column(db.String(10))
    curbside_pickup = db.Column(db.String(10))
    social_distancing = db.Column(db.String(10))
    disinfecting = db.Column(db.String(10))


    


    

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired(), Length(min=4, max=20)])
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

class PreferencesForm(FlaskForm):
    seating = StringField('Seating', validators=[InputRequired(),Length(min=3,max=10)])
    take_out = StringField('Take Out', validators=[InputRequired(),Length(min=3,max=10)])
    delivery = StringField('Delivery', validators=[InputRequired(),Length(min=3,max=10)])
    curbside_pickup = StringField('Curbside Pickup', validators=[InputRequired(),Length(min=3,max=10)])
    social_distancing = StringField('Social Distancing', validators=[InputRequired(),Length(min=3,max=10)])
    disinfecting = StringField('Disinfecting', validators=[InputRequired(),Length(min=3,max=10)])





@app.route('/')
def index():
    return render_template('index.html')





    

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if (user.password == form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        #hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(name=form.name.data,username=form.username.data, email=form.email.data, password=form.password.data)
        db.session.add(new_user)
        db.session.commit()

        return '<h1>New user has been created!</h1>'
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
def set_prefs():
    form = PreferencesForm()

    if form.validate_on_submit():
        #hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(seating=form.seating.data,take_out=form.take_out.data, delivery=form.delivery.data, curbside_pickup=form.curbside_pickup.data,social_distancing=form.social_distancing.data,disinfecting=form.disinfecting.data)
        db.session.add(new_user)
        db.session.commit()

      

    return render_template('dashboard.html', form=form)

@app.route('/myprefs')
def Show_My_Prefs():
    return render_template('myprefs.html',values = User.query.all())

@app.route('/dashboard')
@login_required
def dashboard():
    users = User.query.all()
    for u in users:
        print(u.name)
    return render_template('dashboard.html', name=current_user.name)

#@app.route('/dashboard',methods=['GET'])
#def dropdown_seating():
    #seating = ['Indoor','Outdoor']
    #return render_template('new_search.html',seating=seating)

def yelp_reviews(cmd):
    os.system(cmd)

    api_key= "2-eKqHbDGY84ynQr8dU7kHg80TMxTic_SacDpmp5h7AQWu25H7sFKG9bZdmPtwIHyQ21sa6uDCQMv2l5vX86vmk_ZoTKcNM55jmhxCwZ77DiX92GW9pwwbZPq5zKX3Yx"
    headers = {'Authorization': 'Bearer %s' % api_key}


    url = 'https://api.yelp.com/v3/businesses/search'
    params = {'term':'restaurant','location':'Orange County,California'}

    req = requests.get(url, params=params, headers=headers)
 
    parsed = json.loads(req.text)

    
 
 
    businesses = parsed["businesses"]


 
    for business in businesses:
        print("Name:", business["name"])
        print("Rating:", business["rating"])
        print("Address:", " ".join(business["location"]["display_address"]))
        print("Phone:", business["phone"])
        print("\n")
 
    id = business["id"]
 
    url="https://api.yelp.com/v3/businesses/" + id + "/reviews"
 
    req = requests.get(url, headers=headers)
 
    parsed = json.loads(req.text)
 
    reviews = parsed["reviews"]
 
    print("--- Reviews ---")
 
    for review in reviews:
        print("User:", review["user"]["name"], "Rating:", review["rating"], "Review:", review["text"], "\n")
    
    return reviews

    

@app.route('/yelp')
def yelp_output():
    output = yelp_reviews('./script')

    return render_template('yelp.html',output=output)

@app.route('/Show_Other_Users')
def Show_Other_Users():
    return render_template('Show_Other_Users.html',values = User.query.all())

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html',name=current_user.username)

@app.route('/mapviewer')
@login_required
def mapviewer():
    return render_template('mapviewer.html',name=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))





#if __name__ == '__main__':
    #app.run(debug=True)
