from flask import render_template, flash, redirect, url_for, request, session, g
from app import app, db
from sqlalchemy.exc import IntegrityError
from models import User, Influencer, Campaign, CampaignRequest, AdRequest, Bookmark, Rating
from werkzeug.security import generate_password_hash, check_password_hash
from forms import SignUpForm

app.secret_key = '123456'

@app.route('/')
def index():
    user_id = session.get('user_id')
    return render_template('index.html', title='Home', user_id=user_id)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password')
    
    return render_template('login.html', title='Sign In')

@app.route('/sign_in', methods=['GET', 'POST'])
def sign_in():
    form = SignUpForm()
    if request.method == 'POST' and form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        role = form.role.data
        specialty = form.specialty.data
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists. Please choose a different email.')
            return render_template('sign_in.html', title='Sign In', form=form)
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(name=name, email=email, password=hashed_password, role=role, specialty=specialty)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Sign Up successful! Please log in.')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('An error occurred. Please try again.')
    
    return render_template('sign_in.html', title='Sign In', form=form)

@app.route('/dashboard')
def dashboard():
    user = get_current_user()
    
    if user is None:
        return redirect(url_for('login'))
    
    campaigns = Campaign.query.all()
    return render_template('dashboard.html', title='Dashboard', user=user, campaigns=campaigns)

@app.route('/add_campaign', methods=['GET', 'POST'])
def add_campaign():
    user = get_current_user()
    if user is None:
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description', '')
        start_date = request.form.get('start_date')
        deadline = request.form.get('deadline')
        fund = request.form.get('fund')
        specialty = request.form.get('specialty')

        campaign = Campaign(
            name=name,
            description=description,
            start_date=start_date,
            deadline=deadline,
            fund=fund,
            specialty=specialty,
            user_id=user.id
        )
        db.session.add(campaign)
        db.session.commit()
        flash('Campaign added successfully!')
        return redirect(url_for('manage_campaigns'))
    
    return render_template('add_campaign.html', title='Add Campaign')

@app.route('/manage_campaigns')
def manage_campaigns():
    user = get_current_user()
    if user is None:
        return redirect(url_for('login'))
    campaigns = Campaign.query.filter_by(user_id=user.id).all()
    return render_template('manage_campaigns.html', title='Manage Campaigns', campaigns=campaigns)

def get_current_user():
    user_id = session.get('user_id')
    if user_id is None:
        return None
    return User.query.get(user_id)
