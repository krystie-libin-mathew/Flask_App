from flask import render_template, flash, redirect, url_for, request, session,g
from app import app, db
from sqlalchemy.exc import IntegrityError
from models import User, Influencer, Campaign, CampaignRequest, AdRequest, Bookmark, Rating
from werkzeug.security import generate_password_hash, check_password_hash

app.secret_key = '123456'  

@app.route('/')
def index():
    user_id = session.get('user_id')
    return render_template('index.html', title='Home', user_id=user_id)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id  # Set user_id in session
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password')
    
    return render_template('login.html', title='Sign In')

@app.route('/sign_in', methods=['GET', 'POST'])
def sign_in():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists. Please choose a different email.')
            return render_template('sign_in.html', title='Sign In')
        
        # Correct hashing method
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        new_user = User(name=name, email=email, password=hashed_password, role=role)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Sign Up successful! Please log in.')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('An error occurred. Please try again.')
            return render_template('sign_in.html', title='Sign In')
    
    return render_template('sign_in.html', title='Sign In')

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
        name = request.form['name']
        description = request.form.get('description', '')
        start_date = request.form['start_date']
        deadline = request.form['deadline']
        fund = request.form['fund']
        specialty = request.form['specialty']

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
    
    # Fetch campaigns for the current user
    campaigns = Campaign.query.filter_by(user_id=user.id).all()
    return render_template('manage_campaigns.html', title='Manage Campaigns', campaigns=campaigns)

@app.route('/view_campaign_details/<int:campaign_id>')
def view_campaign_details(campaign_id):
    user = get_current_user()
    if user is None:
        return redirect(url_for('login'))
    
    campaign = Campaign.query.get_or_404(campaign_id)
    
    return render_template('view_campaign_details.html', title='Campaign Details', campaign=campaign)

@app.route('/manage_requests')
def manage_requests():
    user = get_current_user()
    if user is None:
        return redirect(url_for('login'))
    
    # Fetch requests for the current user's campaigns
    requests = CampaignRequest.query.filter_by(campaign_id=Campaign.query.filter_by(user_id=user.id).first().id).all()
    return render_template('manage_requests.html', title='Manage Requests', requests=requests)

@app.route('/profile_settings')
def profile_settings():
    user = get_current_user()
    if user is None:
        return redirect(url_for('login'))
    return render_template('profile_settings.html', title='Profile Settings', user=user)
@app.route('/search_results')
def search_results():
    query = request.args.get('q', '')
    influencers = []
    companies = []

    if query:
        influencers = Influencer.query.filter(
            Influencer.name.ilike(f'%{query}%')
        ).all()

        companies = User.query.filter(
            User.name.ilike(f'%{query}%'), User.role == 'company'
        ).all()

    return render_template('search_results.html', influencers=influencers, companies=companies, query=query)

@app.route('/admin_add_user', methods=['GET', 'POST'])
def admin_add_user():
    user = get_current_user()
    if user is None or user.role != 'admin':
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists. Please choose a different email.')
            return render_template('admin_add_user.html', title='Add User')
        
        # Correct hashing method
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        new_user = User(name=name, email=email, password=hashed_password, role=role)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('User added successfully!')
            return redirect(url_for('admin_manage_users'))
        except IntegrityError:
            db.session.rollback()
            flash('An error occurred. Please try again.')
            return render_template('admin_add_user.html', title='Add User')
    
    return render_template('admin_add_user.html', title='Add User')

@app.route('/admin_manage_users')
def admin_manage_users():
    user = get_current_user()
    if user is None or user.role != 'admin':
        return redirect(url_for('login'))
    users = User.query.all()
    return render_template('admin_manage_users.html', title='Manage Users', users=users)

@app.route('/admin_view_user_details/<int:user_id>')
def admin_view_user_details(user_id):
    user = get_current_user()
    if user is None or user.role != 'admin':
        return redirect(url_for('login'))
    user_details = User.query.get(user_id)
    return render_template('admin_view_user_details.html', title='User Details', user_details=user_details)

def get_current_user():
    user_id = session.get('user_id')
    if user_id:
        return User.query.get(user_id)
    return None

@app.before_request
def before_request():
    if 'user_id' in session:
        user = get_current_user()
        if user:
            g.user = user

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)