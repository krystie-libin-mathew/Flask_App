from app import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(255), nullable=False)
    specialty = db.Column(db.String(255), nullable=False)
    influencers = db.relationship('Influencer', backref='user', lazy=True)
    campaigns = db.relationship('Campaign', backref='user', lazy=True)
    bookmarks = db.relationship('Bookmark', backref='user', lazy=True)

class Influencer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    profile_pic = db.Column(db.String(255), nullable=False)
    specialty = db.Column(db.String(255), nullable=False)
    reach = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    platform = db.Column(db.String(255), nullable=False)
    bank_acc = db.Column(db.Float, nullable=False)
    flagged = db.Column(db.Boolean, default=False, nullable=False)
    campaign_requests = db.relationship('CampaignRequest', backref='influencer', lazy=True)
    ad_requests = db.relationship('AdRequest', backref='influencer', lazy=True)

class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    start_date = db.Column(db.DateTime, nullable=False)
    deadline = db.Column(db.DateTime, nullable=False)
    fund = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    specialty = db.Column(db.String(255), nullable=False)
    status = db.Column(db.Text, nullable=False)
    flagged = db.Column(db.Boolean, default=False, nullable=False)
    campaign_requests = db.relationship('CampaignRequest', backref='campaign', lazy=True)
    ad_requests = db.relationship('AdRequest', backref='campaign', lazy=True)
    bookmarks = db.relationship('Bookmark', backref='campaign', lazy=True)

class CampaignRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=False)
    influencer_id = db.Column(db.Integer, db.ForeignKey('influencer.id'), nullable=False)
    messages = db.Column(db.Text, nullable=False)
    pre_requisite = db.Column(db.Float, nullable=False)
    payment_amt = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(255), nullable=False)
    completed = db.Column(db.Boolean, default=False, nullable=False)
    completion_confirmed = db.Column(db.Boolean, default=False, nullable=False)
    payment_done = db.Column(db.Boolean, default=False, nullable=False)
    rating_done = db.Column(db.Boolean, default=False, nullable=False)

class AdRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=False)
    influencer_id = db.Column(db.Integer, db.ForeignKey('influencer.id'), nullable=False)
    messages = db.Column(db.Text, nullable=False)
    pre_requisite = db.Column(db.Float, nullable=False)
    payment_amt = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(255), nullable=False)
    completed = db.Column(db.Boolean, default=False, nullable=False)
    completion_confirmed = db.Column(db.Boolean, default=False, nullable=False)
    payment_done = db.Column(db.Boolean, default=False, nullable=False)
    rating_done = db.Column(db.Boolean, default=False, nullable=False)

class Bookmark(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.Integer, nullable=False)
    rater_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ratee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Float, nullable=False)
    review = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, nullable=False)