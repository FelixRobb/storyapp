# Story app, by Félix Robb


import os
import string
import random
import hashlib 
from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_argon2 import Argon2
from flask_migrate import Migrate
from sqlalchemy import func, or_
from sqlalchemy.orm import aliased
from datetime import datetime, timezone
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField, FileField, validators, PasswordField, BooleanField, SelectField
from wtforms.validators import DataRequired, Email
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from PIL import Image
from random import SystemRandom
secrets = SystemRandom()

app = Flask(__name__)


app.config['SECRET_KEY'] = "knkdjnkjnjdjdj"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///stories.db'
app.config['IMAGE_UPLOAD_FOLDER'] = 'static/images/profpics'
app.config['AUDIO_UPLOAD_FOLDER'] = 'static/audio'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}  # Specify allowed file extensions if needed

# Configure Flask-Mail settings for Gmail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587  # Gmail SMTP port
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'storia.mailapp@gmail.com'  # Your Gmail address
app.config['MAIL_PASSWORD'] = 'uffb hadb umgh atmm'  # Your Gmail app password
app.config['MAIL_DEFAULT_SENDER'] = 'storia.mailapp@gmail.com'



csrf = CSRFProtect(app)
csrf.init_app(app)
db = SQLAlchemy(app)
argon2 = Argon2(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)
mail = Mail(app)

# cache control
@app.after_request
def add_cache_control(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# Get the path to the tags.txt file in the static folder
tags_file_path = os.path.join(app.root_path, 'static', 'tags.txt')

# Read pre-established tags from the tags.txt file
with open(tags_file_path, 'r') as file:
    preestablished_tags = [line.strip() for line in file]

# image functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def resize_image(image_path, output_path, size=(200, 200)):
    with Image.open(image_path) as img:
        img.thumbnail(size)
        img.save(output_path)

# Convert to PNG function
def convert_to_png(input_path, output_path):
    with Image.open(input_path) as img:
        img.convert("RGBA").save(output_path, "PNG")

#Classes

# db models
        
#User class        
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(100))
    privacy_setting = db.Column(db.String(20), default='public')
    theme = db.Column(db.String(20), default='light')  # Example: 'light' or 'dark'
    language = db.Column(db.String(10), default='en')  # Example: 'en' for English
    bio = db.Column(db.String(255))
    stories = db.relationship('Story', back_populates='author', lazy=True)
    saved_stories = db.relationship('SavedStory', backref='user', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)
    followers = db.relationship('Follow', foreign_keys='Follow.followed_id', backref='followed', lazy='dynamic')
    followed = db.relationship('Follow', foreign_keys='Follow.follower_id', backref='follower', lazy='dynamic')
    notifications = db.relationship('Notification', backref='user', lazy=True)
    profile_pic = db.Column(db.String(255), default='default_profile_pic.png')
    email = db.Column(db.String(120), unique=True, nullable=False)
    reset_token = db.Column(db.String(100), nullable=True)
    is_author = db.Column(db.Boolean, default=False)
    

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.set_password(password)

    def generate_reset_token(self, token_length=32):
        characters = string.ascii_letters + string.digits + '-._~'
        token = ''.join(random.choice(characters) for _ in range(token_length))
        self.reset_token = token

    def set_password(self, password):
        self.password = password
        self.password_hash = argon2.generate_password_hash(password)

    def check_password(self, password):
        return argon2.check_password_hash(self.password_hash, password)

    def is_following(self, user):
        return self.followed.filter_by(followed_id=user.id).first() is not None

    def get_user_stories(self):
        return Story.query.filter_by(author=self).all()

    def has_unread_notifications(self):
        unread_notifications = Notification.query.filter_by(user_id=self.id, read=False).count()
        print(f"Unread notifications count for user {self.id}: {unread_notifications}")
        return unread_notifications > 0

# Send emails
def send_reset_email(email, token):
    reset_url = f'http://127.0.0.1:5000/reset_password/{token}'
    msg = Message('Password Reset Request', sender='mailstory.app@gmail.com', recipients=[email])
    msg.body = f'''Storyapp
    
To reset your password, visit the following link:
{reset_url}

If you did not make this request, ignore this email.

This is an automatic email, please dont respond.
'''
    mail.send(msg)



# Story class
class Story(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    synopsis = db.Column(db.String(1000), nullable=False)
    content = db.Column(db.Text, nullable=False)
    tags = db.Column(db.String(255))
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', back_populates='stories')
    versions = db.relationship('Version', back_populates='story', foreign_keys="[Version.story_id]")
    comments = db.relationship('Comment', back_populates='story', lazy=True)
    saved_by_users = db.relationship('SavedStory', backref='story', lazy=True)
    edit_proposals = db.relationship('EditProposal', back_populates='story', lazy=True)


# Saved story class
class SavedStory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    story_id = db.Column(db.Integer, db.ForeignKey('story.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# Comment class
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    story_id = db.Column(db.Integer, db.ForeignKey('story.id'), nullable=False)

    user = db.relationship('User', back_populates='comments', overlaps="author")
    story = db.relationship('Story', back_populates='comments', lazy=True)
    

# Edit proposals
class EditProposal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    story = db.relationship('Story', back_populates='edit_proposals', lazy=True)
    content = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'accepted', 'declined'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('edit_proposals', lazy=True))
    story_id = db.Column(db.Integer, db.ForeignKey('story.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    author_approval = db.Column(db.Boolean, default=False)



 # Version
class Version(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    story_id = db.Column(db.Integer, db.ForeignKey('story.id'))
    story = db.relationship('Story', back_populates='versions', foreign_keys=[story_id])
    



# Follow
class Follow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    followed_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


# Notifications
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)


# Flask forms

# Login
class LoginForm(FlaskForm):
    username = StringField('Username', [validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])
    submit = SubmitField('Login')




 # Create story
class CreateStoryForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    synopsis = StringField('Synopsis', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    tags = StringField('Tags')
    submit = SubmitField('Create Story')


# Edit story
class EditForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    synopsis = TextAreaField('Synopsis', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    tags = StringField('Tags', validators=[DataRequired()])
    submit = SubmitField('Submit Edit')

# Other user edit story
class ContentEditForm(FlaskForm):
    content = TextAreaField('Content', validators=[DataRequired()])

# Edit profile
class EditProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    bio = TextAreaField('Bio')
    profile_pic = FileField('Profile Picture')
    submit = SubmitField('Save Changes')


# Comment
class CommentForm(FlaskForm):
    comment = TextAreaField('Comment', validators=[DataRequired()])
    submit_comment = SubmitField('Submit Comment')


# Privacy settings
class PrivacySettingsForm(FlaskForm):
    privacy_setting = SelectField('Privacy Setting', choices=[('public', 'Public'), ('private', 'Private')])
    submit = SubmitField('Save Privacy Settings')


# Account settings
class AccountSettingsForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired()])
    new_email = StringField('New Email')  # Add new_email field for changing email
    submit = SubmitField('Change Password/Email')



# Notifications preferences

class NotificationPreferencesForm(FlaskForm):
    story_updates = BooleanField('Receive Story Updates')
    comments = BooleanField('Receive Comments Notifications')
    followers = BooleanField('Receive Followers Notifications')
    submit = SubmitField('Save Preferences')


# Search
class SearchForm(FlaskForm):
    search_query = StringField('Search', render_kw={"placeholder": "Enter your search query"})
    submit = SubmitField('Search')

# password reset
class PasswordResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Reset Password')

# Reset request password
class RequestPasswordResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Reset Password')


# Custom error handler
@app.errorhandler(500)
def internal_server_error(error):
    return render_template('error.html'), 500

    
# Routes

@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(int(user_id))


# Entry Page
@app.route('/entry', methods=['GET'])
def entry_page():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    return render_template('welcome.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)  # Use Flask-Login's login_user function
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html', form=form)

# Logout
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))


# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')  # Add email field to the registration form
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'error')
        else:
            # Check if the username is already taken
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('Username is already taken. Please choose another one.', 'error')
            else:
                # Check if the email is already reagistered
                existing_email = User.query.filter_by(email=email).first()
                if existing_email:
                    flash('Email is already registered. Please use another email.', 'error')
                else:
                    new_user = User(username=username, email=email, password=password)
                    new_user.set_password(password)
                    db.session.add(new_user)
                    db.session.commit()

                    # Log in the user after successful registration
                    login_user(new_user)
                    return redirect(url_for('index'))

    return render_template('register.html')




# index/Feed
@app.route('/', methods=['GET', 'POST'])
def index():
    if current_user.is_authenticated:
        if request.method == 'POST':
            search_query = request.form.get('search_query')
            if search_query:
                # Redirect to the search results page with the query
                return redirect(url_for('search_results', query=search_query))
            else:
                # Fetch all stories if no search query is provided
                saved_stories_alias = aliased(SavedStory)
                subquery = db.session.query(
                    saved_stories_alias.story_id,
                    func.max(saved_stories_alias.date).label('max_date')
                ).filter(saved_stories_alias.user_id == current_user.id).group_by(saved_stories_alias.story_id).subquery()

                stories = (
                    Story.query
                    .join(subquery, Story.id == subquery.c.story_id, isouter=True)
                    .order_by(subquery.c.max_date.desc().nullslast())
                    .all()
                )

                unread_notifications = current_user.has_unread_notifications()
                return render_template('feed.html', stories=stories, unread_notifications=unread_notifications)
        else:
            # Your existing code for fetching stories without search
            saved_stories_alias = aliased(SavedStory)
            subquery = db.session.query(
                saved_stories_alias.story_id,
                func.max(saved_stories_alias.timestamp).label('max_date')
            ).filter(saved_stories_alias.user_id == current_user.id).group_by(saved_stories_alias.story_id).subquery()

            stories = (
                Story.query
                .join(subquery, Story.id == subquery.c.story_id, isouter=True)
                .order_by(subquery.c.max_date.desc().nullslast())
                .all()
            )

            unread_notifications = current_user.has_unread_notifications()

            return render_template('feed.html', stories=stories, unread_notifications=unread_notifications)
    else:
        return redirect(url_for('entry_page'))

# Search results
@app.route('/search_results', methods=['GET', 'POST'])
@login_required
def search_results():
    if request.method == 'POST':
        search_query = request.form.get('search_query')
        if search_query:
            # Search for stories with matching title or tags
            story_results = Story.query.filter(
                or_(Story.title.ilike(f'%{search_query}%'), Story.tags.ilike(f'%{search_query}%'))
            ).all()

            # Search for users with matching username
            user_results = User.query.filter(User.username.ilike(f'%{search_query}%')).all()

            return render_template('search_results.html', query=search_query, story_results=story_results, user_results=user_results)

    return render_template('search_results.html', query=None, story_results=None, user_results=None)


@app.route('/story/<int:story_id>/save', methods=['POST'])
@login_required
def save_story(story_id):
    story = Story.query.get(story_id)

    if not story:
        return jsonify({'error': 'Story not found'}), 404

    saved_story = SavedStory.query.filter_by(user_id=current_user.id, story_id=story_id).first()

    if saved_story:
        # Story is already saved, so unsave it
        db.session.delete(saved_story)
        db.session.commit()
        return jsonify({'status': 'unsaved'})
    else:
        # Story is not saved, so save it
        new_saved_story = SavedStory(user_id=current_user.id, story_id=story_id)
        db.session.add(new_saved_story)
        db.session.commit()
        return jsonify({'status': 'saved'})

# Create story
@app.route('/create_story', methods=['GET', 'POST'])
@login_required
def create_story():
    form = CreateStoryForm()

    if form.validate_on_submit():
        title = form.title.data
        synopsis = form.synopsis.data
        content = form.content.data
        tags = form.tags.data

        # Save content with actual newline characters
        new_story = Story(
            title=title,
            synopsis=synopsis,
            content=content,  # Save content with \n
            tags=tags,
            author=current_user
        )

        # Create an initial version for the story
        initial_version = Version(
            date=datetime.utcnow(),
            content=content.replace('\n', '<br>'),  # Convert newline characters to <br>
            story=new_story
        )

        
        db.session.add(new_story)
        db.session.add(initial_version)
        db.session.commit()

        flash('Story created successfully!', 'success')
        # Redirect to the view_story endpoint with the newly created story's ID
        return redirect(url_for('view_story', story_id=new_story.id))

    return render_template('create_story.html', form=form)


# Route to fetch the pre-established tags
@app.route('/get_tags', methods=['GET'])
def get_tags():
    return jsonify(tags=preestablished_tags)


# View story
@app.route('/story/<int:story_id>')
@login_required
def view_story(story_id):
    story = Story.query.get(story_id)
    versions = Version.query.filter_by(story=story).all()
    edit_proposals = EditProposal.query.filter_by(story=story, status='pending').all()

    if story:
        form = CommentForm()


        return render_template('view_story.html', story=story, versions=versions, edit_proposals=edit_proposals, form=form )
    else:
        return "Story not found", 404


# Saved stories
@app.route('/saved_stories')
@login_required
def saved_stories():
    search_query = request.args.get('search', default='', type=str)
    
    # Filter saved stories based on the search query
    saved_stories = SavedStory.query.filter(
    (SavedStory.user_id == current_user.id) &
    SavedStory.story.has(Story.title.ilike(f"%{search_query}%"))
).all()


    return render_template('saved_stories.html', saved_stories=saved_stories)


# Search saved stories
@app.route('/search_saved_stories', methods=['GET'])
@login_required
def search_saved_stories():
    search_query = request.args.get('query', '').strip()

    if search_query:
        saved_stories = SavedStory.query.join(Story).filter(
            SavedStory.user_id == current_user.id,
            Story.title.ilike(f"%{search_query}%")
        ).all()

        search_results = [{'title': story.story.title, 'url': url_for('view_story', story_id=story.story.id)} for story in saved_stories]
        return jsonify(search_results)

    return jsonify([])


# Edit story
@app.route('/story/edit/<int:story_id>', methods=['GET', 'POST'])
@login_required
def edit_story(story_id):
    story = Story.query.get(story_id)

    if not story:
        flash('Story not found.', 'error')
        return redirect(url_for('index'))

    # Check if the current user is the author of the story
    is_author = current_user == story.author

    if is_author:
        # If the current user is the author, allow editing all fields directly
        form = EditForm(obj=story)

        if form.validate_on_submit():
            form.populate_obj(story)  # Update the story with the form data
            db.session.commit()
            flash('Story successfully updated.', 'success')
            return redirect(url_for('view_story', story_id=story_id))
        
        return render_template('author_edit_story.html', form=form, story=story, is_author=is_author)
    else:
        # If the current user is not the author, allow editing only the content and create an edit proposal
        form = ContentEditForm()

        if form.validate_on_submit():
            content = form.content.data

            # Create an edit proposal for the story
            edit_proposal = EditProposal(
                content=content,
                status='pending',
                user=current_user,
                story=story
            )

            db.session.add(edit_proposal)
            db.session.commit()

            # Create a notification for the author
            notification_content = f"New edit proposal for your story '{story.title}'."
            notification = Notification(
                content=notification_content,
                user=story.author,
                read=False
            )

            db.session.add(notification)
            db.session.commit()

            flash('Edit proposal submitted. The author will review and approve it.', 'info')
            return redirect(url_for('view_story', story_id=story_id))

        # Prepopulate form field with current story content
        form.content.data = story.content

        return render_template('edit_story.html', form=form, story=story, is_author=is_author)
    

# Edit proposal accept/decline route
@app.route('/story/edit_proposal/<int:proposal_id>/<string:action>', methods=['POST'])
@login_required
def handle_edit_proposal(proposal_id, action):
    proposal = EditProposal.query.get(proposal_id)

    if proposal and proposal.story.author == current_user:
        if action == 'accept':
            # Apply the accepted edit to the story
            proposal.story.content = proposal.content
            proposal.status = 'accepted'
            proposal.author_approval = True
            db.session.commit()
            flash('Edit proposal accepted!', 'success')
        elif action == 'decline':
            # Mark the edit proposal as declined
            proposal.status = 'declined'
            db.session.commit()
            flash('Edit proposal declined.', 'info')
        else:
            flash('Invalid action.', 'error')
    else:
        flash('Permission denied or edit proposal not found.', 'error')

    return redirect(url_for('view_story', story_id=proposal.story.id))


# Delete story
@app.route('/story/<int:story_id>/delete', methods=['POST'])
@login_required
def delete_story(story_id):
    story = Story.query.get(story_id)

    if story and story.author == current_user:
        try:

            # Delete associated records in comment table
            Comment.query.filter_by(story_id=story_id).delete()

            # Delete associated records in version table
            Version.query.filter_by(story_id=story_id).delete()

            # Delete associated records in edit_proposal table
            EditProposal.query.filter_by(story_id=story_id).delete()

            # Delete the story
            db.session.delete(story)
            
            # Commit the changes
            db.session.commit()

            return redirect(url_for('index'))
        except Exception as e:
            # Handle any exceptions and rollback changes
            db.session.rollback()


    return redirect(url_for('view_story', story_id=story_id))

    

# Comment
@app.route('/story/<int:story_id>/comment', methods=['POST'])
@login_required
def add_comment(story_id):
    story = Story.query.get(story_id)
    if story and request.method == 'POST':
        comment_content = request.form.get('comment')
        if comment_content:
            new_comment = Comment(content=comment_content, author=current_user, story=story)
            db.session.add(new_comment)
            db.session.commit()
        else:
            flash('Comment content cannot be empty.', 'com_error')

    return redirect(url_for('view_story', story_id=story_id))


# Follow/Unfollow
@app.route('/user/<int:user_id>/follow', methods=['POST'])
@login_required
def follow_user(user_id):
    user_to_follow = User.query.get(user_id)

    if user_to_follow and user_to_follow != current_user:
        if not current_user.is_following(user_to_follow):
            follow = Follow(follower=current_user, followed=user_to_follow)
            db.session.add(follow)
            flash(f'You are now following {user_to_follow.username}!', 'success')
        else:
            # Unfollow if already following
            unfollow = current_user.followed.filter_by(followed_id=user_to_follow.id).first()
            db.session.delete(unfollow)
            flash(f'You have unfollowed {user_to_follow.username}.', 'info')

        db.session.commit()
    else:
        flash('User not found or cannot follow/unfollow yourself.', 'error')

    return redirect(url_for('user_page', user_id=user_id))

# User page
@app.route('/user/<int:user_id>')
@login_required
def user_page(user_id):
    user = User.query.get(user_id)

    if user:
        user_stories = user.get_user_stories()

        # Check if the current user is viewing their own page or another user's page
        is_own_page = user == current_user

        # Check if the current user is following the displayed user
        is_following = current_user.is_following(user)

        
        if is_own_page:
            return render_template('user_page.html', user=user, user_stories=user_stories, is_own_page=is_own_page, is_following=is_following)
        else:
            return render_template('other_user_page.html', user=user, user_stories=user_stories, is_own_page=is_own_page, is_following=is_following)
    else:
        return "User not found", 404


# Edit profile route
@app.route('/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_profile(user_id):
    user = User.query.get(user_id)

    if user and user == current_user:
        form = EditProfileForm()

        if form.validate_on_submit():
            user.username = form.username.data
            user.bio = form.bio.data

            # Check if a new profile picture is provided
            if 'profile_pic' in request.files:
                profile_pic = request.files['profile_pic']

                if profile_pic.filename != '' and allowed_file(profile_pic.filename):
                    # Generate a secure and unique filename
                    filename = secure_filename(profile_pic.filename)
                    username_filename = f"{user.username}_profile_pic.png"

                    # Save the original image
                    original_path = os.path.join(app.config['IMAGE_UPLOAD_FOLDER'], filename)
                    profile_pic.save(original_path)

                    # Convert the image to PNG
                    png_path = os.path.join(app.config['IMAGE_UPLOAD_FOLDER'], username_filename)
                    convert_to_png(original_path, png_path)

                    # Resize the image for the profile picture
                    profile_pic_path = os.path.join(app.config['IMAGE_UPLOAD_FOLDER'], username_filename)
                    resize_image(png_path, profile_pic_path, size=(200, 200))

                    # Update the user profile pic path in the database with the username and PNG extension
                    user.profile_pic = username_filename

                    # Remove the original image
                    os.remove(original_path)

            db.session.commit()
            flash('Profile information updated successfully!', 'success')
            return redirect(url_for('user_page', user_id=user_id))

        # Pre-fill the form with current user information
        form.username.data = user.username
        form.bio.data = user.bio

        return render_template('edit_profile.html', user=user, form=form)

    flash('Permission denied or user not found.', 'error')
    return redirect(url_for('index'))


# User relations
@app.route('/user/relations', methods=['GET'])
@login_required
def user_relations():
    user = current_user
    
    # Get the followed users (users being followed by the current user)
    followed_users = Follow.query.filter_by(follower_id=user.id).join(User, Follow.followed_id == User.id).all()

    # Get the followers (users following the current user)
    followers = Follow.query.filter_by(followed_id=user.id).join(User, Follow.follower_id == User.id).all()

    # Retrieve a list of users that the current user does not follow but has a connection with
    suggested_users = User.query.filter(User.id != user.id, ~user.followers.filter_by(followed_id=User.id).exists()).all()

    return render_template('user_relations.html', user=user, followed_users=followed_users, followers=followers, suggested_users=suggested_users)


# Notifications
@app.route('/notifications')
@login_required
def notifications():
    # Mark all notifications as read when the user views the notifications page
    user_notifications = Notification.query.filter_by(user_id=current_user.id).all()
    for notification in user_notifications:
        notification.read = True

    db.session.commit()

    # Fetch and display notifications
    user_notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.timestamp.desc()).all()
    return render_template('notifications.html', notifications=user_notifications)

# Settings
@app.route('/user/settings', methods=['GET'])
@login_required
def user_settings():
    return render_template('settings.html', user=current_user)


# General Settings
@app.route('/user/settings/general', methods=['GET', 'POST'])
@login_required
def general_settings():
    if request.method == 'POST':
        # Handle saving general settings logic
        user = current_user
        user.language = request.form.get('language')
        user.theme = request.form.get('theme')
        db.session.commit()
        return redirect(url_for('general_settings'))
    return render_template('general_settings.html', user=current_user)


# Account Settings
@app.route('/user/settings/account', methods=['GET', 'POST'])
@login_required
def account_settings():
    form = AccountSettingsForm()

    if form.validate_on_submit():
        user = current_user
        current_password = form.current_password.data
        new_password = form.new_password.data
        confirm_password = form.confirm_password.data
        new_email = form.new_email.data

        # Check if the current passwo(rd is correct
        if user.check_password(current_password):
            # Change password if new password is provided
            if new_password:
                # Check if the new password matches the confirmation
                if new_password == confirm_password:
                    user.set_password(new_password)
                else:
                    flash('New password and confirmation do not match.', 'error')
                    return redirect(url_for('account_settings'))

            # Change email if new email is provided
            if new_email:
                # Check if the new email is already registered
                existing_email = User.query.filter_by(email=new_email).first()
                if existing_email:
                    flash('Email is already registered. Please use another email.', 'error')
                    return redirect(url_for('account_settings'))
                else:
                    user.email = new_email

            db.session.commit()
            flash('Account settings saved successfully!', 'success')
            return redirect(url_for('account_settings'))
        else:
            flash('Current password is incorrect.', 'error')

    return render_template('account_settings.html', user=current_user, form=form)


# Notification Settings
@app.route('/user/settings/notifications', methods=['GET', 'POST'])
@login_required
def notification_settings():
    if request.method == 'POST':
        # Handle saving notification settings logic
        user = current_user
        user.story_updates = 'story_updates' in request.form
        user.comments = 'comments' in request.form
        user.followers = 'followers' in request.form
        db.session.commit()
        flash('Notification settings saved successfully!', 'success')
        return redirect(url_for('notification_settings'))
    return render_template('notification_settings.html', user=current_user)

# Privacy Settings
@app.route('/user/settings/privacy', methods=['GET', 'POST'])
@login_required
def privacy_settings():
    if request.method == 'POST':
        # Handle saving privacy settings logic
        user = current_user
        user.privacy_setting = request.form.get('privacy_setting')
        db.session.commit()
        flash('Privacy settings saved successfully!', 'success')
        return redirect(url_for('privacy_settings'))
    return render_template('privacy_settings.html', user=current_user)

# Request Password reset
@app.route('/request_reset_password', methods=['GET', 'POST'])
def request_reset_password():
    form = RequestPasswordResetForm()

    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()

        if user:
            # Generate and store reset token
            user.generate_reset_token()
            db.session.commit()

            # Send email to user with reset link
            send_reset_email(user.email, user.reset_token)

            flash('Password reset email sent. Check your inbox.', 'success')
            return redirect(url_for('see_email'))
        else:
            flash('User not found with the provided email.', 'error')

    return render_template('request_reset_password.html', form=form)



# Reset password
@app.route('/reset_password/<string:token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()

    if not user:
        abort(404)  # Token not found

    form = PasswordResetForm()

    if form.validate_on_submit():
        # Ensure the provided email matches the user's registered email
        if form.email.data != user.email:
            flash('Invalid email for password reset.', 'error')
            return redirect(url_for('login'))

        # Ensure the new password matches the confirmation
        if form.new_password.data != form.confirm_password.data:
            flash('New password and confirmation do not match.', 'error')
            return redirect(request.url)

        # Update the password and clear the reset_token
        user.set_password(form.new_password.data)
        user.reset_token = None
        db.session.commit()

        flash('Password reset successfully! Please log in with your new password.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', form=form)


# see email
@app.route('/see_email')
def see_email():
    return render_template('see_email.html')

# Run app
if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)