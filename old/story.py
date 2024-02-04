# Story app, by Felix Robb


from flask import Flask, render_template, request, redirect, url_for, flash, request
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_argon2 import Argon2
from flask_migrate import Migrate
from sqlalchemy import func, or_
from datetime import datetime, timezone
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField, PasswordField, BooleanField, SelectField
from wtforms.validators import DataRequired, EqualTo
from flask_socketio import SocketIO

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///stories.db'
app.config['SECRET_KEY'] = "knkdjnkjnjdjdj"
socketio = SocketIO(app)  # Initialize SocketIO

db = SQLAlchemy(app)
argon2 = Argon2(app)  # Use Argon2 instead of Bcrypt
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(100))  # New password hash column
    stories = db.relationship('Story', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)
    followers = db.relationship('Follow', foreign_keys='Follow.followed_id', backref='followed', lazy='dynamic')
    followed = db.relationship('Follow', foreign_keys='Follow.follower_id', backref='follower', lazy='dynamic')
    notifications = db.relationship('Notification', backref='user', lazy=True)

    def set_password(self, password):
        self.password = password  # Store the actual password (for demonstration purposes)
        self.password_hash = argon2.generate_password_hash(password)

    def check_password(self, password):
        return argon2.check_password_hash(self.password_hash, password)

    def is_following(self, user):
        return self.followed.filter_by(followed_id=user.id).first() is not None

    def get_user_stories(self):
        return Story.query.filter_by(author=self).all()

    def get_followers(self):
        return self.followers.all()


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')



class Story(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    synopsis = db.Column(db.String(200))
    content = db.Column(db.Text, nullable=False)
    tags = db.Column(db.String(100))
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    versions = db.relationship('Version', backref='story', lazy=True)
    comments = db.relationship('Comment', backref='story', lazy=True)
    likes = db.Column(db.Integer, default=0)
    favorites = db.Column(db.Integer, default=0)

# Create a FlaskForm for the Create Story form
class CreateStoryForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    synopsis = StringField('Synopsis', validators=[DataRequired()])
    content = TextAreaField('Content', render_kw={'class': 'tinymce'}, validators=[DataRequired()])
    tags = StringField('Tags')
    submit = SubmitField('Create Story')


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')



class ProfileCustomizationForm(FlaskForm):
    theme = SelectField('Theme', choices=[('light', 'Light'), ('dark', 'Dark')])
    display_name = StringField('Display Name')
    submit = SubmitField('Save Settings')


class PrivacySettingsForm(FlaskForm):
    profile_visibility = SelectField('Profile Visibility', choices=[('public', 'Public'), ('followers', 'Followers Only'), ('private', 'Private')])
    submit = SubmitField('Save Settings')


# Create a search form class
class SearchForm(FlaskForm):
    search_query = StringField('Search', render_kw={"placeholder": "Enter your search query"})
    submit = SubmitField('Search')


class Version(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.String(20))
    content = db.Column(db.Text, nullable=False)
    story_id = db.Column(db.Integer, db.ForeignKey('story.id'), nullable=False)
    rich_content = db.Column(db.Text, nullable=False)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    story_id = db.Column(db.Integer, db.ForeignKey('story.id'), nullable=False)


class Follow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    followed_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class NotificationPreferencesForm(FlaskForm):
    story_updates = BooleanField('Receive Story Updates')
    comments = BooleanField('Receive Comments Notifications')
    followers = BooleanField('Receive Followers Notifications')
    submit = SubmitField('Save Preferences')



@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(int(user_id))


# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
            return redirect(url_for('login'))  # Redirect to login page on unsuccessful login

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Check if the username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different username.', 'error')
        elif password != confirm_password:
            flash('Passwords do not match. Please try again.', 'error')
        else:
            new_user = User(username=username)
            new_user.set_password(password)  # Set the password using set_password method
            db.session.add(new_user)
            db.session.commit()

            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')



@app.route('/')
@login_required
def index():
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Adjust as needed
    subquery = db.session.query(
        Version.story_id,
        func.max(Version.date).label('max_date')
    ).group_by(Version.story_id).subquery()

    stories_pagination = (
        Story.query
        .join(subquery, Story.id == subquery.c.story_id)
        .order_by(subquery.c.max_date.desc())
        .paginate(page=page, per_page=per_page, error_out=False, max_per_page=None)
    )

    stories = stories_pagination.items  # Extract the items from the pagination object

    return render_template('feed.html', stories=stories, stories_pagination=stories_pagination)



@app.route('/settings/account', methods=['GET', 'POST'])
@login_required
def account_settings():
    change_password_form = ChangePasswordForm()
    
    if change_password_form.validate_on_submit():
        # Implement password change logic
        flash('Password updated successfully!', 'success')
        return redirect(url_for('account_settings'))


    return render_template('account_settings.html', change_password_form=change_password_form, update_email_form=update_email_form)



@app.route('/settings/privacy', methods=['GET', 'POST'])
@login_required
def privacy_settings():
    privacy_settings_form = PrivacySettingsForm()

    if privacy_settings_form.validate_on_submit():
        # Implement logic to update privacy settings in the database
        flash('Privacy settings updated successfully!', 'success')
        return redirect(url_for('privacy_settings'))

    return render_template('privacy_settings.html', privacy_settings_form=privacy_settings_form)


@app.route('/settings/profile', methods=['GET', 'POST'])
@login_required
def profile_settings():
    profile_customization_form = ProfileCustomizationForm()

    if profile_customization_form.validate_on_submit():
        # Implement logic to update profile customization settings in the database
        flash('Profile customization settings updated successfully!', 'success')
        return redirect(url_for('profile_settings'))

    return render_template('profile_settings.html', profile_customization_form=profile_customization_form)



# Route for creating a story
@app.route('/create_story', methods=['GET', 'POST'])
@login_required
def create_story():
    form = CreateStoryForm()

    if form.validate_on_submit():
        # Form is valid, process the form data
        title = form.title.data
        synopsis = form.synopsis.data
        content = form.content.data
        tags = form.tags.data

        # Create a new story
        new_story = Story(
            title=title,
            synopsis=synopsis,
            content=content,
            tags=tags,
            author=current_user
        )

        # Create an initial version for the story
        initial_version = Version(
            date=datetime.now(timezone.utc).strftime('%Y-%m-%d'),
            content=content,
            story=new_story
        )

        db.session.add(new_story)
        db.session.add(initial_version)
        db.session.commit()

        flash('Story created successfully!', 'success')
        return redirect(url_for('index'))  # Redirect to the feed page after story creation
    else:
        # Form is not valid, render the create_story.html template with form errors
        return render_template('create_story.html', form=form)

# Routes for liking and favoriting stories
@app.route('/story/<int:story_id>/like', methods=['POST'])
@login_required
def like_story(story_id):
    story = Story.query.get(story_id)
    if story:
        story.likes += 1
        db.session.commit()
        flash('Story liked!', 'success')
    else:
        flash('Story not found', 'error')
    return redirect(url_for('view_story', story_id=story_id))


@app.route('/story/<int:story_id>/favorite', methods=['POST'])
@login_required
def favorite_story(story_id):
    story = Story.query.get(story_id)
    if story:
        story.favorites += 1
        db.session.commit()
        flash('Story favorited!', 'success')
    else:
        flash('Story not found', 'error')
    return redirect(url_for('view_story', story_id=story_id))


# Pagination for comments
@app.route('/story/<int:story_id>')
@login_required
def view_story(story_id):
    page = request.args.get('page', 1, type=int)
    story = Story.query.get(story_id)
    if story:
        comments = Comment.query.filter_by(story=story).paginate(page, per_page, False)
        return render_template('view_story.html', story=story, comments=comments)
    else:
        return "Story not found", 404


@app.route('/story/<int:story_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_story(story_id):
    story = Story.query.get(story_id)
    if story:
        if request.method == 'POST':
            new_edit = request.form.get('edit')
            if new_edit:
                version = Version(date=datetime.now(timezone.utc).strftime('%Y-%m-%d'), content=new_edit, story=story)
                db.session.add(version)
                db.session.commit()
            return redirect(url_for('view_story', story_id=story_id))
        return render_template('edit.html', story=story)
    else:
        return "Story not found", 404


@app.route('/story/<int:story_id>/comment', methods=['POST'])
@login_required
def add_comment(story_id):
    story = Story.query.get(story_id)
    comment_content = request.form.get('comment')
    if comment_content:
        new_comment = Comment(content=comment_content, author=current_user, story=story)
        db.session.add(new_comment)
        db.session.commit()
        flash('Comment added successfully!', 'success')
    else:
        flash('Comment content cannot be empty.', 'error')
    return redirect(url_for('view_story', story_id=story_id))


@app.route('/user/<int:user_id>/follow', methods=['POST'])
@login_required
def follow_user(user_id):
    user_to_follow = User.query.get(user_id)
    if user_to_follow and user_to_follow != current_user:
        if not current_user.is_following(user_to_follow):
            follow = Follow(follower=current_user, followed=user_to_follow)
            db.session.add(follow)
            db.session.commit()
            flash(f'You are now following {user_to_follow.username}!', 'success')
        else:
            flash('You are already following this user.', 'info')
    else:
        flash('User not found or cannot follow yourself.', 'error')
    return redirect(url_for('index'))




# Add a new route for user_page
@app.route('/user/<int:user_id>')
@login_required
def user_page(user_id):
    user = User.query.get(user_id)
    if user:
        user_stories = user.get_user_stories()
        followers = user.get_followers()

        # Retrieve a list of users that the current user does not follow but has a connection with
        suggested_users = User.query.filter(User.id != current_user.id, ~current_user.followers.filter_by(follower_id=User.id).exists()).all()

        return render_template('user_page.html', user=user, user_stories=user_stories, followers=followers, suggested_users=suggested_users)
    else:
        return "User not found", 404



@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    form = SearchForm()

    if form.validate_on_submit():
        query = form.search_query.data

        # Search for stories with titles or tags containing the query
        story_results = Story.query.filter(or_(Story.title.ilike(f'%{query}%'), Story.tags.ilike(f'%{query}%'))).all()

        # Search for users with usernames containing the query
        user_results = User.query.filter(User.username.ilike(f'%{query}%')).all()

        return render_template('search_results.html', query=query, story_results=story_results,
                               user_results=user_results)

    return render_template('search.html', form=form)


@app.route('/notifications')
@login_required
def notifications():
    user_notifications = (
    Notification.query.filter_by(user_id=current_user.id).order_by(Notification.timestamp.desc()).all())
    return render_template('notifications.html', notifications=user_notifications)


@app.route('/settings/notifications', methods=['GET', 'POST'])
@login_required
def notification_settings():
    notification_preferences_form = NotificationPreferencesForm()

    if notification_preferences_form.validate_on_submit():
        # Implement logic to update notification preferences in the database
        flash('Notification preferences updated successfully!', 'success')
        return redirect(url_for('notification_settings'))

    return render_template('notification_settings.html', notification_preferences_form=notification_preferences_form)


# Add routes for other features as needed
socketio.init_app(app)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)