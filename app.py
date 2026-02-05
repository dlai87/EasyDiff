from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from datetime import datetime
import uuid
import json
import csv
import io
import os

from config import Config
from models import db, User, Study, Item, Response, Answer, CustomQuestion, CustomQuestionOption, CustomQuestionAnswer
from maxdiff import generate_sets, calculate_scores, get_ranked_items, get_response_statistics

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# OAuth setup
oauth = OAuth(app)

# Google OAuth configuration
google = oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

# Email setup
mail = Mail(app)

def get_serializer():
    return URLSafeTimedSerializer(app.config['SECRET_KEY'])

def generate_reset_token(email):
    serializer = get_serializer()
    return serializer.dumps(email, salt='password-reset-salt')

def verify_reset_token(token, expiration=3600):
    serializer = get_serializer()
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=expiration)
        return email
    except (SignatureExpired, BadSignature):
        return None

def send_reset_email(user):
    token = generate_reset_token(user.email)
    reset_url = url_for('reset_password', token=token, _external=True)

    msg = Message(
        'Password Reset Request - EasyDiff',
        recipients=[user.email]
    )
    msg.body = f'''Hi {user.name},

You requested to reset your password for EasyDiff.

Click the link below to reset your password:
{reset_url}

This link will expire in 1 hour.

If you did not request a password reset, please ignore this email.

Best regards,
EasyDiff Team
'''
    msg.html = f'''
<p>Hi {user.name},</p>
<p>You requested to reset your password for EasyDiff.</p>
<p>Click the link below to reset your password:</p>
<p><a href="{reset_url}">{reset_url}</a></p>
<p>This link will expire in 1 hour.</p>
<p>If you did not request a password reset, please ignore this email.</p>
<p>Best regards,<br>EasyDiff Team</p>
'''
    mail.send(msg)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Create database tables
with app.app_context():
    db.create_all()


def hash_password(password):
    """Hash password using pbkdf2:sha256 for better compatibility."""
    return generate_password_hash(password, method='pbkdf2:sha256')


# ============== Public Routes ==============

@app.route('/')
def index():
    return render_template('index.html')


# ============== Auth Routes ==============

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Validation
        errors = []
        if not name or len(name) < 2:
            errors.append('Name must be at least 2 characters.')
        if not email or '@' not in email:
            errors.append('Please enter a valid email address.')
        if len(password) < 8:
            errors.append('Password must be at least 8 characters.')
        if password != confirm_password:
            errors.append('Passwords do not match.')
        if User.query.filter_by(email=email).first():
            errors.append('Email already registered.')

        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('auth/register.html', name=name, email=email)

        # Create user
        user = User(
            name=name,
            email=email,
            password_hash=hash_password(password)
        )
        db.session.add(user)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    # Check if Google OAuth is configured
    google_enabled = bool(os.environ.get('GOOGLE_CLIENT_ID'))
    return render_template('auth/register.html', google_enabled=google_enabled)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember = request.form.get('remember') == 'on'

        user = User.query.filter_by(email=email).first()

        if user and user.password_hash and check_password_hash(user.password_hash, password):
            login_user(user, remember=remember)
            next_page = request.args.get('next')
            flash('Welcome back!', 'success')
            return redirect(next_page or url_for('dashboard'))

        flash('Invalid email or password.', 'error')
        google_enabled = bool(os.environ.get('GOOGLE_CLIENT_ID'))
        return render_template('auth/login.html', email=email, google_enabled=google_enabled)

    google_enabled = bool(os.environ.get('GOOGLE_CLIENT_ID'))
    return render_template('auth/login.html', google_enabled=google_enabled)


# ============== Google OAuth Routes ==============

@app.route('/login/google')
def login_google():
    """Initiate Google OAuth login."""
    if not os.environ.get('GOOGLE_CLIENT_ID'):
        flash('Google login is not configured.', 'error')
        return redirect(url_for('login'))

    redirect_uri = url_for('authorize_google', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/authorize/google')
def authorize_google():
    """Handle Google OAuth callback."""
    try:
        token = google.authorize_access_token()
        user_info = token.get('userinfo')

        if not user_info:
            flash('Could not get user info from Google.', 'error')
            return redirect(url_for('login'))

        email = user_info.get('email', '').lower()
        name = user_info.get('name', email.split('@')[0])

        if not email:
            flash('Could not get email from Google.', 'error')
            return redirect(url_for('login'))

        # Find or create user
        user = User.query.filter_by(email=email).first()

        if not user:
            # Create new user from Google data
            user = User(
                name=name,
                email=email,
                password_hash=None,  # No password for OAuth users
                google_id=user_info.get('sub')
            )
            db.session.add(user)
            db.session.commit()
            flash('Account created with Google!', 'success')
        else:
            # Update Google ID if not set
            if not user.google_id:
                user.google_id = user_info.get('sub')
                db.session.commit()

        login_user(user, remember=True)
        flash('Welcome back!', 'success')
        return redirect(url_for('dashboard'))

    except Exception as e:
        app.logger.error(f'Google OAuth error: {e}')
        flash('Google login failed. Please try again.', 'error')
        return redirect(url_for('login'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()

        if not email:
            flash('Please enter your email address.', 'error')
            return render_template('auth/forgot_password.html')

        user = User.query.filter_by(email=email).first()

        # Always show success message to prevent email enumeration
        if user and user.has_password:
            try:
                send_reset_email(user)
            except Exception as e:
                # Log error but don't expose to user
                print(f"Failed to send reset email: {e}")

        flash('If an account exists with that email, you will receive a password reset link.', 'info')
        return redirect(url_for('login'))

    return render_template('auth/forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    email = verify_reset_token(token)
    if not email:
        flash('The password reset link is invalid or has expired.', 'error')
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('The password reset link is invalid or has expired.', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('auth/reset_password.html', token=token)

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('auth/reset_password.html', token=token)

        user.password_hash = generate_password_hash(password)
        db.session.commit()

        flash('Your password has been reset. You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('auth/reset_password.html', token=token)


# ============== Dashboard Routes ==============

@app.route('/dashboard')
@login_required
def dashboard():
    status_filter = request.args.get('status', 'all')

    query = Study.query.filter_by(user_id=current_user.id)

    if status_filter != 'all':
        query = query.filter_by(status=status_filter.upper())

    studies = query.order_by(Study.updated_at.desc()).all()

    return render_template('dashboard.html', studies=studies, status_filter=status_filter)


# ============== Study Routes ==============

@app.route('/study/new', methods=['GET', 'POST'])
@login_required
def study_new():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()

        if not name:
            flash('Study name is required.', 'error')
            return render_template('study/new.html')

        study = Study(
            name=name,
            description=description,
            user_id=current_user.id
        )
        db.session.add(study)
        db.session.commit()

        flash('Study created! Now add your items.', 'success')
        return redirect(url_for('study_edit', id=study.id))

    return render_template('study/new.html')


@app.route('/study/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def study_edit(id):
    study = Study.query.filter_by(id=id, user_id=current_user.id).first_or_404()

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'update_metadata':
            study.name = request.form.get('name', '').strip() or study.name
            study.description = request.form.get('description', '').strip()
            study.question_text = request.form.get('question_text', '').strip() or 'Choose the Best and Worst from the following items'
            study.best_label = request.form.get('best_label', 'Best').strip() or 'Best'
            study.worst_label = request.form.get('worst_label', 'Worst').strip() or 'Worst'
            study.items_per_set = int(request.form.get('items_per_set', 4))
            study.sets_per_respondent = int(request.form.get('sets_per_respondent', 10))

            # Validate
            if study.items_per_set < 3:
                study.items_per_set = 3
            elif study.items_per_set > 5:
                study.items_per_set = 5

            if study.sets_per_respondent < 5:
                study.sets_per_respondent = 5
            elif study.sets_per_respondent > 20:
                study.sets_per_respondent = 20

            db.session.commit()
            flash('Study settings updated.', 'success')

        elif action == 'add_item':
            item_name = str(request.form.get('item_name', '') or '').strip()
            item_description = str(request.form.get('item_description', '') or '').strip()
            if item_name:
                # Check for duplicate item name in this study
                existing_item = Item.query.filter_by(study_id=study.id, name=item_name).first()
                if existing_item:
                    flash(f'Item "{item_name}" already exists. Please use a unique name.', 'error')
                else:
                    max_order = db.session.query(db.func.max(Item.order)).filter_by(study_id=study.id).scalar() or 0
                    item = Item(name=item_name, description=item_description if item_description else None, order=max_order + 1, study_id=study.id)
                    db.session.add(item)
                    db.session.commit()
                    flash('Item added.', 'success')
            else:
                flash('Item name is required.', 'error')

        elif action == 'update_item':
            item_id = request.form.get('item_id')
            item_name = str(request.form.get('item_name', '') or '').strip()
            item_description = str(request.form.get('item_description', '') or '').strip()
            if item_id and item_name:
                item = Item.query.filter_by(id=item_id, study_id=study.id).first()
                if item:
                    # Check for duplicate name (excluding current item)
                    existing_item = Item.query.filter_by(study_id=study.id, name=item_name).filter(Item.id != item.id).first()
                    if existing_item:
                        flash(f'Item "{item_name}" already exists. Please use a unique name.', 'error')
                    else:
                        item.name = item_name
                        item.description = item_description if item_description else None
                        db.session.commit()
                        flash('Item updated.', 'success')

        elif action == 'delete_item':
            item_id = request.form.get('item_id')
            if item_id:
                item = Item.query.filter_by(id=item_id, study_id=study.id).first()
                if item:
                    db.session.delete(item)
                    db.session.commit()
                    flash('Item deleted.', 'success')

        elif action == 'publish':
            if study.item_count >= 5:
                study.status = 'ACTIVE'
                db.session.commit()
                flash('Study published! Share the link to collect responses.', 'success')
            else:
                flash('You need at least 5 items to publish.', 'error')

        elif action == 'save_and_publish':
            # Save configuration first
            study.name = request.form.get('name', '').strip() or study.name
            study.description = request.form.get('description', '').strip()
            study.question_text = request.form.get('question_text', '').strip() or 'Choose the Best and Worst from the following items'
            study.best_label = request.form.get('best_label', 'Best').strip() or 'Best'
            study.worst_label = request.form.get('worst_label', 'Worst').strip() or 'Worst'
            study.items_per_set = int(request.form.get('items_per_set', 4))
            study.sets_per_respondent = int(request.form.get('sets_per_respondent', 10))

            # Validate
            if study.items_per_set < 3:
                study.items_per_set = 3
            elif study.items_per_set > 5:
                study.items_per_set = 5

            if study.sets_per_respondent < 5:
                study.sets_per_respondent = 5
            elif study.sets_per_respondent > 20:
                study.sets_per_respondent = 20

            # Then publish
            if study.item_count >= 5:
                study.status = 'ACTIVE'
                db.session.commit()
                flash('Study published! Share the link to collect responses.', 'success')
            else:
                db.session.commit()
                flash('Configuration saved, but you need at least 5 items to publish.', 'error')

        elif action == 'close':
            if study.status == 'ACTIVE':
                study.status = 'CLOSED'
                db.session.commit()
                flash('Study closed. No new responses will be accepted.', 'info')

        elif action == 'reopen':
            if study.status == 'CLOSED':
                study.status = 'ACTIVE'
                db.session.commit()
                flash('Study reopened. Now accepting responses.', 'success')

        elif action == 'unpublish':
            study.status = 'DRAFT'
            db.session.commit()
            flash('Study moved back to draft.', 'info')

        elif action == 'add_custom_question':
            question_text = request.form.get('question_text', '').strip()
            question_type = request.form.get('question_type', 'text')
            is_required = request.form.get('is_required') == 'on'

            if question_text and question_type in ['text', 'single_choice', 'multiple_choice', 'rating_scale']:
                max_order = db.session.query(db.func.max(CustomQuestion.order)).filter_by(study_id=study.id).scalar() or 0
                config = {}

                if question_type == 'text':
                    config['placeholder'] = request.form.get('placeholder', '').strip()
                elif question_type == 'rating_scale':
                    config['min_value'] = int(request.form.get('min_value', 1))
                    config['max_value'] = int(request.form.get('max_value', 5))
                    config['min_label'] = request.form.get('min_label', '').strip()
                    config['max_label'] = request.form.get('max_label', '').strip()

                question = CustomQuestion(
                    study_id=study.id,
                    question_text=question_text,
                    question_type=question_type,
                    is_required=is_required,
                    order=max_order + 1
                )
                question.config = config
                db.session.add(question)
                db.session.commit()

                # Add options for choice questions
                if question_type in ['single_choice', 'multiple_choice']:
                    options_text = request.form.get('options', '').strip()
                    if options_text:
                        for i, opt_text in enumerate(options_text.split('\n')):
                            opt_text = opt_text.strip()
                            if opt_text:
                                option = CustomQuestionOption(
                                    question_id=question.id,
                                    option_text=opt_text,
                                    order=i
                                )
                                db.session.add(option)
                        db.session.commit()

                flash('Pre-survey question added.', 'success')
            else:
                flash('Question text is required.', 'error')

        elif action == 'update_custom_question':
            question_id = request.form.get('question_id')
            question_text = request.form.get('question_text', '').strip()
            is_required = request.form.get('is_required') == 'on'

            if question_id and question_text:
                question = CustomQuestion.query.filter_by(id=question_id, study_id=study.id).first()
                if question:
                    question.question_text = question_text
                    question.is_required = is_required

                    config = question.config or {}
                    if question.question_type == 'text':
                        config['placeholder'] = request.form.get('placeholder', '').strip()
                    elif question.question_type == 'rating_scale':
                        config['min_value'] = int(request.form.get('min_value', 1))
                        config['max_value'] = int(request.form.get('max_value', 5))
                        config['min_label'] = request.form.get('min_label', '').strip()
                        config['max_label'] = request.form.get('max_label', '').strip()
                    question.config = config

                    # Update options for choice questions
                    if question.question_type in ['single_choice', 'multiple_choice']:
                        # Delete existing options
                        CustomQuestionOption.query.filter_by(question_id=question.id).delete()
                        options_text = request.form.get('options', '').strip()
                        if options_text:
                            for i, opt_text in enumerate(options_text.split('\n')):
                                opt_text = opt_text.strip()
                                if opt_text:
                                    option = CustomQuestionOption(
                                        question_id=question.id,
                                        option_text=opt_text,
                                        order=i
                                    )
                                    db.session.add(option)

                    db.session.commit()
                    flash('Pre-survey question updated.', 'success')

        elif action == 'delete_custom_question':
            question_id = request.form.get('question_id')
            if question_id:
                question = CustomQuestion.query.filter_by(id=question_id, study_id=study.id).first()
                if question:
                    db.session.delete(question)
                    db.session.commit()
                    flash('Pre-survey question deleted.', 'success')

        return redirect(url_for('study_edit', id=study.id))

    items = study.items.order_by(Item.order).all()
    custom_questions = study.custom_questions.order_by(CustomQuestion.order).all()
    share_url = url_for('survey_start', token=study.share_token, _external=True)

    # Calculate response stats for active/closed studies
    response_stats = {
        'total_started': Response.query.filter_by(study_id=study.id, is_preview=False).count(),
        'completed': Response.query.filter_by(study_id=study.id, is_preview=False).filter(Response.completed_at != None).count()
    }

    return render_template('study/edit.html', study=study, items=items, custom_questions=custom_questions, share_url=share_url, response_stats=response_stats)


@app.route('/study/<int:id>/bulk-import', methods=['POST'])
@login_required
def study_bulk_import(id):
    """Import multiple items at once, one per line."""
    study = Study.query.filter_by(id=id, user_id=current_user.id).first_or_404()

    if study.status != 'DRAFT':
        flash('Cannot add items to a published study.', 'error')
        return redirect(url_for('study_edit', id=study.id))

    items_text = request.form.get('items_text', '')
    lines = [line.strip() for line in items_text.split('\n') if line.strip()]

    if not lines:
        flash('No items to import.', 'error')
        return redirect(url_for('study_edit', id=study.id))

    # Check if adding these would exceed max (30 items)
    current_count = study.item_count
    if current_count + len(lines) > 30:
        flash(f'Cannot add {len(lines)} items. Maximum is 30 items total (currently have {current_count}).', 'error')
        return redirect(url_for('study_edit', id=study.id))

    max_order = db.session.query(db.func.max(Item.order)).filter_by(study_id=study.id).scalar() or 0

    # Get existing item names for duplicate check
    existing_names = {item.name.lower() for item in study.items.all()}

    added = 0
    skipped = []
    for i, line in enumerate(lines):
        # Support format: "Name | Description" or just "Name"
        if '|' in line:
            parts = line.split('|', 1)
            item_name = str(parts[0]).strip()[:200]
            item_description = str(parts[1]).strip() if len(parts) > 1 else None
        else:
            item_name = str(line).strip()[:200]
            item_description = None

        if item_name:
            # Check for duplicate (case-insensitive)
            if item_name.lower() in existing_names:
                skipped.append(item_name)
            else:
                item = Item(name=item_name, description=item_description if item_description else None, order=max_order + added + 1, study_id=study.id)
                db.session.add(item)
                existing_names.add(item_name.lower())
                added += 1

    db.session.commit()

    if skipped:
        flash(f'Imported {added} items. Skipped {len(skipped)} duplicate(s): {", ".join(skipped[:3])}{"..." if len(skipped) > 3 else ""}', 'warning')
    else:
        flash(f'Successfully imported {added} items.', 'success')
    return redirect(url_for('study_edit', id=study.id))


@app.route('/study/<int:id>/results')
@login_required
def study_results(id):
    study = Study.query.filter_by(id=id, user_id=current_user.id).first_or_404()

    items = study.items.all()
    # Exclude preview responses from results
    responses = study.responses.filter_by(is_preview=False).all()
    completed_responses = [r for r in responses if r.completed_at]
    completed_response_ids = [r.id for r in completed_responses]

    # Get all answers from completed responses
    answers = []
    for response in completed_responses:
        answers.extend(response.answers.all())

    # Calculate scores
    scores = calculate_scores(items, answers)
    ranked_items = get_ranked_items(scores)
    stats = get_response_statistics(responses)

    # Process custom question results
    custom_questions = study.custom_questions.order_by(CustomQuestion.order).all()
    custom_question_results = []

    for question in custom_questions:
        question_result = {
            'question': question,
            'type': question.question_type,
            'responses': []
        }

        # Get answers for this question from completed responses
        question_answers = CustomQuestionAnswer.query.filter(
            CustomQuestionAnswer.question_id == question.id,
            CustomQuestionAnswer.response_id.in_(completed_response_ids)
        ).all() if completed_response_ids else []

        if question.question_type == 'text':
            # List all text responses
            question_result['responses'] = [a.answer_text for a in question_answers if a.answer_text]
        elif question.question_type == 'rating_scale':
            # Calculate average and distribution
            values = [a.answer_value for a in question_answers if a.answer_value is not None]
            question_result['average'] = round(sum(values) / len(values), 2) if values else 0
            question_result['count'] = len(values)
            config = question.config or {}
            min_val = config.get('min_value', 1)
            max_val = config.get('max_value', 5)
            distribution = {i: 0 for i in range(min_val, max_val + 1)}
            for v in values:
                if v in distribution:
                    distribution[v] += 1
            question_result['distribution'] = distribution
            question_result['config'] = config
        elif question.question_type in ['single_choice', 'multiple_choice']:
            # Count per option with percentages
            options = question.options.order_by(CustomQuestionOption.order).all()
            option_counts = {opt.id: {'option': opt, 'count': 0} for opt in options}
            total_responses = len(question_answers)

            for answer in question_answers:
                option_ids = answer.answer_option_ids or []
                for oid in option_ids:
                    if oid in option_counts:
                        option_counts[oid]['count'] += 1

            # Calculate percentages
            for opt_id in option_counts:
                count = option_counts[opt_id]['count']
                option_counts[opt_id]['percentage'] = round((count / total_responses * 100) if total_responses > 0 else 0, 1)

            question_result['option_counts'] = option_counts
            question_result['total_responses'] = total_responses

        custom_question_results.append(question_result)

    return render_template('study/results.html',
                         study=study,
                         ranked_items=ranked_items,
                         stats=stats,
                         scores=scores,
                         custom_question_results=custom_question_results)


@app.route('/study/<int:id>/export')
@login_required
def study_export(id):
    study = Study.query.filter_by(id=id, user_id=current_user.id).first_or_404()

    items = study.items.all()
    # Exclude preview responses from export
    responses = study.responses.filter_by(is_preview=False).all()
    completed_responses = [r for r in responses if r.completed_at]

    answers = []
    for response in completed_responses:
        answers.extend(response.answers.all())

    scores = calculate_scores(items, answers)
    ranked_items = get_ranked_items(scores)

    # Create CSV
    output = io.StringIO()
    writer = csv.writer(output)

    # Section 1: MaxDiff Results
    writer.writerow(['=== MaxDiff Results ==='])
    writer.writerow(['Rank', 'Item', 'Normalized Score', 'Raw Score', 'Best Count', 'Worst Count', 'Appearances'])

    for rank, (item_id, data) in enumerate(ranked_items, 1):
        writer.writerow([
            rank,
            data['name'],
            data['normalized_score'],
            data['raw_score'],
            data['best_count'],
            data['worst_count'],
            data['appearances']
        ])

    # Section 2: Custom Question Responses
    custom_questions = study.custom_questions.order_by(CustomQuestion.order).all()
    if custom_questions:
        writer.writerow([])
        writer.writerow(['=== Pre-Survey Question Responses ==='])

        for question in custom_questions:
            writer.writerow([])
            writer.writerow([f'Question: {question.question_text}'])
            writer.writerow([f'Type: {question.question_type}', f'Required: {"Yes" if question.is_required else "No"}'])

            if question.question_type == 'text':
                writer.writerow(['Response ID', 'Answer'])
                for response in completed_responses:
                    answer = CustomQuestionAnswer.query.filter_by(
                        response_id=response.id,
                        question_id=question.id
                    ).first()
                    if answer and answer.answer_text:
                        writer.writerow([response.respondent_id[:8], answer.answer_text])
                    else:
                        writer.writerow([response.respondent_id[:8], '(no response)'])

            elif question.question_type == 'rating_scale':
                config = question.config or {}
                writer.writerow(['Response ID', 'Rating'])
                for response in completed_responses:
                    answer = CustomQuestionAnswer.query.filter_by(
                        response_id=response.id,
                        question_id=question.id
                    ).first()
                    if answer and answer.answer_value is not None:
                        writer.writerow([response.respondent_id[:8], answer.answer_value])
                    else:
                        writer.writerow([response.respondent_id[:8], '(no response)'])

                # Add summary statistics
                all_answers = CustomQuestionAnswer.query.filter(
                    CustomQuestionAnswer.question_id == question.id,
                    CustomQuestionAnswer.response_id.in_([r.id for r in completed_responses])
                ).all()
                values = [a.answer_value for a in all_answers if a.answer_value is not None]
                if values:
                    writer.writerow([])
                    writer.writerow(['Summary:', f'Average: {round(sum(values)/len(values), 2)}', f'Responses: {len(values)}'])

            elif question.question_type in ['single_choice', 'multiple_choice']:
                options = question.options.order_by(CustomQuestionOption.order).all()
                option_map = {opt.id: opt.option_text for opt in options}

                writer.writerow(['Response ID', 'Selected Option(s)'])
                for response in completed_responses:
                    answer = CustomQuestionAnswer.query.filter_by(
                        response_id=response.id,
                        question_id=question.id
                    ).first()
                    if answer and answer.answer_option_ids:
                        selected = [option_map.get(oid, 'Unknown') for oid in answer.answer_option_ids]
                        writer.writerow([response.respondent_id[:8], '; '.join(selected)])
                    else:
                        writer.writerow([response.respondent_id[:8], '(no response)'])

                # Add option counts summary
                writer.writerow([])
                writer.writerow(['Option', 'Count', 'Percentage'])
                total_responses = len(completed_responses)
                for opt in options:
                    count = sum(1 for r in completed_responses
                              for a in [CustomQuestionAnswer.query.filter_by(response_id=r.id, question_id=question.id).first()]
                              if a and a.answer_option_ids and opt.id in a.answer_option_ids)
                    pct = round(count / total_responses * 100, 1) if total_responses > 0 else 0
                    writer.writerow([opt.option_text, count, f'{pct}%'])

    output.seek(0)

    from flask import Response as FlaskResponse
    return FlaskResponse(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={study.name}_results.csv'}
    )


@app.route('/study/<int:id>/duplicate')
@login_required
def study_duplicate(id):
    study = Study.query.filter_by(id=id, user_id=current_user.id).first_or_404()

    new_study = Study(
        name=f"{study.name} (Copy)",
        description=study.description,
        question_text=study.question_text,
        best_label=study.best_label,
        worst_label=study.worst_label,
        items_per_set=study.items_per_set,
        sets_per_respondent=study.sets_per_respondent,
        user_id=current_user.id
    )
    db.session.add(new_study)
    db.session.commit()

    # Copy items
    for item in study.items.all():
        new_item = Item(name=item.name, description=item.description, order=item.order, study_id=new_study.id)
        db.session.add(new_item)

    # Copy custom questions
    for question in study.custom_questions.all():
        new_question = CustomQuestion(
            study_id=new_study.id,
            question_text=question.question_text,
            question_type=question.question_type,
            is_required=question.is_required,
            order=question.order,
            config_json=question.config_json
        )
        db.session.add(new_question)
        db.session.commit()

        # Copy options for choice questions
        for option in question.options.all():
            new_option = CustomQuestionOption(
                question_id=new_question.id,
                option_text=option.option_text,
                order=option.order
            )
            db.session.add(new_option)

    db.session.commit()

    flash('Study duplicated.', 'success')
    return redirect(url_for('study_edit', id=new_study.id))


@app.route('/study/<int:id>/delete', methods=['POST'])
@login_required
def study_delete(id):
    study = Study.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    db.session.delete(study)
    db.session.commit()
    flash('Study deleted.', 'success')
    return redirect(url_for('dashboard'))


# ============== Survey Routes (Public) ==============

@app.route('/survey/<token>')
def survey_start(token):
    study = Study.query.filter_by(share_token=token).first_or_404()

    # Check if this is a preview (DRAFT status)
    is_preview = request.args.get('preview') == '1' or study.status == 'DRAFT'

    # Only allow ACTIVE status or preview mode
    if study.status not in ['ACTIVE', 'DRAFT']:
        return render_template('survey/inactive.html', study=study)

    # For DRAFT, check if user is the owner (must be logged in)
    if study.status == 'DRAFT':
        if not current_user.is_authenticated or study.user_id != current_user.id:
            return render_template('survey/inactive.html', study=study)
        is_preview = True

    return render_template('survey/start.html', study=study, token=token, is_preview=is_preview)


@app.route('/survey/<token>/begin', methods=['POST'])
def survey_begin(token):
    study = Study.query.filter_by(share_token=token).first_or_404()

    # Check if preview mode
    is_preview = study.status == 'DRAFT'

    # Only allow ACTIVE or DRAFT (preview) status
    if study.status not in ['ACTIVE', 'DRAFT']:
        return redirect(url_for('survey_start', token=token))

    # For DRAFT preview, verify owner
    if study.status == 'DRAFT':
        if not current_user.is_authenticated or study.user_id != current_user.id:
            return redirect(url_for('survey_start', token=token))

    # Create new response (mark as preview if applicable)
    response = Response(study_id=study.id, is_preview=is_preview)
    db.session.add(response)
    db.session.commit()

    # Generate sets for this respondent
    items = study.items.all()
    item_ids = [item.id for item in items]

    sets = generate_sets(item_ids, study.sets_per_respondent, study.items_per_set)

    # Store sets in session
    session['survey_response_id'] = response.id
    session['survey_sets'] = sets
    session['survey_current_set'] = 0
    session['survey_is_preview'] = is_preview
    session['survey_custom_question_index'] = 0

    # Check if there are custom questions
    custom_questions = study.custom_questions.order_by(CustomQuestion.order).all()
    if custom_questions:
        return redirect(url_for('survey_custom_questions', token=token))

    return redirect(url_for('survey_question', token=token))


@app.route('/survey/<token>/question', methods=['GET', 'POST'])
def survey_question(token):
    study = Study.query.filter_by(share_token=token).first_or_404()
    is_preview = session.get('survey_is_preview', False)

    # Allow ACTIVE or preview mode
    if study.status not in ['ACTIVE', 'DRAFT'] and not is_preview:
        return redirect(url_for('survey_start', token=token))

    response_id = session.get('survey_response_id')
    sets = session.get('survey_sets', [])
    current_set = session.get('survey_current_set', 0)

    if not response_id or not sets:
        return redirect(url_for('survey_start', token=token))

    response = Response.query.get_or_404(response_id)

    if current_set >= len(sets):
        # Survey complete
        response.completed_at = datetime.utcnow()
        db.session.commit()
        session.pop('survey_response_id', None)
        session.pop('survey_sets', None)
        session.pop('survey_current_set', None)
        session.pop('survey_custom_question_index', None)
        return redirect(url_for('survey_complete', token=token))

    if request.method == 'POST':
        best_id = request.form.get('best')
        worst_id = request.form.get('worst')

        if not best_id or not worst_id:
            flash('Please select both best and worst options.', 'error')
        elif best_id == worst_id:
            flash('Best and worst cannot be the same item.', 'error')
        else:
            # Save answer
            answer = Answer(
                set_index=current_set,
                best_item_id=int(best_id),
                worst_item_id=int(worst_id),
                response_id=response.id
            )
            answer.item_ids = sets[current_set]
            db.session.add(answer)
            db.session.commit()

            # Move to next set
            session['survey_current_set'] = current_set + 1
            return redirect(url_for('survey_question', token=token))

    # Get current items
    current_item_ids = sets[current_set]
    items = Item.query.filter(Item.id.in_(current_item_ids)).all()
    # Sort items to match the order in the set
    items_dict = {item.id: item for item in items}
    items = [items_dict[id] for id in current_item_ids if id in items_dict]

    return render_template('survey/question.html',
                         study=study,
                         token=token,
                         items=items,
                         current_set=current_set + 1,
                         total_sets=len(sets),
                         is_preview=is_preview)


@app.route('/survey/<token>/questions', methods=['GET', 'POST'])
def survey_custom_questions(token):
    study = Study.query.filter_by(share_token=token).first_or_404()
    is_preview = session.get('survey_is_preview', False)

    # Allow ACTIVE or preview mode
    if study.status not in ['ACTIVE', 'DRAFT'] and not is_preview:
        return redirect(url_for('survey_start', token=token))

    response_id = session.get('survey_response_id')
    current_index = session.get('survey_custom_question_index', 0)

    if not response_id:
        return redirect(url_for('survey_start', token=token))

    response = Response.query.get_or_404(response_id)
    custom_questions = study.custom_questions.order_by(CustomQuestion.order).all()

    if not custom_questions or current_index >= len(custom_questions):
        # No more custom questions, proceed to MaxDiff
        return redirect(url_for('survey_question', token=token))

    current_question = custom_questions[current_index]

    if request.method == 'POST':
        # Get the answer based on question type
        answer_text = None
        answer_value = None
        answer_option_ids = None
        has_answer = False

        if current_question.question_type == 'text':
            answer_text = request.form.get('answer_text', '').strip()
            has_answer = bool(answer_text)
        elif current_question.question_type == 'rating_scale':
            rating = request.form.get('rating')
            if rating:
                answer_value = int(rating)
                has_answer = True
        elif current_question.question_type == 'single_choice':
            option_id = request.form.get('option_id')
            if option_id:
                answer_option_ids = [int(option_id)]
                has_answer = True
        elif current_question.question_type == 'multiple_choice':
            option_ids = request.form.getlist('option_ids')
            if option_ids:
                answer_option_ids = [int(oid) for oid in option_ids]
                has_answer = True

        # Validate required questions
        if current_question.is_required and not has_answer:
            flash('This question is required.', 'error')
        else:
            # Save the answer (even if empty for optional questions)
            if has_answer:
                answer = CustomQuestionAnswer(
                    response_id=response.id,
                    question_id=current_question.id,
                    answer_text=answer_text,
                    answer_value=answer_value
                )
                if answer_option_ids:
                    answer.answer_option_ids = answer_option_ids
                db.session.add(answer)
                db.session.commit()

            # Move to next question
            session['survey_custom_question_index'] = current_index + 1
            return redirect(url_for('survey_custom_questions', token=token))

    # Get options for choice questions
    options = []
    if current_question.question_type in ['single_choice', 'multiple_choice']:
        options = current_question.options.order_by(CustomQuestionOption.order).all()

    return render_template('survey/custom_question.html',
                         study=study,
                         token=token,
                         question=current_question,
                         options=options,
                         current_index=current_index + 1,
                         total_questions=len(custom_questions),
                         is_preview=is_preview)


@app.route('/survey/<token>/complete')
def survey_complete(token):
    study = Study.query.filter_by(share_token=token).first_or_404()
    is_preview = session.pop('survey_is_preview', False)
    session.pop('survey_custom_question_index', None)
    return render_template('survey/complete.html', study=study, is_preview=is_preview)


# ============== API Routes ==============

@app.route('/api/study/<int:id>/items', methods=['POST'])
@login_required
def api_add_item(id):
    study = Study.query.filter_by(id=id, user_id=current_user.id).first_or_404()

    data = request.get_json()
    name = str(data.get('name', '') or '').strip()
    description = str(data.get('description', '') or '').strip()

    if not name:
        return jsonify({'error': 'Item name is required'}), 400

    # Check for duplicate
    existing_item = Item.query.filter_by(study_id=study.id, name=name).first()
    if existing_item:
        return jsonify({'error': f'Item "{name}" already exists. Please use a unique name.'}), 400

    max_order = db.session.query(db.func.max(Item.order)).filter_by(study_id=study.id).scalar() or 0
    item = Item(name=name, description=description if description else None, order=max_order + 1, study_id=study.id)
    db.session.add(item)
    db.session.commit()

    return jsonify({'id': item.id, 'name': item.name, 'description': item.description, 'order': item.order})


@app.route('/api/study/<int:id>/items/<int:item_id>', methods=['PUT', 'DELETE'])
@login_required
def api_item(id, item_id):
    study = Study.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    item = Item.query.filter_by(id=item_id, study_id=study.id).first_or_404()

    if request.method == 'DELETE':
        db.session.delete(item)
        db.session.commit()
        return jsonify({'success': True})

    if request.method == 'PUT':
        data = request.get_json()
        name = str(data.get('name', '') or '').strip()
        description = str(data.get('description', '') or '').strip()
        if name:
            # Check for duplicate (excluding current item)
            existing_item = Item.query.filter_by(study_id=study.id, name=name).filter(Item.id != item.id).first()
            if existing_item:
                return jsonify({'error': f'Item "{name}" already exists. Please use a unique name.'}), 400
            item.name = name
            item.description = description if description else None
            db.session.commit()
            return jsonify({'id': item.id, 'name': item.name, 'description': item.description})
        return jsonify({'error': 'Item name is required'}), 400


if __name__ == '__main__':
    app.run(debug=True, port=5001)
