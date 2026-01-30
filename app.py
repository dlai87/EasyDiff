from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from datetime import datetime
import uuid
import json
import csv
import io
import os

from config import Config
from models import db, User, Study, Item, Response, Answer
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
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
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

        return redirect(url_for('study_edit', id=study.id))

    items = study.items.order_by(Item.order).all()
    share_url = url_for('survey_start', token=study.share_token, _external=True)

    # Calculate response stats for active/closed studies
    response_stats = {
        'total_started': Response.query.filter_by(study_id=study.id, is_preview=False).count(),
        'completed': Response.query.filter_by(study_id=study.id, is_preview=False).filter(Response.completed_at != None).count()
    }

    return render_template('study/edit.html', study=study, items=items, share_url=share_url, response_stats=response_stats)


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

    # Get all answers from completed responses
    answers = []
    for response in completed_responses:
        answers.extend(response.answers.all())

    # Calculate scores
    scores = calculate_scores(items, answers)
    ranked_items = get_ranked_items(scores)
    stats = get_response_statistics(responses)

    return render_template('study/results.html',
                         study=study,
                         ranked_items=ranked_items,
                         stats=stats,
                         scores=scores)


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
    writer.writerow(['Rank', 'Item', 'Normalized Score', 'Raw Score', 'Best Count', 'Worst Count', 'Appearances'])

    for rank, (item_id, data) in enumerate(ranked_items, 1):
        writer.writerow([
            rank,
            data['text'],
            data['normalized_score'],
            data['raw_score'],
            data['best_count'],
            data['worst_count'],
            data['appearances']
        ])

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


@app.route('/survey/<token>/complete')
def survey_complete(token):
    study = Study.query.filter_by(share_token=token).first_or_404()
    is_preview = session.pop('survey_is_preview', False)
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
