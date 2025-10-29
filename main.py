from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
import sqlite3
from PIL import Image
import functools


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['DATABASE'] = 'math_blog.db'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024


# Database setup
def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn


@app.route('/fix-database')
def fix_database():
    """Temporary route to fix database schema"""
    update_database_schema()
    return "Database schema updated! You can now use the contact form."


def init_db():
    with app.app_context():
        db = get_db()

        # Users table
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Posts table
        db.execute('''
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                topic TEXT NOT NULL,
                difficulty TEXT,
                image_path TEXT,
                is_published BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Comments table
        db.execute('''
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                author_name TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (post_id) REFERENCES posts (id)
            )
        ''')

        # Contact messages table - updated with all columns
        db.execute('''
            CREATE TABLE IF NOT EXISTS contact_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                subject TEXT NOT NULL,
                message TEXT NOT NULL,
                image_path TEXT,
                is_urgent BOOLEAN DEFAULT FALSE,
                is_read BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Create default admin user if doesn't exist
        admin_exists = db.execute('SELECT id FROM users WHERE username = ?', ('admin',)).fetchone()
        if not admin_exists:
            db.execute(
                'INSERT INTO users (username, password) VALUES (?, ?)',
                ('admin', generate_password_hash('admin123'))
            )
            print("Default admin user created: admin/admin123")

        db.commit()

        # Update schema if needed
        update_database_schema()


# Login required decorator
def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def save_image(image_file):
    if image_file and image_file.filename:
        filename = secure_filename(image_file.filename)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{filename}"

        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        try:
            image = Image.open(image_file)
            image.thumbnail((800, 800))
            image.save(filepath)
            return filename
        except Exception as e:
            print(f"Error saving image: {e}")
            return None
    return None


# Routes


@app.route('/post/<int:post_id>')
def show_post(post_id):
    db = get_db()
    post = db.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()

    if not post:
        return "Post not found", 404

    if not post['is_published'] and 'user_id' not in session:
        return "Post not found", 404

    comments = db.execute(
        'SELECT * FROM comments WHERE post_id = ? ORDER BY created_at',
        (post_id,)
    ).fetchall()

    return render_template('post.html', post=post, comments=comments)


@app.route('/post/<int:post_id>/comment', methods=['POST'])
def add_comment(post_id):
    author_name = request.form.get('author_name')
    content = request.form.get('content')

    if author_name and content:
        db = get_db()
        db.execute(
            'INSERT INTO comments (post_id, author_name, content) VALUES (?, ?, ?)',
            (post_id, author_name, content)
        )
        db.commit()
        flash('Your comment has been posted!', 'success')

    return redirect(url_for('show_post', post_id=post_id))


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        subject = request.form.get('subject')
        message = request.form.get('message')
        urgent = 'urgent' in request.form

        if name and email and subject and message:
            db = get_db()

            # Handle photo upload
            photo_file = request.files.get('problem_photo')
            photo_filename = None

            if photo_file and photo_file.filename:
                photo_filename = save_image(photo_file)

            try:
                # Try to insert with all columns (including is_urgent and image_path)
                db.execute(
                    '''INSERT INTO contact_messages (name, email, subject, message, image_path, is_urgent) 
                    VALUES (?, ?, ?, ?, ?, ?)''',
                    (name, email, subject, message, photo_filename, urgent)
                )
            except sqlite3.OperationalError as e:
                if "no such column: is_urgent" in str(e):
                    # Fallback: insert without the new columns
                    db.execute(
                        '''INSERT INTO contact_messages (name, email, subject, message, image_path) 
                        VALUES (?, ?, ?, ?, ?)''',
                        (name, email, subject, message, photo_filename)
                    )
                    print("Warning: Using fallback insert (is_urgent column missing)")
                else:
                    # Re-raise other operational errors
                    raise

            db.commit()
            flash('Your message has been sent! I\'ll get back to you soon.', 'success')
            return redirect(url_for('contact'))
        else:
            flash('Please fill in all required fields.', 'danger')

    return render_template('contact.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        db = get_db()
        user = db.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Login unsuccessful. Please check username and password.', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


# Admin routes
@app.route('/admin')
@login_required
def admin_dashboard():
    db = get_db()

    posts_count = db.execute('SELECT COUNT(*) FROM posts').fetchone()[0]
    comments_count = db.execute('SELECT COUNT(*) FROM comments').fetchone()[0]
    unread_messages = db.execute('SELECT COUNT(*) FROM contact_messages WHERE is_read = FALSE').fetchone()[0]

    return render_template('admin/dashboard.html',
                           posts_count=posts_count,
                           comments_count=comments_count,
                           unread_messages=unread_messages)


@app.route('/admin/posts/new', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':
        title = request.form.get('title')
        topic = request.form.get('topic')
        difficulty = request.form.get('difficulty')
        content = request.form.get('content')
        is_published = 'is_published' in request.form  # This should be True if checkbox is checked

        print(f"Creating post: {title}, Published: {is_published}")  # Debug print

        if title and topic and content:
            db = get_db()

            # Handle image upload
            image_file = request.files.get('image')
            image_filename = save_image(image_file) if image_file and image_file.filename else None

            db.execute(
                '''INSERT INTO posts (title, topic, difficulty, content, image_path, is_published) 
                VALUES (?, ?, ?, ?, ?, ?)''',
                (title, topic, difficulty, content, image_filename, is_published)
            )
            db.commit()

            post_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]
            flash('Post created successfully!', 'success')
            return redirect(url_for('show_post', post_id=post_id))
        else:
            flash('Please fill in all required fields.', 'danger')

    return render_template('admin/create_post.html')


@app.route('/admin/messages')
@login_required
def view_messages():
    db = get_db()

    # Check if is_urgent column exists
    try:
        messages = db.execute(
            'SELECT * FROM contact_messages ORDER BY created_at DESC'
        ).fetchall()
    except sqlite3.OperationalError as e:
        if "no such column: is_urgent" in str(e):
            # Fallback: select without is_urgent
            messages = db.execute(
                'SELECT id, name, email, subject, message, image_path, is_read, created_at FROM contact_messages ORDER BY created_at DESC'
            ).fetchall()
            # Add default is_urgent value to each message
            for message in messages:
                message['is_urgent'] = False
        else:
            raise

    return render_template('admin/messages.html', messages=messages)


@app.route('/admin/message/<int:message_id>/read')
@login_required
def mark_message_read(message_id):
    db = get_db()
    db.execute(
        'UPDATE contact_messages SET is_read = TRUE WHERE id = ?',
        (message_id,)
    )
    db.commit()
    return redirect(url_for('view_messages'))


# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500


@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    topic = request.args.get('topic', '')
    difficulty = request.args.get('difficulty', '')

    db = get_db()

    # Build the query
    query = 'SELECT * FROM posts WHERE is_published = 1'
    params = []

    if topic:
        query += ' AND topic = ?'
        params.append(topic)

    # Handle difficulty filter
    if difficulty and difficulty != 'all':
        # Show posts with the selected difficulty OR posts marked as 'both'
        query += ' AND (difficulty = ? OR difficulty = ?)'
        params.extend([difficulty, 'both'])

    query += ' ORDER BY created_at DESC LIMIT 6 OFFSET ?'
    params.append((page - 1) * 6)

    posts = db.execute(query, params).fetchall()

    # Get total count for pagination
    count_query = 'SELECT COUNT(*) FROM posts WHERE is_published = 1'
    count_params = []
    if topic:
        count_query += ' AND topic = ?'
        count_params.append(topic)

    if difficulty and difficulty != 'all':
        count_query += ' AND (difficulty = ? OR difficulty = ?)'
        count_params.extend([difficulty, 'both'])

    total_posts = db.execute(count_query, count_params).fetchone()[0]
    total_pages = (total_posts + 5) // 6 if total_posts > 0 else 1

    return render_template('index.html',
                           posts=posts,
                           topic=topic,
                           difficulty=difficulty,
                           current_page=page,
                           total_pages=total_pages)


@app.route('/test/all-posts')
def test_all_posts():
    """Test route to show all published posts without filtering"""
    db = get_db()
    posts = db.execute('SELECT * FROM posts WHERE is_published = 1').fetchall()
    result = "<h1>All Published Posts</h1>"
    for post in posts:
        result += f"""
        <div style="border: 1px solid #ccc; margin: 10px; padding: 10px;">
            <h3>ID: {post['id']} - {post['title']}</h3>
            <p>Topic: {post['topic']}, Difficulty: {post['difficulty']}, Published: {post['is_published']}</p>
            <p>Created: {post['created_at']}</p>
        </div>
        """
    return result


@app.route('/test/query')
def test_query():
    """Test the exact query used in index"""
    db = get_db()
    query = 'SELECT * FROM posts WHERE is_published = 1 ORDER BY created_at DESC LIMIT 6 OFFSET 0'
    posts = db.execute(query).fetchall()
    result = "<h1>Query Test Results</h1>"
    result += f"<p>Query: {query}</p>"
    result += f"<p>Found {len(posts)} posts</p>"
    for post in posts:
        result += f"<p>ID {post['id']}: {post['title']}</p>"
    return result


@app.route('/debug/posts')
def debug_posts():
    db = get_db()
    posts = db.execute('SELECT * FROM posts').fetchall()
    result = "<h1>All Posts in Database</h1>"
    for post in posts:
        result += f"""
        <div style="border: 1px solid #ccc; margin: 10px; padding: 10px;">
            <h3>ID: {post['id']}</h3>
            <p><strong>Title:</strong> {post['title']}</p>
            <p><strong>Topic:</strong> {post['topic']}</p>
            <p><strong>Published:</strong> {post['is_published']}</p>
            <p><strong>Created:</strong> {post['created_at']}</p>
            <p><strong>Content Preview:</strong> {post['content'][:100]}...</p>
            <a href="/post/{post['id']}">View Post</a>
        </div>
        """
    return result


# Add this route for deleting posts
@app.route('/admin/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    db = get_db()

    # Get the post first to check if it exists and get image path
    post = db.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()

    if not post:
        flash('Post not found!', 'danger')
        return redirect(url_for('admin_dashboard'))

    try:
        # Delete associated comments first (to maintain referential integrity)
        db.execute('DELETE FROM comments WHERE post_id = ?', (post_id,))

        # Delete the post
        db.execute('DELETE FROM posts WHERE id = ?', (post_id,))
        db.commit()

        # Delete the associated image file if it exists
        if post['image_path']:
            try:
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], post['image_path'])
                if os.path.exists(image_path):
                    os.remove(image_path)
                    print(f"Deleted image file: {image_path}")
            except Exception as e:
                print(f"Error deleting image file: {e}")

        flash('Post deleted successfully!', 'success')

    except Exception as e:
        db.rollback()
        flash('Error deleting post!', 'danger')
        print(f"Error deleting post: {e}")

    return redirect(url_for('admin_dashboard'))


# Add a route to view all posts for management
@app.route('/admin/posts')
@login_required
def manage_posts():
    db = get_db()
    posts = db.execute('''
        SELECT posts.*, COUNT(comments.id) as comment_count 
        FROM posts 
        LEFT JOIN comments ON posts.id = comments.post_id 
        GROUP BY posts.id 
        ORDER BY posts.created_at DESC
    ''').fetchall()

    return render_template('admin/manage_posts.html', posts=posts)


# Edit post - display form
@app.route('/admin/post/<int:post_id>/edit', methods=['GET'])
@login_required
def edit_post(post_id):
    db = get_db()
    post = db.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()

    if not post:
        flash('Post not found!', 'danger')
        return redirect(url_for('manage_posts'))

    return render_template('admin/edit_post.html', post=post)


# Update post - process form
@app.route('/admin/post/<int:post_id>/edit', methods=['POST'])
@login_required
def update_post(post_id):
    db = get_db()

    # Verify post exists
    existing_post = db.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()
    if not existing_post:
        flash('Post not found!', 'danger')
        return redirect(url_for('manage_posts'))

    title = request.form.get('title')
    topic = request.form.get('topic')
    difficulty = request.form.get('difficulty')
    content = request.form.get('content')
    is_published = 'is_published' in request.form

    if title and topic and content:
        # Handle image upload
        image_file = request.files.get('image')
        image_filename = existing_post['image_path']  # Keep existing image by default

        if image_file and image_file.filename:
            # New image uploaded - save it and delete old one if exists
            new_image_filename = save_image(image_file)
            if new_image_filename:
                # Delete old image file
                if existing_post['image_path']:
                    try:
                        old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], existing_post['image_path'])
                        if os.path.exists(old_image_path):
                            os.remove(old_image_path)
                    except Exception as e:
                        print(f"Error deleting old image: {e}")
                image_filename = new_image_filename
        elif 'remove_image' in request.form and existing_post['image_path']:
            # Remove image if checkbox is checked
            try:
                old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], existing_post['image_path'])
                if os.path.exists(old_image_path):
                    os.remove(old_image_path)
            except Exception as e:
                print(f"Error deleting image: {e}")
            image_filename = None

        # Update the post
        db.execute('''
            UPDATE posts 
            SET title = ?, topic = ?, difficulty = ?, content = ?, 
                image_path = ?, is_published = ?, updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        ''', (title, topic, difficulty, content, image_filename, is_published, post_id))

        db.commit()
        flash('Post updated successfully!', 'success')
        return redirect(url_for('show_post', post_id=post_id))
    else:
        flash('Please fill in all required fields.', 'danger')
        return redirect(url_for('edit_post', post_id=post_id))


import os
from datetime import datetime


# Image management routes
@app.route('/admin/images')
@login_required
def manage_images():
    upload_folder = app.config['UPLOAD_FOLDER']
    images = []

    # Get all image files from uploads folder
    if os.path.exists(upload_folder):
        for filename in os.listdir(upload_folder):
            if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp')):
                filepath = os.path.join(upload_folder, filename)
                stat = os.stat(filepath)
                images.append({
                    'filename': filename,
                    'filepath': f'uploads/{filename}',
                    'size': round(stat.st_size / 1024, 1),  # KB
                    'created': datetime.fromtimestamp(stat.st_ctime),
                    'full_path': filepath
                })

    # Sort by creation time, newest first
    images.sort(key=lambda x: x['created'], reverse=True)

    return render_template('admin/manage_images.html', images=images)


@app.route('/admin/images/upload', methods=['POST'])
@login_required
def upload_image():
    if 'image' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('manage_images'))

    file = request.files['image']
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('manage_images'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # Add timestamp to make filename unique
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{filename}"

        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        try:
            # Resize image if it's too large
            image = Image.open(file)
            image.thumbnail((1200, 1200))  # Max dimensions
            image.save(filepath)

            flash(f'Image "{filename}" uploaded successfully!', 'success')
        except Exception as e:
            flash(f'Error processing image: {str(e)}', 'danger')
            return redirect(url_for('manage_images'))

    else:
        flash('Invalid file type. Allowed: PNG, JPG, JPEG, GIF, BMP, WEBP', 'danger')

    return redirect(url_for('manage_images'))


@app.route('/admin/images/delete/<filename>', methods=['POST'])
@login_required
def delete_image(filename):
    # Security check - prevent directory traversal
    filename = secure_filename(filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    if os.path.exists(filepath) and filepath.startswith(app.config['UPLOAD_FOLDER']):
        try:
            os.remove(filepath)
            flash(f'Image "{filename}" deleted successfully!', 'success')
        except Exception as e:
            flash(f'Error deleting image: {str(e)}', 'danger')
    else:
        flash('Image not found', 'danger')

    return redirect(url_for('manage_images'))


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'}


def update_database_schema():
    """Update database schema to include new columns"""
    db = get_db()

    # Check if is_urgent column exists in contact_messages table
    try:
        db.execute('SELECT is_urgent FROM contact_messages LIMIT 1')
    except sqlite3.OperationalError:
        # Column doesn't exist, so add it
        print("Adding is_urgent column to contact_messages table...")
        db.execute('ALTER TABLE contact_messages ADD COLUMN is_urgent BOOLEAN DEFAULT FALSE')

    # Check if image_path column exists in contact_messages table
    try:
        db.execute('SELECT image_path FROM contact_messages LIMIT 1')
    except sqlite3.OperationalError:
        # Column doesn't exist, so add it
        print("Adding image_path column to contact_messages table...")
        db.execute('ALTER TABLE contact_messages ADD COLUMN image_path TEXT')

    db.commit()
    print("Database schema updated successfully!")


@app.route('/admin/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        db = get_db()

        # Get current user
        user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

        # Verify current password
        if not check_password_hash(user['password'], current_password):
            flash('Current password is incorrect!', 'danger')
            return render_template('admin/change_password.html')

        # Check if new passwords match
        if new_password != confirm_password:
            flash('New passwords do not match!', 'danger')
            return render_template('admin/change_password.html')

        # Check password strength
        if len(new_password) < 6:
            flash('Password must be at least 6 characters long!', 'danger')
            return render_template('admin/change_password.html')

        # Update password
        db.execute(
            'UPDATE users SET password = ? WHERE id = ?',
            (generate_password_hash(new_password), session['user_id'])
        )
        db.commit()

        flash('Password changed successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('admin/change_password.html')


if __name__ == '__main__':
    # Initialize database and create tables
    init_db()

    # Create upload folder if i doesn't exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    app.run(host='0.0.0.0', port=5000, debug=False)