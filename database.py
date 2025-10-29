from models import db, User
from werkzeug.security import generate_password_hash


def init_db():
    db.create_all()

    # Create default admin user if doesn't exist
    if not User.query.filter_by(username='admin').first():
        admin_user = User(
            username='admin',
            password=generate_password_hash('admin123')  # Change this password!
        )
        db.session.add(admin_user)
        db.session.commit()
        print("Default admin user created: admin/admin123")