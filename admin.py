# make_admin.py
from main import app, db, User

with app.app_context():
    user = User.query.filter_by(email="wasimk14@umail.com").first()
    if user:
        user.is_admin = 1
        db.session.commit()
        print("Admin assigned")
