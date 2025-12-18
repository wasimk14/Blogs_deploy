import os
import pandas
from datetime import date
from tokenize import Comment
from flask import Flask
from flask_gravatar import Gravatar


from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor, CKEditorField
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, func
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from sqlalchemy import ForeignKey

# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
Bootstrap5(app)

ckeditor = CKEditor(app)

# Folder for CSV + downloadable files
REPORT_FOLDER = os.path.join(app.root_path, "static", "files")
os.makedirs(REPORT_FOLDER, exist_ok=True)

# TODO: Configure Flask-Login
# -----------------------------------
# LOGIN MANAGER
# -----------------------------------
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DB_URI',
    'sqlite:///' + os.path.join(app.instance_path, 'posts.db')
)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# CONFIGURE TABLE
class BlogPost(db.Model):
    __tablename__ = "blog_posts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    # Foreign key
    author_id: Mapped[int] = mapped_column(Integer,db.ForeignKey("users.id"),nullable=False)

    # Relationship
    author = relationship("User", back_populates="posts")
    comments = db.relationship("Comment", back_populates="post", cascade="all, delete")


    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}

# TODO: Create a User table for all your registered users.
# User table for registered users
class User(UserMixin, db.Model):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(250), nullable=False)
    is_admin: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    posts = relationship("BlogPost", back_populates="author")
    comments = db.relationship("Comment", back_populates="author")

class Comment(db.Model):
    __tablename__ = "comments"

    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))

    author = db.relationship("User", back_populates="comments")
    post = db.relationship("BlogPost", back_populates="comments")

with app.app_context():
    db.create_all()

class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    date = StringField("Date", validators=[DataRequired()])
    author = StringField("Your Name", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    use_ssl=False,
                    base_url=None)

# -----------------------------------
# ADMIN DECORATOR
# -----------------------------------
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))

        if not current_user.is_admin:
            flash("Access denied. Admins only.", "danger")
            return redirect(url_for("get_all_posts"))

        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def get_all_posts():
    # TODO: Query the database for all the posts. Convert the data to a python list.
    blogs = BlogPost.query.all()
    return render_template("index.html", blogs=blogs)

# TODO: Use Werkzeug to hash the user's password when creating a new user.
from flask import request  # make sure this is imported

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():

        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("An account with this email already exists.", "warning")
            return redirect(url_for('register'))

        # Hash password
        hashed_password = generate_password_hash(
            form.password.data,
            method="pbkdf2:sha256"
        )

        # Create user
        new_user = User(
            username=form.name.data,
            email=form.email.data,
            password=hashed_password
        )

        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)

        # ---------------------------------------
        # Append registration log to users.csv
        # ---------------------------------------
        csv_path = os.path.join(REPORT_FOLDER, "users.csv")

        row = pandas.DataFrame([{
            "id": new_user.id,
            "email": new_user.email,
            "password": new_user.password,
            "username": new_user.username
        }])

        if not os.path.isfile(csv_path):
            row.to_csv(csv_path, index=False)
        else:
            row.to_csv(csv_path, mode="a", index=False, header=False)

        flash("Registration successful.", "success")
        return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=form)


# TODO: Retrieve a user from the database based on their email.
# Retrieve a user from the database based on their email.
@app.route('/login', methods=['GET', 'POST'])
def login():
    # if current_user.is_authenticated:
    #     flash("You are already logged in.")
    #     return redirect(url_for('get_all_posts'))

    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()

        if user is None:
            flash("Please register first.", "warning")
            return redirect(url_for('register'))

        if check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('get_all_posts'))

        flash("Login failed. Incorrect password.", "danger")

    return render_template("login.html", form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    db.session.commit()
    return redirect(url_for('login'))

# TODO: Add a route so that you can click on individual posts.
@app.route("/post/<int:blog_id>", methods=["GET", "POST"])
def show_post(blog_id):
    post = BlogPost.query.get_or_404(blog_id)
    form = CommentForm()

    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("Login required to comment.", "warning")
            return redirect(url_for("login"))

        new_comment = Comment(
            text=form.comment.data,
            author=current_user,
            post=post
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post", blog_id=blog_id))

    return render_template("post.html", post=post, form=form)


# TODO: add_new_post() to create a new blog post

@app.route("/new-post", methods=["GET", "POST"])
@admin_required
def new_post():
    form = CreatePostForm()

    if form.validate_on_submit():
        new_blog = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            date = form.date.data,
            img_url=form.img_url.data,
            body=form.body.data,
            author=current_user
        )
        db.session.add(new_blog)
        db.session.commit()
        return redirect(url_for("get_all_posts"))

    return render_template("make-post.html", form=form)

# TODO: edit_post() to change an existing blog post
@app.route("/edit/<int:blog_id>", methods=["GET", "POST"])
@admin_required
def edit_post(blog_id):
    post = BlogPost.query.get_or_404(blog_id)

    # Pre-fill form with existing blog data on GET request
    form = CreatePostForm(obj=post)

    if form.validate_on_submit():
        post.title = form.title.data
        post.subtitle = form.subtitle.data
        post.date = form.date.data
        post.body = form.body.data
        post.img_url = form.img_url.data
        author = current_user

        db.session.commit()
        return redirect(url_for("get_all_posts", blog_id=post.id))

    return render_template("make-post.html", form=form, is_edit=True)

# TODO: delete_post() to remove a blog post from the database
@app.route("/delete/<int:blog_id>", methods=["GET", "POST"])
@admin_required
def delete_post(blog_id):
    post = BlogPost.query.get_or_404(blog_id)
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for("get_all_posts", blog_id=post.id))

@app.route("/delete-comment/<int:comment_id>")
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)

    if current_user.id != comment.author_id and not current_user.is_admin:
        abort(403)

    db.session.delete(comment)
    db.session.commit()
    flash("Comment deleted.", "success")
    return redirect(url_for("show_post", blog_id=comment.post_id))


@app.route("/edit-comment/<int:comment_id>", methods=["GET", "POST"])
@login_required
def edit_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)

    if current_user.id != comment.author_id:
        abort(403)

    form = CommentForm(obj=comment)

    if form.validate_on_submit():
        comment.text = form.comment.data
        db.session.commit()
        flash("Comment updated.", "success")
        return redirect(url_for("show_post", blog_id=comment.post_id))

    return render_template("edit-comment.html", form=form)


# Below is the code from previous lessons. No changes needed.
@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True, port=5003)
