from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
from forms import CreatePostForm, RegisterUserForm, LoginForm, CommentForm  # import forms from forms.py


app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO 1: configure flask-login (4 parts: from class, initialize app, protect session, load user)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.session_protection = "strong"


@login_manager.user_loader  # create the user_loader callback
def load_user(user_id):
    return db.get_or_404(User, user_id)


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'  # connect to db
db = SQLAlchemy()
db.init_app(app)


# TODO 2: create a User table for all registered users
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    name = db.Column(db.String(100))
    password = db.Column(db.String(100))

    #  acts like a list of BlogPost objects attached to each User:
    posts = relationship("BlogPost", back_populates="author")  # 🚨
    #  where "author" refers to the author property in the BlogPost class

    comments = relationship("Comment", back_populates="comment_author")  # 🚨


class BlogPost(db.Model):  # configure tables
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    #  new - fk to User
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    #  new - create ref to User object; "posts" are posts property in User class
    author = relationship("User", back_populates="posts")  # 🚨
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    #  parent relationship *new*:
    comments = relationship("Comment", back_populates="parent_post")  # 🚨 parent_post is just
    # requested_post 👀


class Comment(db.Model):  # Comment class
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    #  new - fk to User
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    #  new - create ref to User object; "posts" are posts property in User class
    comment_author = relationship("User", back_populates="comments")  # 🚨
    #  child relationships *new*:
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")  # 🚨 aka requested_post
    comment = db.Column(db.Text, nullable=False)


with app.app_context():
    db.create_all()


# TODO 3: use werkzeug to hash the user's password when creating a new user
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterUserForm()
    if form.validate_on_submit():  # first check whether they've previously registered
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        user = result.scalar()
        if user:  # ...already exists in our db, then:
            flash("You are already registered. Please log in.")
            return redirect(url_for('login', form=form))

        hashed_salted_pw = generate_password_hash(  # if not, add user:
            form.password.data,
            method="scrypt",
            salt_length=17
        )
        new_user = User(
            name=form.name.data,
            email=form.email.data,
            password=hashed_salted_pw,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)  # authenticates the user with flask-login
        return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=form, current_user=current_user)


# TODO 4: retrieve a user from the database based on their email
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        password = form.password.data
        email = form.email.data
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()  # should just be one (or zero) results here
        if not user:
            flash("Bad email/password combination. \nEnsure you're registered before logging in.")
            return redirect(url_for('login'))

        elif not check_password_hash(user.password, password):
            flash("Bad email/password combination. \nEnsure you're registered before logging in.")
            return redirect(url_for('login'))

        else:  # deleted code from previous step compared entered pw w/existing hashed/salted pw
            login_user(user)
            return redirect(url_for('get_all_posts'))
    return render_template("login.html", form=form, current_user=current_user)
#  should this be current_user=current_user?


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    index = render_template("index.html")
    # return index  # when debugging "Angela's Revenge," have to do it this way 🥫
    return render_template("index.html", all_posts=posts, current_user=current_user)


# TODO 5: allow logged-in users to comment on posts / first, add profile images for comments
gravatar = Gravatar(app,
                    size=100,
                    rating='r',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
@login_required
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    form = CommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You must be logged in to comment")
            return redirect(url_for('login'))
        new_comment = Comment(
            comment=form.comment.data,
            comment_author=current_user,
            parent_post=requested_post,
        )
        db.session.add(new_comment)
        db.session.commit()
    return render_template("post.html", post=requested_post, current_user=current_user, form=form)


# TODO 6: write a decorator so only an admin can create a new post
def admin_only(f):
    @wraps(f)
    @login_required  # imported this from flask_login
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)  # otherwise, it's okay to proceed with the route
    return decorated_function


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


# TODO 7: use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)


# TODO 8: use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", current_user=current_user)


if __name__ == "__main__":
    app.run(debug=True, port=5002)
