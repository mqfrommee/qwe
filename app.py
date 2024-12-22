from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_login import current_user, LoginManager, login_user, UserMixin, login_required
import random
import logging
from functools import wraps
import re
import os
from flask_migrate import Migrate

app = Flask(__name__)
app.secret_key = 'secret_key_for_security'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quotes.db' #бд 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

static_folder = os.path.join(os.path.dirname(__file__), 'static')

logging.basicConfig(level=logging.DEBUG)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

#модели бд
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')
    date_registered = db.Column(db.DateTime, default=datetime.utcnow)
    
    liked_quotes = db.relationship('UserLikes', back_populates='user_like', lazy='dynamic')  


class Quote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(100), nullable=False)
    likes = db.Column(db.Integer, default=0)
    views = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=False)
    
    category = db.relationship('Category', back_populates='quotes_list')
    user_likes = db.relationship('UserLikes', back_populates='quote')


class UserLikes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quote_id = db.Column(db.Integer, db.ForeignKey('quote.id', ondelete='CASCADE'), nullable=False)

    user_like = db.relationship('User', back_populates='liked_quotes')  # Изменено здесь
    quote = db.relationship('Quote', back_populates='user_likes')


class Category(db.Model):
    __tablename__ = 'categories'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    quotes_list = db.relationship('Quote', back_populates='category')

class RoleRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    requested_role = db.Column(db.String(20), nullable=False, default='editor')
    status = db.Column(db.String(20), nullable=False, default='pending')  
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='role_requests')

def emit(self, record):
    raise NotImplementedError('emit must be implemented')

# загрузка пользователя
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#зявки на смену роли(подтверждение)
@app.route('/admin/role_requests', methods=['GET'])
def role_requests():
    if 'user_role' not in session or session['user_role'] != 'admin':
        flash('Доступ запрещён. Требуется роль администратора.', 'danger')
        return redirect(url_for('profile'))  

    requests = RoleRequest.query.filter_by(status='pending').all()
    return render_template('role_requests.html', requests=requests)

#форма входа 
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            session['user_role'] = user.role  
            session['user_id'] = user.id      
            if user.role == 'admin':
                return redirect(url_for('admin'))  
            return redirect(url_for('profile')) 

        flash('Неверное имя пользователя или пароль.', 'danger')
        return redirect(url_for('login'))

    return render_template('login.html')

#форма регистрации пользователя

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not email or not password or not confirm_password:
            flash('Все поля обязательны для заполнения.', 'danger')
            return redirect(url_for('register'))

        if len(username) < 6:
            flash('Логин должен содержать не менее 6 символов.', 'danger')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Пароли не совпадают.', 'danger')
            return redirect(url_for('register'))

        password_pattern = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[#@<.!?]).{8,12}$'
        if not re.match(password_pattern, password):
            flash('Пароль должен содержать от 8 до 12 символов, включая заглавные и строчные буквы, цифры и специальные символы.', 'danger')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(username=username).first()
        existing_user_email = User.query.filter_by(email=email).first()

        if existing_user:
            flash('Пользователь с таким именем уже существует.', 'danger')
            return redirect(url_for('register'))

        if existing_user_email:
            flash('Пользователь с таким email уже существует.', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()

            flash('Регистрация прошла успешно!', 'success')
            login_user(new_user) 
            session['user_role'] = new_user.role 
            return redirect(url_for('profile')) 

        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при регистрации. Попробуйте снова. Детали: {str(e)}', 'danger')

    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('login'))

#главная страница
@app.route('/')
@login_required
def home():
    popular_quotes = Quote.query.order_by(Quote.likes.desc()).limit(3).all()  
    if not popular_quotes:
        flash("Нет популярных цитат для отображения.", "info")
    
    latest_quotes = Quote.query.order_by(Quote.id.desc()).limit(3).all()      
    if not latest_quotes:
        flash("Нет новых цитат для отображения.", "info")

    recommended_quotes = Quote.query.order_by(db.func.random()).limit(3).all()  
    if not recommended_quotes:
        flash("Нет рекомендуемых цитат для отображения.", "info")
    
    categories = db.session.query(Category, db.func.count(Quote.id).label('quotes_count')) \
                           .join(Quote, Quote.category_id == Category.id, isouter=True) \
                           .group_by(Category.id) \
                           .all()

    return render_template(
        'home.html',
        popular_quotes=popular_quotes,
        latest_quotes=latest_quotes,
        recommended_quotes=recommended_quotes,
        categories=categories 
    )

@app.route('/random_quote')
@login_required
def random_quote():
    random_category = Category.query.order_by(db.func.random()).first()
    
    if not random_category:
        return "Нет доступных категорий", 404
    
    random_quote = Quote.query.filter_by(category_id=random_category.id).order_by(db.func.random()).first()
    
    if not random_quote:
        return "Цитаты в этой категории не найдены", 404
    
    return render_template('random_quote.html', quote=random_quote, category_name=random_category.name)


@app.route('/quotes')
@login_required
def all_quotes():
    quotes = Quote.query.order_by(Quote.id.desc()).all() 
    return render_template('all_quotes.html', quotes=quotes)

@app.route('/search')
@login_required
def search():
    query = request.args.get('query')  
    if query:
        results = Quote.query.filter(Quote.text.contains(query)).all()
    else:
        results = []
    
    return render_template('search_results.html', query=query, results=results)

@app.route('/quote/<int:quote_id>', methods=['GET', 'POST'])
@login_required
def view_quote(quote_id):
    quote = Quote.query.get_or_404(quote_id)

    quote.views += 1
    db.session.commit()

    if request.method == 'POST':
        logging.debug(f"Current user: {current_user.id if current_user.is_authenticated else 'Not authenticated'}")
        if current_user.is_authenticated:
            existing_like = UserLikes.query.filter_by(user_id=current_user.id, quote_id=quote.id).first()
            if not existing_like:
                new_like = UserLikes(user_id=current_user.id, quote_id=quote.id)
                db.session.add(new_like)
                quote.likes += 1
                db.session.commit()
                logging.debug(f"User   {current_user.id} liked quote {quote.id}.")
            else:
                logging.debug(f"User   {current_user.id} already liked quote {quote.id}.")
        else:
            logging.debug("User not authenticated.")

    return render_template('quote.html', quote=quote)


@app.route('/add_quote', methods=['GET', 'POST'])
@login_required
def add_quote():
    if request.method == 'POST':
        text = request.form['content']  
        author = request.form['author']  
        category_id = request.form['category']
        
        if not author:
            flash('Пожалуйста, укажите автора цитаты!', 'danger')
            return redirect(url_for('add_quote'))
        
        category = Category.query.get(category_id)
        if not category:
            flash('Категория не найдена.', 'danger')
            return redirect(url_for('add_quote'))

        try:
            new_quote = Quote(text=text, author=author, category_id=category_id, user_id=current_user.id)
            db.session.add(new_quote)
            db.session.commit()
            flash('Цитата успешно добавлена!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при добавлении цитаты: {str(e)}', 'danger')

    categories = Category.query.all()
    return render_template('add_quote.html', categories=categories)


@app.route('/category/<string:category_name>')
@login_required
def category(category_name):
    category = Category.query.filter_by(name=category_name).first()
    if not category:
        return "Category not found", 404
    quotes = category.quotes_list
    return render_template('category.html', quotes=quotes, category_name=category_name)

@app.route('/add_category', methods=['GET', 'POST'])
@login_required
def add_category():
    if request.method == 'POST':
        name = request.form.get('category_name')
        if not name:
            flash('Поле Название категории обязательно.', 'danger')
            return redirect(url_for('add_category'))

        try:
            new_category = Category(name=name)
            db.session.add(new_category)
            db.session.commit()
            flash('Категория успешно добавлена!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при добавлении категории: {str(e)}', 'danger')
        
    return render_template('add_category.html')

@app.route('/like/<int:quote_id>', methods=['POST'])
@login_required
def like_quote(quote_id):
    if 'user_id' not in session:
        flash('Войдите, чтобы ставить лайки.', 'info')
        return redirect(url_for('login'))

    user_id = session['user_id']
    like = UserLikes.query.filter_by(user_id=user_id, quote_id=quote_id).first()
    if like:
        flash('Вы уже лайкнули эту цитату.', 'info')
    else:
        new_like = UserLikes(user_id=user_id, quote_id=quote_id)
        quote = Quote.query.get(quote_id)
        quote.likes += 1
        db.session.add(new_like)
        db.session.commit()
        flash('Цитата лайкнута!', 'success')
    return redirect(url_for('view_quote', quote_id=quote_id))

@app.route('/profile')
@login_required
def profile():
    user_quotes = Quote.query.filter_by(user_id=current_user.id).all()
    if current_user.role in ['admin', 'editor']:
        all_user_quotes = user_quotes
    else:
        all_user_quotes = []
    liked_quotes = Quote.query.join(UserLikes).filter(UserLikes.user_id == current_user.id).all()

    return render_template('profile.html', 
                           user=current_user, 
                           datetime=datetime, 
                           user_quotes=all_user_quotes, 
                           liked_quotes=liked_quotes)


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Доступ запрещён. Требуется роль администратора.', 'danger')
            return redirect(url_for('login')) 
        return f(*args, **kwargs)  
    return decorated_function

@app.route('/admin', methods=['GET', 'POST'])
@admin_required  
def admin():
    categories = Category.query.all()
    users = User.query.all()
    quotes = Quote.query.all()
    query = request.args.get('query', '')
    search_type = request.args.get('search_type', 'all')

    if query:
        if search_type == 'category':
            categories = Category.query.filter(Category.name.contains(query)).all()
        elif search_type == 'user':
            users = User.query.filter(User.username.contains(query) | User.email.contains(query)).all()
        elif search_type == 'quote':
            quotes = Quote.query.filter(Quote.text.contains(query)).all()
        else:
            categories = Category.query.filter(Category.name.contains(query)).all()
            users = User.query.filter(User.username.contains(query) | User.email.contains(query)).all()
            quotes = Quote.query.filter(Quote.text.contains(query)).all()

    return render_template(
        'admin.html',
        categories=categories,
        users=users,
        quotes=quotes,
        query=query,
        search_type=search_type
    )

@app.route('/admin/delete_category/<int:category_id>', methods=['POST'])
@admin_required
def delete_category(category_id):
    category = Category.query.get_or_404(category_id)
    
    quotes = Quote.query.filter_by(category_id=category_id).all()
    for quote in quotes:
        db.session.delete(quote)

    try:
        db.session.delete(category)
        db.session.commit()
        flash('Категория успешно удалена.', 'success')
    except Exception as e:
        db.session.rollback() 
        flash(f'Ошибка при удалении категории: {e}', 'danger')

    return redirect(url_for('admin')) 

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    role_requests = RoleRequest.query.filter_by(user_id=user_id).all()
    for request in role_requests:
        db.session.delete(request)

    user_likes = UserLikes.query.filter_by(user_id=user_id).all()
    for like in user_likes:
        db.session.delete(like)

    try:
        db.session.delete(user)
        db.session.commit()
        flash('Пользователь успешно удалён.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при удалении пользователя: {str(e)}', 'danger')
    
    return redirect(url_for('admin'))  

@app.route('/admin/delete_quote/<int:quote_id>', methods=['POST'])
@admin_required
def delete_quote(quote_id):
    quote = Quote.query.get_or_404(quote_id)
    user_likes = UserLikes.query.filter_by(quote_id=quote_id).all()
    for like in user_likes:
        db.session.delete(like)

    try:
        db.session.delete(quote)
        db.session.commit()  
        flash('Цитата успешно удалена.', 'success')
    except Exception as e:
        db.session.rollback() 
        flash(f'Ошибка при удалении цитаты: {str(e)}', 'danger')

    return redirect(url_for('admin'))

@app.route('/admin/approve_request/<int:request_id>', methods=['POST'])
@admin_required
def approve_request(request_id):
    if 'user_role' not in session or session['user_role'] != 'admin':
        flash('Доступ запрещён.', 'danger')
        return redirect(url_for('home'))

    role_request = RoleRequest.query.get_or_404(request_id)
    user = User.query.get(role_request.user_id)

    if user:
        user.role = role_request.requested_role
        role_request.status = 'approved'
        db.session.commit()
        flash(f'Роль пользователя {user.username} успешно обновлена.', 'success')

    return redirect(url_for('role_requests'))

#отклонение смены роли
@app.route('/admin/reject_request/<int:request_id>', methods=['POST'])
@admin_required
def reject_request(request_id):
    if 'user_role' not in session or session['user_role'] != 'admin':
        flash('Доступ запрещён.', 'danger')
        return redirect(url_for('home'))

    role_request = RoleRequest.query.get_or_404(request_id)
    role_request.status = 'rejected'
    db.session.commit()
    flash(f'Заявка отклонена.', 'info')

    return redirect(url_for('role_requests'))

#подача заявки на смену роли
@app.route('/request_role', methods=['GET', 'POST'])
def request_role():
    try:
        if not current_user.is_authenticated:
            flash('Войдите, чтобы отправить заявку.', 'info')
            return redirect(url_for('login'))

        if current_user.role != 'user':
            flash('Вы уже обладаете специальной ролью.', 'info')
            return redirect(url_for('profile'))

        existing_request = RoleRequest.query.filter_by(user_id=current_user.id, status='pending').first()
        if existing_request:
            flash('Вы уже подали заявку. Ожидайте решения.', 'info')
            return redirect(url_for('profile'))

        if request.method == 'POST':
            role_request = RoleRequest(user_id=current_user.id)
            db.session.add(role_request)
            db.session.commit()
            flash('Ваша заявка отправлена. Ожидайте решения.', 'success')
            return redirect(url_for('profile'))

    except Exception as e:
        flash(f'Произошла ошибка: {str(e)}', 'danger')

    return render_template('request_role.html', user=current_user)

#footer
@app.route('/info_project')
@login_required
def info_project():
    return render_template('info_project.html')

@app.route('/contact')
@login_required
def contact():
    return render_template('contact.html')

@app.route('/rules')
@login_required
def rules():
    return render_template('rules.html')

@app.route('/musarskoe')
@login_required
def musarskoe():
    return render_template('musarskoe.html')

@app.route('/favicon.ico')
def favicon_ico():
    return send_from_directory(app.static_folder, 'favicon.ico', mimetype='image/x-icon')

@app.route('/favicon.png')
def favicon_png():
    return send_from_directory(app.static_folder, 'favicon.png', mimetype='image/png')

if __name__ == '__main__':
    with app.app_context():
        db.create_all() 
    app.run(debug=True)