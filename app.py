import os
import datetime
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, render_template, request, flash, redirect, url_for, session
from flask_mysqldb import MySQL
from wtforms import Form, StringField, PasswordField, validators
from wtforms.fields import EmailField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from passlib.hash import sha256_crypt
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask_mail import Mail, Message
import plotly.graph_objects as go
from flask_caching import Cache
from flask_wtf.csrf import CSRFProtect
from wtforms import IntegerField
from flask_wtf import FlaskForm  # Use FlaskForm, not just For



# Load environment variables
load_dotenv()

app = Flask(__name__)
csrf = CSRFProtect(app)

# Configuration
app.config.update(
    SECRET_KEY=os.getenv('SECRET_KEY', 'default-secret-key'),
    MYSQL_HOST=os.getenv('MYSQL_HOST', 'localhost'),
    MYSQL_USER=os.getenv('MYSQL_USER', 'root'),
    MYSQL_PASSWORD=os.getenv('MYSQL_PASSWORD', 'Shivam@2911'),
    MYSQL_DB=os.getenv('MYSQL_DB', 'expense_tracker'),
    MAIL_SERVER=os.getenv('MAIL_SERVER', 'smtp.googlemail.com'),
    MAIL_PORT=os.getenv('MAIL_PORT', 587),
    MAIL_USE_TLS=os.getenv('MAIL_USE_TLS', True),
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),
    CACHE_TYPE=os.getenv('CACHE_TYPE', 'SimpleCache'),
    CACHE_DEFAULT_TIMEOUT=os.getenv('CACHE_DEFAULT_TIMEOUT', 300)
)

# Initialize extensions
mysql = MySQL(app)
mail = Mail(app)
cache = Cache(app)

# Database Models
class UserModel:
    @staticmethod
    def get_by_email(email):
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", [email])
        user = cur.fetchone()
        cur.close()
        return user

    @staticmethod
    def create_user(first_name, last_name, email, username, password):
        cur = mysql.connection.cursor()
        cur.execute(
            "INSERT INTO users(first_name, last_name, email, username, password) "
            "VALUES(%s, %s, %s, %s, %s)",
            (first_name, last_name, email, username, password)
        )
        mysql.connection.commit()
        cur.close()

class TransactionModel:
    @staticmethod
    def get_monthly_summary(user_id, year=None, month=None):
        cur = mysql.connection.cursor()
        
        year_condition = "AND YEAR(date) = %s" if year else ""
        month_condition = "AND MONTH(date) = %s" if month else ""
        
        query = f"""
            SELECT SUM(amount) as total 
            FROM transactions 
            WHERE user_id = %s {year_condition} {month_condition}
        """
        
        params = [user_id]
        if year:
            params.append(year)
        if month:
            params.append(month)
            
        cur.execute(query, params)
        result = cur.fetchone()
        cur.close()
        return result['total'] if result and 'total' in result and result['total'] else 0

    @staticmethod
    def get_transactions(user_id, year=None, month=None, limit=None):
        cur = mysql.connection.cursor()
        
        conditions = ["user_id = %s"]
        params = [user_id]
        
        if year:
            conditions.append("YEAR(date) = %s")
            params.append(year)
        if month:
            conditions.append("MONTH(date) = %s")
            params.append(month)
            
        query = f"""
            SELECT id, amount, description, category, date 
            FROM transactions 
            WHERE {' AND '.join(conditions)} 
            ORDER BY date DESC
        """
        
        if limit:
            query += " LIMIT %s"
            params.append(limit)
            
        cur.execute(query, params)
        columns = [col[0] for col in cur.description]
        transactions = [dict(zip(columns, row)) for row in cur.fetchall()]
        cur.close()
        return transactions

    @staticmethod
    def get_category_summary(user_id, year=None):
        cur = mysql.connection.cursor()
        
        year_condition = "AND YEAR(date) = %s" if year else ""
        
        query = f"""
            SELECT category, SUM(amount) as total 
            FROM transactions 
            WHERE user_id = %s {year_condition}
            GROUP BY category
        """
        
        params = [user_id]
        if year:
            params.append(year)
            
        cur.execute(query, params)
        columns = [col[0] for col in cur.description]
        results = [dict(zip(columns, row)) for row in cur.fetchall()]
        cur.close()
        return results

# Forms
class SignUpForm(FlaskForm):  # Change from Form to FlaskForm
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=100)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(max=100)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=100)])
    password = PasswordField('Password', validators=[
        DataRequired(),
        EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Confirm Password')

class LoginForm(FlaskForm):  # Change from Form to FlaskForm
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    
class TransactionForm(Form):
    amount = IntegerField('Amount', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired(), Length(max=200)])
    category = StringField('Category', validators=[DataRequired(), Length(max=50)])

class RequestResetForm(Form):
    email = EmailField('Email', validators=[DataRequired(), Email()])

class ResetPasswordForm(Form):
    password = PasswordField('Password', validators=[
        DataRequired(),
        EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Confirm Password')

# Helpers
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Please log in first', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def format_transaction_dates(transactions):
    if not transactions:
        return []
    
    for t in transactions:
        if 'date' in t:
            delta = datetime.datetime.now() - t['date']
            if isinstance(t['date'], datetime.datetime):
                if delta < datetime.timedelta(hours=12):
                    t['date'] = t['date'].strftime('%I:%M %p')
                else:
                    t['date'] = t['date'].strftime('%d %B, %Y')
    return transactions

def send_reset_email(user):
    s = Serializer(app.config['SECRET_KEY'], expires_in=1800)
    token = s.dumps({'user_id': user['id']}).decode('utf-8')
    msg = Message(
        'Password Reset Request',
        sender=app.config['MAIL_USERNAME'],
        recipients=[user['email']]
    )
    msg.body = f'''To reset your password, visit:
{url_for('reset_token', token=token, _external=True)}

If you didn't request this, ignore this email.
'''
    mail.send(msg)

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))

    form = SignUpForm(request.form)
    if request.method == 'POST' and form.validate():
        # Check if email is already registered
        if UserModel.get_by_email(form.email.data):
            flash('Email already registered', 'danger')
            return redirect(url_for('signup'))

        # Hash the password
        hashed_password = sha256_crypt.hash(form.password.data)

        # Create new user
        UserModel.create_user(
            form.first_name.data,
            form.last_name.data,
            form.email.data,
            form.username.data,
            hashed_password
        )

        flash('Registration successful. Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
        
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        user = UserModel.get_by_email(form.username.data)
        
        if user and sha256_crypt.verify(form.password.data, user['password']):
            session['logged_in'] = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Login successful', 'success')
            return redirect(url_for('dashboard'))
            
        flash('Invalid credentials', 'danger')
        
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    now = datetime.datetime.now()
    current_month_total = TransactionModel.get_monthly_summary(
        session['user_id'],
        now.year,
        now.month
    )
    
    transactions = TransactionModel.get_transactions(
        session['user_id'],
        now.year,
        now.month,
        limit=10
    )
    
    return render_template('dashboard.html', 
                         total_expenses=current_month_total,
                         transactions=format_transaction_dates(transactions),
                         now=now)

@app.route('/transactions/add', methods=['GET', 'POST'])
@login_required
def add_transaction():
    form = TransactionForm(request.form)
    if request.method == 'POST' and form.validate():
        cur = mysql.connection.cursor()
        cur.execute(
            "INSERT INTO transactions(user_id, amount, description, category) "
            "VALUES(%s, %s, %s, %s)",
            (session['user_id'], form.amount.data, form.description.data, form.category.data)
        )
        mysql.connection.commit()
        cur.close()
        flash('Transaction added', 'success')
        return redirect(url_for('dashboard'))
        
    return render_template('add_transaction.html', form=form)

@app.route('/transactions')
@login_required
@cache.cached(timeout=60, query_string=True)
def view_transactions():
    year = request.args.get('year', type=int)
    month = request.args.get('month', type=int)
    
    transactions = TransactionModel.get_transactions(
        session['user_id'],
        year,
        month
    )
    
    total = TransactionModel.get_monthly_summary(
        session['user_id'],
        year,
        month
    )
    
    return render_template('transactions.html',
                         transactions=format_transaction_dates(transactions),
                         total_expenses=total,
                         year=year,
                         month=month,
                         now=datetime.datetime.now())

@app.route('/reset_request', methods=['GET', 'POST'])
def reset_request():
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
        
    form = RequestResetForm(request.form)
    if request.method == 'POST' and form.validate():
        user = UserModel.get_by_email(form.email.data)
        if user:
            send_reset_email(user)
        flash('Reset instructions sent to your email', 'info')
        return redirect(url_for('login'))
        
    return render_template('reset_request.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
        
    s = Serializer(app.config['SECRET_KEY'])
    try:
        user_id = s.loads(token)['user_id']
    except:
        flash('Invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
        
    form = ResetPasswordForm(request.form)
    if request.method == 'POST' and form.validate():
        hashed_password = sha256_crypt.hash(form.password.data)
        cur = mysql.connection.cursor()
        cur.execute(
            "UPDATE users SET password = %s WHERE id = %s",
            (hashed_password, user_id)
        )
        mysql.connection.commit()
        cur.close()
        flash('Password updated. Please login.', 'success')
        return redirect(url_for('login'))
        
    return render_template('reset_token.html', form=form)

# Visualization Routes
@app.route('/visualization/category')
@login_required
@cache.cached(timeout=3600)
def category_visualization():
    data = TransactionModel.get_category_summary(session['user_id'])
    
    if not data:
        flash('No data available for visualization', 'info')
        return redirect(url_for('dashboard'))
    
    labels = [d['category'] for d in data]
    values = [d['total'] for d in data]
    
    fig = go.Figure(data=[go.Pie(labels=labels, values=values)])
    fig.update_layout(title_text='Expense by Category')
    return render_template('visualization.html', plot=fig.to_html(full_html=False))

@app.route('/visualization/monthly')
@login_required
@cache.cached(timeout=3600)
def monthly_visualization():
    now = datetime.datetime.now()
    monthly_data = []
    
    for month in range(1, 13):
        total = TransactionModel.get_monthly_summary(
            session['user_id'],
            now.year,
            month
        )
        monthly_data.append({'month': month, 'total': total})
    
    if not monthly_data or all(m['total'] == 0 for m in monthly_data):
        flash('No data available for visualization', 'info')
        return redirect(url_for('dashboard'))
    
    months = [datetime.date(1900, m['month'], 1).strftime('%b') for m in monthly_data]
    amounts = [m['total'] for m in monthly_data]
    
    fig = go.Figure([go.Bar(x=months, y=amounts)])
    fig.update_layout(title_text='Monthly Expenses')
    return render_template('visualization.html', plot=fig.to_html(full_html=False))

# Error Handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True)