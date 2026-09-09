import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'ahmed_secure_key_2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///reports.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rank = db.Column(db.String(50), nullable=False)
    full_name = db.Column(db.String(150), nullable=False)
    severity = db.Column(db.String(50), nullable=True)
    images = db.Column(db.Text, nullable=True)

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        hashed_pw = generate_password_hash('123456')
        default_user = User(username='admin', password_hash=hashed_pw)
        db.session.add(default_user)
        db.session.commit()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('تم تسجيل الدخول بنجاح', 'success')
            return redirect(url_for('index'))
        flash('اسم المستخدم أو كلمة المرور غير صحيحة', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/submit-report', methods=['POST'])
def submit_report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    rank = request.form.get('user_rank')
    full_name = request.form.get('user_full_name')
    severity = request.form.get('severity', '')
    
    uploaded_files = request.files.getlist('evidence_files')
    filenames = []
    for file in uploaded_files:
        if file and file.filename:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            filenames.append(filename)
    
    new_report = Report(
        rank=rank,
        full_name=full_name,
        severity=severity,
        images=','.join(filenames)
    )
    db.session.add(new_report)
    db.session.commit()
    
    flash('تم حفظ وتقديم البلاغ بنجاح', 'success')
    return redirect(url_for('index'))

@app.route('/change-password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if new_password != confirm_password:
        flash('كلمات المرور الجديدة غير متطابقة', 'danger')
        return redirect(url_for('index'))
        
    user = User.query.get(session['user_id'])
    if not user or not check_password_hash(user.password_hash, current_password):
        flash('كلمة المرور الحالية غير صحيحة', 'danger')
        return redirect(url_for('index'))
        
    user.password_hash = generate_password_hash(new_password)
    db.session.commit()
    
    flash('تم تغيير كلمة السر بنجاح', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
