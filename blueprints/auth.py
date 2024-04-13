from flask import Blueprint, render_template, jsonify, redirect, url_for, session
from exts import mail, db
from flask_mail import Message
from flask import request
import string, random
from models import EmailCaptchaModel, UserModel
from .forms import RegisterForm, LoginForm
from werkzeug.security import generate_password_hash, check_password_hash

bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    else:
        form = LoginForm(request.form)
        if form.validate():
            email = form.email.data
            password = form.password.data
            user = UserModel.query.filter_by(email=email).first()
            if not user:
                return redirect('auth.login')
            if check_password_hash(user.password, password):
                session['user_id'] = user.id
                return redirect('/')
            else:
                return redirect(url_for('auth.login'))

        else:
            return redirect('auth.login')


@bp.route('/register', methods=['GET', 'POST'])
def register():
    # 验证用户提交的验证码
    if request.method == 'GET':
        return render_template('register.html')
    else:
        form = RegisterForm(request.form)
        if form.validate():
            email = form.email.data
            username = form.username.data
            password = form.password.data
            user = UserModel(username=username, password=generate_password_hash(password), email=email)
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('auth.login'))
        else:
            return redirect(url_for('auth.register'))


@bp.route('/mail/test')
def mail_test():
    message = Message(subject='测试', recipients=['shangcoming@gmail.com'], body='这是一条测试邮件')
    mail.send(message)

    return 'chenggong'


@bp.route('/captcha/email')
def get_email_captcha():
    email = request.args.get('email')
    source = string.digits * 4
    captcha = random.sample(source, 4)
    captcha = "".join(captcha)
    print(captcha)
    message = Message(subject='注册', recipients=[email], body=f'验证码为：{captcha}')
    mail.send(message)
    email_captcha = EmailCaptchaModel(email=email, captcha=captcha)
    db.session.add(email_captcha)
    db.session.commit()
    return jsonify({'code': 200, 'message': '', 'data': None})


@bp.route('/logout')
def logout():
    session.clear()
    return redirect('/')
