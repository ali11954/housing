from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from sqlalchemy import text
import os
import logging
from logging.handlers import RotatingFileHandler

# إنشاء instances - 🔥 الطريقة الحديثة
from models import db

login_manager = LoginManager()
migrate = Migrate()


def create_app():
    app = Flask(__name__)

    # 🔥 إعدادات متوافقة مع الإصدارات الجديدة
    database_url = os.environ.get('DATABASE_URL', 'sqlite:///housing.db')
    if database_url and database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)

    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback-secret-key-for-production')

    # 🔥 إعدادات محسنة للإصدارات الجديدة
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'pool_size': 5,
        'max_overflow': 10,
    }

    # تهيئة الإضافات
    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)

    login_manager.login_view = 'main.login'
    login_manager.login_message = 'يجب تسجيل الدخول للوصول إلى هذه الصفحة'

    # التسجيل
    if not app.debug:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = RotatingFileHandler('logs/housing_app.log', maxBytes=10240, backupCount=5)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)

    # تهيئة قاعدة البيانات
    with app.app_context():
        from models import User

        @login_manager.user_loader
        def load_user(user_id):
            # 🔥 الطريقة الحديثة لـ SQLAlchemy 2.0
            return db.session.get(User, int(user_id))

        try:
            # 🔥 التحقق من الاتصال بشكل آمن
            db.session.execute(text('SELECT 1'))
            app.logger.info("اتصال قاعدة البيانات نشط")

            # إنشاء الجداول إذا لم تكن موجودة
            db.create_all()
            app.logger.info("تم تهيئة الجداول")

        except Exception as e:
            app.logger.error(f"خطأ في قاعدة البيانات: {str(e)}")

        # إنشاء مستخدم افتراضي
        try:
            if not User.query.filter_by(username='admin').first():
                admin_user = User(
                    username='admin',
                    email='admin@example.com',
                    role='admin',
                    active=True
                )
                admin_user.set_password('admin123')
                db.session.add(admin_user)
                db.session.commit()
                app.logger.info("تم إنشاء المستخدم الافتراضي")
        except Exception as e:
            app.logger.error(f"خطأ في إنشاء المستخدم: {str(e)}")

    # تسجيل الـ Blueprint
    from routes import bp
    app.register_blueprint(bp)

    # معالجة الأخطاء
    @app.errorhandler(500)
    def internal_error(error):
        return "حدث خطأ داخلي في الخادم", 500

    @app.errorhandler(404)
    def not_found(error):
        return "الصفحة غير موجودة", 404

    return app


# التهيئة
app = create_app()
application = app

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)