from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from sqlalchemy import text  # 🚀 استيراد text المطلوب
import os
import logging
from logging.handlers import RotatingFileHandler

from models import db

# إنشاء instances
login_manager = LoginManager()
migrate = Migrate()


def create_app():
    app = Flask(__name__)

    # 🚀 **إعدادات قاعدة بيانات محسنة لـ Railway**
    database_url = os.environ.get('DATABASE_URL', 'sqlite:///housing.db')

    # إصلاح مشكلة DATABASE_URL إذا كان يبدأ بـ postgres://
    if database_url and database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)

    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # 🔒 **مفتاح سري آمن**
    app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

    # ⚡ **إعدادات متقدمة للأداء**
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'pool_size': 10,
        'max_overflow': 20,
        'connect_args': {
            'timeout': 30,
            'check_same_thread': False
        }
    }

    # تهيئة الإضافات
    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)

    login_manager.login_view = 'main.login'
    login_manager.login_message = 'يجب تسجيل الدخول للوصول إلى هذه الصفحة'
    login_manager.login_message_category = 'warning'

    # 📝 **إعداد التسجيل بدون رموز Unicode**
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

    # 🔧 **تهيئة قاعدة البيانات بشكل آمن**
    with app.app_context():
        from models import User

        @login_manager.user_loader
        def load_user(user_id):
            return User.query.get(int(user_id))

        # 🚀 **التحقق من اتصال قاعدة البيانات باستخدام text()**
        tables_exist = False
        try:
            # استخدام text() للاستعلامات النصية
            db.session.execute(text('SELECT 1'))
            app.logger.info("اتصال قاعدة البيانات نشط")

            # التحقق من وجود الجداول
            inspector = db.inspect(db.engine)
            tables = inspector.get_table_names()
            tables_exist = len(tables) > 0

            if tables_exist:
                app.logger.info("الجداول موجودة بالفعل")
            else:
                app.logger.warning("الجداول غير موجودة، سيتم إنشاؤها...")
                db.create_all()
                app.logger.info("تم إنشاء الجداول بنجاح")

        except Exception as e:
            app.logger.error(f"خطأ في اتصال قاعدة البيانات: {str(e)}")
            # محاولة إنشاء الجداول في حالة الخطأ
            try:
                db.create_all()
                tables_exist = True
                app.logger.info("تم إنشاء الجداول بعد الخطأ الأولي")
            except Exception as create_error:
                app.logger.error(f"فشل في إنشاء الجداول: {str(create_error)}")

        # 🎯 **إنشاء المستخدم الافتراضي فقط إذا كانت الجداول موجودة**
        try:
            if tables_exist:
                admin_exists = User.query.filter_by(username='admin').first()
                if not admin_exists:
                    admin_user = User(
                        username='admin',
                        email='admin@example.com',
                        role='admin',
                        active=True
                    )
                    admin_user.set_password('admin123')
                    db.session.add(admin_user)
                    db.session.commit()
                    app.logger.info("تم إنشاء المستخدم الافتراضي (admin/admin123)")
                else:
                    app.logger.info("المستخدم الافتراضي موجود بالفعل")
            else:
                app.logger.warning("لا يمكن إنشاء المستخدم الافتراضي - الجداول غير موجودة")
        except Exception as e:
            app.logger.error(f"خطأ في إنشاء المستخدم الافتراضي: {str(e)}")

    # 📦 **تسجيل الـ Blueprint**
    from routes import bp
    app.register_blueprint(bp)

    # 🩹 **معالجة الأخطاء**
    @app.errorhandler(404)
    def not_found_error(error):
        return "الصفحة غير موجودة", 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return "حدث خطأ داخلي في الخادم", 500

    return app


# 🚀 **هذا السطر ضروري للنشر**
app = create_app()
application = app

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_ENV') != 'production'
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=debug_mode)