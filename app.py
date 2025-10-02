from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import os

from models import db  # بدلاً من إنشاء db هنا
# إنشاء instances
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)

    # 🚨 **التعديل المهم: استخدام متغيرات البيئة بدلاً من المسار المطلق**
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///housing.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

    # إعدادات إضافية
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'connect_args': {
            'timeout': 30,
            'check_same_thread': False
        }
    }

    # تهيئة الإضافات
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'
    login_manager.login_message = 'يجب تسجيل الدخول للوصول إلى هذه الصفحة'
    login_manager.login_message_category = 'warning'

    # استيراد النماذج بعد تهيئة db
    with app.app_context():
        from models import User

        @login_manager.user_loader
        def load_user(user_id):
            return User.query.get(int(user_id))

        # إنشاء الجداول
        db.create_all()

        # إنشاء مستخدم افتراضي
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
            print("✅ تم إنشاء المستخدم الافتراضي (admin/admin123)")

        print("✅ تم إنشاء الجداول بنجاح!")

    # تسجيل الـ Blueprint
    from routes import bp
    app.register_blueprint(bp)

    return app

# 🚀 **هذا السطر ضروري جداً للنشر - لا تحذفه**
app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)