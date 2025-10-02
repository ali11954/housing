# create_user.py
from app import create_app, db
from models import User

app = create_app()

with app.app_context():
    # إنشاء مستخدم جديد
    new_user = User(
        username='admin',
        email='admin@company.com',
        role='admin',
        is_active=True
    )
    new_user.set_password('admin123')

    db.session.add(new_user)
    db.session.commit()

    print("✅ تم إنشاء المستخدم بنجاح!")
    print("اسم المستخدم: admin")
    print("كلمة المرور: admin123")

    # التحقق
    user = User.query.filter_by(username='admin').first()
    if user and user.check_password('admin123'):
        print("🎉 يمكن تسجيل الدخول بنجاح!")
    else:
        print("❌ خطأ في إنشاء المستخدم")