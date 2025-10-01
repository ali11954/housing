from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from sqlalchemy import Enum
from flask_login import UserMixin

# استيراد db من حزمة app
from app import db

# نموذج المستخدم
# في models.py - تأكد من هذا الكود
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    active = db.Column(db.Boolean, default=True)
    role = db.Column(db.String(20), default='user')  # admin, moderator, user, viewer
    full_name = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    department = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    # نظام الصلاحيات المتقدم
    permissions = db.Column(db.Text)  # تخزين الصلاحيات كـ JSON

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def update_last_login(self):
        self.last_login = datetime.utcnow()
        db.session.commit()

    def get_permissions(self):
        """الحصول على قائمة الصلاحيات"""
        if self.role == 'admin':
            return self.get_all_permissions()

        if self.permissions:
            import json
            return json.loads(self.permissions)
        return []

    def set_permissions(self, permissions_list):
        """تعيين الصلاحيات"""
        import json
        self.permissions = json.dumps(permissions_list)

    def has_permission(self, permission):
        """التحقق من وجود صلاحية"""
        user_permissions = self.get_permissions()
        return permission in user_permissions

    def get_all_permissions(self):
        """جميع الصلاحيات المتاحة (للمسؤول)"""
        return [
            'view_dashboard',
            'view_reports',
            'manage_users',
            'manage_rooms',
            'manage_finance',
            'manage_settings',
            'view_audit_logs',
            'export_data',
            'manage_permissions'
        ]

    def get_available_permissions(self):
        """الصلاحيات المتاحة حسب الدور"""
        base_permissions = ['view_dashboard']

        if self.role == 'viewer':
            return base_permissions + ['view_reports']

        elif self.role == 'user':
            return base_permissions + ['view_reports', 'export_data']

        elif self.role == 'moderator':
            return base_permissions + [
                'view_reports', 'manage_rooms', 'export_data'
            ]

        elif self.role == 'admin':
            return self.get_all_permissions()

        return base_permissions

    def can_manage_users(self):
        """التحقق من صلاحية إدارة المستخدمين"""
        return self.has_permission('manage_users') or self.role == 'admin'

    def can_view_reports(self):
        """التحقق من صلاحية عرض التقارير"""
        return self.has_permission('view_reports') or self.role in ['admin', 'moderator']

    def can_manage_rooms(self):
        """التحقق من صلاحية إدارة الغرف"""
        return self.has_permission('manage_rooms') or self.role in ['admin', 'moderator']

    def __repr__(self):
        return f'<User {self.username}>'


# جدول أنوع الدوام: (أيام دوام, أيام إجازة)
work_type_schedule = {
    "YCSR-A": (4, 3),  # ورديات من السبت الى الثلاثاء
    "YCSR-B": (4, 3),  # اداري من الاحد الى الاربعاء
    "YCSR-C": (4, 3),  # ورديات من الاثنين الى الخميس
    "YCSR-D": (4, 3),  # ورديات الاثنين والثلاثاء اجازة
    "YCSR-c": (4, 3),  # ورديات من الاربعاء الى السبت
    "YCSRW1": (7, 7),  # اسبوع * اسبوع
    "YCSRW2": (7, 7),  # اسبوع * اسبوع
    "YCSRK2": (14, 7),  # اسبوعين * اسبوع
    "YCSRK1": (14, 7),  # اسبوعين * اسبوع
    "YCSRSH1": (6, 1),  # ورديات عادية
    "N_PR28H1": (28, 28),  # شهر *شهر
    "N_PR28H2": (28, 28),  # شهر *شهر
    "N_PR28H3": (28, 28),  # شهر *شهر
    "N_PR28H4": (28, 28),  # شهر *شهر
    "SHIFT2": (42, 14),
    "YCSRK3": (42, 14),  # 6اسابيع * 3اسابيع
    "NORMYS4": (5, 2),  # اداري من الاحد الى الخميس
    "NORMALY2": (6, 1),
    "NORMALY3": (7, 0),
    "NORMYS5": (4, 3),  # اداري من السبت الى الثلاثاء
    "NORMYS6": (4, 3),  # اداري من الاثنين الى الخميس
    "NORMYS7": (42, 21),  # 6اسابيع * 3اسابيع
    "N_YCSRE2": (6, 1),
    "غير محدد": (6, 1),
    "ورديات": (6, 1),
    "ycsrsc": (6, 1),
    "YCSRE1": (6, 1),
    "NORMYS2": (6, 1)  # ورديات المبيعات

}


class Company(db.Model):
    __tablename__ = 'companies'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    employees = db.relationship("Employee", back_populates="company")


class Employee(db.Model):
    __tablename__ = "employees"

    id = db.Column(db.Integer, primary_key=True)
    employee_code = db.Column(db.Integer, unique=True)
    name = db.Column(db.String(200), nullable=False)  # الاسم الكامل
    job_title = db.Column(db.String(200))                                # الوظيفة
    department = db.Column(db.String(200))                               # الإدارة
    work_type = db.Column(db.String, nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey("companies.id"))
    company = db.relationship("Company", back_populates="employees")
    company_name = db.Column(db.String, nullable=True)

    employee_housing_location = db.Column(db.String(200))                         # موقع سكن الموظف
    service_type = db.Column(db.String(100))                             # نوع الخدمة
    company_housing_location = db.Column(db.String(200))                 # موقع سكن الشركة
    company_housing_name = db.Column(db.String(200))                             # اسم السكن في الشركة
    room_number = db.Column(db.String(50))                               # رقم الغرفة
    bed_number = db.Column(db.String(50))                                # رقم السرير
    presence_in_company = db.Column(db.Integer, default=0)


    assignments = db.relationship("BedAssignment", back_populates="employee", lazy="subquery")

    @staticmethod
    def get_employee_status(start_date, duty_type):
        """
        تعطي حالة الموظف بناءً على نوع الدوام وتاريخ بداية الدوام
        """
        try:
            # إذا نوع الدوام غير موجود في الجدول
            if duty_type not in work_type_schedule:
                return "غير محدد"

            work_days, off_days = work_type_schedule[duty_type]

            # إذا أيام الدوام = 0، الموظف في إجازة دائمًا
            if work_days == 0:
                return "إجازة"

            current_date = datetime.today().date()  # اليوم الحالي
            # إذا start_date نص، تأكد من تحويله إلى date
            if isinstance(start_date, datetime):
                start_date = start_date.date()

            total_days = (current_date - start_date).days
            if total_days < 0:
                return "لم يبدأ الدوام"

            cycle_length = work_days + off_days
            day_in_cycle = total_days % cycle_length

            return "نشط" if day_in_cycle < work_days else "إجازة"

        except Exception as e:
            print(f"خطأ في حساب حالة الموظف: {e}")
            return "خطأ"


# جدول الربط بين البنود والسكنات
# جدول الربط بين البنود والسكنات
housing_items = db.Table(
    'housing_items',
    db.Column('housing_id', db.Integer, db.ForeignKey('housing_units.id'), primary_key=True),
    db.Column('item_id', db.Integer, db.ForeignKey('expense_items.id'), primary_key=True)
)

class ExpenseItem(db.Model):
    __tablename__ = "expense_items"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255))  # أو النص المناسب

    unit_price = db.Column(db.Float, nullable=False)  # سعر الوحدة
    unit_qtr= db.Column(db.String, nullable=False)  # سعر الوحدة
    consumptions = db.relationship('MonthlyConsumption', back_populates='expense_item', cascade="all, delete")
    calculation_type = db.Column(db.String(20), default="normal")
    # normal | per_resident | shared
# جدول الاستهلاك الشهري
    housings = db.relationship('HousingUnit', secondary=housing_items, back_populates='items')

class MonthlyConsumption(db.Model):
    __tablename__ = 'monthly_consumption'
    id = db.Column(db.Integer, primary_key=True)
    housing_unit_id = db.Column(db.Integer, db.ForeignKey('housing_units.id'), nullable=False)
    expense_item_id = db.Column(db.Integer, db.ForeignKey('expense_items.id'), nullable=False)
    month = db.Column(db.String(20), nullable=False)  # "2025-09"
    qty = db.Column(db.Float, nullable=True)
    unit_price = db.Column(db.Float, default=0)
    total_price = db.Column(db.Float, default=0)

    housing_unit = db.relationship(
        'HousingUnit',
        back_populates='monthly_consumptions'
    )
    expense_item = db.relationship('ExpenseItem', back_populates='consumptions')

from wtforms.validators import DataRequired
from wtforms import SelectField, TextAreaField, SubmitField
from wtforms import SelectMultipleField

class HousingUnit(db.Model):
    __tablename__ = 'housing_units'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    number = db.Column(db.String(50), nullable=False)
    total_rooms = db.Column(db.Integer, nullable=False)
    total_beds = db.Column(db.Integer, nullable=False)
    rooms = db.relationship('Room', backref='housing_unit', cascade='all, delete-orphan')
    monthly_consumptions = db.relationship(
        'MonthlyConsumption',
        back_populates='housing_unit',
        lazy='dynamic')

    monthly_resident_averages = db.relationship(
        'DailyResident',
        back_populates='housing_unit',
        lazy='dynamic'
    )
    items = db.relationship('ExpenseItem', secondary=housing_items, back_populates='housings')

    allowed_housings = db.Column(db.String, nullable=True, default=None)

    @property
    def occupied_beds(self):
        return sum(room.occupied_beds for room in self.rooms)

    @property
    def available_beds(self):
        return sum(room.total_beds for room in self.rooms) - self.occupied_beds

    @property
    def rooms_count(self):
        return len(self.rooms)

    @rooms_count.setter
    def rooms_count(self, value):
        # تعريف ماذا يحدث عند التعيين، مثلا تخزين في متغير داخلي
        self._rooms_count = value


class Room(db.Model):
    __tablename__ = 'rooms'
    id = db.Column(db.Integer, primary_key=True)
    housing_unit_id = db.Column(db.Integer, db.ForeignKey('housing_units.id'), nullable=False)
    room_number = db.Column(db.String(50), nullable=False)
    beds = db.relationship('Bed', backref='room', cascade='all, delete-orphan', lazy='dynamic')
    total_beds = db.Column(db.Integer)  # يجب أن يكون عمود عادي



    @property
    def occupied_beds(self):
        return sum(1 for bed in self.beds if bed.is_occupied)

    @property
    def vacant_beds(self):
        return sum(1 for bed in self.beds) - self.occupied_beds


class Bed(db.Model):
    __tablename__ = 'beds'
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('rooms.id'), nullable=False)
    bed_number = db.Column(db.String(50), nullable=False)

    assignments = db.relationship('BedAssignment', back_populates='bed', lazy='dynamic')

    def is_on_duty(self, on_date=None):
        on_date = on_date or datetime.utcnow().date()
        # التحقق من حالة التعيين الحالي
        current = self.current_assignment()
        if current:
            return current.status == "نشط" and current.start_date <= on_date and \
                   (current.end_date is None or current.end_date >= on_date)
        return False

    @property
    def is_occupied(self):
        today = datetime.today().date()
        assignment = self.assignments.filter(
            BedAssignment.active == True,
            BedAssignment.start_date <= today,
            (BedAssignment.end_date == None) | (BedAssignment.end_date >= today)
        ).first()
        return assignment is not None

    def current_employee(self):
        today = datetime.today().date()
        assignment = self.assignments.filter(
            BedAssignment.active == True,
            BedAssignment.start_date <= today,
            (BedAssignment.end_date == None) | (BedAssignment.end_date >= today)
        ).first()
        if assignment:
            return assignment.employee
        return None

    def current_assignment(self):
        today = datetime.today().date()
        return self.assignments.filter(
            BedAssignment.active == True,
            BedAssignment.start_date <= today,
            (BedAssignment.end_date == None) | (BedAssignment.end_date >= today)
        ).first()

    @staticmethod
    def can_assign_employee_to_bed(bed_id, start_date=None, end_date=None, assignment_type=None):
        """
        تتحقق إذا يمكن تخصيص موظف على السرير
        - permanent: سرير دائم، فقط موظف واحد
        - rotating: سرير تناوبي، لا يزيد عن موظفين
        """
        today = datetime.utcnow().date()
        assignments = BedAssignment.query.filter(
            BedAssignment.bed_id == bed_id,
            BedAssignment.active == True,
            BedAssignment.start_date <= (end_date or today),
            ((BedAssignment.end_date == None) | (BedAssignment.end_date >= (start_date or today)))
        ).all()

        permanent_count = sum(1 for a in assignments if a.assignment_type == 'permanent')
        rotating_count = sum(1 for a in assignments if a.assignment_type == 'rotating')

        if assignment_type == 'permanent' and permanent_count >= 1:
            return False
        if assignment_type == 'rotating' and rotating_count >= 2:
            return False
        return True

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

class BedAssignment(db.Model):
    __tablename__ = 'bed_assignments'
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    bed_id = db.Column(db.Integer, db.ForeignKey('beds.id'), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=True)
    assignment_type = db.Column(Enum('permanent', 'rotating', name='assignment_type'), nullable=False)
    active = db.Column(db.Boolean, default=True)

    bed = db.relationship('Bed', back_populates='assignments')
    employee = db.relationship('Employee', back_populates='assignments')

    _status = None  # متغير داخلي لتخزين الحالة المخصصة

    @property
    def status(self):
        if self._status is not None:
            return self._status
        if not self.employee or not self.employee.work_type:
            return "غير محدد"
        return Employee.get_employee_status(self.start_date, self.employee.work_type)

    @status.setter
    def status(self, value):
        self._status = value

class BedTransfer(db.Model):
    __tablename__ = "bed_transfers"
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey("employees.id"))
    from_bed_id = db.Column(db.Integer, db.ForeignKey("beds.id"))
    to_bed_id = db.Column(db.Integer, db.ForeignKey("beds.id"))
    transfer_date = db.Column(db.DateTime)
    transfer_type = db.Column(db.String)

    # العلاقة مع موظف
    employee = db.relationship("Employee", backref="transfers")

    # العلاقة مع الأسرة (Beds)
    from_bed = db.relationship("Bed", foreign_keys=[from_bed_id])
    to_bed = db.relationship("Bed", foreign_keys=[to_bed_id])

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime


class Asset(db.Model):
    __tablename__ = 'assets'

    id = db.Column(db.Integer, primary_key=True)
    asset_number = db.Column(db.String, unique=True, nullable=False)
    asset_name = db.Column(db.String, nullable=False)
    asset_description = db.Column(db.String)
    asset_type = db.Column(db.String)
    purchase_date = db.Column(db.DateTime)
    status = db.Column(db.String)
    is_active = db.Column(db.Boolean, default=True)

    links = db.relationship("AssetLink", backref="asset", cascade="all, delete-orphan")
    actions = db.relationship("AssetAction", backref="asset", cascade="all, delete-orphan")
    disposal = db.relationship("AssetDisposal", backref="asset", cascade="all, delete-orphan")

class AssetLink(db.Model):
    __tablename__ = 'asset_links'
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False)
    housing_unit_id = db.Column(db.Integer, db.ForeignKey('housing_units.id'), nullable=True)
    room_id = db.Column(db.Integer, db.ForeignKey('rooms.id'), nullable=True)
    bed_id = db.Column(db.Integer, db.ForeignKey('beds.id'), nullable=True)
    link_date = db.Column(db.Date, default=datetime.utcnow)

    housing_unit = db.relationship("HousingUnit", backref="asset_links")
    room = db.relationship("Room", backref="asset_links")
    bed = db.relationship("Bed", backref="asset_links")

class AssetAction(db.Model):
    __tablename__ = 'asset_actions'
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False)
    action_type = db.Column(db.String(50))
    action_date = db.Column(db.Date, default=datetime.utcnow)
    old_housing = db.Column(db.String(100))
    old_room = db.Column(db.String(50))
    old_bed = db.Column(db.String(50))
    new_housing = db.Column(db.String(100))
    new_room = db.Column(db.String(50))
    new_bed = db.Column(db.String(50))
    description = db.Column(db.String(255))
    purchase_date = db.Column(db.Date)
    disposal_date = db.Column(db.Date)


class AssetDisposal(db.Model):
    __tablename__ = 'asset_disposal'
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False)
    disposal_date = db.Column(db.Date, default=datetime.utcnow)
    disposal_reason = db.Column(db.String(255))

from datetime import datetime

class AttendanceRecord(db.Model):
    __tablename__ = "fingerprint_attendance"
    id = db.Column(db.Integer, primary_key=True)
    # ربط مباشر مع Employee
    employee_id = db.Column(db.Integer, db.ForeignKey("employees.id"), nullable=False)
    employee = db.relationship("Employee", backref="attendance_records")
    date = db.Column(db.Date, nullable=False)
    check_in = db.Column(db.Time)
    check_out = db.Column(db.Time)


class FingerprintArchive(db.Model):
    __tablename__ = "fingerprint_archive"

    id = db.Column(db.Integer, primary_key=True)
    employee_code = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(150), nullable=False)
    company = db.Column(db.String(100), nullable=True)
    job_title = db.Column(db.String(100), nullable=True)
    department = db.Column(db.String(100), nullable=True)
    work_type = db.Column(db.String(50), nullable=True)

    company_housing_name = db.Column(db.String(200), nullable=True)
    room_number = db.Column(db.String(50), nullable=True)
    bed_number = db.Column(db.String(50), nullable=True)

    check_in = db.Column(db.String(20), nullable=True)
    check_out = db.Column(db.String(20), nullable=True)
    date = db.Column(db.Date, nullable=False)

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime


class MaintenanceRequest(db.Model):
    __tablename__ = 'maintenance_requests'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    team = db.Column(db.String(100), nullable=False)
    responsible = db.Column(db.String(100), nullable=False)
    scheduled_date = db.Column(db.Date, nullable=False)
    duration_hours = db.Column(db.Float, nullable=False)
    priority = db.Column(db.String(50), nullable=False)
    maintenance_type = db.Column(db.String(50), nullable=False)
    manufacturing_order = db.Column(db.String(200), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), nullable=False, default="تحت التنفيذ")  # ← الحالة الجديدة

    # أعمدة ForeignKey
    housing_id = db.Column(db.Integer, db.ForeignKey('housing_units.id'), nullable=True)
    room_id = db.Column(db.Integer, db.ForeignKey('rooms.id'), nullable=True)

    # العلاقات الصحيحة
    housing_unit = db.relationship('HousingUnit', backref='maintenance_requests')
    room = db.relationship('Room', backref='maintenance_requests')

class MaintenanceTeam(db.Model):
    __tablename__ = 'maintenance_teams'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)

    def __repr__(self):
        return f"<Team {self.name}>"




class Assetwarehouse(db.Model):
    __tablename__ = 'assets_warehouse'
    id = db.Column(db.Integer, primary_key=True)
    asset_number = db.Column(db.String(50), unique=True, nullable=False)
    asset_name = db.Column(db.String(100))
    asset_description = db.Column(db.String(200))
    asset_type = db.Column(db.String(50))
    status = db.Column(db.String(50))
    purchase_date = db.Column(db.Date)

class Consumable(db.Model):
    __tablename__ = 'consumables'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Float, default=0)
    unit = db.Column(db.String(20))
    entry_date = db.Column(db.Date)

class CleaningMaterial(db.Model):
    __tablename__ = 'cleaning_materials'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Float, default=0)
    unit = db.Column(db.String(20))
    entry_date = db.Column(db.Date)


# جدول بنود المصروفات

# جدول الاستهلاك الشهري حسب البند


class DailyResident(db.Model):
    __tablename__ = 'daily_resident'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    housing_unit_id = db.Column(db.Integer, db.ForeignKey('housing_units.id'), nullable=False)
    residents = db.Column(db.Integer, nullable=False)

    # استخدم نفس الاسم وليس housing_id
    housing_unit = db.relationship(
        "HousingUnit",
        back_populates="monthly_resident_averages"
    )

class MonthlyResidentAverage(db.Model):
    __tablename__ = "monthly_resident_average"
    id = db.Column(db.Integer, primary_key=True)
    housing_unit_id = db.Column(db.Integer, db.ForeignKey('housing_units.id'))
    year_month = db.Column(db.String(7), nullable=False)  # YYYY-MM
    average_residents = db.Column(db.Float, nullable=False)

    housing_unit = db.relationship("HousingUnit")

