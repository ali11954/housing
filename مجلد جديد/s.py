from sqlalchemy import create_engine, MetaData, Table, select
from sqlalchemy.orm import sessionmaker

# قواعد البيانات
old_db_path = "D:/ghith/NEW/rooms/housing.db"
new_db_path = "D:/ghith/NEW/rooms/instance/housing.db"

old_engine = create_engine(f"sqlite:///{old_db_path}")
new_engine = create_engine(f"sqlite:///{new_db_path}")

# إنشاء جلسات
OldSession = sessionmaker(bind=old_engine)
NewSession = sessionmaker(bind=new_engine)
old_session = OldSession()
new_session = NewSession()

# جلب الجداول
metadata_old = MetaData()
metadata_new = MetaData()

old_employees_table = Table('employees', metadata_old, autoload_with=old_engine)
new_employees_table = Table('employees', metadata_new, autoload_with=new_engine)

# نقل البيانات
# نقل البيانات
rows = old_session.execute(select(old_employees_table)).fetchall()
# جلب أسماء أعمدة جدول الوجهة
new_columns = new_employees_table.columns.keys()

for row in rows:
    row_dict = dict(row._mapping)
    filtered_dict = {k: v for k, v in row_dict.items() if k in new_columns}

    # قيم افتراضية للأعمدة NOT NULL
    if 'work_type' in filtered_dict and filtered_dict['work_type'] is None:
        filtered_dict['work_type'] = 'غير محدد'
    if 'employee_code' in filtered_dict and filtered_dict['employee_code'] is None:
        filtered_dict['employee_code'] = 0  # أو أي قيمة مناسبة

    # تحقق من عدم تكرار employee_code
    existing = new_session.execute(
        select(new_employees_table).where(
            new_employees_table.c.employee_code == filtered_dict['employee_code']
        )
    ).first()
    if not existing:
        new_session.execute(new_employees_table.insert().values(**filtered_dict))

new_session.commit()
print(f"{len(rows)} employees copied successfully!")
