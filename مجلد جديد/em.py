import re
from datetime import datetime
import shutil
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from models import Employee, HousingUnit, Room, Bed, BedAssignment

DATABASE_URL = "sqlite:///D:/ghith/NEW/rooms/instance/housing.db"
engine = create_engine(DATABASE_URL, echo=False)
Session = sessionmaker(bind=engine)
session = Session()

# نسخة احتياطية
backup_file = f"{DATABASE_URL.replace('sqlite:///', '')}_backup_{datetime.now().strftime('%Y%m%d%H%M%S')}.db"
shutil.copyfile(DATABASE_URL.replace('sqlite:///', ''), backup_file)
print(f"تم إنشاء نسخة احتياطية من قاعدة البيانات: {backup_file}")

def extract_number(text):
    match = re.search(r'\d+', str(text))
    return int(match.group()) if match else 1

unassigned_employees = []

employees = session.query(Employee).all()

for emp in employees:
    # السكن
    housing_name = emp.company_housing_name or "غير محدد"
    housing = session.query(HousingUnit).filter_by(name=housing_name).first()
    if not housing:
        housing = HousingUnit(
            name=housing_name,
            number=emp.company_housing_location or "0",
            total_rooms=0,
            total_beds=0
        )
        session.add(housing)
        session.flush()

    # الغرفة
    room_number = emp.room_number or "غير محدد"
    room = session.query(Room).filter_by(housing_unit_id=housing.id, room_number=room_number).first()
    if not room:
        total_beds = extract_number(emp.bed_number)
        room = Room(
            housing_unit_id=housing.id,
            room_number=room_number,
            total_beds=total_beds
        )
        session.add(room)
        session.flush()

    # السرير
    bed_number = extract_number(emp.bed_number)
    bed = session.query(Bed).filter_by(room_id=room.id, bed_number=bed_number).first()
    if not bed:
        bed = Bed(room_id=room.id, bed_number=bed_number)
        session.add(bed)
        session.flush()

    # تعيين الموظف
    assignment = session.query(BedAssignment).filter_by(employee_id=emp.id, bed_id=bed.id, active=True).first()
    if not assignment:
        if not bed.is_occupied:
            new_assignment = BedAssignment(
                employee_id=emp.id,
                bed_id=bed.id,
                start_date=datetime.today().date(),
                assignment_type="permanent",
                active=True
            )
            session.add(new_assignment)
        else:
            unassigned_employees.append(emp)

session.commit()

# تقرير الموظفين غير المرتبطين
if unassigned_employees:
    print("الموظفون الذين لم يتم ربطهم بسرة متاحة:")
    for emp in unassigned_employees:
        print(f"- {emp.employee_code} | {emp.name} | الغرفة: {emp.room_number} | السرير: {emp.bed_number}")
else:
    print("تم ربط جميع الموظفين بالسكنات بنجاح!")

session.close()
