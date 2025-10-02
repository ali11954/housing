import sqlite3
import pandas as pd

# ===== قراءة ملف Excel =====
excel_file = "D:/ghith/NEW/rooms/employeeee.xlsx"  # ضع هنا مسار ملف Excel
df = pd.read_excel(excel_file)

# ===== إنشاء الاتصال بقاعدة البيانات =====
conn = sqlite3.connect(r"D:\ghith\NEW\rooms\instance\housing.db")
cursor = conn.cursor()

# ===== إنشاء جدول الموظفين =====
cursor.execute("""
CREATE TABLE IF NOT EXISTS Employeeee (
    employee_id TEXT PRIMARY KEY,
    name TEXT,
    job_title TEXT,
    department TEXT,
    company TEXT,
    work_type TEXT,
    employee_residence TEXT,
    service_type TEXT,
    company_residence TEXT,
    company_dorm_name TEXT,
    room_number TEXT,
    bed_number TEXT,
    presence_in_company TEXT
)
""")

# ===== إدخال البيانات من Excel إلى الجدول =====
for _, row in df.iterrows():
    cursor.execute("""
    INSERT OR REPLACE INTO Employeeee (
        employee_id, name, job_title, department, company, work_type,
        employee_residence, service_type, company_residence, company_dorm_name,
        room_number, bed_number, presence_in_company
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        str(row["الرقم الوظيفي"]),
        row["الاسم الكامل"],
        row["الوظيفة"],
        row["الإدارة"],
        row["الشركة"],
        row["نوع الدوام"],
        row["موقع سكن الموظف"],
        row["نوع الخدمة"],
        row["موقع سكن الشركة"],
        row["اسم السكن في الشركة"],
        str(row["رقم الغرفة"]),
        str(row["رقم السرير"]),
        row["التواجد في الشركة"]
    ))

# ===== حفظ التغييرات وإغلاق الاتصال =====
conn.commit()
conn.close()

print("تم إنشاء الجدول وإدخال البيانات بنجاح!")
