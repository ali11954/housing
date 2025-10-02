import pandas as pd
import sqlite3

# --- قراءة ملف Excel ---
df_excel = pd.read_excel(r"D:\ghith\NEW\rooms\dataemp.xlsx")

# خريطة الأعمدة العربية -> الإنجليزية
columns_map = {
    'الرقم الوظيفي': 'employee_code',
    'الاسم الكامل': 'name',
    'الوظيفة': 'job_title',
    'الإدارة': 'department',
    'نوع الدوام': 'work_type',
    'الشركة': 'company_name',
    'التواجد في الشركة': 'presence_in_company',
    'موقع سكن الموظف': 'employee_housing_location',
    'نوع الخدمة': 'service_type',
    'موقع سكن الشركة': 'company_housing_location',
    'اسم السكن في الشركة': 'company_housing_name',
    'رقم الغرفة': 'room_number',
    'رقم السرير': 'bed_number'
}

# تحويل الأعمدة
df_excel = df_excel.rename(columns=columns_map)

# --- الاتصال بقاعدة البيانات ---
conn = sqlite3.connect(r"D:\ghith\NEW\rooms\database.db")
cursor = conn.cursor()

# --- جلب جميع أرقام الموظفين الموجودين ---
cursor.execute("SELECT employee_code FROM employees")
existing_codes = set([row[0] for row in cursor.fetchall()])

# --- إدراج أو تحديث البيانات ---
for index, row in df_excel.iterrows():
    code = row['employee_code']

    if code not in existing_codes:
        # موظف جديد -> إضافة كاملة
        cols = ', '.join(row.index)
        placeholders = ', '.join(['?']*len(row))
        values = tuple(row.values)
        cursor.execute(f"INSERT INTO employees ({cols}) VALUES ({placeholders})", values)
    else:
        # موظف موجود -> تحديث الحقول الفارغة فقط
        updates = []
        values = []
        for col in row.index:
            if pd.notna(row[col]):
                # تحقق من أن الحقل فارغ في DB قبل التحديث
                updates.append(f"{col} = COALESCE({col}, ?)")
                values.append(row[col])
        if updates:
            set_clause = ', '.join(updates)
            values.append(code)
            cursor.execute(f"UPDATE employees SET {set_clause} WHERE employee_code = ?", values)

# --- حفظ التغييرات ---
conn.commit()
conn.close()
print("✅ تم إضافة البيانات الجديدة وتحديث الحقول الفارغة فقط")
