import pandas as pd
import sqlite3

# مسار ملف Excel
excel_file = r"D:\ghith\NEW\rooms\asset.xlsx"

# قراءة الإكسل
df = pd.read_excel(excel_file)

# اتصال بقاعدة البيانات
conn = sqlite3.connect(r"D:\ghith\NEW\rooms\instance\housing.db")


# تحميل البيانات إلى الجدول assets
df.to_sql("assets", conn, if_exists="append", index=False)

conn.close()

print("تم تحميل البيانات من الإكسل إلى جدول assets بنجاح ✅")
