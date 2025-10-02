import sqlite3

DB_PATH = r"/rooms/database.db"

def clean_duplicates():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # جلب جميع الموظفين
    cur.execute("SELECT employee_code, name, bed_number FROM employees")
    rows = cur.fetchall()

    for code, name, bed in rows:
        if not code:
            continue

        code_str = str(code).strip()
        if code_str.endswith(".0"):
            base_code = code_str.replace(".0", "")

            # جلب الموظف بالكود الأساسي (بدون .0)
            cur.execute("SELECT employee_code, bed_number FROM employees WHERE employee_code = ?", (base_code,))
            main_emp = cur.fetchone()

            if main_emp:
                main_code, main_bed = main_emp

                # لو الأساسي ما عنده سرير والمكرر عنده سرير → ننقله
                if (not main_bed or main_bed.strip() == "") and bed and bed.strip():
                    cur.execute(
                        "UPDATE employees SET bed_number = ? WHERE employee_code = ?",
                        (bed.strip(), base_code)
                    )
                    print(f"🔄 تم نقل السرير من {code_str} → {base_code}")

                # حذف المكرر
                cur.execute("DELETE FROM employees WHERE employee_code = ?", (code_str,))
                print(f"🗑️ تم حذف الموظف المكرر: {code_str}")

            else:
                # إذا مافيش موظف أصلي → نعدل الكود مباشرة ونخليه صحيح
                cur.execute(
                    "UPDATE employees SET employee_code = ? WHERE employee_code = ?",
                    (base_code, code_str)
                )
                print(f"✅ تم تحويل الكود من {code_str} → {base_code}")

    conn.commit()
    conn.close()
    print("🚀 تم تنظيف المكررات بنجاح.")

if __name__ == "__main__":
    clean_duplicates()
