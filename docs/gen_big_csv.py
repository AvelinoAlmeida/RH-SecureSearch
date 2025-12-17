import csv
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(BASE_DIR, "employee_salary_dataset.csv")
DST = os.path.join(BASE_DIR, "employee_salary_dataset_5000.csv")

TARGET = 5000

with open(SRC, "r", encoding="utf-8") as f_in:
    reader = list(csv.DictReader(f_in))

rows = []
emp_id = 1
while len(rows) < TARGET:
    for r in reader:
        if len(rows) >= TARGET:
            break
        new = r.copy()
        new["EmployeeID"] = str(emp_id)
        new["Name"] = f"Employee_{emp_id}"
        rows.append(new)
        emp_id += 1

fieldnames = reader[0].keys()
with open(DST, "w", encoding="utf-8", newline="") as f_out:
    writer = csv.DictWriter(f_out, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

print(f"Gerado {DST} com {len(rows)} registos.")
