"""Data export helpers."""
import csv
def write_excel_csv(path, headers, rows):
    with open(path,"w",newline="",encoding="utf-8-sig") as f:
        writer=csv.writer(f,delimiter=";",lineterminator="\r\n")
        writer.writerow(headers)
        for row in rows:
            writer.writerow([str(v).replace(".",",") if isinstance(v,float) else v for v in row])
