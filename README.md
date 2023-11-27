# pescanner
ML-Based PE File Scanner

# Commands

```shell
python3 main.py --file "test/python3.exe"
python3 main.py --file "test/python3.exe" --remove
python3 main.py --file "test/python3.exe" --report python3_scan_report.csv
python3 main.py --file "test/python3.exe" --report python3_scan_report.csv --remove

python3 main.py --path "exe_files/folder"
python3 main.py --path "exe_files/folder" --remove
python3 main.py --path "exe_files/folder" --report exefiles_scan_report.csv
python3 main.py --path "exe_files/folder" --report exefiles_scan_report.csv --remove
```
