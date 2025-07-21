import cx_Oracle
import getpass
import os
import datetime
from jinja2 import Environment, FileSystemLoader

# --- User Input ---
print("🔐 Oracle Database CIS Audit (Python version)")
host = input("Enter Oracle Host: ")
port = input("Enter Port [default: 1521]: ") or "1521"
service = input("Enter Service Name/SID: ")
user = input("Enter Read-Only Username: ")
password = getpass.getpass(f"Enter password for {user}: ")

dsn = cx_Oracle.makedsn(host, port, service_name=service)

# --- Checks Definition ---
cis_checks = [
    {
        "id": "1.1",
        "desc": "Ensure auditing is enabled",
        "query": "SELECT value FROM v$parameter WHERE name = 'audit_trail'",
        "risk": "High",
        "fix_type": "Quick",
        "remediation": "Set 'audit_trail=DB,EXTENDED' in init.ora or spfile"
    },
    {
        "id": "2.1",
        "desc": "Password complexity enforced",
        "query": """SELECT profile, resource_name, limit 
                    FROM dba_profiles 
                    WHERE resource_name = 'PASSWORD_VERIFY_FUNCTION'""",
        "risk": "Medium",
        "fix_type": "Planned",
        "remediation": "Assign strong password functions to user profiles"
    },
    {
        "id": "3.1",
        "desc": "DBA role misuse",
        "query": """SELECT grantee FROM dba_role_privs 
                    WHERE granted_role = 'DBA'""",
        "risk": "High",
        "fix_type": "Involved",
        "remediation": "Limit DBA role assignment to only authorized users"
    },
    {
        "id": "4.1",
        "desc": "Failed login audit check",
        "query": """SELECT username, timestamp, returncode 
                    FROM dba_audit_session 
                    WHERE returncode != 0 AND ROWNUM <= 5""",
        "risk": "Medium",
        "fix_type": "Quick",
        "remediation": "Enable audit for session logon failures"
    },
    {
        "id": "5.1",
        "desc": "Check for default user accounts",
        "query": """SELECT username, account_status 
                    FROM dba_users 
                    WHERE username IN ('SCOTT','HR','OUTLN')""",
        "risk": "Low",
        "fix_type": "Quick",
        "remediation": "Lock/remove unused default accounts"
    }
]

# --- Connect & Execute ---
print("🧪 Connecting to Oracle...")
try:
    connection = cx_Oracle.connect(user=user, password=password, dsn=dsn)
except cx_Oracle.Error as error:
    print("❌ Connection failed:", error)
    exit(1)

print("✅ Connected.")

results = []
cursor = connection.cursor()

for check in cis_checks:
    try:
        cursor.execute(check["query"])
        output = cursor.fetchall()
    except Exception as e:
        output = [(f"Error: {str(e)}",)]

    results.append({
        "id": check["id"],
        "desc": check["desc"],
        "risk": check["risk"],
        "fix_type": check["fix_type"],
        "remediation": check["remediation"],
        "output": output
    })

cursor.close()
connection.close()

# --- HTML Report Generation ---
report_dir = "cis_html_reports"
os.makedirs(report_dir, exist_ok=True)
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
html_report = f"{report_dir}/oracle_cis_report_{timestamp}.html"

# Use Jinja2 Template Engine
env = Environment(loader=FileSystemLoader('.'))
template = env.from_string("""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Oracle CIS Audit Report</title>
    <style>
        body { font-family: Arial; padding: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 10px; border: 1px solid #ccc; vertical-align: top; }
        th { background-color: #f0f0f0; }
        .High { background-color: #f8d7da; }
        .Medium { background-color: #fff3cd; }
        .Low { background-color: #d4edda; }
        pre { white-space: pre-wrap; background: #f4f4f4; padding: 8px; }
    </style>
</head>
<body>
    <h1>Oracle Database CIS Audit Report</h1>
    <p><strong>Date:</strong> {{ date }}</p>
    <table>
        <thead>
            <tr>
                <th>Finding ID</th>
                <th>Description</th>
                <th>Risk Rating</th>
                <th>Fix Type</th>
                <th>Remediation</th>
                <th>Output</th>
            </tr>
        </thead>
        <tbody>
        {% for item in results %}
            <tr class="{{ item.risk }}">
                <td>{{ item.id }}</td>
                <td>{{ item.desc }}</td>
                <td>{{ item.risk }}</td>
                <td>{{ item.fix_type }}</td>
                <td>{{ item.remediation }}</td>
                <td><pre>{{ item.output | join('\n') }}</pre></td>
            </tr>
        {% endfor %}
        </tbody>
    </table>
</body>
</html>
""")

with open(html_report, "w") as f:
    f.write(template.render(date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), results=results))

print(f"📄 Report saved to: {html_report}")
