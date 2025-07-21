#!/bin/bash

# --- CONFIGURATION ---
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT="oracle_cis_report_$TIMESTAMP.html"
SQL_OUTPUT="sql_output_$TIMESTAMP.txt"
TEMP_SQL="tmp_check_$TIMESTAMP.sql"
HTML_DIR="./cis_reports"
mkdir -p "$HTML_DIR"

# --- USER INPUT ---
read -rp "Enter Oracle Hostname: " HOST
read -rp "Enter Oracle Port [1521]: " PORT
PORT=${PORT:-1521}
read -rp "Enter Oracle SID or Service Name: " SERVICE
read -rp "Enter Read-Only Username: " USERNAME
read -srp "Enter Password for $USERNAME: " PASSWORD
echo

CONN_STRING="$USERNAME/$PASSWORD@(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=$HOST)(PORT=$PORT))(CONNECT_DATA=(SERVICE_NAME=$SERVICE)))"

# --- CHECK CONNECTIVITY ---
echo "[*] Verifying connection..."
if ! echo "SELECT 1 FROM dual;" | sqlplus -s "$CONN_STRING" | grep -q "1"; then
    echo "[!] Connection failed. Exiting."
    exit 1
fi

echo "[✓] Connected successfully."

# --- DEFINE CHECKS (CIS CONTROL ID | DESCRIPTION | SQL | RISK | FIX TYPE | REMEDIATION) ---
declare -a CHECKS=(
  "1.1|Ensure auditing is enabled|show parameter audit_trail|High|Quick|Enable auditing in init.ora/spfile with 'audit_trail=DB,EXTENDED'"
  "2.1|Password complexity enforced|SELECT profile, resource_name, limit FROM dba_profiles WHERE resource_name='PASSWORD_VERIFY_FUNCTION';|Medium|Planned|Assign a strong password policy to each profile"
  "3.1|DBA role misuse|SELECT * FROM dba_role_privs WHERE granted_role='DBA';|High|Involved|Restrict DBA role assignment to limited admins"
  "4.1|Failed login audit|SELECT * FROM dba_audit_trail WHERE returncode <> 0 AND ROWNUM < 5;|Medium|Quick|Enable audit for 'CREATE SESSION' failures"
  "5.1|Default user accounts|SELECT username, account_status FROM dba_users WHERE username IN ('SCOTT','HR','OUTLN');|Low|Quick|Lock or remove unused default accounts"
)

# --- RUN CHECKS ---
echo "[*] Running CIS checks..."

> "$SQL_OUTPUT"

for entry in "${CHECKS[@]}"; do
  IFS='|' read -r ID DESC SQL_QUERY RISK FIX REMED <<< "$entry"
  
  echo "SET HEADING OFF FEEDBACK OFF ECHO OFF PAGESIZE 1000 LINESIZE 200" > "$TEMP_SQL"
  echo "$SQL_QUERY;" >> "$TEMP_SQL"
  
  OUTPUT=$(sqlplus -s "$CONN_STRING" @"$TEMP_SQL")
  echo "[$ID] $DESC" >> "$SQL_OUTPUT"
  echo "$OUTPUT" >> "$SQL_OUTPUT"
  echo -e "--------------------------------------------------\n" >> "$SQL_OUTPUT"

  RESULTS+=("$ID|$DESC|$RISK|$FIX|$REMED|$OUTPUT")
done

rm -f "$TEMP_SQL"

# --- GENERATE HTML REPORT ---
cat > "$HTML_DIR/$REPORT" <<EOF
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Oracle CIS Audit Report</title>
  <style>
    body { font-family: Arial, sans-serif; padding: 20px; }
    h1 { color: #2E86C1; }
    table { border-collapse: collapse; width: 100%; margin-top: 20px; }
    th, td { border: 1px solid #ccc; padding: 10px; text-align: left; vertical-align: top; }
    th { background-color: #f2f2f2; }
    .critical { background-color: #f8d7da; }
    .high { background-color: #f5c6cb; }
    .medium { background-color: #fff3cd; }
    .low { background-color: #d4edda; }
    pre { background-color: #f4f4f4; padding: 10px; }
  </style>
</head>
<body>
  <h1>Oracle Database CIS Audit Report</h1>
  <p>Generated on: $(date)</p>
  <table>
    <tr>
      <th>Finding ID</th>
      <th>Description</th>
      <th>Risk Rating</th>
      <th>Fix Type</th>
      <th>Remediation Steps</th>
      <th>Result Output</th>
    </tr>
EOF

for row in "${RESULTS[@]}"; do
  IFS='|' read -r ID DESC RISK FIX REMED OUT <<< "$row"
  RISK_CLASS=$(echo "$RISK" | tr '[:upper:]' '[:lower:]')
  echo "<tr class=\"$RISK_CLASS\">" >> "$HTML_DIR/$REPORT"
  echo "<td>$ID</td><td>$DESC</td><td>$RISK</td><td>$FIX</td><td>$REMED</td><td><pre>$OUT</pre></td>" >> "$HTML_DIR/$REPORT"
  echo "</tr>" >> "$HTML_DIR/$REPORT"
done

cat >> "$HTML_DIR/$REPORT" <<EOF
  </table>
</body>
</html>
EOF

echo -e "\n[✓] Audit complete. Report saved to: $HTML_DIR/$REPORT"
