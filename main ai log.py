from datetime import datetime

# AI Security Log Analyzer

# Read logs from sample_log.txt
with open("sample_log.txt", "r") as file:
    logs = file.readlines()

user_attack_count = {}
ip_fail_count = {}
ip_timestamps = {}
successful_users = set()
total_failed = 0
successful_logins = 0

# Analyze each log line
for line in logs:
    line = line.strip()

    if line == "":
        continue

    timestamp, ip, user, status = line.split(",")

    if status == "FAILED":
        total_failed += 1
        ip_fail_count[ip] = ip_fail_count.get(ip, 0) + 1
        user_attack_count[user] = user_attack_count.get(user, 0) + 1

        time_obj = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")

        if ip not in ip_timestamps:
            ip_timestamps[ip] = []

        ip_timestamps[ip].append(time_obj)

    elif status == "SUCCESS":
        successful_logins += 1
        successful_users.add(user)

# Time-based brute force detection
brute_force_ips = []

for ip, times in ip_timestamps.items():
    times.sort()

    for i in range(len(times) - 4):
        if (times[i + 4] - times[i]).seconds <= 60:
            brute_force_ips.append(ip)
            break

# Risk classification
high_risk_ips = []
medium_risk_ips = []
low_risk_ips = []

for ip, count in ip_fail_count.items():
    if ip in brute_force_ips or count >= 5:
        high_risk_ips.append(ip)
    elif count >= 3:
        medium_risk_ips.append(ip)
    else:
        low_risk_ips.append(ip)

# Most targeted user
if user_attack_count:
    most_targeted_user = max(user_attack_count, key=user_attack_count.get)
else:
    most_targeted_user = "None"

# Final security assessment
if total_failed >= 8 or brute_force_ips:
    final_assessment = "System Under Attack! Immediate Action Required!"
elif total_failed >= 4:
    final_assessment = "Suspicious Activity Detected. Monitor Closely."
else:
    final_assessment = "System Operating Normally."

# Severity level
if total_failed >= 8 or brute_force_ips:
    severity = "HIGH"
elif total_failed >= 4:
    severity = "MEDIUM"
else:
    severity = "LOW"

# Print report
print("\n🚨 Suspicious Activity Report:\n")

if brute_force_ips:
    print("🚨 TIME-BASED ATTACK DETECTED:")
    for ip in brute_force_ips:
        print(f"⚠️ {ip} → Multiple failed logins within 1 minute!")
    print()

for ip in high_risk_ips:
    print(f"🔥 HIGH RISK ALERT: {ip}")
    print(f"   Failed Attempts: {ip_fail_count[ip]}")
    print("   Status: Possible Brute Force Attack 🚨\n")

for ip in medium_risk_ips:
    print(f"⚠️ MEDIUM RISK: {ip}")
    print(f"   Failed Attempts: {ip_fail_count[ip]}\n")

for ip in low_risk_ips:
    print(f"ℹ️ LOW RISK: {ip}")
    print(f"   Failed Attempts: {ip_fail_count[ip]}\n")

print("📊 Summary Report:\n")
print(f"Total Failed Attempts: {total_failed}")
print(f"Total Successful Logins: {successful_logins}")
print(f"Successful Users: {', '.join(successful_users) if successful_users else 'None'}\n")

print(f"🎯 Most Targeted User: {most_targeted_user}")
if most_targeted_user != "None":
    print(f"   Attack Attempts: {user_attack_count[most_targeted_user]}\n")

print("📋 Risk Breakdown:")
print(f"High Risk IPs: {', '.join(high_risk_ips) if high_risk_ips else 'None'}")
print(f"Medium Risk IPs: {', '.join(medium_risk_ips) if medium_risk_ips else 'None'}")
print(f"Low Risk IPs: {', '.join(low_risk_ips) if low_risk_ips else 'None'}\n")

print("🛡️ Final Security Assessment:")
print(final_assessment)
print(f"🔥 Severity Level: {severity}")

# Save report to report.txt
with open("report.txt", "w") as report:
    report.write("AI Security Log Analyzer Report\n")
    report.write("================================\n\n")

    if brute_force_ips:
        report.write("Time-Based Attack Detected:\n")
        for ip in brute_force_ips:
           report.write(f"{ip} - Multiple failed logins within 1 minute\n")
        report.write("\n")

    report.write("Summary Report:\n")
    report.write(f"Total Failed Attempts: {total_failed}\n")
    report.write(f"Total Successful Logins: {successful_logins}\n")
    report.write(f"Successful Users: {', '.join(successful_users) if successful_users else 'None'}\n\n")

    report.write(f"Most Targeted User: {most_targeted_user}\n")
    if most_targeted_user != "None":
        report.write(f"Attack Attempts: {user_attack_count[most_targeted_user]}\n\n")

    report.write("Risk Breakdown:\n")
    report.write(f"High Risk IPs: {', '.join(high_risk_ips) if high_risk_ips else 'None'}\n")
    report.write(f"Medium Risk IPs: {', '.join(medium_risk_ips) if medium_risk_ips else 'None'}\n")
    report.write(f"Low Risk IPs: {', '.join(low_risk_ips) if low_risk_ips else 'None'}\n\n")

    report.write("Final Assessment:\n")
    report.write(final_assessment + "\n")
    report.write(f"Severity Level: {severity}\n")

print("\n📁 Report saved as report.txt")