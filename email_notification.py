import os
import smtplib
from dotenv import load_dotenv
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

load_dotenv(dotenv_path="C:/Users/Admin/LogSniper-fresh/.env")

email_user = os.getenv("EMAIL_USER")
email_pass = os.getenv("EMAIL_PASS")

def send_alert_report():
    subject = "A Brute Force Attack Detected"
    body = "A brute-force attack was detected on you system. Immediate action is recommended!"
    to_email = f"{email_user}"
    send_email(subject, body, to_email)

def send_analysis_report_access(results):
    subject = "Log Analysis Completed"
    body = f"<h3>The log analysis has been completed. Here are the results:</h3><br><br>"

    for entry in results:
        body += f"<b>[{entry["classification"]}]</b> IP: <b>{entry["ip"]}</b>, Date: <b>{entry["date"]}</b>, Method: <b>{entry["method"]}</b><br>"
        body += f"Path: <b>{entry["path"]}</b> Status: <b>{entry["status"]}</b> User Agent: <b>{entry["user_agent"]}</b><br>"
        body += f"Country: <b>{entry["country"]}</b>, Region: <b>{entry["region"]}</b>, City: <b>{entry["city"]}</b>, Timezone: <b>{entry["timezone"]}</b><br>"
        body += "<hr>"

    body += f"<br><b>Found {len(results)} classified entries. Saved to suspicious_entries_access.json (check on your computer)</b>"

    send_email(subject, body, email_user)

def send_analysis_report_auth(results):
    subject = "Log Analysis Completed"
    body = f"<h3>The log analysis has been completed. Here are the results:</h3>"

    for entry in results:
        body += f"[<b>{entry["classification"]}</b>] IP: <b>{entry["timestamp"]}</b>, Date: <b>{entry["ip"]}</b>, Method: <b>{entry["user"]}</b><br><br>"
        body += f"Country: <b>{entry["country"]}</b>, Region: <b>{entry["region"]}</b>, City: <b>{entry["city"]}</b>, Timezone: <b>{entry["timezone"]}</b><br>"
        body += "<hr>"

    body += f"<br><b>Found {len(results)} classified entries. Saved to suspicious_entries_auth.json (check on your computer)</b>"

    send_email(subject, body, email_user)

def send_analysis_report_evtx(results):
    subject = "Log Analysis Completed"
    body = f"<h3>The log analysis has been completed. Here are the results:</h3><br><br>"

    for entry in results:
        body += f"<b>Detection:</b> {entry.get('detection', 'N/A')}<br>"
        body += f"<b>IP:</b> {entry.get('ip', 'Unknown')}<br>"
        body += f"<b>Account:</b> {entry.get('account', 'Unknown')}<br>"
        body += f"<b>Country:</b> {entry.get('country', 'Unknown')}<br>"
        body += f"<b>Region:</b> {entry.get('region', 'Unknown')}<br>"
        body += f"<b>City:</b> {entry.get('city', 'Unknown')}<br>"
        body += f"<b>Timezone:</b> {entry.get('timezone', 'Unknown')}<br>"
        body += f"<b>Attempts:</b> {entry.get('attempts', 'N/A')}<br>"
        body += f"<b>Time Window Start:</b> {entry.get('time_window_start', 'N/A')}<br>"
        body += f"<b>Time Window End:</b> {entry.get('time_window_end', 'N/A')}<br>"
        body += "<hr>"

    body += f"<br><b>Found {len(results)} classified entries. Saved to suspicious_entries_evtx.json (check on your computer)</b>"

    send_email(subject, body, email_user)

def send_email(subject, body, to_email):
    try:
        smtp_server = "smtp.gmail.com"
        smtp_port = 465

        msg = MIMEMultipart()
        msg['From'] = email_user
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'html'))

        server = smtplib.SMTP_SSL(smtp_server, smtp_port)
#        server.starttls()

        server.login(email_user, email_pass)

        server.sendmail(email_user, to_email, msg.as_string())

        server.quit()

        print(f"Email sent to {to_email}!")
    except Exception as e:
        print(f"An error occured: {e}")
    except smtplib.SMTPConnectError as e:
        print(f"Connection error: {e}")
    except Exception as e:
        print(f"An error occured: {e}")