import os
import smtplib
from dotenv import load_dotenv
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

load_dotenv()

email_user = os.getenv("EMAIL_USER")
email_pass = os.getenv("EMAIL_PASS")

def send_alert_report():
    subject = "A Brute Force Attack Detected"
    body = "A brute-firce attack was detected on you system. Immediate action is recommended!"
    send_email(subject, body)

def send_analysis_report(results):
    subject = "Log Analysis Completed"
    body = f"The log analysis has been completed. Here are the results: {results}"
    send_email(subject, body)

def send_email(subject, body, to_email):
    try:
        smtp_server = "smtp.gmail.com"
        smtp_port = 587

        msg = MIMEMultipart()
        msg['From'] = email_user
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()

        server.login(email_user, email_pass)

        server.sendmail(email_user, to_email, msg.as_string())

        server.quit()

        print(f"Email sent to {to_email}!")
    except Exception as e:
        print(f"An error occured: {e}")