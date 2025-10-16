# messages/mail/mail.py
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class Mail:
    def __init__(self, receiver_email, body, subject="Pesan dari Python"):
        self.sender_email = "liando1801@gmail.com"
        self.password = "rmwfigzyhonwqzkx" 
        self.receiver_email = receiver_email
        self.subject = subject
        self.body = body

    def send(self):
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = self.subject
            msg["From"] = self.sender_email
            msg["To"] = self.receiver_email

            msg.attach(MIMEText(self.body, "html"))

            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(self.sender_email, self.password)
                server.sendmail(self.sender_email, self.receiver_email, msg.as_string())

            return {"status": "success", "message": f"Email terkirim ke {self.receiver_email}"}

        except Exception as e:
            return {"status": "error", "message": str(e)}



# import smtplib
# from email.mime.text import MIMEText
# from email.mime.multipart import MIMEMultipart

# sender_email = "liando1801@gmail.com"
# receiver_email = "liando1804@gmail.com"
# password = "rmwfigzyhonwqzkx" 

# msg = MIMEMultipart("alternative")
# msg["Subject"] = "Pesan dari Python"
# msg["From"] = sender_email
# msg["To"] = receiver_email

# body = "Halo, ini pesan yang dikirim lewat Python!"
# msg.attach(MIMEText(body, "plain"))

# with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
#     server.login(sender_email, password)
#     server.sendmail(sender_email, receiver_email, msg.as_string())

# print("Email terkirim!")
