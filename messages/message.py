from messages.whatsapp.wa import WhatsApp
from messages.mail.mail import Mail

class Message:
    def __init__(self, target, message, subject=None):
        self.target = target
        self.message = message
        self.subject = subject

    def send_via_whatsapp(self):
        whatsapp = WhatsApp(self.target, self.message)
        result = whatsapp.send()
        
        if result.get("status") == "error":
            print(f"Gagal kirim WhatsApp: {result['message']}")
        # else:
        #     print(f"Pesan WhatsApp berhasil dikirim ke {self.target}")
        return result

    def send_via_email(self):
        mail = Mail(self.target, self.message, self.subject or "Pesan dari Python")
        result = mail.send()
        if result.get("status") == "error":
            print(f"Gagal kirim Email: {result['message']}")
        # else:
        #     print(f"Email berhasil dikirim ke {self.target}")
        return result
