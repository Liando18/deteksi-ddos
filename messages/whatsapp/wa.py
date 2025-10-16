import requests

class WhatsApp:
    def __init__(self, target, message):
        self.target = target
        self.message = message

    def send(self):
        url = "https://api.fonnte.com/send"
        token = "aLPFtnLQvB9KCFtXAcVX"

        payload = {
            'target': self.target,
            'message': self.message
        }

        headers = {
            'Authorization': token
        }

        try:
            response = requests.post(url, data=payload, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"status": "error", "message": str(e)}



# url = "https://api.fonnte.com/send"

# payload = {
#     'target': '6285835524290',
#     'message': 'Halo! Pesan ini dikirim otomatis via Python 🚀'
# }

# headers = {
#     'Authorization': 'aLPFtnLQvB9KCFtXAcVX'
# }

# response = requests.post(url, data=payload, headers=headers)

# print(response.text)