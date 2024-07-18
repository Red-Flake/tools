import smtpd
import asyncore

class CustomSMTPServer(smtpd.SMTPServer):

    def process_message(self, peer, mailfrom, rcpttos, data, mail_options=None, rcpt_options=None):
        print('Receiving message from:', peer)
        print('Message addressed from:', mailfrom)
        print('Message addressed to  :', rcpttos)
        print('Message length        :', len(data))
        print('Message content       :\n', data)

if __name__ == "__main__":
    server = CustomSMTPServer(('0.0.0.0', 25), None)
    print("SMTP server is running...")
    asyncore.loop()