import base64
import tkinter as tk
from tkinter import simpledialog, messagebox
from tkinter import filedialog
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

class SecureMessagingApp:
    def __init__(self, master):
        self.master = master
        master.title("Secure Messaging App")

        self.sender_email = "springjava123test@gmail.com"  # введіть свою електронну пошту
        self.sender_password = "ecvn nhyl yctb ksmc"  # введіть свій пароль
        self.receiver_email = "bohdan.pankiv.it.2021@lpnu.ua"  # введіть електронну пошту отримувача
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 587

        self.message_to_send = ""
        self.sender_key = os.urandom(16)

        self.label = tk.Label(master, text="Secure Messaging App", font=("Helvetica", 16))
        self.label.pack(pady=10)

        self.encrypt_button = tk.Button(master, text="Надіслати повідомлення", command=self.send_message)
        self.encrypt_button.pack(pady=20)

        self.quit_button = tk.Button(master, text="Вийти", command=master.quit)
        self.quit_button.pack(pady=10)

    def send_message(self):
        # Питаємо користувача, чи він хоче додати файл
        if messagebox.askyesno("Додати файл", "Бажаєте додати файл до повідомлення?"):
            file_path = filedialog.askopenfilename()  # Обираємо файл
        else:
            file_path = None

        # Викликаємо функцію для введення тексту повідомлення
        message_text = self.get_text_input("Введіть текст повідомлення:")

        # Викликаємо функцію для відправлення повідомлення
        self.send_email(message_text, self.sender_key, file_path)

    def get_text_input(self, prompt):
        # Використовуємо діалогове вікно для введення тексту
        user_input = simpledialog.askstring("Введення тексту", prompt)

        # Перевіряємо, чи користувач не натиснув "Відмінити"
        if user_input is None:
            return ""

        return user_input

    def encrypt_message(self, message, key):
        cipher = Cipher(algorithms.AES(key), modes.CFB8(key), backend=default_backend())
        encryptor = cipher.encryptor()

        # Перевірка, чи дані вже є у вигляді байтів
        if not isinstance(message, bytes):
            message = message.encode()

        ciphertext = encryptor.update(message) + encryptor.finalize()
        return ciphertext

    def send_email(self, message, key, file_path=None):
        encrypted_message = self.encrypt_message(message, key)

        msg = MIMEMultipart()
        msg['From'] = self.sender_email
        msg['To'] = self.receiver_email
        msg['Subject'] = 'Encrypted Message'

        # Додаємо зашифроване повідомлення
        msg.attach(MIMEText(f'Encrypted Message: {encrypted_message.hex()}\nKey: {key.hex()}', 'plain'))

        if file_path:
            # Читаємо вміст файлу
            with open(file_path, "rb") as file:
                file_content = file.read()

            # Шифруємо вміст файлу
            encrypted_file_content = self.encrypt_message(file_content, key)

            # Зберігаємо зашифрований вміст файлу в окремому файлі
            encrypted_file_path = f"{file_path}.enc"
            with open(encrypted_file_path, "wb") as encrypted_file:
                encrypted_file.write(encrypted_file_content)

            # Додаємо зашифрований файл як вкладення
            with open(encrypted_file_path, "rb") as encrypted_file:
                attachment = MIMEApplication(encrypted_file.read(), _subtype="octet-stream")
                attachment.add_header('Content-Disposition', 'attachment', filename=os.path.basename(file_path))
                msg.attach(attachment)

            # Додаємо віддільний ключ для розшифрування вмісту файлу
            msg.attach(MIMEText(f'File Decryption Key: {key.hex()}', 'plain'))

        # Відправлення повідомлення
        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as smtp_server:
                smtp_server.starttls()  # Додаємо TLS
                smtp_server.login(self.sender_email, self.sender_password)
                smtp_server.send_message(msg)
        except Exception as e:
            messagebox.showerror("Помилка", f"Помилка під час відправлення електронної пошти: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureMessagingApp(root)
    root.mainloop()
