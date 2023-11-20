import smtplib
import tkinter as tk
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from tkinter import simpledialog, messagebox, filedialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os


class SecureMessagingApp:
    def __init__(self, master):
        self.master = master
        master.title("Secure Messaging App")

        self.sender_email = "springjava123test@gmail.com"
        self.sender_password = "ecvn nhyl yctb ksmc"
        self.receiver_email = None
        self.sender_key = os.urandom(16)
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 587

        self.label = tk.Label(master, text="Secure Messaging App", font=("Helvetica", 16))
        self.label.pack(pady=10)

        self.send_text_button = tk.Button(master, text="Надіслати текст", command=self.send_text_message)
        self.send_text_button.pack(pady=10)

        self.send_file_button = tk.Button(master, text="Надіслати файл", command=self.send_file_message)
        self.send_file_button.pack(pady=10)

        self.decrypt_button = tk.Button(master, text="Розшифрувати повідомлення", command=self.decrypt_message)
        self.decrypt_button.pack(pady=10)

        self.quit_button = tk.Button(master, text="Вийти", command=master.quit)
        self.quit_button.pack(pady=10)

    def send_text_message(self):
        self.receiver_email = simpledialog.askstring("Secure Messaging App", "Введіть пошту отримувача:")
        if not self.validate_email(self.receiver_email):
            messagebox.showerror("Помилка", "Пошту введено неправильно.")
            return

        message_text = simpledialog.askstring("Secure Messaging App", "Введіть текст повідомлення:")
        if not message_text:
            messagebox.showerror("Помилка", "Повідомлення не може бути порожнім.")
            return

        self.send_email_text(message_text)

    def send_file_message(self):
        self.receiver_email = simpledialog.askstring("Secure Messaging App", "Введіть пошту отримувача:")
        if not self.validate_email(self.receiver_email):
            messagebox.showerror("Помилка", "Пошту введено неправильно.")
            return

        file_path = filedialog.askopenfilename()
        if not file_path:
            messagebox.showerror("Помилка", "Будь ласка, виберіть файл для надіслання.")
            return

        self.send_email_file(file_path)

    def send_email_text(self, message):
        encrypted_message = self.encrypt_message(message, self.sender_key)

        msg = MIMEMultipart()
        msg['From'] = self.sender_email
        msg['To'] = self.receiver_email
        msg['Subject'] = 'Encrypted Message'

        msg.attach(MIMEText(f'Encrypted Message: {encrypted_message.hex()}\nKey: {self.sender_key.hex()}', 'plain'))

        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as smtp_server:
                smtp_server.starttls()
                smtp_server.login(self.sender_email, self.sender_password)
                smtp_server.send_message(msg)
                messagebox.showinfo("Secure Messaging App", "Повідомлення надіслано успішно.")
        except Exception as e:
            messagebox.showerror("Помилка", f"Помилка під час відправлення електронної пошти: {e}")

    def send_email_file(self, file_path):
        with open(file_path, "rb") as file:
            file_content = file.read()

        encrypted_file_content = self.encrypt_message(file_content, self.sender_key)

        msg = MIMEMultipart()
        msg['From'] = self.sender_email
        msg['To'] = self.receiver_email
        msg['Subject'] = 'Encrypted File'

        msg.attach(MIMEText(f' File Decryption Key: {self.sender_key.hex()}', 'plain'))

        encrypted_file_path = f"{file_path}.enc"
        with open(encrypted_file_path, "wb") as encrypted_file:
            encrypted_file.write(encrypted_file_content)

        with open(encrypted_file_path, "rb") as encrypted_file:
            attachment = MIMEApplication(encrypted_file.read(), _subtype="octet-stream")
            attachment.add_header('Content-Disposition', 'attachment', filename=os.path.basename(file_path))
            msg.attach(attachment)

        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as smtp_server:
                smtp_server.starttls()
                smtp_server.login(self.sender_email, self.sender_password)
                smtp_server.send_message(msg)
                messagebox.showinfo("Secure Messaging App", "Файл надіслано успішно.")
        except Exception as e:
            messagebox.showerror("Помилка", f"Помилка під час відправлення електронної пошти: {e}")

    def decrypt_message(self):
        confirm_window = tk.Toplevel(self.master)
        confirm_window.title("Вибір опції розшифрування")

        label = tk.Label(confirm_window, text="Виберіть опцію розшифрування:")
        label.pack(pady=10)

        text_button = tk.Button(confirm_window, text="Текст", command=self.decrypt_text)
        text_button.pack(pady=5)

        file_button = tk.Button(confirm_window, text="Файл", command=self.decrypt_file)
        file_button.pack(pady=5)

    def decrypt_text(self):
        encrypted_message = simpledialog.askstring("Secure Messaging App", "Вставте зашифроване текстове повідомлення:")
        key = simpledialog.askstring("Secure Messaging App", "Вставте ключ для розшифрування:")

        if not encrypted_message or not key:
            messagebox.showerror("Помилка", "Будь ласка, введіть зашифроване текстове повідомлення та ключ.")
            return

        encrypted_message_bytes = bytes.fromhex(encrypted_message)
        key_bytes = bytes.fromhex(key)

        decrypted_message = self.decrypt_message_content(encrypted_message_bytes, key_bytes)

        read_window = tk.Toplevel(self.master)
        read_window.title("Розшифроване текстове повідомлення")

        decrypted_message_text = tk.Text(read_window, wrap=tk.WORD, width=40, height=5)
        decrypted_message_text.insert(tk.END, decrypted_message.decode())
        decrypted_message_text.configure(state="disabled")
        decrypted_message_text.pack(pady=10)

    def decrypt_file(self):
        file_path = filedialog.askopenfilename()

        if not file_path:
            messagebox.showerror("Помилка", "Будь ласка, виберіть файл для розшифрування.")
            return

        key = simpledialog.askstring("Secure Messaging App", "Вставте ключ для розшифрування:")

        if not key:
            messagebox.showerror("Помилка", "Будь ласка, введіть ключ для розшифрування.")
            return

        with open(file_path, "rb") as file:
            encrypted_file_content = file.read()

        key_bytes = bytes.fromhex(key)
        decrypted_file_content = self.decrypt_message_content(encrypted_file_content, key_bytes)

        decrypted_file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                           filetypes=[("Text Files", "*.txt")])

        if decrypted_file_path:
            with open(decrypted_file_path, "wb") as decrypted_file:
                decrypted_file.write(decrypted_file_content)

            messagebox.showinfo("Secure Messaging App", "Файл розшифровано успішно.")
        else:
            messagebox.showwarning("Увага", "Розшифрування файлу скасовано.")

    def decrypt_message_content(self, encrypted_message, key):
        cipher = Cipher(algorithms.AES(key), modes.CFB8(key), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
        return decrypted_message

    def validate_email(self, email):
        return "@" in email and "." in email.split("@")[-1]

    def encrypt_message(self, message, key):
        cipher = Cipher(algorithms.AES(key), modes.CFB8(key), backend=default_backend())
        encryptor = cipher.encryptor()

        if not isinstance(message, bytes):
            message = message.encode()

        ciphertext = encryptor.update(message) + encryptor.finalize()
        return ciphertext


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureMessagingApp(root)
    root.mainloop()
