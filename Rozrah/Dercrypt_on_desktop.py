import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class MainApp:
    def __init__(self, master):
        self.master = master
        master.title("Main App")

        self.create_widgets()

    def create_widgets(self):
        self.decrypt_button = tk.Button(self.master, text="Розшифрувати повідомлення/файл",
                                        command=self.show_decrypt_menu)
        self.decrypt_button.pack(pady=20)

        self.quit_button = tk.Button(self.master, text="Вийти", command=self.master.quit)
        self.quit_button.pack(pady=10)

    def show_decrypt_menu(self):
        decrypt_menu = DecryptMenu(self.master)
        decrypt_menu.show()


class DecryptMenu:
    def __init__(self, master):
        self.master = master
        self.master.withdraw()  # Ховаємо головне вікно

        self.decrypt_window = tk.Toplevel(self.master)
        self.decrypt_window.title("Decrypt Menu")

        self.create_widgets()

    def create_widgets(self):
        self.encrypted_message_label = tk.Label(self.decrypt_window, text="Введіть зашифроване повідомлення:")
        self.encrypted_message_label.pack()

        self.encrypted_message_entry = tk.Entry(self.decrypt_window)
        self.encrypted_message_entry.pack()

        self.key_label = tk.Label(self.decrypt_window, text="Введіть ключ:")
        self.key_label.pack()

        self.key_entry = tk.Entry(self.decrypt_window)
        self.key_entry.pack()

        self.decrypt_button = tk.Button(self.decrypt_window, text="Розшифрувати повідомлення",
                                        command=self.decrypt_message)
        self.decrypt_button.pack()

        self.decrypted_text_label = tk.Label(self.decrypt_window, text="Розшифроване повідомлення:")
        self.decrypted_text_label.pack()

        self.decrypted_text = scrolledtext.ScrolledText(self.decrypt_window, wrap=tk.WORD, width=40, height=10)
        self.decrypted_text.pack()

        copy_button = tk.Button(self.decrypt_window, text="Копіювати", command=lambda: self.copy_to_clipboard(self.decrypted_text))
        copy_button.pack()

        # Додав віджет вибору файлу та кнопку розшифрування файлу
        self.file_path_var = tk.StringVar()
        self.file_path_entry = tk.Entry(self.decrypt_window, textvariable=self.file_path_var, state='readonly')
        self.file_path_entry.pack()

        self.browse_button = tk.Button(self.decrypt_window, text="Вибрати файл", command=self.browse_file)
        self.browse_button.pack()

        self.key_label_file = tk.Label(self.decrypt_window, text="Введіть ключ для файлу:")
        self.key_label_file.pack()

        self.key_entry_file = tk.Entry(self.decrypt_window)
        self.key_entry_file.pack()

        self.decrypt_button_file = tk.Button(self.decrypt_window, text="Розшифрувати файл", command=self.decrypt_file)
        self.decrypt_button_file.pack()

    def decrypt_message(self):
        encrypted_message_hex = self.encrypted_message_entry.get()
        key_hex = self.key_entry.get()

        try:
            encrypted_message = bytes.fromhex(encrypted_message_hex)
            key = bytes.fromhex(key_hex)

            decrypted_message = self.decrypt(encrypted_message, key)

            self.decrypted_text.delete(1.0, tk.END)
            self.decrypted_text.insert(tk.END, decrypted_message)
        except ValueError:
            messagebox.showerror("Помилка", "Неправильний формат зашифрованого повідомлення або ключа.")

    def decrypt_file(self):
        file_path = self.file_path_var.get()
        key_hex = self.key_entry_file.get()

        try:
            key = bytes.fromhex(key_hex)

            decrypted_content = self.decrypt(file_path, key)

            self.decrypted_text.delete(1.0, tk.END)
            self.decrypted_text.insert(tk.END, decrypted_content)
        except (ValueError, FileNotFoundError):
            messagebox.showerror("Помилка", "Неправильний формат ключа або файлу.")

    def decrypt(self, content, key):
        cipher = Cipher(algorithms.AES(key), modes.CFB8(key), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_content = decryptor.update(content) + decryptor.finalize()

        return decrypted_content.decode()

    def copy_to_clipboard(self, text_widget):
        try:
            selected_text = text_widget.get("1.0", tk.END)

            if selected_text:
                self.master.clipboard_clear()
                self.master.clipboard_append(selected_text)
        except tk.TclError:
            pass

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        self.file_path_var.set(file_path)

    def show(self):
        # Виводимо вікно Decrypt File Window
        self.decrypt_window.deiconify()


if __name__ == "__main__":
    root = tk.Tk()
    app = MainApp(root)
    root.mainloop()
