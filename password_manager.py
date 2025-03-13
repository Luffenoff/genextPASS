import sys
import sqlite3
import string
import random
import os
from dotenv import load_dotenv
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QPushButton, QLabel, QLineEdit, 
                            QTableWidget, QTableWidgetItem, QMessageBox)
from PySide6.QtCore import Qt
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Загрузка переменных окружения
load_dotenv()

class PasswordManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(os.getenv('APP_NAME', 'Менеджер паролей'))
        self.setGeometry(100, 100, 
                        int(os.getenv('WINDOW_WIDTH', 800)), 
                        int(os.getenv('WINDOW_HEIGHT', 600)))
        
        # Инициализация базы данных
        self.db_name = os.getenv('DB_NAME', 'passwords.db')
        self.init_database()
        
        # Инициализация шифрования
        self.init_encryption()
        
        # Создание центрального виджета
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Форма добавления нового сервиса
        form_layout = QHBoxLayout()
        
        self.service_input = QLineEdit()
        self.service_input.setPlaceholderText("Название сервиса")
        form_layout.addWidget(self.service_input)
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Имя пользователя")
        form_layout.addWidget(self.username_input)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Пароль")
        form_layout.addWidget(self.password_input)
        
        generate_btn = QPushButton("Сгенерировать")
        generate_btn.clicked.connect(self.generate_password)
        form_layout.addWidget(generate_btn)
        
        add_btn = QPushButton("Добавить")
        add_btn.clicked.connect(self.add_service)
        form_layout.addWidget(add_btn)
        
        layout.addLayout(form_layout)
        
        # Таблица с сервисами
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Сервис", "Пользователь", "Пароль"])
        layout.addWidget(self.table)
        
        # Кнопка обновления таблицы
        refresh_btn = QPushButton("Обновить")
        refresh_btn.clicked.connect(self.refresh_table)
        layout.addWidget(refresh_btn)
        
        # Загрузка данных
        self.refresh_table()
        
    def init_encryption(self):
        key = os.getenv('ENCRYPTION_KEY')
        if not key:
            key = Fernet.generate_key()
            with open('.env', 'a') as f:
                f.write(f'\nENCRYPTION_KEY={key.decode()}\n')
        else:
            try:
                # Пробуем использовать существующий ключ
                key = key.encode()
                Fernet(key)
            except:
                # Если ключ некорректный, генерируем новый
                key = Fernet.generate_key()
                with open('.env', 'a') as f:
                    f.write(f'\nENCRYPTION_KEY={key.decode()}\n')
        
        self.cipher_suite = Fernet(key)
        
    def init_database(self):
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS passwords
                    (service TEXT, username TEXT, password TEXT)''')
        conn.commit()
        conn.close()
        
    def generate_password(self):
        length = 16
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for i in range(length))
        self.password_input.setText(password)
        
    def add_service(self):
        service = self.service_input.text()
        username = self.username_input.text()
        password = self.password_input.text()
        
        if not service or not username or not password:
            QMessageBox.warning(self, "Ошибка", "Заполните все поля!")
            return
            
        # Шифрование пароля
        encrypted_password = self.cipher_suite.encrypt(password.encode()).decode()
            
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()
        c.execute("INSERT INTO passwords VALUES (?, ?, ?)", 
                 (service, username, encrypted_password))
        conn.commit()
        conn.close()
        
        self.service_input.clear()
        self.username_input.clear()
        self.password_input.clear()
        self.refresh_table()
        
    def refresh_table(self):
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()
        c.execute("SELECT * FROM passwords")
        data = c.fetchall()
        conn.close()
        
        self.table.setRowCount(len(data))
        for i, row in enumerate(data):
            for j, value in enumerate(row):
                if j == 2:  # Пароль
                    # Расшифровка пароля
                    decrypted_value = self.cipher_suite.decrypt(value.encode()).decode()
                    self.table.setItem(i, j, QTableWidgetItem(decrypted_value))
                else:
                    self.table.setItem(i, j, QTableWidgetItem(str(value)))

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PasswordManager()
    window.show()
    sys.exit(app.exec()) 