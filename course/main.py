import os
import json
import time
import random
import hashlib
from datetime import datetime
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Конфігурація згідно завдання
N = 14  # Максимальна кількість користувачів
S = 2  # Кількість рівнів доступу
T = 8  # Періодичність перевірки (секунди)
R = 64  # Довжина ключа для RSA
a = 4  # Коефіцієнт для функції F


class UserManager:
    def __init__(self):
        self.users_file = "nameuser.txt"
        self.log_file = "us_book.txt"
        self.questions_file = "ask.txt"
        self.admin_password = "admin123"
        self.load_users()
        self.load_questions()

    def load_users(self):
        try:
            if os.path.exists(self.users_file):
                with open(self.users_file, 'r', encoding='utf-8') as f:
                    self.users = json.load(f)
            else:
                self.users = {}
        except Exception as e:
            print(f"Помилка завантаження користувачів: {e}")
            self.users = {}

    def load_questions(self):
        try:
            if os.path.exists(self.questions_file):
                with open(self.questions_file, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                    if content:
                        self.questions = json.loads(content)
                    else:
                        self.create_default_questions()
            else:
                self.create_default_questions()
        except Exception as e:
            print(f"Помилка завантаження питань: {e}")
            self.create_default_questions()

    def create_default_questions(self):
        # Створюємо 5 фіксованих математичних задач за формулою a * sin(x)
        self.questions = {
            "1": {"question": "4 * sin(0.52)", "answer": "1.99"},
            "2": {"question": "4 * sin(1.05)", "answer": "3.46"},
            "3": {"question": "4 * sin(1.57)", "answer": "4.00"},
            "4": {"question": "4 * sin(2.09)", "answer": "3.47"},
            "5": {"question": "4 * sin(2.62)", "answer": "1.99"}
        }
        self.save_questions()

    def save_users(self):
        try:
            with open(self.users_file, 'w', encoding='utf-8') as f:
                json.dump(self.users, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Помилка збереження користувачів: {e}")

    def save_questions(self):
        try:
            with open(self.questions_file, 'w', encoding='utf-8') as f:
                json.dump(self.questions, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Помилка збереження питань: {e}")

    def log_action(self, username, action):
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"{timestamp} - {username} - {action}\n"
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry)
        except Exception as e:
            print(f"Помилка запису в журнал: {e}")

    def register_user(self, admin_password, username, password, access_rights):
        if admin_password != self.admin_password:
            return False, "Невірний пароль адміністратора"

        if len(self.users) >= N:
            return False, "Досягнуто максимальну кількість користувачів"

        if username in self.users:
            return False, "Користувач вже існує"

        # Генерація RSA ключів для нового користувача
        key = RSA.generate(2048)
        public_key = key.publickey().export_key().decode('utf-8')
        private_key = key.export_key().decode('utf-8')

        self.users[username] = {
            'password': hashlib.md5(password.encode()).hexdigest(),
            'access_rights': access_rights,
            'registered_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'public_key': public_key,
            'private_key': private_key
        }

        self.save_users()
        self.log_action("ADMIN", f"Зареєстровано користувача: {username}")
        return True, f"Користувач {username} успішно зареєстрований"

    def delete_user(self, admin_password, username):
        if admin_password != self.admin_password:
            return False, "Невірний пароль адміністратора"

        if username not in self.users:
            return False, "Користувач не знайдений"

        del self.users[username]
        self.save_users()
        self.log_action("ADMIN", f"Видалено користувача: {username}")
        return True, f"Користувач {username} успішно видалений"

    def authenticate_user(self, username, password):
        if username not in self.users:
            return False, "Користувач не знайдений"

        hashed_password = hashlib.md5(password.encode()).hexdigest()
        if self.users[username]['password'] == hashed_password:
            self.log_action(username, "Успішна ідентифікація")
            return True, "Успішна ідентифікація"
        else:
            self.log_action(username, "Невірний пароль")
            return False, "Невірний пароль"

    def get_user_access(self, username):
        return self.users.get(username, {}).get('access_rights', {})

    def get_user_public_key(self, username):
        return self.users.get(username, {}).get('public_key')

    def get_user_private_key(self, username):
        return self.users.get(username, {}).get('private_key')

    def get_other_users(self, current_username):
        """Отримати список інших користувачів (для вибору отримувача)"""
        return [user for user in self.users.keys() if user != current_username]

    def get_random_question(self):
        """Отримати випадкове питання зі списку"""
        if not self.questions:
            self.create_default_questions()

        question_id = random.choice(list(self.questions.keys()))
        question_data = self.questions[question_id]
        return question_id, question_data["question"], question_data["answer"]

    def verify_question_answer(self, question_id, user_answer):
        """Перевірити відповідь на питання"""
        if question_id not in self.questions:
            return False

        correct_answer = self.questions[question_id]["answer"]
        try:
            # Порівнюємо числові значення з невеликою похибкою
            user_float = float(user_answer.strip())
            correct_float = float(correct_answer.strip())
            return abs(user_float - correct_float) < 0.1  # Похибка 0.1
        except ValueError:
            return False


class CryptoSystem:
    def __init__(self):
        self.input_file = "input.txt"
        self.encrypted_file = "close.json"
        self.decrypted_file = "out.txt"

    def rsa_encrypt(self, public_key, data):
        """Шифрування RSA публічним ключем отримувача"""
        key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(key)

        # Шифруємо по блоках
        encrypted_blocks = []
        block_size = 190  # Для RSA 2048
        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            encrypted_block = cipher.encrypt(block.encode('utf-8'))
            encrypted_blocks.append(base64.b64encode(encrypted_block).decode('utf-8'))

        return json.dumps(encrypted_blocks)

    def rsa_decrypt(self, private_key, encrypted_data):
        """Розшифрування RSA приватним ключем отримувача"""
        key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(key)

        encrypted_blocks = json.loads(encrypted_data)
        decrypted_blocks = []

        for block in encrypted_blocks:
            encrypted_block = base64.b64decode(block)
            decrypted_block = cipher.decrypt(encrypted_block)
            decrypted_blocks.append(decrypted_block.decode('utf-8'))

        return ''.join(decrypted_blocks)

    def generate_signature(self, private_key, data):
        """Генерація цифрового підпису приватним ключем"""
        try:
            key = RSA.import_key(private_key)

            # Хешуємо дані
            data_hash = SHA256.new(data.encode('utf-8'))

            # Створюємо підпис
            signature = pkcs1_15.new(key).sign(data_hash)

            return base64.b64encode(signature).decode('utf-8')
        except Exception as e:
            print(f"Помилка генерації підпису: {e}")
            return None

    def verify_signature(self, public_key, data, signature):
        """Перевірка цифрового підпису публічним ключем"""
        try:
            key = RSA.import_key(public_key)

            # Хешуємо оригінальні дані
            data_hash = SHA256.new(data.encode('utf-8'))

            # Перевіряємо підпис
            signature_bytes = base64.b64decode(signature)
            pkcs1_15.new(key).verify(data_hash, signature_bytes)

            return True  # Якщо verify не викинув виняток, підпис дійсний
        except Exception as e:
            print(f"Помилка перевірки підпису: {e}")
            return False

    def save_encrypted_message(self, sender, receiver, encrypted_data, signature=None):
        """Зберігаємо зашифровані дані у close.json разом з цифровим підписом"""
        messages = self.load_encrypted_messages()

        message_id = f"msg_{int(time.time())}_{random.randint(1000, 9999)}"

        messages[message_id] = {
            'sender': sender,
            'receiver': receiver,
            'encrypted_data': encrypted_data,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'decrypted': False,
            'signed': signature is not None,
            'signature': signature
        }

        with open(self.encrypted_file, 'w', encoding='utf-8') as f:
            json.dump(messages, f, indent=2, ensure_ascii=False)

        return message_id

    def load_encrypted_messages(self):
        """Завантажуємо всі зашифровані повідомлення з close.json"""
        try:
            if os.path.exists(self.encrypted_file):
                with open(self.encrypted_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except:
            pass
        return {}

    def get_user_encrypted_messages(self, username):
        """Отримуємо зашифровані повідомлення для користувача"""
        messages = self.load_encrypted_messages()
        user_messages = {}

        for msg_id, msg_data in messages.items():
            if msg_data['receiver'] == username and not msg_data.get('decrypted', False):
                user_messages[msg_id] = msg_data

        return user_messages

    def mark_message_as_decrypted(self, message_id):
        """Позначаємо повідомлення як розшифроване"""
        messages = self.load_encrypted_messages()
        if message_id in messages:
            messages[message_id]['decrypted'] = True
            messages[message_id]['decrypted_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            with open(self.encrypted_file, 'w', encoding='utf-8') as f:
                json.dump(messages, f, indent=2, ensure_ascii=False)
            return True
        return False

class AccessControl:
    def __init__(self, user_manager):
        self.user_manager = user_manager
        self.drives = ['A', 'B', 'C', 'D', 'E']

    def check_access(self, username, drive, action):
        user_access = self.user_manager.get_user_access(username)
        drive_access = user_access.get(drive, [])

        if action in drive_access:
            return True
        return False

    def hide_inaccessible_drives(self, username):
        accessible_drives = []
        for drive in self.drives:
            if self.check_access(username, drive, 'R'):
                accessible_drives.append(drive)
        return accessible_drives


class AuthenticationSystem:
    def __init__(self):
        self.user_manager = UserManager()
        self.crypto_system = CryptoSystem()
        self.access_control = AccessControl(self.user_manager)
        self.current_user = None
        self.last_auth_time = 0

    def display_access_rights_help(self):
        print("\n=== Довідка по правам доступу ===")
        print("R - Читання (Read)")
        print("W - Запис (Write)")
        print("E - Виконання (Execute)")
        print("A - Доповнення (Append)")
        print("\nПриклади формату:")
        print("A:RWE  - Диск A: читання, запис, виконання")
        print("B:RE   - Диск B: читання, виконання")
        print("C:R    - Диск C: тільки читання")
        print("D:RWA  - Диск D: читання, запис, доповнення")
        print("E:RWEA - Диск E: всі права")

    def get_access_rights_input(self):
        self.display_access_rights_help()
        print("\nВведіть права доступу:")
        access_input = input("Формат: A:RWE,B:RE,C:R,...: ")

        access_rights = {}
        for item in access_input.split(','):
            item = item.strip()
            if ':' in item:
                drive, rights = item.split(':', 1)
                drive = drive.strip().upper()
                rights = [r.upper() for r in rights.strip()]
                access_rights[drive] = rights
            else:
                print(f"Попередження: пропущено ':' в '{item}'")

        return access_rights

    def admin_menu(self):
        while True:
            print("\n=== Меню адміністратора ===")
            print("1. Зареєструвати користувача")
            print("2. Видалити користувача")
            print("3. Перегляд користувачів")
            print("4. Перегляд журналу")
            print("5. Довідка по правам доступу")
            print("6. Вихід")

            choice = input("Оберіть опцію: ")

            if choice == '1':
                username = input("Ім'я користувача: ")
                password = input("Пароль: ")

                access_rights = self.get_access_rights_input()

                if not access_rights:
                    print("Помилка: не вказано права доступу")
                    continue

                success, message = self.user_manager.register_user(
                    self.user_manager.admin_password, username, password, access_rights
                )
                print(message)

            elif choice == '2':
                if self.user_manager.users:
                    print("\nСписок користувачів:")
                    for user in self.user_manager.users:
                        print(f"- {user}")

                username = input("\nІм'я користувача для видалення: ")
                success, message = self.user_manager.delete_user(
                    self.user_manager.admin_password, username
                )
                print(message)

            elif choice == '3':
                if self.user_manager.users:
                    print("\n=== Зареєстровані користувачі ===")
                    for username, data in self.user_manager.users.items():
                        print(f"Користувач: {username}")
                        print(f"Дата реєстрації: {data['registered_date']}")
                        print(f"Права доступу: {data['access_rights']}")
                        print(f"Публічний ключ: {data['public_key'][:50]}...")
                        print("-" * 30)
                else:
                    print("Немає зареєстрованих користувачів")

            elif choice == '4':
                if os.path.exists(self.user_manager.log_file):
                    print("\n=== Журнал подій ===")
                    try:
                        with open(self.user_manager.log_file, 'r', encoding='utf-8') as f:
                            content = f.read()
                            if content:
                                print(content)
                            else:
                                print("Журнал порожній")
                    except Exception as e:
                        print(f"Помилка читання журналу: {e}")
                else:
                    print("Файл журналу не знайдено")

            elif choice == '5':
                self.display_access_rights_help()

            elif choice == '6':
                break
            else:
                print("Невірний вибір. Спробуйте ще раз.")

    def user_login(self):
        username = input("Ім'я користувача: ")
        password = input("Пароль: ")

        success, message = self.user_manager.authenticate_user(username, password)
        print(message)

        if success:
            self.current_user = username
            self.last_auth_time = time.time()
            self.user_session()

        return success

    def question_authentication(self):
        """Автентифікація за допомогою математичних задач з ask.txt"""
        question_id, question, correct_answer = self.user_manager.get_random_question()

        print(f"\n--- Математична автентифікація ---")
        print(f"Обчисліть: {question}")
        print(f"Формат відповіді: число з двома знаками після коми (наприклад: 1.99)")
        user_answer = input("Ваша відповідь: ")

        if self.user_manager.verify_question_answer(question_id, user_answer):
            print("✓ Автентифікація успішна")
            self.user_manager.log_action(self.current_user, "Успішна математична автентифікація")
            return True
        else:
            print("✗ Невірна відповідь")
            print(f"Правильна відповідь: {correct_answer}")
            self.user_manager.log_action(self.current_user, "Невірна математична автентифікація")
            return False

    def user_session(self):
        print(f"\nВітаємо, {self.current_user}!")

        # Показуємо доступні диски
        accessible_drives = self.access_control.hide_inaccessible_drives(self.current_user)
        print(f"Доступні диски: {', '.join(accessible_drives)}")

        session_start = time.time()

        while True:
            # Періодична автентифікація
            current_time = time.time()
            if current_time - self.last_auth_time > T:
                print(f"\n--- Періодична перевірка (кожні {T} сек) ---")
                if not self.question_authentication():
                    print("Доступ заборонено. Ви будете розлогінені.")
                    self.current_user = None
                    return
                self.last_auth_time = current_time

            print(f"\nЧас сесії: {int(current_time - session_start)} сек")
            print("=== Користувацьке меню ===")
            print("1. Шифрування з файлу input")
            print("2. Розшифрування повідомлення з close")
            print("3. Перегляд моїх зашифрованих повідомлень")
            print("4. Перегляд доступних дисків")
            print("5. Перегляд моїх прав")
            print("6. Вихід")

            choice = input("Оберіть опцію: ")

            if choice == '1':
                self.file_encryption_menu()
            elif choice == '2':
                self.file_decryption_menu()
            elif choice == '3':
                self.view_encrypted_messages_menu()
            elif choice == '4':
                accessible = self.access_control.hide_inaccessible_drives(self.current_user)
                print(f"Доступні диски: {', '.join(accessible)}")
            elif choice == '5':
                self.display_user_rights()
            elif choice == '6':
                self.user_manager.log_action(self.current_user, "Вихід з системи")
                self.current_user = None
                break
            else:
                print("Невірний вибір. Спробуйте ще раз.")

    def display_user_rights(self):
        access_rights = self.user_manager.get_user_access(self.current_user)
        print(f"\n=== Ваші права доступу ===")
        if access_rights:
            for drive, rights in access_rights.items():
                print(f"Диск {drive}: {', '.join(rights)}")
        else:
            print("Права доступу не надані")

    def check_c_drive_access(self):
        """Перевірка доступу до диска C"""
        has_access_to_c = any(
            self.access_control.check_access(self.current_user, 'C', right)
            for right in ['R', 'W', 'E', 'A']
        )

        if not has_access_to_c:
            print("✗ У вас немає прав доступу до диска C для операцій з файлами")
            print("Зверніться до адміністратора для надання прав (наприклад, C:RWEA)")
            return False
        return True

    def file_encryption_menu(self):
        """Шифрування з файлу input.txt в close.json з цифровим підписом"""
        print("\n--- Шифрування з файлу input.txt ---")

        if not self.check_c_drive_access():
            return

        # Отримуємо список інших користувачів
        other_users = self.user_manager.get_other_users(self.current_user)
        if not other_users:
            print("✗ В системі немає інших користувачів для відправки повідомлень")
            return

        print("\nДоступні отримувачі:")
        for i, user in enumerate(other_users, 1):
            print(f"{i}. {user}")

        try:
            choice = int(input("\nОберіть отримувача (номер): ")) - 1
            if choice < 0 or choice >= len(other_users):
                print("✗ Невірний вибір")
                return

            receiver = other_users[choice]
            print(f"Отримувач: {receiver}")
        except ValueError:
            print("✗ Введіть коректний номер")
            return

        # Запитуємо чи потрібен цифровий підпис
        use_signature = input("\nДодати цифровий підпис до повідомлення? (y/n): ").lower().strip() == 'y'

        # Отримуємо публічний ключ отримувача
        receiver_public_key = self.user_manager.get_user_public_key(receiver)
        if not receiver_public_key:
            print("✗ Не вдалося отримати публічний ключ отримувача")
            return

        # Читання вхідних даних з файлу input.txt
        try:
            if not os.path.exists(self.crypto_system.input_file):
                print(f"✗ Файл {self.crypto_system.input_file} не знайдено")
                print("Спочатку створіть файл input.txt з текстом для шифрування")
                return

            with open(self.crypto_system.input_file, 'r', encoding='utf-8') as f:
                data = f.read()

            if not data.strip():
                print("✗ Файл input.txt порожній")
                return

            print(f"✓ Прочитано з {self.crypto_system.input_file}: {len(data)} символів")

        except Exception as e:
            print(f"✗ Помилка читання файлу: {e}")
            return

        # Шифрування
        try:
            print("Шифрування даних...")
            encrypted = self.crypto_system.rsa_encrypt(receiver_public_key, data)

            # Генерація цифрового підпису (якщо потрібно)
            signature = None
            if use_signature:
                print("Створення цифрового підпису...")
                sender_private_key = self.user_manager.get_user_private_key(self.current_user)
                if sender_private_key:
                    signature = self.crypto_system.generate_signature(sender_private_key, data)
                    print("✓ Цифровий підпис створено")
                else:
                    print("✗ Не вдалося отримати приватний ключ для створення підпису")

            # Зберігаємо зашифровані дані у close.json
            message_id = self.crypto_system.save_encrypted_message(
                self.current_user, receiver, encrypted, signature
            )

            print("✓ Шифрування завершено успішно!")
            print(f"Вихідний файл: {self.crypto_system.input_file}")
            print(f"Зашифрований файл: {self.crypto_system.encrypted_file}")
            print(f"Отримувач: {receiver}")
            print(f"ID повідомлення: {message_id}")
            print(f"Цифровий підпис: {'Так' if signature else 'Ні'}")
            print(f"Розмір зашифрованих даних: {len(encrypted)} символів")

            action = f"Зашифровано файл для {receiver}"
            if signature:
                action += " з цифровим підписом"
            self.user_manager.log_action(self.current_user, action)

        except Exception as e:
            print(f"✗ Помилка шифрування: {e}")

    def file_decryption_menu(self):
        """Розшифрування конкретного повідомлення з close.json з перевіркою підпису"""
        print("\n--- Розшифрування повідомлення з close.json ---")

        if not self.check_c_drive_access():
            return

        messages = self.crypto_system.get_user_encrypted_messages(self.current_user)

        if not messages:
            print("У вас немає повідомлень для розшифрування")
            return

        print(f"\nДоступні повідомлення:")
        message_list = list(messages.items())
        for i, (msg_id, msg_data) in enumerate(message_list, 1):
            signed_status = "з підписом" if msg_data.get('signed') else "без підпису"
            print(f"{i}. Від: {msg_data['sender']} | Час: {msg_data['timestamp']} | {signed_status} | ID: {msg_id}")

        try:
            choice = int(input("\nОберіть повідомлення для розшифрування: ")) - 1
            if choice < 0 or choice >= len(message_list):
                print("✗ Невірний вибір")
                return

            msg_id, message_data = message_list[choice]
            self.decrypt_specific_message(msg_id, message_data)

        except ValueError:
            print("✗ Введіть коректний номер")

    def decrypt_specific_message(self, message_id, message_data):
        """Розшифрування конкретного повідомлення з перевіркою підпису"""
        print(f"\n--- Розшифрування повідомлення ---")
        print(f"Від: {message_data['sender']}")
        print(f"Час: {message_data['timestamp']}")
        print(f"ID: {message_id}")
        print(f"Цифровий підпис: {'Так' if message_data.get('signed') else 'Ні'}")

        try:
            # Отримуємо приватний ключ поточного користувача
            private_key = self.user_manager.get_user_private_key(self.current_user)
            if not private_key:
                print("✗ Не вдалося отримати ваш приватний ключ")
                return

            print("Розшифрування повідомлення...")
            decrypted = self.crypto_system.rsa_decrypt(private_key, message_data['encrypted_data'])

            # Перевірка цифрового підпису (якщо він є)
            if message_data.get('signed') and message_data.get('signature'):
                print("Перевірка цифрового підпису...")
                sender_public_key = self.user_manager.get_user_public_key(message_data['sender'])
                if sender_public_key:
                    is_signature_valid = self.crypto_system.verify_signature(
                        sender_public_key, decrypted, message_data['signature']
                    )
                    if is_signature_valid:
                        print("✓ Цифровий підпис дійсний")
                    else:
                        print("✗ Цифровий підпис недійсний! Повідомлення могло бути змінено.")
                else:
                    print("✗ Не вдалося отримати публічний ключ відправника для перевірки підпису")

            print("✓ Повідомлення успішно розшифровано!")
            print(f"Текст повідомлення: {decrypted}")

            # Позначаємо повідомлення як розшифроване
            self.crypto_system.mark_message_as_decrypted(message_id)

            # Зберігаємо розшифрований текст у out.txt
            with open(self.crypto_system.decrypted_file, 'w', encoding='utf-8') as f:
                f.write(decrypted)

            print(f"✓ Розшифрований текст збережено у {self.crypto_system.decrypted_file}")

            self.user_manager.log_action(self.current_user, f"Розшифровано повідомлення від {message_data['sender']}")

        except Exception as e:
            print(f"✗ Помилка розшифрування: {e}")

    def view_encrypted_messages_menu(self):
        """Перегляд зашифрованих повідомлень"""
        print("\n--- Мої зашифровані повідомлення ---")

        if not self.check_c_drive_access():
            return

        messages = self.crypto_system.get_user_encrypted_messages(self.current_user)

        if not messages:
            print("У вас немає зашифрованих повідомлень")
            return

        print(f"\nЗнайдено {len(messages)} зашифрованих повідомлень:")
        for i, (msg_id, msg_data) in enumerate(messages.items(), 1):
            status = "розшифровано" if msg_data.get('decrypted') else "не розшифровано"
            signed_status = "з підписом" if msg_data.get('signed') else "без підпису"
            print(f"{i}. Від: {msg_data['sender']} | Час: {msg_data['timestamp']} | Статус: {status} | {signed_status} | ID: {msg_id}")

    def main_menu(self):
        while True:
            print("\n" + "=" * 50)
            print("=== Система ідентифікації та аутентифікації ===")
            print("=" * 50)
            print("1. Вхід адміністратора")
            print("2. Вхід користувача")
            print("3. Вихід")

            choice = input("Оберіть опцію: ")

            if choice == '1':
                password = input("Пароль адміністратора: ")
                if password == self.user_manager.admin_password:
                    self.admin_menu()
                else:
                    print("✗ Невірний пароль адміністратора")

            elif choice == '2':
                self.user_login()

            elif choice == '3':
                print("До побачення!")
                break

            else:
                print("Невірний вибір. Спробуйте ще раз.")


def main():
    print("Ініціалізація системи...")

    # Створюємо тестові файли якщо не існують
    try:
        if not os.path.exists("input.txt"):
            with open("input.txt", "w", encoding='utf-8') as f:
                f.write("Тестовий текст для шифрування RSA")
            print("✓ Створено тестовий файл input.txt")

        # Видаляємо пошкоджений файл ask.txt якщо він існує
        if os.path.exists("ask.txt"):
            with open("ask.txt", "r", encoding='utf-8') as f:
                content = f.read().strip()
                if not content or 'Extra data' in content:
                    print("Видаляємо пошкоджений файл ask.txt...")
                    os.remove("ask.txt")
                    print("✓ Файл ask.txt видалено, буде створено новий з математичними задачами")

    except Exception as e:
        print(f"Попередження: {e}")

    system = AuthenticationSystem()
    system.main_menu()


if __name__ == "__main__":
    main()