import flet as ft
import sqlite3
import base64
import secrets
import string
from collections import Counter
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_key(master_password: str):
    password = master_password.encode()
    salt = b'static_salt_123' 
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def encrypt_data(data: str, key: bytes):
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str, key: bytes):
    try:
        f = Fernet(key)
        return f.decrypt(encrypted_data.encode()).decode()
    except: return None

def init_db():
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            service TEXT, 
            login TEXT, 
            password TEXT,
            notes TEXT
        )
    """)
    try:
        cursor.execute("ALTER TABLE accounts ADD COLUMN notes TEXT")
    except:
        pass
    
    cursor.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT, value TEXT)")
    conn.commit()
    conn.close()

def main(page: ft.Page):
    page.title = "Менеджер Паролей"
    page.window_width = 450
    page.window_height = 800
    page.bgcolor = "#0E111B"
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 20
    
    init_db()
    master_key = None 

    PRIMARY_COLOR = "#005F8B"
    ACCENT_COLOR = "#51FF00"
    CARD_BG = "#1A1C26"

    def copy_to_clipboard(text):
        page.set_clipboard(text)
        page.open(ft.SnackBar(ft.Text("СКОПИРОВАНО! 🚀"), bgcolor="#02DA02"))

    def delete_account(account_id):
        conn = sqlite3.connect("passwords.db")
        cursor = conn.cursor()
        cursor.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
        conn.commit()
        conn.close()
        load_passwords(search_field.value)
        page.open(ft.SnackBar(ft.Text("Удалено успешно"), bgcolor=ft.Colors.RED_700))

    def run_security_analysis(e):
        conn = sqlite3.connect("passwords.db")
        cursor = conn.cursor()
        cursor.execute("SELECT service, password FROM accounts")
        data = cursor.fetchall()
        conn.close()

        all_passwords = []
        weak_list = []
        
        for service, enc_p in data:
            dec_p = decrypt_data(enc_p, master_key)
            all_passwords.append(dec_p)
            
            is_weak = False
            if len(dec_p) < 8: is_weak = True
            if dec_p.isdigit() or dec_p.isalpha(): is_weak = True
            
            if is_weak:
                weak_list.append(ft.Text(f"⚠️ {service}: Слишком простой пароль", color="orange"))

        counts = Counter(all_passwords)
        dup_list = []
        for service, enc_p in data:
            dec_p = decrypt_data(enc_p, master_key)
            if counts[dec_p] > 1:
                dup_list.append(ft.Text(f"❌ {service}: Пароль повторяется!", color="red"))

        analysis_dialog.content.controls = [
            ft.Text("Результаты сканирования:", weight="bold", size=18),
            ft.Divider(),
            *(dup_list if dup_list else [ft.Text("✅ Повторяющихся паролей нет", color="green")]),
            ft.Divider(),
            *(weak_list if weak_list else [ft.Text("✅ Слабых паролей нет", color="green")]),
        ]
        page.open(analysis_dialog)
        page.update()

    analysis_dialog = ft.AlertDialog(
        title=ft.Text("Анализ безопасности"),
        content=ft.Column(scroll=ft.ScrollMode.AUTO, tight=True, height=300),
        actions=[ft.TextButton("Закрыть", on_click=lambda _: page.close(analysis_dialog))]
    )

    def create_password_card(row_id, service, login, enc_pass, notes):
        dec_pass = decrypt_data(enc_pass, master_key)
        return ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Icon(ft.Icons.LANGUAGE, color=ACCENT_COLOR, size=20),
                    ft.Text(service, size=18, weight="bold", color="white", expand=True),
                    ft.IconButton(ft.Icons.DELETE_OUTLINE, icon_color="red400", icon_size=18, on_click=lambda _: delete_account(row_id)),
                ]),
                ft.Text(f"👤 {login}", color="white70", size=14),
                ft.Text(f"📝 {notes}" if notes else "Нет заметок", color="white38", size=12, italic=True),
                ft.Divider(color="white10", height=10),
                ft.Row([
                    ft.Text("••••••••", color=PRIMARY_COLOR, weight="bold", size=16),
                    ft.IconButton(ft.Icons.COPY_ROUNDED, icon_color=PRIMARY_COLOR, on_click=lambda _: copy_to_clipboard(dec_pass)),
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN)
            ]),
            padding=15, bgcolor=CARD_BG, border_radius=15, border=ft.border.all(1, "white10")
        )

    def login_click(e):
        nonlocal master_key
        if not master_pass_input.value:
            master_pass_input.error_text = "Нужен пароль!"
            page.update()
            return
        temp_key = generate_key(master_pass_input.value)
        conn = sqlite3.connect("passwords.db")
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM meta WHERE key='verify_token'")
        row = cursor.fetchone()
        if row is None:
            token = encrypt_data("SECRET", temp_key)
            cursor.execute("INSERT INTO meta (key, value) VALUES ('verify_token', ?)", (token,))
            conn.commit()
            master_key = temp_key
            show_main_screen()
        else:
            if decrypt_data(row[0], temp_key) == "SECRET":
                master_key = temp_key
                show_main_screen()
            else:
                master_pass_input.error_text = "Неверный Пароль!"
                page.update()
        conn.close()

    master_pass_input = ft.TextField(label="Введите пароль для входа", password=True, can_reveal_password=True, border_radius=12)

    login_screen = ft.Container(
        content=ft.Column([
            ft.Icon(ft.Icons.SHIELD_ROUNDED, size=80, color=PRIMARY_COLOR),
            ft.Text("Вход в систему", size=35, weight="bold"),
            ft.Container(height=20),
            master_pass_input,
            ft.ElevatedButton("Войти", on_click=login_click, bgcolor=PRIMARY_COLOR, color="white", width=250, height=50),
        ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
        alignment=ft.alignment.center, expand=True
    )

    pass_grid = ft.Column(scroll=ft.ScrollMode.AUTO, expand=True, spacing=15)
    search_field = ft.TextField(hint_text="Поиск...", prefix_icon=ft.Icons.SEARCH, border_radius=15, bgcolor=CARD_BG, on_change=lambda e: load_passwords(e.control.value))

    def load_passwords(search=""):
        pass_grid.controls.clear()
        conn = sqlite3.connect("passwords.db")
        cursor = conn.cursor()
        if search:
            cursor.execute("SELECT * FROM accounts WHERE service LIKE ?", (f'%{search}%',))
        else:
            cursor.execute("SELECT * FROM accounts")
        for row in cursor.fetchall():
            pass_grid.controls.append(create_password_card(row[0], row[1], row[2], row[3], row[4]))
        conn.close()
        page.update()

    service_in = ft.TextField(label="Сервис", border_radius=12)
    login_in = ft.TextField(label="Логин", border_radius=12)
    pass_in = ft.TextField(label="Пароль", expand=True, border_radius=10, on_change=lambda _: update_strength())
    notes_in = ft.TextField(label="Заметки (необязательно)", border_radius=12, multiline=True, max_lines=3)
    strength_bar = ft.ProgressBar(value=0, color=PRIMARY_COLOR, bgcolor="white10", width=400)

    def update_strength():
        pw = pass_in.value
        score = 0
        if len(pw) >= 8: score += 0.3
        if any(c.isdigit() for c in pw): score += 0.3
        if any(c in "!@#$%^&*" for c in pw): score += 0.4
        strength_bar.value = score
        strength_bar.color = ft.Colors.RED if score < 0.4 else ft.Colors.ORANGE if score < 0.7 else ft.Colors.GREEN
        page.update()

    def generate_safe_password(e):
        safe_chars = string.ascii_letters + string.digits + "!@#$%^&*"
        new_pw = "".join(secrets.choice(safe_chars) for _ in range(16))
        pass_in.value = new_pw
        update_strength()

    def save_new(e):
        if not service_in.value or not pass_in.value: return
        enc = encrypt_data(pass_in.value, master_key)
        conn = sqlite3.connect("passwords.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO accounts (service, login, password, notes) VALUES (?, ?, ?, ?)", 
                       (service_in.value, login_in.value, enc, notes_in.value))
        conn.commit()
        conn.close()
        service_in.value = login_in.value = pass_in.value = notes_in.value = ""
        strength_bar.value = 0
        page.close(add_dialog)
        load_passwords()

    add_dialog = ft.AlertDialog(
        title=ft.Text("Новый аккаунт"),
        content=ft.Column([
            service_in, login_in,
            ft.Row([pass_in, ft.IconButton(ft.Icons.AUTO_FIX_HIGH, on_click=generate_safe_password)]),
            notes_in,
            ft.Text("Сложность:", size=12),
            strength_bar
        ], height=400, tight=True, scroll=ft.ScrollMode.AUTO),
        actions=[ft.ElevatedButton("СОХРАНИТЬ", on_click=save_new, bgcolor=PRIMARY_COLOR, color="white")]
    )

    def show_main_screen():
        page.clean()
        page.floating_action_button = ft.FloatingActionButton(icon=ft.Icons.ADD, bgcolor=PRIMARY_COLOR, on_click=lambda _: page.open(add_dialog))
        page.add(
            ft.Row([
                ft.Text("Passwords", size=30, weight="bold"),
                ft.IconButton(ft.Icons.SHIELD_OUTLINED, tooltip="Анализ безопасности", on_click=run_security_analysis)
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            ft.Container(height=10),
            search_field,
            ft.Container(height=10),
            pass_grid
        )
        load_passwords()

    page.add(login_screen)

ft.app(target=main)
