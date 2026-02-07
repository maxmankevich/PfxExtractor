import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509
import sys


class PFXExtractorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PFX Extractor")
        self.root.geometry("900x700")

        # Переменные
        self.pfx_data = None
        self.password = None

        # Создаем интерфейс
        self.create_widgets()

    def create_widgets(self):
        # Основной контейнер
        main_frame = tk.Frame(self.root, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Заголовок
        title_label = tk.Label(
            main_frame,
            text="PFX to CRT/KEY Extractor",
            font=("Arial", 16, "bold")
        )
        title_label.pack(pady=(0, 20))

        # Кнопка загрузки PFX
        btn_frame = tk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=(0, 20))

        self.load_btn = tk.Button(
            btn_frame,
            text="📁 Загрузить PFX файл",
            command=self.load_pfx,
            font=("Arial", 12),
            bg="#4CAF50",
            fg="white",
            padx=20,
            pady=10
        )
        self.load_btn.pack()

        # Пароль (необязательно)
        pass_frame = tk.Frame(main_frame)
        pass_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Label(pass_frame, text="Пароль (если есть):", font=("Arial", 10)).pack(side=tk.LEFT)
        self.pass_entry = tk.Entry(pass_frame, width=30, show="*", font=("Arial", 10))
        self.pass_entry.pack(side=tk.LEFT, padx=(10, 0))

        # Фреймы для текстовых полей
        self.create_text_frame(main_frame, "Закрытый ключ (*.key)", 0)
        self.create_text_frame(main_frame, "Сертификат (*.crt)", 1)
        self.create_text_frame(main_frame, "Корневой сертификат (*-ca.crt)", 2)

        # Кнопки копирования
        copy_frame = tk.Frame(main_frame)
        copy_frame.pack(fill=tk.X, pady=(10, 0))

        tk.Button(
            copy_frame,
            text="📋 Копировать все",
            command=self.copy_all,
            bg="#2196F3",
            fg="white",
            padx=15,
            pady=8
        ).pack(side=tk.LEFT, padx=(0, 10))

        tk.Button(
            copy_frame,
            text="❌ Очистить все",
            command=self.clear_all,
            bg="#f44336",
            fg="white",
            padx=15,
            pady=8
        ).pack(side=tk.LEFT)

        # Информация внизу
        info_text = """
Инструкция:
1. Нажмите "Загрузить PFX файл" и выберите ваш .pfx файл
2. Если PFX защищен паролем, введите его в поле выше
3. Скопируйте содержимое из нужных полей в панель хостинга
4. Для каждого поля: выделите текст и Ctrl+C или используйте кнопку "Копировать все"
        """
        info_label = tk.Label(main_frame, text=info_text, justify=tk.LEFT, font=("Arial", 9))
        info_label.pack(pady=(20, 0))

    def create_text_frame(self, parent, title, index):
        frame = tk.LabelFrame(parent, text=title, font=("Arial", 11, "bold"), padx=10, pady=10)
        frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Текстовое поле с прокруткой
        text_widget = scrolledtext.ScrolledText(
            frame,
            wrap=tk.WORD,
            width=80,
            height=8,
            font=("Consolas", 9)
        )
        text_widget.pack(fill=tk.BOTH, expand=True)

        # Привязываем контекстное меню
        text_widget.bind("<Button-3>", lambda e: self.show_context_menu(e, text_widget))

        # Сохраняем ссылку на виджет
        if not hasattr(self, 'text_widgets'):
            self.text_widgets = []
        self.text_widgets.append(text_widget)

        # Кнопка копирования для этого поля
        btn_frame = tk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=(5, 0))

        tk.Button(
            btn_frame,
            text="📋 Копировать",
            command=lambda idx=index: self.copy_to_clipboard(idx),
            font=("Arial", 9),
            padx=10
        ).pack(side=tk.RIGHT)

    def load_pfx(self):
        file_path = filedialog.askopenfilename(
            title="Выберите PFX файл",
            filetypes=[("PFX files", "*.pfx *.p12"), ("All files", "*.*")]
        )

        if not file_path:
            return

        try:
            # Читаем файл
            with open(file_path, 'rb') as f:
                pfx_bytes = f.read()

            # Получаем пароль
            password = self.pass_entry.get().encode('utf-8') if self.pass_entry.get() else None

            # Загружаем PKCS12
            private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
                pfx_bytes,
                password
            )

            if not private_key or not cert:
                messagebox.showerror("Ошибка", "Не удалось загрузить PFX файл. Проверьте пароль.")
                return

            # Очищаем предыдущие данные
            self.clear_all()

            # 1. Извлекаем приватный ключ
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')

            self.text_widgets[0].insert(tk.END, private_key_pem)

            # 2. Извлекаем основной сертификат
            cert_pem = cert.public_bytes(
                encoding=serialization.Encoding.PEM
            ).decode('utf-8')

            self.text_widgets[1].insert(tk.END, cert_pem)

            # 3. Извлекаем цепочку сертификатов
            ca_certs_pem = ""
            if additional_certs:
                for ca_cert in additional_certs:
                    ca_cert_pem = ca_cert.public_bytes(
                        encoding=serialization.Encoding.PEM
                    ).decode('utf-8')
                    ca_certs_pem += ca_cert_pem

            if ca_certs_pem:
                self.text_widgets[2].insert(tk.END, ca_certs_pem)
            else:
                self.text_widgets[2].insert(tk.END, "# Цепочка сертификатов не найдена в PFX файле\n")

            messagebox.showinfo("Успех", f"PFX файл успешно загружен!\n\n"
                                         f"• Приватный ключ: {private_key.key_size} бит\n"
                                         f"• Сертификат: {cert.subject.rfc4514_string()}\n"
                                         f"• Доп. сертификатов: {len(additional_certs) if additional_certs else 0}")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось обработать PFX файл:\n\n{str(e)}")

    def copy_to_clipboard(self, index):
        text = self.text_widgets[index].get("1.0", tk.END).strip()
        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            messagebox.showinfo("Скопировано", "Текст скопирован в буфер обмена!")

    def copy_all(self):
        all_text = ""
        titles = ["=== PRIVATE KEY ===\n", "=== CERTIFICATE ===\n", "=== CA CERTIFICATES ===\n"]

        for i, widget in enumerate(self.text_widgets):
            text = widget.get("1.0", tk.END).strip()
            if text and not text.startswith("#"):
                all_text += titles[i] + text + "\n\n"

        if all_text:
            self.root.clipboard_clear()
            self.root.clipboard_append(all_text)
            messagebox.showinfo("Скопировано", "Все данные скопированы в буфер обмена!")

    def clear_all(self):
        for widget in self.text_widgets:
            widget.delete("1.0", tk.END)

    def show_context_menu(self, event, text_widget):
        """Показываем контекстное меню для текстового поля"""
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Копировать", command=lambda: self.copy_text(text_widget))
        menu.add_command(label="Выделить все", command=lambda: text_widget.tag_add(tk.SEL, "1.0", tk.END))
        menu.add_separator()
        menu.add_command(label="Очистить", command=lambda: text_widget.delete("1.0", tk.END))

        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def copy_text(self, text_widget):
        try:
            selected_text = text_widget.get(tk.SEL_FIRST, tk.SEL_LAST)
            self.root.clipboard_clear()
            self.root.clipboard_append(selected_text)
        except:
            # Если ничего не выделено, копируем все
            text_widget.tag_add(tk.SEL, "1.0", tk.END)
            text_widget.update()
            try:
                selected_text = text_widget.get(tk.SEL_FIRST, tk.SEL_LAST)
                self.root.clipboard_clear()
                self.root.clipboard_append(selected_text)
            except:
                pass


def main():
    # Проверяем наличие библиотеки cryptography
    try:
        import cryptography
    except ImportError:
        print("Библиотека cryptography не установлена!")
        print("Установите её командой: pip install cryptography")
        input("Нажмите Enter для выхода...")
        sys.exit(1)

    root = tk.Tk()
    app = PFXExtractorGUI(root)

    # Центрируем окно
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')

    root.mainloop()


if __name__ == "__main__":
    main()