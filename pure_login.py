# -*- coding: utf-8 -*-
"""
同花顺账号密码登录 —— 纯 Python 实现（无 execjs / jsdom / Node）
所有加密均为算法实现：
  - RSA（PKCS#1 v1.5，pubkey 动态获取 default_5）
  - MD5 / SHA256 / HMAC-SHA256
  - passwdSalt（XOR + base64 + RSA，来自 auth-salt.min.js）
  - upwd_score（passwd_check.js 规则纯 Python 翻译）
  - v cookie（v_new.js chameleon 算法纯 Python 翻译，环境参数与 Chrome/146 浏览器一致）
  - collections（get_collections：AES-ECB + RSA，指纹 JSON 为浏览器抓取硬编码）
滑块识别仍用 ddddocr（Python 库）。
"""
import base64
import hashlib
import hmac
import json
import random
import re
import time

import requests
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad

from pure_v import get_v as _gen_v, BROWSER_UA

# ================= 基础工具 =================
def str_md5(target: str) -> str:
    return hashlib.md5(target.encode('utf-8')).hexdigest()

def sha256_hex(target: str) -> str:
    return hashlib.sha256(target.encode('utf-8')).hexdigest()

def hmac_sha256_hex(key: str, msg: str) -> str:
    return hmac.new(key.encode('utf-8'), msg.encode('utf-8'), hashlib.sha256).hexdigest()

def get_crnd() -> str:
    return ''.join(random.choices('0123456789abcdefghijklmnopqrstuvwxyz', k=16))

def get_timestamp() -> int:
    return int(time.time())

def get_random() -> float:
    return random.random() * time.time() * 1000

# ================= RSA（登录公钥，网站 /pubkey/default.js） =================
PUBKEY_URL = 'https://upass.10jqka.com.cn/pubkey/default.js'

# default_5 公钥兜底（网站当前版本）
DEFAULT5_PUBKEY = {
    'v': 'default_5',
    'p': '10001',
    'm': 'D90F4DD5BF444916913F7B434F192587C354387FA531F2964725B5188FB9D5B40FDDD2B34F61B5560468D1F5C568796EB15F7799F03E4A3301EAF8B79B655F1B2B7DC6FFE1084E4C14A05DD9C6D0C72C5ED75890DC5D11AB5990A3C7DEBA0D68EFFD8C619B2A21AEFA3E7FF902CDAE0502025901EE2D42B76A0D7AD389F0BF69'
}

_pubkey_cache = None

def fetch_login_pubkey() -> dict:
    """获取登录 RSA 公钥（thspubkey），失败时用 default_5 兜底"""
    global _pubkey_cache
    if _pubkey_cache:
        return _pubkey_cache
    try:
        r = requests.get(PUBKEY_URL, timeout=15,
                         headers={'User-Agent': BROWSER_UA,
                                  'Referer': 'https://upass.10jqka.com.cn/'})
        m = re.search(r'thspubkey=(\{.*?\});', r.text)
        if m:
            _pubkey_cache = json.loads(m.group(1))
            return _pubkey_cache
    except Exception:
        pass
    return dict(DEFAULT5_PUBKEY)

def rsa_encrypt(data: str, pub: dict) -> str:
    """JSEncrypt 兼容：PKCS#1 v1.5，UTF-8"""
    n = int(pub['m'], 16)
    e = int(pub['p'], 16)
    key = RSA.construct((n, e))
    cipher = PKCS1_v1_5.new(key)
    return base64.b64encode(cipher.encrypt(data.encode('utf-8'))).decode()

# ================= passwdSalt（auth-salt.min.js 算法） =================
def _xor_bytes(e: bytes, t: bytes) -> bytes:
    """JS getStrXOR：e 长度为主，t 循环"""
    n = len(t)
    return bytes(b ^ t[i % n] for i, b in enumerate(e))

def get_passwd_salt(ssv: str, crnd_dsk_sha256: str) -> str:
    """get_passwdSalt：XOR(base64decode(ssv), sha256hex(crnd+dsk))，取第一个 '=' 之后"""
    ssv_decode = base64.b64decode(ssv)
    sb = _xor_bytes(ssv_decode, crnd_dsk_sha256.encode('latin-1')).decode('latin-1')
    return sb.split('=', 1)[1]

def get_passwd_salt2(hex_hmac_result: str, dsv_sha256: str) -> str:
    """get_passwdSalt2：XOR(hmac_sha256hex, sha256hex(dsv)) -> base64 -> RSA"""
    n = _xor_bytes(hex_hmac_result.encode('latin-1'), dsv_sha256.encode('latin-1'))
    n_b64 = base64.b64encode(n).decode()
    return rsa_encrypt(n_b64, fetch_login_pubkey())

# ================= upwd_score（passwd_check.js 翻译） =================
PWD_RULES = {
    'length': [
        {'id': 1, 'score': 25, 'regular': ['/^.{8,}$/']},
        {'id': 2, 'score': 10, 'regular': ['/^.{5,7}$/']},
        {'id': 3, 'score': 5, 'regular': ['/^.{1,4}$/']},
    ],
    'character': [
        {'id': 1, 'score': 20, 'associateFlag': '&&', 'regular': ['/[a-z]{1,}/', '/[A-Z]{1,}/']},
        {'id': 2, 'score': 10, 'associateFlag': '||', 'regular': ['/[a-z]{1,}/', '/[A-Z]{1,}/']},
        {'id': 3, 'score': 0, 'associateFlag': '', 'regular': ['/[^a-zA-Z]/']},
    ],
    'digit': [
        {'id': 1, 'score': 20, 'regular': ['/\\d{1}(.*?)\\d{1}(.*?)\\d{1}/']},
        {'id': 2, 'score': 15, 'regular': ['/\\d{1}(.*?)\\d{1}/']},
        {'id': 3, 'score': 10, 'regular': ['/[0-9]{1}/']},
        {'id': 4, 'score': 0, 'regular': ['/[^0-9]/']},
    ],
    'symbol': [
        {'id': 1, 'score': 25, 'regular': ['/[^a-zA-Z0-9]{1}(.*?)[^a-zA-Z0-9]{1}/']},
        {'id': 2, 'score': 10, 'regular': ['/[^a-zA-Z0-9]{1}/']},
        {'id': 3, 'score': 0, 'regular': ['/[^a-zA-Z0-9$]/']},
    ],
    'defaultReward': [
        {'id': 1, 'score': 5, 'associateFlag': '&&', 'regular': ['/[a-z]{1,}/', '/[A-Z]{1,}/', '/[0-9]{1,}/', '/[^a-zA-Z0-9]{1,}/']},
        {'id': 2, 'score': 3, 'associateFlag': '&&', 'regular': ['/[a-zA-Z]{1,}/', '/[0-9]{1,}/', '/[^a-zA-Z0-9]{1,}/']},
        {'id': 3, 'score': 2, 'associateFlag': '&&', 'regular': ['/[a-zA-Z]{1,}/', '/[0-9]{1,}/']},
    ],
}

def _strip_regex(s: str) -> str:
    return re.sub(r'^/|/$', '', s)

def calculate_password_score(password: str) -> int:
    rules = PWD_RULES
    total = 0
    # length
    for item in rules['length']:
        if re.search(_strip_regex(item['regular'][0]), password):
            total += item['score']
            break
    # character
    char_score = 0
    for item in rules['character']:
        r0 = _strip_regex(item['regular'][0])
        r1 = _strip_regex(item['regular'][1]) if len(item['regular']) > 1 else None
        m0 = re.search(r0, password)
        m1 = re.search(r1, password) if r1 else None
        if item.get('associateFlag') == '&&' and m0 and m1:
            char_score = item['score']
            break
        if item.get('associateFlag') == '||' and (m0 or m1):
            char_score = item['score']
            break
    total += char_score
    # digit
    for item in rules['digit']:
        if re.search(_strip_regex(item['regular'][0]), password):
            total += item['score']
            break
    # symbol
    for item in rules['symbol']:
        if re.search(_strip_regex(item['regular'][0]), password):
            total += item['score']
            break
    # defaultReward（JS 行为：缺失的正则相当于 password.match(undefined)，
    # 即搜索字符串 "undefined"，通常不命中；只有 4 个正则齐全的项才可能命中）
    reward = 0
    for item in rules['defaultReward']:
        ok = True
        for i in range(4):
            if i < len(item['regular']):
                if not re.search(_strip_regex(item['regular'][i]), password):
                    ok = False
                    break
            else:
                if 'undefined' not in password:
                    ok = False
                    break
        if ok:
            reward = item['score']
            break
    total += reward
    return total

# ================= collections（get_collections 翻译） =================
def _load_e_string() -> str:
    try:
        with open('artifacts/tmp/e_string_raw.txt', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        # 从 加密.js 现场提取
        js = open('加密.js', encoding='utf-8').read()
        m = re.search(r"e_string=\s*'(.*?)'", js, re.S)
        return m.group(1).encode('utf-8').decode('unicode_escape')

E_STRING = _load_e_string()

def generate_key() -> str:
    return ''.join(random.choice('0123456789abcdef') for _ in range(16))

def _normalize_pem(pem: str) -> str:
    """接口返回的 pubkey 是单行 PEM，转成标准多行格式"""
    if pem.startswith('-----BEGIN') and '\n' not in pem:
        body = pem.replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----', '').strip()
        body = body.replace('\\/', '/')
        lines = [body[i:i+64] for i in range(0, len(body), 64)]
        return '-----BEGIN PUBLIC KEY-----\n' + '\n'.join(lines) + '\n-----END PUBLIC KEY-----'
    return pem

def get_collections(pubkey_pem: str) -> str:
    """RSA(pubkey, aes_key) + '#' + AES-ECB-Pkcs7(e_string)"""
    pubkey_pem = _normalize_pem(pubkey_pem)
    key = generate_key()
    # AES-ECB-Pkcs7 加密指纹 JSON（key 为 16 字符 hex 串的 UTF-8 字节）
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    enc = base64.b64encode(cipher.encrypt(pad(E_STRING.encode('utf-8'), 16))).decode()
    # RSA 加密 AES key
    rsa_key = RSA.import_key(pubkey_pem)
    c = PKCS1_v1_5.new(rsa_key)
    enc_key = base64.b64encode(c.encrypt(key.encode('utf-8'))).decode()
    return enc_key + '#' + enc

# ================= 登录类 =================
HEADERS = {
    "Accept": "*/*",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "Pragma": "no-cache",
    "Referer": "https://upass.10jqka.com.cn/",
    "Sec-Fetch-Dest": "script",
    "Sec-Fetch-Mode": "no-cors",
    "Sec-Fetch-Site": "same-site",
    "User-Agent": BROWSER_UA,
    "sec-ch-ua": '"Google Chrome";v="146", "Chromium";v="146", "Not_A Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
}

class GGError(Exception):
    pass

class TongHuaShunLogin:
    def __init__(self, user, password):
        self.user = user
        self.password = password
        self.session = requests.Session()
        self._last_v = None

    # ---- v cookie（纯 Python chameleon 算法） ----
    def get_v(self, behavior=None):
        self._last_v = _gen_v(old_v=self._last_v, behavior=behavior)
        return {'v': self._last_v}

    def _set_v(self):
        v = self.get_v()
        self.session.cookies.set('v', v['v'])
        self.headers = dict(HEADERS)
        self.headers.update({'hexin-v': v['v']})
        return v

    # ---- 指纹 pubkey（hawkeye） ----
    def get_fingerprint_pubkey(self):
        url = 'https://upass.10jqka.com.cn/common/getFingerprintRsaInfo?'
        r = self.session.get(url, headers=HEADERS, timeout=15)
        return r.json()['pubkey']

    # ---- hawkeye generate（设备指纹） ----
    def generate(self):
        collections = get_collections(self.get_fingerprint_pubkey())
        url = 'https://hawkeye.10jqka.com.cn/v1/hawkeye/generate'
        v = self.get_v()
        self.session.cookies.set('v', v['v'])
        data = {
            'pass_code': '',
            'user_id': 'null',
            'source_type': 'web',
            'collections': collections,
            'protocol': 'fingerprint_1',
        }
        r = self.session.post(url, headers=HEADERS, cookies=v, data=data, timeout=20)
        return r.json()

    def set_device_cookie(self):
        msg = self.generate()
        pass_code = msg['data']['pass_code']
        expires_time = msg['data']['expires_time']
        device_code = msg['data']['device_code']
        url = 'https://upass.10jqka.com.cn/common/setDeviceCookie'
        data = {
            'u_dpass': pass_code,
            'u_did': device_code,
            'u_uver': '1.0.0',
            'expires_time': expires_time,
        }
        v = self.get_v()
        self.session.cookies.set('v', v['v'])
        self.headers = dict(HEADERS)
        self.headers.update({'hexin-v': v['v']})
        r = self.session.post(url, headers=self.headers, data=data, timeout=20)
        return r.cookies

    # ---- getGS ----
    def get_gs(self, crnd=None):
        url = 'https://upass.10jqka.com.cn/user/getGS'
        pub = fetch_login_pubkey()
        uname = rsa_encrypt(self.user, pub)
        crnd = crnd or get_crnd()
        data = {
            'uname': uname,
            'rsa_version': pub['v'],
            'crnd': crnd,
        }
        v = self.get_v()
        self.session.cookies.set('v', v['v'])
        self.headers = dict(HEADERS)
        self.headers.update({'hexin-v': v['v']})
        r = self.session.post(url, headers=self.headers, data=data, timeout=20)
        return r.json(), crnd

    # ---- 滑块 ----
    def get_pre_handle(self):
        url = 'https://captcha.10jqka.com.cn/getPreHandle'
        params = {
            'captcha_type': '4',
            'appid': 'registernew',
            'random': get_random(),
            'callback': 'PreHandle',
        }
        v = self.get_v()
        self.session.cookies.set('v', v['v'])
        self.headers = dict(HEADERS)
        self.headers.update({'hexin-v': v['v']})
        r = self.session.get(url, headers=self.headers, cookies=v, params=params, timeout=20)
        text = r.text
        url_params = ''.join(re.findall(r'urlParams":"(.*?)"', text))
        imgs = eval(''.join(re.findall(r'"imgs":(\[.*?\]),', text)))
        m_inity = re.search(r'inity":(\d+)', text)
        inity = int(m_inity.group(1)) if m_inity else 0
        from urllib.parse import parse_qs
        p = parse_qs(url_params)
        return p, imgs, inity

    def locate_gap(self, params, imgs, inity):
        """locate gap via max-diff with inity y-window, return 309px x_disp"""
        import cv2
        import numpy as np
        headers = {
            'Accept': 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Pragma': 'no-cache',
            'Referer': 'https://upass.10jqka.com.cn/',
            'Sec-Fetch-Dest': 'image',
            'Sec-Fetch-Mode': 'no-cors',
            'Sec-Fetch-Site': 'same-site',
            'User-Agent': BROWSER_UA,
            'sec-ch-ua': '"Google Chrome";v="146", "Chromium";v="146", "Not_A Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }
        for index, img in enumerate(imgs):
            url = 'https://captcha.10jqka.com.cn/getImg'
            p = {
                'rand': params['rand'][0],
                'time': params['time'][0],
                'appid': 'registernew',
                'captcha_type': '4',
                'signature': params['signature'][0],
                'iuk': img,
            }
            r = self.session.get(url, headers=headers, params=p, timeout=20)
            imgs[index] = r.content
        bg = cv2.imdecode(np.frombuffer(imgs[0], np.uint8), cv2.IMREAD_COLOR)
        bl = cv2.imdecode(np.frombuffer(imgs[1], np.uint8), cv2.IMREAD_UNCHANGED)
        alpha = bl[:, :, 3]
        mask = alpha > 40
        bl_gray = cv2.cvtColor(bl[:, :, :3], cv2.COLOR_BGR2GRAY).astype(np.int16)
        bg_gray = cv2.cvtColor(bg, cv2.COLOR_BGR2GRAY).astype(np.int16)
        bh, bw = bl.shape[:2]
        best = (0.0, 0, 0)
        y0 = max(0, inity - 12)
        y1 = min(bg.shape[0] - bh + 1, inity + 12)
        for y in range(y0, y1):
            for x in range(0, bg.shape[1] - bw + 1):
                roi = bg_gray[y:y + bh, x:x + bw]
                score = float(np.abs(roi - bl_gray)[mask].mean())
                if score > best[0]:
                    best = (score, x, y)
        x340 = best[1]
        return x340 * 309 / 340

    def get_ticket(self, p, x_disp, inity):
        """getTicket: phrase = x_disp;inity/195*height;309;height
        v behavior fields use browser-measured values (mm=55/click=5/pos 583,524)"""
        url = 'https://captcha.10jqka.com.cn/getTicket'
        height = 177.22058823529412
        y_disp = inity / 195 * height
        phrase = f"{x_disp};{y_disp};309;{height}"
        params = {
            'rand': p['rand'][0],
            'time': p['time'][0],
            'appid': 'registernew',
            'captcha_type': '4',
            'signature': p['signature'][0],
            'phrase': phrase,
            'callback': 'verify',
        }
        v = self.get_v(behavior={'mm': 55, 'click': 5, 'x': 583, 'y': 524})
        self.session.cookies.set('v', v['v'])
        self.headers = dict(HEADERS)
        self.headers.update({'hexin-v': v['v']})
        r = self.session.get(url, headers=self.headers, cookies=v, params=params, timeout=20)
        ticket = ''.join(re.findall(r'"ticket":"(.*?)"', r.text))
        return (ticket, phrase) if ticket else (None, None)

    def _login_payload(self, gs, crnd, upwd_score, pub, extra=None):
        data = {
            'uname': rsa_encrypt(self.user, pub),
            'passwd': rsa_encrypt(str_md5(self.password), pub),
            'saltLoginTimes': '1',
            'longLogin': 'on',
            'rsa_version': pub['v'],
            'source': 'pc_web',
            'request_type': 'login',
            'captcha_type': '4',
            'upwd_score': upwd_score,
            'ignore_upwd_score': '',
            'passwdSalt': self.get_passwd_salt(gs, crnd),
            'dsk': gs['dsk'],
            'crnd': crnd,
            'ttype': 'WEB',
            'sdtis': 'C22',
            'timestamp': get_timestamp(),
        }
        if extra:
            data.update(extra)
        return data

    def get_passwd_salt(self, gs, crnd):
        crnd_dsk_sha256 = sha256_hex(crnd + gs['dsk'])
        sb = get_passwd_salt(gs['ssv'], crnd_dsk_sha256)
        hamc_result = hmac_sha256_hex(sb, str_md5(self.password))
        dsv_sha256 = sha256_hex(gs['dsv'])
        return get_passwd_salt2(hamc_result, dsv_sha256)

    def start(self, max_slider_tries=5):
        self.session.cookies.clear()
        self.headers = dict(HEADERS)
        self.set_device_cookie()

        pub = fetch_login_pubkey()
        upwd_score = calculate_password_score(self.password)
        gs, crnd = self.get_gs()
        self._set_v()
        data = self._login_payload(gs, crnd, upwd_score, pub)
        r = self.session.post('https://upass.10jqka.com.cn/login/dologinreturnjson2',
                              headers=self.headers, data=data, timeout=20)
        resp = r.json()
        if resp.get('errorcode') != -11400:
            raise GGError(f'第一次未带验证码出现未知情况>>{resp}')

        gs, crnd = self.get_gs(crnd=crnd)
        ticket = phrase = None
        params = None
        for _ in range(max_slider_tries):
            params, imgs, inity = self.get_pre_handle()
            x_disp = self.locate_gap(params, imgs, inity)
            time.sleep(2)
            ticket, phrase = self.get_ticket(params, x_disp, inity)
            if ticket:
                break
        if not ticket:
            raise GGError('滑块验证多次失败')

        v2 = self.get_v()
        self.session.cookies.set('v', v2['v'])
        self.headers = dict(HEADERS)
        self.headers.update({
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Origin': 'https://upass.10jqka.com.cn',
            'Referer': 'https://upass.10jqka.com.cn/login?redir=HTTP_REFERER',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'X-Requested-With': 'XMLHttpRequest',
            'hexin-v': v2['v'],
        })
        extra = {
            'captcha_phrase': phrase,
            'captcha_ticket': ticket,
            'captcha_signature': params['signature'][0],
        }
        data = self._login_payload(gs, crnd, upwd_score, pub, extra)
        r = self.session.post('https://upass.10jqka.com.cn/login/dologinreturnjson2',
                              headers=self.headers, data=data, timeout=20)
        resp = r.json()
        print('second dologin:', resp.get('errorcode'), resp.get('errormsg'))
        if resp.get('errorcode') == -10510:
            raise GGError(f"环境异常，账号被要求短信验证码登录: {resp.get('errormsg')}")
        if resp.get('errorcode') == -11032:
            raise GGError(f"用户名或密码错误: {resp.get('errormsg')}")
        if resp.get('errorcode') == 0 and resp.get('errormsg') == '成功':
            cookies = self.session.cookies
            if cookies.get('v'):
                del cookies['v']
            return dict_from_cookiejar(cookies)
        raise GGError(f'未知情况>>{resp}')

    # getGS 后二次盐（saltLoginTimes=2）逻辑保留备用
    def start_with_dsk_resend(self, resp):
        """若 dologin 返回 dsk 且 saltLoginTimes==1，需按网站逻辑二次重发（暂未在主流程启用）"""
        raise NotImplementedError


def dict_from_cookiejar(cj):
    from requests.utils import dict_from_cookiejar as _d
    return _d(cj)


if __name__ == '__main__':
    import sys
    cfg = json.load(open('config.json', encoding='utf-8'))
    cookies = TongHuaShunLogin(user=cfg['user'], password=cfg['password']).start()
    print('登录成功，cookies:', cookies)
