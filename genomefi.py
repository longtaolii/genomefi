import asyncio
import sys
import time
import schedule
import requests
import re
from datetime import datetime, timedelta
import httpx
from eth_account.messages import encode_defunct
from loguru import logger
from eth_account import Account
from faker import Faker
import random
import string
import secrets
import uuid
from base64 import b64encode
import json
import tls_client

requests.packages.urllib3.disable_warnings()

fake = Faker(locale='en-US')

g_success, g_fail = 0, 0

logger.remove()
logger.add(sys.stdout, colorize=True,
           format="<w>{time:HH:mm:ss:SSS}</w> | <r>{extra[fail]}</r>-<g>{extra[success]}</g> | <level>{message}</level>")
logger = logger.patch(lambda record: record["extra"].update(fail=g_fail, success=g_success))

proxy_ip = '127.0.0.1:7890'

ezcaptcha_client_key = ''


def reCaptchaV2():
    while True:
        json_data = {
            "clientKey": ezcaptcha_client_key,
            "task":
                {
                    "type": "ReCaptchaV2TaskProxyless",
                    "websiteURL": "https://event.genomefi.io/",
                    "websiteKey": "6LcK_aApAAAAAPAUR8Zo96ZMXGQF12jeUKR2KeGr",
                    "isInvisible": False,
                }
        }
        response = requests.post(url='https://api.ez-captcha.com/createTask', json=json_data).json()
        if response['errorId'] != 0:
            raise ValueError(response)
        task_id = response['taskId']
        time.sleep(5)
        for _ in range(30):
            data = {"clientKey": ezcaptcha_client_key, "taskId": task_id}
            response = requests.post(url='https://api.ez-captcha.com/getTaskResult', json=data).json()
            if response['status'] == 'ready':
                return response['solution']['gRecaptchaResponse']
            else:
                time.sleep(2)


async def auth_twitter(tw_token):
    proxies = {
        'http://': f'http://{proxy_ip}',
        'https://': f'http://{proxy_ip}',
    }
    try:
        http = httpx.AsyncClient(proxies=proxies, verify=False, timeout=10)
        response = await http.get(url='https://twitter.com/home', cookies={
            'auth_token': tw_token,
            'ct0': '960eb16898ea5b715b54e54a8f58c172'
        })
        ct0 = re.findall('ct0=(.*?);', dict(response.headers)['set-cookie'])[0]
        cookies = {'ct0': ct0, 'auth_token': tw_token}
        http.headers = {'authority': 'twitter.com', 'accept': '*/*', 'accept-language': 'zh-CN,zh;q=0.9',
                        'authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA',
                        'cache-control': 'no-cache', 'content-type': 'application/json',
                        'origin': 'https://twitter.com',
                        'pragma': 'no-cache',
                        'referer': 'https://twitter.com/puffer_finance/status/1751954283052810298',
                        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
                        'x-csrf-token': ct0}
        api_url = 'https://twitter.com/i/api/2/oauth2/authorize?code_challenge=challenge&code_challenge_method=plain&client_id=OHdOUXJvREY1R2oyUlE3akI4Vng6MTpjaQ&redirect_uri=https%3A%2F%2Fevent.genomefi.io%2Fevent%3Fsocial%3Dtwitter&response_type=code&scope=follows.read%20follows.write%20offline.access%20users.read%20tweet.read%20tweet.write%20like.read%20like.write&state=state'
        response = await http.get(url=api_url, cookies=cookies)
        auth_code = response.json()['auth_code']
        data = {'approval': True, 'code': auth_code}
        response = await http.post(url=api_url, cookies=cookies, json=data)
        redirect_uri = response.json()['redirect_uri']
        return auth_code
    except Exception as e:
        logger.error(e)


def build_trackers(user_agent) -> str:
    return b64encode(json.dumps({"os": "Mac OS X", "browser": "Safari", "device": "", "system_locale": "zh-CN",
                                 "browser_user_agent": user_agent,
                                 "browser_version": "13.1.twitter_account", "os_version": "10.13.6", "referrer": "",
                                 "referring_domain": "", "referrer_current": "", "referring_domain_current": "",
                                 "release_channel": "stable", "client_build_number": 177662,
                                 "client_event_source": None}, separators=(',', ':')).encode()).decode()


# 授权discord
def auth_discord(dc_token):
    tls_proxies = {
        'http': f'http://{proxy_ip}',
        'https': f'http://{proxy_ip}',
    }
    try:
        session = tls_client.Session(
            random_tls_extension_order=True,
        )
        user_agent = fake.safari()
        headers = {
            'Host': 'discord.com',
            'Connection': 'keep-alive',
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'zh-CN,zh;q=0.9',
        }
        _uuid = uuid.uuid4()
        response = session.get(
            url=f'https://discord.com/api/oauth2/authorize?client_id=1217013639458848778&response_type=code&redirect_uri=https%3A%2F%2Fevent.genomefi.io%2Fevent%3Fsocial%3Ddiscord&scope=identify&state=discord-{_uuid}',
            headers=headers, proxy=tls_proxies, allow_redirects=False)
        # logger.debug(response)
        x_super_properties = build_trackers(user_agent)
        headers.update({"Authorization": dc_token})
        headers.update({"X-Super-Properties": x_super_properties})
        headers.update({"X-Debug-Options": 'bugReporterEnabled'})
        response = session.get(
            url=f'https://discord.com/oauth2/authorize?client_id=1217013639458848778&response_type=code&redirect_uri=https%3A%2F%2Fevent.genomefi.io%2Fevent%3Fsocial%3Ddiscord&scope=identify&state=discord-{_uuid}',
            headers=headers, proxy=tls_proxies, allow_redirects=False)
        # logger.debug(response.status_code)
        data = {"permissions": "0", "authorize": True, "integration_type": 0}
        response = session.post(
            url=f'https://discord.com/api/v9/oauth2/authorize?client_id=1217013639458848778&response_type=code&redirect_uri=https%3A%2F%2Fevent.genomefi.io%2Fevent%3Fsocial%3Ddiscord&scope=identify&state=discord-{_uuid}',
            headers=headers, proxy=tls_proxies, allow_redirects=False, json=data).json()
        # logger.debug(response)
        location = response['location']
        code = re.findall('code=(.*?)&state=', location)[0]
        return code
    except Exception as e:
        logger.error(e)


class GenomeFi:
    def __init__(self, pri_key, referral):
        proxies = {
            'http://': f'http://{proxy_ip}',
            'https://': f'http://{proxy_ip}',
        }
        self.address = Account.from_key(pri_key).address
        self.pri_key = pri_key
        self.referral = referral
        self.http = httpx.AsyncClient(proxies=proxies, verify=False, timeout=30)
        self.http.headers = {
            'Accept-Language': 'en-US,en;q=0.8',
            'Origin': 'https://event.genomefi.io',
            'Referer': 'https://event.genomefi.io/',
            'Sec-Ch-Ua': '"Google Chrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': "Windows",
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Gpc': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/'
        }
        self.token = None

    async def login(self):
        try:
            nonce = secrets.token_hex(16)
            issued_at = datetime.now().isoformat(timespec='milliseconds') + 'Z'
            expiration_time = (datetime.now() + timedelta(minutes=10)).isoformat(timespec='milliseconds') + 'Z'
            reCode = reCaptchaV2()
            message = f"event.genomefi.io wants you to sign in with your Ethereum account:\n{self.address}\n\nSign in GenomeFi.\n\nURI: https://event.genomefi.io\nVersion: 1\nChain ID: 137\nNonce: {nonce}\nIssued At: {issued_at}\nExpiration Time: {expiration_time}"
            signature = Account.from_key(self.pri_key).sign_message(encode_defunct(text=message))
            data = {
                "address": self.address,
                "message": message,
                "signed": signature.signature.hex(),
                "reCode": reCode,
            }

            response = await self.http.post(
                'https://sazn9rq17l.execute-api.ap-northeast-2.amazonaws.com/staging/user/auth/login/wallet', json=data)
            if response.json()['success']:
                self.token = response.json()['accessToken']
                self.http.headers['Authorization'] = 'Bearer ' + self.token
                logger.info(f'{self.address} 登录成功')
                return True
            logger.error(f'{self.address} 登录失败')
            return False
        except Exception as e:
            logger.error(e)
            return False

    async def register(self):
        try:
            nonce = secrets.token_hex(16)
            issued_at = datetime.now().isoformat(timespec='milliseconds') + 'Z'
            expiration_time = (datetime.now() + timedelta(minutes=10)).isoformat(timespec='milliseconds') + 'Z'
            message = f"event.genomefi.io wants you to sign in with your Ethereum account:\n{self.address}\n\nSign in GenomeFi.\n\nURI: https://event.genomefi.io\nVersion: 1\nChain ID: 137\nNonce: {nonce}\nIssued At: {issued_at}\nExpiration Time: {expiration_time}"
            signature = Account.from_key(self.pri_key).sign_message(encode_defunct(text=message))
            rand_str = generate_random_string()
            reCode = reCaptchaV2()
            data = {
                "address": self.address,
                "message": message,
                "nickname": rand_str,
                "reCode": reCode,
                "signed": signature.signature.hex(),
                "walletType": "MetaMask",
            }

            response = await self.http.post(
                'https://sazn9rq17l.execute-api.ap-northeast-2.amazonaws.com/staging/user/auth/join/wallet?referral=' + self.referral,
                json=data)
            if response.json()['success']:
                self.token = response.json()['accessToken']
                self.http.headers['Authorization'] = 'Bearer ' + self.token
                return True
            logger.error(f'{self.address} 注册失败')
            return False
        except Exception as e:
            logger.error(e)
            return False

    async def get_point(self):
        try:
            response = await self.http.get(
                'https://sazn9rq17l.execute-api.ap-northeast-2.amazonaws.com/staging/user/event/point?page=1&item=4')
            if response.json()['success']:
                logger.info(f'{self.address} 当前积分：{str(response.json()["pointTotal"])}')
                return response.json()["pointTotal"]
            logger.error(f'{self.address} 获取用户信息失败')
            return False
        except Exception as e:
            logger.error(e)
            return False

    async def get_nft(self):
        try:
            response = await self.http.get(
                'https://sazn9rq17l.execute-api.ap-northeast-2.amazonaws.com/staging/user/event/dashboard/nft/mygallery?page=1')
            if response.json()['success']:
                return response.json()["data"]['data'][0]['fileKey']
            return False
        except Exception as e:
            logger.error(e)
            return False

    async def get_status(self):
        try:
            response = await self.http.get(
                'https://sazn9rq17l.execute-api.ap-northeast-2.amazonaws.com/staging/user/event/dashboard/status')
            if response.json()['success']:
                return response.json()['data']
            logger.error(f'{self.address} 获取状态失败')
            return False
        except Exception as e:
            logger.error(e)
            return False

    # onece task
    async def bind_twitter(self, tw_token):
        try:
            auth_token = await auth_twitter(tw_token)
            params = {
                'code': auth_token,
                'redirect': 'https://event.genomefi.io/event?social=twitter'
            }
            response = await self.http.post(
                'https://sazn9rq17l.execute-api.ap-northeast-2.amazonaws.com/staging/user/event/task/social/twitter',
                params=params)
            if response.json()['success']:
                logger.info(f'{self.address} 绑定推特成功')
                return True
            logger.error(f'{self.address} 绑定推特失败')
            return False
        except Exception as e:
            logger.error(e)
            return False

    async def bind_discord(self, dc_token):
        try:
            auth_code = auth_discord(dc_token)
            params = {
                'code': auth_code,
                'redirect': 'https://event.genomefi.io/event?social=discord'
            }
            response = await self.http.post(
                'https://sazn9rq17l.execute-api.ap-northeast-2.amazonaws.com/staging/user/event/task/social/discord',
                params=params)
            if response.json()['success']:
                logger.info(f'{self.address} 绑定DC成功')
                return True
            logger.error(f'{self.address} 绑定DC失败')
            return False
        except Exception as e:
            logger.error(e)
            return False

    async def submit_Mbti(self):
        try:
            mbtis = ['INTJ', 'INTP', 'ENTJ', 'ENTP', 'INFJ', 'INFP', 'ENFJ', 'ENFP', 'ISTJ', 'ISFJ', 'ESTJ', 'ESFJ',
                     'ISTP', 'ISFP', 'ESTP', 'ESFP']
            bloods = ['A', 'B', 'O', 'AB']
            data = {
                "mbti": random.choice(mbtis),
                "blood": random.choice(bloods),
            }
            response = await self.http.post(
                'https://sazn9rq17l.execute-api.ap-northeast-2.amazonaws.com/staging/user/event/task/mbti', json=data)
            if response.json()['success']:
                logger.info(f'{self.address} 提交MBTI成功')
                return True
            logger.error(f'{self.address} 提交MBTI失败')
            return False
        except Exception as e:
            logger.error(e)
            return False

    async def submit_profile(self, profile):
        try:
            data = {
                "profile": profile
            }
            response = await self.http.post(
                'https://sazn9rq17l.execute-api.ap-northeast-2.amazonaws.com/staging/user/event/task/profile',
                json=data)
            if response.json()['success']:
                logger.info(f'{self.address} 设置头像成功')
                return True
            logger.error(f'{self.address} 设置头像失败')
            return False
        except Exception as e:
            logger.error(e)
            return False

    # daily task
    async def check_in(self):
        try:
            response = await self.http.post(
                'https://sazn9rq17l.execute-api.ap-northeast-2.amazonaws.com/staging/user/event/task/attendance')
            if response.json()['success'] or response.json()['error']['msg'] == 'Already attended':
                logger.info(f'{self.address} 签到成功')
                return True
            logger.error(f'{self.address} 签到失败')
            return False
        except Exception as e:
            logger.error(e)
            return False

    async def ai_chat(self):
        for i in range(5):
            try:
                data = {
                    'question': 'Please help me generate a paragraph that must contain the word "genome-related"'
                }
                response = await self.http.post(
                    'https://sazn9rq17l.execute-api.ap-northeast-2.amazonaws.com/staging/user/event/task/quiz/quest',
                    json=data)
                if response.json()['success']:
                    logger.info(f'{self.address} AI聊天成功')
                elif response.json()['error']['msg'] == 'Already Max chat today':
                    logger.info(f'{self.address} 今日AI聊天次数已用完')
                    return True
                else:
                    logger.error(f'{self.address} AI聊天失败')
                    continue
            except Exception as e:
                logger.error(e)
                continue
            time.sleep(1)

    async def ai_nft(self):
        try:
            data = {
                'prompt': 'photorealistic， long_hair， realistic， solo， long_hair， （photorealistic:1.4）， best quality， ultra high res， teeth， Long sleeve，Blue dress， Big mouth，full body，3girls， Grin， graffiti (medium)， ok sign，'
            }
            response = await self.http.post(
                'https://sazn9rq17l.execute-api.ap-northeast-2.amazonaws.com/staging/user/event/task/quiz/nft',
                json=data)
            if response.json()['success']:
                logger.info(f'{self.address} AI生图成功')
                return True
            if response.json()['error']['msg'] == 'Already Max nft today':
                logger.info(f'{self.address} 今日AI生图次数已用完')
                return False
            logger.error(f'{self.address} AI生图失败')
            return False
        except Exception as e:
            logger.error(e)
            return False

    async def raffle(self, vgeno):
        num = int(vgeno) // 10
        for i in range(num):
            try:
                response = await self.http.post(
                    'https://sazn9rq17l.execute-api.ap-northeast-2.amazonaws.com/staging/user/event/task/raffle')
                if response.json()['success']:
                    logger.info(f'{self.address} 抽奖成功，获得{response.json()["point"]}积分')
                elif response.json()['error']['msg'] == 'Already Max raffle today':
                    logger.info(f'{self.address} 今日抽奖次数已用完')
                    return True
                else:
                    logger.error(f'{self.address} 抽奖失败')
                    continue
            except Exception as e:
                logger.error(e)
                continue
            time.sleep(1)


def generate_random_string(length=8):
    letters = string.ascii_letters
    result_str = ''.join(random.choice(letters) for _ in range(length))
    return result_str


async def go(filename, isSocial):
    global g_fail, g_success
    with open(filename, 'r') as f, open('genomefi-success.txt', 'a') as s, open('genomefi-error.txt', 'a') as e:
        lines = f.readlines()
        for line in lines:
            if isSocial:
                address = line.strip().split('----')[0]
                private = line.strip().split('----')[1]
                tw_token = line.strip().split('----')[2]
                dc_token = line.strip().split('----')[3]
            else:
                address = line.strip().split('----')[0]
                private = line.strip().split('----')[1]
                tw_token = 'null'
                dc_token = 'null'
            try:
                gf = GenomeFi(private, '')
                if await gf.login():
                    # 补充信息
                    status = await gf.get_status()
                    if status['snsTwitter'] is None and tw_token != 'null':
                        await gf.bind_twitter(tw_token)
                    if status['snsDiscord'] is None and dc_token != 'null':
                        await gf.bind_discord(dc_token)
                    if status['mbti'] is None:
                        await gf.submit_Mbti()
                    if status['profileImg'] is None:
                        profile = await gf.get_nft()
                        if profile is not False and profile is not None:
                            await gf.submit_profile(profile)
                    # 签到
                    await gf.check_in(), await gf.ai_chat(), await gf.ai_nft()
                    point = await gf.get_point()
                    if point is not False:
                        await gf.raffle(point)
                    g_success += 1
                    logger.success(f'{address} 成功')
                    s.write(f'{address}----{private}\n')
                else:
                    g_fail += 1
                    logger.error(f'{address} 失败')
                    e.write(f'{address}----{private}\n')
            except Exception as ex:
                g_fail += 1
                logger.error(f'{address} 失败')
                e.write(f'{address}----{private}\n')
                continue


def main():
    # rel_code = 'USqIXtBAfz' # 替换为你的邀请码
    # count = 500  # 注册账号数量
    filename = 'genomefi-account.txt'
    isSocial = True  # 是否绑定社交账号
    asyncio.run(go(filename, isSocial))


main()
'''
schedule.every().day.at("15:05").do(main)

while True:
    schedule.run_pending()
    time.sleep(1)
'''
