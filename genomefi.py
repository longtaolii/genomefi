import asyncio
import sys
import time
from datetime import datetime, timedelta
import httpx
from eth_account.messages import encode_defunct
from loguru import logger
from urllib.parse import urlparse, parse_qs
from eth_account import Account
import random
import string
import secrets

g_success, g_fail = 0, 0

logger.remove()
logger.add(sys.stdout, colorize=True,
           format="<w>{time:HH:mm:ss:SSS}</w> | <r>{extra[fail]}</r>-<g>{extra[success]}</g> | <level>{message}</level>")
logger = logger.patch(lambda record: record["extra"].update(fail=g_fail, success=g_success))


proxies = {
    'http://': 'http://127.0.0.1:7890',
    'https://': 'http://127.0.0.1:7890',
}


class GenomeFi:
    def __init__(self, pri_key, referral):
        self.address = Account.from_key(pri_key).address
        self.pri_key = pri_key
        self.referral = referral
        self.http = httpx.AsyncClient(proxies=proxies, verify=False)
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

    async def register(self):
        try:
            nonce =secrets.token_hex(16)
            issued_at = datetime.now().isoformat(timespec='milliseconds') + 'Z'
            expiration_time = (datetime.now() + timedelta(minutes=10)).isoformat(timespec='milliseconds') + 'Z'
            message = f"event.genomefi.io wants you to sign in with your Ethereum account:\n{self.address}\n\nSign in GenomeFi.\n\nURI: https://event.genomefi.io\nVersion: 1\nChain ID: 137\nNonce: {nonce}\nIssued At: {issued_at}\nExpiration Time: {expiration_time}"
            signature = Account.from_key(self.pri_key).sign_message(encode_defunct(text=message))
            rand_str = generate_random_string()
            data = {
                "nickname": rand_str,
                "address": self.address,
                "message": message,
                "signed": signature.signature.hex(),
                "walletType": "MetaMask",
            }

            response = await self.http.post('https://sazn9rq17l.execute-api.ap-northeast-2.amazonaws.com/staging/user/auth/join/wallet?referral=' + self.referral, json=data)
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
            response = await self.http.get('https://sazn9rq17l.execute-api.ap-northeast-2.amazonaws.com/staging/user/event/point?page=1&item=4')
            if response.json()['success']:
                logger.info(f'{self.address} 当前积分：{str(response.json()["pointTotal"])}')
                return True
            logger.error(f'{self.address} 获取用户信息失败')
            return False
        except Exception as e:
            logger.error(e)
            return False


def generate_random_string(length=8):
    letters = string.ascii_letters
    result_str = ''.join(random.choice(letters) for _ in range(length))
    return result_str


async def main(referral_code, count=10):
    global g_fail, g_success
    with open('genomefi-success.txt', 'a') as s, open('genomefi-error.txt', 'a') as e:
        for i in range(count):
            try:
                account = Account.create()
                private = account.key.hex()
                address = account.address
                gf = GenomeFi(private, referral_code)
                if await gf.register() and await gf.get_point():
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


if __name__ == '__main__':
    rel_code = '' # 替换为你的邀请码
    count = 50  # 注册账号数量
    asyncio.run(main(rel_code, count))
