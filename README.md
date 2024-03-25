# genomefi
genomefi链游自动化，自动化完成任务已更新

使用方法：

替换代码里的ez-captcha（https://dashboard.ez-captcha.com/#/register?inviteCode=RkmFYdpUiag）的api key与代理url

genomefi-account.txt的格式为：
钱包地址----私钥----tw_token----dc_token。若不需要绑定社交账号则只用填前两个字段，需要将代码中的这一行为False：isSocial = False  # 是否绑定社交账号

python3 genomefi.py
