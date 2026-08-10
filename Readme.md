# 同花顺登录

# 代码
## 配置config.json中的user/password，然后运行 pure_login.py 即可，成功后返回登录cookie
## 注意如果登录多了会风控，会提示手机验证码，需要隔段时间再使用

## 文件说明
- pure_login.py：登录主流程（纯Python，无execjs/Node）
- pure_v.py：v cookie（hexin-v）纯Python生成，环境参数与浏览器Chrome/146一致
- v.js：原始v生成代码（Node补环境跑，getGS验证可用）
- config.json：本地账号配置（已gitignore，勿上传）

# 登录请求大致思路
>1、第一步
请求/pubkey/default.js接口，获取登录RSA公钥（当前default_5，可缓存），旧版硬编码default_4已失效。

>2、第二步
生成设备cookie：getFingerprintRsaInfo → hawkeye/generate（collections指纹加密上报）→ setDeviceCookie；同时生成v cookie放入请求头（hexin-v）。

>3、第三步
请求getGS接口，保存响应结果以及请求时携带的crnd参数。

>4、第四步
从getGS响应中提取dsk，携带crnd发送第一次dologinreturnjson2。此次必定失败（-11400），因为还没进行滑块验证。

>5、第五步
再次请求getGS（复用crnd），然后请求getPreHandle接口，获取滑块背景图和滑块图，保存响应中的signature和inity。

>6、第六步
下载两张图（getImg x2），用max-diff在背景图上定位缺口（y方向用inity约束），换算x_disp=x340*309/340；发送getTicket请求，phrase格式为x_disp;inity/195*177.22058823529412;309;177.22058823529412，验证成功返回ticket。

>7、第七步
携带captcha_phrase/captcha_ticket/captcha_signature发送第二次dologinreturnjson2，errorcode返回0即登录成功。



ps:[CSDN帖子](https://blog.csdn.net/wh00011/article/details/144443511)