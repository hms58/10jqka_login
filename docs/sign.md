# 同花顺登录（纯 Python 版）

账号密码登录同花顺（upass.10jqka.com.cn），**全部加密/签名均为纯 Python 算法实现**（无 execjs / jsdom / Node）。

## 使用

```bash
# 1. 准备本地配置（已 gitignore，勿上传）
# config.json
{
  "user": "你的用户名",
  "password": "你的密码"
}

# 2. 运行
python pure_login.py
```

成功后返回登录 cookies（已剔除 v 等内部字段）。

## 文件

| 文件 | 说明 |
| --- | --- |
| `pure_login.py` | 登录主流程（入口） |
| `pure_v.py` | chameleon v cookie 生成器（纯 Python） |
| `main.py` | 旧版（execjs 补环境），仅供对比，不再使用 |
| `config.json` | 本地账号配置，已加入 .gitignore |

## 加密实现（全部纯算法）

- **RSA**：pycryptodome PKCS#1 v1.5，pubkey 动态获取（当前 default_5）
- **passwdSalt**：auth-salt.min.js 翻译（XOR + base64 + HMAC-SHA256 + RSA）
- **upwd_score**：passwd_check.js 规则纯 Python 翻译
- **collections 指纹**：AES-ECB + RSA（hawkeye 指纹上报）
- **v cookie**：v.js chameleon 算法纯 Python 翻译（zn 编码 + 18 字段 qn 缓冲）

## 滑块验证（关键）

1. `getPreHandle` 返回 `inity`（缺口垂直位置）与两张图
2. 缺口定位：**max-diff**（把缺口块滑到背景图上，差异最大处 = 挖空位置），y 方向用 `inity±12` 约束
3. `x_disp = x340 * 309/340`（340 宽图 → 309 宽显示容器）
4. `phrase = f"{x_disp};{inity/195*177.22058823529412};309;177.22058823529412"`
   （height 必须是 177.22058823529412 = 309/340*195，旧代码用 177 会 Phrase Error）
5. `getTicket` 携带 v cookie，v 的行为字段需为滑块附近鼠标位置

## 注意事项

- 登录频繁会触发风控：`-10510 环境异常`（账号被要求短信验证码）或滑块验证码升级，需隔段时间再试
- `-11032` = 用户名或密码错误
- 网站当前拒绝手机号/邮箱+密码登录，测试账号请用非手机号格式用户名


## PS:[CSDN帖子](https://blog.csdn.net/wh00011/article/details/144443511)