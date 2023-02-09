# Flask JWT Token(JWT Token认证插件)

<p align="center">
<a href="#"><img src="https://img.shields.io/badge/Module-flask--jwt--token-critical.svg"/></a>
<a href="#"><img src="https://img.shields.io/badge/Language-Python-blue"/></a>
    <a href="#"><img src="https://img.shields.io/badge/Version-0.1.0-f1c232"/></a>
<img src="https://img.shields.io/badge/Author-guapit-ff69b4"/>
<a href="https://www.github.com/guapit"><img src="https://img.shields.io/badge/Github-guapit-success"/></a>
<a href="https://www.gitee.com/guapit"><img src="https://img.shields.io/badge/Gitee-guapit-yellowgreen"/></a>
<a href="#"><img src="https://img.shields.io/badge/E--mail-guapit%40qq.com-yellowgreen"/></a>
</p><br>



   This is a highly scalable `token` authentication system developed based on the `PyJWT` plug-in. It can be used simply,  and the encryption method can be customized arbitrarily. It supports password encryption,  private key public key encryption, private key public key file encryption
Whether you are django, Flask, Fastapi or software application authorization,  you can use it to achieve application layer decoupling

这是一个基于 `PyJWT`插件开发的高可扩展的`token`认证系统,可以简单的使用,也可以任意定制加密方式,支持 密码加密, 私钥公钥加密,私钥公钥文件加密
无论你是 django, Flask, Fastapi还是软件应用授权都可以使用,实现应用层解耦

Required plugins 必要的插件

```pthon
pip install -U pyjwt
pip install -U pydantic
pip install -U pytz
```

## pip安装

```bash
pip install flask-jwt-token
```



## settings(配置)

It's easy to use, or you can customize any authorization management you want

可以简单使用,也可以任意定制授权管理,非常好用

`key`:str = "guapi" # 公共加密秘钥

`crypto`: str = 'HS256' # 加密算法

`private_key`: str = None # 这是私钥,如果使用openssl加密

`public_key`: str = None # 这是公钥,如果使用openssl加密

`private_file`: str = None # 这是私钥文件路径,如果使用openssl加密

`public_file`: str = None # 这是公钥文件路径,如果使用openssl加密

`issuer`:str = None # 签发者(可选),如果不填默认 any

`type`: str = 'JWT' # 签发类型(可选),有些环境需要选择签发类型时再设置

`address`: List[str]|str = None # 收件人(可选),如果有指定的签名范围可以

`verify_exp`:Optional[bool] = True # 是否关闭过期验证

`verify_signatrue`:Optional[bool] = True # 验证签名,如果关闭只加密信息,不进行key秘钥加密

`expiration`:Optional[int] = 5 # Token临时到期时间

`expiration_max`:Optional[int] = 7 # Token最大有效期

`is_uuid`:Optional[bool] = False # 是否需要加盐

`utc`:Optional[timezone] = None # 设置时区

`kid`: str = None # 前后端共享公钥

`require`: List[str] = None # 解密后过滤器,可以选择返回指定字段信息

`active_expiration`:Optional[datetime] = None # 设置Token什么时间内无法使用

## Function函数

### create_playload(self, data:dict = {})

测试创建数据和配置是否合法

:param data: 需要加密的信息数据

:return: 验证数据合法后返回 playload 对象

```python
jwt.create_playload({'id':1,'username':'guapit'})
```

### def get_playload(self,palyload:tuple[bool, dict, str],require:List[str]=None,language:str="en")

**English Fields**:

crypto,type,address,create_time,expiration,expiration_max,issuer,issuer,uuid,active_exp,pal

**中文字段**:

加密算法,加盐类型,可访问者,创建时间,到期时间,到期上限,发布者,唯一识别码,主动过期,解密数据

:param palyload: 荷载对象

:param require: 过滤掉不需要返回的字段,参考上面的字段名称

:param language: 设置语言版本 en | cn

:return: 验证数据合法后返回过滤后的 playload 对象

### def get_headers(self,encode_key:str)

得到解密后的明文headers头信息

### def set_headers(self,headers: dict = None)

设置加密荷载的头部信息(内置函数,无需设置)

如果设置了 self.kid 会优先使用属性上的值

:param headers: 需要加密的信息数据

:return: 返回更新后的headers信息

### def get_playload(self,palyload:tuple[bool, dict, str],require:List[str]=None,language:str="en") ->tuple[bool, dict, str]

格式化解密后的结果

English Fields:
    crypto,type,address,create_time,expiration,expiration_max,issuer,issuer,uuid,active_exp,pal
中文字段:
    加密算法,加盐类型,可访问者,创建时间,到期时间,到期上限,发布者,唯一识别码,主动过期,解密数据
:param palyload: 荷载对象
:param require: 过滤掉不需要返回的字段,参考上面的字段名称
:param language: 设置语言版本 en | cn
:return: 验证数据合法后返回过滤后的 playload 对象 

使用方法:

```python
decode = jt.get_playload(decode,language="cn",require=["address",'type','crypto','issuer'])
```

 English:

```json
(True,
 {'create_time': 1675960891,
  'data': {'id': 1, 'username': 'guapit'},
  'expiration': 1675961391,
  'expiration_max': 1676565691,
  'expiration_stop': 1675960891,
  'uuid': None},
 'Token令牌获取成功')
```

中文:

```json
(True,
 {'主动过期': 1675961064,
  '创建时间': 1675961064,
  '到期上限': 1676565864,
  '到期时间': 1675961564,
  '唯一识别码': None,
  '解密数据': {'id': 1, 'username': 'guapit'}},
 'Token令牌获取成功')
```



### def encode(self,data:dict = {},headers:dict = None,json_encoder: Type[JSONEncoder] | None = None)

根据 self.key 的属性进行加密
:param data: 需要加密的信息数据
:param headers: 如果需要在荷载信息头部加入定制信息可以传入字典
:param json_encoder: 自定义json解析接口(一般无需设置)
:return: 验证数据合法后返回 playload 对象

### def decode(self,encode_key:str,address:List[str]|str=None,issue:str = None,leeway:Union[int, float, timedelta] = 0)

根据 self.key 的属性进行解密
:param encode_key: 加密文
:param address: 允许解密的用户范围
:param issue: 发布者中是否包含指定发布者
:param leeway: 过期后允许多久宽容期,一般无需设置,默认设置为: 秒
:return: 验证数据合法后返回 `状态`,`数据`,`状态注解` 

### def encode_ssl(self,data:dict = {},headers:dict = None, json_encoder: Type[JSONEncoder] | None = None)

根据 self.private_key 的属性进行加密
生成私钥，指定私钥的长度为2048bit   1024基本安全, 2048非常安全
linux: openssl genrsa -out rsa_private_key.pem 2048
以上生成的是 RS256 加密密文
:param data: 需要加密的信息数据
:param headers: 如果需要在荷载信息头部加入定制信息可以传入字典
:param json_encoder: 自定义json解析接口(一般无需设置)
:return: 验证数据合法后返回Token密文

### def decode_ssl(self,encode_key:str,address:List[str]|str=None,issue:str = None,leeway:Union[int, float, timedelta] = 0)

根据 self.public_key 的属性进行解密
根据私钥生成对应的公钥参考
linux: openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key_2048.pub    
以上生成的是 RS256 公钥
:param encode_key: 加密文
:param address: 允许解密的用户范围
:param issue: 发布者中是否包含指定发布者
:param leeway: 过期后允许多久宽容期,一般无需设置,默认设置为: 秒

:return: 验证数据合法后返回 `状态`,`数据`,`状态注解`       

### def encode_ssl_file(self,data:dict = {},headers:dict = None, json_encoder: Type[JSONEncoder] | None = None)

根据 self.private_file 的属性的文件里面的私钥进行加密

生成私钥，指定私钥的长度为2048bit  1024基本安全, 2048非常安全

linux: openssl genrsa -out rsa_private_key.pem 2048

以上生成的是 RS256 加密密文

:param data: 需要加密的信息数据

:param headers: 如果需要在荷载信息头部加入定制信息可以传入字典

:param json_encoder: 自定义json解析接口(一般无需设置)

:return: 验证数据合法后返回Token密文

### def decode_ssl_file(self,encode_key:str,address:List[str]|str=None,issue:str = None,leeway:Union[int, float, timedelta] = 0)

根据 self.public_file 的属性的文件里面的公钥进行解密
根据私钥生成对应的公钥参考
linux: openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key_2048.pub    
以上生成的是 RS256 公钥
:param data: 需要加密的信息数据
:param headers: 如果需要在荷载信息头部加入定制信息可以传入字典
:param leeway: 过期后允许多久宽容期,一般无需设置,默认设置为: 秒
:return: 验证数据合法后返回 `状态`,`数据`,`状态注解`

## 使用方法

### 简单的加密

key

```python
from flask_jwt_token import JwtToken

jwt = JwtToken()
jwt.crypto = 'HS256' # 选择加密算法
jwt.key = "iJIUzUxMiIsInR5cC" # 秘钥

user = {'id':1,'username':'guapit'}

# 进行加密
encode_key = jwt.encode(user)

# 进行解密
decode = jwt.decode(encode)
```

### 私钥公钥加密 

private_key and public_key

```python
from flask_jwt_token import JwtToken

jwt = JwtToken()
jwt.crypto = 'HS256' # 选择加密算法
jwt.private_key  = "-----BEGIN PRIVATE KEY-----..." # 秘钥
jwt.public_key  = "-----BEGIN PUBLIC KEY-----..." # 公钥
user = {'id':1,'username':'guapit'}

# 进行加密
encode_key = jt.encode_ssl(user)

# 进行解密
decode = jt.decode_ssl(encode)
```

### 私钥公钥文件加密解密

private_key and public_key

```python
from flask_jwt_token import JwtToken

jwt = JwtToken()
jwt.crypto = 'RS256' # 选择加密算法
jwt.private_file  = "./cart/private_file.pem" # 秘钥
jwt.public_file  = "./cart/private_file.pub"  # 公钥
user = {'id':1,'username':'guapit'}

# 进行加密
encode_key = jwt.encode_ssl_file(user)

# 进行解密
decode = jwt.decode_ssl_file(encode)
```

### 高级扩展

```python
from flask_jwt_token import JwtToken

jwt = JwtToken()
jwt.crypto = 'HS256' # 选择加密算法
jt.key = "iJIUzUxMiIsInR5cC" # 秘钥

jwt.issuer = ["guapit","瓜皮猫"] # 设置签发者
jwt.address = ["https://guapit.com","github.com"] # 设置授权接受订阅用户
user = {'id':1,'username':'guapit'}

# 进行加密
encode_key = jwt.encode(user)

# 进行解密
# 如果设置的解密 issuer 发布者中 属于 jt.issuer 其中一个可以解密成功
# 如果设置的解密 address 订阅者中属于 jt.address 其中一个可以解密成功
decode = jwt.decode(encode,address=["github.com"],issuer=["guapit"])


```

### 返回字段过滤

```python
from flask_jwt_token import JwtToken

jwt = JwtToken()
jwt.crypto = 'HS256' # 选择加密算法
jwt.key = "iJIUzUxMiIsInR5cC" # 秘钥
jwt.require = ['typ','alg','iss','iti','aud']
user = {'id':1,'username':'guapit'}

# 进行加密
encode_key = jwt.encode(user)

# 进行解密
decode = jwt.decode(encode)
```

这样返回后数据就是

```json
True, {'pal': {'id': 1, 'username': 'guapit'}, 'exp': 1675862965, 'exm': 1676438960, 'iat': 1675862960, 'nbf': 1675862960}, 'Token令牌获取成功')
```

### 控制过期时间

```python
jwt.expiration = 500 # 表示500秒后过期
jwt.expiration_max = 7 # 表示 最大可延续的周期为7天

 # 表示当前时间 + 60秒后,此Token才会生效
jwt.active_expiration = datetime.now() + timedelta(seconds=60)
```

### 完整返回信息

```python
typ:str = 'JWT' # 签发类型
alg:str # 加密算法
iss:str = None # 签发者
iti:str = None # uuid
aud:List[str]|str = None # 收信人
pal:dict = {} # 荷载对象
exp:Optional[datetime] # 过期时间
exm:Optional[int] = None # 最大过期时间
iat:Optional[datetime] # 创建时间
nbf:Optional[datetime] = None # 不得超过的最大时间
```

注意返回的信息是一个元祖

第一个参数:表示是否成功获取到解密信息

第二个参数:表示成功获取的解密数据,否则为空字典

第三个参数: 表示获取Token的状态注解

返回后信息

```json
True, {'typ': 'JWT', 'alg': 'HS256', 'iss': None, 'iti': None, 'aud': None, 'pal': {'id': 1, 'username': 'guapit'}, 'exp': 1675862965, 'exm': 1676438960, 'iat': 1675862960, 'nbf': 1675862960}, 'Token令牌获取成功')
```



**更多扩展定制,等待你发现...**

## 支持的加密算法

```bash
HS256 - HMAC using SHA-256 hash algorithm (default)
HS384 - HMAC using SHA-384 hash algorithm
HS512 - HMAC using SHA-512 hash algorithm
ES256 - ECDSA signature algorithm using SHA-256 hash algorithm
ES256K - ECDSA signature algorithm with secp256k1 curve using SHA-256 hash algorithm
ES384 - ECDSA signature algorithm using SHA-384 hash algorithm
ES512 - ECDSA signature algorithm using SHA-512 hash algorithm
RS256 - RSASSA-PKCS1-v1_5 signature algorithm using SHA-256 hash algorithm
RS384 - RSASSA-PKCS1-v1_5 signature algorithm using SHA-384 hash algorithm
RS512 - RSASSA-PKCS1-v1_5 signature algorithm using SHA-512 hash algorithm
PS256 - RSASSA-PSS signature using SHA-256 and MGF1 padding with SHA-256
PS384 - RSASSA-PSS signature using SHA-384 and MGF1 padding with SHA-384
PS512 - RSASSA-PSS signature using SHA-512 and MGF1 padding with SHA-512
EdDSA - Both Ed25519 signature using SHA-512 and Ed448 signature using SHA-3 are supported. Ed25519 and Ed448 provide 128-bit and 224-bit security respectively.

```

