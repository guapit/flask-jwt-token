"""
支持的加密算法:
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
"""
from json import JSONEncoder

import jwt,uuid
from datetime import datetime,timezone,timedelta
import time
# from pprint import pprint
from typing import List,Optional, Type,Union
from pydantic import BaseModel

# 验证配置对象
class Config(BaseModel):
    key: str # 公共加密秘钥
    crypto: str = 'HS256' # 加密算法
    private_key: str = None # 这是私钥,如果使用openssl加密
    public_key: str = None # 这是公钥,如果使用openssl加密
    private_file: str = None # 这是私钥文件路径,如果使用openssl加密
    public_file: str = None # 这是公钥文件路径,如果使用openssl加密
    address: str = None # 收件人,如果有指定的签名范围可以
    verify_exp:Optional[bool] = True # 是否关闭过期验证
    verify_signatrue:Optional[bool] = True # 验证签名,如果希望阅读JWT的声明集而不执行签名或任何已注册的声明名的验证，可以将verify_signature选项设置为False。
    active_expiratin:Optional[datetime] = None # 设置主动过期时间

# 验证荷载对象
class PlayLoad(BaseModel):
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
    

class JwtToken:
    """为了异步运算,JwtToken将尽量减少异常捕获和判断逻辑"""
    def __init__(self):
        self.key:str = "guapi" # 公共加密秘钥
        self.crypto: str = 'HS256' # 加密算法
        self.private_key: str = None # 这是私钥,如果使用openssl加密
        self.public_key: str = None # 这是公钥,如果使用openssl加密
        self.private_file: str = None # 这是私钥文件路径,如果使用openssl加密
        self.public_file: str = None # 这是公钥文件路径,如果使用openssl加密
        self.issuer:str = None # 签发者(可选),如果不填默认 any
        self.type: str = 'JWT' # 签发类型(可选),有些环境需要选择签发类型时再设置
        self.address: List[str]|str = None # 收件人(可选),如果有指定的签名范围可以
        self.verify_exp:Optional[bool] = True # 是否关闭过期验证
        self.verify_signatrue:Optional[bool] = True # 验证签名,如果关闭只加密信息,不进行key秘钥加密
        self.expiration:Optional[int] = 5 # Token临时到期时间
        self.expiration_max:Optional[int] = 7 # Token最大有效期
        self.is_uuid:Optional[bool] = False # 是否需要加盐
        self.utc:Optional[timezone] = None # 设置时区
        self.kid: str = None # 前后端共享公钥
        self.require: List[str] = None # 解密后过滤器,可以选择返回指定字段信息
        self.active_expiration:Optional[datetime] = None # 设置Token什么时间内无法使用

    # 创建荷载对象
    def create_playload(self, data:dict = {}) -> dict:
        """
        将数据封装到playload对象里
        :param data: 需要加密的信息数据
        :return: 验证数据合法后返回 playload 对象
        """
        playload:dict = {}
        playload['alg'] = self.crypto or 'HS256'
        playload['iss'] = self.issuer
        if self.is_uuid:
            playload['iti'] = uuid.uuid4().hax
        if self.address:
            playload['aud'] = self.address
        playload['pal'] = data
        if self.utc:
            playload['exp'] = datetime.now(tz=self.utc) + timedelta(seconds=self.expiration)
            playload['iat'] = datetime.now(tz=self.utc)
            playload['exm'] = time.mktime(datetime.now(tz=timezone.utc).timetuple()) + self.expiration_max * 86400
            playload['nbf'] = datetime.now(tz=self.utc)
        else:
            playload['exp'] = datetime.now() + timedelta(seconds=self.expiration) 
            playload['iat'] = datetime.now()
            playload['exm'] = time.time() + self.expiration_max  * 86400
            playload['nbf'] = datetime.now()
        if self.active_expiration:
                playload['nbf'] = self.active_expiration
        playload_val = PlayLoad(**playload)
        return playload_val.dict()
    
    def get_playload(self,palyload:tuple[bool, dict, str],require:List[str]=None,language:str="en") ->tuple[bool, dict, str]:
        """
        English Fields:
            crypto,type,address,create_time,expiration,expiration_max,issuer,issuer,uuid,active_exp,pal
        中文字段:
            加密算法,加盐类型,可访问者,创建时间,到期时间,到期上限,发布者,唯一识别码,主动过期,解密数据
        :param palyload: 荷载对象
        :param require: 过滤掉不需要返回的字段,参考上面的字段名称
        :param language: 设置语言版本 en | cn
        :return: 验证数据合法后返回过滤后的 playload 对象    
        """
        state,data,msg = palyload
        _data_copy = PlayLoad(**data).dict()
        # pprint(_data_copy)
        in118 = []
        in118.append('crypto' if language == "en" else '加密算法')
        in118.append('type' if language == "en" else '加盐类型')
        in118.append('address' if language == "en" else '可访问者')
        in118.append('create_time' if language == "en" else '创建时间')
        in118.append('expiration' if language == "en" else '到期时间')
        in118.append('expiration_max' if language == "en" else '到期上限')
        in118.append('issuer' if language == "en" else '发布者')
        in118.append('uuid' if language == "en" else '唯一识别码')
        in118.append('expiration_stop' if language == "en" else '主动过期')
        in118.append('data' if language == "en" else '解密数据')
        _data = {}
        _data[in118[0]] = _data_copy.get('alg',None)
        _data[in118[1]] = _data_copy.get('typ',None)
        _data[in118[2]] = _data_copy.get('aud',None)
        _data[in118[3]] = int(time.mktime(_data_copy.get('iat',None).timetuple()))
        _data[in118[4]] =  int(time.mktime(_data_copy.get('exp',None).timetuple()))
        _data[in118[5]] = _data_copy.get('exm',None)
        _data[in118[6]] = _data_copy.get('iss',None)
        _data[in118[7]] = _data_copy.get('iti',None)
        _data[in118[8]] = None if _data_copy.get('nbf',None) == None else int(time.mktime(_data_copy.get('nbf').timetuple()))
        _data[in118[9]] = _data_copy.get('pal',None)
        if require:
            for req in require:
                _data.pop(req)
                    
        return state, _data,msg
        
    def get_headers(self,encode_key:str) -> dict:
        """得到解密后的明文headers头信息"""
        return jwt.get_unverified_header(encode_key)
    
    def set_headers(self,headers: dict = None) -> dict:
        """
        设置加密荷载的头部信息
        如果设置了 self.kid 会优先使用属性上的值
        :param headers: 需要加密的信息数据
        :return: 返回更新后的headers信息
        """
        _headers: dict = {}
        _headers['typ'] = self.type
        if headers:
            _headers.update(headers)
        if self.kid:
            _headers['kid'] = self.kid
        return _headers

    def __base_encode(self,data:dict = {},key:str = "",headers:dict = None,json_encoder: Type[JSONEncoder] | None = None) -> str:
        """
        加密底层接口,请勿乱动!
        """
        _headers = self.set_headers(headers)
        playload = self.create_playload(data)

        _token = jwt.encode(playload,key=key,algorithm=self.crypto,headers=_headers,
                            json_encoder=json_encoder)

        return _token
    
    def encode(self,data:dict = {},headers:dict = None,json_encoder: Type[JSONEncoder] | None = None) -> str:
        """
        根据 self.key 的属性进行加密
        :param data: 需要加密的信息数据
        :param headers: 如果需要在荷载信息头部加入定制信息可以传入字典
        :param json_encoder: 自定义json解析接口(一般无需设置)
        :return: 验证数据合法后返回 playload 对象
        
        """
        _token = self.__base_encode(data,key=self.key,headers=headers, json_encoder=json_encoder)
        return _token

    def __base_decode(self,encode_key:str,key:str = "",address:List[str]|str=None,issue:str = None,leeway:Union[int, float, timedelta] = 0) -> tuple[bool, dict, str]:
        """
        解密底层接口,请勿乱动!
        params:
            encode: token加密后的秘钥
            address: 允许访问的范围,一般设置前端地址,以防跨站攻击
            issue: 签发者
            leeway:到期后的宽限时间 也可以是秒
        return: (是否成功, 数据返回)
        """
        options = {
            "verify_exp": self.verify_exp,
            "verify_signature": self.verify_signatrue
        }
        if self.require:
            options['require'] = self.require
        
        if not address:
            _address = self.address
        else:
            _address = address
        
        if not issue:
            _issue = self.issuer
        else:
            _issue = issue
        try:
            _playload = jwt.decode(encode_key,key=key,algorithms=self.crypto,options=options,
                                audience=_address,issuer = _issue,leeway=leeway)

            if _playload['exp'] and _playload['exm'] and _playload['exp'] >= _playload['exm']:
                return False, {}

            return True, _playload, "Token令牌获取成功"
        except jwt.InvalidSignatureError:
            return False, {}, "Token令牌验证失败"
        except jwt.ExpiredSignatureError:
            return False, {}, "Token令牌已经过期"
        except jwt.DecodeError:
            return False, {}, "Token令牌不正确"
        except jwt.InvalidTokenError:
            return False, {}, "Token令牌无效"   
        
    def decode_complete(self,encode_key:str,address:List[str]|str=None,issue:str = None,leeway:Union[int, float, timedelta] = 0) -> tuple[bool, dict, str]:
        # pprint(self.key)
        return jwt.api_jwt.decode_complete(encode_key,key=self.key,algorithms=self.crypto,address=address,issue=issue,leeway=leeway)
    
    def decode(self,encode_key:str,address:List[str]|str=None,issue:str = None,leeway:Union[int, float, timedelta] = 0) -> tuple[bool, dict, str]:
        """
        根据 self.key 的属性进行解密
        :param encode_key: 加密文
        :param address: 允许解密的用户范围
        :param issue: 发布者中是否包含指定发布者
        :param leeway: 过期后允许多久宽容期,一般无需设置,默认设置为: 秒
        
        :return: 验证数据合法后返回 playload 对象
        
        """
        _playload = self.__base_decode(encode_key,key=self.key,address=address,issue=issue,leeway=leeway)
        return _playload

    def encode_ssl(self,data:dict = {},headers:dict = None, json_encoder: Type[JSONEncoder] | None = None) -> str:
        """
        根据 self.private_key 的属性进行加密
        生成私钥，指定私钥的长度为2048bit   1024基本安全, 2048非常安全
        linux: openssl genrsa -out rsa_private_key.pem 2048
        以上生成的是 RS256 加密密文
        :param data: 需要加密的信息数据
        :param headers: 如果需要在荷载信息头部加入定制信息可以传入字典
        :param json_encoder: 自定义json解析接口(一般无需设置)
        :return: 验证数据合法后返回Token密文
        
        """
        _token = self.__base_encode(data,key=self.private_key,headers=headers, json_encoder=json_encoder)
        return _token

    def decode_ssl(self,encode_key:str,address:List[str]|str=None,issue:str = None,leeway:Union[int, float, timedelta] = 0) -> tuple[bool, dict, str]:
        """
        根据 self.public_key 的属性进行解密
        根据私钥生成对应的公钥参考
        linux: openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key_2048.pub    
        以上生成的是 RS256 公钥
        :param encode_key: 加密文
        :param address: 允许解密的用户范围
        :param issue: 发布者中是否包含指定发布者
        :param leeway: 过期后允许多久宽容期,一般无需设置,默认设置为: 秒
        
        :return: 验证数据合法后返回 playload 对象
        
        """
        _token = self.__base_decode(encode_key,key=self.public_key,address=address,issue=issue,leeway=leeway)
        return _token

    def encode_ssl_file(self,data:dict = {},headers:dict = None, json_encoder: Type[JSONEncoder] | None = None) -> str:
        """
        根据 self.private_file 的属性的文件里面的私钥进行加密
        生成私钥，指定私钥的长度为2048bit   1024基本安全, 2048非常安全
        linux: openssl genrsa -out rsa_private_key.pem 2048
        以上生成的是 RS256 加密密文
        :param data: 需要加密的信息数据
        :param headers: 如果需要在荷载信息头部加入定制信息可以传入字典
        :param json_encoder: 自定义json解析接口(一般无需设置)
        :return: 验证数据合法后返回Token密文
        
        """
        with open(self.private_file,'rb') as f:
            _private = f.read()
            f.close()
        _token = self.__base_encode(data,key=self._private,headers=headers, json_encoder=json_encoder)
        return _token

    def decode_ssl_file(self,encode_key:str,address:List[str]|str=None,issue:str = None,leeway:Union[int, float, timedelta] = 0) -> tuple[bool, dict, str]:
        """
        根据 self.public_file 的属性的文件里面的公钥进行解密
        根据私钥生成对应的公钥参考
        linux: openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key_2048.pub    
        以上生成的是 RS256 公钥
        :param data: 需要加密的信息数据
        :param headers: 如果需要在荷载信息头部加入定制信息可以传入字典
        :param leeway: 过期后允许多久宽容期,一般无需设置,默认设置为: 秒
        :return: 验证数据合法后返回 playload 对象
        
        """
        with open(self.public_file,'rb') as f:
            _public= f.read()
            f.close()
        _token = self.__base_decode(encode_key,key=_public,address=address,issue=issue,leeway=leeway)
        return _token

    
    
    
# if __name__ in '__main__':
#     jt = JwtToken()
#     jt.key = "flask-pyticks-n%!j-fbgn98k4rrsrf*t%tgus^vsd5!p6#7(u82oau!*a3x2!l"
#     jt.crypto = 'HS256'
#     jt.utc = timezone.utc
#     user = {'id':1,'username':'guapit'}
    
#     # playload = jt.create_playload()
    
    # encode = jt.encode(user)
#     # pprint(encode)
#     # pprint(jt.key)
#     # encode_key = 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiIsImlzcyI6bnVsbCwiaXRpIjpudWxsLCJhdWQiOm51bGwsInBhbCI6eyJpZCI6MSwidXNlcm5hbWUiOiJndWFwaXQifSwiZXhwIjoxNjc1Nzg1NTEwLCJleG0iOjE2NzYzNjE1MDUsImlhdCI6MTY3NTc4NTUwNSwibmJmIjoxNjc1Nzg1NTA1fQ.zqG8IYh6qEkgemRNY0WSJhFkrnIHCqIWpGoNtF-jmh1zadb2TZCu2Y7eriZ58DlbhVO2YBbwaqynD9r_DacsUw'
#     # jt.key = "flask-pytic515ks-n%!j-fbgn98k4rrsrf*t%tgus^vsd5!p6#7(u82oau!*a3"
#     # pprint(jt.key)
    # decode = jt.decode(encode)
    # pprint(decode)
#     decode = jt.get_playload(decode,language="en",require=["address",'type','crypto','issuer'])
#     # com = jt.decode_complete(encode)
#     pprint(decode)

    