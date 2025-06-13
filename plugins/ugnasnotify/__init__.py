# 标准库导入
import os
import base64
import json
import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

from urllib3.exceptions import InsecureRequestWarning
# requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)  # 禁用不安全请求警告

# 第三方库导入
from pydantic import BaseModel

from typing import Any, List, Dict, Tuple, Optional
from apscheduler.schedulers.background import BackgroundScheduler
from app.core.config import settings

from apscheduler.triggers.cron import CronTrigger
from ruamel.yaml import CommentedMap

# 本地模块导入
from app import schemas
from app.core.config import settings
from app.helper.notification import NotificationHelper
from app.helper.message import MessageHelper
from app.log import logger
from app.plugins import _PluginBase
from app.schemas import  NotificationType
from app.utils.http import RequestUtils

class UgnasNotify(_PluginBase):

    # 插件名称
    plugin_name = "绿联NAS通知转发"
    # 插件描述
    plugin_desc = "定时获取绿联NAS通知并推送至企业微信"
    # 插件图标
    plugin_icon = "brush.jpg"
    # 插件版本
    plugin_version = "1.0"
    # 插件作者
    plugin_author = "Hesssc"
    # 作者主页
    author_url = "https://github.com/Hesccc"
    # 插件配置项ID前缀
    plugin_config_prefix = "UgnasNotify_"
    # 加载顺序
    plugin_order = 30
    # 可使用的用户级别
    auth_level = 1

    # 定时器
    _scheduler: Optional[BackgroundScheduler] = None
    # 加载的模块
    _site_schema: list = []

    # 配置基础参数属性
    _enabled: bool = False  # 启用插件
    _cron: str = ""  # 定时计划
    _onlyonce: bool = False  # 立即执行
    _ip: str = None
    _port: int = None
    _username: str = None
    _password: str = None
    _url = f"http://127.0.0.1:3001/api/v1/plugin/MsgNotify/send_json?apikey={settings.API_TOKEN}"

    http_proxy = None
    https_proxy = None


    def __init__(self):
        super().__init__()


    def init_plugin(self, config: dict = None):
        # 停止现有任务
        self.stop_service()

        # 获取配置内容
        if config:
            self._enabled = config.get("enabled")
            self._enabled = config.get("notify")
            self._cron = config.get("cron")
            self._onlyonce = config.get("onlyonce")
            self._ip = config.get("ip")
            self._port = config.get("port")
            self._username = config.get("username")
            self._password = config.get("password")

            # 加载模块
            if self._enabled or self._onlyonce:

                # 立即运行一次
                if self._onlyonce:
                    # pass
                    self.start()

    def get_state(self) -> bool:
        return self._enabled

    def stop_service(self):
        """
        退出插件
        """
        try:
            if self._scheduler:
                self._scheduler.remove_all_jobs()
                if self._scheduler.running:
                    self._scheduler.shutdown()
                self._scheduler = None
        except Exception as e:
            logger.error("退出插件失败：%s" % str(e))

    def get_api(self) -> List[Dict[str, Any]]:
        pass


    def start(self):
        # 获取rsa_token
        rsa_token = self.get_rsa_token()

        # 使用rsa_token加密明文密码
        ency_password = self.encrypted_password(rsa_token, self._password)

        # 获取login结果
        login_result = self.login(ency_password)

        # 获取token_id和再次加密token，使用public_key加密token获得持久化的token。
        token_id, token = login_result['data']['token_id'], self.encrypted_password(
            login_result['data']['public_key'], login_result['data']['token'])

        # 保存token消息
        self.save_auth_info(token_id=token_id, token=token)

        # 获取通知
        notify_result = self.get_notify(token_id=token_id, token=token)
        for item in notify_result['data']['List']:
            text = f"通知时间：{datetime.datetime.fromtimestamp(item['time'])}\n内容：{item['body']}\n模块：{item['module']}\n日志ID：{item['id']}\n日志级别：{item['level']}"
            if self.push_notify(text):
                logger.info(f"发送通知成功，内容为：{text}")


    def get_rsa_token(self):
        data = {
            "username": self._username
        }
        headers = {
            "Content-Type": "application/json"
        }
        try:
            response = RequestUtils().post_res(
                url=f"https://{self._ip}:{self._port}/ugreen/v1/verify/check?token=",
                json=data,
                headers=headers,
                verify=False,
                timeout=10
            )
            if response and response.status_code == 200:
                logger.error(response.headers.get("X-Rsa-Token"))
                print(response.headers.get("X-Rsa-Token"))
                return response.headers.get("X-Rsa-Token")
        except Exception as e:
            logger.error(f"获取 token 时出错，IP: {self._ip}, 端口: {self._port}, 错误信息: {e}")
            return None

    def login(self, ency_password:str):
        headers = {
            "x-specify-language": "zh-CN"
        }

        data = {
            "username": self._username,
            "password": ency_password,
            "keepalive": True,
            "is_simple": True
        }

        try:
            response = RequestUtils().post_res(
                url=f"https://{self._ip}:{self._port}/ugreen/v1/verify/login",
                json=data,
                headers=headers,
                verify=False,
                timeout=10)
            if response and response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.error(f"登录时出错，IP: {self._ip}, 端口: {self._port}, 错误信息: {e}")
            return {}

    def encrypted_password(self, encoded_str, text_to_encrypt):
        decoded_bytes = base64.b64decode(encoded_str)  # 返回 bytes
        decoded_str = decoded_bytes.decode('utf-8')  # 转为字符串（如果是文本）

        def encrypt_with_public_key(decoded_str, plaintext) -> str:
            """
            使用已有的公钥加密字符串，返回 Base64 结果（兼容 JSEncrypt）
            :param decoded_str: PEM 格式的公钥（字符串）
            :param plaintext: 要加密的文本
            :return: Base64 编码的加密结果
            """
            # 1. 加载公钥
            key = RSA.import_key(decoded_str)

            # 2. 使用 PKCS#1 v1.5 填充加密
            cipher = PKCS1_v1_5.new(key)
            encrypted_bytes = cipher.encrypt(plaintext.encode('utf-8'))

            # 3. 转为 Base64 字符串（与 JSEncrypt 一致）
            return base64.b64encode(encrypted_bytes).decode('utf-8')

        # Remove the test block and directly call the encryption function
        encrypted_result = encrypt_with_public_key(decoded_str, text_to_encrypt)
        return encrypted_result

    def save_auth_info(self, token_id:str, token:str):
        os.makedirs("token", exist_ok=True)
        config_file = os.path.join("token", f"{self._username}.config")
        auth_info = {
            'ip': self._ip,
            'port': self._port,
            'username': self._username,
            'token_id': token_id,
            'token': token
        }
        with open(config_file, 'w') as f:
            json.dump(auth_info, f)
        return None


    def get_notify(self, token_id: str, token:str):
        """
        获取绿联设备通知
        """
        headers = {
            "x-specify-language": "zh-CN",
            "x-ugreen-security-key": token_id,
            "x-ugreen-token": token
        }
        data = {"level": ["info", "important", "warning"], "page": 1, "size": 10}
        try:
            response = RequestUtils().post_res(
                url = f"https://{self._ip}:{self._port}/ugreen/v1/desktop/message/list",
                json=data,
                headers=headers,
                verify=False,
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"获取绿联通知时出错，IP: {self._ip}, 端口: {self._port}, 错误信息: {e}")
            return {}

    def push_notify(self, message:str):
        try:
            data = {
                "title": "📢绿联NAS消息通知",
                "text": message
            }
            headers = {'content-type': "application/json"}
            response = RequestUtils().post_res(url=self._url,
                                     headers=headers,
                                     json=data,
                                     verify=False,
                                     timeout=10)
            if response.raise_for_status() == 200:
                return True
        except Exception as e:
            logger.error(f"发送{message}出错，错误信息: {e}")
            return False


    def get_form(self) -> Tuple[List[dict], Dict[str, Any]]:
        """
        拼装插件配置页面，需要返回两块数据：1、页面配置；2、数据结构
        """
        
        MsgTypeOptions = []
        for item in NotificationType:
            MsgTypeOptions.append({
                "title": item.value,
                "value": item.name
            })
        return [
            {
                'component': 'VForm',
                'content': [
                    {
                        'component': 'VCard',
                        'props': {
                            'variant': 'flat',
                            'class': 'mb-6',
                            'color': 'surface'
                        },
                        'content': [
                            {
                                'component': 'VCardItem',
                                'props': {
                                    'class': 'px-6 pb-0'
                                },
                                'content': [
                                    {
                                        'component': 'VCardTitle',
                                        'props': {
                                            'class': 'd-flex align-center text-h6'
                                        },
                                        'content': [
                                            {
                                                'component': 'VIcon',
                                                'props': {
                                                    'style': 'color: #16b1ff;',
                                                    'class': 'mr-3',
                                                    'size': 'default'
                                                },
                                                'text': 'mdi-cog'
                                            },
                                            {
                                                'component': 'span',
                                                'text': '基本设置'
                                            }
                                        ]
                                    }
                                ]
                            },
                            {
                                'component': 'VDivider',
                                'props': {
                                    'class': 'mx-4 my-2'
                                }
                            },
                            {
                                'component': 'VCardText',
                                'props': {
                                    'class': 'px-6 pb-6'
                                },
                                'content': [
                                    {
                                        'component': 'VRow',
                                        'content': [
                                            {
                                                'component': 'VCol',
                                                'props': {
                                                    'cols': 12,
                                                    'sm': 4
                                                },
                                                'content': [
                                                    {
                                                        'component': 'VSwitch',
                                                        'props': {
                                                            'model': 'enabled',
                                                            'label': '启用插件',
                                                            'color': 'primary',
                                                            'hide-details': True
                                                        }
                                                    }
                                                ]
                                            },
                                            {
                                                'component': 'VCol',
                                                'props': {
                                                    'cols': 12,
                                                    'sm': 4
                                                },
                                                'content': [
                                                    {
                                                        'component': 'VSwitch',
                                                        'props': {
                                                            'model': 'notify',
                                                            'label': '开启通知',
                                                            'color': 'primary',
                                                            'hide-details': True
                                                        }
                                                    }
                                                ]
                                            },
                                            {
                                                'component': 'VCol',
                                                'props': {
                                                    'cols': 12,
                                                    'sm': 4
                                                },
                                                'content': [
                                                    {
                                                        'component': 'VSwitch',
                                                        'props': {
                                                            'model': 'onlyonce',
                                                            'label': '立即运行一次',
                                                            'color': 'primary',
                                                            'hide-details': True
                                                        }
                                                    }
                                                ]
                                            },
                                        ]
                                    }
                                ]
                            },
                            ## 分隔符
                            {
                                'component': 'VDivider',
                                'props': {
                                    'class': 'mx-4 my-2'
                                }
                            },
                            ########################
                            {
                                'component': 'VCardItem',
                                'props': {
                                    'class': 'px-6 pb-0'
                                },
                                'content': [
                                    {
                                        'component': 'VCardTitle',
                                        'props': {
                                            'class': 'd-flex align-center text-h6'
                                        },
                                        'content': [
                                            {
                                                'component': 'VIcon',
                                                'props': {
                                                    'style': 'color: #16b1ff;',
                                                    'class': 'mr-3',
                                                    'size': 'default'
                                                },
                                                'text': 'mdi-pencil'
                                            },
                                            {
                                                'component': 'span',
                                                'text': '插件基础配置'
                                            }
                                        ]
                                    }
                                ]
                            },
                            ## 分隔符
                            {
                                'component': 'VDivider',
                                'props': {
                                    'class': 'mx-4 my-2'
                                }
                            },
                            #########################

                            {
                                'component': 'VRow',
                                'content': [
                                    {
                                        'component': 'VCol',
                                        'props': {
                                            "cols": 12,
                                            "md": 4
                                        },
                                        'content': [
                                            {
                                                'component': 'VCronField',
                                                'props': {
                                                    'model': 'cron',
                                                    'label': '执行频率',
                                                    'placeholder': '如：0 0-1 * * FRI,SUN；建议30分钟执行一次。',
                                                }
                                            }
                                        ]
                                    },
                                    {
                                        'component': 'VCol',
                                        'props': {
                                            "cols": 12,
                                            "md": 4
                                        },
                                        'content': [
                                            {
                                                'component': 'VTextField',
                                                'props': {
                                                    'model': 'ip',
                                                    'label': 'IP地址',
                                                    'placeholder': '如：10.10.0.241',
                                                }
                                            }
                                        ]
                                    },
                                    {
                                        'component': 'VCol',
                                        'props': {
                                            "cols": 12,
                                            "md": 4
                                        },
                                        'content': [
                                            {
                                                'component': 'VTextField',
                                                'props': {
                                                    'model': 'port',
                                                    'label': '端口',
                                                    'placeholder': '如：9443(https)',
                                                }
                                            }
                                        ]
                                    }
                                ]
                            },
                            {
                                'component': 'VRow',
                                'content': [
                                    {
                                        'component': 'VCol',
                                        'props': {
                                            "cols": 12,
                                            "md": 6
                                        },
                                        'content': [
                                            {
                                                'component': 'VTextField',
                                                'props': {
                                                    'model': 'username',
                                                    'label': '用户名',
                                                    'placeholder': '如：admin',
                                                }
                                            }
                                        ]
                                    },
                                    {
                                        'component': 'VCol',
                                        'props': {
                                            "cols": 12,
                                            "md": 6
                                        },
                                        'content': [
                                            {
                                                'component': 'VTextField',
                                                'props': {
                                                    'model': 'password',
                                                    'label': '密码',
                                                    'placeholder': '如：password',
                                                }
                                            }
                                        ]
                                    },
                                ]
                            },
                        ]
                    },
                    {
                        'component': 'VCard',
                        'props': {
                            'variant': 'flat',
                            'class': 'mb-6',
                            'color': 'surface'
                        },
                        'content': [
                            {
                                'component': 'VCardItem',
                                'props': {
                                    'class': 'px-6 pb-0'
                                },
                                'content': [
                                    {
                                        'component': 'VCardTitle',
                                        'props': {
                                            'class': 'd-flex align-center text-h6 mb-0'
                                        },
                                        'content': [
                                            {
                                                'component': 'VIcon',
                                                'props': {
                                                    'style': 'color: #16b1ff;',
                                                    'class': 'mr-3',
                                                    'size': 'default'
                                                },
                                                'text': 'mdi-information'
                                            },
                                            {
                                                'component': 'span',
                                                'text': '插件使用说明'
                                            }
                                        ]
                                    }
                                ]
                            },
                            {
                                'component': 'VDivider',
                                'props': {
                                    'class': 'mx-4 my-2'
                                }
                            },
                            {
                                'component': 'VCardText',
                                'props': {
                                    'class': 'px-6 pb-6'
                                },
                                'content': [
                                    {
                                        'component': 'VList',
                                        'props': {
                                            'lines': 'two',
                                            'density': 'comfortable'
                                        },
                                        'content': [
                                            {
                                                'component': 'VListItem',
                                                'props': {
                                                    'lines': 'two'
                                                },
                                                'content': [
                                                    {
                                                        'component': 'div',
                                                        'props': {
                                                            'class': 'd-flex align-items-start'
                                                        },
                                                        'content': [
                                                            {
                                                                'component': 'VIcon',
                                                                'props': {
                                                                    'color': 'primary',
                                                                    'class': 'mt-1 mr-2'
                                                                },
                                                                'text': 'mdi-api'
                                                            },
                                                            {
                                                                'component': 'div',
                                                                'props': {
                                                                    'class': 'text-subtitle-1 font-weight-regular mb-1'
                                                                },
                                                                'text': '前提条件'
                                                            }
                                                        ]
                                                    },
                                                    {
                                                        'component': 'div',
                                                        'props': {
                                                            'class': 'text-body-2 ml-8'
                                                        },
                                                        'text': '1、已配置企业微信通知，MoviePilot能正常与企业微信进行交互。'
                                                    },
                                                    {
                                                        'component': 'div',
                                                        'props': {
                                                            'class': 'text-body-2 ml-8'
                                                        },
                                                        'text': '2、已安装并启用 由KoWming佬开发的"外部消息转发"插件。'
                                                    }
                                                ]
                                            },
                                            {
                                                'component': 'VListItem',
                                                'props': {
                                                    'lines': 'two'
                                                },
                                                'content': [
                                                    {
                                                        'component': 'div',
                                                        'props': {
                                                            'class': 'd-flex align-items-start'
                                                        },
                                                        'content': [
                                                            {
                                                                'component': 'VIcon',
                                                                'props': {
                                                                    'color': 'primary',
                                                                    'class': 'mt-1 mr-2'
                                                                },
                                                                'text': 'mdi-api'
                                                            },
                                                            {
                                                                'component': 'div',
                                                                'props': {
                                                                    'class': 'text-subtitle-1 font-weight-regular mb-1'
                                                                },
                                                                'text': '参数说明'
                                                            }
                                                        ]
                                                    },
                                                    {
                                                        'component': 'div',
                                                        'props': {
                                                            'class': 'text-body-2 ml-8'
                                                        },
                                                        'text': '填写绿联NAS设备所在的局域网IP地址及端口，获取通知需要登录凭（建议管理员权限账户）'
                                                    },
                                                    {
                                                        'component': 'div',
                                                        'props': {
                                                            'class': 'text-body-2 ml-8'
                                                        },
                                                        'text': '关于插件的执行频率设置，强烈建议将任务执行间隔设定为每30分钟一次，不会对NAS造成过大的负载压力。'
                                                    }
                                                ]
                                            },
                                            {
                                                'component': 'VListItem',
                                                'props': {
                                                    'lines': 'two'
                                                },
                                                'content': [
                                                    {
                                                        'component': 'div',
                                                        'props': {
                                                            'class': 'd-flex align-items-start'
                                                        },
                                                        'content': [
                                                            {
                                                                'component': 'VIcon',
                                                                'props': {
                                                                    'color': 'error',
                                                                    'class': 'mt-1 mr-2'
                                                                },
                                                                'text': 'mdi-heart'
                                                            },
                                                            {
                                                                'component': 'div',
                                                                'props': {
                                                                    'class': 'text-subtitle-1 font-weight-regular mb-1'
                                                                },
                                                                'text': '致谢'
                                                            }
                                                        ]
                                                    },
                                                    {
                                                        'component': 'div',
                                                        'props': {
                                                            'class': 'text-body-2 ml-8'
                                                        },
                                                        'content': [
                                                            {
                                                                'component': 'span',
                                                                'text': '参考了 '
                                                            },
                                                            {
                                                                'component': 'a',
                                                                'props': {
                                                                    'href': 'https://github.com/KoWming/MoviePilot-Plugins',
                                                                    'target': '_blank',
                                                                    'style': 'text-decoration: underline;'
                                                                },
                                                                'content': [
                                                                    {
                                                                        'component': 'u',
                                                                        'text': 'KoWming/MoviePilot-Plugins'
                                                                    }
                                                                ]
                                                            },
                                                            {
                                                                'component': 'span',
                                                                'text': ' 项目，实现了插件的相关功能。特此感谢 '
                                                            },
                                                            {
                                                                'component': 'a',
                                                                'props': {
                                                                    'href': 'https://github.com/KoWming',
                                                                    'target': '_blank',
                                                                    'style': 'text-decoration: underline;'
                                                                },
                                                                'content': [
                                                                    {
                                                                        'component': 'u',
                                                                        'text': 'KoWming'
                                                                    }
                                                                ]
                                                            },
                                                            {
                                                                'component': 'span',
                                                                'text': ' 大佬！'
                                                            }
                                                        ]
                                                    },
                                                    {
                                                        'component': 'div',
                                                        'props': {
                                                            'class': 'text-body-2 ml-8'
                                                        },
                                                        'content': [
                                                            {
                                                                'component': 'span',
                                                                'text': '参考了 '
                                                            },
                                                            {
                                                                'component': 'a',
                                                                'props': {
                                                                    'href': 'https://mp.weixin.qq.com/s/lzlTmj6eczyrdz60Gvllaw',
                                                                    'target': '_blank',
                                                                    'style': 'text-decoration: underline;'
                                                                },
                                                                'content': [
                                                                    {
                                                                        'component': 'u',
                                                                        'text': 'NAS通知早知道，把绿联云NAS里的通知消息定时推送到微信'
                                                                    }
                                                                ]
                                                            },
                                                            {
                                                                'component': 'span',
                                                                'text': ' 文章，实现插件中绿联NAS登录的相关功能。特此感谢 '
                                                            },
                                                            {
                                                                'component': 'a',
                                                                'props': {
                                                                    'href': 'https://zhiyou.smzdm.com/member/1477395615/',
                                                                    'target': '_blank',
                                                                    'style': 'text-decoration: underline;'
                                                                },
                                                                'content': [
                                                                    {
                                                                        'component': 'u',
                                                                        'text': 'koryking'
                                                                    }
                                                                ]
                                                            },
                                                            {
                                                                'component': 'span',
                                                                'text': ' 大佬！'
                                                            }
                                                        ]
                                                    }
                                                ]
                                            }





                                        ]
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        ], {
            "enabled": False,
            "notify": False,
            "msgtype": "Manual",
            "image_mappings": ""
        }

    def get_page(self) -> List[dict]:
        pass

    def stop_service(self):
        """
        退出插件
        """
        pass
