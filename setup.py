from setuptools import setup, find_packages

setup(
    name="webvulnscanner",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "requests>=2.28.1",
        "beautifulsoup4>=4.11.1",
        "httpx>=0.23.0",
        "PyYAML>=6.0",
        "flask>=2.2.2",
        "flask-socketio>=5.3.0",
        "python-engineio>=4.3.4",
        "python-socketio>=5.7.2",
        "lxml>=4.9.1",
        "robotexclusionrulesparser>=1.7.1",
        "rich>=12.6.0",
        "colorama>=0.4.6",
        "cryptography>=38.0.3",
        "python-dateutil>=2.8.2",
    ],
    entry_points={
        "console_scripts": [
            "webvulnscanner=console:main",
        ],
    },
)
