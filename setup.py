# ─────────────────────────────────────────────────────────────
#  setup.py — Makes osint-tool installable as a package
#  Run: pip install -e .
# ─────────────────────────────────────────────────────────────

from setuptools import setup, find_packages

setup(
    name="osint-tool",
    version="1.0.0",
    description="OSINT Intelligence Tool — BE Cybersecurity Project",
    author="Your Name",
    python_requires=">=3.10",
    packages=find_packages(),
    install_requires=[
        "requests>=2.31.0",
        "aiohttp>=3.9.0",
        "python-dotenv>=1.0.0",
        "rich>=13.7.0",
        "phonenumbers>=8.13.0",
        "dnspython>=2.4.0",
        "Pillow>=10.2.0",
        "imagehash>=4.3.1",
        "reportlab>=4.1.0",
    ],
    entry_points={
        "console_scripts": [
            "osint-tool=main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Intended Audience :: Education",
    ],
)
