from setuptools import setup, find_packages

setup(
    name="SSHWhirl",
    version="1.0.0",
    author="KcanCurly",
    description="A script to brute ssh.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/KcanCurly/ssh-whirl",
    packages=find_packages(),
    install_requires=[
        "rich",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
    ],
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "sshwhirl=src.sshwhirl:main",  
        ],
    },
)