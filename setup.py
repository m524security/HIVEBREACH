from setuptools import setup, find_packages

setup(
    name="hivebreach",
    version="1.1.0",
    description="ECC-agent-harness-based autonomous penetration testing framework",
    author="HiveBreach",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "pyyaml",
        "docker",
        "cryptography",
        "requests",
        "aiohttp",
        "pydantic",
        "click",
    ],
    entry_points={
        "console_scripts": [
            "hivebreach=cli:main",
        ],
    },
)
