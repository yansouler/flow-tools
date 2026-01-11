from setuptools import setup, find_packages

setup(
    name="network-traffic-tool",
    version="1.0.0",
    description="网络流量生成与分析工具",
    author="",
    author_email="",
    packages=find_packages(),
    install_requires=[
        "scapy>=2.4.5",
        "pywin32>=303",
        "PyQt5>=5.15.6",
        "matplotlib>=3.5.2",
        "seaborn>=0.11.2",
        "numpy>=1.21.6",
        "pandas>=1.3.5"
    ],
    entry_points={
        "console_scripts": [
            "traffic-sender = sender.sender_gui:main",
            "traffic-receiver = receiver.receiver_gui:main"
        ]
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Operating System :: Microsoft :: Windows",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Software Development :: Testing"
    ]
)