"""Setup script for UAIP package."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="uaip",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Secure settlement layer for AI agents",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/uaip",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: Other/Proprietary License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "PyNaCl>=1.5.0",
        "base58>=2.1.1",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "black>=22.0.0",
            "flake8>=4.0.0",
        ],
        "langchain": [
            "langchain>=0.1.0",
            "langchain-openai>=0.0.2",
        ],
    },
)