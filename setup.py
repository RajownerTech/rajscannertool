from setuptools import setup, find_packages

setup(
    name="rajscannertool",
    version="1.0.0",
    author="Mr Raj",
    author_email="raj.tech.hacker@protonmail.com",
    description="Multi Advance Host & CIDR Scanner Tool",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    install_requires=[
        "requests",
        "colorama",
        "rich",
    ],
    entry_points={
        "console_scripts": [
            "rajscannertool=rajscannertool.main:start",  # <-- folder name and function
        ],
    },
    python_requires=">=3.7",
)