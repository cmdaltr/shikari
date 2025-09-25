from setuptools import setup, find_packages

setup(
    name="archer",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "fastapi",
        "uvicorn[standard]",
        "pyyaml",
        "python-dotenv",
        "jinja2",
    ],
    entry_points={
        "console_scripts": [
            "archer-service=gorgon.app:app",
        ],
    },
)
