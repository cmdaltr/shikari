from setuptools import setup, find_packages

setup(
    name="archer",
    version="0.1.0",
    packages=find_packages(),  # automatically find archer and subpackages
    install_requires=[
        "fastapi",
        "uvicorn[standard]",
        "pyyaml",
        "requests",
        "python-dotenv",
    ],
    extras_require={"dev": ["pytest", "black", "mypy"]},
    entry_points={
        "console_scripts": [
            "archer-service=archer.app:main",  # start service via `archer-service`
        ],
    },
    python_requires=">=3.11",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Framework :: FastAPI",
        "License :: OSI Approved :: MIT License",
    ],
)
