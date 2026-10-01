from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="shopiscan",
    version="3.0.0",
    author="Juan León Galán",
    description="Auditor de seguridad pasivo para tiendas Shopify, potenciado por IA local (Ollama) con búsqueda vectorial (pgvector) y observabilidad (Prometheus/Grafana)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/juanleongalan/shopiscan",
    package_dir={"": "src"},
    packages=find_packages(where="src", exclude=["tests", "tests.*"]),
    python_requires=">=3.9",
    install_requires=[
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.0",
        "colorama>=0.4.6",
        "python-dotenv>=1.0.0",
    ],
    extras_require={
        # IA local con Ollama (--ai)
        "ai": ["ollama>=0.3.0", "pydantic>=2.0.0"],
        # Búsqueda vectorial con PostgreSQL + pgvector (DATABASE_URL)
        "vector": ["psycopg[binary]>=3.1.0", "pgvector>=0.2.5"],
        # Modo servidor HTTP (FastAPI + endpoint /metrics de Prometheus)
        "server": [
            "fastapi>=0.110.0",
            "uvicorn>=0.29.0",
            "pydantic>=2.0.0",
            "prometheus-client>=0.20.0",
            "python-multipart>=0.0.9",
        ],
        # Todo lo opcional junto
        "full": [
            "ollama>=0.3.0",
            "pydantic>=2.0.0",
            "psycopg[binary]>=3.1.0",
            "pgvector>=0.2.5",
            "fastapi>=0.110.0",
            "uvicorn>=0.29.0",
            "prometheus-client>=0.20.0",
            "python-multipart>=0.0.9",
        ],
        "dev": ["pytest>=8.0.0", "pyyaml>=6.0"],
    },
    entry_points={
        "console_scripts": [
            "shopiscan=shopiscan:main",
            "shopiscan-server=shopiscan.server:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Intended Audience :: Developers",
    ],
)
