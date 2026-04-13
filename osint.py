"""Entry-point shim — allows running `python osint.py <command>`."""
from src.main import app

if __name__ == "__main__":
    app()
