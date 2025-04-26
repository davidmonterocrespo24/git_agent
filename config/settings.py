import os

from dotenv import load_dotenv


class Settings:
    def __init__(self):
        load_dotenv()
        self.GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
        self.OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
        self.GITHUB_REPO_OWNER = os.getenv("GITHUB_REPO_OWNER")
        self.GITHUB_REPO_NAME = os.getenv("GITHUB_REPO_NAME")
        self.MODEL_NAME = os.getenv("MODEL_NAME", "gpt-4o")


settings = Settings()
