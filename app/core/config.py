import os
from pydantic_settings import BaseSettings
from functools import lru_cache
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    # Supabase Configuration
    SUPABASE_URL: str
    SUPABASE_KEY: str
    
    # AI Configuration
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY")
    
    CHATGPT_API_KEY: str = os.getenv("CHATGPT_API_KEY")

    
    # Application Settings
    UPLOAD_DIR: str = "uploads"
    ALLOWED_EXTENSIONS: set = {".zip", ".py", ".js", ".ts", ".java", ".cpp", ".c", ".cs", ".php", ".rb", ".go", ".rs"}
    
    class Config:
        env_file = ".env"

@lru_cache()
def get_settings():
    return Settings() 