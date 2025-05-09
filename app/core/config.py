from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    # Supabase Configuration
    SUPABASE_URL: str
    SUPABASE_KEY: str
    
    # Application Settings
    UPLOAD_DIR: str = "uploads"
    ALLOWED_EXTENSIONS: set = {".zip", ".py", ".js", ".ts", ".java", ".cpp", ".c", ".cs", ".php", ".rb", ".go", ".rs"}
    
    class Config:
        env_file = ".env"

@lru_cache()
def get_settings():
    return Settings() 