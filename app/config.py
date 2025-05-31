import os
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    """Application settings."""
    
    # API Keys
    chatgpt_api_key: str = os.getenv("CHATGPT_API_KEY")
    
    # OpenAI Configuration
    openai_model: str = os.getenv("CHATGPT_MODEL", "gpt-3.5-turbo")  # Default to GPT-3.5 Turbo
    openai_temperature: float = 0.1
    
    # Security Scan Configuration
    max_file_size: int = 80_000  # Maximum file size for analysis in bytes
    code_file_extensions: set[str] = {
        ".py", ".js", ".ts", ".java", ".cpp", ".c", ".cs",
        ".php", ".rb", ".go", ".rs", ".html", ".css", ".jsx",
        ".tsx", ".vue", ".swift", ".kt", ".scala", ".sh",
        ".sql", ".dart", ".yaml", ".yml",
    }
    
    # Architecture Analysis Thresholds
    god_class_threshold: int = 500  # Lines of code
    long_method_threshold: int = 50  # Lines of code
    
    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "allow"  # Allow extra fields from environment variables

settings = Settings() 