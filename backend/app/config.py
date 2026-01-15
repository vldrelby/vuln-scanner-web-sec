"""
Configuration management for the scanner.
Loads settings from YAML config file and environment variables.
"""

import os
from pathlib import Path
from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import Field
import yaml


class ScannerConfig(BaseSettings):
    """Scanner configuration settings."""
    request_timeout: int = 30
    max_concurrent: int = 10
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


class NmapConfig(BaseSettings):
    """Nmap scanner configuration."""
    scan_type: str = "syn"
    ports: str = "80,443,8080,8443,3000,5000"
    arguments: str = "-sV -sC --script vuln"


class NucleiConfig(BaseSettings):
    """Nuclei scanner configuration."""
    binary_path: str = "nuclei"
    templates_path: str = "./nuclei-templates"
    severity: List[str] = ["low", "medium", "high", "critical"]
    rate_limit: int = 150


class CustomScannerConfig(BaseSettings):
    """Custom scanner configuration."""
    common_directories: List[str] = Field(default_factory=lambda: [
        "/admin", "/backup", "/config", "/database", "/logs",
        "/test", "/tmp", "/uploads", "/.git", "/.env"
    ])
    xss_payloads: List[str] = Field(default_factory=lambda: [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=javascript:alert('XSS')>",
        "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>"
    ])
    sensitive_files: List[str] = Field(default_factory=lambda: [
        "/.env", "/.env.local", "/.env.production", "/.git/config",
        "/.git/HEAD", "/.gitignore", "/.htaccess", "/web.config",
        "/backup.sql", "/database.sql", "/dump.sql", "/config.php",
        "/config.json", "/.DS_Store", "/composer.json", "/package.json"
    ])
    sqli_payloads: List[str] = Field(default_factory=lambda: [
        "' OR '1'='1", "' OR '1'='1' --", "' UNION SELECT NULL--",
        "1' AND '1'='1", "admin'--", "' OR 1=1#"
    ])
    security_headers: List[str] = Field(default_factory=lambda: [
        "X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection",
        "Strict-Transport-Security", "Content-Security-Policy",
        "Referrer-Policy", "Permissions-Policy"
    ])


class DatabaseConfig(BaseSettings):
    """Database configuration."""
    path: str = "./scanner.db"


class LoggingConfig(BaseSettings):
    """Logging configuration."""
    level: str = "INFO"
    file: str = "./scanner.log"
    rotation: str = "10 MB"
    retention: str = "7 days"


class Settings(BaseSettings):
    """Main application settings."""
    api_host: str = Field(default="0.0.0.0", env="API_HOST")
    api_port: int = Field(default=8000, env="API_PORT")
    api_reload: bool = Field(default=True, env="API_RELOAD")
    
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    nmap: NmapConfig = Field(default_factory=NmapConfig)
    nuclei: NucleiConfig = Field(default_factory=NucleiConfig)
    custom_scanner: CustomScannerConfig = Field(default_factory=CustomScannerConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


def load_config(config_path: Optional[str] = None) -> Settings:
    """
    Load configuration from YAML file and environment variables.
    
    Args:
        config_path: Path to YAML config file. Defaults to config.yaml in project root.
    
    Returns:
        Settings object with loaded configuration.
    """
    if config_path is None:
        config_path = Path(__file__).parent.parent / "config.yaml"
    else:
        config_path = Path(config_path)
    
    settings = Settings()
    
    # Load YAML config if it exists
    if config_path.exists():
        with open(config_path, "r") as f:
            yaml_config = yaml.safe_load(f)
        
        # Update settings from YAML
        if yaml_config:
            if "scanner" in yaml_config:
                settings.scanner = ScannerConfig(**yaml_config["scanner"])
            if "nmap" in yaml_config:
                settings.nmap = NmapConfig(**yaml_config["nmap"])
            if "nuclei" in yaml_config:
                settings.nuclei = NucleiConfig(**yaml_config["nuclei"])
            if "custom_scanner" in yaml_config:
                settings.custom_scanner = CustomScannerConfig(**yaml_config["custom_scanner"])
            if "database" in yaml_config:
                settings.database = DatabaseConfig(**yaml_config["database"])
            if "logging" in yaml_config:
                settings.logging = LoggingConfig(**yaml_config["logging"])
    
    return settings


# Global settings instance
settings = load_config()

