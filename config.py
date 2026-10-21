"""
Application configuration for the Automated Web Security Scanner.
No database configuration is used. All results are stored in memory only.
"""

import os
import secrets

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


class Config:
    # Flask
    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
    DEBUG = False
    TESTING = False

    # WTForms CSRF
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour

    # In-memory scan storage
    MAX_STORED_SCANS = 20          # Maximum number of scans kept in memory
    SCAN_RESULT_TTL = 3600         # Soft TTL hint (seconds) – enforced on add

    # HTTP client safety limits
    REQUEST_TIMEOUT_CONNECT = 5    # seconds
    REQUEST_TIMEOUT_READ = 10      # seconds
    MAX_RESPONSE_SIZE = 1_048_576  # 1 MB – headers only, body not stored
    MAX_REDIRECTS = 5
    MAX_REQUESTS_PER_SCAN = 10
    MAX_SCAN_DURATION = 30         # seconds

    # Scanner behaviour
    VERIFY_TLS = True
    ALLOWED_SCHEMES = {"http", "https"}

    # Report filenames
    JSON_REPORT_PREFIX = "scan_report_"
    PDF_REPORT_PREFIX = "scan_report_"


class DevelopmentConfig(Config):
    DEBUG = True


class TestingConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False       # Disable CSRF in tests so POST routes work
    SECRET_KEY = "test-secret-key-not-for-production"


class ProductionConfig(Config):
    DEBUG = False


# Config selector
config_map = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}


def get_config(name: str | None = None) -> Config:
    env = name or os.environ.get("FLASK_ENV", "default")
    return config_map.get(env, DevelopmentConfig)()
