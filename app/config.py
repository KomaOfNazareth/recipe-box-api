import os
class Config:
    JWT_SECRET = os.getenv("JWT_SECRET")  # Read the secret from the process environment; None if unset.
    DATABASE = os.getenv("DATABASE")
    DEBUG = os.getenv("DEBUG", "").lower() == "true"
    PBKDF2_ITERATIONS = int(os.getenv("PBKDF2_ITERATIONS", 200_000))  # Default to 200,000 if not set.
    
    if not JWT_SECRET or not DATABASE:
        raise ValueError("JWT_SECRET and DATABASE environment variables are missing.")

class DevelopmentConfig(Config):
    pass

class TestingConfig(Config):
    DEBUG = False

class ProductionConfig(Config):
    DEBUG = False