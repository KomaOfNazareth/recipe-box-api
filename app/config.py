class Config:
    DATABASE = "recipes.db"

class DevelopmentConfig(Config):
    DEBUG = True

class TestingConfig(Config):
    DEBUG = False

class ProductionConfig(Config):
    DEBUG = False