# besta/wsgi.py
import os
import logging
from django.core.wsgi import get_wsgi_application
from django.conf import settings

# Configure logging to stdout
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("startup")

# Initialize OpenTelemetry
# ----------------------------

def log_settings():
    # Environment variable
    logger.info("✅ DJANGO_SETTINGS_MODULE: %s", os.environ.get("DJANGO_SETTINGS_MODULE"))

    # Critical Django settings
    for setting_name in [
        "ROOT_URLCONF",
        "INSTALLED_APPS",
        "DEBUG",
        "ALLOWED_HOSTS",
        "DATABASES",
        "STATIC_URL",
    ]:
        value = getattr(settings, setting_name, "NOT SET")
        # For DATABASES, only log engine and name to avoid credentials
        if setting_name == "DATABASES" and isinstance(value, dict):
            db_info = {
                alias: {"ENGINE": cfg.get("ENGINE"), "NAME": cfg.get("NAME")}
                for alias, cfg in value.items()
            }
            logger.info("✅ %s: %s", setting_name, db_info)
        else:
            logger.info("✅ %s: %s", setting_name, value)

log_settings()

application = get_wsgi_application()