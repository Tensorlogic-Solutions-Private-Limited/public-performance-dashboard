# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

import logging
import os

from celery.schedules import crontab
from flask_caching.backends.filesystemcache import FileSystemCache

from flask import redirect, g, session
import json
import urllib.request
import jwt
from superset.security import SupersetSecurityManager
# TEMPORARILY DISABLE OAUTH - CHANGE THIS BACK WHEN KEYCLOAK IS READY
# from flask_appbuilder.security.manager import AUTH_OAUTH
from flask_appbuilder.security.manager import AUTH_DB

logger = logging.getLogger()

DATABASE_DIALECT = os.getenv("DATABASE_DIALECT")
DATABASE_USER = os.getenv("DATABASE_USER")
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")
DATABASE_HOST = os.getenv("DATABASE_HOST")
DATABASE_PORT = os.getenv("DATABASE_PORT")
DATABASE_DB = os.getenv("DATABASE_DB")

EXAMPLES_USER = os.getenv("EXAMPLES_USER")
EXAMPLES_PASSWORD = os.getenv("EXAMPLES_PASSWORD")
EXAMPLES_HOST = os.getenv("EXAMPLES_HOST")
EXAMPLES_PORT = os.getenv("EXAMPLES_PORT")
EXAMPLES_DB = os.getenv("EXAMPLES_DB")

# AWS Athena configurations
AWS_DEFAULT_REGION = 'ap-south-1'
AWS_ACCESS_KEY_ID = 'xxxxxx'
AWS_SECRET_ACCESS_KEY = 'xxxxxxxxx''

# The SQLAlchemy connection string.
SQLALCHEMY_DATABASE_URI = (
    f"{DATABASE_DIALECT}://"
    f"{DATABASE_USER}:{DATABASE_PASSWORD}@"
    f"{DATABASE_HOST}:{DATABASE_PORT}/{DATABASE_DB}"
)

SQLALCHEMY_EXAMPLES_URI = (
    f"{DATABASE_DIALECT}://"
    f"{EXAMPLES_USER}:{EXAMPLES_PASSWORD}@"
    f"{EXAMPLES_HOST}:{EXAMPLES_PORT}/{EXAMPLES_DB}"
)

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = os.getenv("REDIS_PORT", "6379")
REDIS_CELERY_DB = os.getenv("REDIS_CELERY_DB", "0")
REDIS_RESULTS_DB = os.getenv("REDIS_RESULTS_DB", "1")

RESULTS_BACKEND = FileSystemCache("/app/superset_home/sqllab")

CACHE_CONFIG = {
    "CACHE_TYPE": "RedisCache",
    "CACHE_DEFAULT_TIMEOUT": 3000,
    "CACHE_KEY_PREFIX": "superset_",
    "CACHE_REDIS_HOST": REDIS_HOST,
    "CACHE_REDIS_PORT": REDIS_PORT,
    "CACHE_REDIS_DB": REDIS_RESULTS_DB,
}
DATA_CACHE_CONFIG = CACHE_CONFIG

class CeleryConfig:
    broker_url = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_CELERY_DB}"
    imports = (
        "superset.sql_lab",
        "superset.tasks.scheduler",
        "superset.tasks.thumbnails",
        "superset.tasks.cache",
    )
    result_backend = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_RESULTS_DB}"
    worker_prefetch_multiplier = 1
    task_acks_late = False
    beat_schedule = {
        "reports.scheduler": {
            "task": "reports.scheduler",
            "schedule": crontab(minute="*", hour="*"),
        },
        "reports.prune_log": {
            "task": "reports.prune_log",
            "schedule": crontab(minute=10, hour=0),
        },
    }

CELERY_CONFIG = CeleryConfig

FEATURE_FLAGS = {
    "ALERT_REPORTS": True,
    "DRILL_TO_DETAIL": True,
    "DASHBOARD_NATIVE_FILTERS": True,
    "DRILL_BY": True,
    "ENABLE_ECHARTS_PLUGIN": True,
    "ENABLE_TEMPLATE_PROCESSING": True,
    "DASHBOARD_CROSS_FILTERS": True,
    "DASHBOARD_DRILL_DOWN": True,
    "ENABLE_FILTER_BOX_CROSS_DASHBOARD": True,
    "DASHBOARD_NATIVE_FILTERS_SET": True,
}

ALERT_REPORTS_NOTIFICATION_DRY_RUN = True
WEBDRIVER_BASEURL = "http://superset:8088/"
WEBDRIVER_BASEURL_USER_FRIENDLY = WEBDRIVER_BASEURL
SQLLAB_CTAS_NO_LIMIT = True
ENABLE_JAVASCRIPT_CONTROLS = True
ENABLE_DASHBOARD_URL_PARAMS = True
SQLLAB_TIMEOUT = 3000

# Enable Row Level Security
ENABLE_ROW_LEVEL_SECURITY = True

try:
    import superset_config_docker
    from superset_config_docker import *

    logger.info(
        f"Loaded your Docker configuration at " f"[{superset_config_docker.__file__}]"
    )
except ImportError:
    logger.info("Using default Docker config...")

# TEMPORARILY DISABLE KEYCLOAK AUTHENTICATION
# --- Authentication Type --- CHANGE THIS BACK TO AUTH_OAUTH WHEN KEYCLOAK IS READY
AUTH_TYPE = AUTH_DB

# COMMENTED OUT KEYCLOAK CONFIGURATION - UNCOMMENT WHEN KEYCLOAK IS READY
"""
# --- OAuth Provider Configuration ---
OAUTH_PROVIDERS = [{
    'name': 'keycloak',
    'icon': 'fa-address-card',
    'token_key': 'access_token',
    'remote_app': {
        'client_id': 'emis-apache-superset',
        'client_secret': 'YOUR_CLIENT_SECRET',
        'api_base_url': 'https://oauth2.reaplearn.in/realms/emis/protocol/openid-connect',
        'access_token_url': 'https://oauth2.reaplearn.in/realms/emis/protocol/openid-connect/token',
        'authorize_url': 'https://oauth2.reaplearn.in/realms/emis/protocol/openid-connect/auth',
        'jwks_uri': 'https://oauth2.reaplearn.in/realms/emis/protocol/openid-connect/certs',
        'client_kwargs': {
            'scope': 'openid email profile',
        },
    }
}]

# --- JWT Settings ---
JWT_ALGORITHM = "RS256"

public_key_url = "https://oauth2.reaplearn.in/realms/emis/protocol/openid-connect/certs"

def fetch_keycloak_rs256_public_cert():
    with urllib.request.urlopen(public_key_url) as response:
        jwks = json.load(response)
        key_data = jwks["keys"][0]
        public_key = key_data.get("x5c", [])[0]

    if public_key:
        pem_lines = [
            "-----BEGIN CERTIFICATE-----",
            public_key,
            "-----END CERTIFICATE-----",
        ]
        cert_pem = "\n".join(pem_lines)
    else:
        cert_pem = "No cert found"
    return cert_pem

JWT_PUBLIC_KEY = fetch_keycloak_rs256_public_cert()
"""

# TEMPORARY JWT CONFIGURATION (FOR TESTING ONLY)
JWT_ALGORITHM = "HS256"  # Using simpler algorithm for now
JWT_PUBLIC_KEY = "temporary-secret-key-for-testing"  # Replace this when Keycloak is ready

# COMMENTED OUT KEYCLOAK ROLE MAPPING - UNCOMMENT WHEN KEYCLOAK IS READY
"""
# --- Role Mapping from Keycloak Roles to Superset Roles ---
AUTH_ROLES_MAPPING = {
    "KeycloakAdmin": ["Admin", "sql_lab"],
    "KeycloakPublic": ["Public"],
    "KeycloakAlpha": ["Alpha"],
    "KeycloakGamma": ["Gamma"],
    "KeycloakDistrict": ["District"],
    "KeycloakBlock": ["Block"],
}

AUTH_ROLES_SYNC_AT_LOGIN = True
AUTH_USER_REGISTRATION = True
AUTH_USER_REGISTRATION_ROLE = "Public"
"""

# TEMPORARY DATABASE AUTHENTICATION SETTINGS
AUTH_USER_REGISTRATION = True
AUTH_USER_REGISTRATION_ROLE = "Gamma"  # Default role for new users
AUTH_ROLES_SYNC_AT_LOGIN = False

# COMMENTED OUT CUSTOM SECURITY MANAGER - UNCOMMENT WHEN KEYCLOAK IS READY
"""
# --- Enhanced Custom Security Manager with Dynamic RLS ---
class CustomSsoSecurityManager(SupersetSecurityManager):
    
    def oauth_user_info(self, provider, response=None):
        # [Previous implementation]
        pass

    def extract_user_attributes(self, decoded_token):
        # [Previous implementation]
        pass

    def load_user_jwt(self, _jwt_header, jwt_data):
        # [Previous implementation]
        pass

    def get_rls_filters(self, table):
        # [Previous implementation]
        pass

    def get_user_attributes_from_token(self):
        # [Previous implementation]
        pass

    def get_rls_clause(self, table_name, user_id):
        # [Previous implementation]
        pass

CUSTOM_SECURITY_MANAGER = CustomSsoSecurityManager
"""

# TEMPORARY: Use default security manager
# CUSTOM_SECURITY_MANAGER = None

# COMMENTED OUT RLS CONFIGURATION - UNCOMMENT WHEN KEYCLOAK IS READY
"""
# Optional: Custom RLS for SQL Lab
def RLS_BASE_FILTER(g, table):
    # [Previous implementation]
    pass

# Test endpoint to verify RLS configuration
from flask import Flask
app = Flask(__name__)

@app.route('/test-rls-config')
def test_rls_config():
    # [Previous implementation]
    pass

# Add the test route (REMOVE AFTER TESTING)
try:
    from superset import app as superset_app
    superset_app.add_url_rule('/test-rls-config', 'test_rls_config', test_rls_config)
except:
    pass  # Ignore if can't add route
"""
