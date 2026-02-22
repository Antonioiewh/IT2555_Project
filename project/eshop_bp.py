"""
E-Shop Blueprint Integration
Proxy to the eshop microservice running in a separate container
"""

from flask import Blueprint

# Create blueprint (nginx handles actual routing to eshop container)
eshop_bp = Blueprint(
    'eshop', 
    __name__,
    url_prefix='/eshop'
)

# Mark as available since we're using nginx proxy
ESHOP_AVAILABLE = True

# Note: All routes are handled by nginx proxy to eshop container
# The eshop link in UserBase.html will redirect to /eshop which nginx proxies to eshop:5000
