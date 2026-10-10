"""Shared pytest configuration for the backend test suite."""
import os

# app.core.config rejects SECRET_KEY values shorter than 32 characters (and
# known placeholders) at import time. Test runs commonly export a short
# throwaway value such as SECRET_KEY=test-secret; swap in a test-only key of
# valid length here rather than weakening the production validator.
_TEST_SECRET_KEY = "peek-test-suite-secret-key-not-for-production-0123456789"

if len(os.environ.get("SECRET_KEY", "")) < 32:
    os.environ["SECRET_KEY"] = _TEST_SECRET_KEY

# Cheap bcrypt cost keeps the hashing tests fast; cost-specific tests set their own.
os.environ.setdefault("BCRYPT_ROUNDS", "4")
