from sqlalchemy import Column, String, Boolean, DateTime
from datetime import datetime
import uuid
from ..database import Base
from ..core.timeutil import utcnow

class Organization(Base):
    """
    Placeholder for future team/organization functionality.
    Table exists but unused in Phase 1-4.

    Future use cases:
    - Multi-user teams sharing scans and configs
    - Organization-level billing and quotas
    - Role-based permissions within orgs
    """
    __tablename__ = "organizations"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, unique=True, nullable=False, index=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
