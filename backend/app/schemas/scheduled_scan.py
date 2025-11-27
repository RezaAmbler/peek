from pydantic import BaseModel, Field, validator
from uuid import UUID
from datetime import datetime
from typing import Optional, List
from croniter import croniter

class TargetInput(BaseModel):
    ip_address: str
    device_name: Optional[str] = None

class ScheduledScanBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=1000)
    cron_expression: str
    timezone: str = "UTC"
    config_id: str
    targets: List[TargetInput] = Field(..., min_items=1)
    auto_compare: bool = True
    baseline_scan_id: Optional[str] = None
    compare_with_previous: bool = True
    email_on_completion: bool = False
    email_on_changes_only: bool = True
    email_recipients: Optional[List[str]] = None
    alert_on_critical: bool = True
    alert_on_new_vulns: bool = True
    is_active: bool = True

    @validator('cron_expression')
    def validate_cron(cls, v):
        try:
            croniter(v)
        except Exception as e:
            raise ValueError(f'Invalid cron expression: {str(e)}')
        return v

    @validator('email_recipients')
    def validate_emails(cls, v):
        if v:
            import re
            email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
            for email in v:
                if not re.match(email_regex, email):
                    raise ValueError(f'Invalid email address: {email}')
        return v

class ScheduledScanCreate(ScheduledScanBase):
    pass

class ScheduledScanUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = None
    cron_expression: Optional[str] = None
    timezone: Optional[str] = None
    config_id: Optional[str] = None
    targets: Optional[List[TargetInput]] = None
    auto_compare: Optional[bool] = None
    baseline_scan_id: Optional[str] = None
    compare_with_previous: Optional[bool] = None
    email_on_completion: Optional[bool] = None
    email_on_changes_only: Optional[bool] = None
    email_recipients: Optional[List[str]] = None
    alert_on_critical: Optional[bool] = None
    alert_on_new_vulns: Optional[bool] = None
    is_active: Optional[bool] = None

class ScheduledScanResponse(ScheduledScanBase):
    id: str
    user_id: str
    created_by_id: str
    organization_id: Optional[str]
    last_run_at: Optional[datetime]
    last_run_scan_id: Optional[str]
    next_run_at: Optional[datetime]
    total_runs: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class ScheduledScanListResponse(BaseModel):
    scheduled_scans: List[ScheduledScanResponse]
    total: int
