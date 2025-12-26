"""Parser for httpx output."""
from typing import Optional
from sqlalchemy.orm import Session
import uuid
import logging

from ..models import ToolExecution, ScanTarget, Port
from ..models.httpx_result import HttpxResult
from ..tools.httpx import parse_httpx_output

logger = logging.getLogger(__name__)


def create_httpx_result_from_output(
    db: Session,
    tool_execution: ToolExecution,
    target: ScanTarget,
    port_rec: Port
) -> Optional[HttpxResult]:
    """
    Parse httpx output and create HttpxResult record.

    Args:
        db: Database session
        tool_execution: The ToolExecution record for this httpx run
        target: The ScanTarget being scanned
        port_rec: The Port record being probed

    Returns:
        Created/updated HttpxResult or None if parsing fails
    """
    if not tool_execution.raw_output:
        return None

    try:
        parsed = parse_httpx_output(tool_execution.raw_output)
        if not parsed:
            return None

        # Store parsed output for debugging
        tool_execution.parsed_output = str(parsed)

        # Check if result already exists (prevent duplicates, update if exists)
        existing = db.query(HttpxResult).filter(
            HttpxResult.port_id == str(port_rec.id)
        ).first()

        if existing:
            # Update existing record
            existing.status_code = parsed.get('status_code')
            existing.content_length = parsed.get('content_length')
            existing.content_type = parsed.get('content_type')
            existing.title = parsed.get('title')
            existing.webserver = parsed.get('webserver')
            existing.method = parsed.get('method')
            existing.technologies = parsed.get('technologies')
            existing.cdn = parsed.get('cdn')
            existing.waf = parsed.get('waf')
            existing.final_url = parsed.get('final_url')
            existing.redirect_chain = parsed.get('redirect_chain')
            existing.response_time_ms = parsed.get('response_time_ms')
            existing.body_hash = parsed.get('body_hash')
            existing.tls_version = parsed.get('tls_version')
            existing.tls_cipher = parsed.get('tls_cipher')
            existing.jarm_hash = parsed.get('jarm_hash')
            existing.connection_failed = parsed.get('failed', False)
            existing.tool_execution_id = str(tool_execution.id)
            db.flush()
            logger.info(f"Updated HttpxResult for port {port_rec.port}")
            return existing

        # Create new record
        result = HttpxResult(
            id=str(uuid.uuid4()),
            port_id=str(port_rec.id),
            tool_execution_id=str(tool_execution.id),
            status_code=parsed.get('status_code'),
            content_length=parsed.get('content_length'),
            content_type=parsed.get('content_type'),
            title=parsed.get('title'),
            webserver=parsed.get('webserver'),
            method=parsed.get('method'),
            technologies=parsed.get('technologies'),
            cdn=parsed.get('cdn'),
            waf=parsed.get('waf'),
            final_url=parsed.get('final_url'),
            redirect_chain=parsed.get('redirect_chain'),
            response_time_ms=parsed.get('response_time_ms'),
            body_hash=parsed.get('body_hash'),
            tls_version=parsed.get('tls_version'),
            tls_cipher=parsed.get('tls_cipher'),
            jarm_hash=parsed.get('jarm_hash'),
            connection_failed=parsed.get('failed', False),
        )

        db.add(result)
        db.flush()
        logger.info(f"Created HttpxResult for port {port_rec.port}: status={result.status_code}, techs={result.technologies}")
        return result

    except Exception as e:
        logger.error(f"Failed to parse httpx output: {e}")
        tool_execution.error_message = f"Failed to parse httpx output: {str(e)}"
        db.flush()
        return None
