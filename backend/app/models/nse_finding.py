from sqlalchemy import Column, String, ForeignKey, JSON, Text
from sqlalchemy.orm import relationship
from ..database import Base


class NseFinding(Base):
    """
    Stores NSE (Nmap Scripting Engine) script results.

    NSE scripts provide detailed information about services beyond basic
    service detection. Each NseFinding represents the output of one NSE
    script run against one port.

    Example XML structure parsed:
    <script id="rdp-enum-encryption" output="...">
        <elem key="key1">value1</elem>
        <elem key="key2">value2</elem>
    </script>
    """
    __tablename__ = "nse_findings"

    id = Column(String(36), primary_key=True)
    port_id = Column(String(36), ForeignKey("ports.id", ondelete="CASCADE"), nullable=False, index=True)
    tool_execution_id = Column(String(36), ForeignKey("tool_executions.id", ondelete="CASCADE"), nullable=True)

    # Script identification
    script_id = Column(String(100), nullable=False, index=True)  # e.g., "rdp-enum-encryption", "ntp-monlist"
    profile_name = Column(String(50), nullable=True)  # e.g., "rdp", "ntp" - which NSE profile triggered this

    # Script output
    raw_output = Column(Text, nullable=True)  # The "output" attribute text
    elements = Column(JSON, nullable=True)    # Parsed <elem key="x">value</elem> as {"key": "value"}

    # Severity (derived from script output or profile config)
    severity = Column(String(20), nullable=True)  # critical, high, medium, low, info

    # Connection status
    error = Column(String, nullable=True)  # If script failed

    # Relationships
    port = relationship("Port", backref="nse_findings")
    tool_execution = relationship("ToolExecution")
