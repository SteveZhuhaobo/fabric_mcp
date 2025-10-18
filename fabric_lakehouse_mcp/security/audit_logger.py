"""Audit logging for all data access operations."""

import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path

from ..errors import get_logger, ErrorContext
from ..config.settings import ServerConfig

logger = get_logger(__name__)


class AuditEventType(Enum):
    """Types of audit events."""
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    SCHEMA_ACCESS = "schema_access"
    SCHEMA_MODIFICATION = "schema_modification"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CONFIGURATION = "configuration"
    ERROR = "error"
    SECURITY_VIOLATION = "security_violation"


class AuditEventStatus(Enum):
    """Status of audit events."""
    SUCCESS = "success"
    FAILURE = "failure"
    WARNING = "warning"
    BLOCKED = "blocked"


@dataclass
class AuditEvent:
    """Represents an audit event."""
    event_id: str
    timestamp: datetime
    event_type: AuditEventType
    status: AuditEventStatus
    operation: str
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    resource: Optional[str] = None
    query: Optional[str] = None
    query_hash: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None
    result_count: Optional[int] = None
    execution_time_ms: Optional[int] = None
    error_message: Optional[str] = None
    error_code: Optional[str] = None
    security_context: Optional[Dict[str, Any]] = None
    compliance_tags: Optional[List[str]] = None
    additional_data: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert audit event to dictionary."""
        data = asdict(self)
        
        # Convert datetime to ISO format
        data['timestamp'] = self.timestamp.isoformat()
        
        # Convert enums to string values
        data['event_type'] = self.event_type.value
        data['status'] = self.status.value
        
        # Remove None values to keep logs clean
        return {k: v for k, v in data.items() if v is not None}
    
    def to_json(self) -> str:
        """Convert audit event to JSON string."""
        return json.dumps(self.to_dict(), default=str)


class AuditLogger:
    """Handles audit logging for all data access operations."""
    
    def __init__(self, config: Optional[ServerConfig] = None, audit_file: Optional[str] = None):
        self.config = config
        self.audit_file = audit_file or self._get_default_audit_file()
        self._ensure_audit_directory()
        
        # Initialize audit log file
        self._initialize_audit_log()
        
        logger.info(
            "Audit logger initialized",
            extra={
                "audit_file": self.audit_file,
                "audit_enabled": True
            }
        )
    
    def log_data_access(
        self,
        operation: str,
        resource: Optional[str] = None,
        query: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        result_count: Optional[int] = None,
        execution_time_ms: Optional[int] = None,
        status: AuditEventStatus = AuditEventStatus.SUCCESS,
        additional_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """Log data access operation."""
        event = self._create_audit_event(
            event_type=AuditEventType.DATA_ACCESS,
            operation=operation,
            resource=resource,
            query=query,
            user_id=user_id,
            session_id=session_id,
            result_count=result_count,
            execution_time_ms=execution_time_ms,
            status=status,
            additional_data=additional_data
        )
        
        return self._write_audit_event(event)
    
    def log_data_modification(
        self,
        operation: str,
        resource: Optional[str] = None,
        query: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        affected_rows: Optional[int] = None,
        execution_time_ms: Optional[int] = None,
        status: AuditEventStatus = AuditEventStatus.SUCCESS,
        additional_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """Log data modification operation."""
        if additional_data is None:
            additional_data = {}
        if affected_rows is not None:
            additional_data['affected_rows'] = affected_rows
        
        event = self._create_audit_event(
            event_type=AuditEventType.DATA_MODIFICATION,
            operation=operation,
            resource=resource,
            query=query,
            user_id=user_id,
            session_id=session_id,
            execution_time_ms=execution_time_ms,
            status=status,
            additional_data=additional_data,
            compliance_tags=['data_modification', 'write_operation']
        )
        
        return self._write_audit_event(event)
    
    def log_schema_access(
        self,
        operation: str,
        resource: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        status: AuditEventStatus = AuditEventStatus.SUCCESS,
        additional_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """Log schema access operation."""
        event = self._create_audit_event(
            event_type=AuditEventType.SCHEMA_ACCESS,
            operation=operation,
            resource=resource,
            user_id=user_id,
            session_id=session_id,
            status=status,
            additional_data=additional_data,
            compliance_tags=['schema_access', 'metadata']
        )
        
        return self._write_audit_event(event)
    
    def log_schema_modification(
        self,
        operation: str,
        resource: Optional[str] = None,
        query: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        execution_time_ms: Optional[int] = None,
        status: AuditEventStatus = AuditEventStatus.SUCCESS,
        additional_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """Log schema modification operation."""
        event = self._create_audit_event(
            event_type=AuditEventType.SCHEMA_MODIFICATION,
            operation=operation,
            resource=resource,
            query=query,
            user_id=user_id,
            session_id=session_id,
            execution_time_ms=execution_time_ms,
            status=status,
            additional_data=additional_data,
            compliance_tags=['schema_modification', 'ddl_operation']
        )
        
        return self._write_audit_event(event)
    
    def log_authentication(
        self,
        operation: str,
        user_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        status: AuditEventStatus = AuditEventStatus.SUCCESS,
        error_message: Optional[str] = None,
        additional_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """Log authentication operation."""
        event = self._create_audit_event(
            event_type=AuditEventType.AUTHENTICATION,
            operation=operation,
            user_id=user_id,
            client_ip=client_ip,
            user_agent=user_agent,
            status=status,
            error_message=error_message,
            additional_data=additional_data,
            compliance_tags=['authentication', 'security']
        )
        
        return self._write_audit_event(event)
    
    def log_authorization(
        self,
        operation: str,
        resource: Optional[str] = None,
        user_id: Optional[str] = None,
        status: AuditEventStatus = AuditEventStatus.SUCCESS,
        error_message: Optional[str] = None,
        additional_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """Log authorization operation."""
        event = self._create_audit_event(
            event_type=AuditEventType.AUTHORIZATION,
            operation=operation,
            resource=resource,
            user_id=user_id,
            status=status,
            error_message=error_message,
            additional_data=additional_data,
            compliance_tags=['authorization', 'access_control']
        )
        
        return self._write_audit_event(event)
    
    def log_security_violation(
        self,
        operation: str,
        violation_type: str,
        resource: Optional[str] = None,
        query: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        error_message: Optional[str] = None,
        additional_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """Log security violation."""
        if additional_data is None:
            additional_data = {}
        additional_data['violation_type'] = violation_type
        
        event = self._create_audit_event(
            event_type=AuditEventType.SECURITY_VIOLATION,
            operation=operation,
            resource=resource,
            query=query,
            user_id=user_id,
            session_id=session_id,
            client_ip=client_ip,
            status=AuditEventStatus.BLOCKED,
            error_message=error_message,
            additional_data=additional_data,
            compliance_tags=['security_violation', 'blocked_operation', 'high_priority']
        )
        
        return self._write_audit_event(event)
    
    def log_error(
        self,
        operation: str,
        error_message: str,
        error_code: Optional[str] = None,
        resource: Optional[str] = None,
        query: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        additional_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """Log error event."""
        event = self._create_audit_event(
            event_type=AuditEventType.ERROR,
            operation=operation,
            resource=resource,
            query=query,
            user_id=user_id,
            session_id=session_id,
            status=AuditEventStatus.FAILURE,
            error_message=error_message,
            error_code=error_code,
            additional_data=additional_data,
            compliance_tags=['error', 'failure']
        )
        
        return self._write_audit_event(event)
    
    def _create_audit_event(
        self,
        event_type: AuditEventType,
        operation: str,
        status: AuditEventStatus = AuditEventStatus.SUCCESS,
        resource: Optional[str] = None,
        query: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        result_count: Optional[int] = None,
        execution_time_ms: Optional[int] = None,
        error_message: Optional[str] = None,
        error_code: Optional[str] = None,
        additional_data: Optional[Dict[str, Any]] = None,
        compliance_tags: Optional[List[str]] = None
    ) -> AuditEvent:
        """Create audit event with common fields."""
        event_id = self._generate_event_id()
        timestamp = datetime.now(timezone.utc)
        
        # Hash query for privacy if it's long
        query_hash = None
        if query and len(query) > 1000:
            import hashlib
            query_hash = hashlib.sha256(query.encode()).hexdigest()[:16]
            query = query[:500] + "... [truncated]"
        
        # Add security context
        security_context = self._get_security_context()
        
        return AuditEvent(
            event_id=event_id,
            timestamp=timestamp,
            event_type=event_type,
            status=status,
            operation=operation,
            user_id=user_id,
            session_id=session_id,
            client_ip=client_ip,
            user_agent=user_agent,
            resource=resource,
            query=query,
            query_hash=query_hash,
            result_count=result_count,
            execution_time_ms=execution_time_ms,
            error_message=error_message,
            error_code=error_code,
            security_context=security_context,
            compliance_tags=compliance_tags,
            additional_data=additional_data
        )
    
    def _write_audit_event(self, event: AuditEvent) -> str:
        """Write audit event to log file."""
        try:
            # Write to structured audit log file
            with open(self.audit_file, 'a', encoding='utf-8') as f:
                f.write(event.to_json() + '\n')
            
            # Also log to standard logger for immediate visibility
            logger.info(
                f"AUDIT: {event.event_type.value} - {event.operation}",
                extra={
                    "audit_event_id": event.event_id,
                    "audit_event_type": event.event_type.value,
                    "audit_status": event.status.value,
                    "audit_operation": event.operation,
                    "audit_resource": event.resource,
                    "audit_user_id": event.user_id,
                    "audit_execution_time_ms": event.execution_time_ms,
                    "audit_result_count": event.result_count
                }
            )
            
            return event.event_id
            
        except Exception as e:
            # If audit logging fails, log the error but don't fail the operation
            logger.error(
                f"Failed to write audit event: {e}",
                extra={
                    "audit_event_id": event.event_id,
                    "audit_error": str(e)
                }
            )
            return event.event_id
    
    def _generate_event_id(self) -> str:
        """Generate unique event ID."""
        import uuid
        return f"audit_{int(time.time())}_{uuid.uuid4().hex[:8]}"
    
    def _get_security_context(self) -> Dict[str, Any]:
        """Get current security context."""
        return {
            "server_version": "1.0.0",  # Could be from config
            "audit_version": "1.0",
            "environment": "production" if self.config else "development"
        }
    
    def _get_default_audit_file(self) -> str:
        """Get default audit log file path."""
        audit_dir = Path("logs")
        audit_dir.mkdir(exist_ok=True)
        
        # Use date-based file naming for log rotation
        date_str = datetime.now().strftime("%Y%m%d")
        return str(audit_dir / f"fabric_mcp_audit_{date_str}.jsonl")
    
    def _ensure_audit_directory(self) -> None:
        """Ensure audit log directory exists."""
        audit_path = Path(self.audit_file)
        audit_path.parent.mkdir(parents=True, exist_ok=True)
    
    def _initialize_audit_log(self) -> None:
        """Initialize audit log file with header information."""
        try:
            # Check if file exists and is not empty
            audit_path = Path(self.audit_file)
            if audit_path.exists() and audit_path.stat().st_size > 0:
                return  # File already initialized
            
            # Write initialization event
            init_event = self._create_audit_event(
                event_type=AuditEventType.CONFIGURATION,
                operation="audit_log_initialized",
                status=AuditEventStatus.SUCCESS,
                additional_data={
                    "audit_file": self.audit_file,
                    "server_start_time": datetime.now(timezone.utc).isoformat()
                },
                compliance_tags=['initialization', 'audit_start']
            )
            
            self._write_audit_event(init_event)
            
        except Exception as e:
            logger.error(f"Failed to initialize audit log: {e}")


# Global audit logger instance
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger(config: Optional[ServerConfig] = None) -> AuditLogger:
    """Get global audit logger instance."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger(config)
    return _audit_logger


def initialize_audit_logger(config: Optional[ServerConfig] = None, audit_file: Optional[str] = None) -> AuditLogger:
    """Initialize global audit logger."""
    global _audit_logger
    _audit_logger = AuditLogger(config, audit_file)
    return _audit_logger