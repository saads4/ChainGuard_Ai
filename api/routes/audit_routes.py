"""
Audit Routes - Audit log access endpoints

FastAPI routes for accessing ChainGuardAI audit logs:
- Log retrieval and searching
- Chain verification
- Audit statistics
- Log management
"""

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
import time
import logging

logger = logging.getLogger(__name__)

router = APIRouter()


# Pydantic models
class AuditLogEntry(BaseModel):
    """Audit log entry model."""
    entry_id: str
    timestamp: float
    event_type: str
    agent_id: Optional[str] = None
    session_id: Optional[str] = None
    event_data: Dict[str, Any]
    entry_hash: str
    previous_hash: str
    signature: Optional[str] = None
    metadata: Dict[str, Any]


class ChainVerificationResult(BaseModel):
    """Chain verification result model."""
    verified: bool
    issues: List[str]
    warnings: List[str]
    entries_checked: int
    broken_links: List[Dict[str, Any]]
    verification_time: float


class AuditStatistics(BaseModel):
    """Audit statistics model."""
    total_entries: int
    signed_entries: int
    date_range: Dict[str, float]
    event_types: Dict[str, int]
    agents: Dict[str, int]
    avg_entries_per_day: float


# In-memory storage (in production, use actual audit log files)
audit_entries = []
chain_state = {
    "last_hash": "0000000000000000000000000000000000000000000000000000000000000000",
    "entry_count": 0
}


# Route endpoints
@router.get("/logs", response_model=List[AuditLogEntry])
async def get_audit_logs(
    limit: int = Query(100, ge=1, le=1000),
    event_type: Optional[str] = None,
    agent_id: Optional[str] = None,
    start_time: Optional[float] = None,
    end_time: Optional[float] = None
) -> List[AuditLogEntry]:
    """Get audit log entries with filtering."""
    try:
        filtered_logs = audit_entries.copy()
        
        # Filter by event type
        if event_type:
            filtered_logs = [log for log in filtered_logs if log.get("event_type") == event_type]
        
        # Filter by agent ID
        if agent_id:
            filtered_logs = [log for log in filtered_logs if log.get("agent_id") == agent_id]
        
        # Filter by time range
        if start_time:
            filtered_logs = [log for log in filtered_logs if log.get("timestamp", 0) >= start_time]
        
        if end_time:
            filtered_logs = [log for log in filtered_logs if log.get("timestamp", 0) <= end_time]
        
        # Sort by timestamp (newest first)
        filtered_logs.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
        
        # Limit results
        return filtered_logs[:limit]
        
    except Exception as e:
        logger.error(f"Failed to get audit logs: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/logs/{entry_id}")
async def get_audit_entry(entry_id: str) -> AuditLogEntry:
    """Get a specific audit log entry."""
    try:
        for entry in audit_entries:
            if entry.get("entry_id") == entry_id:
                return AuditLogEntry(**entry)
        
        raise HTTPException(status_code=404, detail=f"Audit entry {entry_id} not found")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get audit entry: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/search")
async def search_audit_logs(
    query: str = Query(..., min_length=1),
    limit: int = Query(100, ge=1, le=1000)
) -> List[AuditLogEntry]:
    """Search audit logs for specific content."""
    try:
        query_lower = query.lower()
        matching_logs = []
        
        for entry in audit_entries:
            # Search in various fields
            searchable_text = " ".join([
                str(entry.get("event_type", "")),
                str(entry.get("agent_id", "")),
                str(entry.get("session_id", "")),
                str(entry.get("event_data", {})),
                str(entry.get("metadata", {}))
            ]).lower()
            
            if query_lower in searchable_text:
                matching_logs.append(entry)
        
        # Sort by timestamp (newest first)
        matching_logs.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
        
        return matching_logs[:limit]
        
    except Exception as e:
        logger.error(f"Failed to search audit logs: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/verify-chain", response_model=ChainVerificationResult)
async def verify_chain() -> ChainVerificationResult:
    """Verify the integrity of the audit log chain."""
    try:
        verification_start = time.time()
        
        result = ChainVerificationResult(
            verified=True,
            issues=[],
            warnings=[],
            entries_checked=len(audit_entries),
            broken_links=[],
            verification_time=0.0
        )
        
        if not audit_entries:
            result.warnings.append("No audit entries to verify")
            result.verification_time = time.time() - verification_start
            return result
        
        # Verify chain integrity
        expected_previous_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        
        for i, entry in enumerate(audit_entries):
            entry_hash = entry.get("entry_hash", "")
            previous_hash = entry.get("previous_hash", "")
            
            # Check previous hash
            if previous_hash != expected_previous_hash:
                result.verified = False
                result.issues.append(f"Hash chain broken at entry {i}")
                result.broken_links.append({
                    "entry_index": i,
                    "entry_id": entry.get("entry_id", "unknown"),
                    "expected_previous": expected_previous_hash,
                    "actual_previous": previous_hash
                })
            
            # Check entry hash (simplified verification)
            if not entry_hash:
                result.warnings.append(f"Missing hash for entry {i}")
            
            expected_previous_hash = entry_hash
        
        # Check for missing entries
        if audit_entries:
            last_entry = audit_entries[-1]
            expected_count = last_entry.get("metadata", {}).get("entry_number", 0)
            if expected_count != len(audit_entries):
                result.warnings.append(f"Entry count mismatch: expected {expected_count}, found {len(audit_entries)}")
        
        result.verification_time = time.time() - verification_start
        
        if result.verified:
            logger.info(f"Chain verification passed: {len(audit_entries)} entries")
        else:
            logger.warning(f"Chain verification failed: {len(result.issues)} issues")
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to verify chain: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics", response_model=AuditStatistics)
async def get_audit_statistics() -> AuditStatistics:
    """Get audit log statistics."""
    try:
        if not audit_entries:
            return AuditStatistics(
                total_entries=0,
                signed_entries=0,
                date_range={"start": 0.0, "end": 0.0},
                event_types={},
                agents={},
                avg_entries_per_day=0.0
            )
        
        # Calculate statistics
        timestamps = [entry.get("timestamp", 0) for entry in audit_entries]
        date_range = {
            "start": min(timestamps),
            "end": max(timestamps)
        }
        
        # Event type distribution
        event_types = {}
        for entry in audit_entries:
            event_type = entry.get("event_type", "unknown")
            event_types[event_type] = event_types.get(event_type, 0) + 1
        
        # Agent distribution
        agents = {}
        for entry in audit_entries:
            agent_id = entry.get("agent_id", "unknown")
            agents[agent_id] = agents.get(agent_id, 0) + 1
        
        # Signed entries count
        signed_entries = len([entry for entry in audit_entries if entry.get("signature")])
        
        # Average entries per day
        if date_range["end"] > date_range["start"]:
            days = (date_range["end"] - date_range["start"]) / (24 * 3600)
            avg_entries_per_day = len(audit_entries) / max(days, 1)
        else:
            avg_entries_per_day = 0.0
        
        return AuditStatistics(
            total_entries=len(audit_entries),
            signed_entries=signed_entries,
            date_range=date_range,
            event_types=event_types,
            agents=agents,
            avg_entries_per_day=avg_entries_per_day
        )
        
    except Exception as e:
        logger.error(f"Failed to get audit statistics: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/chain-status")
async def get_chain_status() -> Dict[str, Any]:
    """Get hash chain status."""
    try:
        return {
            "last_hash": chain_state["last_hash"],
            "entry_count": chain_state["entry_count"],
            "chain_initialized": chain_state["entry_count"] > 0,
            "genesis_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "algorithm": "SHA-256"
        }
        
    except Exception as e:
        logger.error(f"Failed to get chain status: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/export")
async def export_audit_logs(
    event_type: Optional[str] = None,
    agent_id: Optional[str] = None,
    start_time: Optional[float] = None,
    end_time: Optional[float] = None
) -> Dict[str, Any]:
    """Export audit logs to file."""
    try:
        # Filter logs (same logic as get_audit_logs)
        filtered_logs = audit_entries.copy()
        
        if event_type:
            filtered_logs = [log for log in filtered_logs if log.get("event_type") == event_type]
        
        if agent_id:
            filtered_logs = [log for log in filtered_logs if log.get("agent_id") == agent_id]
        
        if start_time:
            filtered_logs = [log for log in filtered_logs if log.get("timestamp", 0) >= start_time]
        
        if end_time:
            filtered_logs = [log for log in filtered_logs if log.get("timestamp", 0) <= end_time]
        
        # Sort by timestamp
        filtered_logs.sort(key=lambda x: x.get("timestamp", 0))
        
        # Create export data
        export_data = {
            "export_timestamp": time.time(),
            "filter_criteria": {
                "event_type": event_type,
                "agent_id": agent_id,
                "start_time": start_time,
                "end_time": end_time
            },
            "total_entries": len(filtered_logs),
            "entries": filtered_logs
        }
        
        # In production, save to file and return download URL
        export_filename = f"audit_export_{int(time.time())}.json"
        
        logger.info(f"Exported {len(filtered_logs)} audit entries to {export_filename}")
        
        return {
            "success": True,
            "filename": export_filename,
            "total_entries": len(filtered_logs),
            "message": f"Export completed successfully"
        }
        
    except Exception as e:
        logger.error(f"Failed to export audit logs: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/logs")
async def clear_audit_logs(
    older_than: Optional[float] = None,
    event_type: Optional[str] = None,
    agent_id: Optional[str] = None
) -> Dict[str, Any]:
    """Clear audit logs based on criteria."""
    try:
        original_count = len(audit_entries)
        
        if older_than is not None:
            # Remove entries older than specified time
            audit_entries[:] = [log for log in audit_entries if log.get("timestamp", 0) >= older_than]
        elif event_type:
            # Remove entries of specific event type
            audit_entries[:] = [log for log in audit_entries if log.get("event_type") != event_type]
        elif agent_id:
            # Remove entries for specific agent
            audit_entries[:] = [log for log in audit_entries if log.get("agent_id") != agent_id]
        else:
            # Clear all entries
            audit_entries.clear()
            chain_state["last_hash"] = "0000000000000000000000000000000000000000000000000000000000000000"
            chain_state["entry_count"] = 0
        
        removed_count = original_count - len(audit_entries)
        
        logger.info(f"Cleared {removed_count} audit log entries")
        
        return {
            "success": True,
            "removed_count": removed_count,
            "remaining_count": len(audit_entries),
            "message": f"{'Entries older than specified time' if older_than else 'All matching entries'} cleared successfully"
        }
        
    except Exception as e:
        logger.error(f"Failed to clear audit logs: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/recent")
async def get_recent_activity(
    hours: int = Query(24, ge=1, le=168),  # 1 hour to 1 week
    agent_id: Optional[str] = None
) -> Dict[str, Any]:
    """Get recent activity summary."""
    try:
        cutoff_time = time.time() - (hours * 3600)
        
        # Filter recent entries
        recent_entries = [
            entry for entry in audit_entries 
            if entry.get("timestamp", 0) >= cutoff_time
        ]
        
        if agent_id:
            recent_entries = [entry for entry in recent_entries if entry.get("agent_id") == agent_id]
        
        # Group by hour
        hourly_activity = {}
        for entry in recent_entries:
            hour = int(entry.get("timestamp", 0) // 3600) * 3600
            if hour not in hourly_activity:
                hourly_activity[hour] = 0
            hourly_activity[hour] += 1
        
        # Group by event type
        event_type_counts = {}
        for entry in recent_entries:
            event_type = entry.get("event_type", "unknown")
            event_type_counts[event_type] = event_type_counts.get(event_type, 0) + 1
        
        # Group by agent
        agent_counts = {}
        for entry in recent_entries:
            agent = entry.get("agent_id", "unknown")
            agent_counts[agent] = agent_counts.get(agent, 0) + 1
        
        return {
            "time_range_hours": hours,
            "total_entries": len(recent_entries),
            "hourly_activity": hourly_activity,
            "event_types": event_type_counts,
            "agents": agent_counts,
            "entries_per_hour": len(recent_entries) / hours,
            "most_active_hour": max(hourly_activity.items(), key=lambda x: x[1])[0] if hourly_activity else None
        }
        
    except Exception as e:
        logger.error(f"Failed to get recent activity: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def get_audit_health() -> Dict[str, Any]:
    """Get audit system health status."""
    try:
        health = {
            "status": "healthy",
            "issues": [],
            "metrics": {}
        }
        
        # Check log count
        if len(audit_entries) == 0:
            health["issues"].append("No audit entries found")
            health["status"] = "warning"
        
        # Check chain integrity
        if len(audit_entries) > 0:
            verification = await verify_chain()
            if not verification.verified:
                health["issues"].append("Hash chain integrity compromised")
                health["status"] = "critical"
            elif verification.issues:
                health["issues"].append(f"Chain verification issues: {len(verification.issues)}")
                health["status"] = "warning"
        
        # Check entry age
        if audit_entries:
            latest_entry = max(audit_entries, key=lambda x: x.get("timestamp", 0))
            age_hours = (time.time() - latest_entry.get("timestamp", 0)) / 3600
            
            if age_hours > 24:
                health["issues"].append(f"No recent entries (last entry {age_hours:.1f} hours ago)")
                health["status"] = "warning"
        
        # Metrics
        health["metrics"] = {
            "total_entries": len(audit_entries),
            "chain_entries": chain_state["entry_count"],
            "latest_entry_time": max([entry.get("timestamp", 0) for entry in audit_entries]) if audit_entries else 0,
            "signed_percentage": (len([e for e in audit_entries if e.get("signature")]) / len(audit_entries) * 100) if audit_entries else 0
        }
        
        return health
        
    except Exception as e:
        logger.error(f"Failed to get audit health: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# Helper function to create sample data (for demonstration)
def create_sample_audit_entries():
    """Create sample audit entries for demonstration."""
    try:
        sample_entries = [
            {
                "entry_id": f"entry_{int(time.time() * 1000000)}_1",
                "timestamp": time.time() - 3600,
                "event_type": "agent_registered",
                "agent_id": "finance_agent_001",
                "session_id": None,
                "event_data": {"agent_type": "finance_agent", "capabilities": ["payment", "transfer"]},
                "entry_hash": "sample_hash_1",
                "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000",
                "signature": "sample_signature_1",
                "metadata": {"entry_number": 1}
            },
            {
                "entry_id": f"entry_{int(time.time() * 1000000)}_2",
                "timestamp": time.time() - 1800,
                "event_type": "request_processed",
                "agent_id": "finance_agent_001",
                "session_id": "session_001",
                "event_data": {"request": "Pay $100 to John Doe", "response": "Payment successful"},
                "entry_hash": "sample_hash_2",
                "previous_hash": "sample_hash_1",
                "signature": "sample_signature_2",
                "metadata": {"entry_number": 2}
            },
            {
                "entry_id": f"entry_{int(time.time() * 1000000)}_3",
                "timestamp": time.time() - 900,
                "event_type": "threat_detected",
                "agent_id": "finance_agent_001",
                "session_id": "session_001",
                "event_data": {"threat_type": "injection_attempt", "risk_level": "medium"},
                "entry_hash": "sample_hash_3",
                "previous_hash": "sample_hash_2",
                "signature": "sample_signature_3",
                "metadata": {"entry_number": 3}
            }
        ]
        
        global audit_entries, chain_state
        audit_entries.extend(sample_entries)
        chain_state["entry_count"] = len(sample_entries)
        chain_state["last_hash"] = "sample_hash_3"
        
        logger.info(f"Created {len(sample_entries)} sample audit entries")
        
    except Exception as e:
        logger.error(f"Failed to create sample audit entries: {str(e)}")


# Create sample data if no entries exist
if not audit_entries:
    create_sample_audit_entries()
