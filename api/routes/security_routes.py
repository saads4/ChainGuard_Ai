"""
Security Routes - Security monitoring endpoints

FastAPI routes for monitoring ChainGuardAI security:
- Security status monitoring
- Threat detection
- Risk assessment
- Security configuration
"""

from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
import time
import logging

logger = logging.getLogger(__name__)

router = APIRouter()


# Pydantic models
class SecurityStatus(BaseModel):
    """Security status model."""
    status: str
    protection_active: bool
    threats_detected: int
    risk_level: str
    last_scan: float
    components: Dict[str, Any]


class ThreatAlert(BaseModel):
    """Threat alert model."""
    alert_id: str
    severity: str
    threat_type: str
    description: str
    timestamp: float
    agent_id: Optional[str] = None
    resolved: bool = False


class SecurityConfig(BaseModel):
    """Security configuration model."""
    threat_detection_enabled: bool = True
    auto_block_enabled: bool = False
    alert_threshold: str = "medium"
    scan_interval: int = 300  # seconds


# In-memory storage (in production, use database)
security_events = []
threat_alerts = []
security_config = {
    "threat_detection_enabled": True,
    "auto_block_enabled": False,
    "alert_threshold": "medium",
    "scan_interval": 300
}


# Route endpoints
@router.get("/status", response_model=SecurityStatus)
async def get_security_status() -> SecurityStatus:
    """Get overall security status."""
    try:
        # Calculate security metrics
        unresolved_threats = [alert for alert in threat_alerts if not alert["resolved"]]
        high_severity_threats = [alert for alert in unresolved_threats if alert["severity"] == "high"]
        
        # Determine risk level
        risk_level = "low"
        if high_severity_threats:
            risk_level = "high"
        elif len(unresolved_threats) > 5:
            risk_level = "medium"
        
        # Component status
        components = {
            "identity_layer": {"status": "active", "issues": []},
            "ingestion_layer": {"status": "active", "issues": []},
            "detection_layer": {"status": "active", "issues": []},
            "action_gate_layer": {"status": "active", "issues": []},
            "audit_layer": {"status": "active", "issues": []}
        }
        
        return SecurityStatus(
            status="operational",
            protection_active=True,
            threats_detected=len(unresolved_threats),
            risk_level=risk_level,
            last_scan=time.time(),
            components=components
        )
        
    except Exception as e:
        logger.error(f"Failed to get security status: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/threats")
async def get_threats(severity: Optional[str] = None, resolved: Optional[bool] = None,
                     limit: int = 50) -> Dict[str, Any]:
    """Get threat alerts."""
    try:
        filtered_threats = threat_alerts.copy()
        
        # Filter by severity
        if severity:
            filtered_threats = [t for t in filtered_threats if t["severity"] == severity]
        
        # Filter by resolution status
        if resolved is not None:
            filtered_threats = [t for t in filtered_threats if t["resolved"] == resolved]
        
        # Sort by timestamp (newest first)
        filtered_threats.sort(key=lambda x: x["timestamp"], reverse=True)
        
        # Limit results
        filtered_threats = filtered_threats[:limit]
        
        # Calculate statistics
        total_threats = len(threat_alerts)
        unresolved_threats = len([t for t in threat_alerts if not t["resolved"]])
        
        severity_counts = {}
        for threat in threat_alerts:
            sev = threat["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        return {
            "threats": filtered_threats,
            "statistics": {
                "total_threats": total_threats,
                "unresolved_threats": unresolved_threats,
                "severity_distribution": severity_counts
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to get threats: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/threats/{threat_id}/resolve")
async def resolve_threat(threat_id: str) -> Dict[str, Any]:
    """Resolve a threat alert."""
    try:
        # Find threat
        threat_found = False
        for threat in threat_alerts:
            if threat["alert_id"] == threat_id:
                threat["resolved"] = True
                threat["resolved_at"] = time.time()
                threat_found = True
                break
        
        if not threat_found:
            raise HTTPException(status_code=404, detail=f"Threat {threat_id} not found")
        
        logger.info(f"Threat resolved: {threat_id}")
        
        return {
            "success": True,
            "threat_id": threat_id,
            "message": "Threat resolved successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to resolve threat: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan")
async def run_security_scan() -> Dict[str, Any]:
    """Run a comprehensive security scan."""
    try:
        scan_start = time.time()
        
        # Simulate security scan
        scan_results = {
            "scan_id": f"scan_{int(time.time() * 1000000)}",
            "timestamp": scan_start,
            "duration": 0.0,
            "findings": [],
            "threats_detected": 0,
            "risk_assessment": "low"
        }
        
        # Simulate scanning different layers
        layers = ["identity", "ingestion", "detection", "action_gate", "audit"]
        
        for layer in layers:
            layer_result = {
                "layer": layer,
                "status": "secure",
                "issues": [],
                "scan_time": time.time()
            }
            
            # Simulate finding issues (in production, actual security checks)
            if layer == "detection" and time.time() % 10 < 2:  # 20% chance
                layer_result["status"] = "warning"
                layer_result["issues"].append("Unusual pattern detected in input processing")
                scan_results["threats_detected"] += 1
            
            scan_results["findings"].append(layer_result)
        
        # Calculate risk assessment
        if scan_results["threats_detected"] > 3:
            scan_results["risk_assessment"] = "high"
        elif scan_results["threats_detected"] > 0:
            scan_results["risk_assessment"] = "medium"
        
        scan_results["duration"] = time.time() - scan_start
        
        # Log scan
        logger.info(f"Security scan completed: {scan_results['scan_id']} ({scan_results['duration']:.3f}s)")
        
        return scan_results
        
    except Exception as e:
        logger.error(f"Failed to run security scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/config")
async def get_security_config() -> Dict[str, Any]:
    """Get security configuration."""
    try:
        return {
            "config": security_config.copy(),
            "last_updated": time.time()
        }
        
    except Exception as e:
        logger.error(f"Failed to get security config: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/config")
async def update_security_config(config: SecurityConfig) -> Dict[str, Any]:
    """Update security configuration."""
    try:
        # Update configuration
        security_config.update({
            "threat_detection_enabled": config.threat_detection_enabled,
            "auto_block_enabled": config.auto_block_enabled,
            "alert_threshold": config.alert_threshold,
            "scan_interval": config.scan_interval
        })
        
        logger.info(f"Security configuration updated")
        
        return {
            "success": True,
            "message": "Security configuration updated successfully",
            "config": security_config.copy()
        }
        
    except Exception as e:
        logger.error(f"Failed to update security config: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/metrics")
async def get_security_metrics() -> Dict[str, Any]:
    """Get security metrics and statistics."""
    try:
        # Calculate metrics
        total_threats = len(threat_alerts)
        unresolved_threats = len([t for t in threat_alerts if not t["resolved"]])
        
        # Threat trends (last 24 hours)
        now = time.time()
        last_24h = now - (24 * 3600)
        recent_threats = [t for t in threat_alerts if t["timestamp"] > last_24h]
        
        # Severity breakdown
        severity_breakdown = {}
        for threat in threat_alerts:
            sev = threat["severity"]
            severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
        
        # Resolution metrics
        resolved_threats = [t for t in threat_alerts if t["resolved"]]
        avg_resolution_time = 0.0
        
        if resolved_threats:
            resolution_times = []
            for threat in resolved_threats:
                if "resolved_at" in threat:
                    resolution_times.append(threat["resolved_at"] - threat["timestamp"])
            
            if resolution_times:
                avg_resolution_time = sum(resolution_times) / len(resolution_times)
        
        metrics = {
            "total_threats": total_threats,
            "unresolved_threats": unresolved_threats,
            "recent_threats_24h": len(recent_threats),
            "severity_breakdown": severity_breakdown,
            "resolution_metrics": {
                "resolved_threats": len(resolved_threats),
                "avg_resolution_time": avg_resolution_time,
                "resolution_rate": (len(resolved_threats) / total_threats * 100) if total_threats > 0 else 0
            },
            "detection_metrics": {
                "threats_detected_today": len([t for t in recent_threats if not t["resolved"]]),
                "high_severity_threats": len([t for t in threat_alerts if t["severity"] == "high" and not t["resolved"]]),
                "auto_blocked": 0  # Placeholder
            }
        }
        
        return metrics
        
    except Exception as e:
        logger.error(f"Failed to get security metrics: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/test-threat")
async def create_test_threat(severity: str = "medium", threat_type: str = "test") -> Dict[str, Any]:
    """Create a test threat for demonstration."""
    try:
        if severity not in ["low", "medium", "high"]:
            raise HTTPException(status_code=400, detail="Invalid severity. Must be low, medium, or high")
        
        threat_id = f"test_{int(time.time() * 1000000)}"
        
        test_threat = {
            "alert_id": threat_id,
            "severity": severity,
            "threat_type": threat_type,
            "description": f"Test threat - {severity} severity",
            "timestamp": time.time(),
            "agent_id": None,
            "resolved": False,
            "test": True
        }
        
        threat_alerts.append(test_threat)
        
        logger.info(f"Test threat created: {threat_id}")
        
        return {
            "success": True,
            "threat_id": threat_id,
            "message": "Test threat created successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create test threat: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dashboard")
async def get_security_dashboard() -> Dict[str, Any]:
    """Get security dashboard data."""
    try:
        # Get current status
        status = await get_security_status()
        
        # Get metrics
        metrics = await get_security_metrics()
        
        # Get recent threats
        recent_threats = [t for t in threat_alerts if not t["resolved"]][:10]
        recent_threats.sort(key=lambda x: x["timestamp"], reverse=True)
        
        # Dashboard data
        dashboard = {
            "status": status.dict(),
            "metrics": metrics,
            "recent_threats": recent_threats,
            "quick_stats": {
                "active_threats": metrics["unresolved_threats"],
                "threats_today": metrics["recent_threats_24h"],
                "high_risk_threats": metrics["detection_metrics"]["high_severity_threats"],
                "protection_status": "active" if status.protection_active else "inactive"
            },
            "last_updated": time.time()
        }
        
        return dashboard
        
    except Exception as e:
        logger.error(f"Failed to get security dashboard: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/threats")
async def clear_threats(resolved_only: bool = False) -> Dict[str, Any]:
    """Clear threat alerts."""
    try:
        original_count = len(threat_alerts)
        
        if resolved_only:
            # Remove only resolved threats
            threat_alerts[:] = [t for t in threat_alerts if not t["resolved"]]
        else:
            # Remove all threats
            threat_alerts.clear()
        
        removed_count = original_count - len(threat_alerts)
        
        logger.info(f"Cleared {removed_count} threat alerts")
        
        return {
            "success": True,
            "removed_count": removed_count,
            "remaining_count": len(threat_alerts),
            "message": f"{'Resolved' if resolved_only else 'All'} threats cleared successfully"
        }
        
    except Exception as e:
        logger.error(f"Failed to clear threats: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
