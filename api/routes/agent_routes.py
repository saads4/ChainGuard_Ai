"""
Agent Routes - Agent management endpoints

FastAPI routes for managing ChainGuardAI-protected agents:
- Agent registration and management
- Request processing
- Agent status monitoring
- Health checks
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
import uuid
import logging

logger = logging.getLogger(__name__)

router = APIRouter()


# Pydantic models for request/response
class AgentRegistrationRequest(BaseModel):
    """Request model for agent registration."""
    agent_id: Optional[str] = Field(None, description="Unique agent identifier")
    agent_type: str = Field(..., description="Type of agent")
    capabilities: List[str] = Field(..., description="Agent capabilities")
    config: Optional[Dict[str, Any]] = Field(None, description="Agent configuration")


class AgentRegistrationResponse(BaseModel):
    """Response model for agent registration."""
    success: bool
    agent_id: str
    message: str
    session_id: Optional[str] = None


class AgentRequest(BaseModel):
    """Request model for agent processing."""
    request: str = Field(..., description="User request to process")
    agent_id: str = Field(..., description="Agent ID")
    session_id: Optional[str] = Field(None, description="Session ID")


class AgentResponse(BaseModel):
    """Response model for agent processing."""
    success: bool
    response: str
    agent_id: str
    session_id: Optional[str] = None
    processing_time: float
    risk_level: Optional[str] = None
    shield_protection: bool
    error: Optional[str] = None


class AgentStatus(BaseModel):
    """Agent status model."""
    agent_id: str
    agent_type: str
    is_active: bool
    session_active: bool
    protected: bool
    trust_score: float
    statistics: Dict[str, Any]
    health_status: Dict[str, Any]


# In-memory agent storage (in production, use database)
registered_agents = {}
agent_sessions = {}


# Dependency functions
async def get_agent(agent_id: str) -> Dict[str, Any]:
    """Get agent by ID."""
    if agent_id not in registered_agents:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")
    return registered_agents[agent_id]


# Route endpoints
@router.post("/register", response_model=AgentRegistrationResponse)
async def register_agent(request: AgentRegistrationRequest) -> AgentRegistrationResponse:
    """Register a new agent with ChainGuardAI protection."""
    try:
        # Generate agent ID if not provided
        if not request.agent_id:
            request.agent_id = f"agent_{uuid.uuid4().hex[:8]}"
        
        # Check if agent already exists
        if request.agent_id in registered_agents:
            return AgentRegistrationResponse(
                success=False,
                agent_id=request.agent_id,
                message="Agent already registered"
            )
        
        # Create agent instance (simplified for example)
        agent_instance = {
            "agent_id": request.agent_id,
            "agent_type": request.agent_type,
            "capabilities": request.capabilities,
            "config": request.config or {},
            "is_active": False,
            "session_id": None,
            "protected": False,
            "trust_score": 1.0,
            "statistics": {
                "total_requests": 0,
                "successful_requests": 0,
                "blocked_requests": 0,
                "escalated_requests": 0,
                "avg_processing_time": 0.0
            },
            "created_at": time.time()
        }
        
        # Store agent
        registered_agents[request.agent_id] = agent_instance
        
        logger.info(f"Agent registered: {request.agent_id} ({request.agent_type})")
        
        return AgentRegistrationResponse(
            success=True,
            agent_id=request.agent_id,
            message="Agent registered successfully"
        )
        
    except Exception as e:
        logger.error(f"Failed to register agent: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/unregister")
async def unregister_agent(agent_id: str) -> Dict[str, Any]:
    """Unregister an agent."""
    try:
        if agent_id not in registered_agents:
            raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")
        
        # End session if active
        agent = registered_agents[agent_id]
        if agent["session_id"]:
            if agent["session_id"] in agent_sessions:
                del agent_sessions[agent["session_id"]]
            agent["session_id"] = None
            agent["is_active"] = False
        
        # Remove agent
        del registered_agents[agent_id]
        
        logger.info(f"Agent unregistered: {agent_id}")
        
        return {"success": True, "message": f"Agent {agent_id} unregistered successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to unregister agent: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/session/start")
async def start_session(agent_id: str) -> Dict[str, Any]:
    """Start a new session for an agent."""
    try:
        if agent_id not in registered_agents:
            raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")
        
        agent = registered_agents[agent_id]
        
        # End existing session if active
        if agent["session_id"] and agent["session_id"] in agent_sessions:
            del agent_sessions[agent["session_id"]]
        
        # Create new session
        session_id = str(uuid.uuid4())
        agent["session_id"] = session_id
        agent["is_active"] = True
        agent_sessions[session_id] = agent_id
        
        logger.info(f"Session started for agent {agent_id}: {session_id}")
        
        return {
            "success": True,
            "session_id": session_id,
            "agent_id": agent_id,
            "message": "Session started successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to start session: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/session/end")
async def end_session(agent_id: str) -> Dict[str, Any]:
    """End an agent session."""
    try:
        if agent_id not in registered_agents:
            raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")
        
        agent = registered_agents[agent_id]
        
        if not agent["session_id"]:
            return {"success": True, "message": "No active session to end"}
        
        session_id = agent["session_id"]
        
        # Remove session
        if session_id in agent_sessions:
            del agent_sessions[session_id]
        
        # Update agent state
        agent["session_id"] = None
        agent["is_active"] = False
        
        logger.info(f"Session ended for agent {agent_id}: {session_id}")
        
        return {
            "success": True,
            "session_id": session_id,
            "agent_id": agent_id,
            "message": "Session ended successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to end session: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/process", response_model=AgentResponse)
async def process_request(request: AgentRequest, background_tasks: BackgroundTasks) -> AgentResponse:
    """Process a request through an ChainGuardAI-protected agent."""
    try:
        import time
        start_time = time.time()
        
        # Validate agent exists
        if request.agent_id not in registered_agents:
            raise HTTPException(status_code=404, detail=f"Agent {request.agent_id} not found")
        
        agent = registered_agents[request.agent_id]
        
        # Validate session if provided
        if request.session_id and request.session_id != agent["session_id"]:
            raise HTTPException(status_code=401, detail="Invalid session ID")
        
        # Update statistics
        agent["statistics"]["total_requests"] += 1
        
        # Process request (simplified for example)
        # In production, this would use the actual ChainGuardAI framework
        response_text = f"Processed request for {agent['agent_type']}: '{request.request}'"
        processing_time = time.time() - start_time
        
        # Update statistics
        agent["statistics"]["successful_requests"] += 1
        current_avg = agent["statistics"]["avg_processing_time"]
        count = agent["statistics"]["total_requests"]
        agent["statistics"]["avg_processing_time"] = ((current_avg * (count - 1)) + processing_time) / count
        
        # Log the request in background
        background_tasks.add_task(
            log_agent_request,
            request.agent_id,
            request.request,
            response_text,
            processing_time
        )
        
        return AgentResponse(
            success=True,
            response=response_text,
            agent_id=request.agent_id,
            session_id=request.session_id,
            processing_time=processing_time,
            risk_level="LOW",  # Simplified
            shield_protection=agent["protected"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to process request: {str(e)}")
        
        # Update error statistics
        if request.agent_id in registered_agents:
            registered_agents[request.agent_id]["statistics"]["blocked_requests"] += 1
        
        return AgentResponse(
            success=False,
            response="Error processing request",
            agent_id=request.agent_id,
            session_id=request.session_id,
            processing_time=0.0,
            shield_protection=False,
            error=str(e)
        )


@router.get("/status/{agent_id}", response_model=AgentStatus)
async def get_agent_status(agent_id: str = Depends(get_agent)) -> AgentStatus:
    """Get agent status."""
    try:
        # Calculate health status
        health_status = calculate_agent_health(agent_id)
        
        return AgentStatus(
            agent_id=agent_id["agent_id"],
            agent_type=agent_id["agent_type"],
            is_active=agent_id["is_active"],
            session_active=agent_id["session_id"] is not None,
            protected=agent_id["protected"],
            trust_score=agent_id["trust_score"],
            statistics=agent_id["statistics"],
            health_status=health_status
        )
        
    except Exception as e:
        logger.error(f"Failed to get agent status: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/list")
async def list_agents() -> Dict[str, Any]:
    """List all registered agents."""
    try:
        agents_list = []
        
        for agent_id, agent in registered_agents.items():
            agents_list.append({
                "agent_id": agent_id,
                "agent_type": agent["agent_type"],
                "is_active": agent["is_active"],
                "protected": agent["protected"],
                "trust_score": agent["trust_score"],
                "created_at": agent["created_at"]
            })
        
        return {
            "total_agents": len(agents_list),
            "agents": agents_list
        }
        
    except Exception as e:
        logger.error(f"Failed to list agents: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def get_agents_health() -> Dict[str, Any]:
    """Get health status of all agents."""
    try:
        health_summary = {
            "total_agents": len(registered_agents),
            "healthy_agents": 0,
            "degraded_agents": 0,
            "unhealthy_agents": 0,
            "agents": {}
        }
        
        for agent_id, agent in registered_agents.items():
            health = calculate_agent_health(agent_id)
            health_summary["agents"][agent_id] = health
            
            status = health.get("status", "unknown")
            if status == "healthy":
                health_summary["healthy_agents"] += 1
            elif status == "degraded":
                health_summary["degraded_agents"] += 1
            elif status == "unhealthy":
                health_summary["unhealthy_agents"] += 1
        
        return health_summary
        
    except Exception as e:
        logger.error(f"Failed to get agents health: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/trust-score/{agent_id}")
async def update_trust_score(agent_id: str, score: float) -> Dict[str, Any]:
    """Update agent trust score."""
    try:
        if agent_id not in registered_agents:
            raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")
        
        if not 0.0 <= score <= 1.0:
            raise HTTPException(status_code=400, detail="Trust score must be between 0.0 and 1.0")
        
        old_score = registered_agents[agent_id]["trust_score"]
        registered_agents[agent_id]["trust_score"] = score
        
        logger.info(f"Trust score updated for {agent_id}: {old_score} -> {score}")
        
        return {
            "success": True,
            "agent_id": agent_id,
            "old_score": old_score,
            "new_score": score
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update trust score: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics/{agent_id}")
async def get_agent_statistics(agent_id: str = Depends(get_agent)) -> Dict[str, Any]:
    """Get detailed statistics for an agent."""
    try:
        stats = agent_id["statistics"].copy()
        
        # Calculate derived statistics
        total_requests = stats["total_requests"]
        if total_requests > 0:
            stats["success_rate"] = (stats["successful_requests"] / total_requests) * 100
            stats["block_rate"] = (stats["blocked_requests"] / total_requests) * 100
            stats["escalation_rate"] = (stats["escalated_requests"] / total_requests) * 100
        else:
            stats["success_rate"] = 0.0
            stats["block_rate"] = 0.0
            stats["escalation_rate"] = 0.0
        
        return {
            "agent_id": agent_id["agent_id"],
            "statistics": stats,
            "trust_score": agent_id["trust_score"],
            "last_updated": time.time()
        }
        
    except Exception as e:
        logger.error(f"Failed to get agent statistics: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# Helper functions
def calculate_agent_health(agent: Dict[str, Any]) -> Dict[str, Any]:
    """Calculate agent health status."""
    try:
        health = {
            "status": "healthy",
            "issues": []
        }
        
        # Check protection status
        if not agent["protected"]:
            health["issues"].append("ChainGuardAI protection not active")
            health["status"] = "degraded"
        
        # Check trust score
        if agent["trust_score"] < 0.5:
            health["issues"].append(f"Low trust score: {agent['trust_score']}")
            health["status"] = "degraded"
        
        # Check success rate
        stats = agent["statistics"]
        if stats["total_requests"] > 0:
            success_rate = stats["successful_requests"] / stats["total_requests"]
            if success_rate < 0.8:
                health["issues"].append(f"Low success rate: {success_rate:.2%}")
                health["status"] = "unhealthy"
        
        # Check processing time
        if stats["avg_processing_time"] > 5.0:
            health["issues"].append(f"High processing time: {stats['avg_processing_time']:.2f}s")
            health["status"] = "degraded"
        
        return health
        
    except Exception as e:
        logger.error(f"Failed to calculate agent health: {str(e)}")
        return {"status": "error", "issues": [str(e)]}


async def log_agent_request(agent_id: str, request: str, response: str, processing_time: float):
    """Log agent request asynchronously."""
    try:
        logger.info(f"Agent request logged: {agent_id} - {request[:50]}... ({processing_time:.3f}s)")
    except Exception as e:
        logger.error(f"Failed to log agent request: {str(e)}")


# Import time for timestamp generation
import time
