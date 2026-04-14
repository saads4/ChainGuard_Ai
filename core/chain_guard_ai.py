import time
from typing import Dict, Any, List, Optional
from loguru import logger

from .identity.key_manager import KeyManager
from .identity.registry.registry_manager import RegistryManager
from .ingestion.ingestion_worker import IngestionWorker
from .detection.detection_pipeline import DetectionPipeline
from .action_gate.gate_controller import GateController
from .audit.audit_logger import AuditLogger

class ChainGuardAI:
    """
    Main Orchestrator for the ChainGuardAI 5-Layer Security Framework.
    """
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # 1. Identity Layer
        self.key_manager = KeyManager(keys_directory="./data/keys")
        self.registry_manager = RegistryManager(registry_path="./data/registry/agent_registry.json")
        
        # 2. Ingestion Layer
        self.ingestion_worker = IngestionWorker()
        
        # 3. Detection Layer
        self.detection_pipeline = DetectionPipeline(self.config.get("detection", {}))
        
        # 4. Action Gate Layer
        self.gate_controller = GateController()
        if "action_gate" in self.config:
            self.gate_controller.update_configuration(self.config["action_gate"])
            
        # 5. Audit Layer
        self.audit_logger = AuditLogger(self.config.get("audit", {}))
        
        self.stats = {
            "total_requests": 0,
            "blocked_requests": 0,
            "escalated_requests": 0,
            "successful_requests": 0
        }
        
    def register_agent(self, agent_id: str, agent_type: str, capabilities: List[str], context: Dict[str, Any] = None) -> bool:
        """Register an agent with ChainGuardAI Identity Layer."""
        try:
            private_key, public_key = self.key_manager.generate_keypair(agent_id=agent_id)
            self.key_manager.save_keypair(agent_id, private_key, public_key, encrypt=False)
            
            metadata = {
                "agent_type": agent_type,
                "capabilities": capabilities,
                "context": context or {}
            }
            self.registry_manager.register_agent(agent_id, public_key, metadata)
            logger.info(f"Registered agent {agent_id} in ChainGuardAI")
            return True
        except Exception as e:
            logger.error(f"Failed to register agent {agent_id}: {e}")
            return False

    def process_request(self, request: str, agent_id: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Process an incoming request through all 5 security layers."""
        start_time = time.time()
        self.stats["total_requests"] += 1
        
        try:
            # 1. Identity verification
            agent_info = self.registry_manager.get_agent(agent_id)
            if not agent_info:
                return self._create_result(False, "HIGH", "Agent not registered or invalid", start_time, error="Unauthorized agent")

            # 2. Ingestion (sanitization and parsing)
            ingested = self.ingestion_worker.process_input_safely(request, context)
            if not ingested.get("success", False):
                self.stats["blocked_requests"] += 1
                risk_level = ingested.get("risk_level", "HIGH")
                return self._create_result(False, risk_level, "Input ingestion failed: sandboxed rejection", start_time, error=ingested.get("error"))

            intent = ingested.get("intent", {})

            # 3. Detection Pipeline
            detection_result = self.detection_pipeline.evaluate_request(request, agent_id, context)
            risk_level = detection_result.get("risk_level", "UNKNOWN")
            
            if not detection_result.get("safe", False):
                if detection_result.get("escalate", False):
                    self.stats["escalated_requests"] += 1
                    return self._create_result(False, risk_level, "Request escalated due to HIGH risk", start_time, escalated=True)
                
                self.stats["blocked_requests"] += 1
                return self._create_result(False, risk_level, "Request blocked by detection pipeline", start_time)

            # 4. Action Gate Check
            action = {"type": "intent_execution", "intent": intent}
            agent_context = {"agent_id": agent_id, "role": agent_info.get("metadata", {}).get("agent_type")}
            gate_result = self.gate_controller.evaluate_action(action, agent_context)
            
            if not gate_result.get("approved"):
                self.stats["blocked_requests"] += 1
                return self._create_result(False, risk_level, "Action denied by Gate Controller", start_time)

            # 5. Audit Logging
            self.stats["successful_requests"] += 1
            audit_entry = {
                "agent_id": agent_id,
                "request": request,
                "timestamp": start_time,
                "intent": intent
            }
            self.audit_logger.log_event("request_approved", audit_entry, risk_level)
            
            return self._create_result(True, risk_level, "Request processed safely", start_time, response="Action approved and processed")

        except Exception as e:
            logger.error(f"Error processing request: {e}")
            return self._create_result(False, "HIGH", "Internal processing error", start_time, error=str(e))

    def _create_result(self, success: bool, risk_level: str, msg: str, start_time: float, error: str = None, escalated: bool = False, response: str = None) -> Dict[str, Any]:
        res = {
            "success": success,
            "risk_level": risk_level,
            "shield_protection": True,
            "processing_time": time.time() - start_time
        }
        if success:
            res["response"] = response or msg
        else:
            res["error"] = error or msg
            res["escalated"] = escalated
        return res

    def get_agent_info(self, agent_id: str) -> Dict[str, Any]:
        agent_info = self.registry_manager.get_agent(agent_id)
        if agent_info:
            agent_info["statistics"] = self.stats
        return agent_info

    def get_status(self) -> Dict[str, Any]:
        return {
            "status": "active",
            "statistics": self.stats
        }

    def cleanup(self) -> None:
        self.ingestion_worker.cleanup()
        self.registry_manager.cleanup_inactive_agents()

    def wrap_agent(self, agent):
        from agents.base_agent import BaseAgent
        if hasattr(agent, "initialize_shield"):
            agent.initialize_shield(self.config)
            agent.shield = self # Override to self
            agent.protected = True
        return agent
