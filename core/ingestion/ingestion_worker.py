"""
Ingestion Worker - Sandboxed process: reads raw input, CANNOT execute tools

Handles sandboxed input processing for ChainGuardAI:
- Sandboxed process isolation
- Raw input reading and processing
- No tool execution capabilities
- Secure input handling
"""

import os
import sys
import json
import time
import signal
import multiprocessing
from typing import Dict, Any, Optional, Callable
from pathlib import Path
from loguru import logger
from .intent_parser import IntentParser
from .intent_validator import IntentValidator
from .input_sanitizer import InputSanitizer
from .ipc_bridge import IPCBridge


class IngestionWorker:
    """Sandboxed worker for processing raw input without execution capabilities."""
    
    def __init__(self, max_input_length: int = 10000, timeout: int = 30):
        """
        Initialize IngestionWorker.
        
        Args:
            max_input_length: Maximum allowed input length
            timeout: Processing timeout in seconds
        """
        self.max_input_length = max_input_length
        self.timeout = timeout
        
        # Initialize components
        self.intent_parser = IntentParser()
        self.intent_validator = IntentValidator()
        self.input_sanitizer = InputSanitizer()
        self.ipc_bridge = IPCBridge()
        
        # Process management
        self.worker_process = None
        self.worker_id = None
        
        logger.info("Initialized IngestionWorker")
    
    def process_input_safely(self, raw_input: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Process raw input in a sandboxed environment.
        
        Args:
            raw_input: Raw input string to process
            context: Additional context for processing
            
        Returns:
            Processed intent object
        """
        try:
            # Validate input length
            if len(raw_input) > self.max_input_length:
                raise ValueError(f"Input too long: {len(raw_input)} > {self.max_input_length}")
            
            # Create processing task
            task = {
                "type": "process_input",
                "raw_input": raw_input,
                "context": context or {},
                "timestamp": time.time()
            }
            
            # Process in sandboxed worker
            result = self._run_sandboxed_task(task)
            
            logger.info(f"Successfully processed input in sandbox: {len(raw_input)} chars")
            return result
            
        except Exception as e:
            logger.error(f"Failed to process input safely: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "intent": None,
                "risk_level": "HIGH"
            }
    
    def _run_sandboxed_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Run a task in a sandboxed worker process."""
        try:
            # Create communication queues
            parent_conn, child_conn = multiprocessing.Pipe()
            
            # Start worker process
            self.worker_process = multiprocessing.Process(
                target=self._worker_main,
                args=(child_conn, task)
            )
            self.worker_process.start()
            
            # Wait for result with timeout
            if parent_conn.poll(self.timeout):
                result = parent_conn.recv()
                
                if result.get("success", False):
                    return result
                else:
                    raise Exception(result.get("error", "Unknown worker error"))
            else:
                # Timeout occurred
                self.worker_process.terminate()
                self.worker_process.join(timeout=5)
                raise TimeoutError("Worker process timed out")
                
        except Exception as e:
            logger.error(f"Sandboxed task failed: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "intent": None,
                "risk_level": "HIGH"
            }
        finally:
            # Clean up process
            if self.worker_process and self.worker_process.is_alive():
                self.worker_process.terminate()
                self.worker_process.join(timeout=5)
    
    @staticmethod
    def _worker_main(conn, task: Dict[str, Any]) -> None:
        """Main worker function running in sandboxed process."""
        try:
            # Restrict process capabilities
            IngestionWorker._sandbox_process()
            
            # Initialize components in worker
            intent_parser = IntentParser()
            intent_validator = IntentValidator()
            input_sanitizer = InputSanitizer()
            
            # Process the task
            if task["type"] == "process_input":
                raw_input = task["raw_input"]
                context = task.get("context", {})
                
                # Step 1: Sanitize input
                sanitized_input = input_sanitizer.sanitize(raw_input)
                
                # Step 2: Parse intent
                intent = intent_parser.parse_intent(sanitized_input, context)
                
                # Step 3: Validate intent
                validation_result = intent_validator.validate_intent(intent)
                
                # Send result back
                result = {
                    "success": True,
                    "intent": intent,
                    "validation": validation_result,
                    "sanitized_input": sanitized_input,
                    "processing_time": time.time() - task["timestamp"]
                }
                
                conn.send(result)
                
        except Exception as e:
            # Send error back
            error_result = {
                "success": False,
                "error": str(e),
                "intent": None,
                "validation": None
            }
            conn.send(error_result)
        finally:
            conn.close()
    
    @staticmethod
    def _sandbox_process() -> None:
        """Apply sandbox restrictions to the current process."""
        try:
            # Remove dangerous functions from builtins
            dangerous_builtins = [
                'open', 'file', 'input', 'raw_input',
                'exec', 'eval', 'compile', '__import__',
                'reload', 'exit', 'quit'
            ]
            
            for name in dangerous_builtins:
                if hasattr(__builtins__, name):
                    delattr(__builtins__, name)
            
            # Restrict module imports
            original_import = __builtins__.__import__
            
            def restricted_import(name, *args, **kwargs):
                # Whitelist of allowed modules
                allowed_modules = {
                    'json', 'time', 'datetime', 're', 'math',
                    'collections', 'itertools', 'functools'
                }
                
                if name not in allowed_modules:
                    raise ImportError(f"Module '{name}' not allowed in sandbox")
                
                return original_import(name, *args, **kwargs)
            
            __builtins__.__import__ = restricted_import
            
            # Set resource limits (if available)
            try:
                import resource
                # Limit CPU time
                resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
                # Limit memory usage (50MB)
                resource.setrlimit(resource.RLIMIT_AS, (50 * 1024 * 1024, 50 * 1024 * 1024))
            except ImportError:
                pass  # resource module not available on Windows
            
        except Exception as e:
            # If sandboxing fails, exit the process
            sys.exit(1)
    
    def batch_process_inputs(self, inputs: list, context: Optional[Dict[str, Any]] = None) -> list:
        """
        Process multiple inputs in batch.
        
        Args:
            inputs: List of input strings
            context: Shared context for all inputs
            
        Returns:
            List of processing results
        """
        results = []
        
        for i, raw_input in enumerate(inputs):
            try:
                result = self.process_input_safely(raw_input, context)
                result["batch_index"] = i
                results.append(result)
                
                # Add small delay between processing to prevent resource exhaustion
                time.sleep(0.01)
                
            except Exception as e:
                logger.error(f"Failed to process batch input {i}: {str(e)}")
                results.append({
                    "success": False,
                    "error": str(e),
                    "intent": None,
                    "batch_index": i,
                    "risk_level": "HIGH"
                })
        
        logger.info(f"Processed batch of {len(inputs)} inputs")
        return results
    
    def validate_input_safety(self, raw_input: str) -> Dict[str, Any]:
        """
        Perform preliminary safety checks on raw input.
        
        Args:
            raw_input: Raw input string
            
        Returns:
            Safety assessment result
        """
        try:
            safety_result = {
                "safe": True,
                "warnings": [],
                "blocked_patterns": [],
                "length_ok": len(raw_input) <= self.max_input_length
            }
            
            # Check for obviously dangerous patterns
            dangerous_patterns = [
                "import os", "import sys", "__import__",
                "exec(", "eval(", "compile(",
                "subprocess", "commands.getoutput",
                "open(", "file(", "input(", "raw_input("
            ]
            
            for pattern in dangerous_patterns:
                if pattern in raw_input:
                    safety_result["safe"] = False
                    safety_result["blocked_patterns"].append(pattern)
                    safety_result["warnings"].append(f"Dangerous pattern detected: {pattern}")
            
            # Check for very long input
            if not safety_result["length_ok"]:
                safety_result["safe"] = False
                safety_result["warnings"].append(f"Input too long: {len(raw_input)} chars")
            
            # Check for null bytes and other control characters
            if '\x00' in raw_input:
                safety_result["safe"] = False
                safety_result["warnings"].append("Null bytes detected in input")
            
            # Check for excessive whitespace
            whitespace_ratio = sum(c.isspace() for c in raw_input) / len(raw_input) if raw_input else 0
            if whitespace_ratio > 0.8:
                safety_result["warnings"].append("Excessive whitespace detected")
            
            return safety_result
            
        except Exception as e:
            logger.error(f"Input safety validation failed: {str(e)}")
            return {
                "safe": False,
                "warnings": [f"Safety validation error: {str(e)}"],
                "blocked_patterns": [],
                "length_ok": False
            }
    
    def get_worker_status(self) -> Dict[str, Any]:
        """
        Get the current status of the worker.
        
        Returns:
            Worker status dictionary
        """
        return {
            "worker_alive": self.worker_process.is_alive() if self.worker_process else False,
            "worker_id": self.worker_id,
            "max_input_length": self.max_input_length,
            "timeout": self.timeout,
            "pid": os.getpid()
        }
    
    def cleanup(self) -> None:
        """Clean up worker resources."""
        try:
            if self.worker_process and self.worker_process.is_alive():
                self.worker_process.terminate()
                self.worker_process.join(timeout=5)
            
            logger.info("IngestionWorker cleanup completed")
            
        except Exception as e:
            logger.error(f"Cleanup failed: {str(e)}")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.cleanup()
