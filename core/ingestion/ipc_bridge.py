"""
IPC Bridge - Inter-Process Communication: sends intents to execution

Handles IPC between ingestion and execution processes for ChainGuardAI:
- Secure inter-process communication
- Intent object transmission
- Response handling
- Connection management
"""

import json
import time
import socket
import threading
import multiprocessing
from typing import Dict, Any, Optional, Callable
from queue import Queue, Empty
from loguru import logger


class IPCBridge:
    """Manages inter-process communication for ChainGuardAI."""
    
    def __init__(self, connection_type: str = "queue", timeout: int = 30):
        """
        Initialize IPCBridge.
        
        Args:
            connection_type: Type of IPC connection ("queue", "socket", "pipe")
            timeout: Communication timeout in seconds
        """
        self.connection_type = connection_type
        self.timeout = timeout
        
        # Connection objects
        self.request_queue = None
        self.response_queue = None
        self.server_socket = None
        self.client_socket = None
        self.pipe_conn = None
        
        # Connection state
        self.is_connected = False
        self.is_server = False
        self.connection_id = None
        
        # Message handlers
        self.message_handlers = {}
        self.response_callbacks = {}
        
        # Statistics
        self.stats = {
            "messages_sent": 0,
            "messages_received": 0,
            "connection_failures": 0,
            "total_bytes_transferred": 0
        }
        
        logger.info(f"Initialized IPCBridge with {connection_type} connection")
    
    def start_server(self, host: str = "localhost", port: int = 0) -> bool:
        """
        Start IPC server.
        
        Args:
            host: Host address for socket connections
            port: Port number (0 for auto-assign)
            
        Returns:
            True if server started successfully, False otherwise
        """
        try:
            if self.connection_type == "queue":
                return self._start_queue_server()
            elif self.connection_type == "socket":
                return self._start_socket_server(host, port)
            elif self.connection_type == "pipe":
                return self._start_pipe_server()
            else:
                logger.error(f"Unsupported connection type: {self.connection_type}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to start IPC server: {str(e)}")
            return False
    
    def connect_to_server(self, server_address: str) -> bool:
        """
        Connect to IPC server.
        
        Args:
            server_address: Server address (format depends on connection type)
            
        Returns:
            True if connected successfully, False otherwise
        """
        try:
            if self.connection_type == "queue":
                return self._connect_to_queue_server(server_address)
            elif self.connection_type == "socket":
                return self._connect_to_socket_server(server_address)
            elif self.connection_type == "pipe":
                return self._connect_to_pipe_server(server_address)
            else:
                logger.error(f"Unsupported connection type: {self.connection_type}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to connect to IPC server: {str(e)}")
            return False
    
    def send_intent(self, intent: Dict[str, Any], priority: str = "normal") -> Optional[Dict[str, Any]]:
        """
        Send intent object through IPC.
        
        Args:
            intent: Intent object to send
            priority: Message priority ("low", "normal", "high")
            
        Returns:
            Response from receiver or None if failed
        """
        try:
            if not self.is_connected:
                logger.error("Not connected to IPC server")
                return None
            
            # Create message
            message = {
                "type": "intent",
                "data": intent,
                "priority": priority,
                "timestamp": time.time(),
                "message_id": f"msg_{int(time.time() * 1000000)}"
            }
            
            # Send message
            response = self._send_message(message)
            
            if response:
                self.stats["messages_sent"] += 1
                logger.debug(f"Sent intent message: {message['message_id']}")
                return response
            else:
                self.stats["connection_failures"] += 1
                logger.error("Failed to send intent message")
                return None
                
        except Exception as e:
            logger.error(f"Intent sending failed: {str(e)}")
            self.stats["connection_failures"] += 1
            return None
    
    def send_response(self, original_message_id: str, response_data: Dict[str, Any]) -> bool:
        """
        Send response to a received message.
        
        Args:
            original_message_id: ID of the original message
            response_data: Response data to send
            
        Returns:
            True if sent successfully, False otherwise
        """
        try:
            if not self.is_connected:
                logger.error("Not connected to IPC server")
                return False
            
            # Create response message
            message = {
                "type": "response",
                "original_message_id": original_message_id,
                "data": response_data,
                "timestamp": time.time(),
                "message_id": f"resp_{int(time.time() * 1000000)}"
            }
            
            # Send message
            success = self._send_message(message) is not None
            
            if success:
                logger.debug(f"Sent response message: {message['message_id']}")
            else:
                logger.error("Failed to send response message")
            
            return success
            
        except Exception as e:
            logger.error(f"Response sending failed: {str(e)}")
            return False
    
    def register_message_handler(self, message_type: str, handler: Callable) -> None:
        """
        Register a message handler.
        
        Args:
            message_type: Type of message to handle
            handler: Handler function
        """
        self.message_handlers[message_type] = handler
        logger.info(f"Registered handler for message type: {message_type}")
    
    def start_message_loop(self) -> None:
        """Start the message receiving loop."""
        try:
            logger.info("Starting IPC message loop")
            
            while self.is_connected:
                try:
                    message = self._receive_message()
                    if message:
                        self._handle_message(message)
                    else:
                        time.sleep(0.01)  # Small delay to prevent busy waiting
                        
                except Exception as e:
                    logger.error(f"Message loop error: {str(e)}")
                    time.sleep(1)  # Wait before retrying
                    
        except KeyboardInterrupt:
            logger.info("Message loop interrupted")
        finally:
            self.disconnect()
    
    def _handle_message(self, message: Dict[str, Any]) -> None:
        """Handle a received message."""
        try:
            message_type = message.get("type")
            message_id = message.get("message_id")
            
            logger.debug(f"Handling message: {message_type} ({message_id})")
            
            # Get handler for message type
            handler = self.message_handlers.get(message_type)
            
            if handler:
                try:
                    # Call handler
                    response = handler(message)
                    
                    # Send response if handler returned one
                    if response and message_type != "response":
                        self.send_response(message_id, response)
                        
                except Exception as e:
                    logger.error(f"Message handler error: {str(e)}")
                    error_response = {"error": str(e), "status": "error"}
                    self.send_response(message_id, error_response)
            else:
                logger.warning(f"No handler for message type: {message_type}")
                
            self.stats["messages_received"] += 1
            
        except Exception as e:
            logger.error(f"Message handling failed: {str(e)}")
    
    def _send_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Send a message through the IPC connection."""
        try:
            message_bytes = json.dumps(message).encode('utf-8')
            self.stats["total_bytes_transferred"] += len(message_bytes)
            
            if self.connection_type == "queue":
                return self._send_queue_message(message_bytes)
            elif self.connection_type == "socket":
                return self._send_socket_message(message_bytes)
            elif self.connection_type == "pipe":
                return self._send_pipe_message(message_bytes)
            else:
                logger.error(f"Unsupported connection type: {self.connection_type}")
                return None
                
        except Exception as e:
            logger.error(f"Message sending failed: {str(e)}")
            return None
    
    def _receive_message(self) -> Optional[Dict[str, Any]]:
        """Receive a message from the IPC connection."""
        try:
            if self.connection_type == "queue":
                return self._receive_queue_message()
            elif self.connection_type == "socket":
                return self._receive_socket_message()
            elif self.connection_type == "pipe":
                return self._receive_pipe_message()
            else:
                logger.error(f"Unsupported connection type: {self.connection_type}")
                return None
                
        except Exception as e:
            logger.error(f"Message receiving failed: {str(e)}")
            return None
    
    def _start_queue_server(self) -> bool:
        """Start queue-based IPC server."""
        try:
            self.request_queue = multiprocessing.Queue()
            self.response_queue = multiprocessing.Queue()
            self.is_connected = True
            self.is_server = True
            self.connection_id = f"queue_server_{int(time.time())}"
            
            logger.info(f"Started queue server: {self.connection_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start queue server: {str(e)}")
            return False
    
    def _connect_to_queue_server(self, server_address: str) -> bool:
        """Connect to queue-based IPC server."""
        try:
            # In a real implementation, this would connect to existing queues
            # For now, we'll create new ones for demonstration
            self.request_queue = multiprocessing.Queue()
            self.response_queue = multiprocessing.Queue()
            self.is_connected = True
            self.connection_id = f"queue_client_{int(time.time())}"
            
            logger.info(f"Connected to queue server: {self.connection_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to queue server: {str(e)}")
            return False
    
    def _send_queue_message(self, message_bytes: bytes) -> Optional[Dict[str, Any]]:
        """Send message through queue."""
        try:
            self.request_queue.put(message_bytes, timeout=self.timeout)
            
            # Wait for response
            response_bytes = self.response_queue.get(timeout=self.timeout)
            response = json.loads(response_bytes.decode('utf-8'))
            
            return response
            
        except Empty:
            logger.error("Queue send timeout")
            return None
        except Exception as e:
            logger.error(f"Queue send failed: {str(e)}")
            return None
    
    def _receive_queue_message(self) -> Optional[Dict[str, Any]]:
        """Receive message from queue."""
        try:
            message_bytes = self.request_queue.get(timeout=1)
            message = json.loads(message_bytes.decode('utf-8'))
            
            return message
            
        except Empty:
            return None
        except Exception as e:
            logger.error(f"Queue receive failed: {str(e)}")
            return None
    
    def _start_socket_server(self, host: str, port: int) -> bool:
        """Start socket-based IPC server."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((host, port))
            self.server_socket.listen(5)
            
            # Get actual port if auto-assigned
            if port == 0:
                actual_port = self.server_socket.getsockname()[1]
            else:
                actual_port = port
            
            self.is_connected = True
            self.is_server = True
            self.connection_id = f"socket_server_{host}:{actual_port}"
            
            logger.info(f"Started socket server: {self.connection_id}")
            
            # Start accepting connections in a separate thread
            threading.Thread(target=self._accept_socket_connections, daemon=True).start()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start socket server: {str(e)}")
            return False
    
    def _accept_socket_connections(self) -> None:
        """Accept socket connections."""
        while self.is_connected:
            try:
                client_socket, address = self.server_socket.accept()
                logger.info(f"Accepted socket connection from: {address}")
                
                # Handle client in separate thread
                threading.Thread(
                    target=self._handle_socket_client,
                    args=(client_socket, address),
                    daemon=True
                ).start()
                
            except Exception as e:
                if self.is_connected:
                    logger.error(f"Socket accept error: {str(e)}")
                break
    
    def _handle_socket_client(self, client_socket: socket.socket, address: tuple) -> None:
        """Handle a socket client connection."""
        try:
            while self.is_connected:
                try:
                    # Receive message length
                    length_data = client_socket.recv(4)
                    if not length_data:
                        break
                    
                    message_length = int.from_bytes(length_data, byteorder='big')
                    
                    # Receive message
                    message_bytes = b''
                    while len(message_bytes) < message_length:
                        chunk = client_socket.recv(message_length - len(message_bytes))
                        if not chunk:
                            break
                        message_bytes += chunk
                    
                    if len(message_bytes) == message_length:
                        message = json.loads(message_bytes.decode('utf-8'))
                        self._handle_message(message)
                    
                except Exception as e:
                    logger.error(f"Socket client handling error: {str(e)}")
                    break
                    
        finally:
            client_socket.close()
            logger.info(f"Socket client disconnected: {address}")
    
    def _connect_to_socket_server(self, server_address: str) -> bool:
        """Connect to socket-based IPC server."""
        try:
            host, port = server_address.split(':')
            port = int(port)
            
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((host, port))
            
            self.is_connected = True
            self.connection_id = f"socket_client_{host}:{port}"
            
            logger.info(f"Connected to socket server: {self.connection_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to socket server: {str(e)}")
            return False
    
    def _send_socket_message(self, message_bytes: bytes) -> Optional[Dict[str, Any]]:
        """Send message through socket."""
        try:
            if not self.client_socket:
                logger.error("No socket connection available")
                return None
            
            # Send message length
            length = len(message_bytes).to_bytes(4, byteorder='big')
            self.client_socket.send(length)
            
            # Send message
            self.client_socket.send(message_bytes)
            
            # For simplicity, we don't wait for response in socket mode
            return {"status": "sent"}
            
        except Exception as e:
            logger.error(f"Socket send failed: {str(e)}")
            return None
    
    def _receive_socket_message(self) -> Optional[Dict[str, Any]]:
        """Receive message from socket."""
        # This would be implemented in the client handler
        return None
    
    def _start_pipe_server(self) -> bool:
        """Start pipe-based IPC server."""
        try:
            self.pipe_conn, client_conn = multiprocessing.Pipe()
            self.is_connected = True
            self.is_server = True
            self.connection_id = f"pipe_server_{int(time.time())}"
            
            logger.info(f"Started pipe server: {self.connection_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start pipe server: {str(e)}")
            return False
    
    def _connect_to_pipe_server(self, server_address: str) -> bool:
        """Connect to pipe-based IPC server."""
        try:
            # In a real implementation, this would connect to existing pipe
            self.pipe_conn, server_conn = multiprocessing.Pipe()
            self.is_connected = True
            self.connection_id = f"pipe_client_{int(time.time())}"
            
            logger.info(f"Connected to pipe server: {self.connection_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to pipe server: {str(e)}")
            return False
    
    def _send_pipe_message(self, message_bytes: bytes) -> Optional[Dict[str, Any]]:
        """Send message through pipe."""
        try:
            if not self.pipe_conn:
                logger.error("No pipe connection available")
                return None
            
            self.pipe_conn.send_bytes(message_bytes)
            
            # Wait for response
            if self.pipe_conn.poll(self.timeout):
                response_bytes = self.pipe_conn.recv_bytes()
                response = json.loads(response_bytes.decode('utf-8'))
                return response
            else:
                logger.error("Pipe send timeout")
                return None
                
        except Exception as e:
            logger.error(f"Pipe send failed: {str(e)}")
            return None
    
    def _receive_pipe_message(self) -> Optional[Dict[str, Any]]:
        """Receive message from pipe."""
        try:
            if not self.pipe_conn:
                return None
            
            if self.pipe_conn.poll(0.1):
                message_bytes = self.pipe_conn.recv_bytes()
                message = json.loads(message_bytes.decode('utf-8'))
                return message
            
            return None
            
        except Exception as e:
            logger.error(f"Pipe receive failed: {str(e)}")
            return None
    
    def disconnect(self) -> None:
        """Disconnect from IPC server."""
        try:
            self.is_connected = False
            
            if self.server_socket:
                self.server_socket.close()
                self.server_socket = None
            
            if self.client_socket:
                self.client_socket.close()
                self.client_socket = None
            
            if self.pipe_conn:
                self.pipe_conn.close()
                self.pipe_conn = None
            
            logger.info("IPC connection closed")
            
        except Exception as e:
            logger.error(f"IPC disconnect failed: {str(e)}")
    
    def get_connection_info(self) -> Dict[str, Any]:
        """Get connection information."""
        return {
            "connection_type": self.connection_type,
            "is_connected": self.is_connected,
            "is_server": self.is_server,
            "connection_id": self.connection_id,
            "timeout": self.timeout,
            "registered_handlers": list(self.message_handlers.keys()),
            "statistics": self.stats.copy()
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get IPC statistics."""
        stats = self.stats.copy()
        
        if stats["messages_sent"] > 0 or stats["messages_received"] > 0:
            stats["success_rate"] = (
                (stats["messages_sent"] + stats["messages_received"]) /
                (stats["messages_sent"] + stats["messages_received"] + stats["connection_failures"])
            )
        else:
            stats["success_rate"] = 0.0
        
        return stats
    
    def reset_statistics(self) -> None:
        """Reset IPC statistics."""
        self.stats = {
            "messages_sent": 0,
            "messages_received": 0,
            "connection_failures": 0,
            "total_bytes_transferred": 0
        }
        logger.info("IPC statistics reset")
