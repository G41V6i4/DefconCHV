import asyncio
import websockets
import can
import json
import logging
import time
import struct
from collections import defaultdict
from auth_protocol import AuthProtocol
import threading
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CANGateway:
    def __init__(self):
        self.can_interface = os.environ.get('CAN_INTERFACE', 'vcan0')
        self.clients = {}
        self.client_sessions = defaultdict(dict)
        self.auth_protocol = AuthProtocol()
        self.bus = None
        self.running = False
        
        # Load routing rules
        with open('routing_rules.json') as f:
            self.routing_rules = json.load(f)
            
        # Statistics
        self.stats = {
            'messages_sent': 0,
            'messages_received': 0,
            'active_clients': 0
        }
        
    def setup_can(self):
        """Initialize CAN interface"""
        try:
            self.bus = can.interface.Bus(self.can_interface, bustype='socketcan')
            logger.info(f"CAN interface {self.can_interface} initialized")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize CAN interface: {e}")
            return False
            
    async def handle_client(self, websocket, path):
        """Handle individual client connections"""
        client_id = id(websocket)
        client_ip = websocket.remote_address[0]
        
        logger.info(f"New client connected: {client_ip} (ID: {client_id})")
        self.clients[client_id] = {
            'websocket': websocket,
            'authenticated': False,
            'session_id': None,
            'ip': client_ip,
            'connected_at': time.time()
        }
        self.stats['active_clients'] += 1
        
        try:
            # Send welcome message
            await websocket.send(json.dumps({
                'type': 'welcome',
                'message': 'Connected to CAN Gateway. Please authenticate.',
                'challenge': self.auth_protocol.generate_challenge()
            }))
            
            async for message in websocket:
                await self.process_client_message(client_id, message)
                
        except websockets.exceptions.ConnectionClosed:
            logger.info(f"Client {client_id} disconnected")
        except Exception as e:
            logger.error(f"Error handling client {client_id}: {e}")
        finally:
            await self.cleanup_client(client_id)
            
    async def process_client_message(self, client_id, message):
        """Process incoming messages from clients"""
        try:
            data = json.loads(message)
            client = self.clients[client_id]
            
            if data['type'] == 'auth':
                # Handle authentication
                if self.auth_protocol.verify_response(data['response'], data.get('challenge')):
                    client['authenticated'] = True
                    client['session_id'] = self.generate_session_id()
                    
                    await client['websocket'].send(json.dumps({
                        'type': 'auth_success',
                        'session_id': client['session_id'],
                        'message': 'Authentication successful'
                    }))
                    logger.info(f"Client {client_id} authenticated with session {client['session_id']}")
                else:
                    await client['websocket'].send(json.dumps({
                        'type': 'auth_failed',
                        'message': 'Authentication failed'
                    }))
                    
            elif data['type'] == 'can_send' and client['authenticated']:
                # Handle CAN message sending
                can_id = data['can_id']
                can_data = data['data']
                
                # Check routing rules
                if self.check_routing_permission(client, can_id):
                    # Inject session ID into message
                    session_bytes = struct.pack('>H', client['session_id'])
                    modified_data = session_bytes + bytes(can_data)[:6]  # Max 8 bytes total
                    
                    # Send CAN message
                    msg = can.Message(
                        arbitration_id=can_id,
                        data=modified_data,
                        is_extended_id=data.get('is_extended', False)
                    )
                    
                    self.bus.send(msg)
                    self.stats['messages_sent'] += 1
                    
                    # Log for debugging
                    logger.debug(f"Sent CAN message from client {client_id}: ID=0x{can_id:X}")
                    
                    await client['websocket'].send(json.dumps({
                        'type': 'send_success',
                        'can_id': can_id
                    }))
                else:
                    await client['websocket'].send(json.dumps({
                        'type': 'send_failed',
                        'message': 'Access denied for this CAN ID'
                    }))
                    
            elif data['type'] == 'stats' and client['authenticated']:
                # Send statistics
                await client['websocket'].send(json.dumps({
                    'type': 'stats',
                    'data': self.stats
                }))
                
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON from client {client_id}")
        except Exception as e:
            logger.error(f"Error processing message from client {client_id}: {e}")
            
    def check_routing_permission(self, client, can_id):
        """Check if client is allowed to send to specific CAN ID"""
        # Implement your routing rules logic here
        # For CTF, you might want to restrict certain CAN IDs
        
        # Example: Block direct access to engine ECU diagnostic IDs
        restricted_ids = self.routing_rules.get('restricted_ids', [])
        if can_id in restricted_ids and not client.get('elevated_privileges'):
            return False
            
        return True
        
    def generate_session_id(self):
        """Generate unique session ID for client"""
        return int(time.time() * 1000) & 0xFFFF
        
    async def can_receive_loop(self):
        """Continuously receive CAN messages and route to appropriate clients"""
        while self.running:
            try:
                msg = self.bus.recv(timeout=0.1)
                if msg:
                    await self.route_can_message(msg)
            except Exception as e:
                logger.error(f"CAN receive error: {e}")
            await asyncio.sleep(0.001)
            
    async def route_can_message(self, msg):
        """Route received CAN messages to appropriate clients"""
        # Extract session ID from message data
        if len(msg.data) >= 2:
            session_id = struct.unpack('>H', msg.data[:2])[0]
            
            # Find client with matching session ID
            for client_id, client in self.clients.items():
                if client.get('session_id') == session_id and client['authenticated']:
                    try:
                        await client['websocket'].send(json.dumps({
                            'type': 'can_receive',
                            'can_id': msg.arbitration_id,
                            'data': list(msg.data),
                            'timestamp': msg.timestamp
                        }))
                        self.stats['messages_received'] += 1
                    except:
                        pass
                        
    async def cleanup_client(self, client_id):
        """Clean up disconnected client"""
        if client_id in self.clients:
            del self.clients[client_id]
            self.stats['active_clients'] -= 1
            
    async def admin_interface(self, websocket, path):
        """Admin interface for monitoring"""
        if path == '/admin':
            await websocket.send(json.dumps({
                'type': 'admin_stats',
                'clients': len(self.clients),
                'stats': self.stats
            }))
            
    async def start(self):
        """Start the gateway server"""
        if not self.setup_can():
            return
            
        self.running = True
        
        # Start CAN receive loop
        can_task = asyncio.create_task(self.can_receive_loop())
        
        # Start WebSocket servers
        client_server = await websockets.serve(
            self.handle_client, '0.0.0.0', 8080
        )
        
        admin_server = await websockets.serve(
            self.admin_interface, '0.0.0.0', 8081
        )
        
        logger.info("CAN Gateway started on port 8080 (clients) and 8081 (admin)")
        
        try:
            await asyncio.Future()  # Run forever
        except KeyboardInterrupt:
            logger.info("Shutting down...")
        finally:
            self.running = False
            await can_task
            client_server.close()
            admin_server.close()

if __name__ == "__main__":
    gateway = CANGateway()
    asyncio.run(gateway.start())