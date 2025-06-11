#!/usr/bin/env python3
import can
import threading
import time
import json
import logging
import asyncio
import websockets
import hashlib
import hmac
import subprocess
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DynamicCANGateway:
    """
    Dynamic CAN Gateway with python-can library
    vcan0 <-> vcan2+ <-> vcan1
    """
    
    def __init__(self):
        self.external_vcan = 'vcan0'  # Infotainment
        self.internal_vcan = 'vcan1'  # Engine
        
        self.running = True
        self.next_vcan_id = 2
        self.session_vcans = {}  # {session_id: vcan_name}
        self.bridges = {}  # {bridge_name: {'threads': [], 'buses': []}}
        
        # WebSocket clients
        self.clients = {}
        
        # Authentication
        self.secret_key = b"CTF_CAN_GATEWAY_SECRET_2024"
        self.challenges = {}
        
        # Load routing rules
        self.load_routing_rules()
        
    def load_routing_rules(self):
        """Load routing rules"""
        self.routing_rules = {
            "external_to_internal": {
                "allowed_ranges": [[0x300, 0x3FF]],
                "blocked_ids": [0x3FF],
                "default_policy": "deny"
            },
            "internal_to_external": {
                "allowed_ranges": [[0x700, 0x7FF]],
                "blocked_ids": [0x7E0, 0x7DF],
                "default_policy": "deny"
            }
        }
    
    def create_session_vcan(self, session_id):
        """Create a dedicated vcan interface for a session"""
        vcan_name = f"vcan{self.next_vcan_id}"
        self.next_vcan_id += 1
        
        try:
            # Create vcan interface
            subprocess.run(['ip', 'link', 'add', 'dev', vcan_name, 'type', 'vcan'], 
                         check=True, capture_output=True)
            subprocess.run(['ip', 'link', 'set', 'up', vcan_name], 
                         check=True, capture_output=True)
            
            self.session_vcans[session_id] = vcan_name
            logger.info(f"Created {vcan_name} for session {session_id}")
            
            # Create bridges
            self.create_bridge(vcan_name, self.external_vcan)  # Session <-> Infotainment
            self.create_bridge(vcan_name, self.internal_vcan)  # Session <-> Engine
            
            return vcan_name
            
        except Exception as e:
            logger.error(f"Failed to create session vcan: {e}")
            return None
    
    def create_bridge(self, vcan1, vcan2):
        """Create bridge between two vcan interfaces using python-can"""
        bridge_name = f"{vcan1}-{vcan2}"
        
        try:
            # Create CAN buses
            bus1 = can.interface.Bus(channel=vcan1, bustype='socketcan')
            bus2 = can.interface.Bus(channel=vcan2, bustype='socketcan')
            
            # Create bridge threads
            thread1 = threading.Thread(
                target=self.bridge_worker,
                args=(bus1, bus2, vcan1, vcan2, bridge_name),
                daemon=True
            )
            thread2 = threading.Thread(
                target=self.bridge_worker,
                args=(bus2, bus1, vcan2, vcan1, bridge_name),
                daemon=True
            )
            
            thread1.start()
            thread2.start()
            
            self.bridges[bridge_name] = {
                'threads': [thread1, thread2],
                'buses': [bus1, bus2]
            }
            
            logger.info(f"Bridge created: {bridge_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create bridge {bridge_name}: {e}")
            return False
    
    def bridge_worker(self, src_bus, dst_bus, src_name, dst_name, bridge_name):
        """Worker thread for bridging CAN messages"""
        while self.running and bridge_name in self.bridges:
            try:
                msg = src_bus.recv(timeout=0.1)
                if msg:
                    # Apply routing rules
                    if self.should_route(msg.arbitration_id, src_name, dst_name):
                        dst_bus.send(msg)
                        logger.debug(f"{src_name}->{dst_name}: ID=0x{msg.arbitration_id:03X}")
            except can.CanError as e:
                if self.running:
                    logger.error(f"CAN error in bridge {bridge_name}: {e}")
            except Exception as e:
                if self.running:
                    logger.error(f"Bridge error {bridge_name}: {e}")
                break
    
    def should_route(self, can_id, src_vcan, dst_vcan):
        """Check if message should be routed based on rules"""
        # Always allow session-to-session traffic
        if src_vcan.startswith('vcan') and dst_vcan.startswith('vcan'):
            if int(src_vcan[4:]) >= 2 and int(dst_vcan[4:]) >= 2:
                return True
        
        # Determine direction
        if src_vcan == self.external_vcan and dst_vcan == self.internal_vcan:
            direction = "external_to_internal"
        elif src_vcan == self.internal_vcan and dst_vcan == self.external_vcan:
            direction = "internal_to_external"
        else:
            return True  # Allow all other traffic
            
        rules = self.routing_rules.get(direction, {})
        
        # Check blocked IDs
        if can_id in rules.get('blocked_ids', []):
            return False
            
        # Check allowed ranges
        for range_item in rules.get('allowed_ranges', []):
            if isinstance(range_item, list) and len(range_item) == 2:
                if range_item[0] <= can_id <= range_item[1]:
                    return True
                    
        return rules.get('default_policy', 'allow') == 'allow'
    
    def remove_session_vcan(self, session_id):
        """Remove session-specific vcan interface"""
        if session_id in self.session_vcans:
            vcan_name = self.session_vcans[session_id]
            
            # Remove bridges
            bridges_to_remove = []
            for bridge_name in self.bridges:
                if vcan_name in bridge_name:
                    bridges_to_remove.append(bridge_name)
            
            for bridge_name in bridges_to_remove:
                bridge_info = self.bridges[bridge_name]
                for bus in bridge_info['buses']:
                    try:
                        bus.shutdown()
                    except:
                        pass
                del self.bridges[bridge_name]
                logger.info(f"Removed bridge: {bridge_name}")
            
            # Remove vcan interface
            try:
                subprocess.run(['ip', 'link', 'del', vcan_name], 
                             check=True, capture_output=True)
                logger.info(f"Removed {vcan_name}")
            except:
                pass
                
            del self.session_vcans[session_id]
    
    async def handle_websocket(self, websocket, path):
        """Handle WebSocket client connections"""
        client_id = id(websocket)
        
        try:
            # Generate challenge
            challenge = hashlib.sha256(str(time.time()).encode()).hexdigest()
            self.challenges[challenge] = time.time()
            
            # Send welcome
            await websocket.send(json.dumps({
                'type': 'welcome',
                'challenge': challenge
            }))
            
            # Wait for auth
            auth_msg = await websocket.recv()
            auth_data = json.loads(auth_msg)
            
            if auth_data['type'] == 'auth':
                expected = hmac.new(
                    self.secret_key,
                    auth_data['challenge'].encode(),
                    hashlib.sha256
                ).hexdigest()
                
                if auth_data['response'] == expected:
                    session_id = int(time.time() * 1000) & 0xFFFF
                    vcan_name = self.create_session_vcan(session_id)
                    
                    if vcan_name:
                        self.clients[client_id] = {
                            'websocket': websocket,
                            'session_id': session_id,
                            'vcan': vcan_name,
                            'bus': can.interface.Bus(channel=vcan_name, bustype='socketcan')
                        }
                        
                        await websocket.send(json.dumps({
                            'type': 'auth_success',
                            'session_id': session_id,
                            'vcan': vcan_name
                        }))
                        
                        # Start CAN listener
                        listener_task = asyncio.create_task(
                            self.session_can_listener(client_id)
                        )
                        
                        # Handle messages
                        async for message in websocket:
                            await self.process_client_message(client_id, message)
                else:
                    await websocket.send(json.dumps({
                        'type': 'auth_failed'
                    }))
                    
        except websockets.exceptions.ConnectionClosed:
            logger.info(f"Client {client_id} disconnected")
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
        finally:
            if client_id in self.clients:
                client_info = self.clients[client_id]
                try:
                    client_info['bus'].shutdown()
                except:
                    pass
                self.remove_session_vcan(client_info['session_id'])
                del self.clients[client_id]
    
    async def process_client_message(self, client_id, message):
        """Process message from WebSocket client"""
        try:
            data = json.loads(message)
            client_info = self.clients[client_id]
            
            if data['type'] == 'can_send':
                can_id = data['can_id']
                can_data = bytes(data['data'])
                
                # Send CAN message
                msg = can.Message(
                    arbitration_id=can_id,
                    data=can_data,
                    is_extended_id=False
                )
                client_info['bus'].send(msg)
                logger.debug(f"Client {client_id} sent CAN ID=0x{can_id:03X}")
                
        except Exception as e:
            logger.error(f"Error processing client message: {e}")
    
    async def session_can_listener(self, client_id):
        """Listen for CAN messages on session vcan"""
        client_info = self.clients[client_id]
        
        while client_id in self.clients:
            try:
                # Non-blocking receive
                msg = client_info['bus'].recv(timeout=0.01)
                if msg:
                    await client_info['websocket'].send(json.dumps({
                        'type': 'can_receive',
                        'can_id': msg.arbitration_id,
                        'data': list(msg.data)
                    }))
            except:
                await asyncio.sleep(0.01)
    
    async def start_websocket_server(self):
        """Start WebSocket server"""
        async with websockets.serve(self.handle_websocket, '0.0.0.0', 8080):
            logger.info("WebSocket server started on port 8080")
            await asyncio.Future()  # Run forever
    
    def setup_main_vcans(self):
        """Setup main vcan interfaces"""
        for vcan in [self.external_vcan, self.internal_vcan]:
            try:
                # Check if exists
                result = subprocess.run(['ip', 'link', 'show', vcan], 
                                      capture_output=True)
                if result.returncode != 0:
                    # Create if doesn't exist
                    subprocess.run(['ip', 'link', 'add', 'dev', vcan, 'type', 'vcan'])
                    subprocess.run(['ip', 'link', 'set', 'up', vcan])
                    logger.info(f"Created {vcan}")
            except Exception as e:
                logger.error(f"Error setting up {vcan}: {e}")
    
    def start(self):
        """Start the gateway"""
        logger.info("Dynamic CAN Gateway starting...")
        
        # Setup main interfaces
        self.setup_main_vcans()
        
        # Start WebSocket server
        try:
            asyncio.run(self.start_websocket_server())
        except KeyboardInterrupt:
            logger.info("Shutting down...")
        finally:
            self.running = False
            
            # Clean up all bridges
            for bridge_info in self.bridges.values():
                for bus in bridge_info['buses']:
                    try:
                        bus.shutdown()
                    except:
                        pass
            
            # Clean up all session vcans
            for session_id in list(self.session_vcans.keys()):
                self.remove_session_vcan(session_id)

if __name__ == "__main__":
    gateway = DynamicCANGateway()
    gateway.start()