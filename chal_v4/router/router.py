#!/usr/bin/env python3
import socket
import threading
import docker
import uuid
import time
import logging
import subprocess

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ECUChallengeRouter:
    def __init__(self, listen_port=1337):
        self.listen_port = listen_port
        self.docker_client = docker.from_env()
        self.active_instances = {}
        self.lock = threading.Lock()
        
    def create_user_environment(self, user_id):
        """각 사용자를 위한 독립적인 Docker 환경 생성"""
        instance_id = str(uuid.uuid4())[:8]
        logger.info(f"Creating environment for user {user_id}, instance {instance_id}")
        
        try:
            # 사용자 전용 네트워크 생성
            network_name = f"ecu_net_{instance_id}"
            network = self.docker_client.networks.create(
                network_name,
                driver="bridge",
                internal=True
            )
            
            # 환경 변수 설정
            env_vars = {
                'USER_ID': instance_id,
                'INSTANCE_ID': instance_id
            }
            
            containers = {}
            
            # CAN Bridge 컨테이너
            containers['can_bridge'] = self.docker_client.containers.run(
                "ecu_ctf/can_bridge:latest",
                detach=True,
                name=f"can_bridge_{instance_id}",
                network=network_name,
                environment=env_vars,
                remove=True,
                mem_limit="128m",
                cpu_quota=50000  # 0.5 CPU
            )
            
            # Gateway ECU 컨테이너
            containers['gateway'] = self.docker_client.containers.run(
                "ecu_ctf/gateway:latest",
                detach=True,
                name=f"gateway_{instance_id}",
                network=network_name,
                environment=env_vars,
                remove=True,
                mem_limit="128m",
                cpu_quota=50000
            )
            
            # ECM 컨테이너
            containers['ecm'] = self.docker_client.containers.run(
                "ecu_ctf/ecm:latest",
                detach=True,
                name=f"ecm_{instance_id}",
                network=network_name,
                environment=env_vars,
                remove=True,
                mem_limit="128m",
                cpu_quota=50000
            )
            
            # Infotainment ECU 컨테이너 (마지막에 생성)
            containers['infotainment'] = self.docker_client.containers.run(
                "ecu_ctf/infotainment:latest",
                detach=True,
                name=f"infotainment_{instance_id}",
                network=network_name,
                environment=env_vars,
                ports=1337,  # 랜덤 포트 할당
                remove=True,
                mem_limit="256m",
                cpu_quota=50000
            )
            
            # 할당된 포트 확인
            containers['infotainment'].reload()
            for _ in range(10):
                ports = containers['infotainment'].ports
                logger.info(f"ports: {ports}")
                if ports and '1337/tcp' in ports and ports['1337/tcp']:
                    infotainment_port = ports['1337/tcp'][0]['HostPort']
                    break
                time.sleep(0.5)
                containers['infotainment'].reload()
            else:
                raise Exception("Infotainment port not mapped")
            
            return {
                'instance_id': instance_id,
                'containers': containers,
                'network': network,
                'infotainment_port': int(infotainment_port),
                'created_at': time.time()
            }
            
        except Exception as e:
            logger.error(f"Failed to create environment: {e}")
            # 정리
            if 'containers' in locals():
                for container in containers.values():
                    try:
                        container.stop()
                        container.remove()
                    except:
                        pass
            if 'network' in locals():
                try:
                    network.remove()
                except:
                    pass
            raise
    
    def cleanup_instance(self, instance):
        """인스턴스 정리"""
        logger.info(f"Cleaning up instance {instance['instance_id']}")
        
        for container in instance['containers'].values():
            try:
                container.stop(timeout=5)
            except:
                pass
                
        try:
            instance['network'].remove()
        except:
            pass
    
    def handle_client(self, client_sock, addr):
        """클라이언트 연결 처리"""
        user_id = f"{addr[0]}:{addr[1]}"
        instance = None
        backend_sock = None
        
        try:
            # 환경 생성
            instance = self.create_user_environment(user_id)
            
            with self.lock:
                self.active_instances[user_id] = instance
            
            # Infotainment ECU로 연결
            time.sleep(2)  # 컨테이너 시작 대기
            backend_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            backend_sock.connect(('localhost', instance['infotainment_port']))
            
            # 환영 메시지
            welcome_msg = f"""
╔════════════════════════════════════════════╗
║        ECU Simulator CTF Challenge         ║
║                                            ║
║  Instance ID: {instance['instance_id']}              ║
║  Your dedicated environment is ready!      ║
╚════════════════════════════════════════════╝

Connecting to Infotainment ECU...

"""
            client_sock.send(welcome_msg.encode())
            
            # 양방향 프록시
            self.proxy_connection(client_sock, backend_sock)
            
        except Exception as e:
            logger.error(f"Error handling client {user_id}: {e}")
            error_msg = f"Error creating environment: {e}\n"
            try:
                client_sock.send(error_msg.encode())
            except:
                pass
                
        finally:
            # 정리
            if backend_sock:
                backend_sock.close()
            client_sock.close()
            
            if instance:
                self.cleanup_instance(instance)
                
            with self.lock:
                if user_id in self.active_instances:
                    del self.active_instances[user_id]
    
    def proxy_connection(self, client, backend):
        """양방향 데이터 프록시"""
        def forward(src, dst):
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    dst.send(data)
            except:
                pass
            finally:
                src.close()
                dst.close()
        
        t1 = threading.Thread(target=forward, args=(client, backend))
        t2 = threading.Thread(target=forward, args=(backend, client))
        
        t1.start()
        t2.start()
        
        t1.join()
        t2.join()
    
    def start(self):
        """라우터 시작"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', self.listen_port))
        server.listen(50)
        
        logger.info(f"ECU Challenge Router listening on port {self.listen_port}")
        
        # 정리 스레드
        cleanup_thread = threading.Thread(target=self.cleanup_old_instances)
        cleanup_thread.daemon = True
        cleanup_thread.start()
        
        try:
            while True:
                client, addr = server.accept()
                logger.info(f"New connection from {addr}")
                
                thread = threading.Thread(target=self.handle_client, args=(client, addr))
                thread.daemon = True
                thread.start()
                
        except KeyboardInterrupt:
            logger.info("Shutting down...")
        finally:
            server.close()
            
            # 모든 인스턴스 정리
            with self.lock:
                for instance in self.active_instances.values():
                    self.cleanup_instance(instance)
    
    def cleanup_old_instances(self):
        """오래된 인스턴스 자동 정리"""
        while True:
            time.sleep(60)  # 1분마다 체크
            
            with self.lock:
                current_time = time.time()
                to_remove = []
                
                for user_id, instance in self.active_instances.items():
                    # 30분 이상 된 인스턴스 정리
                    if current_time - instance['created_at'] > 1800:
                        to_remove.append(user_id)
                
                for user_id in to_remove:
                    logger.info(f"Cleaning up old instance for {user_id}")
                    self.cleanup_instance(self.active_instances[user_id])
                    del self.active_instances[user_id]

if __name__ == "__main__":
    router = ECUChallengeRouter()
    router.start()