import can
import time
import sys
from collections import defaultdict

class CANAnalyzer:
    def __init__(self, interface='vcan0'):
        try:
            self.bus = can.interface.Bus(channel=interface, bustype='socketcan')
        except Exception as e:
            print(f"CAN interface connection failed: {e}")
            sys.exit(1)
        
        self.message_count = defaultdict(int)
        self.last_messages = {}
    
    def analyze_traffic(self, duration=30):
        """CAN 트래픽 분석"""
        print(f"Analyzing CAN traffic for {duration} seconds...")
        print("CAN ID | Count | Last Data")
        print("-" * 40)
        
        start_time = time.time()
        
        try:
            for msg in self.bus:
                if time.time() - start_time > duration:
                    break
                
                can_id = f"0x{msg.arbitration_id:03X}"
                self.message_count[can_id] += 1
                self.last_messages[can_id] = msg.data.hex().upper()
                
                # 실시간 출력
                print(f"\r{can_id:6} | {self.message_count[can_id]:5} | {self.last_messages[can_id]}", end="")
                time.sleep(0.1)
        
        except KeyboardInterrupt:
            print("\nAnalysis stopped by user")
        
        print(f"\n\nAnalysis complete!")
        self.print_summary()
    
    def print_summary(self):
        """분석 결과 요약"""
        print("\n=== Traffic Summary ===")
        for can_id in sorted(self.message_count.keys()):
            print(f"{can_id}: {self.message_count[can_id]} messages")
        
        print("\n=== Potential ECU Communication ===")
        print("0x123: Infotainment → Gateway")
        print("0x124: Gateway → Infotainment") 
        print("0x700: Gateway → Engine")
        print("0x701: Engine → Gateway")

def main():
    if len(sys.argv) > 1:
        duration = int(sys.argv[1])
    else:
        duration = 30
    
    analyzer = CANAnalyzer()
    analyzer.analyze_traffic(duration)

if __name__ == "__main__":
    main()
