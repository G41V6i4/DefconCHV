class UDSService:
    def __init__(self, ecu):
        self.ecu = ecu
        
    def process_request(self, data):
        # Basic UDS implementation
        return bytes([0x7F, data[0], 0x11])
