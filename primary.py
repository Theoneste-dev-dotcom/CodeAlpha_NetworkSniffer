import socket
import struct

class PacketSniffer:
    """PacketSniffer captures and decodes Ethernet frames and protocols."""

    def __init__(self):
        self._observers = []

    def register(self, observer):
        """Register an observer to receive frame updates."""
        self._observers.append(observer)

    def notify_observers(self, frame):
        """Notify all observers with the captured frame data."""
        for observer in self._observers:
            observer.update(frame)

    def listen(self, interface=None):
        """Listen on a specified network interface or all interfaces."""
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

        while True:
            raw_frame, _ = conn.recvfrom(65536)
            frame = self._decode_frame(raw_frame)
            self.notify_observers(frame)
            yield frame

    def _decode_frame(self, raw_frame):
        """Decode the raw frame and classify protocols (simplified for demonstration)."""
        ethernet_header = struct.unpack('!6s6sH', raw_frame[:14])
        ether_type = socket.ntohs(ethernet_header[2])

        # Classify protocols and set up a protocol queue for display
        protocol_queue = ['ethernet']
        if ether_type == 0x0800:
            protocol_queue.append('ipv4')
            ip_header = raw_frame[14:34]
            protocol = ip_header[9]
            
            if protocol == 1:
                protocol_queue.append('icmp')
            elif protocol == 6:
                protocol_queue.append('tcp')
            elif protocol == 17:
                protocol_queue.append('udp')

        return FrameData(packet_num=1, protocol_queue=protocol_queue)  # Adjust `packet_num` increment as needed

class FrameData:
    """Frame data structure for packet analysis."""
    def __init__(self, packet_num, protocol_queue):
        self.packet_num = packet_num
        self.protocol_queue = protocol_queue
