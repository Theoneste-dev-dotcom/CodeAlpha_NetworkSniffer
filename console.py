import time
from abc import ABC, abstractmethod

class Output(ABC):
    """Interface for further processing/output of captured data."""

    def __init__(self, subject):
        subject.register(self)

    @abstractmethod
    def update(self, *args, **kwargs):
        pass

class OutputToScreen(Output):
    """Output data from a decoded frame to screen."""
    
    def __init__(self, subject, *, display_data: bool):
        super().__init__(subject)
        self._display_data = display_data
        self._frame = None
        self._initialize()

    @staticmethod
    def _initialize() -> None:
        print("\n[>>>] Packet Sniffer initialized. Waiting for incoming data. Press Ctrl-C to abort..\n")

    def update(self, frame) -> None:
        self._frame = frame
        self._display_output_header()
        self._display_protocol_info()

    def _display_output_header(self) -> None:
        local_time = time.strftime("%H:%M:%S", time.localtime())
        print(f"[>] Frame #{self._frame.packet_num} at {local_time}")
        print(f"    [+] Frame Length: {self._frame.length} bytes")

    def _display_protocol_info(self) -> None:
        """Iterate over protocols in the queue and display relevant data."""
        for proto in self._frame.protocol_queue:
            try:
                getattr(self, f"_display_{proto.lower()}_data")()
            except AttributeError:
                print(f"    [+] {proto.upper()}: Unknown Protocol")

    def _display_ethernet_data(self) -> None:
        print(f"    [+] Ethernet Frame:")
        print(f"        - Source MAC Address: {self._frame.src_mac}")
        print(f"        - Destination MAC Address: {self._frame.dest_mac}")

    def _display_ipv4_data(self) -> None:
        print(f"    [+] IPv4 Packet:")
        print(f"        - Source IP Address: {self._frame.src_ip}")
        print(f"        - Destination IP Address: {self._frame.dest_ip}")
        print(f"        - Packet Length: {self._frame.length} bytes")

    def _display_icmp_data(self) -> None:
        print(f"    [+] ICMP Packet:")
        print(f"        - Type: {self._frame.icmp_type}")
        print(f"        - Code: {self._frame.icmp_code}")
        print(f"        - Checksum: {self._frame.icmp_checksum}")

    def _display_tcp_data(self) -> None:
        print(f"    [+] TCP Packet:")
        print(f"        - Source Port: {self._frame.src_port}")
        print(f"        - Destination Port: {self._frame.dest_port}")
        print(f"        - Sequence Number: {self._frame.seq_num}")
        print(f"        - Acknowledgment Number: {self._frame.ack_num}")
        if self._display_data:
            print(f"        - Data: {self._frame.data[:50]}..." if len(self._frame.data) > 50 else f"        - Data: {self._frame.data}")

    def _display_udp_data(self) -> None:
        print(f"    [+] UDP Packet:")
        print(f"        - Source Port: {self._frame.src_port}")
        print(f"        - Destination Port: {self._frame.dest_port}")
        print(f"        - Length: {self._frame.length} bytes")
        if self._display_data:
            print(f"        - Data: {self._frame.data[:50]}..." if len(self._frame.data) > 50 else f"        - Data: {self._frame.data}")

    def _display_ftp_data(self) -> None:
        print(f"    [+] FTP Packet:")
        print(f"        - Command: {self._frame.ftp_command}")
        print(f"        - Response: {self._frame.ftp_response}")
        if self._display_data:
            print(f"        - Content: {self._frame.data[:50]}..." if len(self._frame.data) > 50 else f"        - Content: {self._frame.data}")
