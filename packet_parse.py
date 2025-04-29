import json
from datetime import datetime
from collections import defaultdict
import struct
import logging
from io import BytesIO
from typing import List, Optional

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Set to DEBUG to capture all logs
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class Component:
    def __init__(self, entity_id: int, resource_id: int, component_size: int,
                 component_id: int, component_buffer: bytes):
        self.EntityId = entity_id
        self.ResourceId = resource_id
        self.ComponentSize = component_size
        self.ComponentId = component_id
        self.componentBuffer = component_buffer

    @classmethod
    def GetComponent(cls, entity_id: int, resource_id: int, component_size: int,
                    component_id: int, component_buffer: bytes) -> 'Component':
        return cls(entity_id, resource_id, component_size, component_id, component_buffer)

    def __str__(self):
        return (f"Component(EntityId={self.EntityId}, ResourceId={self.ResourceId}, "
                f"ComponentSize={self.ComponentSize}, ComponentId={self.ComponentId}, "
                f"componentBuffer={self.componentBuffer.hex()})")

class ZeroRunLengthCompression:
    def __init__(self, input_stream: BytesIO):
        self.input_stream = input_stream

    def decompress(self, expected_size: int) -> bytes:
        """
        Decompresses data using Zero Run-Length Compression (ZRL).
        The ZRL scheme is assumed to work as follows:
            - Read one byte at a time.
            - If the byte is non-zero, append it to the output.
            - If the byte is zero, the next byte specifies how many zeros to append.

        Args:
            expected_size (int): The number of uncompressed bytes expected.

        Returns:
            bytes: The decompressed data.
        """
        output = bytearray()
        decompressed_bytes = 0
        while decompressed_bytes < expected_size:
            flag_byte = self.input_stream.read(1)
            if not flag_byte:
                # End of stream reached unexpectedly
                logger.error(f"ZRL Decompression: Unexpected end of stream. Expected {expected_size} bytes, got {decompressed_bytes} bytes.")
                break

            if flag_byte != b'\x00':
                # Non-zero byte, append directly
                output.append(flag_byte[0])
                decompressed_bytes += 1
                logger.debug(f"ZRL: Appended byte 0x{flag_byte[0]:02X}, Total: {decompressed_bytes}/{expected_size}")
            else:
                # Zero byte, next byte specifies run length
                run_length_byte = self.input_stream.read(1)
                if not run_length_byte:
                    logger.error("ZRL Decompression: Unexpected end of stream after zero flag.")
                    break
                run_length = run_length_byte[0]
                output.extend(b'\x00' * run_length)
                decompressed_bytes += run_length
                logger.debug(f"ZRL: Appended {run_length} zeros, Total: {decompressed_bytes}/{expected_size}")

        if decompressed_bytes < expected_size:
            logger.warning(f"ZRL Decompression: Expected {expected_size} bytes, but only {decompressed_bytes} bytes were decompressed.")

        # Truncate to expected size in case of over-decompression
        return bytes(output[:expected_size])

class Snapshot:
    def __init__(self, data: bytes):
        self.Components: List[Component] = []
        self.parse_snapshot(data)

    def parse_snapshot(self, data: bytes):
        reader = BytesIO(data)
        while reader.tell() < len(data):
            component = self.parse_component(reader)
            if component:
                self.Components.append(component)
                logger.debug(str(component))
            else:
                logger.warning("Failed to parse component. Skipping remaining data.")
                break  # Exit if a component fails to parse

    def parse_component(self, reader: BytesIO) -> Optional[Component]:
        try:
            # Read the header byte
            header_byte_data = reader.read(1)
            if not header_byte_data:
                logger.error("Unexpected end of stream while reading header byte.")
                return None
            header_byte = header_byte_data[0]
            logger.debug(f"Header Byte: 0x{header_byte:02X}")

            # Extract fields from header_byte
            action = (header_byte >> 6) & 0x03  # bits 7..6
            entity_id_length = ((header_byte >> 4) & 0x03) + 1  # bits 5..4 + 1
            use_zero_run_length = ((header_byte & 0x01) == 0)  # bit 0
            is_large_component_id = ((header_byte & 0x08) != 0)  # bit 3

            logger.debug(f"Action: {action}, EntityID Length: {entity_id_length}, "
                         f"Use ZRL: {use_zero_run_length}, Is Large Component ID: {is_large_component_id}")

            # Determine lengths based on action
            if action != 3:  # If not DeleteEntity
                component_id_length = 2 if is_large_component_id else 1
            else:
                component_id_length = 0

            if action == 0:  # UpdateFromDefault
                resource_id_length = ((header_byte >> 1) & 0x03) + 1  # bits 2..1 +1
                component_size_length = 1
            elif action == 1:  # UpdateFromPrevious
                resource_id_length = 0
                component_size_length = 1
            elif action == 2:  # DeleteComponent
                resource_id_length = 0
                component_size_length = 0
            elif action == 3:  # DeleteEntity
                resource_id_length = 0
                component_size_length = 0
            else:
                logger.error(f"Unknown action type: {action}")
                return None

            logger.debug(f"ComponentID Length: {component_id_length}, "
                         f"ResourceID Length: {resource_id_length}, "
                         f"ComponentSize Length: {component_size_length}")

            # Helper function to read little-endian unsigned int
            def read_little_uint(length: int) -> int:
                if length == 0:
                    return 0
                bytes_read = reader.read(length)
                if len(bytes_read) != length:
                    logger.error(f"Expected {length} bytes, got {len(bytes_read)} bytes.")
                    raise ValueError(f"Insufficient bytes for field. Expected {length}, got {len(bytes_read)}.")
                value = int.from_bytes(bytes_read, 'little')
                logger.debug(f"Read {length} bytes: 0x{value:X}")
                return value

            # Read EntityId, ComponentId, ResourceId, ComponentSize
            entity_id = read_little_uint(entity_id_length)
            component_id = read_little_uint(component_id_length)
            resource_id = read_little_uint(resource_id_length)
            component_size = read_little_uint(component_size_length)

            logger.debug(f"Parsed Fields -> EntityID: {entity_id}, ComponentID: {component_id}, "
                         f"ResourceID: {resource_id}, ComponentSize: {component_size}")

            # Read component data
            component_buffer = b''
            if component_size > 0:
                if use_zero_run_length:
                    # Initialize ZRL decompressor
                    zrl = ZeroRunLengthCompression(reader)
                    logger.debug("Using Zero Run-Length Compression for component data.")
                    component_buffer = zrl.decompress(component_size)
                    actual_size = len(component_buffer)
                    logger.debug(f"Decompressed Component Buffer Length: {actual_size} bytes")
                    if actual_size < component_size:
                        logger.error(f"Expected {component_size} bytes for component data, got {actual_size} bytes.")
                        raise ValueError(f"Insufficient bytes for component data. Expected {component_size}, got {actual_size}.")
                else:
                    logger.debug("Component data is uncompressed.")
                    component_buffer = reader.read(component_size)
                    actual_size = len(component_buffer)
                    logger.debug(f"Read Component Buffer Length: {actual_size} bytes")
                    if actual_size != component_size:
                        logger.error(f"Expected {component_size} bytes for component data, got {actual_size} bytes.")
                        raise ValueError(f"Insufficient bytes for component data. Expected {component_size}, got {actual_size}.")

            logger.debug(f"Component Buffer Data: {component_buffer.hex()}")

            return Component.GetComponent(
                entity_id=entity_id,
                resource_id=resource_id,
                component_size=component_size,
                component_id=component_id,
                component_buffer=component_buffer
            )

        except Exception as e:
            logger.exception(f"Exception while parsing component: {e}")
            return None

# Helper function to parse log entry
def parse_packet_udp(log_entry):
    try:
        entry_data = json.loads(log_entry)
        direction = entry_data['event']
        direction = 'in_' if direction == 'net.packet.recv' else 'out'
        packet_hex = entry_data['data']['packet']

        packet_data = bytes.fromhex(packet_hex)
        client_id = packet_data[:2]
        packet_type = packet_data[2]
        
        if packet_type == 0:
            return {
                'direction': direction,
                'client_id': client_id,
                'packet_type': packet_type,
                'packet_seq': 999,
                'payload': packet_data[3:]
            }
        
        if len(packet_data) < 6:
            logger.error(f"Packet data too short for type {packet_type}. Data: {packet_data.hex()}")
            return None

        packet_seq = packet_data[3]
        total_packets = packet_data[4]
        fragment_number = packet_data[5]
        payload = packet_data[6:]
        
        return {
            'direction': direction,
            'client_id': client_id,
            'packet_type': packet_type,
            'packet_seq': packet_seq,
            'total_packets': total_packets,
            'fragment_number': fragment_number,
            'payload': payload
        }
    except (KeyError, IndexError, json.JSONDecodeError) as e:
        logger.error(f"Failed to parse packet: {e} | Log Entry: {log_entry}")
        return None  # Explicitly return None for failed parses

def parse_packet_ping(packet_data):
    try:
        current_pos = 0
        Timestamp = int.from_bytes(packet_data[current_pos:current_pos + 4], 'little')
        CleanTimestamp = datetime.utcfromtimestamp(Timestamp).strftime('%Y-%m-%d %H:%M:%S')
        current_pos += 4
        Bps = int.from_bytes(packet_data[current_pos:current_pos + 2], 'little')
        current_pos += 2
        peer = int.from_bytes(packet_data[current_pos:current_pos + 2], 'little')
        current_pos += 2
        throttle = int.from_bytes(packet_data[current_pos:current_pos + 1], 'little')
        return {
            'timestamp': Timestamp,
            'cleantimestamp': CleanTimestamp,
            'bps': Bps,
            'peer': peer,
            'throttle': throttle
        }
    except (IndexError, ValueError) as e:
        logger.error(f"Failed to parse ping packet: {e} | Data: {packet_data.hex()}")
        return None

def parse_packet_main(packet_data, direction):
    try:
        # Define the initial fixed part of the packet
        header_format = '<IB'  # Little endian: unsigned int (4 bytes), unsigned char (1 byte)
        header_size = struct.calcsize(header_format)
        if len(packet_data) < header_size:
            logger.error(f"Packet data too short for header. Expected {header_size} bytes, got {len(packet_data)} bytes.")
            return None
        rmsg_frame, rmsg_flag = struct.unpack_from(header_format, packet_data, 0)

        current_pos = header_size

        rmsg_incoming_seq = None
        rmsg_size_real = None
        rmsg_count = None
        unseq_rmsg_size_real = None
        unseq_rmsg_count = None
        rmsg_data = None
        unseq_rmsg_data = None

        if rmsg_flag != 0:
            # Parse sequenced Rmsg
            if rmsg_flag & 0x01:
                seq_format = '<IHH'  # unsigned int, unsigned short, unsigned short
                seq_size = struct.calcsize(seq_format)
                if len(packet_data) < current_pos + seq_size:
                    logger.error(f"Packet data too short for sequenced Rmsg. Expected additional {seq_size} bytes.")
                    return None
                rmsg_incoming_seq, rmsg_size, rmsg_count = struct.unpack_from(seq_format, packet_data, current_pos)
                rmsg_size_real = (rmsg_size & 0x7FFF) - 2
                current_pos += seq_size
                rmsg_data = packet_data[current_pos:current_pos + rmsg_size_real]
                current_pos += rmsg_size_real

            # Parse unsequenced Rmsg
            if rmsg_flag & 0x02:
                unseq_format = '<HH'  # unsigned short, unsigned short
                unseq_size = struct.calcsize(unseq_format)
                if len(packet_data) < current_pos + unseq_size:
                    logger.error(f"Packet data too short for unsequenced Rmsg. Expected additional {unseq_size} bytes.")
                    return None
                unseq_rmsg_size, unseq_rmsg_count = struct.unpack_from(unseq_format, packet_data, current_pos)
                unseq_rmsg_size_real = (unseq_rmsg_size & 0x7FFF) - 2
                current_pos += unseq_size
                unseq_rmsg_data = packet_data[current_pos:current_pos + unseq_rmsg_size_real]
                current_pos += unseq_rmsg_size_real

        # Continue parsing fixed-size fields
        fixed_format = '<IIIIIIHI'  # Adjust format as per actual structure
        fixed_size = struct.calcsize(fixed_format)
        if len(packet_data) < current_pos + fixed_size:
            logger.error(f"Packet data too short for fixed-size fields. Expected additional {fixed_size} bytes.")
            return None
        (
            last_ack,
            ack_bits,
            delta,
            base,
            compressed_body,
            uncompressed_body,
            component_count,
            timestamp
        ) = struct.unpack_from(fixed_format, packet_data, current_pos)
        current_pos += fixed_size

        # Extract component_data
        if len(packet_data) < current_pos + compressed_body:
            logger.error(f"Packet data too short for component_data. Expected {compressed_body} bytes, got {len(packet_data) - current_pos} bytes.")
            component_data = packet_data[current_pos:]
            logger.warning(f"Using available {len(component_data)} bytes for component_data.")
        else:
            component_data = packet_data[current_pos:current_pos + compressed_body]

        # Calculate prob_new_base
        ack_bits_bin = bin(ack_bits)
        total_ack_bits = ack_bits_bin.count('1')
        prob_new_base = last_ack - total_ack_bits

        base_range = f"{prob_new_base}-{last_ack}" if prob_new_base != last_ack else str(prob_new_base)

        # Debugging statements
        logger.debug(f"Parsed Packet:")
        logger.debug(f"  Frame: {rmsg_frame}")
        logger.debug(f"  Flag: {rmsg_flag}")
        if rmsg_incoming_seq is not None:
            logger.debug(f"  Incoming Seq: {rmsg_incoming_seq}")
        if rmsg_size_real is not None:
            logger.debug(f"  Rmsg Size Real: {rmsg_size_real}")
        if rmsg_count is not None:
            logger.debug(f"  Rmsg Count: {rmsg_count}")
        if unseq_rmsg_size_real is not None:
            logger.debug(f"  Unseq Rmsg Size Real: {unseq_rmsg_size_real}")
        if unseq_rmsg_count is not None:
            logger.debug(f"  Unseq Rmsg Count: {unseq_rmsg_count}")
        logger.debug(f"  Last Ack: {last_ack}")
        logger.debug(f"  Ack Bits: {ack_bits_bin}")
        logger.debug(f"  Delta: {delta}")
        logger.debug(f"  Base: {base}")
        logger.debug(f"  Uncompressed Body: {uncompressed_body}")
        logger.debug(f"  Component Count: {component_count}")
        logger.debug(f"  Timestamp: {timestamp}")
        logger.debug(f"  Base Range: {base_range}")

        return {
            'frame': rmsg_frame,
            'flag': rmsg_flag,
            'incoming_seq': rmsg_incoming_seq,
            'rmsg_size_real': rmsg_size_real,
            'count': rmsg_count,
            'unseq_rmsg_size_real': unseq_rmsg_size_real,
            'unseq_rmsg_count': unseq_rmsg_count,
            'last_ack': last_ack,
            'ack_bits': ack_bits_bin,        
            'delta': delta,
            'base': base,
            'uncompressed_body': uncompressed_body,
            'component_count': component_count,
            'timestamp': timestamp,
            'component_data': component_data,
            'base_range': base_range, 
        }
    except struct.error as e:
        logger.error(f"Struct error while parsing packet: {e} | Data: {packet_data.hex()}")
        return None

def lzw_decompress(compressed_data):
    """
    Decompresses LZW-compressed data.

    Args:
        compressed_data (bytes): The LZW-compressed data.

    Returns:
        bytes: The decompressed data.
    """
    # Initialize the dictionary with single-byte entries
    dict_size = 256
    dictionary = {i: bytes([i]) for i in range(dict_size)}
    
    # Variables for decompression
    result = bytearray()
    prev_code = None
    bits = 0
    bit_buffer = 0
    code_size = 9  # Starting with 9 bits
    max_code_size = 16  # Maximum code size (adjust as needed)
    next_code = dict_size
    
    # Convert compressed_data to a list for efficient popping
    compressed = list(compressed_data)
    
    def get_code():
        nonlocal bits, bit_buffer, compressed, code_size
        while bits < code_size:
            if len(compressed) == 0:
                break
            byte = compressed.pop(0)
            bit_buffer |= byte << bits
            bits += 8
        if bits >= code_size:
            code = bit_buffer & ((1 << code_size) - 1)
            bit_buffer >>= code_size
            bits -= code_size
            return code
        return None
    
    while True:
        code = get_code()
        if code is None:
            break
        
        if code in dictionary:
            entry = dictionary[code]
        elif code == next_code and prev_code is not None:
            entry = dictionary[prev_code] + dictionary[prev_code][:1]
        else:
            raise ValueError(f"Bad compressed code: {code}")
        
        result += entry
        
        if prev_code is not None:
            if next_code < (1 << max_code_size):
                dictionary[next_code] = dictionary[prev_code] + entry[:1]
                next_code += 1
                # Increase code size if needed
                if next_code >= (1 << code_size) and code_size < max_code_size:
                    code_size += 1
        
        prev_code = code
    
    return bytes(result)

def reconstruct_packets(entries):
    partial_packets = defaultdict(lambda: {
        'total_packets': None,
        'received_fragments': {}
    })

    pingpong = 0
    last_in_seq = None
    in_rollover_counter = 0
    last_out_seq = None
    out_rollover_counter = 0

    for entry in entries:
        packet_info = parse_packet_udp(entry)
        if not packet_info:
            continue  # Skip failed parses

        ptype = packet_info['packet_type']
        direction = packet_info['direction']
        seq = packet_info['packet_seq']
        client_id = packet_info['client_id']

        if ptype == 130 and 'total_packets' in packet_info and 'fragment_number' in packet_info:
            total_packets = packet_info['total_packets']
            fragment_num = packet_info['fragment_number']

            # Determine rollover
            if direction == 'in_':
                if last_in_seq is not None and seq < last_in_seq:
                    in_rollover_counter += 1
                last_in_seq = seq
                rollover_count = in_rollover_counter
            else:
                if last_out_seq is not None and seq < last_out_seq:
                    out_rollover_counter += 1
                last_out_seq = seq
                rollover_count = out_rollover_counter

            packet_key = (client_id, seq, direction, rollover_count, ptype)
            ppacket = partial_packets[packet_key]

            if ppacket['total_packets'] is None:
                ppacket['total_packets'] = total_packets

            # Check for duplicate fragments
            if fragment_num in ppacket['received_fragments']:
                logger.warning(f"Duplicate fragment {packet_key}, fragment {fragment_num}")
            ppacket['received_fragments'][fragment_num] = packet_info['payload']

        elif ptype in (0, 128, 129):
            packet_key = (client_id, seq, direction, pingpong, ptype)
            pingpong += 1

            ppacket = partial_packets[packet_key]
            if ppacket['total_packets'] is None:
                ppacket['total_packets'] = 1
            else:
                logger.warning(f"Duplicate or unexpected second arrival for {packet_key}")

            ppacket['received_fragments'][0] = packet_info['payload']

    # Final assembly
    reconstructed_packets = {}
    for packet_key, ppacket in partial_packets.items():
        total_frags = ppacket['total_packets'] or 0
        fragments = ppacket['received_fragments']

        if total_frags == 0:
            continue  # Skip packets with no fragments

        # Identify missing fragments
        missing = [i for i in range(total_frags) if i not in fragments]
        if missing:
            logger.warning(f"Missing fragments {missing} for packet {packet_key}")

        # Assemble fragments in order
        try:
            assembled = b''.join(fragments[i] for i in sorted(fragments.keys()))
            reconstructed_packets[packet_key] = assembled
        except KeyError as e:
            logger.error(f"Failed to assemble packet {packet_key}: Missing fragment {e}")
        except TypeError as e:
            logger.error(f"Type error while assembling packet {packet_key}: {e}")

    return reconstructed_packets

def process_packet_components(packet_data: bytes):
    """
    Processes the component data within a packet using the Snapshot class.
    """
    snapshot = Snapshot(packet_data)
    for component in snapshot.Components:
        # Further processing of each component
        # For example, decompress componentBuffer if needed
        logger.info(f"Processed Component: {component}")

# Test function
def test_snapshot_parsing():
    """
    Test the Snapshot class with sample data.
    """
    # Example component:
    # Header byte:
    # - Action: 0 (UpdateFromDefault) => bits 7-6: 00
    # - EntityIdLength: 2 => bits 5-4: 01 (1 + 1)
    # - IsLargeComponentId: False => bit 3: 0
    # - ResourceIdLength: 2 => bits 2-1: 01 (1 + 1)
    # - IsUncompressed: True => bit 0: 1
    # Header byte: 00 01 01 1 => 0b00010101 => 0x15
    header_byte = 0x15

    # EntityId: 2 bytes, e.g., 0x1234 => 4660
    entity_id = (0x34 << 8) | 0x12  # 0x1234 = 4660

    # ComponentId: 1 byte, e.g., 0x56 => 86
    component_id = 0x56

    # ResourceId: 3 bytes, e.g., 0x789ABC => 0x789ABC = 789ABC (decimal: 789ABC is not valid)
    # Correction: If resource_id_length=3, we need to read 3 bytes. Assuming little-endian:
    resource_id = (0xBC << 16) | (0x9A << 8) | 0x78  # 0x789ABC = 789ABC

    # ComponentSize: 1 byte, e.g., 0x03 => 3
    component_size = 3

    # Component Data: Uncompressed, 3 bytes, e.g., b'\xAA\xBB\xCC'
    component_data = b'\xAA\xBB\xCC'

    # Construct the binary data
    binary_data = bytearray()
    binary_data.append(header_byte)
    binary_data.extend(entity_id.to_bytes(2))
    binary_data.extend(component_id.to_bytes(1))
    binary_data.extend(resource_id.to_bytes(3))
    binary_data.extend(component_size.to_bytes(1))
    binary_data.extend(component_data)

    # Initialize Snapshot
    snapshot = Snapshot(bytes(binary_data))

    # Verify the parsed component
    assert len(snapshot.Components) == 1, "Should have parsed exactly one component."
    component = snapshot.Components[0]
    assert component.EntityId == 4660, f"Expected EntityId=4660, got {component.EntityId}"
    assert component.ComponentId == 86, f"Expected ComponentId=86, got {component.ComponentId}"
    assert component.ResourceId == 0x789ABC, f"Expected ResourceId=0x789ABC, got {hex(component.ResourceId)}"
    assert component.ComponentSize == 3, f"Expected ComponentSize=3, got {component.ComponentSize}"
    assert component.componentBuffer == b'\xAA\xBB\xCC', f"Expected componentBuffer=b'\\xAA\\xBB\\xCC', got {component.componentBuffer}"

    print("Test passed: Snapshot parsed correctly.")

def main():
    file_path = "Client_PLg.0.log"

    # Read log file and parse packet entries
    try:
        with open(file_path, 'r') as file:
            packet_log_content = file.readlines()
    except FileNotFoundError:
        logger.error(f"Log file {file_path} not found.")
        return

    # Reconstruct the packets
    processed_packets = reconstruct_packets(packet_log_content)
    delta_check = {}

    # Save reconstructed packets to a binary file
    output_file_path = 'reconstructed_packets.bin'
    try:
        with open(output_file_path, 'wb') as f:
            for packet_key, complete_packet in processed_packets.items():
                if not isinstance(complete_packet, bytes):
                    logger.warning(f"Packet {packet_key} is not bytes. Skipping.")
                    continue  # Skip non-bytes packets

                if packet_key[4] == 130:
                    complete_packet_output = parse_packet_main(complete_packet, packet_key[2])
                    if not complete_packet_output:
                        logger.error(f"Failed to parse main packet {packet_key}. Skipping.")
                        continue

                    # Decompress component_data if it exists
                    component_data = complete_packet_output.get('component_data')
                    component_count = complete_packet_output.get('component_count')
                    if component_data:
                        try:
                            snapshot = Snapshot(component_data)
                            for component in snapshot.Components:
                                logger.info(str(component))
                                # Further processing of components
                        except Exception as e:
                            logger.error(f"Error processing components for {packet_key}: {e}")
                            continue

                    # Store in delta_check
                    delta_check_key = (packet_key[2], complete_packet_output['delta'])
                    delta_check[delta_check_key] = complete_packet_output['base_range']

                    opposite_direction = 'out' if packet_key[2] == 'in_' else 'in_'

                    try:
                        acked_delta = delta_check.get((opposite_direction, complete_packet_output['last_ack']))
                        if acked_delta is None:
                            logger.warning(f"Failed to find {opposite_direction} {complete_packet_output['last_ack']} in delta_check")
                            lower_val = upper_val = None
                        else:
                            if isinstance(acked_delta, str) and '-' in acked_delta:
                                lower_val, upper_val = map(int, acked_delta.split('-'))
                            else:
                                lower_val = upper_val = int(acked_delta)

                        if lower_val is not None and upper_val is not None:
                            if lower_val <= complete_packet_output['base'] <= upper_val:
                                # Base is within the expected range
                                pass  # Handle as needed
                            else:
                                logger.warning(f"{packet_key} {complete_packet_output['base']} is not in {acked_delta}")

                    except KeyError:
                        logger.error(f"Failed to find {opposite_direction} {complete_packet_output['last_ack']} in delta_check")
                        lower_val = upper_val = None

                    logger.debug(f"{packet_key} {str(complete_packet_output)}")
                    f.write(complete_packet)
                
                elif packet_key[4] in (128, 129):
                    ping_packet_output = parse_packet_ping(complete_packet)
                    if not ping_packet_output:
                        logger.error(f"Failed to parse ping packet {packet_key}. Skipping.")
                        continue

                    logger.debug(f"{packet_key} {str(ping_packet_output)}")
                    f.write(complete_packet)
    except Exception as e:
        logger.exception(f"Failed to write to output file {output_file_path}: {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        test_snapshot_parsing()
    else:
        main()
