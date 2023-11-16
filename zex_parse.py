import json
import struct
file_path = "Client_PLg.0.log"
format_string = 'H B I H H '

def parse_game_packet_udp(packet_data):
    client_id = packet_data[:2]
    packet_type = packet_data[2]
    packet_seq = packet_data[3] #this is a rolling 256 number that gets reused
    total_packets = packet_data[4]
    fragment_number = packet_data[5]
    payload = packet_data[6:]
    
    return {
        'client_id': client_id,
        'packet_type': packet_type,
        'packet_seq': packet_seq,
        'total_packets': total_packets,
        'fragment_number': fragment_number,
        'payload': payload
    }

def parse_packet_main(packet_data):

    rflag = False
    rmsg_incoming_seq = None
    rmsg_size_real = None
    rmsg_count = None
    rmsg_data = None
    
    current_pos = 0

    frame = int.from_bytes(packet_data[current_pos:current_pos + 4], 'little')
    current_pos += 4

    rmsg_flag = packet_data[current_pos]
    current_pos += 1
    if rmsg_flag != 0: # Sequenced r_messages
        rflag = True
        # Advanced fields parsing based on the flag
        rmsg_incoming_seq = int.from_bytes(packet_data[current_pos:current_pos + 4], 'little') 
        current_pos += 4  # Update position
        rmsg_size = int.from_bytes(packet_data[current_pos:current_pos + 2], 'little')  
        current_pos += 2  # Update position
        rmsg_size_real = (rmsg_size & 0x7FFF) - 2
        rmsg_size_real = rmsg_size_real % 65536  # Ensure it's in the range of an unsigned short

        rmsg_count = int.from_bytes(packet_data[current_pos:current_pos + 2], 'little') 
        current_pos += 2  # Update position
        rmsg_data = packet_data[current_pos:current_pos + rmsg_size_real]  # Extracting data based on rmsg_size_real
        current_pos += rmsg_size_real  # Update position

    last_ack = int.from_bytes(packet_data[current_pos:current_pos + 4], 'little')
    current_pos += 4

    ack_bits = int.from_bytes(packet_data[current_pos:current_pos + 4], 'little')
    current_pos += 4

    delta = int.from_bytes(packet_data[current_pos:current_pos + 4], 'little')
    current_pos += 4

    base = int.from_bytes(packet_data[current_pos:current_pos + 4], 'little')
    current_pos += 4

    compressed_body = int.from_bytes(packet_data[current_pos:current_pos + 4], 'little')
    current_pos += 4

    uncompressed_body = int.from_bytes(packet_data[current_pos:current_pos + 4], 'little')
    current_pos += 4

    component_count = int.from_bytes(packet_data[current_pos:current_pos + 2], 'little')
    current_pos += 2

    timestamp = int.from_bytes(packet_data[current_pos:current_pos + 4], 'little')
    current_pos += 4

    component_data = packet_data[current_pos:]  # All remaining bytes

    return {
        'rmsg_frame': frame,
        'rmsg_flag': rmsg_flag,
        'rmsg_incoming_seq': rmsg_incoming_seq if rmsg_flag == True else None,
        'rmsg_size': rmsg_size_real if rmsg_flag == True else None,
        'rmsg_count': rmsg_count if rmsg_flag == True else None,
        'rmsg_data': rmsg_data.hex() if rmsg_flag == True else None,
        'last_ack': last_ack,
        'ack_bits': ack_bits,        
        'delta': delta,
        'base': base,
        'compressed_body': compressed_body,
        'uncompressed_body': uncompressed_body,
        'component_count': component_count,
        'timestamp': timestamp,
        'component_data': component_data.hex() if compressed_body != 0 else None,
    }
# Helper function to reconstruct packets
def reconstruct_packets(entries):
    reconstructed_packets = {}
    
    for entry in entries:
        entry_data = json.loads(entry)
        packet_hex = entry_data['data']['packet']
        direction = entry_data['event']
        if direction == "net.packet.recv": # Each side has its own stream, don't let the streams touch. (this could be easier by just embedding, I don't want the rest of the string here)
            direction = "recv"
        else:
            direction = "sent"
        packet_data = bytes.fromhex(packet_hex)
        packet_type = packet_data[2]
        if packet_type == 130:
            packet_info = parse_game_packet_udp(packet_data) #Take the UDP Packets and make sure they are combined into full game packets.
            packet_key = (packet_info['client_id'].hex(), packet_info['packet_seq'], direction)
            # Initialize the packet array if it's a new packet
            if packet_key not in reconstructed_packets:
                reconstructed_packets[packet_key] = [None] * packet_info['total_packets']

            # Store the fragment in the corresponding position
            reconstructed_packets[packet_key][packet_info['fragment_number']] = packet_info['payload'][6:] if packet_info['fragment_number'] != 0 else packet_info['payload']

            # Check if the packet is fully reconstructed
            if None not in reconstructed_packets[packet_key]:
                # Process the complete packet
                complete_packet = b''.join(reconstructed_packets[packet_key])
                print(complete_packet.hex())
                complete_packet_output = parse_packet_main(complete_packet)
                print(f"{str(packet_key)} : {str(complete_packet_output)}")
               # if complete_packet_output['rmsg_data'] is not None:
               #     print(f"{complete_packet_output['rmsg_count']} R-MSG's detected: {complete_packet_output['rmsg_data']}")

                # Delete the processed packet to free up memory
                del reconstructed_packets[packet_key]
        elif packet_type == 129: #TODO: Process out Ping
            # Unpack the data if it matches the expected length
            if len(packet_data) == struct.calcsize(format_string):
                session, packet_type, timestamp, bps, peer = struct.unpack(format_string, packet_data)
                print(f"Session: {session}, Type: {packet_type}, Timestamp: {timestamp}, Bps: {bps}, Peer: {peer}")
            else:
                print(f"Error: Data length mismatch. Expected {struct.calcsize(format_string)}, but got {len(packet_data)}")
        elif packet_type == 128: #TODO: Process out Pong
            # Unpack the data if it matches the expected length
            if len(packet_data) == struct.calcsize(format_string):
                session, packet_type, timestamp, bps, peer = struct.unpack(format_string, packet_data)
                print(f"Session: {session}, Type: {packet_type}, Timestamp: {timestamp}, Bps: {bps}, Peer: {peer}")
            else:
                print(f"Error: Data length mismatch. Expected {struct.calcsize(format_string)}, but got {len(packet_data)}")

        elif packet_type == 00: #TODO: Process out Tokens
            print(f"token: {packet_data.hex()}")
        else:
            print(f"Unknown: {packet_type.hex()} : {packet_data.hex()}")
    # At the end, there might be some incomplete packets left in the storage
    for packet_key in reconstructed_packets:
        if None in reconstructed_packets[packet_key]:
            # Handle or log incomplete packets
            print(f"Incomplete packet detected: {packet_key}")

# Read log file and parse packet entries
with open(file_path, 'r') as file:
    packet_log_content = file.readlines()

# Reconstruct the packets
processed_packets = reconstruct_packets(packet_log_content)

