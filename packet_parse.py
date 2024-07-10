import json
from datetime import datetime

file_path = "Client_PLg.0.log"
# Helper function to parse log entry
def parse_packet_udp(log_entry):
    entry_data = json.loads(log_entry)
    direction = entry_data['event']
    if direction == 'net.packet.recv':
        direction = 'in_'
    else:
        direction = 'out'
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
    try:
        packet_seq = packet_data[3]
        total_packets = packet_data[4]

        fragment_number = packet_data[5]
    except:
        print(f"packet {log_entry} failed")
    try:
        payload = packet_data[6:]
    except:
        print(f"packet {packet_seq} failed")
    return {
        'direction': direction,
        'client_id': client_id,
        'packet_type': packet_type,
        'packet_seq': packet_seq,
        'total_packets': total_packets,
        'fragment_number': fragment_number,
        'payload': payload
    }

def parse_packet_ping(packet_data):
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

def parse_packet_main(packet_data, direction):
    rmsg_frame = int.from_bytes(packet_data[:4], 'little')
    rmsg_flag = packet_data[4]

 #   print(f"Frame: {rmsg_frame}, Flag: {rmsg_flag}")
    # Initialize the current position
    current_pos = 5  # Position after rmsg_flag
    if rmsg_flag != 0:
        # split the flag into its individual bits
        # bit 0: 1 = Sequenced Rmsg present, 0 = no Sequenced Rmsg present
        # bit 1: 1 = Unsequenced Rmsg present, 0 = no Unsequenced Rmsg present

        if rmsg_flag & 0x01:
            rmsg_incoming_seq = int.from_bytes(packet_data[current_pos:current_pos + 4], 'little')  # Adjust the slicing as per your packet structure

            # Sequenced Rmsg present
    #      print(f"Advanced fields parsing for frame {rmsg_frame}, flag {rmsg_flag}")
            # Advanced fields parsing based on the flag
            current_pos += 4  # Update position
            rmsg_size = int.from_bytes(packet_data[current_pos:current_pos + 2], 'little')  # Adjust slicing; convert bytes to int
            current_pos += 2  # Update position
            rmsg_size_real = (rmsg_size & 0x7FFF) - 2 # Your specified calculation
            rmsg_count = int.from_bytes(packet_data[current_pos:current_pos + 2], 'little') # Adjust slicing
            current_pos += 2  # Update positionx
            rmsg_data = packet_data[current_pos:current_pos + rmsg_size_real]  # Extracting data based on rmsg_size_real
            current_pos += rmsg_size_real  # Update position
        if rmsg_flag & 0x02:
            # Advanced fields parsing based on the flag
#            current_pos += 4  # Update position
            unseq_rmsg_size = int.from_bytes(packet_data[current_pos:current_pos + 2], 'little')  # Adjust slicing; convert bytes to int
            current_pos += 2  # Update position
            unseq_rmsg_size_real = (unseq_rmsg_size & 0x7FFF) - 2 # Your specified calculation
            unseq_rmsg_count = int.from_bytes(packet_data[current_pos:current_pos + 2], 'little') # Adjust slicing
            current_pos += 2  # Update positionx
            unseq_rmsg_data = packet_data[current_pos:current_pos + unseq_rmsg_size_real]  # Extracting data based on rmsg_size_real
            current_pos += unseq_rmsg_size_real  # Update position
    last_ack = int.from_bytes(packet_data[current_pos:current_pos + 4], 'little')
    current_pos += 4  # Update position
    ack_bits = int.from_bytes(packet_data[current_pos:current_pos + 4], 'little')
    # convert ack_bits to binary
    ack_bits = bin(ack_bits)
    # sum up the number of 1s in the binary string
    total_ack_bits = ack_bits.count('1')
    prob_new_base = last_ack - total_ack_bits
    current_pos += 4  # Update position
    delta = int.from_bytes(packet_data[current_pos:current_pos + 4], 'little')
    current_pos += 4  # Update position
    base = int.from_bytes(packet_data[current_pos:current_pos + 4], 'little')
    current_pos += 4  # Update position
    compressed_body = int.from_bytes(packet_data[current_pos:current_pos + 4], 'little')
    current_pos += 4  # Update position
    uncompressed_body = int.from_bytes(packet_data[current_pos:current_pos + 4], 'little')
    current_pos += 4  # Update position
    component_count = int.from_bytes(packet_data[current_pos:current_pos + 2], 'little')
    current_pos += 2  # Update position
    timestamp = int.from_bytes(packet_data[current_pos:current_pos + 4], 'little')
    current_pos += 4  # Update position
    component_data = packet_data[current_pos:current_pos + compressed_body]  # Extracting data based on rmsg_size_real
    # create key value pairs for the output for direction + delta and base range

    return {
        'frame': rmsg_frame,
        'flag': rmsg_flag,
        'incoming_seq': rmsg_incoming_seq if rmsg_flag & 0x01 else  None,
      #  'rmsgsize': rmsg_size_real if rmsg_flag & 0x01 else  None,
      #  'unseq_rmsgsize': unseq_rmsg_size_real if rmsg_flag & 0x02 else  None,
        'count': rmsg_count if rmsg_flag & 0x01 else  None,
        'unseq_count': unseq_rmsg_count if rmsg_flag & 0x02 else  None,
       # 'data': rmsg_data if rmsg_flag != 0 else None,
        'last_ack': last_ack,
        'ack_bits': ack_bits,        
        'delta': delta,
        'base': base,
      #  'compressed_body': compressed_body,
        'uncompressed_body': uncompressed_body,
        'component_count': component_count,
        'timestamp': timestamp,
        # if last_ack and prob_new_base are == then just return a single output 
        'base_range': f"{prob_new_base}-{last_ack}" if prob_new_base != last_ack else prob_new_base, 
      #  'component_data': component_data,
    }
# Helper function to reconstruct packets
def reconstruct_packets(entries):
    reconstructed_packets = {}
    pingpong = 0
    last_in_packet_seq = None
    out_rollover_counter = 0
    last__out_packet_seq = None
    in_rollover_counter = 0
    for entry in entries:
        packet_info = parse_packet_udp(entry)
        # Check if the packet is a control packet and long enough to contain the packet sequence
        if packet_info['packet_type'] == 130 and len(packet_info['payload']) >= 12:

            packet_seq = packet_info['packet_seq']
            if packet_info['direction'] != 'in_':

                if last__out_packet_seq is not None and packet_seq < last__out_packet_seq:
                    out_rollover_counter += 1
                last__out_packet_seq = packet_seq
                packet_key = (packet_info['client_id'], packet_seq, packet_info['direction'], out_rollover_counter,packet_info['packet_type'])

            else:
                if last_in_packet_seq is not None and packet_seq < last_in_packet_seq:
                    in_rollover_counter += 1
                last_in_packet_seq = packet_seq
                packet_key = (packet_info['client_id'], packet_seq, packet_info['direction'], in_rollover_counter,packet_info['packet_type'])

            
            if packet_key not in reconstructed_packets:
                reconstructed_packets[packet_key] = [None] * packet_info['total_packets']
            else:
                if reconstructed_packets[packet_key][packet_info['fragment_number']] is not None:
                    print(f"Duplicate packet {packet_key} {packet_info['fragment_number']}")    
            
            if packet_info['fragment_number'] == 0:
                reconstructed_packets[packet_key][packet_info['fragment_number']] = packet_info['payload']
            else:
                try:
                    # order the packets based on the fragment number
                    for i in range(packet_info['fragment_number'], len(reconstructed_packets[packet_key])):
                        if reconstructed_packets[packet_key][i] is None:
                            reconstructed_packets[packet_key][i] = packet_info['payload']
                            break
                except:
                    print(f"skipping {packet_key}")
        elif packet_info['packet_type'] == 0 or packet_info['packet_type'] == 128 or packet_info['packet_type'] == 129:
            packet_key = (packet_info['client_id'], packet_info['packet_seq'], packet_info['direction'], pingpong, packet_info['packet_type'])
            pingpong += 1
            if packet_key not in reconstructed_packets:
                reconstructed_packets[packet_key] = [packet_info['payload']]
            else:
                print(f"Duplicate packet {packet_key}")
    
    return reconstructed_packets

# Read log file and parse packet entries
with open(file_path, 'r') as file:
    packet_log_content = file.readlines()

# Reconstruct the packets
processed_packets = reconstruct_packets(packet_log_content)
delta_check = {}

# Save reconstructed packets to a binary file
output_file_path = 'reconstructed_packets.bin'
with open(output_file_path, 'wb') as f:
    for packet_key in processed_packets:
        acked_delta = 0
        valid_base = False
        upper_val = 0
        lower_val = 0
        complete_packet = b''.join(fragment for fragment in processed_packets[packet_key] if fragment is not None)
        if packet_key[4] == 130:
            complete_packet_output = parse_packet_main(complete_packet, packet_key[2])
            delta_check_key = (packet_key[2], complete_packet_output['delta'])
            delta_check[delta_check_key] = complete_packet_output['base_range']

            if packet_key[2] == 'in_':
                opposite_direction = 'out'
            else:
                opposite_direction = 'in_'

            try:
                acked_delta = delta_check[(opposite_direction, complete_packet_output['last_ack'])]
                if isinstance(acked_delta, str) and '-' in acked_delta:
                    upper_lower = acked_delta.split('-')
                    lower_val = int(upper_lower[0])
                    upper_val = int(upper_lower[1])
                #   print(f"acked_delta: {acked_delta}, lower_val: {lower_val}, upper_val: {upper_val}")
                else:
                    lower_val = upper_val = int(acked_delta)
                #  print(f"acked_delta: {acked_delta}, single value: {upper_val}")
            except KeyError:
                print(f"Failed to find {opposite_direction} {complete_packet_output['last_ack']} in delta_check")

            if lower_val <= complete_packet_output['base'] <= upper_val:
                valid_base = True
                #print(f"{packet_key} {complete_packet_output['base']} is within the range {acked_delta}")
            else:
                print(f"{packet_key} {complete_packet_output['base']} is not in {acked_delta}")

            print(f"{packet_key} {str(complete_packet_output)}")
            f.write(complete_packet)
        elif packet_key[4] == 128 or packet_key[4] == 129:
            
            ping_packet_output = parse_packet_ping(complete_packet)
            print(f"{packet_key} {str(ping_packet_output)}")
            f.write(complete_packet)