import json
from datetime import datetime
from collections import defaultdict
from sqlite3.dbapi2 import Timestamp
import struct
import logging
from io import BytesIO
from typing import List, Optional
import io

# Configure logging to output to console and file
logging.basicConfig(
    level=logging.DEBUG,  # Set to DEBUG to capture all logs
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("packet_parse.log"),  # Log to file
        logging.StreamHandler()  # Log to console
    ]
)

logger = logging.getLogger(__name__)

class Component:
    def __init__(self, header: List, entity_id: int, resource_id: int, component_size: int,
                 component_id: int, component_buffer: bytes):
        self.Header = header
        self.EntityId = entity_id
        self.ResourceId = resource_id
        self.ComponentSize = component_size
        self.ComponentId = component_id
        self.componentBuffer = component_buffer

    @classmethod
    def GetComponent(cls, header: List, entity_id: int, resource_id: int, component_size: int,
                    component_id: int, component_buffer: bytes) -> 'Component':
        return cls(header, entity_id, resource_id, component_size, component_id, component_buffer)

    def __str__(self):
        return (f"Component(Header={self.Header}, EntityId={hex(self.EntityId)}, ResourceId={hex(self.ResourceId)}, "
                f"ComponentSize={self.ComponentSize}, ComponentId={hex(self.ComponentId)}, "
                f"componentBuffer={self.componentBuffer.hex()})")


class ZeroRunLengthCompression:
    def __init__(self, incoming_stream_or_maxsize):
        self.zero_count = 0
        self.compressed_size = 0

        if isinstance(incoming_stream_or_maxsize, io.BytesIO):
            self.compressed_stream = incoming_stream_or_maxsize
            self.maximum_size = 0xFFFF
        else:
            self.maximum_size = incoming_stream_or_maxsize
            self.compressed_stream = io.BytesIO()

    def dispose(self):
        if self.compressed_stream:
            self.compressed_stream.close()

    def read_bytes(self, length):
        output = bytearray()
        for _ in range(length):
            output.append(self.read_byte())
        return bytes(output)

    def write_bytes(self, data):
        for value in data:
            self.write_byte(value)

    def end(self):
        self.write_run_length()
        if self.maximum_size == -1:
            return -1
        return self.compressed_size

    def write_run_length(self):
        if self.zero_count > 0:
            if self.compressed_size + 2 > self.maximum_size:
                self.maximum_size = -1
                return False

            self.compressed_stream.write(bytes([0, self.zero_count]))
            self.compressed_size += 2
            self.zero_count = 0
        return True

    def write_byte(self, value):
        if value != 0 or self.zero_count >= 255:
            if not self.write_run_length():
                self.maximum_size = -1
                return False

        if value != 0:
            if self.compressed_size + 1 > self.maximum_size:
                self.maximum_size = -1
                return False

            self.compressed_stream.write(bytes([value]))
            self.compressed_size += 1
        else:
            self.zero_count += 1

        return True

    def read_byte(self):
        if self.zero_count == 0:
            value = self.read_internal()
            if value != 0:
                return value
            self.zero_count = self.read_internal()

        self.zero_count -= 1
        return 0

    def read_internal(self):
        self.compressed_size += 1
        value = self.compressed_stream.read(1)
        if not value:
            raise EOFError("Unexpected end of stream")
        return value[0]

class LZWCompressionData:
    LZW_DICT_BITS = 12
    LZW_DICT_SIZE = 1 << LZW_DICT_BITS

    def __init__(self):
        self.dictionary_k = bytearray(self.LZW_DICT_SIZE)
        self.dictionary_w = [0] * self.LZW_DICT_SIZE
        self.next_code = 0
        self.code_bits = 0
        self.code_word = 0
        self.temp_value = 0
        self.temp_bits = 0
        self.bytes_written = 0


class LightweightCompression:
    LZW_BLOCK_SIZE = 1 << 15
    LZW_START_BITS = 9
    LZW_FIRST_CODE = 1 << (LZW_START_BITS - 1)
    DICTIONARY_HASH_BITS = 10
    MAX_DICTIONARY_HASH = 1 << DICTIONARY_HASH_BITS
    HASH_MASK = MAX_DICTIONARY_HASH - 1

    def __init__(self):
        self._lzw_data = LZWCompressionData()
        self._hash = [0] * self.MAX_DICTIONARY_HASH
        self._next_hash = [0] * LZWCompressionData.LZW_DICT_SIZE
        self.overflowed = False
        self._block = bytearray(self.LZW_BLOCK_SIZE)
        self._data = None
        self._block_size = 0
        self._block_index = 0
        self.bytes_read = 0
        self._max_size = 0
        self._old_code = 0
        self.total_bytes_read = 0
        self.total_bits_read = 0

    @property
    def length(self):
        return self._lzw_data.bytes_written

    def start(self, source_array_or_size, maximum_size_or_append, append=None):
        if isinstance(source_array_or_size, (bytes, bytearray)):
            source_array = source_array_or_size
            maximum_size = maximum_size_or_append
            # Start(byte[], int, bool)
            self._clear_hash()

            if append:
                original_next_code = self._lzw_data.next_code
                self._lzw_data.next_code = self.LZW_FIRST_CODE
                for i in range(self.LZW_FIRST_CODE, original_next_code):
                    self._add_to_dictionary(self._lzw_data.dictionary_w[i], self._lzw_data.dictionary_k[i])
            else:
                for i in range(self.LZW_FIRST_CODE):
                    self._lzw_data.dictionary_k[i] = i & 0xFF
                    self._lzw_data.dictionary_w[i] = 0xFFFF

                self._lzw_data.next_code = self.LZW_FIRST_CODE
                self._lzw_data.code_bits = self.LZW_START_BITS
                self._lzw_data.code_word = -1
                self._lzw_data.temp_value = 0
                self._lzw_data.temp_bits = 0
                self._lzw_data.bytes_written = 0

            self._old_code = -1
            self._data = bytearray(source_array) if not isinstance(source_array, bytearray) else source_array
            self._block_size = 0
            self._block_index = 0
            self.bytes_read = 0
            self.total_bytes_read = 0
            self.total_bits_read = 0
            self._max_size = maximum_size
            self.overflowed = False
        else:
            # Start(int, bool)
            maximum_size = source_array_or_size
            append_flag = maximum_size_or_append

            self._clear_hash()

            if append_flag:
                original_next_code = self._lzw_data.next_code
                self._lzw_data.next_code = self.LZW_FIRST_CODE
                for i in range(self.LZW_FIRST_CODE, original_next_code):
                    self._add_to_dictionary(self._lzw_data.dictionary_w[i], self._lzw_data.dictionary_k[i])
            else:
                for i in range(self.LZW_FIRST_CODE):
                    self._lzw_data.dictionary_k[i] = i & 0xFF
                    self._lzw_data.dictionary_w[i] = 0xFFFF

                self._lzw_data.next_code = self.LZW_FIRST_CODE
                self._lzw_data.code_bits = self.LZW_START_BITS
                self._lzw_data.code_word = -1
                self._lzw_data.temp_value = 0
                self._lzw_data.temp_bits = 0
                self._lzw_data.bytes_written = 0

            self._old_code = -1
            self._block_size = 0
            self._block_index = 0
            self._data = bytearray(maximum_size)
            self.bytes_read = 0
            self.total_bytes_read = 0
            self.total_bits_read = 0
            self._max_size = maximum_size
            self.overflowed = False

    def read_bytes(self, buffer, length, ignore_overflow=False):
        for i in range(length):
            b = self._read_byte(ignore_overflow)
            if b == -1:
                buffer[i] = 0
                return i
            buffer[i] = b & 0xFF
        return length

    def read_byte_out(self):
        b = self._read_byte(False)
        if b == -1:
            return False, 0
        return True, b & 0xFF

    def read_to_end(self, buffer):
        result = bytearray()
        while True:
            b = self._read_byte(False)
            if b == -1:
                break
            result.append(b & 0xFF)

        for i in range(min(len(result), len(buffer))):
            buffer[i] = result[i]
        return len(result)

    def _read_byte(self, ignore_overflow=False):
        if self._block_index == self._block_size:
            self._decompress_block()

        if self._block_index == self._block_size:
            if not ignore_overflow:
                self.overflowed = True
            return -1

        self.total_bytes_read += 1
        self.total_bits_read += 8
        value = self._block[self._block_index]
        self._block_index += 1
        return value
    
    def read_bytes_out(self, length):
        """Read N decompressed bytes and return them as a bytes object."""
        buf = bytearray(length)
        count = self.read_bytes(buf, length)
        return bytes(buf[:count])

    def read_dynamic_uint_terminated(self):
        """Read a 7-bit encoded uint (variable-length, LEB128-style) from the LZW stream."""
        result = 0
        shift = 0
        while True:
            b = self._read_byte()
            if b == -1:
                break
            result |= (b & 0x7F) << shift
            shift += 7
            if (b & 0x80) == 0:
                break
        return result & 0xFFFFFFFF

    def read_dynamic_ushort_terminated(self):
        """Read a 7-bit encoded ushort from the LZW stream."""
        return self.read_dynamic_uint_terminated() & 0xFFFF
    
    def read_single_byte(self):
        buf = bytearray(1)
        if self.read_bytes(buf, 1) > 0:
            return buf[0]
        return 0

    def write_byte(self, value):
        code = self._lookup(self._lzw_data.code_word, value)
        if code >= 0:
            self._lzw_data.code_word = code
        else:
            self._write_bits(self._lzw_data.code_word & 0xFFFFFFFF, self._lzw_data.code_bits)
            if not self._bump_bits():
                self._add_to_dictionary(self._lzw_data.code_word, value)
            self._lzw_data.code_word = value

        if self._lzw_data.bytes_written >= self._max_size - (self._lzw_data.code_bits + self._lzw_data.temp_bits + 7) // 8:
            self.overflowed = True

    def write7_bit_encoded_uint(self, value):
        if isinstance(value, int) and value <= 0xFFFF:
            # ushort version
            max_iter = 2
        else:
            max_iter = 4

        count = 0
        buffer = []
        while value >= 0x80 and count < max_iter:
            buffer.append((value & 0xFF) | 0x80)
            value >>= 7
            count += 1
        buffer.append(value & 0xFF)

        for b in buffer:
            self.write_byte(b)

    def _lookup(self, w, k):
        if w == -1:
            return k
        i = self._hash_index(w, k)
        j = self._hash[i]
        while j != 0xFFFF and j != 0:
            if self._lzw_data.dictionary_k[j] == k and self._lzw_data.dictionary_w[j] == w:
                return j
            j = self._next_hash[j]
        return -1

    def _read_bits(self, bits):
        bits_to_read = bits - self._lzw_data.temp_bits
        while bits_to_read > 0:
            if self.bytes_read >= self._max_size:
                return -1
            self._lzw_data.temp_value |= self._data[self.bytes_read] << self._lzw_data.temp_bits
            self.bytes_read += 1
            self._lzw_data.temp_bits += 8
            bits_to_read -= 8

        value = self._lzw_data.temp_value & ((1 << bits) - 1)
        self._lzw_data.temp_value >>= bits
        self._lzw_data.temp_bits -= bits
        return value

    def _write_bits(self, value, bits):
        self._lzw_data.temp_value |= value << self._lzw_data.temp_bits
        self._lzw_data.temp_bits += bits

        while self._lzw_data.temp_bits >= 8:
            if self._lzw_data.bytes_written >= self._max_size:
                self.overflowed = True
                return
            self._data[self._lzw_data.bytes_written] = self._lzw_data.temp_value & 0xFF
            self._lzw_data.bytes_written += 1
            self._lzw_data.temp_value >>= 8
            self._lzw_data.temp_bits -= 8

    def _write_chain(self, code):
        chain = bytearray(LZWCompressionData.LZW_DICT_SIZE)
        i = 0
        while True:
            chain[i] = self._lzw_data.dictionary_k[code]
            i += 1
            code = self._lzw_data.dictionary_w[code]
            if code == 0xFFFF:
                break

        i -= 1
        first_char = chain[i]
        while i >= 0:
            self._block[self._block_size] = chain[i]
            self._block_size += 1
            i -= 1
        return first_char

    def _add_to_dictionary(self, w, k):
        self._lzw_data.dictionary_k[self._lzw_data.next_code] = k & 0xFF
        self._lzw_data.dictionary_w[self._lzw_data.next_code] = w & 0xFFFF
        i = self._hash_index(w, k)
        self._next_hash[self._lzw_data.next_code] = self._hash[i]
        self._hash[i] = self._lzw_data.next_code & 0xFFFF
        result = self._lzw_data.next_code
        self._lzw_data.next_code += 1
        return result

    def _hash_index(self, w, k):
        return (w ^ k) & self.HASH_MASK

    def _decompress_block(self):
        self._block_index = 0
        self._block_size = 0
        first_char = -1

        while self._block_size < self.LZW_BLOCK_SIZE - LZWCompressionData.LZW_DICT_SIZE:
            code = self._read_bits(self._lzw_data.code_bits)
            if code == -1:
                break

            if self._old_code == -1:
                self._block[self._block_size] = code & 0xFF
                self._block_size += 1
                self._old_code = code
                first_char = code
                continue

            if code >= self._lzw_data.next_code:
                first_char = self._write_chain(self._old_code)
                self._block[self._block_size] = first_char & 0xFF
                self._block_size += 1
            else:
                first_char = self._write_chain(code)

            self._add_to_dictionary(self._old_code, first_char)

            if self._bump_bits():
                self._old_code = -1
            else:
                self._old_code = code

    def _bump_bits(self):
        bumped = False
        if self._lzw_data.next_code == (1 << self._lzw_data.code_bits):
            self._lzw_data.code_bits += 1
            if self._lzw_data.code_bits > LZWCompressionData.LZW_DICT_BITS:
                self._lzw_data.next_code = self.LZW_FIRST_CODE
                self._lzw_data.code_bits = self.LZW_START_BITS
                self._clear_hash()
                bumped = True
        return bumped

    def end(self):
        if self._lzw_data.code_word != -1:
            self._write_bits(self._lzw_data.code_word & 0xFFFFFFFF, self._lzw_data.code_bits)

        if self._lzw_data.temp_bits > 0:
            if self._lzw_data.bytes_written >= self._max_size:
                self.overflowed = True
                return -1
            self._data[self._lzw_data.bytes_written] = self._lzw_data.temp_value & ((1 << self._lzw_data.temp_bits) - 1)
            self._lzw_data.bytes_written += 1

        return self.length if self.length > 0 else -1

    def _clear_hash(self):
        self._hash = [0xFF] * self.MAX_DICTIONARY_HASH

    def get_data(self):
        return bytes(self._data[:self._lzw_data.bytes_written])

    def write_bytes(self, data):
        for b in data:
            self.write_byte(b)

    @staticmethod
    def compress(component_bytes):
        lwc = LightweightCompression()
        lwc.start(0x7FFF, False)
        lwc.write_bytes(component_bytes)
        lwc.end()
        return lwc.get_data()
    
class Snapshot:
    def __init__(self, data: bytes, component_count: int = 0):
        self.ComponentCount = component_count
        self.Components: List[Component] = []
        self.parse_snapshot(data)

    def parse_snapshot(self, data: bytes):
        reader = BytesIO(data)
        current_component = 0
        while reader.tell() < len(data):
            current_component += 1
            if self.ComponentCount > 0 and current_component == self.ComponentCount:
                break
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
            component_id_length = 0
            resource_id_length = 0
            component_size_length = 0
            action = (header_byte >> 6) & 0x03  # bits 7..6
            entity_id_length = ((header_byte >> 4) & 0x03) + 1  # bits 5..4 + 1
            IsUncompressed = ((header_byte & 0x01) != 0)  # bit 0
            is_large_component_id = ((header_byte & 0x08) != 0)  # bit 3

            logger.debug(f"Action: {action}, EntityID Length: {entity_id_length}, "
                         f"IsUncompressed: {IsUncompressed}, Is Large Component ID: {is_large_component_id}")


            if action == 0:  # UpdateFromDefault
                component_id_length = 2 if is_large_component_id else 1
                resource_id_length = ((header_byte >> 1) & 0x03) + 1  # bits 2..1 +1
                component_size_length = 1
            elif action == 1:  # UpdateFromPrevious
                pass
            elif action == 2:  # DeleteComponent
                resource_id_length = 0
                component_size_length = 0
                component_id_length = 2 if is_large_component_id else 1
            elif action == 3:  # DeleteEntity
                pass
            else:
                logger.error(f"Unknown action type: {action}")
                return None

            logger.debug(f"ComponentID Length: {component_id_length}, "
                         f"ResourceID Length: {resource_id_length}, "
                         f"ComponentSize Length: {component_size_length}")
            # store header data for debugging
            header_data = {
                'action': action,
                'entity_id_length': entity_id_length,
                'is_uncompressed': IsUncompressed,
                'is_large_component_id': is_large_component_id,
                'component_id_length': component_id_length,
                'resource_id_length': resource_id_length,
                'component_size_length': component_size_length
            }

            # Helper function to read little-endian unsigned int
            def read_little_uint(length: int) -> int:
                if length == 0:
                    return 0
                bytes_read = reader.read(length)
                if len(bytes_read) != length:
                    logger.error(f"Expected {length} bytes, got {len(bytes_read)} bytes.")
                    # raise ValueError(f"Insufficient bytes for field. Expected {length}, got {len(bytes_read)}.")
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
                if IsUncompressed:
                    logger.debug("Component data is uncompressed.")
                    component_buffer = reader.read(component_size)
                    actual_size = len(component_buffer)
                    logger.debug(f"Read Component Buffer Length: {actual_size} bytes")
                    if actual_size != component_size:
                        logger.error(f"Expected {component_size} bytes for component data, got {actual_size} bytes.")
                        raise ValueError(f"Insufficient bytes for component data. Expected {component_size}, got {actual_size}.")
                else:
                    # Initialize ZRL decompressor
                    zrl = ZeroRunLengthCompression(reader)
                    logger.debug("Using Zero Run-Length Compression for component data.")
                    component_buffer = zrl.read_bytes(component_size)
                    actual_size = len(component_buffer)
                    logger.debug(f"Decompressed Component Buffer Length: {actual_size} bytes")
                    if actual_size < component_size:
                        logger.error(f"Expected {component_size} bytes for component data, got {actual_size} bytes.")
                        raise ValueError(f"Insufficient bytes for component data. Expected {component_size}, got {actual_size}.")


            logger.debug(f"Component Buffer Data: {component_buffer.hex()}")

            return Component.GetComponent(
                header=header_data,
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

        packet_data = bytes.fromhex(packet_hex.replace(' ', '')) 
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
# global channel list & data tuple for rmsg parsing (0 - 9)
channel_data = {i: None for i in range(10)}
    
def parse_rmsg(rmsg_data, count):
    try:
        # store the messages to come out
        rmsgs = []
        current_pos = 0
        lzw_compression = LightweightCompression()
        lzw_compression.start(rmsg_data, len(rmsg_data), False)

        for i in range(count):
            channel = lzw_compression.read_single_byte()
            logger.debug(f"Current Channel: {channel}")
            # check if the channel is open and being used, if not initialize it with the data tuple.
            if channel < 10:
                if channel_data[channel] is None:
                    # total message size (4 bytes with the 8th bit terminating the size), game message type (2 bytes with the 8th bit terminating the size), message flags (1 byte) GameMessageBlockSize (4 bytes with the 8th bit terminating the size)))
                    total_size = lzw_compression.read_dynamic_uint_terminated()

                    game_message_type = lzw_compression.read_dynamic_ushort_terminated()
                    if game_message_type > 0:
                        game_message_type -= 1  # adjust for 0-based indexing
                    message_flags = lzw_compression.read_single_byte()
                    game_message_block_size = lzw_compression.read_dynamic_uint_terminated()
                    message_block_data = bytearray(game_message_block_size)
                    read_bytes = lzw_compression.read_bytes_out(game_message_block_size)

                    # if total message size is greater than the game message block size, then we need to wait for the next packet to get the rest of the data, so we will store the data tuple in the channel_data list at the index of the channel, if it is not then we can just store the data tuple in the channel_data list at the index of the channel.
                    # store the data tuple in the channel_data list at the index of the channel.
                    if total_size > game_message_block_size:
                        channel_data[channel] = (total_size, game_message_type, message_flags, game_message_block_size, read_bytes)
                    else:
                        rmsgs.append((game_message_type, message_flags, read_bytes))
                        logger.debug(f"Parsed Rmsg - Channel: {channel}, Type: {game_message_type}, Flags: {message_flags}, Data: {read_bytes.hex()}")
                # if the channel is already open and being used, check if the total message size is greater than the game message block size, if it is then append the data to the existing data tuple in the channel_data list at the index of the channel, if it is not then replace the existing data tuple in the channel_data list at the index of the channel with the new data tuple.
                else:
                    # game_message_block_size
                    game_message_block_size = lzw_compression.read_dynamic_uint_terminated()
                    message_block_data = bytearray(game_message_block_size)
                    read_bytes = lzw_compression.read_bytes_out(game_message_block_size)
                    # append the data to the existing data tuple in the channel_data list at the index of the channel.
                    current_data_tuple = channel_data[channel]
                    total_size = current_data_tuple[0]
                    game_message_type = current_data_tuple[1]
                    message_flags = current_data_tuple[2]
                    existing_game_message_data = current_data_tuple[4]
                    game_message_data = existing_game_message_data + read_bytes
                    if total_size > game_message_block_size:
                        game_message_data += read_bytes
                        channel_data[channel] = (total_size, game_message_type, message_flags, game_message_block_size + len(game_message_data), game_message_data)
                    else:
                        # clear the channel data since we have received the full message and store the data tuple in the channel_data list at the index of the channel.
                        channel_data[channel] = None
                        rmsgs.append((game_message_type, message_flags, game_message_data.hex()))
                        logger.debug(f"Parsed Rmsg - Channel: {channel}, Type: {game_message_type}, Flags: {message_flags}, Data: {game_message_data.hex()}")
        return {
            'rmsgs': rmsgs
        }
    except (IndexError, ValueError) as e:
        logger.error(f"Failed to parse rmsg packet: {e} | Data: {rmsg_data.hex()}")
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
        fixed_format = '<IIIIiIHI'  # Adjust format as per actual structure
        fixed_size = struct.calcsize(fixed_format)
        if len(packet_data) < current_pos + fixed_size:
            logger.error(f"Packet data too short for fixed-size fields. Expected additional {fixed_size} bytes.")
            return None
        (
            last_ack,
            ack_bits,
            delta,
            base,
            compressed_body_check,
            uncompressed_body,
            component_count,
            timestamp
        ) = struct.unpack_from(fixed_format, packet_data, current_pos)
        current_pos += fixed_size
        # seq.CompressedBodyMessageSizePreCompressionCheck = reader.ReadInt32();
        # seq.IsBodyCompressed = seq.CompressedBodyMessageSizePreCompressionCheck < 0;
        # seq.CompressedBodyMessageSize = (uint)(seq.CompressedBodyMessageSizePreCompressionCheck & 0x7FFFFFFF);
        logger.debug(f"Compressed Body Check: {compressed_body_check}")
        compressed_body = 0
        if compressed_body_check < 0:
            IsBodyCompressed = True
            compressed_body = compressed_body_check & 0x7FFFFFFF
        # Extract component_data
        if uncompressed_body > 0:
            temp_component_data = packet_data[current_pos:]
            component_data = lzw_decompress(temp_component_data)
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
        logger.debug(f"  Compressed Body: {compressed_body}")
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
            'rmsg_data': rmsg_data,
            'unseq_rmsg_count': unseq_rmsg_count,
            'unseq_rmsg_data': unseq_rmsg_data,
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
    pos = 0
    
    def get_code():
        nonlocal bits, bit_buffer, pos, code_size
        while bits < code_size:
            if pos >= len(compressed_data):
                break
            bit_buffer |= compressed_data[pos] << bits
            pos += 1
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

    logger.debug("Test passed: Snapshot parsed correctly.")

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
                    
                    # rmsg_data and unseq_rmsg_data parsing
                    rmsg_data = complete_packet_output.get('rmsg_data') 
                    rmsg_count = complete_packet_output.get('count', 0)
                    if rmsg_data:
                        rmsg_info = parse_rmsg(rmsg_data, rmsg_count)
                        if rmsg_info:
                            logger.debug(f"Parsed Rmsg Data: {rmsg_info}")
                        else:
                            logger.error(f"Failed to parse Rmsg data for {packet_key}")
                    unseq_rmsg_data = complete_packet_output.get('unseq_rmsg_data')
                    if unseq_rmsg_data:
                        unseq_rmsg_data_count = complete_packet_output.get('unseq_rmsg_count', 0)   
                        unseq_rmsg_info = parse_rmsg(unseq_rmsg_data, unseq_rmsg_data_count)
                        
                        if unseq_rmsg_info:
                            logger.debug(f"Parsed Unseq Rmsg Data: {unseq_rmsg_info}")
                        else:
                            logger.error(f"Failed to parse Unseq Rmsg data for {packet_key}")

                    # Decompress component_data if it exists
                    component_data = complete_packet_output.get('component_data')
                    component_count = complete_packet_output.get('component_count')
                    if component_count:
                        try:
                            # lzw_decompressed = lzw_decompress(component_data)
                            snapshot = Snapshot(component_data, component_count)
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
                        if acked_delta is None or acked_delta != 0:
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
