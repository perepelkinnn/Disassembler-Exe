from textwrap import wrap


class MSDOS:
    """MS DOS Header"""

    def __init__(self, bytes):
        self.magic = CharArray(bytes[0:2])
        self.page_count = WORD(bytes[2:4])
        self.reloc_count = WORD(bytes[4:6])
        self.header_size = WORD(bytes[6:8])
        self.min_alloc = WORD(bytes[8:10])
        self.max_alloc = WORD(bytes[10:12])
        self.init_ss = WORD(bytes[12:14])
        self.init_sp = WORD(bytes[14:16])
        self.check_sum = WORD(bytes[16:18])
        self.init_ip = WORD(bytes[18:20])
        self.init_cs = WORD(bytes[20:22])
        self.reloc_addr = WORD(bytes[22:24])
        self.overlay_count = WORD(bytes[24:26])
        self.oem_identifier = WORD(bytes[36:38])
        self.oem_info = WORD(bytes[38:40])
        self.pe_header_addr = DWORD(bytes[60:64])


class PE:
    """PE Header"""

    def __init__(self, bytes):
        self.magic = CharArray(bytes[0:4])
        self.cpu_pype = WORD(bytes[4:6])
        self.section_count = WORD(bytes[6:8])
        self.data_time = DWORD(bytes[8:12])
        self.symbol_table_addr = DWORD(bytes[12:16])
        self.symbol_table_size = DWORD(bytes[16:20])
        self.optional_header_size = WORD(bytes[20:22])
        self.flags = WORD(bytes[22:24])


class OptionalHeader:
    """Optional Header"""

    def __init__(self, bytes):
        self.magic = WORD(bytes[0:2])
        self.major_link_ver = BYTE(bytes[2:3])
        self.minor_link_ver = BYTE(bytes[3:4])
        self.code_size = DWORD(bytes[4:8])
        self.init_data_size = DWORD(bytes[8:12])
        self.un_init_data_size = DWORD(bytes[12:16])
        self.entry_point_addr = DWORD(bytes[16:20])
        self.code_base = DWORD(bytes[20:24])
        self.data_base = DWORD(bytes[24:28])
        self.image_base = DWORD(bytes[28:32])
        self.section_align = DWORD(bytes[32:36])
        self.file_align = DWORD(bytes[36:40])
        self.major_os_ver = WORD(bytes[40:42])
        self.minor_os_ver = WORD(bytes[42:44])
        self.major_imaeg_ver = WORD(bytes[44:46])
        self.monor_image_ver = WORD(bytes[46:48])
        self.major_sub_sys_ver = WORD(bytes[48:50])
        self.minor_sub_sys_ver = WORD(bytes[50:52])
        self.image_size = DWORD(bytes[56:60])
        self.header_size = DWORD(bytes[60:64])
        self.check_sum = DWORD(bytes[64:68])
        self.sub_system = WORD(bytes[68:70])
        self.dll_flags = WORD(bytes[70:72])
        self.stack_reverse_size = DWORD(bytes[72:76])
        self.stack_commit_size = DWORD(bytes[76:80])
        self.heap_reverse_size = DWORD(bytes[80:84])
        self.heap_commit_size = DWORD(bytes[84:88])
        self.loader_flags = DWORD(bytes[88:92])
        self.data_dir_size = DWORD(bytes[92:96])


class DataDir:
    """Data Directory"""

    def __init__(self, bytes):
        self.virtual_address = DWORD(bytes[0:4])
        self.size = DWORD(bytes[4:8])


class Section:
    """Section"""

    def __init__(self, bytes):
        self.name = CharArray(bytes[0:8])
        self.virtual_size = DWORD(bytes[8:12])
        self.virtual_address = DWORD(bytes[12:16])
        self.size_of_raw_data = DWORD(bytes[16:20])
        self.pointer_to_raw_data = DWORD(bytes[20:24])
        self.pointer_to_relocations = DWORD(bytes[24:28])
        self.pointer_to_linenumbers = DWORD(bytes[28:32])
        self.number_of_relocations = WORD(bytes[32:34])
        self.number_of_linenumbers = WORD(bytes[34:36])
        self.characteristics = DWORD(bytes[36:40])


def head_to_str(head):
    res = ""
    res += head.__doc__ + '\n'
    for attr in dir(head):
        if attr[:2] != '__':
            res += '\t' + attr + (30-len(attr))*' '
            res += str(head.__getattribute__(attr)) + '\n'
    return res


def bytes_to_chararray(bytes):
    return bytes.strip(b'x\00').decode('utf-8')


def wrap_bytes(b):
    return wrap(b.hex(), 2)


def to_big_endian(words):
    words.reverse()
    return words


def words_to_str(words):
    return ' '.join(words)


def bytes_to_hex(bytes):
    return words_to_str(to_big_endian(wrap_bytes(bytes)))


class WORD:
    def __init__(self, bytes):
        self.value = bytes

    def __str__(self):
        return bytes_to_hex(self.value)


class DWORD:
    def __init__(self, bytes):
        self.value = bytes

    def __str__(self):
        return bytes_to_hex(self.value)


class BYTE:
    def __init__(self, bytes):
        self.value = bytes

    def __str__(self):
        return bytes_to_hex(self.value)


class CharArray:
    def __init__(self, bytes):
        self.value = bytes

    def __str__(self):
        return bytes_to_chararray(self.value)
