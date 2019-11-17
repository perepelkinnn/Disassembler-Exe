class MSDOS:
    """MS DOS Header"""

    def __init__(self, bytes):
        self.magic = bytes[0:2]
        self.page_count = bytes[2:4]
        self.reloc_count = bytes[4:6]
        self.header_size = bytes[6:8]
        self.min_alloc = bytes[8:10]
        self.max_alloc = bytes[10:12]
        self.init_ss = bytes[12:14]
        self.init_sp = bytes[14:16]
        self.check_sum = bytes[16:18]
        self.init_ip = bytes[18:20]
        self.init_cs = bytes[20:22]
        self.reloc_addr = bytes[22:24]
        self.overlay_count = bytes[24:26]
        self.oem_identifier = bytes[36:38]
        self.oem_info = bytes[38:40]
        self.pe_header_addr = bytes[60:64]


class PE:
    """PE Header"""

    def __init__(self, bytes):
        self.magic = bytes[0:4]
        self.cpu_pype = bytes[4:6]
        self.section_count = bytes[6:8]
        self.data_time = bytes[8:12]
        self.symbol_table_addr = bytes[12:16]
        self.symbol_table_size = bytes[16:20]
        self.optional_header_size = bytes[20:22]
        self.flags = bytes[22:24]


class OptionalHeader:
    """Optional Header"""

    def __init__(self, bytes):
        self.magic = bytes[0:2]
        self.major_link_ver = bytes[2:3]
        self.minor_link_ver = bytes[3:4]
        self.code_size = bytes[4:8]
        self.init_data_size = bytes[8:12]
        self.un_init_data_size = bytes[12:16]
        self.entry_point_addr = bytes[16:20]
        self.code_base = bytes[20:24]
        self.data_base = bytes[24:28]
        self.image_base = bytes[28:32]
        self.section_align = bytes[32:36]
        self.file_align = bytes[36:40]
        self.major_os_ver = bytes[40:42]
        self.minor_os_ver = bytes[42:44]
        self.major_imaeg_ver = bytes[44:46]
        self.monor_image_ver = bytes[46:48]
        self.major_sub_sys_ver = bytes[48:50]
        self.minor_sub_sys_ver = bytes[50:52]
        self.image_size = bytes[56:60]
        self.header_size = bytes[60:64]
        self.check_sum = bytes[64:68]
        self.sub_system = bytes[68:70]
        self.dll_flags = bytes[70:72]
        self.stack_reverse_size = bytes[72:76]
        self.stack_commit_size = bytes[76:80]
        self.heap_reverse_size = bytes[80:84]
        self.heap_commit_size = bytes[84:88]
        self.loader_flags = bytes[88:92]
        self.data_dir_size = bytes[92:96]


class DataDir:
    """Data Directory"""

    def __init__(self, bytes):
        self.virtual_address = bytes[0:4]
        self.size = bytes[4:8]


class Section:
    """Section"""

    def __init__(self, bytes):
        self.name = bytes[0:8]
        self.virtual_size = bytes[8:12]
        self.virtual_address = bytes[12:16]
        self.size_of_raw_data = bytes[16:20]
        self.pointer_to_raw_data = bytes[20:24]
        self.pointer_to_relocations = bytes[24:28]
        self.pointer_to_linenumbers = bytes[28:32]
        self.number_of_relocations = bytes[32:34]
        self.number_of_linenumbers = bytes[34:36]
        self.characteristics = bytes[36:40]


def head_to_str(head):
    res = ""
    res += head.__doc__ + '\n'
    for attr in dir(head):
        if attr[:2] != '__':
            res += '\t' + attr + (30-len(attr))*' ' + str(head.__getattribute__(attr))[2:-1] + '\n'
    return res
