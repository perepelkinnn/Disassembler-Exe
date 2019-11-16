class MSDOSHead:
    def __init__(self, bytes):
        self.magic = bytes[0:2].decode('utf-8')
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
        self.pe_header_addr = int.from_bytes(bytes[60:64], "little")