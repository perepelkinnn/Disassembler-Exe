if __name__ == "__main__":
    from headers import *
    import cli
    import os

    __dos__ = None
    __pe__ = None
    __optional__ = None
    __data_dirs__ = None
    __sections__ = None

    commands = cli.cli()

    @commands.add
    def parse(path):
        """Parse exe file, args=path"""

        global __dos__, __pe__, __optional__, __data_dirs__, __sections__

        if os.path.isfile(path):
            with open(path, "rb") as f:
                b = f.read(64)
                __dos__ = MSDOS(b)
                f.seek(int.from_bytes(__dos__.pe_header_addr.value, "little"))
                b = f.read(120)
                __pe__ = PE(b[:24])
                __optional__ = OptionalHeader(b[24:])
                b = f.read(128)
                __data_dirs__ = []
                for i in range(16):
                    __data_dirs__.append(DataDir(b[8*i:8*(i+1)]))
                __sections__ = []
                b = f.read(
                    40 * int.from_bytes(__pe__.section_count.value, "little"))
                for i in range(int.from_bytes(__pe__.section_count.value, "little")):
                    __sections__.append(Section(b[40*i: 40*(i + 1)]))
        else:
            print("File doesn't exist")

    @commands.add
    def head():
        """Print MSDOS, PE, Optional headers"""
        global __dos__, __pe__, __optional__, __data_dirs__, __sections__

        print(head_to_str(__dos__))
        print(head_to_str(__pe__))
        print(head_to_str(__optional__))

    @commands.add
    def data():
        """Print data dir array"""
        global __dos__, __pe__, __optional__, __data_dirs__, __sections__

        for data_dir in __data_dirs__:
            print(head_to_str(data_dir))

    @commands.add
    def sections():
        """Print sections"""
        global __dos__, __pe__, __optional__, __data_dirs__, __sections__

        for section in __sections__:
            print(head_to_str(section))
    commands.run()
