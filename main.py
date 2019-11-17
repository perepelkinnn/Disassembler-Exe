import headers


if __name__ == "__main__":
    with open("sample.exe", "rb") as f:
        b = f.read(64)
        head1 = headers.MSDOS(b)
        f.seek(head1.pe_header_addr)
        b = f.read(120)
        print(len(b))
        head2 = headers.PE(b[:24])
        head3 = headers.OptionalHeader(b[24:])
        b = f.read(128)
        print(len(b))
        head4 = []
        for i in range(16):
            head4.append(headers.DataDir(b[4*i:4*i+8]))
