import struct

FILE_HEADER_SIZE = 0x20
SECTION_HEADER_SIZE = 16
SECTION_ALIGNMENT = 16
PADDING_BYTE = b'\xAB'


def _align_up(value, alignment=SECTION_ALIGNMENT):
    """Rounds value up to the next multiple of alignment"""
    return (value + alignment - 1) // alignment * alignment


def _clean_hex(data):
    """Normalises a text command payload ('0xab cd', '0xabcd', ...) into raw bytes"""
    return bytes.fromhex(''.join(data.split()).replace('0x', ''))


class MSBTWriter:
    """
    Writes a MSBTFile back out in the MSBT format.

    Every section is laid out sequentially: a 16 byte section header, the
    section table itself, then 0xAB filler bytes up to the next 16 byte
    boundary. The size stored in the section header is the size of the table
    only, it never includes the filler bytes.
    """

    def __init__(self, msbt_file, filepath=None):
        """
        Writes to a file in the MSBT format using the specified MSBTFile

            msbt_file: A MSBTFile instance
            filepath (optional): The path to write the ouput file to, defaults to the same filepath as the msbt file.
        """
        self.msbt = msbt_file
        self.filepath = filepath or self.msbt.filepath

        self.data = self.to_bytes()
        with open(self.filepath, 'wb') as stream:
            stream.write(self.data)

    def to_bytes(self):
        """Builds the whole MSBT file and returns it as bytes"""
        out = bytearray(FILE_HEADER_SIZE)

        for i in range(self.msbt.header.section_count):
            section = self.msbt.sections[i]
            signature = section.signature

            if signature == "LBL1":
                print("Writing Labels section...")
                self._append_section(out, signature, self._build_labels_section())
            elif signature == "TXT2":
                print("Writing Text section...")
                self._append_section(out, signature, self._build_text_section())
            else:
                print(f"Unknown section: {signature}")

                if section.bytes is None:
                    raise ValueError(f"Cannot rewrite unparsed section {signature}: no source bytes")

                # unsupported sections are copied over verbatim, header and filler included
                out += section.bytes

        out[0:FILE_HEADER_SIZE] = self._build_header(len(out))
        return bytes(out)

    def _append_section(self, out, signature, table):
        """Appends a section header, its table and the 0xAB filler bytes to out"""
        out += struct.pack('<4sI', signature.encode('ascii'), len(table))
        out += b'\x00' * (SECTION_HEADER_SIZE - 8)
        out += table
        out += PADDING_BYTE * (_align_up(len(out)) - len(out))

    def _build_header(self, file_size):
        """Builds the 0x20 byte MSBT header"""
        return struct.pack(
            '<8s H H H H H I 10s',
            self.msbt.header.magic.encode('ascii'), #8s
            self.msbt.header.byte_order, # H
            0, # H
            self.msbt.header.version, #H
            self.msbt.header.section_count, #H
            0, # H
            file_size, #I
            b'\x00' * 10 # 10s
        )

    # LABELS
    def _build_labels_section(self):
        """Builds the LBL1 section table"""
        lbl1 = self.msbt.LBL1
        offset_table = bytearray()
        labels = bytearray()

        # the label strings start right after the offset table
        labels_start = 4 + lbl1.offset_count * 8
        label_index = 0

        for i in range(lbl1.offset_count):
            str_count = lbl1.offset_table[i][0]
            offset_table += struct.pack('<II', str_count, labels_start + len(labels))

            for _ in range(str_count):
                labels += self._build_label(lbl1.labels[label_index])
                label_index += 1

        return struct.pack('<I', lbl1.offset_count) + bytes(offset_table) + bytes(labels)

    def _build_label(self, label):
        """Builds a single LBL1 entry: length prefixed string followed by its text index"""
        encoded = label.data.encode('ascii')
        if len(encoded) > 255:
            raise ValueError(f"Label is too long to store ({len(encoded)} bytes): {label.data}")

        return struct.pack(f'<B{len(encoded)}sI', len(encoded), encoded, label.string_index)

    ## TEXT
    def _build_text_section(self):
        """Builds the TXT2 section table"""
        txt2 = self.msbt.TXT2
        offset_table = bytearray()
        texts = bytearray()

        # the texts start right after the offset table
        texts_start = 4 + txt2.offset_count * 4

        for i in range(txt2.offset_count):
            offset_table += struct.pack('<I', texts_start + len(texts))
            texts += self._build_text(txt2.texts[i])

        return struct.pack('<I', txt2.offset_count) + bytes(offset_table) + bytes(texts)

    def _build_text(self, components):
        """Builds a single null terminated TXT2 text out of its text and command components"""
        text = bytearray()
        for component in components:
            if component.type == 'command':
                text += self._build_text_command(component.data)
            else:
                # surrogatepass keeps lone surrogates read back from the file intact
                text += component.data.encode('utf-16-le', errors='surrogatepass')

        text += struct.pack('<H', 0x0000) # null terminator
        return bytes(text)

    def _build_text_command(self, command):
        """Builds a text command"""
        data = _clean_hex(command.data) if command.data else b''

        return struct.pack(
            f'<HHHH{command.data_size}s',
            int(command.magic, 16),
            command.group,
            command.type,
            command.data_size,
            data
        )


    ## ATTRIBUTES
    #def write_attributes_section(self, section_offset, table_size):
    #    offset = section_offset + 16  # skip section header
    #
    #    attr_count, attr_data_size = self.msbt.attr_header_data
    #    self._pack_into_stream("<II", offset, attr_count, attr_data_size)
    #    offset += 8

        #for i in range(attr_count):
        #    # Read each attribute entry (4-byte offset from beginning)
        #    attr_offset, = struct.unpack_from("<I", self.data, offset)
        #    self.attributes.append(attr_offset)
        #    offset += 4
