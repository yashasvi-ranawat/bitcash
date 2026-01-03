import io
from bitcash.utils import (
    Decimal,
    bytes_to_hex,
    chunk_data,
    flip_hex_byte_order,
    hex_to_bytes,
    hex_to_int,
    int_to_hex,
    int_to_unknown_bytes,
    int_to_varint,
    varint_to_int,
)

BIG_INT = 123456789**5
BYTES_BIG = b"TH8\xe2\xaaN\xd7^aX7\x93\xe7\xc6\xa3\x02\x85"
BYTES_LITTLE = b"\x85\x02\xa3\xc6\xe7\x937Xa^\xd7N\xaa\xe28HT"
HEX = "544838e2aa4ed75e61583793e7c6a30285"
ODD_HEX = "4fadd1977328c11efc1c1d8a781aa6b9677984d3e0bd0bfc52b9f3b03885a00"
ODD_HEX_BYTES = (
    b"\x04\xfa\xdd\x19w2\x8c\x11\xef\xc1\xc1\xd8\xa7\x81"
    b"\xaak\x96w\x98M>\x0b\xd0\xbf\xc5+\x9f;\x03\x88Z\x00"
)
ODD_HEX_NUM = (
    2252489133021925628692706218705147644319767320134875440800653003170737838592
)


def test_decimal():
    assert Decimal(0.8) == Decimal("0.8")


class TestBytesToHex:
    def test_correct(self):
        assert bytes.fromhex(bytes_to_hex(BYTES_BIG)) == BYTES_BIG

    def test_default(self):
        assert bytes_to_hex(BYTES_BIG) == HEX

    def test_upper(self):
        assert bytes_to_hex(BYTES_BIG, upper=True) == HEX.upper()


class TestIntToUnknownBytes:
    def test_default(self):
        assert int_to_unknown_bytes(BIG_INT) == BYTES_BIG

    def test_little(self):
        assert int_to_unknown_bytes(BIG_INT, "little") == BYTES_LITTLE

    def test_zero(self):
        assert int_to_unknown_bytes(0) == b"\x00"


class TestIntToHex:
    def test_default(self):
        assert int_to_hex(BIG_INT) == HEX

    def test_upper(self):
        assert int_to_hex(BIG_INT, upper=True) == HEX.upper()


class TestIntToVarInt:
    def test_val_less_than_65535(self):
        assert int_to_varint(65535) == b"\xfd\xff\xff"

    def test_val_less_than_4294967295(self):
        assert int_to_varint(4294967294) == b"\xfe\xfe\xff\xff\xff"

    def test_val_more_than_4294967295(self):
        assert int_to_varint(10000000000) == b"\xff\x00\xe4\x0bT\x02\x00\x00\x00"


class TestVarIntToInt:
    def test_val_less_than_253(self):
        stream = io.BytesIO(b"\x14T")
        assert varint_to_int(stream) == 20

    def test_val_less_than_65535(self):
        stream = io.BytesIO(b"\xfd\xff\xffT")
        assert varint_to_int(stream) == 65535

    def test_val_less_than_4294967295(self):
        stream = io.BytesIO(b"\xfe\xfe\xff\xff\xffT")
        assert varint_to_int(stream) == 4294967294

    def test_val_more_than_4294967295(self):
        stream = io.BytesIO(b"\xff\x00\xe4\x0bT\x02\x00\x00\x00T")
        assert varint_to_int(stream) == 10000000000


def test_hex_to_bytes():
    assert hex_to_bytes(HEX) == BYTES_BIG
    assert hex_to_bytes(ODD_HEX) == ODD_HEX_BYTES


def test_hex_to_int():
    assert hex_to_int(HEX) == BIG_INT


def test_flip_hex_byte_order():
    assert flip_hex_byte_order(bytes_to_hex(BYTES_LITTLE)) == HEX


def test_chunk_data():
    assert list(chunk_data(ODD_HEX.encode(), 2)) == [
        b"4f",
        b"ad",
        b"d1",
        b"97",
        b"73",
        b"28",
        b"c1",
        b"1e",
        b"fc",
        b"1c",
        b"1d",
        b"8a",
        b"78",
        b"1a",
        b"a6",
        b"b9",
        b"67",
        b"79",
        b"84",
        b"d3",
        b"e0",
        b"bd",
        b"0b",
        b"fc",
        b"52",
        b"b9",
        b"f3",
        b"b0",
        b"38",
        b"85",
        b"a0",
        b"0",
    ]
