# -*- coding: utf-8 -*-
#
# WORD_SIZE is: 8
# POINTER_SIZE is: 8
# LONGDOUBLE_SIZE is: 16
#
import ctypes
from .r_libs import r_anal as _libr_anal
from .r_libs import r_asm as _libr_asm
from .r_libs import r_bin as _libr_bin
from .r_libs import r_bp as _libr_bp
from .r_libs import r_config as _libr_config
from .r_libs import r_cons as _libr_cons
from .r_libs import r_core as _libr_core
from .r_libs import r_crypto as _libr_crypto
from .r_libs import r_debug as _libr_debug
from .r_libs import r_egg as _libr_egg
from .r_libs import r_flag as _libr_flag
from .r_libs import r_fs as _libr_fs
from .r_libs import r_hash as _libr_hash
from .r_libs import r_io as _libr_io
from .r_libs import r_lang as _libr_lang
from .r_libs import r_magic as _libr_magic
from .r_libs import r_main as _libr_main
from .r_libs import r_parse as _libr_parse
from .r_libs import r_reg as _libr_reg
from .r_libs import r_search as _libr_search
from .r_libs import r_socket as _libr_socket
from .r_libs import r_syscall as _libr_syscall
from .r_libs import r_util as _libr_util


_libraries = {}
def string_cast(char_pointer, encoding='utf-8', errors='strict'):
    value = ctypes.cast(char_pointer, ctypes.c_char_p).value
    if value is not None and encoding is not None:
        value = value.decode(encoding, errors=errors)
    return value


def char_pointer_cast(string, encoding='utf-8'):
    if encoding is not None:
        try:
            string = string.encode(encoding)
        except AttributeError:
            # In Python3, bytes has no encode attribute
            pass
    string = ctypes.c_char_p(string)
    return ctypes.cast(string, ctypes.POINTER(ctypes.c_char))



class AsDictMixin:
    @classmethod
    def as_dict(cls, self):
        result = {}
        if not isinstance(self, AsDictMixin):
            # not a structure, assume it's already a python object
            return self
        if not hasattr(cls, "_fields_"):
            return result
        # sys.version_info >= (3, 5)
        # for (field, *_) in cls._fields_:  # noqa
        for field_tuple in cls._fields_:  # noqa
            field = field_tuple[0]
            if field.startswith('PADDING_'):
                continue
            value = getattr(self, field)
            type_ = type(value)
            if hasattr(value, "_length_") and hasattr(value, "_type_"):
                # array
                if not hasattr(type_, "as_dict"):
                    value = [v for v in value]
                else:
                    type_ = type_._type_
                    value = [type_.as_dict(v) for v in value]
            elif hasattr(value, "contents") and hasattr(value, "_type_"):
                # pointer
                try:
                    if not hasattr(type_, "as_dict"):
                        value = value.contents
                    else:
                        type_ = type_._type_
                        value = type_.as_dict(value.contents)
                except ValueError:
                    # nullptr
                    value = None
            elif isinstance(value, AsDictMixin):
                # other structure
                value = type_.as_dict(value)
            result[field] = value
        return result


class Structure(ctypes.Structure, AsDictMixin):

    def __init__(self, *args, **kwds):
        # We don't want to use positional arguments fill PADDING_* fields

        args = dict(zip(self.__class__._field_names_(), args))
        args.update(kwds)
        super(Structure, self).__init__(**args)

    @classmethod
    def _field_names_(cls):
        if hasattr(cls, '_fields_'):
            return (f[0] for f in cls._fields_ if not f[0].startswith('PADDING'))
        else:
            return ()

    @classmethod
    def get_type(cls, field):
        for f in cls._fields_:
            if f[0] == field:
                return f[1]
        return None

    @classmethod
    def bind(cls, bound_fields):
        fields = {}
        for name, type_ in cls._fields_:
            if hasattr(type_, "restype"):
                if name in bound_fields:
                    if bound_fields[name] is None:
                        fields[name] = type_()
                    else:
                        # use a closure to capture the callback from the loop scope
                        fields[name] = (
                            type_((lambda callback: lambda *args: callback(*args))(
                                bound_fields[name]))
                        )
                    del bound_fields[name]
                else:
                    # default callback implementation (does nothing)
                    try:
                        default_ = type_(0).restype().value
                    except TypeError:
                        default_ = None
                    fields[name] = type_((
                        lambda default_: lambda *args: default_)(default_))
            else:
                # not a callback function, use default initialization
                if name in bound_fields:
                    fields[name] = bound_fields[name]
                    del bound_fields[name]
                else:
                    fields[name] = type_()
        if len(bound_fields) != 0:
            raise ValueError(
                "Cannot bind the following unknown callback(s) {}.{}".format(
                    cls.__name__, bound_fields.keys()
            ))
        return cls(**fields)


class Union(ctypes.Union, AsDictMixin):
    pass



c_int128 = ctypes.c_ubyte*16
c_uint128 = c_int128
void = None
if ctypes.sizeof(ctypes.c_longdouble) == 16:
    c_long_double_t = ctypes.c_longdouble
else:
    c_long_double_t = ctypes.c_ubyte*16



r_hash_version = _libr_hash.r_hash_version
r_hash_version.restype = ctypes.POINTER(ctypes.c_char)
r_hash_version.argtypes = []
class struct_c__SA_R_MD5_CTX(Structure):
    pass

struct_c__SA_R_MD5_CTX._pack_ = 1 # source:False
struct_c__SA_R_MD5_CTX._fields_ = [
    ('state', ctypes.c_uint32 * 4),
    ('count', ctypes.c_uint32 * 2),
    ('buffer', ctypes.c_ubyte * 64),
]

R_MD5_CTX = struct_c__SA_R_MD5_CTX
class struct_c__SA_R_SHA_CTX(Structure):
    pass

struct_c__SA_R_SHA_CTX._pack_ = 1 # source:False
struct_c__SA_R_SHA_CTX._fields_ = [
    ('H', ctypes.c_uint32 * 5),
    ('W', ctypes.c_uint32 * 80),
    ('lenW', ctypes.c_int32),
    ('sizeHi', ctypes.c_uint32),
    ('sizeLo', ctypes.c_uint32),
]

R_SHA_CTX = struct_c__SA_R_SHA_CTX
class struct__SHA256_CTX(Structure):
    pass

struct__SHA256_CTX._pack_ = 1 # source:False
struct__SHA256_CTX._fields_ = [
    ('state', ctypes.c_uint32 * 8),
    ('bitcount', ctypes.c_uint64),
    ('buffer', ctypes.c_ubyte * 64),
]

R_SHA256_CTX = struct__SHA256_CTX
class struct__SHA512_CTX(Structure):
    pass

struct__SHA512_CTX._pack_ = 1 # source:False
struct__SHA512_CTX._fields_ = [
    ('state', ctypes.c_uint64 * 8),
    ('bitcount', ctypes.c_uint64 * 2),
    ('buffer', ctypes.c_ubyte * 128),
]

R_SHA512_CTX = struct__SHA512_CTX
R_SHA384_CTX = struct__SHA512_CTX
utcrc = ctypes.c_uint64
size_t = ctypes.c_uint64
r_hash_fletcher8 = _libr_hash.r_hash_fletcher8
r_hash_fletcher8.restype = ctypes.c_ubyte
r_hash_fletcher8.argtypes = [ctypes.POINTER(ctypes.c_ubyte), size_t]
r_hash_fletcher16 = _libr_hash.r_hash_fletcher16
r_hash_fletcher16.restype = ctypes.c_uint16
r_hash_fletcher16.argtypes = [ctypes.POINTER(ctypes.c_ubyte), size_t]
r_hash_fletcher32 = _libr_hash.r_hash_fletcher32
r_hash_fletcher32.restype = ctypes.c_uint32
r_hash_fletcher32.argtypes = [ctypes.POINTER(ctypes.c_ubyte), size_t]
r_hash_fletcher64 = _libr_hash.r_hash_fletcher64
r_hash_fletcher64.restype = ctypes.c_uint64
r_hash_fletcher64.argtypes = [ctypes.POINTER(ctypes.c_ubyte), size_t]
class struct_c__SA_R_CRC_CTX(Structure):
    pass

struct_c__SA_R_CRC_CTX._pack_ = 1 # source:False
struct_c__SA_R_CRC_CTX._fields_ = [
    ('crc', ctypes.c_uint64),
    ('size', ctypes.c_uint32),
    ('reflect', ctypes.c_int32),
    ('poly', ctypes.c_uint64),
    ('xout', ctypes.c_uint64),
]

R_CRC_CTX = struct_c__SA_R_CRC_CTX

# values for enumeration 'CRC_PRESETS'
CRC_PRESETS__enumvalues = {
    0: 'CRC_PRESET_8_SMBUS',
    1: 'CRC_PRESET_15_CAN',
    2: 'CRC_PRESET_16',
    3: 'CRC_PRESET_16_CITT',
    4: 'CRC_PRESET_16_USB',
    5: 'CRC_PRESET_16_HDLC',
    6: 'CRC_PRESET_24',
    7: 'CRC_PRESET_32',
    8: 'CRC_PRESET_32_ECMA_267',
    9: 'CRC_PRESET_32C',
    10: 'CRC_PRESET_CRC32_BZIP2',
    11: 'CRC_PRESET_CRC32D',
    12: 'CRC_PRESET_CRC32_MPEG2',
    13: 'CRC_PRESET_CRC32_POSIX',
    14: 'CRC_PRESET_CRC32Q',
    15: 'CRC_PRESET_CRC32_JAMCRC',
    16: 'CRC_PRESET_CRC32_XFER',
    17: 'CRC_PRESET_CRC64',
    18: 'CRC_PRESET_CRC64_ECMA182',
    19: 'CRC_PRESET_CRC64_WE',
    20: 'CRC_PRESET_CRC64_XZ',
    21: 'CRC_PRESET_CRC64_ISO',
    22: 'CRC_PRESET_SIZE',
}
CRC_PRESET_8_SMBUS = 0
CRC_PRESET_15_CAN = 1
CRC_PRESET_16 = 2
CRC_PRESET_16_CITT = 3
CRC_PRESET_16_USB = 4
CRC_PRESET_16_HDLC = 5
CRC_PRESET_24 = 6
CRC_PRESET_32 = 7
CRC_PRESET_32_ECMA_267 = 8
CRC_PRESET_32C = 9
CRC_PRESET_CRC32_BZIP2 = 10
CRC_PRESET_CRC32D = 11
CRC_PRESET_CRC32_MPEG2 = 12
CRC_PRESET_CRC32_POSIX = 13
CRC_PRESET_CRC32Q = 14
CRC_PRESET_CRC32_JAMCRC = 15
CRC_PRESET_CRC32_XFER = 16
CRC_PRESET_CRC64 = 17
CRC_PRESET_CRC64_ECMA182 = 18
CRC_PRESET_CRC64_WE = 19
CRC_PRESET_CRC64_XZ = 20
CRC_PRESET_CRC64_ISO = 21
CRC_PRESET_SIZE = 22
CRC_PRESETS = ctypes.c_uint32 # enum
class struct_r_hash_t(Structure):
    pass

struct_r_hash_t._pack_ = 1 # source:False
struct_r_hash_t._fields_ = [
    ('md5', R_MD5_CTX),
    ('sha1', R_SHA_CTX),
    ('sha256', R_SHA256_CTX),
    ('sha384', R_SHA384_CTX),
    ('sha512', R_SHA512_CTX),
    ('rst', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
    ('entropy', ctypes.c_double),
    ('digest', ctypes.c_ubyte * 128),
]

class struct_r_hash_seed_t(Structure):
    pass

struct_r_hash_seed_t._pack_ = 1 # source:False
struct_r_hash_seed_t._fields_ = [
    ('prefix', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('buf', ctypes.POINTER(ctypes.c_ubyte)),
    ('len', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
]

RHashSeed = struct_r_hash_seed_t

# values for enumeration 'HASH_INDICES'
HASH_INDICES__enumvalues = {
    0: 'R_HASH_IDX_MD5',
    1: 'R_HASH_IDX_SHA1',
    2: 'R_HASH_IDX_SHA256',
    3: 'R_HASH_IDX_SHA384',
    4: 'R_HASH_IDX_SHA512',
    5: 'R_HASH_IDX_MD4',
    6: 'R_HASH_IDX_XOR',
    7: 'R_HASH_IDX_XORPAIR',
    8: 'R_HASH_IDX_PARITY',
    9: 'R_HASH_IDX_ENTROPY',
    10: 'R_HASH_IDX_HAMDIST',
    11: 'R_HASH_IDX_PCPRINT',
    12: 'R_HASH_IDX_MOD255',
    13: 'R_HASH_IDX_XXHASH',
    14: 'R_HASH_IDX_ADLER32',
    15: 'R_HASH_IDX_BASE64',
    16: 'R_HASH_IDX_BASE91',
    17: 'R_HASH_IDX_PUNYCODE',
    18: 'R_HASH_IDX_LUHN',
    19: 'R_HASH_IDX_SSDEEP',
    20: 'R_HASH_IDX_CRC8_SMBUS',
    21: 'R_HASH_IDX_CRC15_CAN',
    22: 'R_HASH_IDX_CRC16',
    23: 'R_HASH_IDX_CRC16_HDLC',
    24: 'R_HASH_IDX_CRC16_USB',
    25: 'R_HASH_IDX_CRC16_CITT',
    26: 'R_HASH_IDX_CRC24',
    27: 'R_HASH_IDX_CRC32',
    28: 'R_HASH_IDX_CRC32C',
    29: 'R_HASH_IDX_CRC32_ECMA_267',
    30: 'R_HASH_IDX_CRC32_BZIP2',
    31: 'R_HASH_IDX_CRC32D',
    32: 'R_HASH_IDX_CRC32_MPEG2',
    33: 'R_HASH_IDX_CRC32_POSIX',
    34: 'R_HASH_IDX_CRC32Q',
    35: 'R_HASH_IDX_CRC32_JAMCRC',
    36: 'R_HASH_IDX_CRC32_XFER',
    37: 'R_HASH_IDX_CRC64',
    38: 'R_HASH_IDX_CRC64_ECMA182',
    39: 'R_HASH_IDX_CRC64_WE',
    40: 'R_HASH_IDX_CRC64_XZ',
    41: 'R_HASH_IDX_CRC64_ISO',
    42: 'R_HASH_IDX_FLETCHER8',
    43: 'R_HASH_IDX_FLETCHER16',
    44: 'R_HASH_IDX_FLETCHER32',
    45: 'R_HASH_IDX_FLETCHER64',
    46: 'R_HASH_NUM_INDICES',
}
R_HASH_IDX_MD5 = 0
R_HASH_IDX_SHA1 = 1
R_HASH_IDX_SHA256 = 2
R_HASH_IDX_SHA384 = 3
R_HASH_IDX_SHA512 = 4
R_HASH_IDX_MD4 = 5
R_HASH_IDX_XOR = 6
R_HASH_IDX_XORPAIR = 7
R_HASH_IDX_PARITY = 8
R_HASH_IDX_ENTROPY = 9
R_HASH_IDX_HAMDIST = 10
R_HASH_IDX_PCPRINT = 11
R_HASH_IDX_MOD255 = 12
R_HASH_IDX_XXHASH = 13
R_HASH_IDX_ADLER32 = 14
R_HASH_IDX_BASE64 = 15
R_HASH_IDX_BASE91 = 16
R_HASH_IDX_PUNYCODE = 17
R_HASH_IDX_LUHN = 18
R_HASH_IDX_SSDEEP = 19
R_HASH_IDX_CRC8_SMBUS = 20
R_HASH_IDX_CRC15_CAN = 21
R_HASH_IDX_CRC16 = 22
R_HASH_IDX_CRC16_HDLC = 23
R_HASH_IDX_CRC16_USB = 24
R_HASH_IDX_CRC16_CITT = 25
R_HASH_IDX_CRC24 = 26
R_HASH_IDX_CRC32 = 27
R_HASH_IDX_CRC32C = 28
R_HASH_IDX_CRC32_ECMA_267 = 29
R_HASH_IDX_CRC32_BZIP2 = 30
R_HASH_IDX_CRC32D = 31
R_HASH_IDX_CRC32_MPEG2 = 32
R_HASH_IDX_CRC32_POSIX = 33
R_HASH_IDX_CRC32Q = 34
R_HASH_IDX_CRC32_JAMCRC = 35
R_HASH_IDX_CRC32_XFER = 36
R_HASH_IDX_CRC64 = 37
R_HASH_IDX_CRC64_ECMA182 = 38
R_HASH_IDX_CRC64_WE = 39
R_HASH_IDX_CRC64_XZ = 40
R_HASH_IDX_CRC64_ISO = 41
R_HASH_IDX_FLETCHER8 = 42
R_HASH_IDX_FLETCHER16 = 43
R_HASH_IDX_FLETCHER32 = 44
R_HASH_IDX_FLETCHER64 = 45
R_HASH_NUM_INDICES = 46
HASH_INDICES = ctypes.c_uint32 # enum
r_hash_new = _libr_hash.r_hash_new
r_hash_new.restype = ctypes.POINTER(struct_r_hash_t)
r_hash_new.argtypes = [ctypes.c_bool, ctypes.c_uint64]
r_hash_free = _libr_hash.r_hash_free
r_hash_free.restype = None
r_hash_free.argtypes = [ctypes.POINTER(struct_r_hash_t)]
r_hash_do_md4 = _libr_hash.r_hash_do_md4
r_hash_do_md4.restype = ctypes.POINTER(ctypes.c_ubyte)
r_hash_do_md4.argtypes = [ctypes.POINTER(struct_r_hash_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_hash_do_ssdeep = _libr_hash.r_hash_do_ssdeep
r_hash_do_ssdeep.restype = ctypes.POINTER(ctypes.c_ubyte)
r_hash_do_ssdeep.argtypes = [ctypes.POINTER(struct_r_hash_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_hash_do_md5 = _libr_hash.r_hash_do_md5
r_hash_do_md5.restype = ctypes.POINTER(ctypes.c_ubyte)
r_hash_do_md5.argtypes = [ctypes.POINTER(struct_r_hash_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_hash_do_sha1 = _libr_hash.r_hash_do_sha1
r_hash_do_sha1.restype = ctypes.POINTER(ctypes.c_ubyte)
r_hash_do_sha1.argtypes = [ctypes.POINTER(struct_r_hash_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_hash_do_sha256 = _libr_hash.r_hash_do_sha256
r_hash_do_sha256.restype = ctypes.POINTER(ctypes.c_ubyte)
r_hash_do_sha256.argtypes = [ctypes.POINTER(struct_r_hash_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_hash_do_sha384 = _libr_hash.r_hash_do_sha384
r_hash_do_sha384.restype = ctypes.POINTER(ctypes.c_ubyte)
r_hash_do_sha384.argtypes = [ctypes.POINTER(struct_r_hash_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_hash_do_sha512 = _libr_hash.r_hash_do_sha512
r_hash_do_sha512.restype = ctypes.POINTER(ctypes.c_ubyte)
r_hash_do_sha512.argtypes = [ctypes.POINTER(struct_r_hash_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_hash_do_hmac_sha256 = _libr_hash.r_hash_do_hmac_sha256
r_hash_do_hmac_sha256.restype = ctypes.POINTER(ctypes.c_ubyte)
r_hash_do_hmac_sha256.argtypes = [ctypes.POINTER(struct_r_hash_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_hash_to_string = _libr_hash.r_hash_to_string
r_hash_to_string.restype = ctypes.POINTER(ctypes.c_char)
r_hash_to_string.argtypes = [ctypes.POINTER(struct_r_hash_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_hash_name = _libr_hash.r_hash_name
r_hash_name.restype = ctypes.POINTER(ctypes.c_char)
r_hash_name.argtypes = [ctypes.c_uint64]
r_hash_name_to_bits = _libr_hash.r_hash_name_to_bits
r_hash_name_to_bits.restype = ctypes.c_uint64
r_hash_name_to_bits.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_hash_size = _libr_hash.r_hash_size
r_hash_size.restype = ctypes.c_int32
r_hash_size.argtypes = [ctypes.c_uint64]
r_hash_calculate = _libr_hash.r_hash_calculate
r_hash_calculate.restype = ctypes.c_int32
r_hash_calculate.argtypes = [ctypes.POINTER(struct_r_hash_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_hash_deviation = _libr_hash.r_hash_deviation
r_hash_deviation.restype = ctypes.c_ubyte
r_hash_deviation.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64]
r_hash_adler32 = _libr_hash.r_hash_adler32
r_hash_adler32.restype = ctypes.c_uint32
r_hash_adler32.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_hash_xxhash = _libr_hash.r_hash_xxhash
r_hash_xxhash.restype = ctypes.c_uint32
r_hash_xxhash.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64]
r_hash_xor = _libr_hash.r_hash_xor
r_hash_xor.restype = ctypes.c_ubyte
r_hash_xor.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64]
r_hash_xorpair = _libr_hash.r_hash_xorpair
r_hash_xorpair.restype = ctypes.c_uint16
r_hash_xorpair.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64]
r_hash_parity = _libr_hash.r_hash_parity
r_hash_parity.restype = ctypes.c_int32
r_hash_parity.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64]
r_hash_mod255 = _libr_hash.r_hash_mod255
r_hash_mod255.restype = ctypes.c_ubyte
r_hash_mod255.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64]
r_hash_luhn = _libr_hash.r_hash_luhn
r_hash_luhn.restype = ctypes.c_uint64
r_hash_luhn.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64]
r_hash_ssdeep = _libr_hash.r_hash_ssdeep
r_hash_ssdeep.restype = ctypes.POINTER(ctypes.c_char)
r_hash_ssdeep.argtypes = [ctypes.POINTER(ctypes.c_ubyte), size_t]
r_hash_crc_preset = _libr_hash.r_hash_crc_preset
r_hash_crc_preset.restype = utcrc
r_hash_crc_preset.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32, CRC_PRESETS]
r_hash_hamdist = _libr_hash.r_hash_hamdist
r_hash_hamdist.restype = ctypes.c_ubyte
r_hash_hamdist.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_hash_entropy = _libr_hash.r_hash_entropy
r_hash_entropy.restype = ctypes.c_double
r_hash_entropy.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64]
r_hash_entropy_fraction = _libr_hash.r_hash_entropy_fraction
r_hash_entropy_fraction.restype = ctypes.c_double
r_hash_entropy_fraction.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64]
r_hash_pcprint = _libr_hash.r_hash_pcprint
r_hash_pcprint.restype = ctypes.c_int32
r_hash_pcprint.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64]
r_hash_do_begin = _libr_hash.r_hash_do_begin
r_hash_do_begin.restype = None
r_hash_do_begin.argtypes = [ctypes.POINTER(struct_r_hash_t), ctypes.c_uint64]
r_hash_do_end = _libr_hash.r_hash_do_end
r_hash_do_end.restype = None
r_hash_do_end.argtypes = [ctypes.POINTER(struct_r_hash_t), ctypes.c_uint64]
r_hash_do_spice = _libr_hash.r_hash_do_spice
r_hash_do_spice.restype = None
r_hash_do_spice.argtypes = [ctypes.POINTER(struct_r_hash_t), ctypes.c_uint64, ctypes.c_int32, ctypes.POINTER(struct_r_hash_seed_t)]
__all__ = \
    ['CRC_PRESETS', 'CRC_PRESET_15_CAN', 'CRC_PRESET_16',
    'CRC_PRESET_16_CITT', 'CRC_PRESET_16_HDLC', 'CRC_PRESET_16_USB',
    'CRC_PRESET_24', 'CRC_PRESET_32', 'CRC_PRESET_32C',
    'CRC_PRESET_32_ECMA_267', 'CRC_PRESET_8_SMBUS',
    'CRC_PRESET_CRC32D', 'CRC_PRESET_CRC32Q',
    'CRC_PRESET_CRC32_BZIP2', 'CRC_PRESET_CRC32_JAMCRC',
    'CRC_PRESET_CRC32_MPEG2', 'CRC_PRESET_CRC32_POSIX',
    'CRC_PRESET_CRC32_XFER', 'CRC_PRESET_CRC64',
    'CRC_PRESET_CRC64_ECMA182', 'CRC_PRESET_CRC64_ISO',
    'CRC_PRESET_CRC64_WE', 'CRC_PRESET_CRC64_XZ', 'CRC_PRESET_SIZE',
    'HASH_INDICES', 'RHashSeed', 'R_CRC_CTX', 'R_HASH_IDX_ADLER32',
    'R_HASH_IDX_BASE64', 'R_HASH_IDX_BASE91', 'R_HASH_IDX_CRC15_CAN',
    'R_HASH_IDX_CRC16', 'R_HASH_IDX_CRC16_CITT',
    'R_HASH_IDX_CRC16_HDLC', 'R_HASH_IDX_CRC16_USB',
    'R_HASH_IDX_CRC24', 'R_HASH_IDX_CRC32', 'R_HASH_IDX_CRC32C',
    'R_HASH_IDX_CRC32D', 'R_HASH_IDX_CRC32Q',
    'R_HASH_IDX_CRC32_BZIP2', 'R_HASH_IDX_CRC32_ECMA_267',
    'R_HASH_IDX_CRC32_JAMCRC', 'R_HASH_IDX_CRC32_MPEG2',
    'R_HASH_IDX_CRC32_POSIX', 'R_HASH_IDX_CRC32_XFER',
    'R_HASH_IDX_CRC64', 'R_HASH_IDX_CRC64_ECMA182',
    'R_HASH_IDX_CRC64_ISO', 'R_HASH_IDX_CRC64_WE',
    'R_HASH_IDX_CRC64_XZ', 'R_HASH_IDX_CRC8_SMBUS',
    'R_HASH_IDX_ENTROPY', 'R_HASH_IDX_FLETCHER16',
    'R_HASH_IDX_FLETCHER32', 'R_HASH_IDX_FLETCHER64',
    'R_HASH_IDX_FLETCHER8', 'R_HASH_IDX_HAMDIST', 'R_HASH_IDX_LUHN',
    'R_HASH_IDX_MD4', 'R_HASH_IDX_MD5', 'R_HASH_IDX_MOD255',
    'R_HASH_IDX_PARITY', 'R_HASH_IDX_PCPRINT', 'R_HASH_IDX_PUNYCODE',
    'R_HASH_IDX_SHA1', 'R_HASH_IDX_SHA256', 'R_HASH_IDX_SHA384',
    'R_HASH_IDX_SHA512', 'R_HASH_IDX_SSDEEP', 'R_HASH_IDX_XOR',
    'R_HASH_IDX_XORPAIR', 'R_HASH_IDX_XXHASH', 'R_HASH_NUM_INDICES',
    'R_MD5_CTX', 'R_SHA256_CTX', 'R_SHA384_CTX', 'R_SHA512_CTX',
    'R_SHA_CTX', 'r_hash_adler32', 'r_hash_calculate',
    'r_hash_crc_preset', 'r_hash_deviation', 'r_hash_do_begin',
    'r_hash_do_end', 'r_hash_do_hmac_sha256', 'r_hash_do_md4',
    'r_hash_do_md5', 'r_hash_do_sha1', 'r_hash_do_sha256',
    'r_hash_do_sha384', 'r_hash_do_sha512', 'r_hash_do_spice',
    'r_hash_do_ssdeep', 'r_hash_entropy', 'r_hash_entropy_fraction',
    'r_hash_fletcher16', 'r_hash_fletcher32', 'r_hash_fletcher64',
    'r_hash_fletcher8', 'r_hash_free', 'r_hash_hamdist',
    'r_hash_luhn', 'r_hash_mod255', 'r_hash_name',
    'r_hash_name_to_bits', 'r_hash_new', 'r_hash_parity',
    'r_hash_pcprint', 'r_hash_size', 'r_hash_ssdeep',
    'r_hash_to_string', 'r_hash_version', 'r_hash_xor',
    'r_hash_xorpair', 'r_hash_xxhash', 'size_t', 'struct__SHA256_CTX',
    'struct__SHA512_CTX', 'struct_c__SA_R_CRC_CTX',
    'struct_c__SA_R_MD5_CTX', 'struct_c__SA_R_SHA_CTX',
    'struct_r_hash_seed_t', 'struct_r_hash_t', 'utcrc']
