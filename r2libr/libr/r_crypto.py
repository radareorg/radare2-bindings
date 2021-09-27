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



r_crypto_version = _libr_crypto.r_crypto_version
r_crypto_version.restype = ctypes.POINTER(ctypes.c_char)
r_crypto_version.argtypes = []

# values for enumeration 'c__Ea_R_CRYPTO_MODE_ECB'
c__Ea_R_CRYPTO_MODE_ECB__enumvalues = {
    0: 'R_CRYPTO_MODE_ECB',
    1: 'R_CRYPTO_MODE_CBC',
    2: 'R_CRYPTO_MODE_OFB',
    3: 'R_CRYPTO_MODE_CFB',
}
R_CRYPTO_MODE_ECB = 0
R_CRYPTO_MODE_CBC = 1
R_CRYPTO_MODE_OFB = 2
R_CRYPTO_MODE_CFB = 3
c__Ea_R_CRYPTO_MODE_ECB = ctypes.c_uint32 # enum

# values for enumeration 'c__Ea_R_CRYPTO_DIR_CIPHER'
c__Ea_R_CRYPTO_DIR_CIPHER__enumvalues = {
    0: 'R_CRYPTO_DIR_CIPHER',
    1: 'R_CRYPTO_DIR_DECIPHER',
}
R_CRYPTO_DIR_CIPHER = 0
R_CRYPTO_DIR_DECIPHER = 1
c__Ea_R_CRYPTO_DIR_CIPHER = ctypes.c_uint32 # enum
class struct_r_crypto_t(Structure):
    pass

class struct_r_crypto_plugin_t(Structure):
    pass

class struct_r_list_t(Structure):
    pass

struct_r_crypto_t._pack_ = 1 # source:False
struct_r_crypto_t._fields_ = [
    ('h', ctypes.POINTER(struct_r_crypto_plugin_t)),
    ('key', ctypes.POINTER(ctypes.c_ubyte)),
    ('iv', ctypes.POINTER(ctypes.c_ubyte)),
    ('key_len', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('output', ctypes.POINTER(ctypes.c_ubyte)),
    ('output_len', ctypes.c_int32),
    ('output_size', ctypes.c_int32),
    ('dir', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
    ('user', ctypes.POINTER(None)),
    ('plugins', ctypes.POINTER(struct_r_list_t)),
]

struct_r_crypto_plugin_t._pack_ = 1 # source:False
struct_r_crypto_plugin_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('license', ctypes.POINTER(ctypes.c_char)),
    ('get_key_size', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_crypto_t))),
    ('set_iv', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_crypto_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)),
    ('set_key', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_crypto_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32)),
    ('update', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_crypto_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)),
    ('final', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_crypto_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)),
    ('use', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(ctypes.c_char))),
    ('fini', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_crypto_t))),
]

class struct_r_list_iter_t(Structure):
    pass

struct_r_list_t._pack_ = 1 # source:False
struct_r_list_t._fields_ = [
    ('head', ctypes.POINTER(struct_r_list_iter_t)),
    ('tail', ctypes.POINTER(struct_r_list_iter_t)),
    ('free', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
    ('length', ctypes.c_int32),
    ('sorted', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 3),
]

struct_r_list_iter_t._pack_ = 1 # source:False
struct_r_list_iter_t._fields_ = [
    ('data', ctypes.POINTER(None)),
    ('n', ctypes.POINTER(struct_r_list_iter_t)),
    ('p', ctypes.POINTER(struct_r_list_iter_t)),
]

RCrypto = struct_r_crypto_t
RCryptoPlugin = struct_r_crypto_plugin_t
RCryptoSelector = ctypes.c_uint64
r_crypto_init = _libr_crypto.r_crypto_init
r_crypto_init.restype = ctypes.POINTER(struct_r_crypto_t)
r_crypto_init.argtypes = [ctypes.POINTER(struct_r_crypto_t), ctypes.c_int32]
r_crypto_as_new = _libr_crypto.r_crypto_as_new
r_crypto_as_new.restype = ctypes.POINTER(struct_r_crypto_t)
r_crypto_as_new.argtypes = [ctypes.POINTER(struct_r_crypto_t)]
r_crypto_add = _libr_crypto.r_crypto_add
r_crypto_add.restype = ctypes.c_int32
r_crypto_add.argtypes = [ctypes.POINTER(struct_r_crypto_t), ctypes.POINTER(struct_r_crypto_plugin_t)]
r_crypto_new = _libr_crypto.r_crypto_new
r_crypto_new.restype = ctypes.POINTER(struct_r_crypto_t)
r_crypto_new.argtypes = []
r_crypto_free = _libr_crypto.r_crypto_free
r_crypto_free.restype = ctypes.POINTER(struct_r_crypto_t)
r_crypto_free.argtypes = [ctypes.POINTER(struct_r_crypto_t)]
r_crypto_use = _libr_crypto.r_crypto_use
r_crypto_use.restype = ctypes.c_bool
r_crypto_use.argtypes = [ctypes.POINTER(struct_r_crypto_t), ctypes.POINTER(ctypes.c_char)]
r_crypto_set_key = _libr_crypto.r_crypto_set_key
r_crypto_set_key.restype = ctypes.c_bool
r_crypto_set_key.argtypes = [ctypes.POINTER(struct_r_crypto_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
r_crypto_set_iv = _libr_crypto.r_crypto_set_iv
r_crypto_set_iv.restype = ctypes.c_bool
r_crypto_set_iv.argtypes = [ctypes.POINTER(struct_r_crypto_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_crypto_update = _libr_crypto.r_crypto_update
r_crypto_update.restype = ctypes.c_int32
r_crypto_update.argtypes = [ctypes.POINTER(struct_r_crypto_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_crypto_final = _libr_crypto.r_crypto_final
r_crypto_final.restype = ctypes.c_int32
r_crypto_final.argtypes = [ctypes.POINTER(struct_r_crypto_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_crypto_append = _libr_crypto.r_crypto_append
r_crypto_append.restype = ctypes.c_int32
r_crypto_append.argtypes = [ctypes.POINTER(struct_r_crypto_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_crypto_get_output = _libr_crypto.r_crypto_get_output
r_crypto_get_output.restype = ctypes.POINTER(ctypes.c_ubyte)
r_crypto_get_output.argtypes = [ctypes.POINTER(struct_r_crypto_t), ctypes.POINTER(ctypes.c_int32)]
r_crypto_name = _libr_crypto.r_crypto_name
r_crypto_name.restype = ctypes.POINTER(ctypes.c_char)
r_crypto_name.argtypes = [RCryptoSelector]
r_crypto_codec_name = _libr_crypto.r_crypto_codec_name
r_crypto_codec_name.restype = ctypes.POINTER(ctypes.c_char)
r_crypto_codec_name.argtypes = [RCryptoSelector]
r_crypto_plugin_aes = struct_r_crypto_plugin_t # Variable struct_r_crypto_plugin_t
r_crypto_plugin_des = struct_r_crypto_plugin_t # Variable struct_r_crypto_plugin_t
r_crypto_plugin_rc4 = struct_r_crypto_plugin_t # Variable struct_r_crypto_plugin_t
r_crypto_plugin_xor = struct_r_crypto_plugin_t # Variable struct_r_crypto_plugin_t
r_crypto_plugin_blowfish = struct_r_crypto_plugin_t # Variable struct_r_crypto_plugin_t
r_crypto_plugin_rc2 = struct_r_crypto_plugin_t # Variable struct_r_crypto_plugin_t
r_crypto_plugin_rot = struct_r_crypto_plugin_t # Variable struct_r_crypto_plugin_t
r_crypto_plugin_rol = struct_r_crypto_plugin_t # Variable struct_r_crypto_plugin_t
r_crypto_plugin_ror = struct_r_crypto_plugin_t # Variable struct_r_crypto_plugin_t
r_crypto_plugin_base64 = struct_r_crypto_plugin_t # Variable struct_r_crypto_plugin_t
r_crypto_plugin_base91 = struct_r_crypto_plugin_t # Variable struct_r_crypto_plugin_t
r_crypto_plugin_aes_cbc = struct_r_crypto_plugin_t # Variable struct_r_crypto_plugin_t
r_crypto_plugin_punycode = struct_r_crypto_plugin_t # Variable struct_r_crypto_plugin_t
r_crypto_plugin_rc6 = struct_r_crypto_plugin_t # Variable struct_r_crypto_plugin_t
r_crypto_plugin_cps2 = struct_r_crypto_plugin_t # Variable struct_r_crypto_plugin_t
r_crypto_plugin_serpent = struct_r_crypto_plugin_t # Variable struct_r_crypto_plugin_t
r_crypto_plugin_aes_wrap = struct_r_crypto_plugin_t # Variable struct_r_crypto_plugin_t
__all__ = \
    ['RCrypto', 'RCryptoPlugin', 'RCryptoSelector',
    'R_CRYPTO_DIR_CIPHER', 'R_CRYPTO_DIR_DECIPHER',
    'R_CRYPTO_MODE_CBC', 'R_CRYPTO_MODE_CFB', 'R_CRYPTO_MODE_ECB',
    'R_CRYPTO_MODE_OFB', 'c__Ea_R_CRYPTO_DIR_CIPHER',
    'c__Ea_R_CRYPTO_MODE_ECB', 'r_crypto_add', 'r_crypto_append',
    'r_crypto_as_new', 'r_crypto_codec_name', 'r_crypto_final',
    'r_crypto_free', 'r_crypto_get_output', 'r_crypto_init',
    'r_crypto_name', 'r_crypto_new', 'r_crypto_plugin_aes',
    'r_crypto_plugin_aes_cbc', 'r_crypto_plugin_aes_wrap',
    'r_crypto_plugin_base64', 'r_crypto_plugin_base91',
    'r_crypto_plugin_blowfish', 'r_crypto_plugin_cps2',
    'r_crypto_plugin_des', 'r_crypto_plugin_punycode',
    'r_crypto_plugin_rc2', 'r_crypto_plugin_rc4',
    'r_crypto_plugin_rc6', 'r_crypto_plugin_rol',
    'r_crypto_plugin_ror', 'r_crypto_plugin_rot',
    'r_crypto_plugin_serpent', 'r_crypto_plugin_xor',
    'r_crypto_set_iv', 'r_crypto_set_key', 'r_crypto_update',
    'r_crypto_use', 'r_crypto_version', 'struct_r_crypto_plugin_t',
    'struct_r_crypto_t', 'struct_r_list_iter_t', 'struct_r_list_t']
