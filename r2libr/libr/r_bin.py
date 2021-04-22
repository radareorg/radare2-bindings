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



c_int128 = ctypes.c_ubyte*16
c_uint128 = c_int128
void = None
if ctypes.sizeof(ctypes.c_longdouble) == 16:
    c_long_double_t = ctypes.c_longdouble
else:
    c_long_double_t = ctypes.c_ubyte*16

_libraries = {}
class FunctionFactoryStub:
    def __getattr__(self, _):
      return ctypes.CFUNCTYPE(lambda y:y)

# libraries['FIXME_STUB'] explanation
# As you did not list (-l libraryname.so) a library that exports this function
# This is a non-working stub instead. 
# You can either re-run clan2py with -l /path/to/library.so
# Or manually fix this by comment the ctypes.CDLL loading
_libraries['FIXME_STUB'] = FunctionFactoryStub() #  ctypes.CDLL('FIXME_STUB')


class struct_r_bin_t(Structure):
    pass

class struct_r_list_t(Structure):
    pass

class struct_r_id_storage_t(Structure):
    pass

class struct_r_bin_file_t(Structure):
    pass

class struct_sdb_t(Structure):
    pass

class struct_r_str_constpool_t(Structure):
    pass

class struct_ht_pp_t(Structure):
    pass

struct_r_str_constpool_t._pack_ = 1 # source:False
struct_r_str_constpool_t._fields_ = [
    ('ht', ctypes.POINTER(struct_ht_pp_t)),
]

class struct_r_io_bind_t(Structure):
    pass

class struct_r_io_t(Structure):
    pass

class struct_r_io_desc_t(Structure):
    pass

class struct_r_io_map_t(Structure):
    pass

struct_r_io_bind_t._pack_ = 1 # source:False
struct_r_io_bind_t._fields_ = [
    ('init', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('io', ctypes.POINTER(struct_r_io_t)),
    ('desc_use', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_io_t), ctypes.c_int32)),
    ('desc_get', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_io_desc_t), ctypes.POINTER(struct_r_io_t), ctypes.c_int32)),
    ('desc_size', ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(struct_r_io_desc_t))),
    ('open', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_io_desc_t), ctypes.POINTER(struct_r_io_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32)),
    ('open_at', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_io_desc_t), ctypes.POINTER(struct_r_io_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32, ctypes.c_uint64)),
    ('close', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_io_t), ctypes.c_int32)),
    ('read_at', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_io_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)),
    ('write_at', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_io_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)),
    ('system', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_io_t), ctypes.POINTER(ctypes.c_char))),
    ('fd_open', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_io_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32)),
    ('fd_close', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_io_t), ctypes.c_int32)),
    ('fd_seek', ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.c_uint64, ctypes.c_int32)),
    ('fd_size', ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(struct_r_io_t), ctypes.c_int32)),
    ('fd_resize', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.c_uint64)),
    ('fd_read', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)),
    ('fd_write', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)),
    ('fd_read_at', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)),
    ('fd_write_at', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)),
    ('fd_is_dbg', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_io_t), ctypes.c_int32)),
    ('fd_get_name', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_io_t), ctypes.c_int32)),
    ('fd_get_map', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_io_t), ctypes.c_int32)),
    ('fd_remap', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.c_uint64)),
    ('is_valid_offset', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_io_t), ctypes.c_uint64, ctypes.c_int32)),
    ('addr_is_mapped', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_io_t), ctypes.c_uint64)),
    ('map_get_at', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_io_map_t), ctypes.POINTER(struct_r_io_t), ctypes.c_uint64)),
    ('map_get_paddr', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_io_map_t), ctypes.POINTER(struct_r_io_t), ctypes.c_uint64)),
    ('map_add', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_io_map_t), ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64)),
    ('v2p', ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(struct_r_io_t), ctypes.c_uint64)),
    ('p2v', ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(struct_r_io_t), ctypes.c_uint64)),
]

class struct_r_cons_bind_t(Structure):
    pass

struct_r_cons_bind_t._pack_ = 1 # source:False
struct_r_cons_bind_t._fields_ = [
    ('get_size', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_int32))),
    ('get_cursor', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_int32))),
    ('cb_printf', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_char))),
    ('is_breaked', ctypes.CFUNCTYPE(ctypes.c_bool)),
    ('cb_flush', ctypes.CFUNCTYPE(None)),
    ('cb_grep', ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_char))),
]

struct_r_bin_t._pack_ = 1 # source:False
struct_r_bin_t._fields_ = [
    ('file', ctypes.POINTER(ctypes.c_char)),
    ('cur', ctypes.POINTER(struct_r_bin_file_t)),
    ('narch', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('user', ctypes.POINTER(None)),
    ('debase64', ctypes.c_int32),
    ('minstrlen', ctypes.c_int32),
    ('maxstrlen', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
    ('maxstrbuf', ctypes.c_uint64),
    ('rawstr', ctypes.c_int32),
    ('PADDING_2', ctypes.c_ubyte * 4),
    ('sdb', ctypes.POINTER(struct_sdb_t)),
    ('ids', ctypes.POINTER(struct_r_id_storage_t)),
    ('plugins', ctypes.POINTER(struct_r_list_t)),
    ('binxtrs', ctypes.POINTER(struct_r_list_t)),
    ('binldrs', ctypes.POINTER(struct_r_list_t)),
    ('binfiles', ctypes.POINTER(struct_r_list_t)),
    ('cb_printf', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_char))),
    ('loadany', ctypes.c_int32),
    ('PADDING_3', ctypes.c_ubyte * 4),
    ('iob', struct_r_io_bind_t),
    ('consb', struct_r_cons_bind_t),
    ('force', ctypes.POINTER(ctypes.c_char)),
    ('want_dbginfo', ctypes.c_bool),
    ('PADDING_4', ctypes.c_ubyte * 3),
    ('filter', ctypes.c_int32),
    ('strfilter', ctypes.c_char),
    ('PADDING_5', ctypes.c_ubyte * 7),
    ('strpurge', ctypes.POINTER(ctypes.c_char)),
    ('srcdir', ctypes.POINTER(ctypes.c_char)),
    ('prefix', ctypes.POINTER(ctypes.c_char)),
    ('strenc', ctypes.POINTER(ctypes.c_char)),
    ('filter_rules', ctypes.c_uint64),
    ('demanglercmd', ctypes.c_bool),
    ('verbose', ctypes.c_bool),
    ('use_xtr', ctypes.c_bool),
    ('use_ldr', ctypes.c_bool),
    ('PADDING_6', ctypes.c_ubyte * 4),
    ('constpool', struct_r_str_constpool_t),
    ('is_reloc_patched', ctypes.c_bool),
    ('PADDING_7', ctypes.c_ubyte * 7),
]

RBin = struct_r_bin_t
r_bin_version = _libr_bin.r_bin_version
r_bin_version.restype = ctypes.POINTER(ctypes.c_char)
r_bin_version.argtypes = []

# values for enumeration 'c__Ea_R_BIN_SYM_ENTRY'
c__Ea_R_BIN_SYM_ENTRY__enumvalues = {
    0: 'R_BIN_SYM_ENTRY',
    1: 'R_BIN_SYM_INIT',
    2: 'R_BIN_SYM_MAIN',
    3: 'R_BIN_SYM_FINI',
    4: 'R_BIN_SYM_LAST',
}
R_BIN_SYM_ENTRY = 0
R_BIN_SYM_INIT = 1
R_BIN_SYM_MAIN = 2
R_BIN_SYM_FINI = 3
R_BIN_SYM_LAST = 4
c__Ea_R_BIN_SYM_ENTRY = ctypes.c_uint32 # enum

# values for enumeration 'c__Ea_R_BIN_NM_NONE'
c__Ea_R_BIN_NM_NONE__enumvalues = {
    0: 'R_BIN_NM_NONE',
    1: 'R_BIN_NM_JAVA',
    2: 'R_BIN_NM_C',
    4: 'R_BIN_NM_GO',
    8: 'R_BIN_NM_CXX',
    16: 'R_BIN_NM_OBJC',
    32: 'R_BIN_NM_SWIFT',
    64: 'R_BIN_NM_DLANG',
    128: 'R_BIN_NM_MSVC',
    256: 'R_BIN_NM_RUST',
    512: 'R_BIN_NM_KOTLIN',
    -2147483648: 'R_BIN_NM_BLOCKS',
    -1: 'R_BIN_NM_ANY',
}
R_BIN_NM_NONE = 0
R_BIN_NM_JAVA = 1
R_BIN_NM_C = 2
R_BIN_NM_GO = 4
R_BIN_NM_CXX = 8
R_BIN_NM_OBJC = 16
R_BIN_NM_SWIFT = 32
R_BIN_NM_DLANG = 64
R_BIN_NM_MSVC = 128
R_BIN_NM_RUST = 256
R_BIN_NM_KOTLIN = 512
R_BIN_NM_BLOCKS = -2147483648
R_BIN_NM_ANY = -1
c__Ea_R_BIN_NM_NONE = ctypes.c_int32 # enum

# values for enumeration 'c__Ea_R_STRING_TYPE_DETECT'
c__Ea_R_STRING_TYPE_DETECT__enumvalues = {
    63: 'R_STRING_TYPE_DETECT',
    97: 'R_STRING_TYPE_ASCII',
    117: 'R_STRING_TYPE_UTF8',
    119: 'R_STRING_TYPE_WIDE',
    87: 'R_STRING_TYPE_WIDE32',
    98: 'R_STRING_TYPE_BASE64',
}
R_STRING_TYPE_DETECT = 63
R_STRING_TYPE_ASCII = 97
R_STRING_TYPE_UTF8 = 117
R_STRING_TYPE_WIDE = 119
R_STRING_TYPE_WIDE32 = 87
R_STRING_TYPE_BASE64 = 98
c__Ea_R_STRING_TYPE_DETECT = ctypes.c_uint32 # enum

# values for enumeration 'c__Ea_R_BIN_CLASS_PRIVATE'
c__Ea_R_BIN_CLASS_PRIVATE__enumvalues = {
    0: 'R_BIN_CLASS_PRIVATE',
    1: 'R_BIN_CLASS_PUBLIC',
    2: 'R_BIN_CLASS_FRIENDLY',
    3: 'R_BIN_CLASS_PROTECTED',
}
R_BIN_CLASS_PRIVATE = 0
R_BIN_CLASS_PUBLIC = 1
R_BIN_CLASS_FRIENDLY = 2
R_BIN_CLASS_PROTECTED = 3
c__Ea_R_BIN_CLASS_PRIVATE = ctypes.c_uint32 # enum

# values for enumeration 'c__Ea_R_BIN_RELOC_8'
c__Ea_R_BIN_RELOC_8__enumvalues = {
    8: 'R_BIN_RELOC_8',
    16: 'R_BIN_RELOC_16',
    32: 'R_BIN_RELOC_32',
    64: 'R_BIN_RELOC_64',
}
R_BIN_RELOC_8 = 8
R_BIN_RELOC_16 = 16
R_BIN_RELOC_32 = 32
R_BIN_RELOC_64 = 64
c__Ea_R_BIN_RELOC_8 = ctypes.c_uint32 # enum

# values for enumeration 'c__Ea_R_BIN_TYPE_DEFAULT'
c__Ea_R_BIN_TYPE_DEFAULT__enumvalues = {
    0: 'R_BIN_TYPE_DEFAULT',
    1: 'R_BIN_TYPE_CORE',
}
R_BIN_TYPE_DEFAULT = 0
R_BIN_TYPE_CORE = 1
c__Ea_R_BIN_TYPE_DEFAULT = ctypes.c_uint32 # enum
class struct_r_bin_addr_t(Structure):
    pass

struct_r_bin_addr_t._pack_ = 1 # source:False
struct_r_bin_addr_t._fields_ = [
    ('vaddr', ctypes.c_uint64),
    ('paddr', ctypes.c_uint64),
    ('hvaddr', ctypes.c_uint64),
    ('hpaddr', ctypes.c_uint64),
    ('type', ctypes.c_int32),
    ('bits', ctypes.c_int32),
]

RBinAddr = struct_r_bin_addr_t
class struct_r_bin_hash_t(Structure):
    pass

struct_r_bin_hash_t._pack_ = 1 # source:False
struct_r_bin_hash_t._fields_ = [
    ('type', ctypes.POINTER(ctypes.c_char)),
    ('addr', ctypes.c_uint64),
    ('len', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('from', ctypes.c_uint64),
    ('to', ctypes.c_uint64),
    ('buf', ctypes.c_ubyte * 32),
    ('cmd', ctypes.POINTER(ctypes.c_char)),
]

RBinHash = struct_r_bin_hash_t
class struct_r_bin_file_hash_t(Structure):
    pass

struct_r_bin_file_hash_t._pack_ = 1 # source:False
struct_r_bin_file_hash_t._fields_ = [
    ('type', ctypes.POINTER(ctypes.c_char)),
    ('hex', ctypes.POINTER(ctypes.c_char)),
]

RBinFileHash = struct_r_bin_file_hash_t
class struct_r_bin_info_t(Structure):
    pass

struct_r_bin_info_t._pack_ = 1 # source:False
struct_r_bin_info_t._fields_ = [
    ('file', ctypes.POINTER(ctypes.c_char)),
    ('type', ctypes.POINTER(ctypes.c_char)),
    ('bclass', ctypes.POINTER(ctypes.c_char)),
    ('rclass', ctypes.POINTER(ctypes.c_char)),
    ('arch', ctypes.POINTER(ctypes.c_char)),
    ('cpu', ctypes.POINTER(ctypes.c_char)),
    ('machine', ctypes.POINTER(ctypes.c_char)),
    ('head_flag', ctypes.POINTER(ctypes.c_char)),
    ('features', ctypes.POINTER(ctypes.c_char)),
    ('os', ctypes.POINTER(ctypes.c_char)),
    ('subsystem', ctypes.POINTER(ctypes.c_char)),
    ('rpath', ctypes.POINTER(ctypes.c_char)),
    ('guid', ctypes.POINTER(ctypes.c_char)),
    ('debug_file_name', ctypes.POINTER(ctypes.c_char)),
    ('lang', ctypes.POINTER(ctypes.c_char)),
    ('default_cc', ctypes.POINTER(ctypes.c_char)),
    ('file_hashes', ctypes.POINTER(struct_r_list_t)),
    ('bits', ctypes.c_int32),
    ('has_va', ctypes.c_int32),
    ('has_pi', ctypes.c_int32),
    ('has_canary', ctypes.c_int32),
    ('has_retguard', ctypes.c_int32),
    ('has_sanitizers', ctypes.c_int32),
    ('has_crypto', ctypes.c_int32),
    ('has_nx', ctypes.c_int32),
    ('big_endian', ctypes.c_int32),
    ('has_lit', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 3),
    ('actual_checksum', ctypes.POINTER(ctypes.c_char)),
    ('claimed_checksum', ctypes.POINTER(ctypes.c_char)),
    ('pe_overlay', ctypes.c_int32),
    ('signature', ctypes.c_bool),
    ('PADDING_1', ctypes.c_ubyte * 3),
    ('dbg_info', ctypes.c_uint64),
    ('sum', struct_r_bin_hash_t * 3),
    ('baddr', ctypes.c_uint64),
    ('intrp', ctypes.POINTER(ctypes.c_char)),
    ('compiler', ctypes.POINTER(ctypes.c_char)),
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

RBinInfo = struct_r_bin_info_t
class struct_r_bin_object_t(Structure):
    pass

class struct_ht_up_t(Structure):
    pass

class struct_r_bin_plugin_t(Structure):
    pass

class struct_r_rb_node_t(Structure):
    pass

struct_r_bin_object_t._pack_ = 1 # source:False
struct_r_bin_object_t._fields_ = [
    ('baddr', ctypes.c_uint64),
    ('baddr_shift', ctypes.c_int64),
    ('loadaddr', ctypes.c_uint64),
    ('boffset', ctypes.c_uint64),
    ('size', ctypes.c_uint64),
    ('obj_size', ctypes.c_uint64),
    ('sections', ctypes.POINTER(struct_r_list_t)),
    ('imports', ctypes.POINTER(struct_r_list_t)),
    ('symbols', ctypes.POINTER(struct_r_list_t)),
    ('entries', ctypes.POINTER(struct_r_list_t)),
    ('fields', ctypes.POINTER(struct_r_list_t)),
    ('libs', ctypes.POINTER(struct_r_list_t)),
    ('relocs', ctypes.POINTER(struct_r_rb_node_t)),
    ('strings', ctypes.POINTER(struct_r_list_t)),
    ('classes', ctypes.POINTER(struct_r_list_t)),
    ('classes_ht', ctypes.POINTER(struct_ht_pp_t)),
    ('methods_ht', ctypes.POINTER(struct_ht_pp_t)),
    ('lines', ctypes.POINTER(struct_r_list_t)),
    ('strings_db', ctypes.POINTER(struct_ht_up_t)),
    ('mem', ctypes.POINTER(struct_r_list_t)),
    ('maps', ctypes.POINTER(struct_r_list_t)),
    ('regstate', ctypes.POINTER(ctypes.c_char)),
    ('info', ctypes.POINTER(struct_r_bin_info_t)),
    ('binsym', ctypes.POINTER(struct_r_bin_addr_t) * 4),
    ('plugin', ctypes.POINTER(struct_r_bin_plugin_t)),
    ('lang', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('kv', ctypes.POINTER(struct_sdb_t)),
    ('addr2klassmethod', ctypes.POINTER(struct_ht_up_t)),
    ('bin_obj', ctypes.POINTER(None)),
]

struct_r_rb_node_t._pack_ = 1 # source:False
struct_r_rb_node_t._fields_ = [
    ('parent', ctypes.POINTER(struct_r_rb_node_t)),
    ('child', ctypes.POINTER(struct_r_rb_node_t) * 2),
    ('red', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
]

class struct_ht_pp_bucket_t(Structure):
    pass

class struct_ht_pp_options_t(Structure):
    pass

class struct_ht_pp_kv(Structure):
    pass

struct_ht_pp_options_t._pack_ = 1 # source:False
struct_ht_pp_options_t._fields_ = [
    ('cmp', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(None))),
    ('hashfn', ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.POINTER(None))),
    ('dupkey', ctypes.CFUNCTYPE(ctypes.POINTER(None), ctypes.POINTER(None))),
    ('dupvalue', ctypes.CFUNCTYPE(ctypes.POINTER(None), ctypes.POINTER(None))),
    ('calcsizeK', ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.POINTER(None))),
    ('calcsizeV', ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.POINTER(None))),
    ('freefn', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_ht_pp_kv))),
    ('elem_size', ctypes.c_uint64),
]

struct_ht_pp_t._pack_ = 1 # source:False
struct_ht_pp_t._fields_ = [
    ('size', ctypes.c_uint32),
    ('count', ctypes.c_uint32),
    ('table', ctypes.POINTER(struct_ht_pp_bucket_t)),
    ('prime_idx', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('opt', struct_ht_pp_options_t),
]

struct_ht_pp_bucket_t._pack_ = 1 # source:False
struct_ht_pp_bucket_t._fields_ = [
    ('arr', ctypes.POINTER(struct_ht_pp_kv)),
    ('count', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

struct_ht_pp_kv._pack_ = 1 # source:False
struct_ht_pp_kv._fields_ = [
    ('key', ctypes.POINTER(None)),
    ('value', ctypes.POINTER(None)),
    ('key_len', ctypes.c_uint32),
    ('value_len', ctypes.c_uint32),
]

class struct_ht_up_bucket_t(Structure):
    pass

class struct_ht_up_options_t(Structure):
    pass

class struct_ht_up_kv(Structure):
    pass

struct_ht_up_options_t._pack_ = 1 # source:False
struct_ht_up_options_t._fields_ = [
    ('cmp', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_uint64, ctypes.c_uint64)),
    ('hashfn', ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_uint64)),
    ('dupkey', ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64)),
    ('dupvalue', ctypes.CFUNCTYPE(ctypes.POINTER(None), ctypes.POINTER(None))),
    ('calcsizeK', ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_uint64)),
    ('calcsizeV', ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.POINTER(None))),
    ('freefn', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_ht_up_kv))),
    ('elem_size', ctypes.c_uint64),
]

struct_ht_up_t._pack_ = 1 # source:False
struct_ht_up_t._fields_ = [
    ('size', ctypes.c_uint32),
    ('count', ctypes.c_uint32),
    ('table', ctypes.POINTER(struct_ht_up_bucket_t)),
    ('prime_idx', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('opt', struct_ht_up_options_t),
]

struct_ht_up_bucket_t._pack_ = 1 # source:False
struct_ht_up_bucket_t._fields_ = [
    ('arr', ctypes.POINTER(struct_ht_up_kv)),
    ('count', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

struct_ht_up_kv._pack_ = 1 # source:False
struct_ht_up_kv._fields_ = [
    ('key', ctypes.c_uint64),
    ('value', ctypes.POINTER(None)),
    ('key_len', ctypes.c_uint32),
    ('value_len', ctypes.c_uint32),
]

class struct_r_bin_write_t(Structure):
    pass

class struct_r_bin_dbginfo_t(Structure):
    pass

class struct_r_buf_t(Structure):
    pass

class struct_r_bin_arch_options_t(Structure):
    pass

struct_r_bin_plugin_t._pack_ = 1 # source:False
struct_r_bin_plugin_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('desc', ctypes.POINTER(ctypes.c_char)),
    ('author', ctypes.POINTER(ctypes.c_char)),
    ('version', ctypes.POINTER(ctypes.c_char)),
    ('license', ctypes.POINTER(ctypes.c_char)),
    ('init', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None))),
    ('fini', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None))),
    ('get_sdb', ctypes.CFUNCTYPE(ctypes.POINTER(struct_sdb_t), ctypes.POINTER(struct_r_bin_file_t))),
    ('load_buffer', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_bin_file_t), ctypes.POINTER(ctypes.POINTER(None)), ctypes.POINTER(struct_r_buf_t), ctypes.c_uint64, ctypes.POINTER(struct_sdb_t))),
    ('size', ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(struct_r_bin_file_t))),
    ('destroy', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_bin_file_t))),
    ('check_bytes', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64)),
    ('check_buffer', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_buf_t))),
    ('baddr', ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(struct_r_bin_file_t))),
    ('boffset', ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(struct_r_bin_file_t))),
    ('binsym', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_bin_addr_t), ctypes.POINTER(struct_r_bin_file_t), ctypes.c_int32)),
    ('entries', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_bin_file_t))),
    ('sections', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_bin_file_t))),
    ('lines', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_bin_file_t))),
    ('symbols', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_bin_file_t))),
    ('imports', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_bin_file_t))),
    ('strings', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_bin_file_t))),
    ('info', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_bin_info_t), ctypes.POINTER(struct_r_bin_file_t))),
    ('fields', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_bin_file_t))),
    ('libs', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_bin_file_t))),
    ('relocs', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_bin_file_t))),
    ('trycatch', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_bin_file_t))),
    ('classes', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_bin_file_t))),
    ('mem', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_bin_file_t))),
    ('patch_relocs', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_bin_t))),
    ('maps', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_bin_file_t))),
    ('hashes', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_bin_file_t))),
    ('header', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_bin_file_t))),
    ('signature', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_bin_file_t), ctypes.c_bool)),
    ('demangle_type', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_char))),
    ('dbginfo', ctypes.POINTER(struct_r_bin_dbginfo_t)),
    ('write', ctypes.POINTER(struct_r_bin_write_t)),
    ('get_offset', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_bin_file_t), ctypes.c_int32, ctypes.c_int32)),
    ('get_name', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_bin_file_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_bool)),
    ('get_vaddr', ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(struct_r_bin_file_t), ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64)),
    ('create', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(struct_r_bin_arch_options_t))),
    ('demangle', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char))),
    ('regstate', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_bin_file_t))),
    ('file_type', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_bin_file_t))),
    ('minstrlen', ctypes.c_int32),
    ('strfilter', ctypes.c_char),
    ('PADDING_0', ctypes.c_ubyte * 3),
    ('user', ctypes.POINTER(None)),
]

class struct_sdb_gperf_t(Structure):
    pass

class struct_ls_t(Structure):
    pass

class struct_cdb(Structure):
    pass

struct_cdb._pack_ = 1 # source:False
struct_cdb._fields_ = [
    ('map', ctypes.POINTER(ctypes.c_char)),
    ('fd', ctypes.c_int32),
    ('size', ctypes.c_uint32),
    ('loop', ctypes.c_uint32),
    ('khash', ctypes.c_uint32),
    ('kpos', ctypes.c_uint32),
    ('hpos', ctypes.c_uint32),
    ('hslots', ctypes.c_uint32),
    ('dpos', ctypes.c_uint32),
    ('dlen', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

class struct_cdb_make(Structure):
    pass

class struct_cdb_hplist(Structure):
    pass

class struct_cdb_hp(Structure):
    pass

class struct_buffer(Structure):
    pass

struct_buffer._pack_ = 1 # source:False
struct_buffer._fields_ = [
    ('x', ctypes.POINTER(ctypes.c_char)),
    ('p', ctypes.c_uint32),
    ('n', ctypes.c_uint32),
    ('fd', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('op', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.c_int32)),
]

struct_cdb_make._pack_ = 1 # source:False
struct_cdb_make._fields_ = [
    ('bspace', ctypes.c_char * 8192),
    ('final', ctypes.c_char * 1024),
    ('count', ctypes.c_uint32 * 256),
    ('start', ctypes.c_uint32 * 256),
    ('head', ctypes.POINTER(struct_cdb_hplist)),
    ('split', ctypes.POINTER(struct_cdb_hp)),
    ('hash', ctypes.POINTER(struct_cdb_hp)),
    ('numentries', ctypes.c_uint32),
    ('memsize', ctypes.c_uint32),
    ('b', struct_buffer),
    ('pos', ctypes.c_uint32),
    ('fd', ctypes.c_int32),
]

class struct_c__SA_dict(Structure):
    pass

struct_c__SA_dict._pack_ = 1 # source:False
struct_c__SA_dict._fields_ = [
    ('table', ctypes.POINTER(ctypes.POINTER(None))),
    ('f', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
    ('size', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

class struct_sdb_kv(Structure):
    pass

struct_sdb_kv._pack_ = 1 # source:False
struct_sdb_kv._fields_ = [
    ('base', struct_ht_pp_kv),
    ('cas', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('expire', ctypes.c_uint64),
]

struct_sdb_t._pack_ = 1 # source:False
struct_sdb_t._fields_ = [
    ('dir', ctypes.POINTER(ctypes.c_char)),
    ('path', ctypes.POINTER(ctypes.c_char)),
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('fd', ctypes.c_int32),
    ('refs', ctypes.c_int32),
    ('lock', ctypes.c_int32),
    ('journal', ctypes.c_int32),
    ('db', struct_cdb),
    ('m', struct_cdb_make),
    ('ht', ctypes.POINTER(struct_ht_pp_t)),
    ('eod', ctypes.c_uint32),
    ('pos', ctypes.c_uint32),
    ('gp', ctypes.POINTER(struct_sdb_gperf_t)),
    ('fdump', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('ndump', ctypes.POINTER(ctypes.c_char)),
    ('expire', ctypes.c_uint64),
    ('last', ctypes.c_uint64),
    ('options', ctypes.c_int32),
    ('ns_lock', ctypes.c_int32),
    ('ns', ctypes.POINTER(struct_ls_t)),
    ('hooks', ctypes.POINTER(struct_ls_t)),
    ('tmpkv', struct_sdb_kv),
    ('depth', ctypes.c_uint32),
    ('timestamped', ctypes.c_bool),
    ('PADDING_1', ctypes.c_ubyte * 3),
    ('mht', struct_c__SA_dict),
]

struct_cdb_hp._pack_ = 1 # source:False
struct_cdb_hp._fields_ = [
    ('h', ctypes.c_uint32),
    ('p', ctypes.c_uint32),
]

struct_cdb_hplist._pack_ = 1 # source:False
struct_cdb_hplist._fields_ = [
    ('hp', struct_cdb_hp * 1000),
    ('next', ctypes.POINTER(struct_cdb_hplist)),
    ('num', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

struct_sdb_gperf_t._pack_ = 1 # source:False
struct_sdb_gperf_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('get', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char))),
    ('hash', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_char))),
]

class struct_ls_iter_t(Structure):
    pass

struct_ls_t._pack_ = 1 # source:False
struct_ls_t._fields_ = [
    ('length', ctypes.c_uint64),
    ('head', ctypes.POINTER(struct_ls_iter_t)),
    ('tail', ctypes.POINTER(struct_ls_iter_t)),
    ('free', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
    ('cmp', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(None))),
    ('sorted', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
]

struct_ls_iter_t._pack_ = 1 # source:False
struct_ls_iter_t._fields_ = [
    ('data', ctypes.POINTER(None)),
    ('n', ctypes.POINTER(struct_ls_iter_t)),
    ('p', ctypes.POINTER(struct_ls_iter_t)),
]

class struct_r_bin_xtr_plugin_t(Structure):
    pass

struct_r_bin_file_t._pack_ = 1 # source:False
struct_r_bin_file_t._fields_ = [
    ('file', ctypes.POINTER(ctypes.c_char)),
    ('fd', ctypes.c_int32),
    ('size', ctypes.c_int32),
    ('rawstr', ctypes.c_int32),
    ('strmode', ctypes.c_int32),
    ('id', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('buf', ctypes.POINTER(struct_r_buf_t)),
    ('offset', ctypes.c_uint64),
    ('o', ctypes.POINTER(struct_r_bin_object_t)),
    ('xtr_obj', ctypes.POINTER(None)),
    ('loadaddr', ctypes.c_uint64),
    ('minstrlen', ctypes.c_int32),
    ('maxstrlen', ctypes.c_int32),
    ('narch', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
    ('curxtr', ctypes.POINTER(struct_r_bin_xtr_plugin_t)),
    ('xtr_data', ctypes.POINTER(struct_r_list_t)),
    ('sdb', ctypes.POINTER(struct_sdb_t)),
    ('sdb_info', ctypes.POINTER(struct_sdb_t)),
    ('sdb_addrinfo', ctypes.POINTER(struct_sdb_t)),
    ('rbin', ctypes.POINTER(struct_r_bin_t)),
]

class struct_r_buffer_methods_t(Structure):
    pass

struct_r_buf_t._pack_ = 1 # source:False
struct_r_buf_t._fields_ = [
    ('methods', ctypes.POINTER(struct_r_buffer_methods_t)),
    ('priv', ctypes.POINTER(None)),
    ('whole_buf', ctypes.POINTER(ctypes.c_ubyte)),
    ('readonly', ctypes.c_bool),
    ('Oxff_priv', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte * 2),
    ('refctr', ctypes.c_int32),
]

struct_r_buffer_methods_t._pack_ = 1 # source:False
struct_r_buffer_methods_t._fields_ = [
    ('init', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(None))),
    ('fini', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_buf_t))),
    ('read', ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64)),
    ('write', ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64)),
    ('get_size', ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(struct_r_buf_t))),
    ('resize', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_buf_t), ctypes.c_uint64)),
    ('seek', ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.POINTER(struct_r_buf_t), ctypes.c_int64, ctypes.c_int32)),
    ('get_whole_buf', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_uint64))),
    ('free_whole_buf', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_buf_t))),
    ('nonempty_list', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_buf_t))),
]

class struct_r_bin_xtr_extract_t(Structure):
    pass

struct_r_bin_xtr_plugin_t._pack_ = 1 # source:False
struct_r_bin_xtr_plugin_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('desc', ctypes.POINTER(ctypes.c_char)),
    ('license', ctypes.POINTER(ctypes.c_char)),
    ('init', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None))),
    ('fini', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None))),
    ('check_buffer', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_buf_t))),
    ('extract_from_bytes', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_bin_xtr_extract_t), ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64, ctypes.c_int32)),
    ('extract_from_buffer', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_bin_xtr_extract_t), ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(struct_r_buf_t), ctypes.c_int32)),
    ('extractall_from_bytes', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64)),
    ('extractall_from_buffer', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(struct_r_buf_t))),
    ('extract', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_bin_xtr_extract_t), ctypes.POINTER(struct_r_bin_t), ctypes.c_int32)),
    ('extractall', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_bin_t))),
    ('load', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_bin_t))),
    ('size', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_bin_t))),
    ('destroy', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_bin_t))),
    ('free_xtr', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
]

class struct_r_bin_xtr_metadata_t(Structure):
    pass

struct_r_bin_xtr_extract_t._pack_ = 1 # source:False
struct_r_bin_xtr_extract_t._fields_ = [
    ('file', ctypes.POINTER(ctypes.c_char)),
    ('buf', ctypes.POINTER(struct_r_buf_t)),
    ('size', ctypes.c_uint64),
    ('offset', ctypes.c_uint64),
    ('baddr', ctypes.c_uint64),
    ('laddr', ctypes.c_uint64),
    ('file_count', ctypes.c_int32),
    ('loaded', ctypes.c_int32),
    ('metadata', ctypes.POINTER(struct_r_bin_xtr_metadata_t)),
]

struct_r_bin_xtr_metadata_t._pack_ = 1 # source:False
struct_r_bin_xtr_metadata_t._fields_ = [
    ('arch', ctypes.POINTER(ctypes.c_char)),
    ('bits', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('libname', ctypes.POINTER(ctypes.c_char)),
    ('machine', ctypes.POINTER(ctypes.c_char)),
    ('type', ctypes.POINTER(ctypes.c_char)),
    ('xtr_type', ctypes.POINTER(ctypes.c_char)),
]

struct_r_bin_dbginfo_t._pack_ = 1 # source:False
struct_r_bin_dbginfo_t._fields_ = [
    ('get_line', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_bin_file_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(ctypes.c_int32))),
]

struct_r_bin_write_t._pack_ = 1 # source:False
struct_r_bin_write_t._fields_ = [
    ('scn_resize', ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(struct_r_bin_file_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64)),
    ('scn_perms', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_bin_file_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32)),
    ('rpath_del', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_bin_file_t))),
    ('entry', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_bin_file_t), ctypes.c_uint64)),
    ('addlib', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_bin_file_t), ctypes.POINTER(ctypes.c_char))),
]

struct_r_bin_arch_options_t._pack_ = 1 # source:False
struct_r_bin_arch_options_t._fields_ = [
    ('arch', ctypes.POINTER(ctypes.c_char)),
    ('bits', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

RBinObject = struct_r_bin_object_t
RBinFile = struct_r_bin_file_t
class struct_r_bin_file_options_t(Structure):
    pass

struct_r_bin_file_options_t._pack_ = 1 # source:False
struct_r_bin_file_options_t._fields_ = [
    ('rawstr', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('baddr', ctypes.c_uint64),
    ('laddr', ctypes.c_uint64),
    ('paddr', ctypes.c_uint64),
    ('plugname', ctypes.POINTER(ctypes.c_char)),
]

RBinFileOptions = struct_r_bin_file_options_t
class struct_r_id_pool_t(Structure):
    pass

struct_r_id_storage_t._pack_ = 1 # source:False
struct_r_id_storage_t._fields_ = [
    ('pool', ctypes.POINTER(struct_r_id_pool_t)),
    ('data', ctypes.POINTER(ctypes.POINTER(None))),
    ('top_id', ctypes.c_uint32),
    ('size', ctypes.c_uint32),
]

class struct_r_queue_t(Structure):
    pass

struct_r_id_pool_t._pack_ = 1 # source:False
struct_r_id_pool_t._fields_ = [
    ('start_id', ctypes.c_uint32),
    ('last_id', ctypes.c_uint32),
    ('next_id', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('freed_ids', ctypes.POINTER(struct_r_queue_t)),
]

struct_r_queue_t._pack_ = 1 # source:False
struct_r_queue_t._fields_ = [
    ('elems', ctypes.POINTER(ctypes.POINTER(None))),
    ('capacity', ctypes.c_uint32),
    ('front', ctypes.c_uint32),
    ('rear', ctypes.c_int32),
    ('size', ctypes.c_uint32),
]

class struct_r_event_t(Structure):
    pass

class struct_r_cache_t(Structure):
    pass

class struct_r_core_bind_t(Structure):
    pass

struct_r_core_bind_t._pack_ = 1 # source:False
struct_r_core_bind_t._fields_ = [
    ('core', ctypes.POINTER(None)),
    ('cmd', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))),
    ('cmdf', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))),
    ('cmdstr', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))),
    ('cmdstrf', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))),
    ('puts', ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_char))),
    ('bphit', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(None))),
    ('syshit', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
    ('setab', ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char), ctypes.c_int32)),
    ('getName', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.c_uint64)),
    ('getNameDelta', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.c_uint64)),
    ('archbits', ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.c_uint64)),
    ('cfggeti', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))),
    ('cfgGet', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))),
    ('numGet', ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))),
    ('isMapped', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(None), ctypes.c_uint64, ctypes.c_int32)),
    ('syncDebugMaps', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(None))),
    ('pjWithEncoding', ctypes.CFUNCTYPE(ctypes.POINTER(None), ctypes.POINTER(None))),
]

class struct_r_skyline_t(Structure):
    pass

class struct_r_vector_t(Structure):
    pass

struct_r_vector_t._pack_ = 1 # source:False
struct_r_vector_t._fields_ = [
    ('a', ctypes.POINTER(None)),
    ('len', ctypes.c_uint64),
    ('capacity', ctypes.c_uint64),
    ('elem_size', ctypes.c_uint64),
    ('free', ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(None))),
    ('free_user', ctypes.POINTER(None)),
]

struct_r_skyline_t._pack_ = 1 # source:False
struct_r_skyline_t._fields_ = [
    ('v', struct_r_vector_t),
]

class struct_r_io_undo_t(Structure):
    pass

class struct_r_io_undos_t(Structure):
    pass

struct_r_io_undos_t._pack_ = 1 # source:False
struct_r_io_undos_t._fields_ = [
    ('off', ctypes.c_uint64),
    ('cursor', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

struct_r_io_undo_t._pack_ = 1 # source:False
struct_r_io_undo_t._fields_ = [
    ('s_enable', ctypes.c_int32),
    ('w_enable', ctypes.c_int32),
    ('w_list', ctypes.POINTER(struct_r_list_t)),
    ('w_init', ctypes.c_int32),
    ('idx', ctypes.c_int32),
    ('undos', ctypes.c_int32),
    ('redos', ctypes.c_int32),
    ('seek', struct_r_io_undos_t * 64),
]

class struct_r_pvector_t(Structure):
    _pack_ = 1 # source:False
    _fields_ = [
    ('v', struct_r_vector_t),
     ]

struct_r_io_t._pack_ = 1 # source:False
struct_r_io_t._fields_ = [
    ('desc', ctypes.POINTER(struct_r_io_desc_t)),
    ('off', ctypes.c_uint64),
    ('bits', ctypes.c_int32),
    ('va', ctypes.c_int32),
    ('ff', ctypes.c_bool),
    ('Oxff', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte * 6),
    ('addrbytes', ctypes.c_uint64),
    ('aslr', ctypes.c_bool),
    ('autofd', ctypes.c_bool),
    ('PADDING_1', ctypes.c_ubyte * 2),
    ('cached', ctypes.c_uint32),
    ('cachemode', ctypes.c_bool),
    ('PADDING_2', ctypes.c_ubyte * 3),
    ('p_cache', ctypes.c_uint32),
    ('map_ids', ctypes.POINTER(struct_r_id_pool_t)),
    ('maps', struct_r_pvector_t),
    ('map_skyline', struct_r_skyline_t),
    ('files', ctypes.POINTER(struct_r_id_storage_t)),
    ('buffer', ctypes.POINTER(struct_r_cache_t)),
    ('cache', struct_r_pvector_t),
    ('cache_skyline', struct_r_skyline_t),
    ('write_mask', ctypes.POINTER(ctypes.c_ubyte)),
    ('write_mask_len', ctypes.c_int32),
    ('PADDING_3', ctypes.c_ubyte * 4),
    ('mask', ctypes.c_uint64),
    ('undo', struct_r_io_undo_t),
    ('plugins', ctypes.POINTER(struct_ls_t)),
    ('runprofile', ctypes.POINTER(ctypes.c_char)),
    ('envprofile', ctypes.POINTER(ctypes.c_char)),
    ('args', ctypes.POINTER(ctypes.c_char)),
    ('event', ctypes.POINTER(struct_r_event_t)),
    ('cb_printf', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_char))),
    ('corebind', struct_r_core_bind_t),
    ('want_ptrace_wrap', ctypes.c_bool),
    ('PADDING_4', ctypes.c_ubyte * 7),
]

class struct_r_io_plugin_t(Structure):
    pass

struct_r_io_desc_t._pack_ = 1 # source:False
struct_r_io_desc_t._fields_ = [
    ('fd', ctypes.c_int32),
    ('perm', ctypes.c_int32),
    ('uri', ctypes.POINTER(ctypes.c_char)),
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('referer', ctypes.POINTER(ctypes.c_char)),
    ('cache', ctypes.POINTER(struct_ht_up_t)),
    ('data', ctypes.POINTER(None)),
    ('plugin', ctypes.POINTER(struct_r_io_plugin_t)),
    ('io', ctypes.POINTER(struct_r_io_t)),
]

struct_r_io_plugin_t._pack_ = 1 # source:False
struct_r_io_plugin_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('desc', ctypes.POINTER(ctypes.c_char)),
    ('version', ctypes.POINTER(ctypes.c_char)),
    ('author', ctypes.POINTER(ctypes.c_char)),
    ('license', ctypes.POINTER(ctypes.c_char)),
    ('widget', ctypes.POINTER(None)),
    ('uris', ctypes.POINTER(ctypes.c_char)),
    ('listener', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_io_desc_t))),
    ('init', ctypes.CFUNCTYPE(ctypes.c_int32)),
    ('undo', struct_r_io_undo_t),
    ('isdbg', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
    ('system', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_io_t), ctypes.POINTER(struct_r_io_desc_t), ctypes.POINTER(ctypes.c_char))),
    ('open', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_io_desc_t), ctypes.POINTER(struct_r_io_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32)),
    ('open_many', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_io_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32)),
    ('read', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_io_t), ctypes.POINTER(struct_r_io_desc_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)),
    ('lseek', ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(struct_r_io_t), ctypes.POINTER(struct_r_io_desc_t), ctypes.c_uint64, ctypes.c_int32)),
    ('write', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_io_t), ctypes.POINTER(struct_r_io_desc_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)),
    ('close', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_io_desc_t))),
    ('is_blockdevice', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_io_desc_t))),
    ('is_chardevice', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_io_desc_t))),
    ('getpid', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_io_desc_t))),
    ('gettid', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_io_desc_t))),
    ('getbase', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_io_desc_t), ctypes.POINTER(ctypes.c_uint64))),
    ('resize', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_io_t), ctypes.POINTER(struct_r_io_desc_t), ctypes.c_uint64)),
    ('extend', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_io_t), ctypes.POINTER(struct_r_io_desc_t), ctypes.c_uint64)),
    ('accept', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_io_t), ctypes.POINTER(struct_r_io_desc_t), ctypes.c_int32)),
    ('create', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_io_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32)),
    ('check', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_io_t), ctypes.POINTER(ctypes.c_char), ctypes.c_bool)),
]

struct_r_cache_t._pack_ = 1 # source:False
struct_r_cache_t._fields_ = [
    ('base', ctypes.c_uint64),
    ('buf', ctypes.POINTER(ctypes.c_ubyte)),
    ('len', ctypes.c_uint64),
]

struct_r_event_t._pack_ = 1 # source:False
struct_r_event_t._fields_ = [
    ('user', ctypes.POINTER(None)),
    ('incall', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
    ('callbacks', ctypes.POINTER(struct_ht_up_t)),
    ('all_callbacks', struct_r_vector_t),
    ('next_handle', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
]

class struct_r_interval_t(Structure):
    pass

struct_r_interval_t._pack_ = 1 # source:False
struct_r_interval_t._fields_ = [
    ('addr', ctypes.c_uint64),
    ('size', ctypes.c_uint64),
]

struct_r_io_map_t._pack_ = 1 # source:False
struct_r_io_map_t._fields_ = [
    ('fd', ctypes.c_int32),
    ('perm', ctypes.c_int32),
    ('id', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('itv', struct_r_interval_t),
    ('delta', ctypes.c_uint64),
    ('name', ctypes.POINTER(ctypes.c_char)),
]

RBinXtrMetadata = struct_r_bin_xtr_metadata_t
FREE_XTR = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None))
RBinXtrData = struct_r_bin_xtr_extract_t
r_bin_xtrdata_new = _libr_bin.r_bin_xtrdata_new
r_bin_xtrdata_new.restype = ctypes.POINTER(struct_r_bin_xtr_extract_t)
r_bin_xtrdata_new.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint32, ctypes.POINTER(struct_r_bin_xtr_metadata_t)]
r_bin_xtrdata_free = _libr_bin.r_bin_xtrdata_free
r_bin_xtrdata_free.restype = None
r_bin_xtrdata_free.argtypes = [ctypes.POINTER(None)]
RBinXtrPlugin = struct_r_bin_xtr_plugin_t
class struct_r_bin_ldr_plugin_t(Structure):
    pass

struct_r_bin_ldr_plugin_t._pack_ = 1 # source:False
struct_r_bin_ldr_plugin_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('desc', ctypes.POINTER(ctypes.c_char)),
    ('license', ctypes.POINTER(ctypes.c_char)),
    ('init', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None))),
    ('fini', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None))),
    ('load', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_bin_t))),
]

RBinLdrPlugin = struct_r_bin_ldr_plugin_t
RBinArchOptions = struct_r_bin_arch_options_t
class struct_r_bin_trycatch_t(Structure):
    pass

struct_r_bin_trycatch_t._pack_ = 1 # source:False
struct_r_bin_trycatch_t._fields_ = [
    ('source', ctypes.c_uint64),
    ('from', ctypes.c_uint64),
    ('to', ctypes.c_uint64),
    ('handler', ctypes.c_uint64),
    ('filter', ctypes.c_uint64),
]

RBinTrycatch = struct_r_bin_trycatch_t
r_bin_trycatch_new = _libr_bin.r_bin_trycatch_new
r_bin_trycatch_new.restype = ctypes.POINTER(struct_r_bin_trycatch_t)
r_bin_trycatch_new.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64]
r_bin_trycatch_free = _libr_bin.r_bin_trycatch_free
r_bin_trycatch_free.restype = None
r_bin_trycatch_free.argtypes = [ctypes.POINTER(struct_r_bin_trycatch_t)]
RBinPlugin = struct_r_bin_plugin_t
RBinSymbollCallback = ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_bin_object_t), ctypes.POINTER(None))
class struct_r_bin_section_t(Structure):
    pass

struct_r_bin_section_t._pack_ = 1 # source:False
struct_r_bin_section_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('size', ctypes.c_uint64),
    ('vsize', ctypes.c_uint64),
    ('vaddr', ctypes.c_uint64),
    ('paddr', ctypes.c_uint64),
    ('perm', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('arch', ctypes.POINTER(ctypes.c_char)),
    ('format', ctypes.POINTER(ctypes.c_char)),
    ('bits', ctypes.c_int32),
    ('has_strings', ctypes.c_bool),
    ('add', ctypes.c_bool),
    ('is_data', ctypes.c_bool),
    ('is_segment', ctypes.c_bool),
]

RBinSection = struct_r_bin_section_t
class struct_r_bin_class_t(Structure):
    pass

struct_r_bin_class_t._pack_ = 1 # source:False
struct_r_bin_class_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('super', ctypes.POINTER(ctypes.c_char)),
    ('visibility_str', ctypes.POINTER(ctypes.c_char)),
    ('index', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('addr', ctypes.c_uint64),
    ('methods', ctypes.POINTER(struct_r_list_t)),
    ('fields', ctypes.POINTER(struct_r_list_t)),
    ('visibility', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
]

RBinClass = struct_r_bin_class_t
class struct_r_bin_symbol_t(Structure):
    pass

struct_r_bin_symbol_t._pack_ = 1 # source:False
struct_r_bin_symbol_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('dname', ctypes.POINTER(ctypes.c_char)),
    ('libname', ctypes.POINTER(ctypes.c_char)),
    ('classname', ctypes.POINTER(ctypes.c_char)),
    ('forwarder', ctypes.POINTER(ctypes.c_char)),
    ('bind', ctypes.POINTER(ctypes.c_char)),
    ('type', ctypes.POINTER(ctypes.c_char)),
    ('rtype', ctypes.POINTER(ctypes.c_char)),
    ('is_imported', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
    ('visibility_str', ctypes.POINTER(ctypes.c_char)),
    ('vaddr', ctypes.c_uint64),
    ('paddr', ctypes.c_uint64),
    ('size', ctypes.c_uint32),
    ('ordinal', ctypes.c_uint32),
    ('visibility', ctypes.c_uint32),
    ('bits', ctypes.c_int32),
    ('method_flags', ctypes.c_uint64),
    ('dup_count', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
]

RBinSymbol = struct_r_bin_symbol_t
class struct_r_bin_import_t(Structure):
    pass

struct_r_bin_import_t._pack_ = 1 # source:False
struct_r_bin_import_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('libname', ctypes.POINTER(ctypes.c_char)),
    ('bind', ctypes.POINTER(ctypes.c_char)),
    ('type', ctypes.POINTER(ctypes.c_char)),
    ('classname', ctypes.POINTER(ctypes.c_char)),
    ('descriptor', ctypes.POINTER(ctypes.c_char)),
    ('ordinal', ctypes.c_uint32),
    ('visibility', ctypes.c_uint32),
]

RBinImport = struct_r_bin_import_t
class struct_r_bin_reloc_t(Structure):
    pass

struct_r_bin_reloc_t._pack_ = 1 # source:False
struct_r_bin_reloc_t._fields_ = [
    ('type', ctypes.c_ubyte),
    ('additive', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte * 6),
    ('symbol', ctypes.POINTER(struct_r_bin_symbol_t)),
    ('import', ctypes.POINTER(struct_r_bin_import_t)),
    ('addend', ctypes.c_int64),
    ('vaddr', ctypes.c_uint64),
    ('paddr', ctypes.c_uint64),
    ('visibility', ctypes.c_uint32),
    ('is_ifunc', ctypes.c_bool),
    ('PADDING_1', ctypes.c_ubyte * 3),
    ('vrb', struct_r_rb_node_t),
]

RBinReloc = struct_r_bin_reloc_t
class struct_r_bin_string_t(Structure):
    pass

struct_r_bin_string_t._pack_ = 1 # source:False
struct_r_bin_string_t._fields_ = [
    ('string', ctypes.POINTER(ctypes.c_char)),
    ('vaddr', ctypes.c_uint64),
    ('paddr', ctypes.c_uint64),
    ('ordinal', ctypes.c_uint32),
    ('size', ctypes.c_uint32),
    ('length', ctypes.c_uint32),
    ('type', ctypes.c_char),
    ('PADDING_0', ctypes.c_ubyte * 3),
]

RBinString = struct_r_bin_string_t
class struct_r_bin_field_t(Structure):
    pass

struct_r_bin_field_t._pack_ = 1 # source:False
struct_r_bin_field_t._fields_ = [
    ('vaddr', ctypes.c_uint64),
    ('paddr', ctypes.c_uint64),
    ('size', ctypes.c_int32),
    ('offset', ctypes.c_int32),
    ('visibility', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('type', ctypes.POINTER(ctypes.c_char)),
    ('comment', ctypes.POINTER(ctypes.c_char)),
    ('format', ctypes.POINTER(ctypes.c_char)),
    ('format_named', ctypes.c_bool),
    ('PADDING_1', ctypes.c_ubyte * 7),
    ('flags', ctypes.c_uint64),
]

RBinField = struct_r_bin_field_t
r_bin_field_new = _libr_bin.r_bin_field_new
r_bin_field_new.restype = ctypes.POINTER(struct_r_bin_field_t)
r_bin_field_new.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_bool]
r_bin_field_free = _libr_bin.r_bin_field_free
r_bin_field_free.restype = None
r_bin_field_free.argtypes = [ctypes.POINTER(None)]
class struct_r_bin_mem_t(Structure):
    pass

struct_r_bin_mem_t._pack_ = 1 # source:False
struct_r_bin_mem_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('addr', ctypes.c_uint64),
    ('size', ctypes.c_int32),
    ('perms', ctypes.c_int32),
    ('mirrors', ctypes.POINTER(struct_r_list_t)),
]

RBinMem = struct_r_bin_mem_t
class struct_r_bin_map_t(Structure):
    pass

struct_r_bin_map_t._pack_ = 1 # source:False
struct_r_bin_map_t._fields_ = [
    ('addr', ctypes.c_uint64),
    ('offset', ctypes.c_uint64),
    ('size', ctypes.c_int32),
    ('perms', ctypes.c_int32),
    ('file', ctypes.POINTER(ctypes.c_char)),
]

RBinMap = struct_r_bin_map_t
RBinDbgInfo = struct_r_bin_dbginfo_t
RBinWrite = struct_r_bin_write_t
RBinGetOffset = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_bin_t), ctypes.c_int32, ctypes.c_int32)
RBinGetName = ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_bin_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_bool)
RBinGetSections = ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_bin_t))
RBinGetSectionAt = ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_bin_section_t), ctypes.POINTER(struct_r_bin_t), ctypes.c_uint64)
RBinDemangle = ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_bin_file_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64, ctypes.c_bool)
class struct_r_bin_bind_t(Structure):
    pass

struct_r_bin_bind_t._pack_ = 1 # source:False
struct_r_bin_bind_t._fields_ = [
    ('bin', ctypes.POINTER(struct_r_bin_t)),
    ('get_offset', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_bin_t), ctypes.c_int32, ctypes.c_int32)),
    ('get_name', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_bin_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_bool)),
    ('get_sections', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_bin_t))),
    ('get_vsect_at', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_bin_section_t), ctypes.POINTER(struct_r_bin_t), ctypes.c_uint64)),
    ('demangle', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_bin_file_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64, ctypes.c_bool)),
    ('visibility', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

RBinBind = struct_r_bin_bind_t
r_bin_section_new = _libraries['FIXME_STUB'].r_bin_section_new
r_bin_section_new.restype = ctypes.POINTER(struct_r_bin_section_t)
r_bin_section_new.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_bin_section_free = _libraries['FIXME_STUB'].r_bin_section_free
r_bin_section_free.restype = None
r_bin_section_free.argtypes = [ctypes.POINTER(struct_r_bin_section_t)]
r_bin_info_free = _libr_bin.r_bin_info_free
r_bin_info_free.restype = None
r_bin_info_free.argtypes = [ctypes.POINTER(struct_r_bin_info_t)]
r_bin_import_free = _libr_bin.r_bin_import_free
r_bin_import_free.restype = None
r_bin_import_free.argtypes = [ctypes.POINTER(struct_r_bin_import_t)]
r_bin_symbol_free = _libr_bin.r_bin_symbol_free
r_bin_symbol_free.restype = None
r_bin_symbol_free.argtypes = [ctypes.POINTER(None)]
r_bin_symbol_new = _libr_bin.r_bin_symbol_new
r_bin_symbol_new.restype = ctypes.POINTER(struct_r_bin_symbol_t)
r_bin_symbol_new.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_uint64, ctypes.c_uint64]
r_bin_string_free = _libr_bin.r_bin_string_free
r_bin_string_free.restype = None
r_bin_string_free.argtypes = [ctypes.POINTER(None)]
class struct_r_bin_options_t(Structure):
    pass

struct_r_bin_options_t._pack_ = 1 # source:False
struct_r_bin_options_t._fields_ = [
    ('pluginname', ctypes.POINTER(ctypes.c_char)),
    ('baseaddr', ctypes.c_uint64),
    ('loadaddr', ctypes.c_uint64),
    ('sz', ctypes.c_uint64),
    ('xtr_idx', ctypes.c_int32),
    ('rawstr', ctypes.c_int32),
    ('fd', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('filename', ctypes.POINTER(ctypes.c_char)),
]

RBinOptions = struct_r_bin_options_t
r_bin_import_clone = _libr_bin.r_bin_import_clone
r_bin_import_clone.restype = ctypes.POINTER(struct_r_bin_import_t)
r_bin_import_clone.argtypes = [ctypes.POINTER(struct_r_bin_import_t)]
r_bin_symbol_name = _libr_bin.r_bin_symbol_name
r_bin_symbol_name.restype = ctypes.POINTER(ctypes.c_char)
r_bin_symbol_name.argtypes = [ctypes.POINTER(struct_r_bin_symbol_t)]
RBinSymbolCallback = ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_bin_object_t), ctypes.POINTER(struct_r_bin_symbol_t))
r_bin_options_init = _libr_bin.r_bin_options_init
r_bin_options_init.restype = None
r_bin_options_init.argtypes = [ctypes.POINTER(struct_r_bin_options_t), ctypes.c_int32, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int32]
r_bin_arch_options_init = _libr_bin.r_bin_arch_options_init
r_bin_arch_options_init.restype = None
r_bin_arch_options_init.argtypes = [ctypes.POINTER(struct_r_bin_arch_options_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_bin_new = _libr_bin.r_bin_new
r_bin_new.restype = ctypes.POINTER(struct_r_bin_t)
r_bin_new.argtypes = []
r_bin_free = _libr_bin.r_bin_free
r_bin_free.restype = None
r_bin_free.argtypes = [ctypes.POINTER(struct_r_bin_t)]
r_bin_open = _libr_bin.r_bin_open
r_bin_open.restype = ctypes.c_bool
r_bin_open.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_bin_options_t)]
r_bin_open_io = _libr_bin.r_bin_open_io
r_bin_open_io.restype = ctypes.c_bool
r_bin_open_io.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(struct_r_bin_options_t)]
r_bin_open_buf = _libr_bin.r_bin_open_buf
r_bin_open_buf.restype = ctypes.c_bool
r_bin_open_buf.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(struct_r_bin_options_t)]
r_bin_reload = _libr_bin.r_bin_reload
r_bin_reload.restype = ctypes.c_bool
r_bin_reload.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.c_uint32, ctypes.c_uint64]
r_bin_bind = _libr_bin.r_bin_bind
r_bin_bind.restype = None
r_bin_bind.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(struct_r_bin_bind_t)]
r_bin_add = _libr_bin.r_bin_add
r_bin_add.restype = ctypes.c_bool
r_bin_add.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(struct_r_bin_plugin_t)]
r_bin_xtr_add = _libr_bin.r_bin_xtr_add
r_bin_xtr_add.restype = ctypes.c_bool
r_bin_xtr_add.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(struct_r_bin_xtr_plugin_t)]
r_bin_ldr_add = _libr_bin.r_bin_ldr_add
r_bin_ldr_add.restype = ctypes.c_bool
r_bin_ldr_add.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(struct_r_bin_ldr_plugin_t)]
class struct_pj_t(Structure):
    pass


# values for enumeration 'PJEncodingStr'
PJEncodingStr__enumvalues = {
    0: 'PJ_ENCODING_STR_DEFAULT',
    1: 'PJ_ENCODING_STR_BASE64',
    2: 'PJ_ENCODING_STR_HEX',
    3: 'PJ_ENCODING_STR_ARRAY',
    4: 'PJ_ENCODING_STR_STRIP',
}
PJ_ENCODING_STR_DEFAULT = 0
PJ_ENCODING_STR_BASE64 = 1
PJ_ENCODING_STR_HEX = 2
PJ_ENCODING_STR_ARRAY = 3
PJ_ENCODING_STR_STRIP = 4
PJEncodingStr = ctypes.c_uint32 # enum
class struct_c__SA_RStrBuf(Structure):
    pass

struct_c__SA_RStrBuf._pack_ = 1 # source:False
struct_c__SA_RStrBuf._fields_ = [
    ('buf', ctypes.c_char * 32),
    ('len', ctypes.c_uint64),
    ('ptr', ctypes.POINTER(ctypes.c_char)),
    ('ptrlen', ctypes.c_uint64),
    ('weakref', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
]


# values for enumeration 'PJEncodingNum'
PJEncodingNum__enumvalues = {
    0: 'PJ_ENCODING_NUM_DEFAULT',
    1: 'PJ_ENCODING_NUM_STR',
    2: 'PJ_ENCODING_NUM_HEX',
}
PJ_ENCODING_NUM_DEFAULT = 0
PJ_ENCODING_NUM_STR = 1
PJ_ENCODING_NUM_HEX = 2
PJEncodingNum = ctypes.c_uint32 # enum
struct_pj_t._pack_ = 1 # source:False
struct_pj_t._fields_ = [
    ('sb', struct_c__SA_RStrBuf),
    ('is_first', ctypes.c_bool),
    ('is_key', ctypes.c_bool),
    ('braces', ctypes.c_char * 128),
    ('PADDING_0', ctypes.c_ubyte * 2),
    ('level', ctypes.c_int32),
    ('str_encoding', PJEncodingStr),
    ('num_encoding', PJEncodingNum),
]

r_bin_list = _libr_bin.r_bin_list
r_bin_list.restype = None
r_bin_list.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(struct_pj_t), ctypes.c_int32]
r_bin_list_plugin = _libr_bin.r_bin_list_plugin
r_bin_list_plugin.restype = ctypes.c_bool
r_bin_list_plugin.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_pj_t), ctypes.c_int32]
r_bin_get_binplugin_by_bytes = _libraries['FIXME_STUB'].r_bin_get_binplugin_by_bytes
r_bin_get_binplugin_by_bytes.restype = ctypes.POINTER(struct_r_bin_plugin_t)
r_bin_get_binplugin_by_bytes.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64]
r_bin_get_binplugin_by_buffer = _libr_bin.r_bin_get_binplugin_by_buffer
r_bin_get_binplugin_by_buffer.restype = ctypes.POINTER(struct_r_bin_plugin_t)
r_bin_get_binplugin_by_buffer.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(struct_r_buf_t)]
r_bin_force_plugin = _libr_bin.r_bin_force_plugin
r_bin_force_plugin.restype = None
r_bin_force_plugin.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(ctypes.c_char)]
r_bin_get_baddr = _libr_bin.r_bin_get_baddr
r_bin_get_baddr.restype = ctypes.c_uint64
r_bin_get_baddr.argtypes = [ctypes.POINTER(struct_r_bin_t)]
r_bin_file_get_baddr = _libr_bin.r_bin_file_get_baddr
r_bin_file_get_baddr.restype = ctypes.c_uint64
r_bin_file_get_baddr.argtypes = [ctypes.POINTER(struct_r_bin_file_t)]
r_bin_set_user_ptr = _libr_bin.r_bin_set_user_ptr
r_bin_set_user_ptr.restype = None
r_bin_set_user_ptr.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(None)]
r_bin_get_info = _libr_bin.r_bin_get_info
r_bin_get_info.restype = ctypes.POINTER(struct_r_bin_info_t)
r_bin_get_info.argtypes = [ctypes.POINTER(struct_r_bin_t)]
r_bin_set_baddr = _libr_bin.r_bin_set_baddr
r_bin_set_baddr.restype = None
r_bin_set_baddr.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.c_uint64]
r_bin_get_laddr = _libr_bin.r_bin_get_laddr
r_bin_get_laddr.restype = ctypes.c_uint64
r_bin_get_laddr.argtypes = [ctypes.POINTER(struct_r_bin_t)]
r_bin_get_size = _libr_bin.r_bin_get_size
r_bin_get_size.restype = ctypes.c_uint64
r_bin_get_size.argtypes = [ctypes.POINTER(struct_r_bin_t)]
r_bin_get_sym = _libr_bin.r_bin_get_sym
r_bin_get_sym.restype = ctypes.POINTER(struct_r_bin_addr_t)
r_bin_get_sym.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.c_int32]
r_bin_raw_strings = _libr_bin.r_bin_raw_strings
r_bin_raw_strings.restype = ctypes.POINTER(struct_r_list_t)
r_bin_raw_strings.argtypes = [ctypes.POINTER(struct_r_bin_file_t), ctypes.c_int32]
r_bin_dump_strings = _libr_bin.r_bin_dump_strings
r_bin_dump_strings.restype = ctypes.POINTER(struct_r_list_t)
r_bin_dump_strings.argtypes = [ctypes.POINTER(struct_r_bin_file_t), ctypes.c_int32, ctypes.c_int32]
r_bin_get_entries = _libr_bin.r_bin_get_entries
r_bin_get_entries.restype = ctypes.POINTER(struct_r_list_t)
r_bin_get_entries.argtypes = [ctypes.POINTER(struct_r_bin_t)]
r_bin_get_fields = _libr_bin.r_bin_get_fields
r_bin_get_fields.restype = ctypes.POINTER(struct_r_list_t)
r_bin_get_fields.argtypes = [ctypes.POINTER(struct_r_bin_t)]
r_bin_get_imports = _libr_bin.r_bin_get_imports
r_bin_get_imports.restype = ctypes.POINTER(struct_r_list_t)
r_bin_get_imports.argtypes = [ctypes.POINTER(struct_r_bin_t)]
r_bin_get_libs = _libr_bin.r_bin_get_libs
r_bin_get_libs.restype = ctypes.POINTER(struct_r_list_t)
r_bin_get_libs.argtypes = [ctypes.POINTER(struct_r_bin_t)]
r_bin_patch_relocs = _libr_bin.r_bin_patch_relocs
r_bin_patch_relocs.restype = ctypes.POINTER(struct_r_rb_node_t)
r_bin_patch_relocs.argtypes = [ctypes.POINTER(struct_r_bin_t)]
r_bin_patch_relocs_list = _libr_bin.r_bin_patch_relocs_list
r_bin_patch_relocs_list.restype = ctypes.POINTER(struct_r_list_t)
r_bin_patch_relocs_list.argtypes = [ctypes.POINTER(struct_r_bin_t)]
r_bin_get_relocs = _libr_bin.r_bin_get_relocs
r_bin_get_relocs.restype = ctypes.POINTER(struct_r_rb_node_t)
r_bin_get_relocs.argtypes = [ctypes.POINTER(struct_r_bin_t)]
r_bin_get_relocs_list = _libr_bin.r_bin_get_relocs_list
r_bin_get_relocs_list.restype = ctypes.POINTER(struct_r_list_t)
r_bin_get_relocs_list.argtypes = [ctypes.POINTER(struct_r_bin_t)]
r_bin_get_sections = _libr_bin.r_bin_get_sections
r_bin_get_sections.restype = ctypes.POINTER(struct_r_list_t)
r_bin_get_sections.argtypes = [ctypes.POINTER(struct_r_bin_t)]
r_bin_get_classes = _libr_bin.r_bin_get_classes
r_bin_get_classes.restype = ctypes.POINTER(struct_r_list_t)
r_bin_get_classes.argtypes = [ctypes.POINTER(struct_r_bin_t)]
r_bin_get_strings = _libr_bin.r_bin_get_strings
r_bin_get_strings.restype = ctypes.POINTER(struct_r_list_t)
r_bin_get_strings.argtypes = [ctypes.POINTER(struct_r_bin_t)]
r_bin_file_get_trycatch = _libr_bin.r_bin_file_get_trycatch
r_bin_file_get_trycatch.restype = ctypes.POINTER(struct_r_list_t)
r_bin_file_get_trycatch.argtypes = [ctypes.POINTER(struct_r_bin_file_t)]
r_bin_get_symbols = _libr_bin.r_bin_get_symbols
r_bin_get_symbols.restype = ctypes.POINTER(struct_r_list_t)
r_bin_get_symbols.argtypes = [ctypes.POINTER(struct_r_bin_t)]
r_bin_reset_strings = _libr_bin.r_bin_reset_strings
r_bin_reset_strings.restype = ctypes.POINTER(struct_r_list_t)
r_bin_reset_strings.argtypes = [ctypes.POINTER(struct_r_bin_t)]
r_bin_is_string = _libr_bin.r_bin_is_string
r_bin_is_string.restype = ctypes.c_int32
r_bin_is_string.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.c_uint64]
r_bin_is_big_endian = _libr_bin.r_bin_is_big_endian
r_bin_is_big_endian.restype = ctypes.c_int32
r_bin_is_big_endian.argtypes = [ctypes.POINTER(struct_r_bin_t)]
r_bin_is_static = _libr_bin.r_bin_is_static
r_bin_is_static.restype = ctypes.c_int32
r_bin_is_static.argtypes = [ctypes.POINTER(struct_r_bin_t)]
r_bin_get_vaddr = _libr_bin.r_bin_get_vaddr
r_bin_get_vaddr.restype = ctypes.c_uint64
r_bin_get_vaddr.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.c_uint64, ctypes.c_uint64]
r_bin_file_get_vaddr = _libr_bin.r_bin_file_get_vaddr
r_bin_file_get_vaddr.restype = ctypes.c_uint64
r_bin_file_get_vaddr.argtypes = [ctypes.POINTER(struct_r_bin_file_t), ctypes.c_uint64, ctypes.c_uint64]
r_bin_a2b = _libr_bin.r_bin_a2b
r_bin_a2b.restype = ctypes.c_uint64
r_bin_a2b.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.c_uint64]
r_bin_load_languages = _libr_bin.r_bin_load_languages
r_bin_load_languages.restype = ctypes.c_int32
r_bin_load_languages.argtypes = [ctypes.POINTER(struct_r_bin_file_t)]
r_bin_cur = _libr_bin.r_bin_cur
r_bin_cur.restype = ctypes.POINTER(struct_r_bin_file_t)
r_bin_cur.argtypes = [ctypes.POINTER(struct_r_bin_t)]
r_bin_cur_object = _libr_bin.r_bin_cur_object
r_bin_cur_object.restype = ctypes.POINTER(struct_r_bin_object_t)
r_bin_cur_object.argtypes = [ctypes.POINTER(struct_r_bin_t)]
r_bin_select = _libr_bin.r_bin_select
r_bin_select.restype = ctypes.c_bool
r_bin_select.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
r_bin_select_bfid = _libr_bin.r_bin_select_bfid
r_bin_select_bfid.restype = ctypes.c_bool
r_bin_select_bfid.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.c_uint32]
r_bin_use_arch = _libr_bin.r_bin_use_arch
r_bin_use_arch.restype = ctypes.c_bool
r_bin_use_arch.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
r_bin_list_archs = _libr_bin.r_bin_list_archs
r_bin_list_archs.restype = None
r_bin_list_archs.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(struct_pj_t), ctypes.c_int32]
r_bin_create = _libr_bin.r_bin_create
r_bin_create.restype = ctypes.POINTER(struct_r_buf_t)
r_bin_create.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(struct_r_bin_arch_options_t)]
r_bin_package = _libr_bin.r_bin_package
r_bin_package.restype = ctypes.POINTER(struct_r_buf_t)
r_bin_package.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_list_t)]
r_bin_string_type = _libr_bin.r_bin_string_type
r_bin_string_type.restype = ctypes.POINTER(ctypes.c_char)
r_bin_string_type.argtypes = [ctypes.c_int32]
r_bin_entry_type_string = _libr_bin.r_bin_entry_type_string
r_bin_entry_type_string.restype = ctypes.POINTER(ctypes.c_char)
r_bin_entry_type_string.argtypes = [ctypes.c_int32]
r_bin_file_object_new_from_xtr_data = _libr_bin.r_bin_file_object_new_from_xtr_data
r_bin_file_object_new_from_xtr_data.restype = ctypes.c_bool
r_bin_file_object_new_from_xtr_data.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(struct_r_bin_file_t), ctypes.c_uint64, ctypes.c_uint64, ctypes.POINTER(struct_r_bin_xtr_extract_t)]
r_bin_file_close = _libr_bin.r_bin_file_close
r_bin_file_close.restype = ctypes.c_bool
r_bin_file_close.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.c_int32]
r_bin_file_free = _libr_bin.r_bin_file_free
r_bin_file_free.restype = None
r_bin_file_free.argtypes = [ctypes.POINTER(None)]
r_bin_file_at = _libr_bin.r_bin_file_at
r_bin_file_at.restype = ctypes.POINTER(struct_r_bin_file_t)
r_bin_file_at.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.c_uint64]
r_bin_file_find_by_object_id = _libraries['FIXME_STUB'].r_bin_file_find_by_object_id
r_bin_file_find_by_object_id.restype = ctypes.POINTER(struct_r_bin_file_t)
r_bin_file_find_by_object_id.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.c_uint32]
r_bin_file_get_symbols = _libr_bin.r_bin_file_get_symbols
r_bin_file_get_symbols.restype = ctypes.POINTER(struct_r_list_t)
r_bin_file_get_symbols.argtypes = [ctypes.POINTER(struct_r_bin_file_t)]
r_bin_file_add_class = _libr_bin.r_bin_file_add_class
r_bin_file_add_class.restype = ctypes.POINTER(struct_r_bin_class_t)
r_bin_file_add_class.argtypes = [ctypes.POINTER(struct_r_bin_file_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_bin_file_add_method = _libr_bin.r_bin_file_add_method
r_bin_file_add_method.restype = ctypes.POINTER(struct_r_bin_symbol_t)
r_bin_file_add_method.argtypes = [ctypes.POINTER(struct_r_bin_file_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_bin_file_add_field = _libr_bin.r_bin_file_add_field
r_bin_file_add_field.restype = ctypes.POINTER(struct_r_bin_field_t)
r_bin_file_add_field.argtypes = [ctypes.POINTER(struct_r_bin_file_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_bin_file_find_by_arch_bits = _libr_bin.r_bin_file_find_by_arch_bits
r_bin_file_find_by_arch_bits.restype = ctypes.POINTER(struct_r_bin_file_t)
r_bin_file_find_by_arch_bits.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_bin_file_find_by_id = _libr_bin.r_bin_file_find_by_id
r_bin_file_find_by_id.restype = ctypes.POINTER(struct_r_bin_file_t)
r_bin_file_find_by_id.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.c_uint32]
r_bin_file_find_by_fd = _libr_bin.r_bin_file_find_by_fd
r_bin_file_find_by_fd.restype = ctypes.POINTER(struct_r_bin_file_t)
r_bin_file_find_by_fd.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.c_uint32]
r_bin_file_find_by_name = _libr_bin.r_bin_file_find_by_name
r_bin_file_find_by_name.restype = ctypes.POINTER(struct_r_bin_file_t)
r_bin_file_find_by_name.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(ctypes.c_char)]
r_bin_file_set_cur_binfile = _libr_bin.r_bin_file_set_cur_binfile
r_bin_file_set_cur_binfile.restype = ctypes.c_bool
r_bin_file_set_cur_binfile.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(struct_r_bin_file_t)]
r_bin_file_set_cur_by_name = _libr_bin.r_bin_file_set_cur_by_name
r_bin_file_set_cur_by_name.restype = ctypes.c_bool
r_bin_file_set_cur_by_name.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(ctypes.c_char)]
r_bin_file_deref = _libr_bin.r_bin_file_deref
r_bin_file_deref.restype = ctypes.c_bool
r_bin_file_deref.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(struct_r_bin_file_t)]
r_bin_file_set_cur_by_fd = _libr_bin.r_bin_file_set_cur_by_fd
r_bin_file_set_cur_by_fd.restype = ctypes.c_bool
r_bin_file_set_cur_by_fd.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.c_uint32]
r_bin_file_set_cur_by_id = _libr_bin.r_bin_file_set_cur_by_id
r_bin_file_set_cur_by_id.restype = ctypes.c_bool
r_bin_file_set_cur_by_id.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.c_uint32]
r_bin_file_delete_all = _libr_bin.r_bin_file_delete_all
r_bin_file_delete_all.restype = ctypes.c_uint64
r_bin_file_delete_all.argtypes = [ctypes.POINTER(struct_r_bin_t)]
r_bin_file_delete = _libr_bin.r_bin_file_delete
r_bin_file_delete.restype = ctypes.c_bool
r_bin_file_delete.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.c_uint32]
r_bin_file_compute_hashes = _libr_bin.r_bin_file_compute_hashes
r_bin_file_compute_hashes.restype = ctypes.POINTER(struct_r_list_t)
r_bin_file_compute_hashes.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.c_uint64]
r_bin_file_set_hashes = _libr_bin.r_bin_file_set_hashes
r_bin_file_set_hashes.restype = ctypes.POINTER(struct_r_list_t)
r_bin_file_set_hashes.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(struct_r_list_t)]
r_bin_file_cur_plugin = _libr_bin.r_bin_file_cur_plugin
r_bin_file_cur_plugin.restype = ctypes.POINTER(struct_r_bin_plugin_t)
r_bin_file_cur_plugin.argtypes = [ctypes.POINTER(struct_r_bin_file_t)]
r_bin_file_hash_free = _libr_bin.r_bin_file_hash_free
r_bin_file_hash_free.restype = None
r_bin_file_hash_free.argtypes = [ctypes.POINTER(struct_r_bin_file_hash_t)]
r_bin_object_set_items = _libr_bin.r_bin_object_set_items
r_bin_object_set_items.restype = ctypes.c_int32
r_bin_object_set_items.argtypes = [ctypes.POINTER(struct_r_bin_file_t), ctypes.POINTER(struct_r_bin_object_t)]
r_bin_object_delete = _libr_bin.r_bin_object_delete
r_bin_object_delete.restype = ctypes.c_bool
r_bin_object_delete.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.c_uint32]
r_bin_mem_free = _libr_bin.r_bin_mem_free
r_bin_mem_free.restype = None
r_bin_mem_free.argtypes = [ctypes.POINTER(None)]
r_bin_demangle = _libr_bin.r_bin_demangle
r_bin_demangle.restype = ctypes.POINTER(ctypes.c_char)
r_bin_demangle.argtypes = [ctypes.POINTER(struct_r_bin_file_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64, ctypes.c_bool]
r_bin_demangle_java = _libr_bin.r_bin_demangle_java
r_bin_demangle_java.restype = ctypes.POINTER(ctypes.c_char)
r_bin_demangle_java.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_bin_demangle_cxx = _libr_bin.r_bin_demangle_cxx
r_bin_demangle_cxx.restype = ctypes.POINTER(ctypes.c_char)
r_bin_demangle_cxx.argtypes = [ctypes.POINTER(struct_r_bin_file_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64]
r_bin_demangle_msvc = _libr_bin.r_bin_demangle_msvc
r_bin_demangle_msvc.restype = ctypes.POINTER(ctypes.c_char)
r_bin_demangle_msvc.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_bin_demangle_swift = _libr_bin.r_bin_demangle_swift
r_bin_demangle_swift.restype = ctypes.POINTER(ctypes.c_char)
r_bin_demangle_swift.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_bool]
r_bin_demangle_objc = _libr_bin.r_bin_demangle_objc
r_bin_demangle_objc.restype = ctypes.POINTER(ctypes.c_char)
r_bin_demangle_objc.argtypes = [ctypes.POINTER(struct_r_bin_file_t), ctypes.POINTER(ctypes.c_char)]
r_bin_demangle_rust = _libr_bin.r_bin_demangle_rust
r_bin_demangle_rust.restype = ctypes.POINTER(ctypes.c_char)
r_bin_demangle_rust.argtypes = [ctypes.POINTER(struct_r_bin_file_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64]
r_bin_demangle_type = _libr_bin.r_bin_demangle_type
r_bin_demangle_type.restype = ctypes.c_int32
r_bin_demangle_type.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_bin_demangle_list = _libr_bin.r_bin_demangle_list
r_bin_demangle_list.restype = None
r_bin_demangle_list.argtypes = [ctypes.POINTER(struct_r_bin_t)]
r_bin_demangle_plugin = _libr_bin.r_bin_demangle_plugin
r_bin_demangle_plugin.restype = ctypes.POINTER(ctypes.c_char)
r_bin_demangle_plugin.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_bin_get_meth_flag_string = _libr_bin.r_bin_get_meth_flag_string
r_bin_get_meth_flag_string.restype = ctypes.POINTER(ctypes.c_char)
r_bin_get_meth_flag_string.argtypes = [ctypes.c_uint64, ctypes.c_bool]
r_bin_get_section_at = _libr_bin.r_bin_get_section_at
r_bin_get_section_at.restype = ctypes.POINTER(struct_r_bin_section_t)
r_bin_get_section_at.argtypes = [ctypes.POINTER(struct_r_bin_object_t), ctypes.c_uint64, ctypes.c_int32]
r_bin_addr2line = _libr_bin.r_bin_addr2line
r_bin_addr2line.restype = ctypes.c_bool
r_bin_addr2line.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(ctypes.c_int32)]
r_bin_addr2line2 = _libr_bin.r_bin_addr2line2
r_bin_addr2line2.restype = ctypes.c_bool
r_bin_addr2line2.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(ctypes.c_int32)]
r_bin_addr2text = _libr_bin.r_bin_addr2text
r_bin_addr2text.restype = ctypes.POINTER(ctypes.c_char)
r_bin_addr2text.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.c_uint64, ctypes.c_int32]
r_bin_addr2fileline = _libr_bin.r_bin_addr2fileline
r_bin_addr2fileline.restype = ctypes.POINTER(ctypes.c_char)
r_bin_addr2fileline.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.c_uint64]
r_bin_wr_addlib = _libr_bin.r_bin_wr_addlib
r_bin_wr_addlib.restype = ctypes.c_bool
r_bin_wr_addlib.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(ctypes.c_char)]
r_bin_wr_scn_resize = _libr_bin.r_bin_wr_scn_resize
r_bin_wr_scn_resize.restype = ctypes.c_uint64
r_bin_wr_scn_resize.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64]
r_bin_wr_scn_perms = _libr_bin.r_bin_wr_scn_perms
r_bin_wr_scn_perms.restype = ctypes.c_bool
r_bin_wr_scn_perms.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_bin_wr_rpath_del = _libr_bin.r_bin_wr_rpath_del
r_bin_wr_rpath_del.restype = ctypes.c_bool
r_bin_wr_rpath_del.argtypes = [ctypes.POINTER(struct_r_bin_t)]
r_bin_wr_entry = _libr_bin.r_bin_wr_entry
r_bin_wr_entry.restype = ctypes.c_bool
r_bin_wr_entry.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.c_uint64]
r_bin_wr_output = _libr_bin.r_bin_wr_output
r_bin_wr_output.restype = ctypes.c_bool
r_bin_wr_output.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(ctypes.c_char)]
r_bin_get_mem = _libr_bin.r_bin_get_mem
r_bin_get_mem.restype = ctypes.POINTER(struct_r_list_t)
r_bin_get_mem.argtypes = [ctypes.POINTER(struct_r_bin_t)]
r_bin_load_filter = _libr_bin.r_bin_load_filter
r_bin_load_filter.restype = None
r_bin_load_filter.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.c_uint64]
r_bin_filter_symbols = _libr_bin.r_bin_filter_symbols
r_bin_filter_symbols.restype = None
r_bin_filter_symbols.argtypes = [ctypes.POINTER(struct_r_bin_file_t), ctypes.POINTER(struct_r_list_t)]
r_bin_filter_sections = _libr_bin.r_bin_filter_sections
r_bin_filter_sections.restype = None
r_bin_filter_sections.argtypes = [ctypes.POINTER(struct_r_bin_file_t), ctypes.POINTER(struct_r_list_t)]
r_bin_filter_name = _libr_bin.r_bin_filter_name
r_bin_filter_name.restype = ctypes.POINTER(ctypes.c_char)
r_bin_filter_name.argtypes = [ctypes.POINTER(struct_r_bin_file_t), ctypes.POINTER(struct_sdb_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_char)]
r_bin_filter_sym = _libr_bin.r_bin_filter_sym
r_bin_filter_sym.restype = None
r_bin_filter_sym.argtypes = [ctypes.POINTER(struct_r_bin_file_t), ctypes.POINTER(struct_ht_pp_t), ctypes.c_uint64, ctypes.POINTER(struct_r_bin_symbol_t)]
r_bin_strpurge = _libr_bin.r_bin_strpurge
r_bin_strpurge.restype = ctypes.c_bool
r_bin_strpurge.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64]
r_bin_string_filter = _libr_bin.r_bin_string_filter
r_bin_string_filter.restype = ctypes.c_bool
r_bin_string_filter.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64]
r_bin_plugin_any = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_fs = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_cgc = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_elf = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_elf64 = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_p9 = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_ne = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_le = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_pe = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_mz = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_pe64 = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_pebble = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_bios = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_bf = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_te = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_symbols = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_mach0 = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_mach064 = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_mdmp = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_java = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_dex = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_coff = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_ningb = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_ningba = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_ninds = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_nin3ds = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_xbe = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_bflt = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_xtr_plugin_xtr_fatmach0 = struct_r_bin_xtr_plugin_t # Variable struct_r_bin_xtr_plugin_t
r_bin_xtr_plugin_xtr_dyldcache = struct_r_bin_xtr_plugin_t # Variable struct_r_bin_xtr_plugin_t
r_bin_xtr_plugin_xtr_pemixed = struct_r_bin_xtr_plugin_t # Variable struct_r_bin_xtr_plugin_t
r_bin_xtr_plugin_xtr_sep64 = struct_r_bin_xtr_plugin_t # Variable struct_r_bin_xtr_plugin_t
r_bin_ldr_plugin_ldr_linux = struct_r_bin_ldr_plugin_t # Variable struct_r_bin_ldr_plugin_t
r_bin_plugin_zimg = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_omf = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_art = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_bootimg = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_dol = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_nes = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_qnx = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_mbn = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_smd = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_sms = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_psxexe = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_vsf = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_dyldcache = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_xnu_kernelcache = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_avr = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_menuet = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_wasm = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_nro = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_nso = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_sfc = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_z64 = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_prg = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_dmp64 = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
r_bin_plugin_pyc = struct_r_bin_plugin_t # Variable struct_r_bin_plugin_t
__all__ = \
    ['FREE_XTR', 'PJEncodingNum', 'PJEncodingStr',
    'PJ_ENCODING_NUM_DEFAULT', 'PJ_ENCODING_NUM_HEX',
    'PJ_ENCODING_NUM_STR', 'PJ_ENCODING_STR_ARRAY',
    'PJ_ENCODING_STR_BASE64', 'PJ_ENCODING_STR_DEFAULT',
    'PJ_ENCODING_STR_HEX', 'PJ_ENCODING_STR_STRIP', 'RBin',
    'RBinAddr', 'RBinArchOptions', 'RBinBind', 'RBinClass',
    'RBinDbgInfo', 'RBinDemangle', 'RBinField', 'RBinFile',
    'RBinFileHash', 'RBinFileOptions', 'RBinGetName', 'RBinGetOffset',
    'RBinGetSectionAt', 'RBinGetSections', 'RBinHash', 'RBinImport',
    'RBinInfo', 'RBinLdrPlugin', 'RBinMap', 'RBinMem', 'RBinObject',
    'RBinOptions', 'RBinPlugin', 'RBinReloc', 'RBinSection',
    'RBinString', 'RBinSymbol', 'RBinSymbolCallback',
    'RBinSymbollCallback', 'RBinTrycatch', 'RBinWrite', 'RBinXtrData',
    'RBinXtrMetadata', 'RBinXtrPlugin', 'R_BIN_CLASS_FRIENDLY',
    'R_BIN_CLASS_PRIVATE', 'R_BIN_CLASS_PROTECTED',
    'R_BIN_CLASS_PUBLIC', 'R_BIN_NM_ANY', 'R_BIN_NM_BLOCKS',
    'R_BIN_NM_C', 'R_BIN_NM_CXX', 'R_BIN_NM_DLANG', 'R_BIN_NM_GO',
    'R_BIN_NM_JAVA', 'R_BIN_NM_KOTLIN', 'R_BIN_NM_MSVC',
    'R_BIN_NM_NONE', 'R_BIN_NM_OBJC', 'R_BIN_NM_RUST',
    'R_BIN_NM_SWIFT', 'R_BIN_RELOC_16', 'R_BIN_RELOC_32',
    'R_BIN_RELOC_64', 'R_BIN_RELOC_8', 'R_BIN_SYM_ENTRY',
    'R_BIN_SYM_FINI', 'R_BIN_SYM_INIT', 'R_BIN_SYM_LAST',
    'R_BIN_SYM_MAIN', 'R_BIN_TYPE_CORE', 'R_BIN_TYPE_DEFAULT',
    'R_STRING_TYPE_ASCII', 'R_STRING_TYPE_BASE64',
    'R_STRING_TYPE_DETECT', 'R_STRING_TYPE_UTF8',
    'R_STRING_TYPE_WIDE', 'R_STRING_TYPE_WIDE32',
    'c__Ea_R_BIN_CLASS_PRIVATE', 'c__Ea_R_BIN_NM_NONE',
    'c__Ea_R_BIN_RELOC_8', 'c__Ea_R_BIN_SYM_ENTRY',
    'c__Ea_R_BIN_TYPE_DEFAULT', 'c__Ea_R_STRING_TYPE_DETECT',
    'r_bin_a2b', 'r_bin_add', 'r_bin_addr2fileline',
    'r_bin_addr2line', 'r_bin_addr2line2', 'r_bin_addr2text',
    'r_bin_arch_options_init', 'r_bin_bind', 'r_bin_create',
    'r_bin_cur', 'r_bin_cur_object', 'r_bin_demangle',
    'r_bin_demangle_cxx', 'r_bin_demangle_java',
    'r_bin_demangle_list', 'r_bin_demangle_msvc',
    'r_bin_demangle_objc', 'r_bin_demangle_plugin',
    'r_bin_demangle_rust', 'r_bin_demangle_swift',
    'r_bin_demangle_type', 'r_bin_dump_strings',
    'r_bin_entry_type_string', 'r_bin_field_free', 'r_bin_field_new',
    'r_bin_file_add_class', 'r_bin_file_add_field',
    'r_bin_file_add_method', 'r_bin_file_at', 'r_bin_file_close',
    'r_bin_file_compute_hashes', 'r_bin_file_cur_plugin',
    'r_bin_file_delete', 'r_bin_file_delete_all', 'r_bin_file_deref',
    'r_bin_file_find_by_arch_bits', 'r_bin_file_find_by_fd',
    'r_bin_file_find_by_id', 'r_bin_file_find_by_name',
    'r_bin_file_find_by_object_id', 'r_bin_file_free',
    'r_bin_file_get_baddr', 'r_bin_file_get_symbols',
    'r_bin_file_get_trycatch', 'r_bin_file_get_vaddr',
    'r_bin_file_hash_free', 'r_bin_file_object_new_from_xtr_data',
    'r_bin_file_set_cur_binfile', 'r_bin_file_set_cur_by_fd',
    'r_bin_file_set_cur_by_id', 'r_bin_file_set_cur_by_name',
    'r_bin_file_set_hashes', 'r_bin_filter_name',
    'r_bin_filter_sections', 'r_bin_filter_sym',
    'r_bin_filter_symbols', 'r_bin_force_plugin', 'r_bin_free',
    'r_bin_get_baddr', 'r_bin_get_binplugin_by_buffer',
    'r_bin_get_binplugin_by_bytes', 'r_bin_get_classes',
    'r_bin_get_entries', 'r_bin_get_fields', 'r_bin_get_imports',
    'r_bin_get_info', 'r_bin_get_laddr', 'r_bin_get_libs',
    'r_bin_get_mem', 'r_bin_get_meth_flag_string', 'r_bin_get_relocs',
    'r_bin_get_relocs_list', 'r_bin_get_section_at',
    'r_bin_get_sections', 'r_bin_get_size', 'r_bin_get_strings',
    'r_bin_get_sym', 'r_bin_get_symbols', 'r_bin_get_vaddr',
    'r_bin_import_clone', 'r_bin_import_free', 'r_bin_info_free',
    'r_bin_is_big_endian', 'r_bin_is_static', 'r_bin_is_string',
    'r_bin_ldr_add', 'r_bin_ldr_plugin_ldr_linux', 'r_bin_list',
    'r_bin_list_archs', 'r_bin_list_plugin', 'r_bin_load_filter',
    'r_bin_load_languages', 'r_bin_mem_free', 'r_bin_new',
    'r_bin_object_delete', 'r_bin_object_set_items', 'r_bin_open',
    'r_bin_open_buf', 'r_bin_open_io', 'r_bin_options_init',
    'r_bin_package', 'r_bin_patch_relocs', 'r_bin_patch_relocs_list',
    'r_bin_plugin_any', 'r_bin_plugin_art', 'r_bin_plugin_avr',
    'r_bin_plugin_bf', 'r_bin_plugin_bflt', 'r_bin_plugin_bios',
    'r_bin_plugin_bootimg', 'r_bin_plugin_cgc', 'r_bin_plugin_coff',
    'r_bin_plugin_dex', 'r_bin_plugin_dmp64', 'r_bin_plugin_dol',
    'r_bin_plugin_dyldcache', 'r_bin_plugin_elf',
    'r_bin_plugin_elf64', 'r_bin_plugin_fs', 'r_bin_plugin_java',
    'r_bin_plugin_le', 'r_bin_plugin_mach0', 'r_bin_plugin_mach064',
    'r_bin_plugin_mbn', 'r_bin_plugin_mdmp', 'r_bin_plugin_menuet',
    'r_bin_plugin_mz', 'r_bin_plugin_ne', 'r_bin_plugin_nes',
    'r_bin_plugin_nin3ds', 'r_bin_plugin_ninds', 'r_bin_plugin_ningb',
    'r_bin_plugin_ningba', 'r_bin_plugin_nro', 'r_bin_plugin_nso',
    'r_bin_plugin_omf', 'r_bin_plugin_p9', 'r_bin_plugin_pe',
    'r_bin_plugin_pe64', 'r_bin_plugin_pebble', 'r_bin_plugin_prg',
    'r_bin_plugin_psxexe', 'r_bin_plugin_pyc', 'r_bin_plugin_qnx',
    'r_bin_plugin_sfc', 'r_bin_plugin_smd', 'r_bin_plugin_sms',
    'r_bin_plugin_symbols', 'r_bin_plugin_te', 'r_bin_plugin_vsf',
    'r_bin_plugin_wasm', 'r_bin_plugin_xbe',
    'r_bin_plugin_xnu_kernelcache', 'r_bin_plugin_z64',
    'r_bin_plugin_zimg', 'r_bin_raw_strings', 'r_bin_reload',
    'r_bin_reset_strings', 'r_bin_section_free', 'r_bin_section_new',
    'r_bin_select', 'r_bin_select_bfid', 'r_bin_set_baddr',
    'r_bin_set_user_ptr', 'r_bin_string_filter', 'r_bin_string_free',
    'r_bin_string_type', 'r_bin_strpurge', 'r_bin_symbol_free',
    'r_bin_symbol_name', 'r_bin_symbol_new', 'r_bin_trycatch_free',
    'r_bin_trycatch_new', 'r_bin_use_arch', 'r_bin_version',
    'r_bin_wr_addlib', 'r_bin_wr_entry', 'r_bin_wr_output',
    'r_bin_wr_rpath_del', 'r_bin_wr_scn_perms', 'r_bin_wr_scn_resize',
    'r_bin_xtr_add', 'r_bin_xtr_plugin_xtr_dyldcache',
    'r_bin_xtr_plugin_xtr_fatmach0', 'r_bin_xtr_plugin_xtr_pemixed',
    'r_bin_xtr_plugin_xtr_sep64', 'r_bin_xtrdata_free',
    'r_bin_xtrdata_new', 'struct_buffer', 'struct_c__SA_RStrBuf',
    'struct_c__SA_dict', 'struct_cdb', 'struct_cdb_hp',
    'struct_cdb_hplist', 'struct_cdb_make', 'struct_ht_pp_bucket_t',
    'struct_ht_pp_kv', 'struct_ht_pp_options_t', 'struct_ht_pp_t',
    'struct_ht_up_bucket_t', 'struct_ht_up_kv',
    'struct_ht_up_options_t', 'struct_ht_up_t', 'struct_ls_iter_t',
    'struct_ls_t', 'struct_pj_t', 'struct_r_bin_addr_t',
    'struct_r_bin_arch_options_t', 'struct_r_bin_bind_t',
    'struct_r_bin_class_t', 'struct_r_bin_dbginfo_t',
    'struct_r_bin_field_t', 'struct_r_bin_file_hash_t',
    'struct_r_bin_file_options_t', 'struct_r_bin_file_t',
    'struct_r_bin_hash_t', 'struct_r_bin_import_t',
    'struct_r_bin_info_t', 'struct_r_bin_ldr_plugin_t',
    'struct_r_bin_map_t', 'struct_r_bin_mem_t',
    'struct_r_bin_object_t', 'struct_r_bin_options_t',
    'struct_r_bin_plugin_t', 'struct_r_bin_reloc_t',
    'struct_r_bin_section_t', 'struct_r_bin_string_t',
    'struct_r_bin_symbol_t', 'struct_r_bin_t',
    'struct_r_bin_trycatch_t', 'struct_r_bin_write_t',
    'struct_r_bin_xtr_extract_t', 'struct_r_bin_xtr_metadata_t',
    'struct_r_bin_xtr_plugin_t', 'struct_r_buf_t',
    'struct_r_buffer_methods_t', 'struct_r_cache_t',
    'struct_r_cons_bind_t', 'struct_r_core_bind_t',
    'struct_r_event_t', 'struct_r_id_pool_t', 'struct_r_id_storage_t',
    'struct_r_interval_t', 'struct_r_io_bind_t', 'struct_r_io_desc_t',
    'struct_r_io_map_t', 'struct_r_io_plugin_t', 'struct_r_io_t',
    'struct_r_io_undo_t', 'struct_r_io_undos_t',
    'struct_r_list_iter_t', 'struct_r_list_t', 'struct_r_pvector_t',
    'struct_r_queue_t', 'struct_r_rb_node_t', 'struct_r_skyline_t',
    'struct_r_str_constpool_t', 'struct_r_vector_t',
    'struct_sdb_gperf_t', 'struct_sdb_kv', 'struct_sdb_t']
