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

class FunctionFactoryStub:
    def __getattr__(self, _):
      return ctypes.CFUNCTYPE(lambda y:y)

# libraries['FIXME_STUB'] explanation
# As you did not list (-l libraryname.so) a library that exports this function
# This is a non-working stub instead. 
# You can either re-run clan2py with -l /path/to/library.so
# Or manually fix this by comment the ctypes.CDLL loading
_libraries['FIXME_STUB'] = FunctionFactoryStub() #  ctypes.CDLL('FIXME_STUB')


r_search_version = _libr_search.r_search_version
r_search_version.restype = ctypes.POINTER(ctypes.c_char)
r_search_version.argtypes = []

# values for enumeration 'c__Ea_R_SEARCH_ESIL'
c__Ea_R_SEARCH_ESIL__enumvalues = {
    0: 'R_SEARCH_ESIL',
    1: 'R_SEARCH_KEYWORD',
    2: 'R_SEARCH_REGEXP',
    3: 'R_SEARCH_PATTERN',
    4: 'R_SEARCH_STRING',
    5: 'R_SEARCH_XREFS',
    6: 'R_SEARCH_AES',
    7: 'R_SEARCH_PRIV_KEY',
    8: 'R_SEARCH_DELTAKEY',
    9: 'R_SEARCH_MAGIC',
    10: 'R_SEARCH_LAST',
}
R_SEARCH_ESIL = 0
R_SEARCH_KEYWORD = 1
R_SEARCH_REGEXP = 2
R_SEARCH_PATTERN = 3
R_SEARCH_STRING = 4
R_SEARCH_XREFS = 5
R_SEARCH_AES = 6
R_SEARCH_PRIV_KEY = 7
R_SEARCH_DELTAKEY = 8
R_SEARCH_MAGIC = 9
R_SEARCH_LAST = 10
c__Ea_R_SEARCH_ESIL = ctypes.c_uint32 # enum
class struct_r_search_keyword_t(Structure):
    pass

struct_r_search_keyword_t._pack_ = 1 # source:False
struct_r_search_keyword_t._fields_ = [
    ('bin_keyword', ctypes.POINTER(ctypes.c_ubyte)),
    ('bin_binmask', ctypes.POINTER(ctypes.c_ubyte)),
    ('keyword_length', ctypes.c_uint32),
    ('binmask_length', ctypes.c_uint32),
    ('data', ctypes.POINTER(None)),
    ('count', ctypes.c_int32),
    ('kwidx', ctypes.c_int32),
    ('icase', ctypes.c_int32),
    ('type', ctypes.c_int32),
    ('last', ctypes.c_uint64),
]

RSearchKeyword = struct_r_search_keyword_t
class struct_r_search_uds_t(Structure):
    pass

struct_r_search_uds_t._pack_ = 1 # source:False
struct_r_search_uds_t._fields_ = [
    ('addr', ctypes.c_uint64),
    ('stride', ctypes.c_int32),
    ('score', ctypes.c_int32),
]

RSearchUds = struct_r_search_uds_t
class struct_r_search_hit_t(Structure):
    pass

struct_r_search_hit_t._pack_ = 1 # source:False
struct_r_search_hit_t._fields_ = [
    ('kw', ctypes.POINTER(struct_r_search_keyword_t)),
    ('addr', ctypes.c_uint64),
]

RSearchHit = struct_r_search_hit_t
RSearchCallback = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_search_keyword_t), ctypes.POINTER(None), ctypes.c_uint64)
class struct_r_search_t(Structure):
    pass

class struct_r_list_t(Structure):
    pass

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

struct_r_search_t._pack_ = 1 # source:False
struct_r_search_t._fields_ = [
    ('n_kws', ctypes.c_int32),
    ('mode', ctypes.c_int32),
    ('pattern_size', ctypes.c_uint32),
    ('string_min', ctypes.c_uint32),
    ('string_max', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('data', ctypes.POINTER(None)),
    ('user', ctypes.POINTER(None)),
    ('callback', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_search_keyword_t), ctypes.POINTER(None), ctypes.c_uint64)),
    ('nhits', ctypes.c_uint64),
    ('maxhits', ctypes.c_uint64),
    ('hits', ctypes.POINTER(struct_r_list_t)),
    ('distance', ctypes.c_int32),
    ('inverse', ctypes.c_int32),
    ('overlap', ctypes.c_bool),
    ('PADDING_1', ctypes.c_ubyte * 3),
    ('contiguous', ctypes.c_int32),
    ('align', ctypes.c_int32),
    ('PADDING_2', ctypes.c_ubyte * 4),
    ('update', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_search_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)),
    ('kws', ctypes.POINTER(struct_r_list_t)),
    ('iob', struct_r_io_bind_t),
    ('bckwrds', ctypes.c_char),
    ('PADDING_3', ctypes.c_ubyte * 7),
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

class struct_ls_t(Structure):
    pass

class struct_r_id_storage_t(Structure):
    pass

class struct_r_id_pool_t(Structure):
    pass

class struct_r_event_t(Structure):
    pass

class struct_r_cache_t(Structure):
    pass

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

class struct_ht_up_t(Structure):
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

struct_r_id_storage_t._pack_ = 1 # source:False
struct_r_id_storage_t._fields_ = [
    ('pool', ctypes.POINTER(struct_r_id_pool_t)),
    ('data', ctypes.POINTER(ctypes.POINTER(None))),
    ('top_id', ctypes.c_uint32),
    ('size', ctypes.c_uint32),
]

struct_r_cache_t._pack_ = 1 # source:False
struct_r_cache_t._fields_ = [
    ('base', ctypes.c_uint64),
    ('buf', ctypes.POINTER(ctypes.c_ubyte)),
    ('len', ctypes.c_uint64),
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

RSearch = struct_r_search_t
r_search_new = _libr_search.r_search_new
r_search_new.restype = ctypes.POINTER(struct_r_search_t)
r_search_new.argtypes = [ctypes.c_int32]
r_search_set_mode = _libr_search.r_search_set_mode
r_search_set_mode.restype = ctypes.c_int32
r_search_set_mode.argtypes = [ctypes.POINTER(struct_r_search_t), ctypes.c_int32]
r_search_free = _libr_search.r_search_free
r_search_free.restype = ctypes.POINTER(struct_r_search_t)
r_search_free.argtypes = [ctypes.POINTER(struct_r_search_t)]
r_search_find = _libr_search.r_search_find
r_search_find.restype = ctypes.POINTER(struct_r_list_t)
r_search_find.argtypes = [ctypes.POINTER(struct_r_search_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
size_t = ctypes.c_uint64
r_search_find_uds = _libr_search.r_search_find_uds
r_search_find_uds.restype = ctypes.POINTER(struct_r_list_t)
r_search_find_uds.argtypes = [ctypes.POINTER(struct_r_search_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), size_t, ctypes.c_bool]
r_search_update = _libr_search.r_search_update
r_search_update.restype = ctypes.c_int32
r_search_update.argtypes = [ctypes.POINTER(struct_r_search_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int64]
r_search_update_i = _libr_search.r_search_update_i
r_search_update_i.restype = ctypes.c_int32
r_search_update_i.argtypes = [ctypes.POINTER(struct_r_search_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int64]
r_search_keyword_free = _libr_search.r_search_keyword_free
r_search_keyword_free.restype = None
r_search_keyword_free.argtypes = [ctypes.POINTER(struct_r_search_keyword_t)]
r_search_keyword_new = _libr_search.r_search_keyword_new
r_search_keyword_new.restype = ctypes.POINTER(struct_r_search_keyword_t)
r_search_keyword_new.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
r_search_keyword_new_str = _libr_search.r_search_keyword_new_str
r_search_keyword_new_str.restype = ctypes.POINTER(struct_r_search_keyword_t)
r_search_keyword_new_str.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_search_keyword_new_wide = _libr_search.r_search_keyword_new_wide
r_search_keyword_new_wide.restype = ctypes.POINTER(struct_r_search_keyword_t)
r_search_keyword_new_wide.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_search_keyword_new_hex = _libr_search.r_search_keyword_new_hex
r_search_keyword_new_hex.restype = ctypes.POINTER(struct_r_search_keyword_t)
r_search_keyword_new_hex.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_search_keyword_new_hexmask = _libr_search.r_search_keyword_new_hexmask
r_search_keyword_new_hexmask.restype = ctypes.POINTER(struct_r_search_keyword_t)
r_search_keyword_new_hexmask.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_search_keyword_new_regexp = _libr_search.r_search_keyword_new_regexp
r_search_keyword_new_regexp.restype = ctypes.POINTER(struct_r_search_keyword_t)
r_search_keyword_new_regexp.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_search_kw_add = _libr_search.r_search_kw_add
r_search_kw_add.restype = ctypes.c_int32
r_search_kw_add.argtypes = [ctypes.POINTER(struct_r_search_t), ctypes.POINTER(struct_r_search_keyword_t)]
r_search_reset = _libr_search.r_search_reset
r_search_reset.restype = None
r_search_reset.argtypes = [ctypes.POINTER(struct_r_search_t), ctypes.c_int32]
r_search_kw_reset = _libr_search.r_search_kw_reset
r_search_kw_reset.restype = None
r_search_kw_reset.argtypes = [ctypes.POINTER(struct_r_search_t)]
r_search_string_prepare_backward = _libr_search.r_search_string_prepare_backward
r_search_string_prepare_backward.restype = None
r_search_string_prepare_backward.argtypes = [ctypes.POINTER(struct_r_search_t)]
r_search_range_add = _libraries['FIXME_STUB'].r_search_range_add
r_search_range_add.restype = ctypes.c_int32
r_search_range_add.argtypes = [ctypes.POINTER(struct_r_search_t), ctypes.c_uint64, ctypes.c_uint64]
r_search_range_set = _libraries['FIXME_STUB'].r_search_range_set
r_search_range_set.restype = ctypes.c_int32
r_search_range_set.argtypes = [ctypes.POINTER(struct_r_search_t), ctypes.c_uint64, ctypes.c_uint64]
r_search_range_reset = _libraries['FIXME_STUB'].r_search_range_reset
r_search_range_reset.restype = ctypes.c_int32
r_search_range_reset.argtypes = [ctypes.POINTER(struct_r_search_t)]
r_search_set_blocksize = _libraries['FIXME_STUB'].r_search_set_blocksize
r_search_set_blocksize.restype = ctypes.c_int32
r_search_set_blocksize.argtypes = [ctypes.POINTER(struct_r_search_t), ctypes.c_uint32]
r_search_bmh = _libraries['FIXME_STUB'].r_search_bmh
r_search_bmh.restype = ctypes.c_int32
r_search_bmh.argtypes = [ctypes.POINTER(struct_r_search_keyword_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_uint64)]
r_search_mybinparse_update = _libr_search.r_search_mybinparse_update
r_search_mybinparse_update.restype = ctypes.c_int32
r_search_mybinparse_update.argtypes = [ctypes.POINTER(struct_r_search_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_search_aes_update = _libr_search.r_search_aes_update
r_search_aes_update.restype = ctypes.c_int32
r_search_aes_update.argtypes = [ctypes.POINTER(struct_r_search_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_search_privkey_update = _libr_search.r_search_privkey_update
r_search_privkey_update.restype = ctypes.c_int32
r_search_privkey_update.argtypes = [ctypes.POINTER(struct_r_search_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_search_magic_update = _libr_search.r_search_magic_update
r_search_magic_update.restype = ctypes.c_int32
r_search_magic_update.argtypes = [ctypes.POINTER(struct_r_search_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_search_deltakey_update = _libr_search.r_search_deltakey_update
r_search_deltakey_update.restype = ctypes.c_int32
r_search_deltakey_update.argtypes = [ctypes.POINTER(struct_r_search_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_search_strings_update = _libr_search.r_search_strings_update
r_search_strings_update.restype = ctypes.c_int32
r_search_strings_update.argtypes = [ctypes.POINTER(struct_r_search_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_search_regexp_update = _libr_search.r_search_regexp_update
r_search_regexp_update.restype = ctypes.c_int32
r_search_regexp_update.argtypes = [ctypes.POINTER(struct_r_search_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_search_xrefs_update = _libraries['FIXME_STUB'].r_search_xrefs_update
r_search_xrefs_update.restype = ctypes.c_int32
r_search_xrefs_update.argtypes = [ctypes.POINTER(struct_r_search_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_search_hit_new = _libr_search.r_search_hit_new
r_search_hit_new.restype = ctypes.c_int32
r_search_hit_new.argtypes = [ctypes.POINTER(struct_r_search_t), ctypes.POINTER(struct_r_search_keyword_t), ctypes.c_uint64]
r_search_set_distance = _libr_search.r_search_set_distance
r_search_set_distance.restype = None
r_search_set_distance.argtypes = [ctypes.POINTER(struct_r_search_t), ctypes.c_int32]
r_search_strings = _libraries['FIXME_STUB'].r_search_strings
r_search_strings.restype = ctypes.c_int32
r_search_strings.argtypes = [ctypes.POINTER(struct_r_search_t), ctypes.c_uint32, ctypes.c_uint32]
r_search_set_string_limits = _libr_search.r_search_set_string_limits
r_search_set_string_limits.restype = ctypes.c_int32
r_search_set_string_limits.argtypes = [ctypes.POINTER(struct_r_search_t), ctypes.c_uint32, ctypes.c_uint32]
r_search_set_callback = _libr_search.r_search_set_callback
r_search_set_callback.restype = None
r_search_set_callback.argtypes = [ctypes.POINTER(struct_r_search_t), RSearchCallback, ctypes.POINTER(None)]
r_search_begin = _libr_search.r_search_begin
r_search_begin.restype = ctypes.c_int32
r_search_begin.argtypes = [ctypes.POINTER(struct_r_search_t)]
r_search_pattern_size = _libr_search.r_search_pattern_size
r_search_pattern_size.restype = None
r_search_pattern_size.argtypes = [ctypes.POINTER(struct_r_search_t), ctypes.c_int32]
r_search_pattern = _libr_search.r_search_pattern
r_search_pattern.restype = ctypes.c_int32
r_search_pattern.argtypes = [ctypes.POINTER(struct_r_search_t), ctypes.c_uint64, ctypes.c_uint64]
__all__ = \
    ['RSearch', 'RSearchCallback', 'RSearchHit', 'RSearchKeyword',
    'RSearchUds', 'R_SEARCH_AES', 'R_SEARCH_DELTAKEY',
    'R_SEARCH_ESIL', 'R_SEARCH_KEYWORD', 'R_SEARCH_LAST',
    'R_SEARCH_MAGIC', 'R_SEARCH_PATTERN', 'R_SEARCH_PRIV_KEY',
    'R_SEARCH_REGEXP', 'R_SEARCH_STRING', 'R_SEARCH_XREFS',
    'c__Ea_R_SEARCH_ESIL', 'r_search_aes_update', 'r_search_begin',
    'r_search_bmh', 'r_search_deltakey_update', 'r_search_find',
    'r_search_find_uds', 'r_search_free', 'r_search_hit_new',
    'r_search_keyword_free', 'r_search_keyword_new',
    'r_search_keyword_new_hex', 'r_search_keyword_new_hexmask',
    'r_search_keyword_new_regexp', 'r_search_keyword_new_str',
    'r_search_keyword_new_wide', 'r_search_kw_add',
    'r_search_kw_reset', 'r_search_magic_update',
    'r_search_mybinparse_update', 'r_search_new', 'r_search_pattern',
    'r_search_pattern_size', 'r_search_privkey_update',
    'r_search_range_add', 'r_search_range_reset',
    'r_search_range_set', 'r_search_regexp_update', 'r_search_reset',
    'r_search_set_blocksize', 'r_search_set_callback',
    'r_search_set_distance', 'r_search_set_mode',
    'r_search_set_string_limits', 'r_search_string_prepare_backward',
    'r_search_strings', 'r_search_strings_update', 'r_search_update',
    'r_search_update_i', 'r_search_version', 'r_search_xrefs_update',
    'size_t', 'struct_ht_up_bucket_t', 'struct_ht_up_kv',
    'struct_ht_up_options_t', 'struct_ht_up_t', 'struct_ls_iter_t',
    'struct_ls_t', 'struct_r_cache_t', 'struct_r_core_bind_t',
    'struct_r_event_t', 'struct_r_id_pool_t', 'struct_r_id_storage_t',
    'struct_r_interval_t', 'struct_r_io_bind_t', 'struct_r_io_desc_t',
    'struct_r_io_map_t', 'struct_r_io_plugin_t', 'struct_r_io_t',
    'struct_r_io_undo_t', 'struct_r_io_undos_t',
    'struct_r_list_iter_t', 'struct_r_list_t', 'struct_r_pvector_t',
    'struct_r_queue_t', 'struct_r_search_hit_t',
    'struct_r_search_keyword_t', 'struct_r_search_t',
    'struct_r_search_uds_t', 'struct_r_skyline_t',
    'struct_r_vector_t']
