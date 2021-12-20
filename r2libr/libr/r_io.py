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


r_io_version = _libr_io.r_io_version
r_io_version.restype = ctypes.POINTER(ctypes.c_char)
r_io_version.argtypes = []
class struct_r_io_undos_t(Structure):
    pass

struct_r_io_undos_t._pack_ = 1 # source:False
struct_r_io_undos_t._fields_ = [
    ('off', ctypes.c_uint64),
    ('cursor', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

RIOUndos = struct_r_io_undos_t
class struct_r_io_undo_t(Structure):
    pass

class struct_r_list_t(Structure):
    pass

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

RIOUndo = struct_r_io_undo_t
class struct_r_io_undo_w_t(Structure):
    pass

struct_r_io_undo_w_t._pack_ = 1 # source:False
struct_r_io_undo_w_t._fields_ = [
    ('set', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
    ('off', ctypes.c_uint64),
    ('o', ctypes.POINTER(ctypes.c_ubyte)),
    ('n', ctypes.POINTER(ctypes.c_ubyte)),
    ('len', ctypes.c_uint64),
]

RIOUndoWrite = struct_r_io_undo_w_t
class struct_r_io_t(Structure):
    pass

class struct_r_id_storage_t(Structure):
    pass

class struct_r_event_t(Structure):
    pass

class struct_ls_t(Structure):
    pass

class struct_r_cache_t(Structure):
    pass

class struct_r_io_desc_t(Structure):
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

class struct_r_pvector_t(Structure):
    _pack_ = 1 # source:False
    _fields_ = [
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

struct_r_io_t._pack_ = 1 # source:False
struct_r_io_t._fields_ = [
    ('desc', ctypes.POINTER(struct_r_io_desc_t)),
    ('off', ctypes.c_uint64),
    ('bank', ctypes.c_uint32),
    ('bits', ctypes.c_int32),
    ('va', ctypes.c_int32),
    ('ff', ctypes.c_bool),
    ('Oxff', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte * 2),
    ('addrbytes', ctypes.c_uint64),
    ('aslr', ctypes.c_bool),
    ('autofd', ctypes.c_bool),
    ('PADDING_1', ctypes.c_ubyte * 2),
    ('cached', ctypes.c_uint32),
    ('cachemode', ctypes.c_bool),
    ('PADDING_2', ctypes.c_ubyte * 3),
    ('p_cache', ctypes.c_uint32),
    ('mts', ctypes.c_uint64),
    ('files', ctypes.POINTER(struct_r_id_storage_t)),
    ('maps', ctypes.POINTER(struct_r_id_storage_t)),
    ('banks', ctypes.POINTER(struct_r_id_storage_t)),
    ('buffer', ctypes.POINTER(struct_r_cache_t)),
    ('cache', struct_r_pvector_t),
    ('cache_skyline', struct_r_skyline_t),
    ('write_mask', ctypes.POINTER(ctypes.c_ubyte)),
    ('write_mask_len', ctypes.c_int32),
    ('PADDING_3', ctypes.c_ubyte * 4),
    ('mask', ctypes.c_uint64),
    ('undo', RIOUndo),
    ('plugins', ctypes.POINTER(struct_ls_t)),
    ('nodup', ctypes.c_bool),
    ('PADDING_4', ctypes.c_ubyte * 7),
    ('runprofile', ctypes.POINTER(ctypes.c_char)),
    ('envprofile', ctypes.POINTER(ctypes.c_char)),
    ('args', ctypes.POINTER(ctypes.c_char)),
    ('event', ctypes.POINTER(struct_r_event_t)),
    ('cb_printf', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_char))),
    ('corebind', struct_r_core_bind_t),
    ('want_ptrace_wrap', ctypes.c_bool),
    ('PADDING_5', ctypes.c_ubyte * 7),
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
    ('init', ctypes.CFUNCTYPE(ctypes.c_bool)),
    ('undo', RIOUndo),
    ('isdbg', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
    ('system', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_io_t), ctypes.POINTER(struct_r_io_desc_t), ctypes.POINTER(ctypes.c_char))),
    ('open', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_io_desc_t), ctypes.POINTER(struct_r_io_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32)),
    ('open_many', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_io_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32)),
    ('read', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_io_t), ctypes.POINTER(struct_r_io_desc_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)),
    ('seek', ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(struct_r_io_t), ctypes.POINTER(struct_r_io_desc_t), ctypes.c_uint64, ctypes.c_int32)),
    ('write', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_io_t), ctypes.POINTER(struct_r_io_desc_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)),
    ('close', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_io_desc_t))),
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

RIO = struct_r_io_t
RIODesc = struct_r_io_desc_t
class struct_c__SA_RIORap(Structure):
    pass

class struct_r_socket_t(Structure):
    pass

struct_c__SA_RIORap._pack_ = 1 # source:False
struct_c__SA_RIORap._fields_ = [
    ('fd', ctypes.POINTER(struct_r_socket_t)),
    ('client', ctypes.POINTER(struct_r_socket_t)),
    ('listener', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
]

class struct_sockaddr_in(Structure):
    pass

class struct_in_addr(Structure):
    pass

struct_in_addr._pack_ = 1 # source:False
struct_in_addr._fields_ = [
    ('s_addr', ctypes.c_uint32),
]

struct_sockaddr_in._pack_ = 1 # source:False
struct_sockaddr_in._fields_ = [
    ('sin_family', ctypes.c_uint16),
    ('sin_port', ctypes.c_uint16),
    ('sin_addr', struct_in_addr),
    ('sin_zero', ctypes.c_ubyte * 8),
]

struct_r_socket_t._pack_ = 1 # source:False
struct_r_socket_t._fields_ = [
    ('fd', ctypes.c_int32),
    ('is_ssl', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 3),
    ('proto', ctypes.c_int32),
    ('local', ctypes.c_int32),
    ('port', ctypes.c_int32),
    ('sa', struct_sockaddr_in),
]

RIORap = struct_c__SA_RIORap
RIOPlugin = struct_r_io_plugin_t
class struct_r_io_map_t(Structure):
    pass

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
    ('ts', ctypes.c_uint64),
    ('itv', struct_r_interval_t),
    ('delta', ctypes.c_uint64),
    ('name', ctypes.POINTER(ctypes.c_char)),
]

RIOMap = struct_r_io_map_t
class struct_r_io_map_ref_t(Structure):
    pass

struct_r_io_map_ref_t._pack_ = 1 # source:False
struct_r_io_map_ref_t._fields_ = [
    ('id', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('ts', ctypes.c_uint64),
]

RIOMapRef = struct_r_io_map_ref_t
class struct_r_io_submap_t(Structure):
    _pack_ = 1 # source:False
    _fields_ = [
    ('mapref', RIOMapRef),
    ('itv', struct_r_interval_t),
     ]

RIOSubMap = struct_r_io_submap_t
class struct_r_io_bank_t(Structure):
    pass

class struct_r_crbtree_t(Structure):
    pass

class struct_r_crbtree_node(Structure):
    pass

struct_r_io_bank_t._pack_ = 1 # source:False
struct_r_io_bank_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('submaps', ctypes.POINTER(struct_r_crbtree_t)),
    ('maprefs', ctypes.POINTER(struct_r_list_t)),
    ('todo', ctypes.POINTER(struct_r_queue_t)),
    ('last_used', ctypes.POINTER(struct_r_crbtree_node)),
    ('id', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

struct_r_crbtree_t._pack_ = 1 # source:False
struct_r_crbtree_t._fields_ = [
    ('root', ctypes.POINTER(struct_r_crbtree_node)),
    ('size', ctypes.c_uint64),
    ('free', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
]

struct_r_crbtree_node._pack_ = 1 # source:False
struct_r_crbtree_node._fields_ = [
    ('link', ctypes.POINTER(struct_r_crbtree_node) * 2),
    ('parent', ctypes.POINTER(struct_r_crbtree_node)),
    ('red', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('data', ctypes.POINTER(None)),
]

RIOBank = struct_r_io_bank_t
class struct_r_io_cache_t(Structure):
    pass

struct_r_io_cache_t._pack_ = 1 # source:False
struct_r_io_cache_t._fields_ = [
    ('itv', struct_r_interval_t),
    ('data', ctypes.POINTER(ctypes.c_ubyte)),
    ('odata', ctypes.POINTER(ctypes.c_ubyte)),
    ('written', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

RIOCache = struct_r_io_cache_t
class struct_r_io_desc_cache_t(Structure):
    pass

struct_r_io_desc_cache_t._pack_ = 1 # source:False
struct_r_io_desc_cache_t._fields_ = [
    ('cached', ctypes.c_uint64),
    ('cdata', ctypes.c_ubyte * 64),
]

RIODescCache = struct_r_io_desc_cache_t
RIODescUse = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_io_t), ctypes.c_int32)
RIODescGet = ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_io_desc_t), ctypes.POINTER(struct_r_io_t), ctypes.c_int32)
RIODescSize = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(struct_r_io_desc_t))
RIOOpen = ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_io_desc_t), ctypes.POINTER(struct_r_io_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32)
RIOOpenAt = ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_io_desc_t), ctypes.POINTER(struct_r_io_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32, ctypes.c_uint64)
RIOClose = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_io_t), ctypes.c_int32)
RIOReadAt = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_io_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)
RIOWriteAt = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_io_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)
RIOSystem = ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_io_t), ctypes.POINTER(ctypes.c_char))
RIOFdOpen = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_io_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32)
RIOFdClose = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_io_t), ctypes.c_int32)
RIOFdSeek = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.c_uint64, ctypes.c_int32)
RIOFdSize = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(struct_r_io_t), ctypes.c_int32)
RIOFdResize = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.c_uint64)
RIOP2V = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(struct_r_io_t), ctypes.c_uint64)
RIOV2P = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(struct_r_io_t), ctypes.c_uint64)
RIOFdRead = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)
RIOFdWrite = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)
RIOFdReadAt = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)
RIOFdWriteAt = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)
RIOFdIsDbg = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_io_t), ctypes.c_int32)
RIOFdGetName = ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_io_t), ctypes.c_int32)
RIOFdGetMap = ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_io_t), ctypes.c_int32)
RIOFdRemap = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.c_uint64)
RIOIsValidOff = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_io_t), ctypes.c_uint64, ctypes.c_int32)
RIOBankGet = ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_io_bank_t), ctypes.POINTER(struct_r_io_t), ctypes.c_uint32)
RIOMapGet = ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_io_map_t), ctypes.POINTER(struct_r_io_t), ctypes.c_uint32)
RIOMapGetAt = ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_io_map_t), ctypes.POINTER(struct_r_io_t), ctypes.c_uint64)
RIOMapGetPaddr = ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_io_map_t), ctypes.POINTER(struct_r_io_t), ctypes.c_uint64)
RIOAddrIsMapped = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_io_t), ctypes.c_uint64)
RIOMapAdd = ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_io_map_t), ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64)
class struct_r_io_bind_t(Structure):
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
    ('bank_get', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_io_bank_t), ctypes.POINTER(struct_r_io_t), ctypes.c_uint32)),
    ('map_get', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_io_map_t), ctypes.POINTER(struct_r_io_t), ctypes.c_uint32)),
    ('map_get_at', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_io_map_t), ctypes.POINTER(struct_r_io_t), ctypes.c_uint64)),
    ('map_get_paddr', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_io_map_t), ctypes.POINTER(struct_r_io_t), ctypes.c_uint64)),
    ('map_add', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_io_map_t), ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64)),
    ('v2p', ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(struct_r_io_t), ctypes.c_uint64)),
    ('p2v', ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(struct_r_io_t), ctypes.c_uint64)),
]

RIOBind = struct_r_io_bind_t
r_io_map_init = _libr_io.r_io_map_init
r_io_map_init.restype = None
r_io_map_init.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_map_remap = _libr_io.r_io_map_remap
r_io_map_remap.restype = ctypes.c_bool
r_io_map_remap.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint32, ctypes.c_uint64]
r_io_map_remap_fd = _libr_io.r_io_map_remap_fd
r_io_map_remap_fd.restype = ctypes.c_bool
r_io_map_remap_fd.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.c_uint64]
r_io_map_exists = _libr_io.r_io_map_exists
r_io_map_exists.restype = ctypes.c_bool
r_io_map_exists.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.POINTER(struct_r_io_map_t)]
r_io_map_exists_for_id = _libr_io.r_io_map_exists_for_id
r_io_map_exists_for_id.restype = ctypes.c_bool
r_io_map_exists_for_id.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint32]
r_io_map_get = _libr_io.r_io_map_get
r_io_map_get.restype = ctypes.POINTER(struct_r_io_map_t)
r_io_map_get.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint32]
r_io_map_add = _libr_io.r_io_map_add
r_io_map_add.restype = ctypes.POINTER(struct_r_io_map_t)
r_io_map_add.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64]
r_io_map_add_bottom = _libr_io.r_io_map_add_bottom
r_io_map_add_bottom.restype = ctypes.POINTER(struct_r_io_map_t)
r_io_map_add_bottom.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64]
r_io_map_get_at = _libr_io.r_io_map_get_at
r_io_map_get_at.restype = ctypes.POINTER(struct_r_io_map_t)
r_io_map_get_at.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64]
r_io_map_get_by_ref = _libr_io.r_io_map_get_by_ref
r_io_map_get_by_ref.restype = ctypes.POINTER(struct_r_io_map_t)
r_io_map_get_by_ref.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.POINTER(struct_r_io_map_ref_t)]
r_io_map_is_mapped = _libr_io.r_io_map_is_mapped
r_io_map_is_mapped.restype = ctypes.c_bool
r_io_map_is_mapped.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64]
r_io_map_get_paddr = _libr_io.r_io_map_get_paddr
r_io_map_get_paddr.restype = ctypes.POINTER(struct_r_io_map_t)
r_io_map_get_paddr.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64]
r_io_map_reset = _libr_io.r_io_map_reset
r_io_map_reset.restype = None
r_io_map_reset.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_map_del = _libr_io.r_io_map_del
r_io_map_del.restype = None
r_io_map_del.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint32]
r_io_map_del_for_fd = _libr_io.r_io_map_del_for_fd
r_io_map_del_for_fd.restype = ctypes.c_bool
r_io_map_del_for_fd.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32]
r_io_map_depriorize = _libr_io.r_io_map_depriorize
r_io_map_depriorize.restype = ctypes.c_bool
r_io_map_depriorize.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint32]
r_io_map_priorize = _libr_io.r_io_map_priorize
r_io_map_priorize.restype = ctypes.c_bool
r_io_map_priorize.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint32]
r_io_map_priorize_for_fd = _libr_io.r_io_map_priorize_for_fd
r_io_map_priorize_for_fd.restype = ctypes.c_bool
r_io_map_priorize_for_fd.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32]
r_io_map_cleanup = _libr_io.r_io_map_cleanup
r_io_map_cleanup.restype = None
r_io_map_cleanup.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_map_fini = _libr_io.r_io_map_fini
r_io_map_fini.restype = None
r_io_map_fini.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_map_is_in_range = _libraries['FIXME_STUB'].r_io_map_is_in_range
r_io_map_is_in_range.restype = ctypes.c_bool
r_io_map_is_in_range.argtypes = [ctypes.POINTER(struct_r_io_map_t), ctypes.c_uint64, ctypes.c_uint64]
r_io_map_set_name = _libr_io.r_io_map_set_name
r_io_map_set_name.restype = None
r_io_map_set_name.argtypes = [ctypes.POINTER(struct_r_io_map_t), ctypes.POINTER(ctypes.c_char)]
r_io_map_del_name = _libr_io.r_io_map_del_name
r_io_map_del_name.restype = None
r_io_map_del_name.argtypes = [ctypes.POINTER(struct_r_io_map_t)]
r_io_map_get_by_fd = _libr_io.r_io_map_get_by_fd
r_io_map_get_by_fd.restype = ctypes.POINTER(struct_r_list_t)
r_io_map_get_by_fd.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32]
r_io_map_resize = _libr_io.r_io_map_resize
r_io_map_resize.restype = ctypes.c_bool
r_io_map_resize.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint32, ctypes.c_uint64]
r_io_map_locate = _libr_io.r_io_map_locate
r_io_map_locate.restype = ctypes.c_bool
r_io_map_locate.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.POINTER(ctypes.c_uint64), ctypes.c_uint64, ctypes.c_uint64]
r_io_p2v = _libr_io.r_io_p2v
r_io_p2v.restype = ctypes.c_uint64
r_io_p2v.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64]
r_io_v2p = _libr_io.r_io_v2p
r_io_v2p.restype = ctypes.c_uint64
r_io_v2p.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64]
r_io_submap_new = _libr_io.r_io_submap_new
r_io_submap_new.restype = ctypes.POINTER(struct_r_io_submap_t)
r_io_submap_new.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.POINTER(struct_r_io_map_ref_t)]
r_io_submap_set_from = _libr_io.r_io_submap_set_from
r_io_submap_set_from.restype = ctypes.c_bool
r_io_submap_set_from.argtypes = [ctypes.POINTER(struct_r_io_submap_t), ctypes.c_uint64]
r_io_submap_set_to = _libr_io.r_io_submap_set_to
r_io_submap_set_to.restype = ctypes.c_bool
r_io_submap_set_to.argtypes = [ctypes.POINTER(struct_r_io_submap_t), ctypes.c_uint64]
r_io_bank_new = _libr_io.r_io_bank_new
r_io_bank_new.restype = ctypes.POINTER(struct_r_io_bank_t)
r_io_bank_new.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_io_bank_del = _libr_io.r_io_bank_del
r_io_bank_del.restype = None
r_io_bank_del.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint32]
r_io_bank_first = _libr_io.r_io_bank_first
r_io_bank_first.restype = ctypes.c_uint32
r_io_bank_first.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_bank_add = _libr_io.r_io_bank_add
r_io_bank_add.restype = ctypes.c_bool
r_io_bank_add.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.POINTER(struct_r_io_bank_t)]
r_io_bank_clear = _libr_io.r_io_bank_clear
r_io_bank_clear.restype = None
r_io_bank_clear.argtypes = [ctypes.POINTER(struct_r_io_bank_t)]
r_io_bank_free = _libr_io.r_io_bank_free
r_io_bank_free.restype = None
r_io_bank_free.argtypes = [ctypes.POINTER(struct_r_io_bank_t)]
r_io_bank_init = _libr_io.r_io_bank_init
r_io_bank_init.restype = None
r_io_bank_init.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_bank_fini = _libr_io.r_io_bank_fini
r_io_bank_fini.restype = None
r_io_bank_fini.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_bank_get = _libr_io.r_io_bank_get
r_io_bank_get.restype = ctypes.POINTER(struct_r_io_bank_t)
r_io_bank_get.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint32]
r_io_bank_use = _libr_io.r_io_bank_use
r_io_bank_use.restype = ctypes.c_bool
r_io_bank_use.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint32]
r_io_bank_map_add_top = _libr_io.r_io_bank_map_add_top
r_io_bank_map_add_top.restype = ctypes.c_bool
r_io_bank_map_add_top.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint32, ctypes.c_uint32]
r_io_bank_map_add_bottom = _libr_io.r_io_bank_map_add_bottom
r_io_bank_map_add_bottom.restype = ctypes.c_bool
r_io_bank_map_add_bottom.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint32, ctypes.c_uint32]
r_io_bank_map_priorize = _libr_io.r_io_bank_map_priorize
r_io_bank_map_priorize.restype = ctypes.c_bool
r_io_bank_map_priorize.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint32, ctypes.c_uint32]
r_io_bank_map_depriorize = _libr_io.r_io_bank_map_depriorize
r_io_bank_map_depriorize.restype = ctypes.c_bool
r_io_bank_map_depriorize.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint32, ctypes.c_uint32]
r_io_bank_update_map_boundaries = _libr_io.r_io_bank_update_map_boundaries
r_io_bank_update_map_boundaries.restype = ctypes.c_bool
r_io_bank_update_map_boundaries.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint64, ctypes.c_uint64]
r_io_bank_locate = _libr_io.r_io_bank_locate
r_io_bank_locate.restype = ctypes.c_bool
r_io_bank_locate.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint64), ctypes.c_uint64, ctypes.c_uint64]
r_io_bank_del_map = _libr_io.r_io_bank_del_map
r_io_bank_del_map.restype = None
r_io_bank_del_map.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint32, ctypes.c_uint32]
r_io_bank_get_map_at = _libr_io.r_io_bank_get_map_at
r_io_bank_get_map_at.restype = ctypes.POINTER(struct_r_io_map_t)
r_io_bank_get_map_at.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint32, ctypes.c_uint64]
r_io_bank_read_at = _libr_io.r_io_bank_read_at
r_io_bank_read_at.restype = ctypes.c_bool
r_io_bank_read_at.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint32, ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_bank_write_at = _libr_io.r_io_bank_write_at
r_io_bank_write_at.restype = ctypes.c_bool
r_io_bank_write_at.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint32, ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_bank_read_from_submap_at = _libr_io.r_io_bank_read_from_submap_at
r_io_bank_read_from_submap_at.restype = ctypes.c_int32
r_io_bank_read_from_submap_at.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint32, ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_bank_write_to_submap_at = _libr_io.r_io_bank_write_to_submap_at
r_io_bank_write_to_submap_at.restype = ctypes.c_int32
r_io_bank_write_to_submap_at.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint32, ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_bank_drain = _libr_io.r_io_bank_drain
r_io_bank_drain.restype = None
r_io_bank_drain.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint32]
r_io_new = _libr_io.r_io_new
r_io_new.restype = ctypes.POINTER(struct_r_io_t)
r_io_new.argtypes = []
r_io_init = _libr_io.r_io_init
r_io_init.restype = ctypes.POINTER(struct_r_io_t)
r_io_init.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_open_nomap = _libr_io.r_io_open_nomap
r_io_open_nomap.restype = ctypes.POINTER(struct_r_io_desc_t)
r_io_open_nomap.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32]
r_io_open = _libr_io.r_io_open
r_io_open.restype = ctypes.POINTER(struct_r_io_desc_t)
r_io_open.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32]
r_io_open_at = _libr_io.r_io_open_at
r_io_open_at.restype = ctypes.POINTER(struct_r_io_desc_t)
r_io_open_at.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32, ctypes.c_uint64]
r_io_open_many = _libr_io.r_io_open_many
r_io_open_many.restype = ctypes.POINTER(struct_r_list_t)
r_io_open_many.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32]
class struct_r_buf_t(Structure):
    pass

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

r_io_open_buffer = _libr_io.r_io_open_buffer
r_io_open_buffer.restype = ctypes.POINTER(struct_r_io_desc_t)
r_io_open_buffer.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.POINTER(struct_r_buf_t), ctypes.c_int32, ctypes.c_int32]
r_io_close = _libr_io.r_io_close
r_io_close.restype = ctypes.c_bool
r_io_close.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_reopen = _libr_io.r_io_reopen
r_io_reopen.restype = ctypes.c_bool
r_io_reopen.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
r_io_close_all = _libr_io.r_io_close_all
r_io_close_all.restype = None
r_io_close_all.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_pread_at = _libr_io.r_io_pread_at
r_io_pread_at.restype = ctypes.c_int32
r_io_pread_at.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_pwrite_at = _libr_io.r_io_pwrite_at
r_io_pwrite_at.restype = ctypes.c_int32
r_io_pwrite_at.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_vread_at = _libr_io.r_io_vread_at
r_io_vread_at.restype = ctypes.c_bool
r_io_vread_at.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_vwrite_at = _libr_io.r_io_vwrite_at
r_io_vwrite_at.restype = ctypes.c_bool
r_io_vwrite_at.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_read_at = _libr_io.r_io_read_at
r_io_read_at.restype = ctypes.c_bool
r_io_read_at.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_read_at_mapped = _libr_io.r_io_read_at_mapped
r_io_read_at_mapped.restype = ctypes.c_bool
r_io_read_at_mapped.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_nread_at = _libr_io.r_io_nread_at
r_io_nread_at.restype = ctypes.c_int32
r_io_nread_at.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_write_at = _libr_io.r_io_write_at
r_io_write_at.restype = ctypes.c_bool
r_io_write_at.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_read = _libr_io.r_io_read
r_io_read.restype = ctypes.c_bool
r_io_read.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_write = _libr_io.r_io_write
r_io_write.restype = ctypes.c_bool
r_io_write.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_size = _libr_io.r_io_size
r_io_size.restype = ctypes.c_uint64
r_io_size.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_is_listener = _libr_io.r_io_is_listener
r_io_is_listener.restype = ctypes.c_bool
r_io_is_listener.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_system = _libr_io.r_io_system
r_io_system.restype = ctypes.POINTER(ctypes.c_char)
r_io_system.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.POINTER(ctypes.c_char)]
r_io_resize = _libr_io.r_io_resize
r_io_resize.restype = ctypes.c_bool
r_io_resize.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64]
r_io_extend_at = _libr_io.r_io_extend_at
r_io_extend_at.restype = ctypes.c_int32
r_io_extend_at.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64, ctypes.c_uint64]
r_io_set_write_mask = _libr_io.r_io_set_write_mask
r_io_set_write_mask.restype = ctypes.c_bool
r_io_set_write_mask.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_bind = _libr_io.r_io_bind
r_io_bind.restype = None
r_io_bind.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.POINTER(struct_r_io_bind_t)]
r_io_shift = _libr_io.r_io_shift
r_io_shift.restype = ctypes.c_bool
r_io_shift.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int64]
r_io_seek = _libr_io.r_io_seek
r_io_seek.restype = ctypes.c_uint64
r_io_seek.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64, ctypes.c_int32]
r_io_fini = _libr_io.r_io_fini
r_io_fini.restype = None
r_io_fini.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_free = _libr_io.r_io_free
r_io_free.restype = None
r_io_free.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_plugin_init = _libr_io.r_io_plugin_init
r_io_plugin_init.restype = ctypes.c_bool
r_io_plugin_init.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_plugin_add = _libr_io.r_io_plugin_add
r_io_plugin_add.restype = ctypes.c_bool
r_io_plugin_add.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.POINTER(struct_r_io_plugin_t)]
r_io_plugin_list = _libr_io.r_io_plugin_list
r_io_plugin_list.restype = ctypes.c_int32
r_io_plugin_list.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_plugin_list_json = _libr_io.r_io_plugin_list_json
r_io_plugin_list_json.restype = ctypes.c_int32
r_io_plugin_list_json.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_plugin_read = _libr_io.r_io_plugin_read
r_io_plugin_read.restype = ctypes.c_int32
r_io_plugin_read.argtypes = [ctypes.POINTER(struct_r_io_desc_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_plugin_write = _libr_io.r_io_plugin_write
r_io_plugin_write.restype = ctypes.c_int32
r_io_plugin_write.argtypes = [ctypes.POINTER(struct_r_io_desc_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_plugin_read_at = _libr_io.r_io_plugin_read_at
r_io_plugin_read_at.restype = ctypes.c_int32
r_io_plugin_read_at.argtypes = [ctypes.POINTER(struct_r_io_desc_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_plugin_write_at = _libr_io.r_io_plugin_write_at
r_io_plugin_write_at.restype = ctypes.c_int32
r_io_plugin_write_at.argtypes = [ctypes.POINTER(struct_r_io_desc_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_plugin_resolve = _libr_io.r_io_plugin_resolve
r_io_plugin_resolve.restype = ctypes.POINTER(struct_r_io_plugin_t)
r_io_plugin_resolve.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.POINTER(ctypes.c_char), ctypes.c_bool]
r_io_plugin_get_default = _libr_io.r_io_plugin_get_default
r_io_plugin_get_default.restype = ctypes.POINTER(struct_r_io_plugin_t)
r_io_plugin_get_default.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.POINTER(ctypes.c_char), ctypes.c_bool]
r_io_undo_init = _libr_io.r_io_undo_init
r_io_undo_init.restype = ctypes.c_int32
r_io_undo_init.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_undo_enable = _libr_io.r_io_undo_enable
r_io_undo_enable.restype = None
r_io_undo_enable.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.c_int32]
r_io_sundo = _libr_io.r_io_sundo
r_io_sundo.restype = ctypes.POINTER(struct_r_io_undos_t)
r_io_sundo.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64]
r_io_sundo_redo = _libr_io.r_io_sundo_redo
r_io_sundo_redo.restype = ctypes.POINTER(struct_r_io_undos_t)
r_io_sundo_redo.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_sundo_push = _libr_io.r_io_sundo_push
r_io_sundo_push.restype = None
r_io_sundo_push.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64, ctypes.c_int32]
r_io_sundo_reset = _libr_io.r_io_sundo_reset
r_io_sundo_reset.restype = None
r_io_sundo_reset.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_sundo_list = _libr_io.r_io_sundo_list
r_io_sundo_list.restype = ctypes.POINTER(struct_r_list_t)
r_io_sundo_list.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32]
r_io_wundo_new = _libr_io.r_io_wundo_new
r_io_wundo_new.restype = None
r_io_wundo_new.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_wundo_apply_all = _libr_io.r_io_wundo_apply_all
r_io_wundo_apply_all.restype = None
r_io_wundo_apply_all.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32]
r_io_wundo_apply = _libr_io.r_io_wundo_apply
r_io_wundo_apply.restype = ctypes.c_int32
r_io_wundo_apply.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.POINTER(struct_r_io_undo_w_t), ctypes.c_int32]
r_io_wundo_clear = _libr_io.r_io_wundo_clear
r_io_wundo_clear.restype = None
r_io_wundo_clear.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_wundo_size = _libr_io.r_io_wundo_size
r_io_wundo_size.restype = ctypes.c_int32
r_io_wundo_size.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_wundo_list = _libr_io.r_io_wundo_list
r_io_wundo_list.restype = None
r_io_wundo_list.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_wundo_set_t = _libraries['FIXME_STUB'].r_io_wundo_set_t
r_io_wundo_set_t.restype = ctypes.c_int32
r_io_wundo_set_t.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.POINTER(struct_r_io_undo_w_t), ctypes.c_int32]
r_io_wundo_set_all = _libraries['FIXME_STUB'].r_io_wundo_set_all
r_io_wundo_set_all.restype = None
r_io_wundo_set_all.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32]
r_io_wundo_set = _libr_io.r_io_wundo_set
r_io_wundo_set.restype = ctypes.c_int32
r_io_wundo_set.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.c_int32]
r_io_desc_new = _libr_io.r_io_desc_new
r_io_desc_new.restype = ctypes.POINTER(struct_r_io_desc_t)
r_io_desc_new.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.POINTER(struct_r_io_plugin_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(None)]
r_io_desc_open = _libr_io.r_io_desc_open
r_io_desc_open.restype = ctypes.POINTER(struct_r_io_desc_t)
r_io_desc_open.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32]
r_io_desc_open_plugin = _libr_io.r_io_desc_open_plugin
r_io_desc_open_plugin.restype = ctypes.POINTER(struct_r_io_desc_t)
r_io_desc_open_plugin.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.POINTER(struct_r_io_plugin_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32]
r_io_desc_close = _libr_io.r_io_desc_close
r_io_desc_close.restype = ctypes.c_bool
r_io_desc_close.argtypes = [ctypes.POINTER(struct_r_io_desc_t)]
r_io_desc_read = _libr_io.r_io_desc_read
r_io_desc_read.restype = ctypes.c_int32
r_io_desc_read.argtypes = [ctypes.POINTER(struct_r_io_desc_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_desc_write = _libr_io.r_io_desc_write
r_io_desc_write.restype = ctypes.c_int32
r_io_desc_write.argtypes = [ctypes.POINTER(struct_r_io_desc_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_desc_free = _libr_io.r_io_desc_free
r_io_desc_free.restype = None
r_io_desc_free.argtypes = [ctypes.POINTER(struct_r_io_desc_t)]
r_io_desc_add = _libr_io.r_io_desc_add
r_io_desc_add.restype = ctypes.c_bool
r_io_desc_add.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.POINTER(struct_r_io_desc_t)]
r_io_desc_del = _libr_io.r_io_desc_del
r_io_desc_del.restype = ctypes.c_bool
r_io_desc_del.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32]
r_io_desc_get = _libr_io.r_io_desc_get
r_io_desc_get.restype = ctypes.POINTER(struct_r_io_desc_t)
r_io_desc_get.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32]
r_io_desc_get_byuri = _libr_io.r_io_desc_get_byuri
r_io_desc_get_byuri.restype = ctypes.POINTER(struct_r_io_desc_t)
r_io_desc_get_byuri.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.POINTER(ctypes.c_char)]
r_io_desc_get_next = _libr_io.r_io_desc_get_next
r_io_desc_get_next.restype = ctypes.POINTER(struct_r_io_desc_t)
r_io_desc_get_next.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.POINTER(struct_r_io_desc_t)]
r_io_desc_get_prev = _libr_io.r_io_desc_get_prev
r_io_desc_get_prev.restype = ctypes.POINTER(struct_r_io_desc_t)
r_io_desc_get_prev.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.POINTER(struct_r_io_desc_t)]
r_io_desc_get_highest = _libr_io.r_io_desc_get_highest
r_io_desc_get_highest.restype = ctypes.POINTER(struct_r_io_desc_t)
r_io_desc_get_highest.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_desc_get_lowest = _libr_io.r_io_desc_get_lowest
r_io_desc_get_lowest.restype = ctypes.POINTER(struct_r_io_desc_t)
r_io_desc_get_lowest.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_desc_seek = _libr_io.r_io_desc_seek
r_io_desc_seek.restype = ctypes.c_uint64
r_io_desc_seek.argtypes = [ctypes.POINTER(struct_r_io_desc_t), ctypes.c_uint64, ctypes.c_int32]
r_io_desc_resize = _libr_io.r_io_desc_resize
r_io_desc_resize.restype = ctypes.c_bool
r_io_desc_resize.argtypes = [ctypes.POINTER(struct_r_io_desc_t), ctypes.c_uint64]
r_io_desc_size = _libr_io.r_io_desc_size
r_io_desc_size.restype = ctypes.c_uint64
r_io_desc_size.argtypes = [ctypes.POINTER(struct_r_io_desc_t)]
r_io_desc_is_blockdevice = _libr_io.r_io_desc_is_blockdevice
r_io_desc_is_blockdevice.restype = ctypes.c_bool
r_io_desc_is_blockdevice.argtypes = [ctypes.POINTER(struct_r_io_desc_t)]
r_io_desc_is_chardevice = _libr_io.r_io_desc_is_chardevice
r_io_desc_is_chardevice.restype = ctypes.c_bool
r_io_desc_is_chardevice.argtypes = [ctypes.POINTER(struct_r_io_desc_t)]
r_io_desc_exchange = _libr_io.r_io_desc_exchange
r_io_desc_exchange.restype = ctypes.c_bool
r_io_desc_exchange.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.c_int32]
r_io_desc_is_dbg = _libr_io.r_io_desc_is_dbg
r_io_desc_is_dbg.restype = ctypes.c_bool
r_io_desc_is_dbg.argtypes = [ctypes.POINTER(struct_r_io_desc_t)]
r_io_desc_get_pid = _libr_io.r_io_desc_get_pid
r_io_desc_get_pid.restype = ctypes.c_int32
r_io_desc_get_pid.argtypes = [ctypes.POINTER(struct_r_io_desc_t)]
r_io_desc_get_tid = _libr_io.r_io_desc_get_tid
r_io_desc_get_tid.restype = ctypes.c_int32
r_io_desc_get_tid.argtypes = [ctypes.POINTER(struct_r_io_desc_t)]
r_io_desc_get_base = _libr_io.r_io_desc_get_base
r_io_desc_get_base.restype = ctypes.c_bool
r_io_desc_get_base.argtypes = [ctypes.POINTER(struct_r_io_desc_t), ctypes.POINTER(ctypes.c_uint64)]
r_io_desc_read_at = _libr_io.r_io_desc_read_at
r_io_desc_read_at.restype = ctypes.c_int32
r_io_desc_read_at.argtypes = [ctypes.POINTER(struct_r_io_desc_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_desc_write_at = _libr_io.r_io_desc_write_at
r_io_desc_write_at.restype = ctypes.c_int32
r_io_desc_write_at.argtypes = [ctypes.POINTER(struct_r_io_desc_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_desc_init = _libraries['FIXME_STUB'].r_io_desc_init
r_io_desc_init.restype = ctypes.c_bool
r_io_desc_init.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_desc_fini = _libraries['FIXME_STUB'].r_io_desc_fini
r_io_desc_fini.restype = None
r_io_desc_fini.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_cache_invalidate = _libr_io.r_io_cache_invalidate
r_io_cache_invalidate.restype = ctypes.c_int32
r_io_cache_invalidate.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64, ctypes.c_uint64]
r_io_cache_at = _libr_io.r_io_cache_at
r_io_cache_at.restype = ctypes.c_bool
r_io_cache_at.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64]
r_io_cache_commit = _libr_io.r_io_cache_commit
r_io_cache_commit.restype = None
r_io_cache_commit.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64, ctypes.c_uint64]
r_io_cache_init = _libr_io.r_io_cache_init
r_io_cache_init.restype = None
r_io_cache_init.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_cache_fini = _libr_io.r_io_cache_fini
r_io_cache_fini.restype = None
r_io_cache_fini.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_cache_list = _libr_io.r_io_cache_list
r_io_cache_list.restype = ctypes.c_bool
r_io_cache_list.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32]
r_io_cache_reset = _libr_io.r_io_cache_reset
r_io_cache_reset.restype = None
r_io_cache_reset.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32]
r_io_cache_write = _libr_io.r_io_cache_write
r_io_cache_write.restype = ctypes.c_bool
r_io_cache_write.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_cache_read = _libr_io.r_io_cache_read
r_io_cache_read.restype = ctypes.c_bool
r_io_cache_read.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_desc_cache_init = _libr_io.r_io_desc_cache_init
r_io_desc_cache_init.restype = ctypes.c_bool
r_io_desc_cache_init.argtypes = [ctypes.POINTER(struct_r_io_desc_t)]
r_io_desc_cache_write = _libr_io.r_io_desc_cache_write
r_io_desc_cache_write.restype = ctypes.c_int32
r_io_desc_cache_write.argtypes = [ctypes.POINTER(struct_r_io_desc_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_desc_cache_read = _libr_io.r_io_desc_cache_read
r_io_desc_cache_read.restype = ctypes.c_int32
r_io_desc_cache_read.argtypes = [ctypes.POINTER(struct_r_io_desc_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_desc_cache_commit = _libr_io.r_io_desc_cache_commit
r_io_desc_cache_commit.restype = ctypes.c_bool
r_io_desc_cache_commit.argtypes = [ctypes.POINTER(struct_r_io_desc_t)]
r_io_desc_cache_cleanup = _libr_io.r_io_desc_cache_cleanup
r_io_desc_cache_cleanup.restype = None
r_io_desc_cache_cleanup.argtypes = [ctypes.POINTER(struct_r_io_desc_t)]
r_io_desc_cache_fini = _libr_io.r_io_desc_cache_fini
r_io_desc_cache_fini.restype = None
r_io_desc_cache_fini.argtypes = [ctypes.POINTER(struct_r_io_desc_t)]
r_io_desc_cache_fini_all = _libr_io.r_io_desc_cache_fini_all
r_io_desc_cache_fini_all.restype = None
r_io_desc_cache_fini_all.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_desc_cache_list = _libr_io.r_io_desc_cache_list
r_io_desc_cache_list.restype = ctypes.POINTER(struct_r_list_t)
r_io_desc_cache_list.argtypes = [ctypes.POINTER(struct_r_io_desc_t)]
r_io_desc_extend = _libr_io.r_io_desc_extend
r_io_desc_extend.restype = ctypes.c_int32
r_io_desc_extend.argtypes = [ctypes.POINTER(struct_r_io_desc_t), ctypes.c_uint64]
r_io_buffer_read = _libraries['FIXME_STUB'].r_io_buffer_read
r_io_buffer_read.restype = ctypes.c_int32
r_io_buffer_read.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_buffer_load = _libraries['FIXME_STUB'].r_io_buffer_load
r_io_buffer_load.restype = ctypes.c_int32
r_io_buffer_load.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64, ctypes.c_int32]
r_io_buffer_close = _libraries['FIXME_STUB'].r_io_buffer_close
r_io_buffer_close.restype = None
r_io_buffer_close.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_fd_open = _libr_io.r_io_fd_open
r_io_fd_open.restype = ctypes.c_int32
r_io_fd_open.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32]
r_io_fd_close = _libr_io.r_io_fd_close
r_io_fd_close.restype = ctypes.c_bool
r_io_fd_close.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32]
r_io_fd_read = _libr_io.r_io_fd_read
r_io_fd_read.restype = ctypes.c_int32
r_io_fd_read.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_fd_write = _libr_io.r_io_fd_write
r_io_fd_write.restype = ctypes.c_int32
r_io_fd_write.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_fd_seek = _libr_io.r_io_fd_seek
r_io_fd_seek.restype = ctypes.c_uint64
r_io_fd_seek.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.c_uint64, ctypes.c_int32]
r_io_fd_size = _libr_io.r_io_fd_size
r_io_fd_size.restype = ctypes.c_uint64
r_io_fd_size.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32]
r_io_fd_resize = _libr_io.r_io_fd_resize
r_io_fd_resize.restype = ctypes.c_bool
r_io_fd_resize.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.c_uint64]
r_io_fd_is_blockdevice = _libr_io.r_io_fd_is_blockdevice
r_io_fd_is_blockdevice.restype = ctypes.c_bool
r_io_fd_is_blockdevice.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32]
r_io_fd_is_chardevice = _libr_io.r_io_fd_is_chardevice
r_io_fd_is_chardevice.restype = ctypes.c_bool
r_io_fd_is_chardevice.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32]
r_io_fd_read_at = _libr_io.r_io_fd_read_at
r_io_fd_read_at.restype = ctypes.c_int32
r_io_fd_read_at.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_fd_write_at = _libr_io.r_io_fd_write_at
r_io_fd_write_at.restype = ctypes.c_int32
r_io_fd_write_at.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_io_fd_is_dbg = _libr_io.r_io_fd_is_dbg
r_io_fd_is_dbg.restype = ctypes.c_bool
r_io_fd_is_dbg.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32]
r_io_fd_get_pid = _libr_io.r_io_fd_get_pid
r_io_fd_get_pid.restype = ctypes.c_int32
r_io_fd_get_pid.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32]
r_io_fd_get_tid = _libr_io.r_io_fd_get_tid
r_io_fd_get_tid.restype = ctypes.c_int32
r_io_fd_get_tid.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32]
r_io_fd_get_base = _libr_io.r_io_fd_get_base
r_io_fd_get_base.restype = ctypes.c_bool
r_io_fd_get_base.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32, ctypes.POINTER(ctypes.c_uint64)]
r_io_fd_get_name = _libr_io.r_io_fd_get_name
r_io_fd_get_name.restype = ctypes.POINTER(ctypes.c_char)
r_io_fd_get_name.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32]
r_io_fd_get_current = _libr_io.r_io_fd_get_current
r_io_fd_get_current.restype = ctypes.c_int32
r_io_fd_get_current.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_use_fd = _libr_io.r_io_use_fd
r_io_use_fd.restype = ctypes.c_bool
r_io_use_fd.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32]
r_io_fd_get_next = _libr_io.r_io_fd_get_next
r_io_fd_get_next.restype = ctypes.c_int32
r_io_fd_get_next.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32]
r_io_fd_get_prev = _libr_io.r_io_fd_get_prev
r_io_fd_get_prev.restype = ctypes.c_int32
r_io_fd_get_prev.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_int32]
r_io_fd_get_highest = _libr_io.r_io_fd_get_highest
r_io_fd_get_highest.restype = ctypes.c_int32
r_io_fd_get_highest.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_fd_get_lowest = _libr_io.r_io_fd_get_lowest
r_io_fd_get_lowest.restype = ctypes.c_int32
r_io_fd_get_lowest.argtypes = [ctypes.POINTER(struct_r_io_t)]
r_io_is_valid_offset = _libr_io.r_io_is_valid_offset
r_io_is_valid_offset.restype = ctypes.c_bool
r_io_is_valid_offset.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64, ctypes.c_int32]
r_io_addr_is_mapped = _libr_io.r_io_addr_is_mapped
r_io_addr_is_mapped.restype = ctypes.c_bool
r_io_addr_is_mapped.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64]
r_io_read_i = _libr_io.r_io_read_i
r_io_read_i.restype = ctypes.c_bool
r_io_read_i.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64), ctypes.c_int32, ctypes.c_bool]
r_io_write_i = _libr_io.r_io_write_i
r_io_write_i.restype = ctypes.c_bool
r_io_write_i.argtypes = [ctypes.POINTER(struct_r_io_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64), ctypes.c_int32, ctypes.c_bool]
r_io_plugin_procpid = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_malloc = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_sparse = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_ptrace = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_w32dbg = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_windbg = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_mach = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_debug = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_shm = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_gdb = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_rap = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_http = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_bfdbg = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_w32 = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_zip = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_mmap = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_default = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_ihex = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_self = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_gzip = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_winkd = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_r2pipe = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_r2web = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_qnx = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_r2k = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_tcpslurp = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_bochs = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_null = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_ar = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_rbuf = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_winedbg = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_gprobe = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_fd = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_socket = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
r_io_plugin_isotp = struct_r_io_plugin_t # Variable struct_r_io_plugin_t
__all__ = \
    ['RIO', 'RIOAddrIsMapped', 'RIOBank', 'RIOBankGet', 'RIOBind',
    'RIOCache', 'RIOClose', 'RIODesc', 'RIODescCache', 'RIODescGet',
    'RIODescSize', 'RIODescUse', 'RIOFdClose', 'RIOFdGetMap',
    'RIOFdGetName', 'RIOFdIsDbg', 'RIOFdOpen', 'RIOFdRead',
    'RIOFdReadAt', 'RIOFdRemap', 'RIOFdResize', 'RIOFdSeek',
    'RIOFdSize', 'RIOFdWrite', 'RIOFdWriteAt', 'RIOIsValidOff',
    'RIOMap', 'RIOMapAdd', 'RIOMapGet', 'RIOMapGetAt',
    'RIOMapGetPaddr', 'RIOMapRef', 'RIOOpen', 'RIOOpenAt', 'RIOP2V',
    'RIOPlugin', 'RIORap', 'RIOReadAt', 'RIOSubMap', 'RIOSystem',
    'RIOUndo', 'RIOUndoWrite', 'RIOUndos', 'RIOV2P', 'RIOWriteAt',
    'r_io_addr_is_mapped', 'r_io_bank_add', 'r_io_bank_clear',
    'r_io_bank_del', 'r_io_bank_del_map', 'r_io_bank_drain',
    'r_io_bank_fini', 'r_io_bank_first', 'r_io_bank_free',
    'r_io_bank_get', 'r_io_bank_get_map_at', 'r_io_bank_init',
    'r_io_bank_locate', 'r_io_bank_map_add_bottom',
    'r_io_bank_map_add_top', 'r_io_bank_map_depriorize',
    'r_io_bank_map_priorize', 'r_io_bank_new', 'r_io_bank_read_at',
    'r_io_bank_read_from_submap_at',
    'r_io_bank_update_map_boundaries', 'r_io_bank_use',
    'r_io_bank_write_at', 'r_io_bank_write_to_submap_at', 'r_io_bind',
    'r_io_buffer_close', 'r_io_buffer_load', 'r_io_buffer_read',
    'r_io_cache_at', 'r_io_cache_commit', 'r_io_cache_fini',
    'r_io_cache_init', 'r_io_cache_invalidate', 'r_io_cache_list',
    'r_io_cache_read', 'r_io_cache_reset', 'r_io_cache_write',
    'r_io_close', 'r_io_close_all', 'r_io_desc_add',
    'r_io_desc_cache_cleanup', 'r_io_desc_cache_commit',
    'r_io_desc_cache_fini', 'r_io_desc_cache_fini_all',
    'r_io_desc_cache_init', 'r_io_desc_cache_list',
    'r_io_desc_cache_read', 'r_io_desc_cache_write',
    'r_io_desc_close', 'r_io_desc_del', 'r_io_desc_exchange',
    'r_io_desc_extend', 'r_io_desc_fini', 'r_io_desc_free',
    'r_io_desc_get', 'r_io_desc_get_base', 'r_io_desc_get_byuri',
    'r_io_desc_get_highest', 'r_io_desc_get_lowest',
    'r_io_desc_get_next', 'r_io_desc_get_pid', 'r_io_desc_get_prev',
    'r_io_desc_get_tid', 'r_io_desc_init', 'r_io_desc_is_blockdevice',
    'r_io_desc_is_chardevice', 'r_io_desc_is_dbg', 'r_io_desc_new',
    'r_io_desc_open', 'r_io_desc_open_plugin', 'r_io_desc_read',
    'r_io_desc_read_at', 'r_io_desc_resize', 'r_io_desc_seek',
    'r_io_desc_size', 'r_io_desc_write', 'r_io_desc_write_at',
    'r_io_extend_at', 'r_io_fd_close', 'r_io_fd_get_base',
    'r_io_fd_get_current', 'r_io_fd_get_highest',
    'r_io_fd_get_lowest', 'r_io_fd_get_name', 'r_io_fd_get_next',
    'r_io_fd_get_pid', 'r_io_fd_get_prev', 'r_io_fd_get_tid',
    'r_io_fd_is_blockdevice', 'r_io_fd_is_chardevice',
    'r_io_fd_is_dbg', 'r_io_fd_open', 'r_io_fd_read',
    'r_io_fd_read_at', 'r_io_fd_resize', 'r_io_fd_seek',
    'r_io_fd_size', 'r_io_fd_write', 'r_io_fd_write_at', 'r_io_fini',
    'r_io_free', 'r_io_init', 'r_io_is_listener',
    'r_io_is_valid_offset', 'r_io_map_add', 'r_io_map_add_bottom',
    'r_io_map_cleanup', 'r_io_map_del', 'r_io_map_del_for_fd',
    'r_io_map_del_name', 'r_io_map_depriorize', 'r_io_map_exists',
    'r_io_map_exists_for_id', 'r_io_map_fini', 'r_io_map_get',
    'r_io_map_get_at', 'r_io_map_get_by_fd', 'r_io_map_get_by_ref',
    'r_io_map_get_paddr', 'r_io_map_init', 'r_io_map_is_in_range',
    'r_io_map_is_mapped', 'r_io_map_locate', 'r_io_map_priorize',
    'r_io_map_priorize_for_fd', 'r_io_map_remap', 'r_io_map_remap_fd',
    'r_io_map_reset', 'r_io_map_resize', 'r_io_map_set_name',
    'r_io_new', 'r_io_nread_at', 'r_io_open', 'r_io_open_at',
    'r_io_open_buffer', 'r_io_open_many', 'r_io_open_nomap',
    'r_io_p2v', 'r_io_plugin_add', 'r_io_plugin_ar',
    'r_io_plugin_bfdbg', 'r_io_plugin_bochs', 'r_io_plugin_debug',
    'r_io_plugin_default', 'r_io_plugin_fd', 'r_io_plugin_gdb',
    'r_io_plugin_get_default', 'r_io_plugin_gprobe',
    'r_io_plugin_gzip', 'r_io_plugin_http', 'r_io_plugin_ihex',
    'r_io_plugin_init', 'r_io_plugin_isotp', 'r_io_plugin_list',
    'r_io_plugin_list_json', 'r_io_plugin_mach', 'r_io_plugin_malloc',
    'r_io_plugin_mmap', 'r_io_plugin_null', 'r_io_plugin_procpid',
    'r_io_plugin_ptrace', 'r_io_plugin_qnx', 'r_io_plugin_r2k',
    'r_io_plugin_r2pipe', 'r_io_plugin_r2web', 'r_io_plugin_rap',
    'r_io_plugin_rbuf', 'r_io_plugin_read', 'r_io_plugin_read_at',
    'r_io_plugin_resolve', 'r_io_plugin_self', 'r_io_plugin_shm',
    'r_io_plugin_socket', 'r_io_plugin_sparse',
    'r_io_plugin_tcpslurp', 'r_io_plugin_w32', 'r_io_plugin_w32dbg',
    'r_io_plugin_windbg', 'r_io_plugin_winedbg', 'r_io_plugin_winkd',
    'r_io_plugin_write', 'r_io_plugin_write_at', 'r_io_plugin_zip',
    'r_io_pread_at', 'r_io_pwrite_at', 'r_io_read', 'r_io_read_at',
    'r_io_read_at_mapped', 'r_io_read_i', 'r_io_reopen',
    'r_io_resize', 'r_io_seek', 'r_io_set_write_mask', 'r_io_shift',
    'r_io_size', 'r_io_submap_new', 'r_io_submap_set_from',
    'r_io_submap_set_to', 'r_io_sundo', 'r_io_sundo_list',
    'r_io_sundo_push', 'r_io_sundo_redo', 'r_io_sundo_reset',
    'r_io_system', 'r_io_undo_enable', 'r_io_undo_init',
    'r_io_use_fd', 'r_io_v2p', 'r_io_version', 'r_io_vread_at',
    'r_io_vwrite_at', 'r_io_write', 'r_io_write_at', 'r_io_write_i',
    'r_io_wundo_apply', 'r_io_wundo_apply_all', 'r_io_wundo_clear',
    'r_io_wundo_list', 'r_io_wundo_new', 'r_io_wundo_set',
    'r_io_wundo_set_all', 'r_io_wundo_set_t', 'r_io_wundo_size',
    'struct_c__SA_RIORap', 'struct_ht_up_bucket_t', 'struct_ht_up_kv',
    'struct_ht_up_options_t', 'struct_ht_up_t', 'struct_in_addr',
    'struct_ls_iter_t', 'struct_ls_t', 'struct_r_buf_t',
    'struct_r_buffer_methods_t', 'struct_r_cache_t',
    'struct_r_core_bind_t', 'struct_r_crbtree_node',
    'struct_r_crbtree_t', 'struct_r_event_t', 'struct_r_id_pool_t',
    'struct_r_id_storage_t', 'struct_r_interval_t',
    'struct_r_io_bank_t', 'struct_r_io_bind_t', 'struct_r_io_cache_t',
    'struct_r_io_desc_cache_t', 'struct_r_io_desc_t',
    'struct_r_io_map_ref_t', 'struct_r_io_map_t',
    'struct_r_io_plugin_t', 'struct_r_io_submap_t', 'struct_r_io_t',
    'struct_r_io_undo_t', 'struct_r_io_undo_w_t',
    'struct_r_io_undos_t', 'struct_r_list_iter_t', 'struct_r_list_t',
    'struct_r_pvector_t', 'struct_r_queue_t', 'struct_r_skyline_t',
    'struct_r_socket_t', 'struct_r_vector_t', 'struct_sockaddr_in']
