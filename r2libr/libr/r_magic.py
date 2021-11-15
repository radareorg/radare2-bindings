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



r_magic_version = _libr_magic.r_magic_version
r_magic_version.restype = ctypes.POINTER(ctypes.c_char)
r_magic_version.argtypes = []
class union_VALUETYPE(Union):
    pass

union_VALUETYPE._pack_ = 1 # source:False
union_VALUETYPE._fields_ = [
    ('b', ctypes.c_ubyte),
    ('h', ctypes.c_uint16),
    ('l', ctypes.c_uint32),
    ('q', ctypes.c_uint64),
    ('hs', ctypes.c_ubyte * 2),
    ('hl', ctypes.c_ubyte * 4),
    ('hq', ctypes.c_ubyte * 8),
    ('s', ctypes.c_char * 32),
    ('f', ctypes.c_float),
    ('d', ctypes.c_double),
    ('PADDING_0', ctypes.c_ubyte * 24),
]

class struct_r_magic(Structure):
    pass

class union_r_magic_0(Union):
    pass

class struct_r_magic_0_0(Structure):
    pass

struct_r_magic_0_0._pack_ = 1 # source:False
struct_r_magic_0_0._fields_ = [
    ('_count', ctypes.c_uint32),
    ('_flags', ctypes.c_uint32),
]

union_r_magic_0._pack_ = 1 # source:False
union_r_magic_0._anonymous_ = ('_0',)
union_r_magic_0._fields_ = [
    ('_mask', ctypes.c_uint64),
    ('_0', struct_r_magic_0_0),
]

struct_r_magic._pack_ = 1 # source:False
struct_r_magic._anonymous_ = ('_0',)
struct_r_magic._fields_ = [
    ('cont_level', ctypes.c_uint16),
    ('flag', ctypes.c_ubyte),
    ('dummy1', ctypes.c_ubyte),
    ('reln', ctypes.c_ubyte),
    ('vallen', ctypes.c_ubyte),
    ('type', ctypes.c_ubyte),
    ('in_type', ctypes.c_ubyte),
    ('in_op', ctypes.c_ubyte),
    ('mask_op', ctypes.c_ubyte),
    ('cond', ctypes.c_ubyte),
    ('dummy2', ctypes.c_ubyte),
    ('offset', ctypes.c_uint32),
    ('in_offset', ctypes.c_uint32),
    ('lineno', ctypes.c_uint32),
    ('_0', union_r_magic_0),
    ('value', union_VALUETYPE),
    ('desc', ctypes.c_char * 64),
    ('mimetype', ctypes.c_char * 64),
]

class struct_mlist(Structure):
    pass

struct_mlist._pack_ = 1 # source:False
struct_mlist._fields_ = [
    ('magic', ctypes.POINTER(struct_r_magic)),
    ('nmagic', ctypes.c_uint32),
    ('mapped', ctypes.c_int32),
    ('next', ctypes.POINTER(struct_mlist)),
    ('prev', ctypes.POINTER(struct_mlist)),
]

class struct_r_magic_set(Structure):
    pass

class struct_out(Structure):
    pass

struct_out._pack_ = 1 # source:False
struct_out._fields_ = [
    ('buf', ctypes.POINTER(ctypes.c_char)),
    ('pbuf', ctypes.POINTER(ctypes.c_char)),
]

class struct_cont(Structure):
    pass

class struct_level_info(Structure):
    pass

struct_cont._pack_ = 1 # source:False
struct_cont._fields_ = [
    ('len', ctypes.c_uint64),
    ('li', ctypes.POINTER(struct_level_info)),
]

class struct_r_magic_set_2(Structure):
    pass

struct_r_magic_set_2._pack_ = 1 # source:False
struct_r_magic_set_2._fields_ = [
    ('s', ctypes.POINTER(ctypes.c_char)),
    ('s_len', ctypes.c_uint64),
    ('offset', ctypes.c_uint64),
    ('rm_len', ctypes.c_uint64),
]

struct_r_magic_set._pack_ = 1 # source:False
struct_r_magic_set._anonymous_ = ('_0',)
struct_r_magic_set._fields_ = [
    ('mlist', ctypes.POINTER(struct_mlist)),
    ('c', struct_cont),
    ('o', struct_out),
    ('offset', ctypes.c_uint32),
    ('error', ctypes.c_int32),
    ('flags', ctypes.c_int32),
    ('haderr', ctypes.c_int32),
    ('file', ctypes.POINTER(ctypes.c_char)),
    ('line', ctypes.c_uint64),
    ('_0', struct_r_magic_set_2),
    ('ms_value', union_VALUETYPE),
]

struct_level_info._pack_ = 1 # source:False
struct_level_info._fields_ = [
    ('off', ctypes.c_int32),
    ('got_match', ctypes.c_int32),
    ('last_match', ctypes.c_int32),
    ('last_cond', ctypes.c_int32),
]

RMagic = struct_r_magic_set
r_magic_new = _libr_magic.r_magic_new
r_magic_new.restype = ctypes.POINTER(struct_r_magic_set)
r_magic_new.argtypes = [ctypes.c_int32]
r_magic_free = _libr_magic.r_magic_free
r_magic_free.restype = None
r_magic_free.argtypes = [ctypes.POINTER(struct_r_magic_set)]
r_magic_file = _libr_magic.r_magic_file
r_magic_file.restype = ctypes.POINTER(ctypes.c_char)
r_magic_file.argtypes = [ctypes.POINTER(struct_r_magic_set), ctypes.POINTER(ctypes.c_char)]
r_magic_descriptor = _libr_magic.r_magic_descriptor
r_magic_descriptor.restype = ctypes.POINTER(ctypes.c_char)
r_magic_descriptor.argtypes = [ctypes.POINTER(struct_r_magic_set), ctypes.c_int32]
size_t = ctypes.c_uint64
r_magic_buffer = _libr_magic.r_magic_buffer
r_magic_buffer.restype = ctypes.POINTER(ctypes.c_char)
r_magic_buffer.argtypes = [ctypes.POINTER(struct_r_magic_set), ctypes.POINTER(None), size_t]
r_magic_error = _libr_magic.r_magic_error
r_magic_error.restype = ctypes.POINTER(ctypes.c_char)
r_magic_error.argtypes = [ctypes.POINTER(struct_r_magic_set)]
r_magic_setflags = _libr_magic.r_magic_setflags
r_magic_setflags.restype = None
r_magic_setflags.argtypes = [ctypes.POINTER(struct_r_magic_set), ctypes.c_int32]
r_magic_load = _libr_magic.r_magic_load
r_magic_load.restype = ctypes.c_bool
r_magic_load.argtypes = [ctypes.POINTER(struct_r_magic_set), ctypes.POINTER(ctypes.c_char)]
r_magic_load_buffer = _libr_magic.r_magic_load_buffer
r_magic_load_buffer.restype = ctypes.c_bool
r_magic_load_buffer.argtypes = [ctypes.POINTER(struct_r_magic_set), ctypes.POINTER(ctypes.c_ubyte), size_t]
r_magic_compile = _libr_magic.r_magic_compile
r_magic_compile.restype = ctypes.c_bool
r_magic_compile.argtypes = [ctypes.POINTER(struct_r_magic_set), ctypes.POINTER(ctypes.c_char)]
r_magic_check = _libr_magic.r_magic_check
r_magic_check.restype = ctypes.c_bool
r_magic_check.argtypes = [ctypes.POINTER(struct_r_magic_set), ctypes.POINTER(ctypes.c_char)]
r_magic_errno = _libr_magic.r_magic_errno
r_magic_errno.restype = ctypes.c_int32
r_magic_errno.argtypes = [ctypes.POINTER(struct_r_magic_set)]
__all__ = \
    ['RMagic', 'r_magic_buffer', 'r_magic_check', 'r_magic_compile',
    'r_magic_descriptor', 'r_magic_errno', 'r_magic_error',
    'r_magic_file', 'r_magic_free', 'r_magic_load',
    'r_magic_load_buffer', 'r_magic_new', 'r_magic_setflags',
    'r_magic_version', 'size_t', 'struct_cont', 'struct_level_info',
    'struct_mlist', 'struct_out', 'struct_r_magic',
    'struct_r_magic_0_0', 'struct_r_magic_set',
    'struct_r_magic_set_2', 'union_VALUETYPE', 'union_r_magic_0']
