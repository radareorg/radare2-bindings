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



r_main_version = _libr_main.r_main_version
r_main_version.restype = ctypes.POINTER(ctypes.c_char)
r_main_version.argtypes = []
class struct_r_main_t(Structure):
    pass

struct_r_main_t._pack_ = 1 # source:False
struct_r_main_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('main', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char)))),
]

RMain = struct_r_main_t
RMainCallback = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char)))
r_main_new = _libr_main.r_main_new
r_main_new.restype = ctypes.POINTER(struct_r_main_t)
r_main_new.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_main_free = _libr_main.r_main_free
r_main_free.restype = None
r_main_free.argtypes = [ctypes.POINTER(struct_r_main_t)]
r_main_run = _libr_main.r_main_run
r_main_run.restype = ctypes.c_int32
r_main_run.argtypes = [ctypes.POINTER(struct_r_main_t), ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
r_main_version_print = _libr_main.r_main_version_print
r_main_version_print.restype = ctypes.c_int32
r_main_version_print.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_main_ravc2 = _libr_main.r_main_ravc2
r_main_ravc2.restype = ctypes.c_int32
r_main_ravc2.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
r_main_rax2 = _libr_main.r_main_rax2
r_main_rax2.restype = ctypes.c_int32
r_main_rax2.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
r_main_rarun2 = _libr_main.r_main_rarun2
r_main_rarun2.restype = ctypes.c_int32
r_main_rarun2.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
r_main_rahash2 = _libr_main.r_main_rahash2
r_main_rahash2.restype = ctypes.c_int32
r_main_rahash2.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
r_main_rabin2 = _libr_main.r_main_rabin2
r_main_rabin2.restype = ctypes.c_int32
r_main_rabin2.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
r_main_radare2 = _libr_main.r_main_radare2
r_main_radare2.restype = ctypes.c_int32
r_main_radare2.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
r_main_rasm2 = _libr_main.r_main_rasm2
r_main_rasm2.restype = ctypes.c_int32
r_main_rasm2.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
r_main_r2agent = _libr_main.r_main_r2agent
r_main_r2agent.restype = ctypes.c_int32
r_main_r2agent.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
r_main_rafind2 = _libr_main.r_main_rafind2
r_main_rafind2.restype = ctypes.c_int32
r_main_rafind2.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
r_main_radiff2 = _libr_main.r_main_radiff2
r_main_radiff2.restype = ctypes.c_int32
r_main_radiff2.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
r_main_ragg2 = _libr_main.r_main_ragg2
r_main_ragg2.restype = ctypes.c_int32
r_main_ragg2.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
r_main_rasign2 = _libr_main.r_main_rasign2
r_main_rasign2.restype = ctypes.c_int32
r_main_rasign2.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
r_main_r2pm = _libr_main.r_main_r2pm
r_main_r2pm.restype = ctypes.c_int32
r_main_r2pm.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
__all__ = \
    ['RMain', 'RMainCallback', 'r_main_free', 'r_main_new',
    'r_main_r2agent', 'r_main_r2pm', 'r_main_rabin2',
    'r_main_radare2', 'r_main_radiff2', 'r_main_rafind2',
    'r_main_ragg2', 'r_main_rahash2', 'r_main_rarun2',
    'r_main_rasign2', 'r_main_rasm2', 'r_main_ravc2', 'r_main_rax2',
    'r_main_run', 'r_main_version', 'r_main_version_print',
    'struct_r_main_t']
