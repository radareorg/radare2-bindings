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



c_int128 = ctypes.c_ubyte*16
c_uint128 = c_int128
void = None
if ctypes.sizeof(ctypes.c_longdouble) == 16:
    c_long_double_t = ctypes.c_longdouble
else:
    c_long_double_t = ctypes.c_ubyte*16

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





r_lang_version = _libr_lang.r_lang_version
r_lang_version.restype = ctypes.POINTER(ctypes.c_char)
r_lang_version.argtypes = []
RCoreCmdStrCallback = ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))
RCoreCmdfCallback = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))
class struct_r_lang_t(Structure):
    pass

class struct_r_list_t(Structure):
    pass

class struct_r_lang_plugin_t(Structure):
    pass

struct_r_lang_t._pack_ = 1 # source:False
struct_r_lang_t._fields_ = [
    ('cur', ctypes.POINTER(struct_r_lang_plugin_t)),
    ('user', ctypes.POINTER(None)),
    ('defs', ctypes.POINTER(struct_r_list_t)),
    ('langs', ctypes.POINTER(struct_r_list_t)),
    ('cb_printf', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_char))),
    ('cmd_str', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))),
    ('cmdf', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))),
]

struct_r_lang_plugin_t._pack_ = 1 # source:False
struct_r_lang_plugin_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('alias', ctypes.POINTER(ctypes.c_char)),
    ('desc', ctypes.POINTER(ctypes.c_char)),
    ('example', ctypes.POINTER(ctypes.c_char)),
    ('license', ctypes.POINTER(ctypes.c_char)),
    ('help', ctypes.POINTER(ctypes.POINTER(ctypes.c_char))),
    ('ext', ctypes.POINTER(ctypes.c_char)),
    ('init', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_lang_t))),
    ('setup', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_lang_t))),
    ('fini', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_lang_t))),
    ('prompt', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_lang_t))),
    ('run', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_lang_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32)),
    ('run_file', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_lang_t), ctypes.POINTER(ctypes.c_char))),
    ('set_argv', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_lang_t), ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char)))),
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

RLang = struct_r_lang_t
RLangPlugin = struct_r_lang_plugin_t
class struct_r_lang_def_t(Structure):
    pass

struct_r_lang_def_t._pack_ = 1 # source:False
struct_r_lang_def_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('type', ctypes.POINTER(ctypes.c_char)),
    ('value', ctypes.POINTER(None)),
]

RLangDef = struct_r_lang_def_t
r_lang_new = _libr_lang.r_lang_new
r_lang_new.restype = ctypes.POINTER(struct_r_lang_t)
r_lang_new.argtypes = []
r_lang_free = _libr_lang.r_lang_free
r_lang_free.restype = None
r_lang_free.argtypes = [ctypes.POINTER(struct_r_lang_t)]
r_lang_setup = _libr_lang.r_lang_setup
r_lang_setup.restype = ctypes.c_bool
r_lang_setup.argtypes = [ctypes.POINTER(struct_r_lang_t)]
r_lang_add = _libr_lang.r_lang_add
r_lang_add.restype = ctypes.c_bool
r_lang_add.argtypes = [ctypes.POINTER(struct_r_lang_t), ctypes.POINTER(struct_r_lang_plugin_t)]
r_lang_list = _libr_lang.r_lang_list
r_lang_list.restype = ctypes.c_bool
r_lang_list.argtypes = [ctypes.POINTER(struct_r_lang_t)]
r_lang_use = _libr_lang.r_lang_use
r_lang_use.restype = ctypes.c_bool
r_lang_use.argtypes = [ctypes.POINTER(struct_r_lang_t), ctypes.POINTER(ctypes.c_char)]
r_lang_run = _libr_lang.r_lang_run
r_lang_run.restype = ctypes.c_bool
r_lang_run.argtypes = [ctypes.POINTER(struct_r_lang_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_lang_run_string = _libr_lang.r_lang_run_string
r_lang_run_string.restype = ctypes.c_bool
r_lang_run_string.argtypes = [ctypes.POINTER(struct_r_lang_t), ctypes.POINTER(ctypes.c_char)]
r_lang_set_user_ptr = _libr_lang.r_lang_set_user_ptr
r_lang_set_user_ptr.restype = None
r_lang_set_user_ptr.argtypes = [ctypes.POINTER(struct_r_lang_t), ctypes.POINTER(None)]
r_lang_set_argv = _libr_lang.r_lang_set_argv
r_lang_set_argv.restype = ctypes.c_bool
r_lang_set_argv.argtypes = [ctypes.POINTER(struct_r_lang_t), ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
r_lang_run_file = _libr_lang.r_lang_run_file
r_lang_run_file.restype = ctypes.c_bool
r_lang_run_file.argtypes = [ctypes.POINTER(struct_r_lang_t), ctypes.POINTER(ctypes.c_char)]
r_lang_prompt = _libr_lang.r_lang_prompt
r_lang_prompt.restype = ctypes.c_bool
r_lang_prompt.argtypes = [ctypes.POINTER(struct_r_lang_t)]
r_lang_plugin_free = _libr_lang.r_lang_plugin_free
r_lang_plugin_free.restype = None
r_lang_plugin_free.argtypes = [ctypes.POINTER(struct_r_lang_plugin_t)]
r_lang_get_by_name = _libr_lang.r_lang_get_by_name
r_lang_get_by_name.restype = ctypes.POINTER(struct_r_lang_plugin_t)
r_lang_get_by_name.argtypes = [ctypes.POINTER(struct_r_lang_t), ctypes.POINTER(ctypes.c_char)]
r_lang_get_by_extension = _libr_lang.r_lang_get_by_extension
r_lang_get_by_extension.restype = ctypes.POINTER(struct_r_lang_plugin_t)
r_lang_get_by_extension.argtypes = [ctypes.POINTER(struct_r_lang_t), ctypes.POINTER(ctypes.c_char)]
r_lang_define = _libr_lang.r_lang_define
r_lang_define.restype = ctypes.c_bool
r_lang_define.argtypes = [ctypes.POINTER(struct_r_lang_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None)]
r_lang_undef = _libr_lang.r_lang_undef
r_lang_undef.restype = None
r_lang_undef.argtypes = [ctypes.POINTER(struct_r_lang_t), ctypes.POINTER(ctypes.c_char)]
r_lang_def_free = _libr_lang.r_lang_def_free
r_lang_def_free.restype = None
r_lang_def_free.argtypes = [ctypes.POINTER(struct_r_lang_def_t)]
__all__ = \
    ['RCoreCmdStrCallback', 'RCoreCmdfCallback', 'RLang', 'RLangDef',
    'RLangPlugin', 'r_lang_add', 'r_lang_def_free', 'r_lang_define',
    'r_lang_free', 'r_lang_get_by_extension', 'r_lang_get_by_name',
    'r_lang_list', 'r_lang_new', 'r_lang_plugin_free',
    'r_lang_prompt', 'r_lang_run', 'r_lang_run_file',
    'r_lang_run_string', 'r_lang_set_argv', 'r_lang_set_user_ptr',
    'r_lang_setup', 'r_lang_undef', 'r_lang_use', 'r_lang_version',
    'struct_r_lang_def_t', 'struct_r_lang_plugin_t',
    'struct_r_lang_t', 'struct_r_list_iter_t', 'struct_r_list_t']
