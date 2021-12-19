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



class FunctionFactoryStub:
    def __getattr__(self, _):
      return ctypes.CFUNCTYPE(lambda y:y)

# libraries['FIXME_STUB'] explanation
# As you did not list (-l libraryname.so) a library that exports this function
# This is a non-working stub instead. 
# You can either re-run clan2py with -l /path/to/library.so
# Or manually fix this by comment the ctypes.CDLL loading
_libraries['FIXME_STUB'] = FunctionFactoryStub() #  ctypes.CDLL('FIXME_STUB')


r_cons_version = _libr_cons.r_cons_version
r_cons_version.restype = ctypes.POINTER(ctypes.c_char)
r_cons_version.argtypes = []
RConsGetSize = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_int32))
RConsGetCursor = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_int32))
RConsIsBreaked = ctypes.CFUNCTYPE(ctypes.c_bool)
RConsFlush = ctypes.CFUNCTYPE(None)
RConsGrepCallback = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_char))
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

RConsBind = struct_r_cons_bind_t
class struct_r_cons_grep_t(Structure):
    pass

struct_r_cons_grep_t._pack_ = 1 # source:False
struct_r_cons_grep_t._fields_ = [
    ('strings', ctypes.c_char * 64 * 10),
    ('nstrings', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('str', ctypes.POINTER(ctypes.c_char)),
    ('counter', ctypes.c_int32),
    ('charCounter', ctypes.c_bool),
    ('PADDING_1', ctypes.c_ubyte * 3),
    ('less', ctypes.c_int32),
    ('hud', ctypes.c_bool),
    ('human', ctypes.c_bool),
    ('PADDING_2', ctypes.c_ubyte * 2),
    ('json', ctypes.c_int32),
    ('PADDING_3', ctypes.c_ubyte * 4),
    ('json_path', ctypes.POINTER(ctypes.c_char)),
    ('range_line', ctypes.c_int32),
    ('line', ctypes.c_int32),
    ('sort', ctypes.c_int32),
    ('sort_row', ctypes.c_int32),
    ('sort_invert', ctypes.c_bool),
    ('PADDING_4', ctypes.c_ubyte * 3),
    ('f_line', ctypes.c_int32),
    ('l_line', ctypes.c_int32),
    ('tokens', ctypes.c_int32 * 64),
    ('tokens_used', ctypes.c_int32),
    ('amp', ctypes.c_int32),
    ('zoom', ctypes.c_int32),
    ('zoomy', ctypes.c_int32),
    ('neg', ctypes.c_int32),
    ('begin', ctypes.c_int32),
    ('end', ctypes.c_int32),
    ('icase', ctypes.c_bool),
    ('ascart', ctypes.c_bool),
    ('PADDING_5', ctypes.c_ubyte * 6),
]

RConsGrep = struct_r_cons_grep_t

# values for enumeration 'c__Ea_ALPHA_RESET'
c__Ea_ALPHA_RESET__enumvalues = {
    0: 'ALPHA_RESET',
    1: 'ALPHA_FG',
    2: 'ALPHA_BG',
    3: 'ALPHA_FGBG',
}
ALPHA_RESET = 0
ALPHA_FG = 1
ALPHA_BG = 2
ALPHA_FGBG = 3
c__Ea_ALPHA_RESET = ctypes.c_uint32 # enum

# values for enumeration 'c__Ea_R_CONS_ATTR_BOLD'
c__Ea_R_CONS_ATTR_BOLD__enumvalues = {
    2: 'R_CONS_ATTR_BOLD',
    4: 'R_CONS_ATTR_DIM',
    8: 'R_CONS_ATTR_ITALIC',
    16: 'R_CONS_ATTR_UNDERLINE',
    32: 'R_CONS_ATTR_BLINK',
}
R_CONS_ATTR_BOLD = 2
R_CONS_ATTR_DIM = 4
R_CONS_ATTR_ITALIC = 8
R_CONS_ATTR_UNDERLINE = 16
R_CONS_ATTR_BLINK = 32
c__Ea_R_CONS_ATTR_BOLD = ctypes.c_uint32 # enum
class struct_rcolor_t(Structure):
    pass

struct_rcolor_t._pack_ = 1 # source:False
struct_rcolor_t._fields_ = [
    ('attr', ctypes.c_ubyte),
    ('a', ctypes.c_ubyte),
    ('r', ctypes.c_ubyte),
    ('g', ctypes.c_ubyte),
    ('b', ctypes.c_ubyte),
    ('r2', ctypes.c_ubyte),
    ('g2', ctypes.c_ubyte),
    ('b2', ctypes.c_ubyte),
    ('id16', ctypes.c_byte),
]

RColor = struct_rcolor_t
class struct_r_cons_palette_t(Structure):
    _pack_ = 1 # source:False
    _fields_ = [
    ('b0x00', RColor),
    ('b0x7f', RColor),
    ('b0xff', RColor),
    ('args', RColor),
    ('bin', RColor),
    ('btext', RColor),
    ('call', RColor),
    ('cjmp', RColor),
    ('cmp', RColor),
    ('comment', RColor),
    ('usercomment', RColor),
    ('creg', RColor),
    ('flag', RColor),
    ('fline', RColor),
    ('floc', RColor),
    ('flow', RColor),
    ('flow2', RColor),
    ('fname', RColor),
    ('help', RColor),
    ('input', RColor),
    ('invalid', RColor),
    ('jmp', RColor),
    ('label', RColor),
    ('math', RColor),
    ('mov', RColor),
    ('nop', RColor),
    ('num', RColor),
    ('offset', RColor),
    ('other', RColor),
    ('pop', RColor),
    ('prompt', RColor),
    ('push', RColor),
    ('crypto', RColor),
    ('reg', RColor),
    ('reset', RColor),
    ('ret', RColor),
    ('swi', RColor),
    ('trap', RColor),
    ('ucall', RColor),
    ('ujmp', RColor),
    ('ai_read', RColor),
    ('ai_write', RColor),
    ('ai_exec', RColor),
    ('ai_seq', RColor),
    ('ai_ascii', RColor),
    ('gui_cflow', RColor),
    ('gui_dataoffset', RColor),
    ('gui_background', RColor),
    ('gui_alt_background', RColor),
    ('gui_border', RColor),
    ('wordhl', RColor),
    ('linehl', RColor),
    ('func_var', RColor),
    ('func_var_type', RColor),
    ('func_var_addr', RColor),
    ('widget_bg', RColor),
    ('widget_sel', RColor),
    ('graph_box', RColor),
    ('graph_box2', RColor),
    ('graph_box3', RColor),
    ('graph_box4', RColor),
    ('graph_true', RColor),
    ('graph_false', RColor),
    ('graph_trufae', RColor),
    ('graph_traced', RColor),
    ('graph_current', RColor),
    ('graph_diff_match', RColor),
    ('graph_diff_unmatch', RColor),
    ('graph_diff_unknown', RColor),
    ('graph_diff_new', RColor),
     ]

RConsPalette = struct_r_cons_palette_t
class struct_r_cons_printable_palette_t(Structure):
    pass

struct_r_cons_printable_palette_t._pack_ = 1 # source:False
struct_r_cons_printable_palette_t._fields_ = [
    ('b0x00', ctypes.POINTER(ctypes.c_char)),
    ('b0x7f', ctypes.POINTER(ctypes.c_char)),
    ('b0xff', ctypes.POINTER(ctypes.c_char)),
    ('args', ctypes.POINTER(ctypes.c_char)),
    ('bin', ctypes.POINTER(ctypes.c_char)),
    ('btext', ctypes.POINTER(ctypes.c_char)),
    ('call', ctypes.POINTER(ctypes.c_char)),
    ('cjmp', ctypes.POINTER(ctypes.c_char)),
    ('cmp', ctypes.POINTER(ctypes.c_char)),
    ('comment', ctypes.POINTER(ctypes.c_char)),
    ('usercomment', ctypes.POINTER(ctypes.c_char)),
    ('creg', ctypes.POINTER(ctypes.c_char)),
    ('flag', ctypes.POINTER(ctypes.c_char)),
    ('fline', ctypes.POINTER(ctypes.c_char)),
    ('floc', ctypes.POINTER(ctypes.c_char)),
    ('flow', ctypes.POINTER(ctypes.c_char)),
    ('flow2', ctypes.POINTER(ctypes.c_char)),
    ('fname', ctypes.POINTER(ctypes.c_char)),
    ('help', ctypes.POINTER(ctypes.c_char)),
    ('input', ctypes.POINTER(ctypes.c_char)),
    ('invalid', ctypes.POINTER(ctypes.c_char)),
    ('jmp', ctypes.POINTER(ctypes.c_char)),
    ('label', ctypes.POINTER(ctypes.c_char)),
    ('math', ctypes.POINTER(ctypes.c_char)),
    ('mov', ctypes.POINTER(ctypes.c_char)),
    ('nop', ctypes.POINTER(ctypes.c_char)),
    ('num', ctypes.POINTER(ctypes.c_char)),
    ('offset', ctypes.POINTER(ctypes.c_char)),
    ('other', ctypes.POINTER(ctypes.c_char)),
    ('pop', ctypes.POINTER(ctypes.c_char)),
    ('prompt', ctypes.POINTER(ctypes.c_char)),
    ('push', ctypes.POINTER(ctypes.c_char)),
    ('crypto', ctypes.POINTER(ctypes.c_char)),
    ('reg', ctypes.POINTER(ctypes.c_char)),
    ('reset', ctypes.POINTER(ctypes.c_char)),
    ('ret', ctypes.POINTER(ctypes.c_char)),
    ('swi', ctypes.POINTER(ctypes.c_char)),
    ('trap', ctypes.POINTER(ctypes.c_char)),
    ('ucall', ctypes.POINTER(ctypes.c_char)),
    ('ujmp', ctypes.POINTER(ctypes.c_char)),
    ('ai_read', ctypes.POINTER(ctypes.c_char)),
    ('ai_write', ctypes.POINTER(ctypes.c_char)),
    ('ai_exec', ctypes.POINTER(ctypes.c_char)),
    ('ai_seq', ctypes.POINTER(ctypes.c_char)),
    ('ai_ascii', ctypes.POINTER(ctypes.c_char)),
    ('ai_unmap', ctypes.POINTER(ctypes.c_char)),
    ('gui_cflow', ctypes.POINTER(ctypes.c_char)),
    ('gui_dataoffset', ctypes.POINTER(ctypes.c_char)),
    ('gui_background', ctypes.POINTER(ctypes.c_char)),
    ('gui_alt_background', ctypes.POINTER(ctypes.c_char)),
    ('gui_border', ctypes.POINTER(ctypes.c_char)),
    ('wordhl', ctypes.POINTER(ctypes.c_char)),
    ('linehl', ctypes.POINTER(ctypes.c_char)),
    ('func_var', ctypes.POINTER(ctypes.c_char)),
    ('func_var_type', ctypes.POINTER(ctypes.c_char)),
    ('func_var_addr', ctypes.POINTER(ctypes.c_char)),
    ('widget_bg', ctypes.POINTER(ctypes.c_char)),
    ('widget_sel', ctypes.POINTER(ctypes.c_char)),
    ('graph_box', ctypes.POINTER(ctypes.c_char)),
    ('graph_box2', ctypes.POINTER(ctypes.c_char)),
    ('graph_box3', ctypes.POINTER(ctypes.c_char)),
    ('graph_box4', ctypes.POINTER(ctypes.c_char)),
    ('graph_diff_match', ctypes.POINTER(ctypes.c_char)),
    ('graph_diff_unmatch', ctypes.POINTER(ctypes.c_char)),
    ('graph_diff_unknown', ctypes.POINTER(ctypes.c_char)),
    ('graph_diff_new', ctypes.POINTER(ctypes.c_char)),
    ('graph_true', ctypes.POINTER(ctypes.c_char)),
    ('graph_false', ctypes.POINTER(ctypes.c_char)),
    ('graph_trufae', ctypes.POINTER(ctypes.c_char)),
    ('graph_traced', ctypes.POINTER(ctypes.c_char)),
    ('graph_current', ctypes.POINTER(ctypes.c_char)),
    ('rainbow', ctypes.POINTER(ctypes.POINTER(ctypes.c_char))),
    ('rainbow_sz', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

RConsPrintablePalette = struct_r_cons_printable_palette_t
RConsEvent = ctypes.CFUNCTYPE(None, ctypes.POINTER(None))
class struct_r_cons_canvas_t(Structure):
    pass

class struct_ht_up_t(Structure):
    pass

class struct_r_str_constpool_t(Structure):
    pass

class struct_ht_pp_t(Structure):
    pass

struct_r_str_constpool_t._pack_ = 1 # source:False
struct_r_str_constpool_t._fields_ = [
    ('ht', ctypes.POINTER(struct_ht_pp_t)),
]

struct_r_cons_canvas_t._pack_ = 1 # source:False
struct_r_cons_canvas_t._fields_ = [
    ('w', ctypes.c_int32),
    ('h', ctypes.c_int32),
    ('x', ctypes.c_int32),
    ('y', ctypes.c_int32),
    ('b', ctypes.POINTER(ctypes.POINTER(ctypes.c_char))),
    ('blen', ctypes.POINTER(ctypes.c_int32)),
    ('bsize', ctypes.POINTER(ctypes.c_int32)),
    ('attr', ctypes.POINTER(ctypes.c_char)),
    ('attrs', ctypes.POINTER(struct_ht_up_t)),
    ('constpool', struct_r_str_constpool_t),
    ('sx', ctypes.c_int32),
    ('sy', ctypes.c_int32),
    ('color', ctypes.c_int32),
    ('linemode', ctypes.c_int32),
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

RConsCanvas = struct_r_cons_canvas_t
RConsEditorCallback = ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char))
RConsClickCallback = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.c_int32, ctypes.c_int32)
RConsBreakCallback = ctypes.CFUNCTYPE(None, ctypes.POINTER(None))
RConsSleepBeginCallback = ctypes.CFUNCTYPE(ctypes.POINTER(None), ctypes.POINTER(None))
RConsSleepEndCallback = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(None))
RConsQueueTaskOneshot = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None))
RConsFunctionKey = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.c_int32)

# values for enumeration 'c__EA_RConsColorMode'
c__EA_RConsColorMode__enumvalues = {
    0: 'COLOR_MODE_DISABLED',
    1: 'COLOR_MODE_16',
    2: 'COLOR_MODE_256',
    3: 'COLOR_MODE_16M',
}
COLOR_MODE_DISABLED = 0
COLOR_MODE_16 = 1
COLOR_MODE_256 = 2
COLOR_MODE_16M = 3
c__EA_RConsColorMode = ctypes.c_uint32 # enum
RConsColorMode = c__EA_RConsColorMode
RConsColorMode__enumvalues = c__EA_RConsColorMode__enumvalues
class struct_r_cons_context_t(Structure):
    pass

class struct_r_stack_t(Structure):
    pass

class struct_r_list_t(Structure):
    pass

class struct_c__SA_RStrBuf(Structure):
    pass


# values for enumeration 'r_log_level'
r_log_level__enumvalues = {
    0: 'R_LOGLVL_SILLY',
    1: 'R_LOGLVL_DEBUG',
    2: 'R_LOGLVL_VERBOSE',
    3: 'R_LOGLVL_INFO',
    4: 'R_LOGLVL_WARN',
    5: 'R_LOGLVL_ERROR',
    6: 'R_LOGLVL_FATAL',
    255: 'R_LOGLVL_NONE',
}
R_LOGLVL_SILLY = 0
R_LOGLVL_DEBUG = 1
R_LOGLVL_VERBOSE = 2
R_LOGLVL_INFO = 3
R_LOGLVL_WARN = 4
R_LOGLVL_ERROR = 5
R_LOGLVL_FATAL = 6
R_LOGLVL_NONE = 255
r_log_level = ctypes.c_uint32 # enum
struct_r_cons_context_t._pack_ = 1 # source:False
struct_r_cons_context_t._fields_ = [
    ('grep', RConsGrep),
    ('cons_stack', ctypes.POINTER(struct_r_stack_t)),
    ('buffer', ctypes.POINTER(ctypes.c_char)),
    ('buffer_len', ctypes.c_uint64),
    ('buffer_sz', ctypes.c_uint64),
    ('error', ctypes.POINTER(struct_c__SA_RStrBuf)),
    ('errmode', ctypes.c_int32),
    ('breaked', ctypes.c_bool),
    ('was_breaked', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 2),
    ('break_stack', ctypes.POINTER(struct_r_stack_t)),
    ('event_interrupt', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
    ('event_interrupt_data', ctypes.POINTER(None)),
    ('cmd_depth', ctypes.c_int32),
    ('cmd_str_depth', ctypes.c_int32),
    ('noflush', ctypes.c_bool),
    ('PADDING_1', ctypes.c_ubyte * 7),
    ('log_callback', ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_uint32, r_log_level, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char))),
    ('lastOutput', ctypes.POINTER(ctypes.c_char)),
    ('lastLength', ctypes.c_int32),
    ('lastMode', ctypes.c_bool),
    ('lastEnabled', ctypes.c_bool),
    ('is_interactive', ctypes.c_bool),
    ('pageable', ctypes.c_bool),
    ('color_mode', ctypes.c_int32),
    ('cpal', RConsPalette),
    ('PADDING_2', ctypes.c_ubyte * 6),
    ('pal', RConsPrintablePalette),
    ('sorted_lines', ctypes.POINTER(struct_r_list_t)),
    ('unsorted_lines', ctypes.POINTER(struct_r_list_t)),
    ('sorted_column', ctypes.c_int32),
    ('demo', ctypes.c_bool),
    ('is_html', ctypes.c_bool),
    ('was_html', ctypes.c_bool),
    ('grep_color', ctypes.c_bool),
    ('grep_highlight', ctypes.c_bool),
    ('filter', ctypes.c_bool),
    ('use_tts', ctypes.c_bool),
    ('flush', ctypes.c_bool),
    ('PADDING_3', ctypes.c_ubyte * 4),
]

struct_r_stack_t._pack_ = 1 # source:False
struct_r_stack_t._fields_ = [
    ('elems', ctypes.POINTER(ctypes.POINTER(None))),
    ('n_elems', ctypes.c_uint32),
    ('top', ctypes.c_int32),
    ('free', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
]

struct_c__SA_RStrBuf._pack_ = 1 # source:False
struct_c__SA_RStrBuf._fields_ = [
    ('buf', ctypes.c_char * 32),
    ('len', ctypes.c_uint64),
    ('ptr', ctypes.POINTER(ctypes.c_char)),
    ('ptrlen', ctypes.c_uint64),
    ('weakref', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
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

RConsContext = struct_r_cons_context_t
class struct_c__SA_RConsCursorPos(Structure):
    pass

struct_c__SA_RConsCursorPos._pack_ = 1 # source:False
struct_c__SA_RConsCursorPos._fields_ = [
    ('x', ctypes.c_int32),
    ('y', ctypes.c_int32),
]

RConsCursorPos = struct_c__SA_RConsCursorPos
class struct_r_cons_t(Structure):
    pass

class struct_r_num_t(Structure):
    pass

class struct_r_line_t(Structure):
    pass

class struct__IO_FILE(Structure):
    pass

class struct_termios(Structure):
    pass

struct_termios._pack_ = 1 # source:False
struct_termios._fields_ = [
    ('c_iflag', ctypes.c_uint32),
    ('c_oflag', ctypes.c_uint32),
    ('c_cflag', ctypes.c_uint32),
    ('c_lflag', ctypes.c_uint32),
    ('c_line', ctypes.c_ubyte),
    ('c_cc', ctypes.c_ubyte * 32),
    ('PADDING_0', ctypes.c_ubyte * 3),
    ('c_ispeed', ctypes.c_uint32),
    ('c_ospeed', ctypes.c_uint32),
]

struct_r_cons_t._pack_ = 1 # source:False
struct_r_cons_t._fields_ = [
    ('context', ctypes.POINTER(struct_r_cons_context_t)),
    ('lastline', ctypes.POINTER(ctypes.c_char)),
    ('lines', ctypes.c_int32),
    ('rows', ctypes.c_int32),
    ('echo', ctypes.c_int32),
    ('fps', ctypes.c_int32),
    ('columns', ctypes.c_int32),
    ('force_rows', ctypes.c_int32),
    ('force_columns', ctypes.c_int32),
    ('fix_rows', ctypes.c_int32),
    ('fix_columns', ctypes.c_int32),
    ('break_lines', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 3),
    ('optimize', ctypes.c_int32),
    ('show_autocomplete_widget', ctypes.c_bool),
    ('PADDING_1', ctypes.c_ubyte * 3),
    ('fdin', ctypes.POINTER(struct__IO_FILE)),
    ('fdout', ctypes.c_int32),
    ('PADDING_2', ctypes.c_ubyte * 4),
    ('teefile', ctypes.POINTER(ctypes.c_char)),
    ('user_fgets', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.c_int32)),
    ('event_resize', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
    ('event_data', ctypes.POINTER(None)),
    ('mouse_event', ctypes.c_int32),
    ('PADDING_3', ctypes.c_ubyte * 4),
    ('cb_editor', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char))),
    ('cb_break', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
    ('cb_sleep_begin', ctypes.CFUNCTYPE(ctypes.POINTER(None), ctypes.POINTER(None))),
    ('cb_sleep_end', ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(None))),
    ('cb_click', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.c_int32, ctypes.c_int32)),
    ('cb_task_oneshot', ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None))),
    ('cb_fkey', ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.c_int32)),
    ('user', ctypes.POINTER(None)),
    ('term_raw', struct_termios),
    ('term_buf', struct_termios),
    ('num', ctypes.POINTER(struct_r_num_t)),
    ('pager', ctypes.POINTER(ctypes.c_char)),
    ('blankline', ctypes.c_int32),
    ('PADDING_4', ctypes.c_ubyte * 4),
    ('highlight', ctypes.POINTER(ctypes.c_char)),
    ('enable_highlight', ctypes.c_bool),
    ('PADDING_5', ctypes.c_ubyte * 3),
    ('null', ctypes.c_int32),
    ('mouse', ctypes.c_int32),
    ('is_wine', ctypes.c_int32),
    ('line', ctypes.POINTER(struct_r_line_t)),
    ('vline', ctypes.POINTER(ctypes.POINTER(ctypes.c_char))),
    ('refcnt', ctypes.c_int32),
    ('newline', ctypes.c_bool),
    ('PADDING_6', ctypes.c_ubyte * 3),
    ('vtmode', ctypes.c_int32),
    ('use_utf8', ctypes.c_bool),
    ('use_utf8_curvy', ctypes.c_bool),
    ('dotted_lines', ctypes.c_bool),
    ('PADDING_7', ctypes.c_ubyte),
    ('linesleep', ctypes.c_int32),
    ('pagesize', ctypes.c_int32),
    ('break_word', ctypes.POINTER(ctypes.c_char)),
    ('break_word_len', ctypes.c_int32),
    ('PADDING_8', ctypes.c_ubyte * 4),
    ('timeout', ctypes.c_uint64),
    ('rgbstr', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64, ctypes.c_uint64)),
    ('click_set', ctypes.c_bool),
    ('PADDING_9', ctypes.c_ubyte * 3),
    ('click_x', ctypes.c_int32),
    ('click_y', ctypes.c_int32),
    ('show_vals', ctypes.c_bool),
    ('PADDING_10', ctypes.c_ubyte * 3),
    ('cpos', RConsCursorPos),
]

class struct__IO_wide_data(Structure):
    pass

class struct__IO_codecvt(Structure):
    pass

class struct__IO_marker(Structure):
    pass

struct__IO_FILE._pack_ = 1 # source:False
struct__IO_FILE._fields_ = [
    ('_flags', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('_IO_read_ptr', ctypes.POINTER(ctypes.c_char)),
    ('_IO_read_end', ctypes.POINTER(ctypes.c_char)),
    ('_IO_read_base', ctypes.POINTER(ctypes.c_char)),
    ('_IO_write_base', ctypes.POINTER(ctypes.c_char)),
    ('_IO_write_ptr', ctypes.POINTER(ctypes.c_char)),
    ('_IO_write_end', ctypes.POINTER(ctypes.c_char)),
    ('_IO_buf_base', ctypes.POINTER(ctypes.c_char)),
    ('_IO_buf_end', ctypes.POINTER(ctypes.c_char)),
    ('_IO_save_base', ctypes.POINTER(ctypes.c_char)),
    ('_IO_backup_base', ctypes.POINTER(ctypes.c_char)),
    ('_IO_save_end', ctypes.POINTER(ctypes.c_char)),
    ('_markers', ctypes.POINTER(struct__IO_marker)),
    ('_chain', ctypes.POINTER(struct__IO_FILE)),
    ('_fileno', ctypes.c_int32),
    ('_flags2', ctypes.c_int32),
    ('_old_offset', ctypes.c_int64),
    ('_cur_column', ctypes.c_uint16),
    ('_vtable_offset', ctypes.c_byte),
    ('_shortbuf', ctypes.c_char * 1),
    ('PADDING_1', ctypes.c_ubyte * 4),
    ('_lock', ctypes.POINTER(None)),
    ('_offset', ctypes.c_int64),
    ('_codecvt', ctypes.POINTER(struct__IO_codecvt)),
    ('_wide_data', ctypes.POINTER(struct__IO_wide_data)),
    ('_freeres_list', ctypes.POINTER(struct__IO_FILE)),
    ('_freeres_buf', ctypes.POINTER(None)),
    ('__pad5', ctypes.c_uint64),
    ('_mode', ctypes.c_int32),
    ('_unused2', ctypes.c_char * 20),
]

class struct_r_num_calc_t(Structure):
    pass

class struct_c__SA_RNumCalcValue(Structure):
    pass

struct_c__SA_RNumCalcValue._pack_ = 1 # source:False
struct_c__SA_RNumCalcValue._fields_ = [
    ('d', ctypes.c_double),
    ('n', ctypes.c_uint64),
]


# values for enumeration 'c__EA_RNumCalcToken'
c__EA_RNumCalcToken__enumvalues = {
    0: 'RNCNAME',
    1: 'RNCNUMBER',
    2: 'RNCEND',
    3: 'RNCINC',
    4: 'RNCDEC',
    5: 'RNCLT',
    6: 'RNCGT',
    43: 'RNCPLUS',
    45: 'RNCMINUS',
    42: 'RNCMUL',
    47: 'RNCDIV',
    37: 'RNCMOD',
    126: 'RNCNEG',
    38: 'RNCAND',
    124: 'RNCOR',
    94: 'RNCXOR',
    59: 'RNCPRINT',
    61: 'RNCASSIGN',
    40: 'RNCLEFTP',
    41: 'RNCRIGHTP',
    60: 'RNCSHL',
    62: 'RNCSHR',
    35: 'RNCROL',
    36: 'RNCROR',
}
RNCNAME = 0
RNCNUMBER = 1
RNCEND = 2
RNCINC = 3
RNCDEC = 4
RNCLT = 5
RNCGT = 6
RNCPLUS = 43
RNCMINUS = 45
RNCMUL = 42
RNCDIV = 47
RNCMOD = 37
RNCNEG = 126
RNCAND = 38
RNCOR = 124
RNCXOR = 94
RNCPRINT = 59
RNCASSIGN = 61
RNCLEFTP = 40
RNCRIGHTP = 41
RNCSHL = 60
RNCSHR = 62
RNCROL = 35
RNCROR = 36
c__EA_RNumCalcToken = ctypes.c_uint32 # enum
struct_r_num_calc_t._pack_ = 1 # source:False
struct_r_num_calc_t._fields_ = [
    ('curr_tok', c__EA_RNumCalcToken),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('number_value', struct_c__SA_RNumCalcValue),
    ('string_value', ctypes.c_char * 1024),
    ('errors', ctypes.c_int32),
    ('oc', ctypes.c_char),
    ('PADDING_1', ctypes.c_ubyte * 3),
    ('calc_err', ctypes.POINTER(ctypes.c_char)),
    ('calc_i', ctypes.c_int32),
    ('PADDING_2', ctypes.c_ubyte * 4),
    ('calc_buf', ctypes.POINTER(ctypes.c_char)),
    ('calc_len', ctypes.c_int32),
    ('under_calc', ctypes.c_bool),
    ('PADDING_3', ctypes.c_ubyte * 3),
]

struct_r_num_t._pack_ = 1 # source:False
struct_r_num_t._fields_ = [
    ('callback', ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(struct_r_num_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_int32))),
    ('cb_from_value', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_num_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_int32))),
    ('value', ctypes.c_uint64),
    ('fvalue', ctypes.c_double),
    ('userptr', ctypes.POINTER(None)),
    ('dbz', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('nc', struct_r_num_calc_t),
]

class struct_r_hud_t(Structure):
    pass

class struct_r_selection_widget_t(Structure):
    pass

class struct_r_line_hist_t(Structure):
    pass

struct_r_line_hist_t._pack_ = 1 # source:False
struct_r_line_hist_t._fields_ = [
    ('data', ctypes.POINTER(ctypes.POINTER(ctypes.c_char))),
    ('match', ctypes.POINTER(ctypes.c_char)),
    ('size', ctypes.c_int32),
    ('index', ctypes.c_int32),
    ('top', ctypes.c_int32),
    ('autosave', ctypes.c_int32),
    ('do_setup_match', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
]

class struct_r_line_comp_t(Structure):
    pass

class struct_r_line_buffer_t(Structure):
    pass


# values for enumeration 'c__EA_RLinePromptType'
c__EA_RLinePromptType__enumvalues = {
    0: 'R_LINE_PROMPT_DEFAULT',
    1: 'R_LINE_PROMPT_OFFSET',
    2: 'R_LINE_PROMPT_FILE',
}
R_LINE_PROMPT_DEFAULT = 0
R_LINE_PROMPT_OFFSET = 1
R_LINE_PROMPT_FILE = 2
c__EA_RLinePromptType = ctypes.c_uint32 # enum
class struct_r_pvector_t(Structure):
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

struct_r_pvector_t._pack_ = 1 # source:False
struct_r_pvector_t._fields_ = [
    ('v', struct_r_vector_t),
]

struct_r_line_comp_t._pack_ = 1 # source:False
struct_r_line_comp_t._fields_ = [
    ('opt', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
    ('args_limit', ctypes.c_uint64),
    ('quit', ctypes.c_bool),
    ('PADDING_1', ctypes.c_ubyte * 7),
    ('args', struct_r_pvector_t),
    ('run', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_line_comp_t), ctypes.POINTER(struct_r_line_buffer_t), c__EA_RLinePromptType, ctypes.POINTER(None))),
    ('run_user', ctypes.POINTER(None)),
]

struct_r_line_buffer_t._pack_ = 1 # source:False
struct_r_line_buffer_t._fields_ = [
    ('data', ctypes.c_char * 4096),
    ('index', ctypes.c_int32),
    ('length', ctypes.c_int32),
]

struct_r_line_t._pack_ = 1 # source:False
struct_r_line_t._fields_ = [
    ('completion', struct_r_line_comp_t),
    ('buffer', struct_r_line_buffer_t),
    ('history', struct_r_line_hist_t),
    ('sel_widget', ctypes.POINTER(struct_r_selection_widget_t)),
    ('cb_history_up', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_line_t))),
    ('cb_history_down', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_line_t))),
    ('cb_editor', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))),
    ('cb_fkey', ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.c_int32)),
    ('echo', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
    ('prompt', ctypes.POINTER(ctypes.c_char)),
    ('kill_ring', ctypes.POINTER(struct_r_list_t)),
    ('kill_ring_ptr', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
    ('clipboard', ctypes.POINTER(ctypes.c_char)),
    ('disable', ctypes.c_bool),
    ('PADDING_2', ctypes.c_ubyte * 7),
    ('user', ctypes.POINTER(None)),
    ('histfilter', ctypes.c_bool),
    ('PADDING_3', ctypes.c_ubyte * 7),
    ('hist_up', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None))),
    ('hist_down', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None))),
    ('contents', ctypes.POINTER(ctypes.c_char)),
    ('zerosep', ctypes.c_bool),
    ('enable_vi_mode', ctypes.c_bool),
    ('PADDING_4', ctypes.c_ubyte * 2),
    ('vi_mode', ctypes.c_int32),
    ('prompt_mode', ctypes.c_bool),
    ('PADDING_5', ctypes.c_ubyte * 3),
    ('prompt_type', c__EA_RLinePromptType),
    ('offset_hist_index', ctypes.c_int32),
    ('file_hist_index', ctypes.c_int32),
    ('hud', ctypes.POINTER(struct_r_hud_t)),
    ('sdbshell_hist', ctypes.POINTER(struct_r_list_t)),
    ('sdbshell_hist_iter', ctypes.POINTER(struct_r_list_iter_t)),
    ('vtmode', ctypes.c_int32),
    ('PADDING_6', ctypes.c_ubyte * 4),
]

struct_r_selection_widget_t._pack_ = 1 # source:False
struct_r_selection_widget_t._fields_ = [
    ('options', ctypes.POINTER(ctypes.POINTER(ctypes.c_char))),
    ('options_len', ctypes.c_int32),
    ('selection', ctypes.c_int32),
    ('w', ctypes.c_int32),
    ('h', ctypes.c_int32),
    ('scroll', ctypes.c_int32),
    ('complete_common', ctypes.c_bool),
    ('direction', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 2),
]

struct_r_hud_t._pack_ = 1 # source:False
struct_r_hud_t._fields_ = [
    ('current_entry_n', ctypes.c_int32),
    ('top_entry_n', ctypes.c_int32),
    ('activate', ctypes.c_char),
    ('PADDING_0', ctypes.c_ubyte * 3),
    ('vi', ctypes.c_int32),
]

RCons = struct_r_cons_t

# values for enumeration 'c__Ea_PAL_PROMPT'
c__Ea_PAL_PROMPT__enumvalues = {
    0: 'PAL_PROMPT',
    1: 'PAL_ADDRESS',
    2: 'PAL_DEFAULT',
    3: 'PAL_CHANGED',
    4: 'PAL_JUMP',
    5: 'PAL_CALL',
    6: 'PAL_PUSH',
    7: 'PAL_TRAP',
    8: 'PAL_CMP',
    9: 'PAL_RET',
    10: 'PAL_NOP',
    11: 'PAL_METADATA',
    12: 'PAL_HEADER',
    13: 'PAL_PRINTABLE',
    14: 'PAL_LINES0',
    15: 'PAL_LINES1',
    16: 'PAL_LINES2',
    17: 'PAL_00',
    18: 'PAL_7F',
    19: 'PAL_FF',
}
PAL_PROMPT = 0
PAL_ADDRESS = 1
PAL_DEFAULT = 2
PAL_CHANGED = 3
PAL_JUMP = 4
PAL_CALL = 5
PAL_PUSH = 6
PAL_TRAP = 7
PAL_CMP = 8
PAL_RET = 9
PAL_NOP = 10
PAL_METADATA = 11
PAL_HEADER = 12
PAL_PRINTABLE = 13
PAL_LINES0 = 14
PAL_LINES1 = 15
PAL_LINES2 = 16
PAL_00 = 17
PAL_7F = 18
PAL_FF = 19
c__Ea_PAL_PROMPT = ctypes.c_uint32 # enum

# values for enumeration 'c__Ea_LINE_NONE'
c__Ea_LINE_NONE__enumvalues = {
    0: 'LINE_NONE',
    1: 'LINE_TRUE',
    2: 'LINE_FALSE',
    3: 'LINE_UNCJMP',
    4: 'LINE_NOSYM_VERT',
    5: 'LINE_NOSYM_HORIZ',
}
LINE_NONE = 0
LINE_TRUE = 1
LINE_FALSE = 2
LINE_UNCJMP = 3
LINE_NOSYM_VERT = 4
LINE_NOSYM_HORIZ = 5
c__Ea_LINE_NONE = ctypes.c_uint32 # enum

# values for enumeration 'c__EA_RViMode'
c__EA_RViMode__enumvalues = {
    105: 'INSERT_MODE',
    99: 'CONTROL_MODE',
}
INSERT_MODE = 105
CONTROL_MODE = 99
c__EA_RViMode = ctypes.c_uint32 # enum
RViMode = c__EA_RViMode
RViMode__enumvalues = c__EA_RViMode__enumvalues
class struct_r_cons_canvas_line_style_t(Structure):
    pass

struct_r_cons_canvas_line_style_t._pack_ = 1 # source:False
struct_r_cons_canvas_line_style_t._fields_ = [
    ('color', ctypes.c_int32),
    ('symbol', ctypes.c_int32),
    ('dot_style', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('ansicolor', ctypes.POINTER(ctypes.c_char)),
]

RCanvasLineStyle = struct_r_cons_canvas_line_style_t
r_cons_image = _libr_cons.r_cons_image
r_cons_image.restype = None
r_cons_image.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
r_cons_canvas_new = _libr_cons.r_cons_canvas_new
r_cons_canvas_new.restype = ctypes.POINTER(struct_r_cons_canvas_t)
r_cons_canvas_new.argtypes = [ctypes.c_int32, ctypes.c_int32]
r_cons_canvas_free = _libr_cons.r_cons_canvas_free
r_cons_canvas_free.restype = None
r_cons_canvas_free.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t)]
r_cons_canvas_clear = _libr_cons.r_cons_canvas_clear
r_cons_canvas_clear.restype = None
r_cons_canvas_clear.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t)]
r_cons_canvas_print = _libr_cons.r_cons_canvas_print
r_cons_canvas_print.restype = None
r_cons_canvas_print.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t)]
r_cons_canvas_print_region = _libr_cons.r_cons_canvas_print_region
r_cons_canvas_print_region.restype = None
r_cons_canvas_print_region.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t)]
r_cons_canvas_to_string = _libr_cons.r_cons_canvas_to_string
r_cons_canvas_to_string.restype = ctypes.POINTER(ctypes.c_char)
r_cons_canvas_to_string.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t)]
r_cons_canvas_attr = _libraries['FIXME_STUB'].r_cons_canvas_attr
r_cons_canvas_attr.restype = None
r_cons_canvas_attr.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t), ctypes.POINTER(ctypes.c_char)]
r_cons_canvas_write = _libr_cons.r_cons_canvas_write
r_cons_canvas_write.restype = None
r_cons_canvas_write.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t), ctypes.POINTER(ctypes.c_char)]
r_cons_canvas_gotoxy = _libr_cons.r_cons_canvas_gotoxy
r_cons_canvas_gotoxy.restype = ctypes.c_bool
r_cons_canvas_gotoxy.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t), ctypes.c_int32, ctypes.c_int32]
r_cons_canvas_goto_write = _libraries['FIXME_STUB'].r_cons_canvas_goto_write
r_cons_canvas_goto_write.restype = None
r_cons_canvas_goto_write.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t), ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
r_cons_canvas_box = _libr_cons.r_cons_canvas_box
r_cons_canvas_box.restype = None
r_cons_canvas_box.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
r_cons_canvas_circle = _libr_cons.r_cons_canvas_circle
r_cons_canvas_circle.restype = None
r_cons_canvas_circle.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
r_cons_canvas_line = _libr_cons.r_cons_canvas_line
r_cons_canvas_line.restype = None
r_cons_canvas_line.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(struct_r_cons_canvas_line_style_t)]
r_cons_canvas_line_diagonal = _libr_cons.r_cons_canvas_line_diagonal
r_cons_canvas_line_diagonal.restype = None
r_cons_canvas_line_diagonal.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(struct_r_cons_canvas_line_style_t)]
r_cons_canvas_line_square = _libr_cons.r_cons_canvas_line_square
r_cons_canvas_line_square.restype = None
r_cons_canvas_line_square.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(struct_r_cons_canvas_line_style_t)]
r_cons_canvas_resize = _libr_cons.r_cons_canvas_resize
r_cons_canvas_resize.restype = ctypes.c_int32
r_cons_canvas_resize.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t), ctypes.c_int32, ctypes.c_int32]
r_cons_canvas_fill = _libr_cons.r_cons_canvas_fill
r_cons_canvas_fill.restype = None
r_cons_canvas_fill.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_char]
r_cons_canvas_line_square_defined = _libr_cons.r_cons_canvas_line_square_defined
r_cons_canvas_line_square_defined.restype = None
r_cons_canvas_line_square_defined.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(struct_r_cons_canvas_line_style_t), ctypes.c_int32, ctypes.c_int32]
r_cons_canvas_line_back_edge = _libr_cons.r_cons_canvas_line_back_edge
r_cons_canvas_line_back_edge.restype = None
r_cons_canvas_line_back_edge.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(struct_r_cons_canvas_line_style_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
r_cons_new = _libr_cons.r_cons_new
r_cons_new.restype = ctypes.POINTER(struct_r_cons_t)
r_cons_new.argtypes = []
r_cons_singleton = _libr_cons.r_cons_singleton
r_cons_singleton.restype = ctypes.POINTER(struct_r_cons_t)
r_cons_singleton.argtypes = []
r_cons_context = _libr_cons.r_cons_context
r_cons_context.restype = ctypes.POINTER(struct_r_cons_context_t)
r_cons_context.argtypes = []
r_cons_free = _libr_cons.r_cons_free
r_cons_free.restype = ctypes.POINTER(struct_r_cons_t)
r_cons_free.argtypes = []
r_cons_lastline = _libr_cons.r_cons_lastline
r_cons_lastline.restype = ctypes.POINTER(ctypes.c_char)
r_cons_lastline.argtypes = [ctypes.POINTER(ctypes.c_int32)]
r_cons_lastline_utf8_ansi_len = _libr_cons.r_cons_lastline_utf8_ansi_len
r_cons_lastline_utf8_ansi_len.restype = ctypes.POINTER(ctypes.c_char)
r_cons_lastline_utf8_ansi_len.argtypes = [ctypes.POINTER(ctypes.c_int32)]
r_cons_set_click = _libr_cons.r_cons_set_click
r_cons_set_click.restype = None
r_cons_set_click.argtypes = [ctypes.c_int32, ctypes.c_int32]
r_cons_get_click = _libr_cons.r_cons_get_click
r_cons_get_click.restype = ctypes.c_bool
r_cons_get_click.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32)]
RConsBreak = ctypes.CFUNCTYPE(None, ctypes.POINTER(None))
r_cons_is_breaked = _libr_cons.r_cons_is_breaked
r_cons_is_breaked.restype = ctypes.c_bool
r_cons_is_breaked.argtypes = []
r_cons_was_breaked = _libr_cons.r_cons_was_breaked
r_cons_was_breaked.restype = ctypes.c_bool
r_cons_was_breaked.argtypes = []
r_cons_is_interactive = _libr_cons.r_cons_is_interactive
r_cons_is_interactive.restype = ctypes.c_bool
r_cons_is_interactive.argtypes = []
r_cons_default_context_is_interactive = _libr_cons.r_cons_default_context_is_interactive
r_cons_default_context_is_interactive.restype = ctypes.c_bool
r_cons_default_context_is_interactive.argtypes = []
r_cons_sleep_begin = _libr_cons.r_cons_sleep_begin
r_cons_sleep_begin.restype = ctypes.POINTER(None)
r_cons_sleep_begin.argtypes = []
r_cons_sleep_end = _libr_cons.r_cons_sleep_end
r_cons_sleep_end.restype = None
r_cons_sleep_end.argtypes = [ctypes.POINTER(None)]
r_cons_break_push = _libr_cons.r_cons_break_push
r_cons_break_push.restype = None
r_cons_break_push.argtypes = [RConsBreak, ctypes.POINTER(None)]
r_cons_break_pop = _libr_cons.r_cons_break_pop
r_cons_break_pop.restype = None
r_cons_break_pop.argtypes = []
r_cons_break_clear = _libr_cons.r_cons_break_clear
r_cons_break_clear.restype = None
r_cons_break_clear.argtypes = []
r_cons_breakword = _libr_cons.r_cons_breakword
r_cons_breakword.restype = None
r_cons_breakword.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_cons_break_end = _libr_cons.r_cons_break_end
r_cons_break_end.restype = None
r_cons_break_end.argtypes = []
r_cons_break_timeout = _libr_cons.r_cons_break_timeout
r_cons_break_timeout.restype = None
r_cons_break_timeout.argtypes = [ctypes.c_int32]
r_cons_pipe_open = _libr_cons.r_cons_pipe_open
r_cons_pipe_open.restype = ctypes.c_int32
r_cons_pipe_open.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32]
r_cons_pipe_close = _libr_cons.r_cons_pipe_close
r_cons_pipe_close.restype = None
r_cons_pipe_close.argtypes = [ctypes.c_int32]

# values for enumeration 'c__Ea_R_CONS_ERRMODE_NULL'
c__Ea_R_CONS_ERRMODE_NULL__enumvalues = {
    0: 'R_CONS_ERRMODE_NULL',
    1: 'R_CONS_ERRMODE_QUIET',
    2: 'R_CONS_ERRMODE_ECHO',
    3: 'R_CONS_ERRMODE_BUFFER',
    4: 'R_CONS_ERRMODE_FLUSH',
}
R_CONS_ERRMODE_NULL = 0
R_CONS_ERRMODE_QUIET = 1
R_CONS_ERRMODE_ECHO = 2
R_CONS_ERRMODE_BUFFER = 3
R_CONS_ERRMODE_FLUSH = 4
c__Ea_R_CONS_ERRMODE_NULL = ctypes.c_uint32 # enum
r_cons_push = _libr_cons.r_cons_push
r_cons_push.restype = None
r_cons_push.argtypes = []
r_cons_pop = _libr_cons.r_cons_pop
r_cons_pop.restype = None
r_cons_pop.argtypes = []
r_cons_context_new = _libr_cons.r_cons_context_new
r_cons_context_new.restype = ctypes.POINTER(struct_r_cons_context_t)
r_cons_context_new.argtypes = [ctypes.POINTER(struct_r_cons_context_t)]
r_cons_context_free = _libr_cons.r_cons_context_free
r_cons_context_free.restype = None
r_cons_context_free.argtypes = [ctypes.POINTER(struct_r_cons_context_t)]
r_cons_context_load = _libr_cons.r_cons_context_load
r_cons_context_load.restype = None
r_cons_context_load.argtypes = [ctypes.POINTER(struct_r_cons_context_t)]
r_cons_context_reset = _libr_cons.r_cons_context_reset
r_cons_context_reset.restype = None
r_cons_context_reset.argtypes = []
r_cons_context_is_main = _libr_cons.r_cons_context_is_main
r_cons_context_is_main.restype = ctypes.c_bool
r_cons_context_is_main.argtypes = []
r_cons_context_break = _libr_cons.r_cons_context_break
r_cons_context_break.restype = None
r_cons_context_break.argtypes = [ctypes.POINTER(struct_r_cons_context_t)]
r_cons_context_break_push = _libr_cons.r_cons_context_break_push
r_cons_context_break_push.restype = None
r_cons_context_break_push.argtypes = [ctypes.POINTER(struct_r_cons_context_t), RConsBreak, ctypes.POINTER(None), ctypes.c_bool]
r_cons_context_break_pop = _libr_cons.r_cons_context_break_pop
r_cons_context_break_pop.restype = None
r_cons_context_break_pop.argtypes = [ctypes.POINTER(struct_r_cons_context_t), ctypes.c_bool]
r_cons_editor = _libr_cons.r_cons_editor
r_cons_editor.restype = ctypes.POINTER(ctypes.c_char)
r_cons_editor.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_cons_reset = _libr_cons.r_cons_reset
r_cons_reset.restype = None
r_cons_reset.argtypes = []
r_cons_reset_colors = _libr_cons.r_cons_reset_colors
r_cons_reset_colors.restype = None
r_cons_reset_colors.argtypes = []
r_cons_errstr = _libr_cons.r_cons_errstr
r_cons_errstr.restype = ctypes.POINTER(ctypes.c_char)
r_cons_errstr.argtypes = []
r_cons_errmode = _libr_cons.r_cons_errmode
r_cons_errmode.restype = None
r_cons_errmode.argtypes = [ctypes.c_int32]
r_cons_errmodes = _libr_cons.r_cons_errmodes
r_cons_errmodes.restype = None
r_cons_errmodes.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_cons_eprintf = _libr_cons.r_cons_eprintf
r_cons_eprintf.restype = ctypes.c_int32
r_cons_eprintf.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_cons_eflush = _libr_cons.r_cons_eflush
r_cons_eflush.restype = None
r_cons_eflush.argtypes = []
r_cons_print_clear = _libr_cons.r_cons_print_clear
r_cons_print_clear.restype = None
r_cons_print_clear.argtypes = []
r_cons_echo = _libr_cons.r_cons_echo
r_cons_echo.restype = None
r_cons_echo.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_cons_zero = _libr_cons.r_cons_zero
r_cons_zero.restype = None
r_cons_zero.argtypes = []
r_cons_highlight = _libr_cons.r_cons_highlight
r_cons_highlight.restype = None
r_cons_highlight.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_cons_clear = _libr_cons.r_cons_clear
r_cons_clear.restype = None
r_cons_clear.argtypes = []
r_cons_clear_buffer = _libr_cons.r_cons_clear_buffer
r_cons_clear_buffer.restype = None
r_cons_clear_buffer.argtypes = []
r_cons_clear00 = _libr_cons.r_cons_clear00
r_cons_clear00.restype = None
r_cons_clear00.argtypes = []
r_cons_clear_line = _libr_cons.r_cons_clear_line
r_cons_clear_line.restype = None
r_cons_clear_line.argtypes = [ctypes.c_int32]
r_cons_fill_line = _libr_cons.r_cons_fill_line
r_cons_fill_line.restype = None
r_cons_fill_line.argtypes = []
r_cons_stdout_open = _libraries['FIXME_STUB'].r_cons_stdout_open
r_cons_stdout_open.restype = None
r_cons_stdout_open.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_cons_stdout_set_fd = _libraries['FIXME_STUB'].r_cons_stdout_set_fd
r_cons_stdout_set_fd.restype = ctypes.c_int32
r_cons_stdout_set_fd.argtypes = [ctypes.c_int32]
r_cons_gotoxy = _libr_cons.r_cons_gotoxy
r_cons_gotoxy.restype = None
r_cons_gotoxy.argtypes = [ctypes.c_int32, ctypes.c_int32]
r_cons_get_cur_line = _libr_cons.r_cons_get_cur_line
r_cons_get_cur_line.restype = ctypes.c_int32
r_cons_get_cur_line.argtypes = []
r_cons_line = _libr_cons.r_cons_line
r_cons_line.restype = None
r_cons_line.argtypes = [ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
r_cons_show_cursor = _libr_cons.r_cons_show_cursor
r_cons_show_cursor.restype = None
r_cons_show_cursor.argtypes = [ctypes.c_int32]
r_cons_swap_ground = _libr_cons.r_cons_swap_ground
r_cons_swap_ground.restype = ctypes.POINTER(ctypes.c_char)
r_cons_swap_ground.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_cons_drop = _libr_cons.r_cons_drop
r_cons_drop.restype = ctypes.c_bool
r_cons_drop.argtypes = [ctypes.c_int32]
r_cons_chop = _libr_cons.r_cons_chop
r_cons_chop.restype = None
r_cons_chop.argtypes = []
r_cons_set_raw = _libr_cons.r_cons_set_raw
r_cons_set_raw.restype = None
r_cons_set_raw.argtypes = [ctypes.c_bool]
r_cons_set_interactive = _libr_cons.r_cons_set_interactive
r_cons_set_interactive.restype = None
r_cons_set_interactive.argtypes = [ctypes.c_bool]
r_cons_set_last_interactive = _libr_cons.r_cons_set_last_interactive
r_cons_set_last_interactive.restype = None
r_cons_set_last_interactive.argtypes = []
r_cons_set_utf8 = _libr_cons.r_cons_set_utf8
r_cons_set_utf8.restype = None
r_cons_set_utf8.argtypes = [ctypes.c_bool]
r_cons_grep = _libr_cons.r_cons_grep
r_cons_grep.restype = None
r_cons_grep.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_cons_printf = _libr_cons.r_cons_printf
r_cons_printf.restype = ctypes.c_int32
r_cons_printf.argtypes = [ctypes.POINTER(ctypes.c_char)]
class struct___va_list_tag(Structure):
    pass

struct___va_list_tag._pack_ = 1 # source:False
struct___va_list_tag._fields_ = [
    ('gp_offset', ctypes.c_uint32),
    ('fp_offset', ctypes.c_uint32),
    ('overflow_arg_area', ctypes.POINTER(None)),
    ('reg_save_area', ctypes.POINTER(None)),
]

va_list = struct___va_list_tag * 1
r_cons_printf_list = _libr_cons.r_cons_printf_list
r_cons_printf_list.restype = None
r_cons_printf_list.argtypes = [ctypes.POINTER(ctypes.c_char), va_list]
r_cons_strcat = _libr_cons.r_cons_strcat
r_cons_strcat.restype = None
r_cons_strcat.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_cons_strcat_at = _libr_cons.r_cons_strcat_at
r_cons_strcat_at.restype = None
r_cons_strcat_at.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_char, ctypes.c_int32, ctypes.c_int32]
r_cons_println = _libr_cons.r_cons_println
r_cons_println.restype = None
r_cons_println.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_cons_strcat_justify = _libr_cons.r_cons_strcat_justify
r_cons_strcat_justify.restype = None
r_cons_strcat_justify.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_char]
r_cons_printat = _libr_cons.r_cons_printat
r_cons_printat.restype = None
r_cons_printat.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_char]
r_cons_write = _libr_cons.r_cons_write
r_cons_write.restype = ctypes.c_int32
r_cons_write.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_cons_newline = _libr_cons.r_cons_newline
r_cons_newline.restype = None
r_cons_newline.argtypes = []
r_cons_filter = _libr_cons.r_cons_filter
r_cons_filter.restype = None
r_cons_filter.argtypes = []
r_cons_flush = _libr_cons.r_cons_flush
r_cons_flush.restype = None
r_cons_flush.argtypes = []
r_cons_print_fps = _libr_cons.r_cons_print_fps
r_cons_print_fps.restype = None
r_cons_print_fps.argtypes = [ctypes.c_int32]
r_cons_last = _libr_cons.r_cons_last
r_cons_last.restype = None
r_cons_last.argtypes = []
r_cons_less_str = _libr_cons.r_cons_less_str
r_cons_less_str.restype = ctypes.c_int32
r_cons_less_str.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_cons_less = _libr_cons.r_cons_less
r_cons_less.restype = None
r_cons_less.argtypes = []
r_cons_2048 = _libr_cons.r_cons_2048
r_cons_2048.restype = None
r_cons_2048.argtypes = [ctypes.c_bool]
r_cons_memset = _libr_cons.r_cons_memset
r_cons_memset.restype = None
r_cons_memset.argtypes = [ctypes.c_char, ctypes.c_int32]
r_cons_visual_flush = _libr_cons.r_cons_visual_flush
r_cons_visual_flush.restype = None
r_cons_visual_flush.argtypes = []
r_cons_visual_write = _libr_cons.r_cons_visual_write
r_cons_visual_write.restype = None
r_cons_visual_write.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_cons_is_utf8 = _libr_cons.r_cons_is_utf8
r_cons_is_utf8.restype = ctypes.c_bool
r_cons_is_utf8.argtypes = []
r_cons_is_windows = _libr_cons.r_cons_is_windows
r_cons_is_windows.restype = ctypes.c_bool
r_cons_is_windows.argtypes = []
r_cons_cmd_help = _libr_cons.r_cons_cmd_help
r_cons_cmd_help.restype = None
r_cons_cmd_help.argtypes = [ctypes.POINTER(ctypes.c_char) * 0, ctypes.c_bool]
r_cons_log_stub = _libraries['FIXME_STUB'].r_cons_log_stub
r_cons_log_stub.restype = None
r_cons_log_stub.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_uint32, ctypes.c_uint32, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_cons_controlz = _libr_cons.r_cons_controlz
r_cons_controlz.restype = ctypes.c_int32
r_cons_controlz.argtypes = [ctypes.c_int32]
r_cons_readchar = _libr_cons.r_cons_readchar
r_cons_readchar.restype = ctypes.c_int32
r_cons_readchar.argtypes = []
r_cons_readpush = _libr_cons.r_cons_readpush
r_cons_readpush.restype = ctypes.c_bool
r_cons_readpush.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_cons_readflush = _libr_cons.r_cons_readflush
r_cons_readflush.restype = None
r_cons_readflush.argtypes = []
r_cons_switchbuf = _libr_cons.r_cons_switchbuf
r_cons_switchbuf.restype = None
r_cons_switchbuf.argtypes = [ctypes.c_bool]
r_cons_readchar_timeout = _libr_cons.r_cons_readchar_timeout
r_cons_readchar_timeout.restype = ctypes.c_int32
r_cons_readchar_timeout.argtypes = [ctypes.c_uint32]
r_cons_any_key = _libr_cons.r_cons_any_key
r_cons_any_key.restype = ctypes.c_int32
r_cons_any_key.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_cons_eof = _libr_cons.r_cons_eof
r_cons_eof.restype = ctypes.c_int32
r_cons_eof.argtypes = []
r_cons_palette_init = _libraries['FIXME_STUB'].r_cons_palette_init
r_cons_palette_init.restype = ctypes.c_int32
r_cons_palette_init.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
r_cons_pal_set = _libr_cons.r_cons_pal_set
r_cons_pal_set.restype = ctypes.c_int32
r_cons_pal_set.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_cons_pal_update_event = _libr_cons.r_cons_pal_update_event
r_cons_pal_update_event.restype = None
r_cons_pal_update_event.argtypes = []
r_cons_pal_free = _libr_cons.r_cons_pal_free
r_cons_pal_free.restype = None
r_cons_pal_free.argtypes = [ctypes.POINTER(struct_r_cons_context_t)]
r_cons_pal_init = _libr_cons.r_cons_pal_init
r_cons_pal_init.restype = None
r_cons_pal_init.argtypes = [ctypes.POINTER(struct_r_cons_context_t)]
r_cons_pal_copy = _libr_cons.r_cons_pal_copy
r_cons_pal_copy.restype = None
r_cons_pal_copy.argtypes = [ctypes.POINTER(struct_r_cons_context_t), ctypes.POINTER(struct_r_cons_context_t)]
r_cons_pal_parse = _libr_cons.r_cons_pal_parse
r_cons_pal_parse.restype = ctypes.POINTER(ctypes.c_char)
r_cons_pal_parse.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_rcolor_t)]
r_cons_pal_random = _libr_cons.r_cons_pal_random
r_cons_pal_random.restype = None
r_cons_pal_random.argtypes = []
r_cons_pal_get = _libr_cons.r_cons_pal_get
r_cons_pal_get.restype = RColor
r_cons_pal_get.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_cons_pal_get_i = _libr_cons.r_cons_pal_get_i
r_cons_pal_get_i.restype = RColor
r_cons_pal_get_i.argtypes = [ctypes.c_int32]
r_cons_pal_get_name = _libr_cons.r_cons_pal_get_name
r_cons_pal_get_name.restype = ctypes.POINTER(ctypes.c_char)
r_cons_pal_get_name.argtypes = [ctypes.c_int32]
r_cons_pal_len = _libr_cons.r_cons_pal_len
r_cons_pal_len.restype = ctypes.c_int32
r_cons_pal_len.argtypes = []
r_cons_rgb_parse = _libr_cons.r_cons_rgb_parse
r_cons_rgb_parse.restype = ctypes.c_int32
r_cons_rgb_parse.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
r_cons_rgb_tostring = _libr_cons.r_cons_rgb_tostring
r_cons_rgb_tostring.restype = ctypes.POINTER(ctypes.c_char)
r_cons_rgb_tostring.argtypes = [ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte]
r_cons_pal_list = _libr_cons.r_cons_pal_list
r_cons_pal_list.restype = None
r_cons_pal_list.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
r_cons_pal_show = _libr_cons.r_cons_pal_show
r_cons_pal_show.restype = None
r_cons_pal_show.argtypes = []
r_cons_get_size = _libr_cons.r_cons_get_size
r_cons_get_size.restype = ctypes.c_int32
r_cons_get_size.argtypes = [ctypes.POINTER(ctypes.c_int32)]
r_cons_is_tty = _libr_cons.r_cons_is_tty
r_cons_is_tty.restype = ctypes.c_bool
r_cons_is_tty.argtypes = []
r_cons_get_cursor = _libr_cons.r_cons_get_cursor
r_cons_get_cursor.restype = ctypes.c_int32
r_cons_get_cursor.argtypes = [ctypes.POINTER(ctypes.c_int32)]
r_cons_arrow_to_hjkl = _libr_cons.r_cons_arrow_to_hjkl
r_cons_arrow_to_hjkl.restype = ctypes.c_int32
r_cons_arrow_to_hjkl.argtypes = [ctypes.c_int32]
r_cons_html_filter = _libr_cons.r_cons_html_filter
r_cons_html_filter.restype = ctypes.POINTER(ctypes.c_char)
r_cons_html_filter.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_int32)]
r_cons_rainbow_get = _libr_cons.r_cons_rainbow_get
r_cons_rainbow_get.restype = ctypes.POINTER(ctypes.c_char)
r_cons_rainbow_get.argtypes = [ctypes.c_int32, ctypes.c_int32, ctypes.c_bool]
r_cons_rainbow_free = _libr_cons.r_cons_rainbow_free
r_cons_rainbow_free.restype = None
r_cons_rainbow_free.argtypes = [ctypes.POINTER(struct_r_cons_context_t)]
r_cons_rainbow_new = _libr_cons.r_cons_rainbow_new
r_cons_rainbow_new.restype = None
r_cons_rainbow_new.argtypes = [ctypes.POINTER(struct_r_cons_context_t), ctypes.c_int32]
r_cons_fgets = _libr_cons.r_cons_fgets
r_cons_fgets.restype = ctypes.c_int32
r_cons_fgets.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
r_cons_hud = _libr_cons.r_cons_hud
r_cons_hud.restype = ctypes.POINTER(ctypes.c_char)
r_cons_hud.argtypes = [ctypes.POINTER(struct_r_list_t), ctypes.POINTER(ctypes.c_char)]
r_cons_hud_line = _libr_cons.r_cons_hud_line
r_cons_hud_line.restype = ctypes.POINTER(ctypes.c_char)
r_cons_hud_line.argtypes = [ctypes.POINTER(struct_r_list_t), ctypes.POINTER(ctypes.c_char)]
r_cons_hud_line_string = _libr_cons.r_cons_hud_line_string
r_cons_hud_line_string.restype = ctypes.POINTER(ctypes.c_char)
r_cons_hud_line_string.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_cons_hud_path = _libr_cons.r_cons_hud_path
r_cons_hud_path.restype = ctypes.POINTER(ctypes.c_char)
r_cons_hud_path.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_cons_hud_string = _libr_cons.r_cons_hud_string
r_cons_hud_string.restype = ctypes.POINTER(ctypes.c_char)
r_cons_hud_string.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_cons_hud_file = _libr_cons.r_cons_hud_file
r_cons_hud_file.restype = ctypes.POINTER(ctypes.c_char)
r_cons_hud_file.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_cons_get_buffer = _libr_cons.r_cons_get_buffer
r_cons_get_buffer.restype = ctypes.POINTER(ctypes.c_char)
r_cons_get_buffer.argtypes = []
r_cons_get_buffer_len = _libr_cons.r_cons_get_buffer_len
r_cons_get_buffer_len.restype = ctypes.c_int32
r_cons_get_buffer_len.argtypes = []
r_cons_grep_help = _libr_cons.r_cons_grep_help
r_cons_grep_help.restype = None
r_cons_grep_help.argtypes = []
r_cons_grep_parsecmd = _libr_cons.r_cons_grep_parsecmd
r_cons_grep_parsecmd.restype = None
r_cons_grep_parsecmd.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_cons_grep_strip = _libr_cons.r_cons_grep_strip
r_cons_grep_strip.restype = ctypes.POINTER(ctypes.c_char)
r_cons_grep_strip.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_cons_grep_process = _libr_cons.r_cons_grep_process
r_cons_grep_process.restype = None
r_cons_grep_process.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_cons_grep_line = _libr_cons.r_cons_grep_line
r_cons_grep_line.restype = ctypes.c_int32
r_cons_grep_line.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_cons_grepbuf = _libr_cons.r_cons_grepbuf
r_cons_grepbuf.restype = None
r_cons_grepbuf.argtypes = []
r_cons_rgb = _libraries['FIXME_STUB'].r_cons_rgb
r_cons_rgb.restype = None
r_cons_rgb.argtypes = [ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte]
r_cons_rgb_fgbg = _libraries['FIXME_STUB'].r_cons_rgb_fgbg
r_cons_rgb_fgbg.restype = None
r_cons_rgb_fgbg.argtypes = [ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte]
r_cons_rgb_init = _libr_cons.r_cons_rgb_init
r_cons_rgb_init.restype = None
r_cons_rgb_init.argtypes = []
size_t = ctypes.c_uint64
r_cons_rgb_str_mode = _libr_cons.r_cons_rgb_str_mode
r_cons_rgb_str_mode.restype = ctypes.POINTER(ctypes.c_char)
r_cons_rgb_str_mode.argtypes = [RConsColorMode, ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(struct_rcolor_t)]
r_cons_rgb_str = _libr_cons.r_cons_rgb_str
r_cons_rgb_str.restype = ctypes.POINTER(ctypes.c_char)
r_cons_rgb_str.argtypes = [ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(struct_rcolor_t)]
r_cons_rgb_str_off = _libr_cons.r_cons_rgb_str_off
r_cons_rgb_str_off.restype = ctypes.POINTER(ctypes.c_char)
r_cons_rgb_str_off.argtypes = [ctypes.POINTER(ctypes.c_char), size_t, ctypes.c_uint64]
r_cons_color = _libr_cons.r_cons_color
r_cons_color.restype = None
r_cons_color.argtypes = [ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
r_cons_color_random = _libr_cons.r_cons_color_random
r_cons_color_random.restype = RColor
r_cons_color_random.argtypes = [ctypes.c_ubyte]
r_cons_invert = _libr_cons.r_cons_invert
r_cons_invert.restype = None
r_cons_invert.argtypes = [ctypes.c_int32, ctypes.c_int32]
r_cons_yesno = _libr_cons.r_cons_yesno
r_cons_yesno.restype = ctypes.c_bool
r_cons_yesno.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
r_cons_input = _libr_cons.r_cons_input
r_cons_input.restype = ctypes.POINTER(ctypes.c_char)
r_cons_input.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_cons_password = _libr_cons.r_cons_password
r_cons_password.restype = ctypes.POINTER(ctypes.c_char)
r_cons_password.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_cons_set_cup = _libr_cons.r_cons_set_cup
r_cons_set_cup.restype = ctypes.c_bool
r_cons_set_cup.argtypes = [ctypes.c_bool]
r_cons_column = _libr_cons.r_cons_column
r_cons_column.restype = None
r_cons_column.argtypes = [ctypes.c_int32]
r_cons_get_column = _libr_cons.r_cons_get_column
r_cons_get_column.restype = ctypes.c_int32
r_cons_get_column.argtypes = []
r_cons_message = _libr_cons.r_cons_message
r_cons_message.restype = ctypes.POINTER(ctypes.c_char)
r_cons_message.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_cons_set_title = _libr_cons.r_cons_set_title
r_cons_set_title.restype = None
r_cons_set_title.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_cons_enable_mouse = _libr_cons.r_cons_enable_mouse
r_cons_enable_mouse.restype = ctypes.c_bool
r_cons_enable_mouse.argtypes = [ctypes.c_bool]
r_cons_enable_highlight = _libr_cons.r_cons_enable_highlight
r_cons_enable_highlight.restype = None
r_cons_enable_highlight.argtypes = [ctypes.c_bool]
r_cons_bind = _libr_cons.r_cons_bind
r_cons_bind.restype = None
r_cons_bind.argtypes = [ctypes.POINTER(struct_r_cons_bind_t)]
r_cons_get_rune = _libr_cons.r_cons_get_rune
r_cons_get_rune.restype = ctypes.POINTER(ctypes.c_char)
r_cons_get_rune.argtypes = [ctypes.c_ubyte]
class struct_c__SA_RConsPixel(Structure):
    pass

struct_c__SA_RConsPixel._pack_ = 1 # source:False
struct_c__SA_RConsPixel._fields_ = [
    ('w', ctypes.c_int32),
    ('h', ctypes.c_int32),
    ('buf', ctypes.POINTER(ctypes.c_ubyte)),
    ('buf_size', ctypes.c_uint64),
]

RConsPixel = struct_c__SA_RConsPixel
r_cons_pixel_new = _libr_cons.r_cons_pixel_new
r_cons_pixel_new.restype = ctypes.POINTER(struct_c__SA_RConsPixel)
r_cons_pixel_new.argtypes = [ctypes.c_int32, ctypes.c_int32]
r_cons_pixel_free = _libr_cons.r_cons_pixel_free
r_cons_pixel_free.restype = None
r_cons_pixel_free.argtypes = [ctypes.POINTER(struct_c__SA_RConsPixel)]
r_cons_pixel_flush = _libr_cons.r_cons_pixel_flush
r_cons_pixel_flush.restype = None
r_cons_pixel_flush.argtypes = [ctypes.POINTER(struct_c__SA_RConsPixel), ctypes.c_int32, ctypes.c_int32]
r_cons_pixel_drain = _libr_cons.r_cons_pixel_drain
r_cons_pixel_drain.restype = ctypes.POINTER(ctypes.c_char)
r_cons_pixel_drain.argtypes = [ctypes.POINTER(struct_c__SA_RConsPixel)]
r_cons_pixel_get = _libr_cons.r_cons_pixel_get
r_cons_pixel_get.restype = ctypes.c_ubyte
r_cons_pixel_get.argtypes = [ctypes.POINTER(struct_c__SA_RConsPixel), ctypes.c_int32, ctypes.c_int32]
r_cons_pixel_set = _libr_cons.r_cons_pixel_set
r_cons_pixel_set.restype = None
r_cons_pixel_set.argtypes = [ctypes.POINTER(struct_c__SA_RConsPixel), ctypes.c_int32, ctypes.c_int32, ctypes.c_ubyte]
r_cons_pixel_sets = _libr_cons.r_cons_pixel_sets
r_cons_pixel_sets.restype = None
r_cons_pixel_sets.argtypes = [ctypes.POINTER(struct_c__SA_RConsPixel), ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
r_cons_pixel_fill = _libr_cons.r_cons_pixel_fill
r_cons_pixel_fill.restype = None
r_cons_pixel_fill.argtypes = [ctypes.POINTER(struct_c__SA_RConsPixel), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
r_cons_pixel_tostring = _libr_cons.r_cons_pixel_tostring
r_cons_pixel_tostring.restype = ctypes.POINTER(ctypes.c_char)
r_cons_pixel_tostring.argtypes = [ctypes.POINTER(struct_c__SA_RConsPixel)]
RSelWidget = struct_r_selection_widget_t
RLineHistory = struct_r_line_hist_t
RLineBuffer = struct_r_line_buffer_t
RLineHud = struct_r_hud_t
RLine = struct_r_line_t
RLineCompletion = struct_r_line_comp_t
RLinePromptType = c__EA_RLinePromptType
RLinePromptType__enumvalues = c__EA_RLinePromptType__enumvalues
RLineCompletionCb = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_line_comp_t), ctypes.POINTER(struct_r_line_buffer_t), c__EA_RLinePromptType, ctypes.POINTER(None))
RLineEditorCb = ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))
RLineHistoryUpCb = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_line_t))
RLineHistoryDownCb = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_line_t))
r_line_new = _libr_cons.r_line_new
r_line_new.restype = ctypes.POINTER(struct_r_line_t)
r_line_new.argtypes = []
r_line_singleton = _libr_cons.r_line_singleton
r_line_singleton.restype = ctypes.POINTER(struct_r_line_t)
r_line_singleton.argtypes = []
r_line_free = _libr_cons.r_line_free
r_line_free.restype = None
r_line_free.argtypes = []
r_line_get_prompt = _libr_cons.r_line_get_prompt
r_line_get_prompt.restype = ctypes.POINTER(ctypes.c_char)
r_line_get_prompt.argtypes = []
r_line_set_prompt = _libr_cons.r_line_set_prompt
r_line_set_prompt.restype = None
r_line_set_prompt.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_line_dietline_init = _libr_cons.r_line_dietline_init
r_line_dietline_init.restype = ctypes.c_int32
r_line_dietline_init.argtypes = []
r_line_clipboard_push = _libr_cons.r_line_clipboard_push
r_line_clipboard_push.restype = None
r_line_clipboard_push.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_line_hist_free = _libr_cons.r_line_hist_free
r_line_hist_free.restype = None
r_line_hist_free.argtypes = []
RLineReadCallback = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))
r_line_readline = _libr_cons.r_line_readline
r_line_readline.restype = ctypes.POINTER(ctypes.c_char)
r_line_readline.argtypes = []
r_line_readline_cb = _libr_cons.r_line_readline_cb
r_line_readline_cb.restype = ctypes.POINTER(ctypes.c_char)
r_line_readline_cb.argtypes = [RLineReadCallback, ctypes.POINTER(None)]
r_line_hist_load = _libr_cons.r_line_hist_load
r_line_hist_load.restype = ctypes.c_int32
r_line_hist_load.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_line_hist_add = _libr_cons.r_line_hist_add
r_line_hist_add.restype = ctypes.c_int32
r_line_hist_add.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_line_hist_save = _libr_cons.r_line_hist_save
r_line_hist_save.restype = ctypes.c_bool
r_line_hist_save.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_line_hist_label = _libraries['FIXME_STUB'].r_line_hist_label
r_line_hist_label.restype = ctypes.c_int32
r_line_hist_label.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_char))]
r_line_label_show = _libraries['FIXME_STUB'].r_line_label_show
r_line_label_show.restype = None
r_line_label_show.argtypes = []
r_line_hist_list = _libr_cons.r_line_hist_list
r_line_hist_list.restype = ctypes.c_int32
r_line_hist_list.argtypes = []
r_line_hist_get = _libr_cons.r_line_hist_get
r_line_hist_get.restype = ctypes.POINTER(ctypes.c_char)
r_line_hist_get.argtypes = [ctypes.c_int32]
r_line_set_hist_callback = _libr_cons.r_line_set_hist_callback
r_line_set_hist_callback.restype = ctypes.c_int32
r_line_set_hist_callback.argtypes = [ctypes.POINTER(struct_r_line_t), RLineHistoryUpCb, RLineHistoryDownCb]
r_line_hist_cmd_up = _libr_cons.r_line_hist_cmd_up
r_line_hist_cmd_up.restype = ctypes.c_int32
r_line_hist_cmd_up.argtypes = [ctypes.POINTER(struct_r_line_t)]
r_line_hist_cmd_down = _libr_cons.r_line_hist_cmd_down
r_line_hist_cmd_down.restype = ctypes.c_int32
r_line_hist_cmd_down.argtypes = [ctypes.POINTER(struct_r_line_t)]
r_line_completion_init = _libr_cons.r_line_completion_init
r_line_completion_init.restype = None
r_line_completion_init.argtypes = [ctypes.POINTER(struct_r_line_comp_t), size_t]
r_line_completion_fini = _libr_cons.r_line_completion_fini
r_line_completion_fini.restype = None
r_line_completion_fini.argtypes = [ctypes.POINTER(struct_r_line_comp_t)]
r_line_completion_push = _libr_cons.r_line_completion_push
r_line_completion_push.restype = None
r_line_completion_push.argtypes = [ctypes.POINTER(struct_r_line_comp_t), ctypes.POINTER(ctypes.c_char)]
r_line_completion_set = _libr_cons.r_line_completion_set
r_line_completion_set.restype = None
r_line_completion_set.argtypes = [ctypes.POINTER(struct_r_line_comp_t), ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
r_line_completion_clear = _libr_cons.r_line_completion_clear
r_line_completion_clear.restype = None
r_line_completion_clear.argtypes = [ctypes.POINTER(struct_r_line_comp_t)]
RPanelsMenuCallback = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None))
class struct_r_panels_menu_item(Structure):
    pass

class struct_r_panel_t(Structure):
    pass

struct_r_panels_menu_item._pack_ = 1 # source:False
struct_r_panels_menu_item._fields_ = [
    ('n_sub', ctypes.c_int32),
    ('selectedIndex', ctypes.c_int32),
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('sub', ctypes.POINTER(ctypes.POINTER(struct_r_panels_menu_item))),
    ('cb', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None))),
    ('p', ctypes.POINTER(struct_r_panel_t)),
]

class struct_r_panel_model_t(Structure):
    pass

class struct_r_panel_view_t(Structure):
    pass

struct_r_panel_t._pack_ = 1 # source:False
struct_r_panel_t._fields_ = [
    ('model', ctypes.POINTER(struct_r_panel_model_t)),
    ('view', ctypes.POINTER(struct_r_panel_view_t)),
]


# values for enumeration 'c__EA_RPanelType'
c__EA_RPanelType__enumvalues = {
    0: 'PANEL_TYPE_DEFAULT',
    1: 'PANEL_TYPE_MENU',
}
PANEL_TYPE_DEFAULT = 0
PANEL_TYPE_MENU = 1
c__EA_RPanelType = ctypes.c_uint32 # enum
struct_r_panel_model_t._pack_ = 1 # source:False
struct_r_panel_model_t._fields_ = [
    ('directionCb', ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.c_int32)),
    ('rotateCb', ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.c_bool)),
    ('print_cb', ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(None))),
    ('type', c__EA_RPanelType),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('cmd', ctypes.POINTER(ctypes.c_char)),
    ('title', ctypes.POINTER(ctypes.c_char)),
    ('baseAddr', ctypes.c_uint64),
    ('addr', ctypes.c_uint64),
    ('cache', ctypes.c_bool),
    ('PADDING_1', ctypes.c_ubyte * 7),
    ('cmdStrCache', ctypes.POINTER(ctypes.c_char)),
    ('readOnly', ctypes.POINTER(ctypes.c_char)),
    ('funcName', ctypes.POINTER(ctypes.c_char)),
    ('filter', ctypes.POINTER(ctypes.POINTER(ctypes.c_char))),
    ('n_filter', ctypes.c_int32),
    ('rotate', ctypes.c_int32),
]

class struct_r_panel_pos_t(Structure):
    pass

struct_r_panel_pos_t._pack_ = 1 # source:False
struct_r_panel_pos_t._fields_ = [
    ('x', ctypes.c_int32),
    ('y', ctypes.c_int32),
    ('w', ctypes.c_int32),
    ('h', ctypes.c_int32),
]

struct_r_panel_view_t._pack_ = 1 # source:False
struct_r_panel_view_t._fields_ = [
    ('pos', struct_r_panel_pos_t),
    ('prevPos', struct_r_panel_pos_t),
    ('sx', ctypes.c_int32),
    ('sy', ctypes.c_int32),
    ('curpos', ctypes.c_int32),
    ('refresh', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 3),
    ('edge', ctypes.c_int32),
]

RPanelsMenuItem = struct_r_panels_menu_item
class struct_r_panels_menu_t(Structure):
    pass

struct_r_panels_menu_t._pack_ = 1 # source:False
struct_r_panels_menu_t._fields_ = [
    ('root', ctypes.POINTER(struct_r_panels_menu_item)),
    ('history', ctypes.POINTER(ctypes.POINTER(struct_r_panels_menu_item))),
    ('depth', ctypes.c_int32),
    ('n_refresh', ctypes.c_int32),
    ('refreshPanels', ctypes.POINTER(ctypes.POINTER(struct_r_panel_t))),
]

RPanelsMenu = struct_r_panels_menu_t

# values for enumeration 'c__EA_RPanelsMode'
c__EA_RPanelsMode__enumvalues = {
    0: 'PANEL_MODE_DEFAULT',
    1: 'PANEL_MODE_MENU',
    2: 'PANEL_MODE_ZOOM',
    3: 'PANEL_MODE_WINDOW',
    4: 'PANEL_MODE_HELP',
}
PANEL_MODE_DEFAULT = 0
PANEL_MODE_MENU = 1
PANEL_MODE_ZOOM = 2
PANEL_MODE_WINDOW = 3
PANEL_MODE_HELP = 4
c__EA_RPanelsMode = ctypes.c_uint32 # enum
RPanelsMode = c__EA_RPanelsMode
RPanelsMode__enumvalues = c__EA_RPanelsMode__enumvalues

# values for enumeration 'c__EA_RPanelsFun'
c__EA_RPanelsFun__enumvalues = {
    0: 'PANEL_FUN_SNOW',
    1: 'PANEL_FUN_SAKURA',
    2: 'PANEL_FUN_NOFUN',
}
PANEL_FUN_SNOW = 0
PANEL_FUN_SAKURA = 1
PANEL_FUN_NOFUN = 2
c__EA_RPanelsFun = ctypes.c_uint32 # enum
RPanelsFun = c__EA_RPanelsFun
RPanelsFun__enumvalues = c__EA_RPanelsFun__enumvalues

# values for enumeration 'c__EA_RPanelsLayout'
c__EA_RPanelsLayout__enumvalues = {
    0: 'PANEL_LAYOUT_DEFAULT_STATIC',
    1: 'PANEL_LAYOUT_DEFAULT_DYNAMIC',
}
PANEL_LAYOUT_DEFAULT_STATIC = 0
PANEL_LAYOUT_DEFAULT_DYNAMIC = 1
c__EA_RPanelsLayout = ctypes.c_uint32 # enum
RPanelsLayout = c__EA_RPanelsLayout
RPanelsLayout__enumvalues = c__EA_RPanelsLayout__enumvalues
class struct_c__SA_RPanelsSnow(Structure):
    pass

struct_c__SA_RPanelsSnow._pack_ = 1 # source:False
struct_c__SA_RPanelsSnow._fields_ = [
    ('x', ctypes.c_int32),
    ('y', ctypes.c_int32),
    ('stuck', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 3),
]

RPanelsSnow = struct_c__SA_RPanelsSnow
class struct_c__SA_RModal(Structure):
    pass

struct_c__SA_RModal._pack_ = 1 # source:False
struct_c__SA_RModal._fields_ = [
    ('data', ctypes.POINTER(struct_c__SA_RStrBuf)),
    ('pos', struct_r_panel_pos_t),
    ('idx', ctypes.c_int32),
    ('offset', ctypes.c_int32),
]

RModal = struct_c__SA_RModal
class struct_r_panels_t(Structure):
    pass

class struct_sdb_t(Structure):
    pass

struct_r_panels_t._pack_ = 1 # source:False
struct_r_panels_t._fields_ = [
    ('can', ctypes.POINTER(struct_r_cons_canvas_t)),
    ('panel', ctypes.POINTER(ctypes.POINTER(struct_r_panel_t))),
    ('n_panels', ctypes.c_int32),
    ('columnWidth', ctypes.c_int32),
    ('curnode', ctypes.c_int32),
    ('mouse_orig_x', ctypes.c_int32),
    ('mouse_orig_y', ctypes.c_int32),
    ('autoUpdate', ctypes.c_bool),
    ('mouse_on_edge_x', ctypes.c_bool),
    ('mouse_on_edge_y', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte),
    ('panels_menu', ctypes.POINTER(struct_r_panels_menu_t)),
    ('db', ctypes.POINTER(struct_sdb_t)),
    ('rotate_db', ctypes.POINTER(struct_sdb_t)),
    ('modal_db', ctypes.POINTER(struct_sdb_t)),
    ('mht', ctypes.POINTER(struct_ht_pp_t)),
    ('mode', RPanelsMode),
    ('fun', RPanelsFun),
    ('prevMode', RPanelsMode),
    ('layout', RPanelsLayout),
    ('snows', ctypes.POINTER(struct_r_list_t)),
    ('name', ctypes.POINTER(ctypes.c_char)),
]

class struct_ls_t(Structure):
    pass

class struct_sdb_gperf_t(Structure):
    pass

class struct_c__SA_dict(Structure):
    pass

struct_c__SA_dict._pack_ = 1 # source:False
struct_c__SA_dict._fields_ = [
    ('table', ctypes.POINTER(ctypes.POINTER(None))),
    ('f', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
    ('size', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

class struct_cdb_make(Structure):
    pass

class struct_cdb_hp(Structure):
    pass

class struct_cdb_hplist(Structure):
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

class struct_sdb_kv(Structure):
    pass

struct_sdb_kv._pack_ = 1 # source:False
struct_sdb_kv._fields_ = [
    ('base', struct_ht_pp_kv),
    ('cas', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('expire', ctypes.c_uint64),
]

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
    ('foreach', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)), ctypes.POINTER(None))),
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

RPanels = struct_r_panels_t

# values for enumeration 'c__EA_RPanelsRootState'
c__EA_RPanelsRootState__enumvalues = {
    0: 'DEFAULT',
    1: 'ROTATE',
    2: 'DEL',
    3: 'QUIT',
}
DEFAULT = 0
ROTATE = 1
DEL = 2
QUIT = 3
c__EA_RPanelsRootState = ctypes.c_uint32 # enum
RPanelsRootState = c__EA_RPanelsRootState
RPanelsRootState__enumvalues = c__EA_RPanelsRootState__enumvalues
class struct_r_panels_root_t(Structure):
    pass

struct_r_panels_root_t._pack_ = 1 # source:False
struct_r_panels_root_t._fields_ = [
    ('n_panels', ctypes.c_int32),
    ('cur_panels', ctypes.c_int32),
    ('pdc_caches', ctypes.POINTER(struct_sdb_t)),
    ('cur_pdc_cache', ctypes.POINTER(struct_sdb_t)),
    ('panels', ctypes.POINTER(ctypes.POINTER(struct_r_panels_t))),
    ('root_state', RPanelsRootState),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

RPanelsRoot = struct_r_panels_root_t
__all__ = \
    ['ALPHA_BG', 'ALPHA_FG', 'ALPHA_FGBG', 'ALPHA_RESET',
    'COLOR_MODE_16', 'COLOR_MODE_16M', 'COLOR_MODE_256',
    'COLOR_MODE_DISABLED', 'CONTROL_MODE', 'DEFAULT', 'DEL',
    'INSERT_MODE', 'LINE_FALSE', 'LINE_NONE', 'LINE_NOSYM_HORIZ',
    'LINE_NOSYM_VERT', 'LINE_TRUE', 'LINE_UNCJMP', 'PAL_00', 'PAL_7F',
    'PAL_ADDRESS', 'PAL_CALL', 'PAL_CHANGED', 'PAL_CMP',
    'PAL_DEFAULT', 'PAL_FF', 'PAL_HEADER', 'PAL_JUMP', 'PAL_LINES0',
    'PAL_LINES1', 'PAL_LINES2', 'PAL_METADATA', 'PAL_NOP',
    'PAL_PRINTABLE', 'PAL_PROMPT', 'PAL_PUSH', 'PAL_RET', 'PAL_TRAP',
    'PANEL_FUN_NOFUN', 'PANEL_FUN_SAKURA', 'PANEL_FUN_SNOW',
    'PANEL_LAYOUT_DEFAULT_DYNAMIC', 'PANEL_LAYOUT_DEFAULT_STATIC',
    'PANEL_MODE_DEFAULT', 'PANEL_MODE_HELP', 'PANEL_MODE_MENU',
    'PANEL_MODE_WINDOW', 'PANEL_MODE_ZOOM', 'PANEL_TYPE_DEFAULT',
    'PANEL_TYPE_MENU', 'QUIT', 'RCanvasLineStyle', 'RColor', 'RCons',
    'RConsBind', 'RConsBreak', 'RConsBreakCallback', 'RConsCanvas',
    'RConsClickCallback', 'RConsColorMode',
    'RConsColorMode__enumvalues', 'RConsContext', 'RConsCursorPos',
    'RConsEditorCallback', 'RConsEvent', 'RConsFlush',
    'RConsFunctionKey', 'RConsGetCursor', 'RConsGetSize', 'RConsGrep',
    'RConsGrepCallback', 'RConsIsBreaked', 'RConsPalette',
    'RConsPixel', 'RConsPrintablePalette', 'RConsQueueTaskOneshot',
    'RConsSleepBeginCallback', 'RConsSleepEndCallback', 'RLine',
    'RLineBuffer', 'RLineCompletion', 'RLineCompletionCb',
    'RLineEditorCb', 'RLineHistory', 'RLineHistoryDownCb',
    'RLineHistoryUpCb', 'RLineHud', 'RLinePromptType',
    'RLinePromptType__enumvalues', 'RLineReadCallback', 'RModal',
    'RNCAND', 'RNCASSIGN', 'RNCDEC', 'RNCDIV', 'RNCEND', 'RNCGT',
    'RNCINC', 'RNCLEFTP', 'RNCLT', 'RNCMINUS', 'RNCMOD', 'RNCMUL',
    'RNCNAME', 'RNCNEG', 'RNCNUMBER', 'RNCOR', 'RNCPLUS', 'RNCPRINT',
    'RNCRIGHTP', 'RNCROL', 'RNCROR', 'RNCSHL', 'RNCSHR', 'RNCXOR',
    'ROTATE', 'RPanels', 'RPanelsFun', 'RPanelsFun__enumvalues',
    'RPanelsLayout', 'RPanelsLayout__enumvalues', 'RPanelsMenu',
    'RPanelsMenuCallback', 'RPanelsMenuItem', 'RPanelsMode',
    'RPanelsMode__enumvalues', 'RPanelsRoot', 'RPanelsRootState',
    'RPanelsRootState__enumvalues', 'RPanelsSnow', 'RSelWidget',
    'RViMode', 'RViMode__enumvalues', 'R_CONS_ATTR_BLINK',
    'R_CONS_ATTR_BOLD', 'R_CONS_ATTR_DIM', 'R_CONS_ATTR_ITALIC',
    'R_CONS_ATTR_UNDERLINE', 'R_CONS_ERRMODE_BUFFER',
    'R_CONS_ERRMODE_ECHO', 'R_CONS_ERRMODE_FLUSH',
    'R_CONS_ERRMODE_NULL', 'R_CONS_ERRMODE_QUIET',
    'R_LINE_PROMPT_DEFAULT', 'R_LINE_PROMPT_FILE',
    'R_LINE_PROMPT_OFFSET', 'R_LOGLVL_DEBUG', 'R_LOGLVL_ERROR',
    'R_LOGLVL_FATAL', 'R_LOGLVL_INFO', 'R_LOGLVL_NONE',
    'R_LOGLVL_SILLY', 'R_LOGLVL_VERBOSE', 'R_LOGLVL_WARN',
    'c__EA_RConsColorMode', 'c__EA_RLinePromptType',
    'c__EA_RNumCalcToken', 'c__EA_RPanelType', 'c__EA_RPanelsFun',
    'c__EA_RPanelsLayout', 'c__EA_RPanelsMode',
    'c__EA_RPanelsRootState', 'c__EA_RViMode', 'c__Ea_ALPHA_RESET',
    'c__Ea_LINE_NONE', 'c__Ea_PAL_PROMPT', 'c__Ea_R_CONS_ATTR_BOLD',
    'c__Ea_R_CONS_ERRMODE_NULL', 'r_cons_2048', 'r_cons_any_key',
    'r_cons_arrow_to_hjkl', 'r_cons_bind', 'r_cons_break_clear',
    'r_cons_break_end', 'r_cons_break_pop', 'r_cons_break_push',
    'r_cons_break_timeout', 'r_cons_breakword', 'r_cons_canvas_attr',
    'r_cons_canvas_box', 'r_cons_canvas_circle',
    'r_cons_canvas_clear', 'r_cons_canvas_fill', 'r_cons_canvas_free',
    'r_cons_canvas_goto_write', 'r_cons_canvas_gotoxy',
    'r_cons_canvas_line', 'r_cons_canvas_line_back_edge',
    'r_cons_canvas_line_diagonal', 'r_cons_canvas_line_square',
    'r_cons_canvas_line_square_defined', 'r_cons_canvas_new',
    'r_cons_canvas_print', 'r_cons_canvas_print_region',
    'r_cons_canvas_resize', 'r_cons_canvas_to_string',
    'r_cons_canvas_write', 'r_cons_chop', 'r_cons_clear',
    'r_cons_clear00', 'r_cons_clear_buffer', 'r_cons_clear_line',
    'r_cons_cmd_help', 'r_cons_color', 'r_cons_color_random',
    'r_cons_column', 'r_cons_context', 'r_cons_context_break',
    'r_cons_context_break_pop', 'r_cons_context_break_push',
    'r_cons_context_free', 'r_cons_context_is_main',
    'r_cons_context_load', 'r_cons_context_new',
    'r_cons_context_reset', 'r_cons_controlz',
    'r_cons_default_context_is_interactive', 'r_cons_drop',
    'r_cons_echo', 'r_cons_editor', 'r_cons_eflush',
    'r_cons_enable_highlight', 'r_cons_enable_mouse', 'r_cons_eof',
    'r_cons_eprintf', 'r_cons_errmode', 'r_cons_errmodes',
    'r_cons_errstr', 'r_cons_fgets', 'r_cons_fill_line',
    'r_cons_filter', 'r_cons_flush', 'r_cons_free',
    'r_cons_get_buffer', 'r_cons_get_buffer_len', 'r_cons_get_click',
    'r_cons_get_column', 'r_cons_get_cur_line', 'r_cons_get_cursor',
    'r_cons_get_rune', 'r_cons_get_size', 'r_cons_gotoxy',
    'r_cons_grep', 'r_cons_grep_help', 'r_cons_grep_line',
    'r_cons_grep_parsecmd', 'r_cons_grep_process',
    'r_cons_grep_strip', 'r_cons_grepbuf', 'r_cons_highlight',
    'r_cons_html_filter', 'r_cons_hud', 'r_cons_hud_file',
    'r_cons_hud_line', 'r_cons_hud_line_string', 'r_cons_hud_path',
    'r_cons_hud_string', 'r_cons_image', 'r_cons_input',
    'r_cons_invert', 'r_cons_is_breaked', 'r_cons_is_interactive',
    'r_cons_is_tty', 'r_cons_is_utf8', 'r_cons_is_windows',
    'r_cons_last', 'r_cons_lastline', 'r_cons_lastline_utf8_ansi_len',
    'r_cons_less', 'r_cons_less_str', 'r_cons_line',
    'r_cons_log_stub', 'r_cons_memset', 'r_cons_message',
    'r_cons_new', 'r_cons_newline', 'r_cons_pal_copy',
    'r_cons_pal_free', 'r_cons_pal_get', 'r_cons_pal_get_i',
    'r_cons_pal_get_name', 'r_cons_pal_init', 'r_cons_pal_len',
    'r_cons_pal_list', 'r_cons_pal_parse', 'r_cons_pal_random',
    'r_cons_pal_set', 'r_cons_pal_show', 'r_cons_pal_update_event',
    'r_cons_palette_init', 'r_cons_password', 'r_cons_pipe_close',
    'r_cons_pipe_open', 'r_cons_pixel_drain', 'r_cons_pixel_fill',
    'r_cons_pixel_flush', 'r_cons_pixel_free', 'r_cons_pixel_get',
    'r_cons_pixel_new', 'r_cons_pixel_set', 'r_cons_pixel_sets',
    'r_cons_pixel_tostring', 'r_cons_pop', 'r_cons_print_clear',
    'r_cons_print_fps', 'r_cons_printat', 'r_cons_printf',
    'r_cons_printf_list', 'r_cons_println', 'r_cons_push',
    'r_cons_rainbow_free', 'r_cons_rainbow_get', 'r_cons_rainbow_new',
    'r_cons_readchar', 'r_cons_readchar_timeout', 'r_cons_readflush',
    'r_cons_readpush', 'r_cons_reset', 'r_cons_reset_colors',
    'r_cons_rgb', 'r_cons_rgb_fgbg', 'r_cons_rgb_init',
    'r_cons_rgb_parse', 'r_cons_rgb_str', 'r_cons_rgb_str_mode',
    'r_cons_rgb_str_off', 'r_cons_rgb_tostring', 'r_cons_set_click',
    'r_cons_set_cup', 'r_cons_set_interactive',
    'r_cons_set_last_interactive', 'r_cons_set_raw',
    'r_cons_set_title', 'r_cons_set_utf8', 'r_cons_show_cursor',
    'r_cons_singleton', 'r_cons_sleep_begin', 'r_cons_sleep_end',
    'r_cons_stdout_open', 'r_cons_stdout_set_fd', 'r_cons_strcat',
    'r_cons_strcat_at', 'r_cons_strcat_justify', 'r_cons_swap_ground',
    'r_cons_switchbuf', 'r_cons_version', 'r_cons_visual_flush',
    'r_cons_visual_write', 'r_cons_was_breaked', 'r_cons_write',
    'r_cons_yesno', 'r_cons_zero', 'r_line_clipboard_push',
    'r_line_completion_clear', 'r_line_completion_fini',
    'r_line_completion_init', 'r_line_completion_push',
    'r_line_completion_set', 'r_line_dietline_init', 'r_line_free',
    'r_line_get_prompt', 'r_line_hist_add', 'r_line_hist_cmd_down',
    'r_line_hist_cmd_up', 'r_line_hist_free', 'r_line_hist_get',
    'r_line_hist_label', 'r_line_hist_list', 'r_line_hist_load',
    'r_line_hist_save', 'r_line_label_show', 'r_line_new',
    'r_line_readline', 'r_line_readline_cb',
    'r_line_set_hist_callback', 'r_line_set_prompt',
    'r_line_singleton', 'r_log_level', 'size_t', 'struct__IO_FILE',
    'struct__IO_codecvt', 'struct__IO_marker', 'struct__IO_wide_data',
    'struct___va_list_tag', 'struct_buffer',
    'struct_c__SA_RConsCursorPos', 'struct_c__SA_RConsPixel',
    'struct_c__SA_RModal', 'struct_c__SA_RNumCalcValue',
    'struct_c__SA_RPanelsSnow', 'struct_c__SA_RStrBuf',
    'struct_c__SA_dict', 'struct_cdb', 'struct_cdb_hp',
    'struct_cdb_hplist', 'struct_cdb_make', 'struct_ht_pp_bucket_t',
    'struct_ht_pp_kv', 'struct_ht_pp_options_t', 'struct_ht_pp_t',
    'struct_ht_up_bucket_t', 'struct_ht_up_kv',
    'struct_ht_up_options_t', 'struct_ht_up_t', 'struct_ls_iter_t',
    'struct_ls_t', 'struct_r_cons_bind_t',
    'struct_r_cons_canvas_line_style_t', 'struct_r_cons_canvas_t',
    'struct_r_cons_context_t', 'struct_r_cons_grep_t',
    'struct_r_cons_palette_t', 'struct_r_cons_printable_palette_t',
    'struct_r_cons_t', 'struct_r_hud_t', 'struct_r_line_buffer_t',
    'struct_r_line_comp_t', 'struct_r_line_hist_t', 'struct_r_line_t',
    'struct_r_list_iter_t', 'struct_r_list_t', 'struct_r_num_calc_t',
    'struct_r_num_t', 'struct_r_panel_model_t',
    'struct_r_panel_pos_t', 'struct_r_panel_t',
    'struct_r_panel_view_t', 'struct_r_panels_menu_item',
    'struct_r_panels_menu_t', 'struct_r_panels_root_t',
    'struct_r_panels_t', 'struct_r_pvector_t',
    'struct_r_selection_widget_t', 'struct_r_stack_t',
    'struct_r_str_constpool_t', 'struct_r_vector_t',
    'struct_rcolor_t', 'struct_sdb_gperf_t', 'struct_sdb_kv',
    'struct_sdb_t', 'struct_termios', 'va_list']
