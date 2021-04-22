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

class FunctionFactoryStub:
    def __getattr__(self, _):
      return ctypes.CFUNCTYPE(lambda y:y)

# libraries['FIXME_STUB'] explanation
# As you did not list (-l libraryname.so) a library that exports this function
# This is a non-working stub instead. 
# You can either re-run clan2py with -l /path/to/library.so
# Or manually fix this by comment the ctypes.CDLL loading
_libraries = {}
_libraries['FIXME_STUB'] = FunctionFactoryStub() #  ctypes.CDLL('FIXME_STUB')
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





PrintfCallback = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_char))
r_new_copy = _libraries['FIXME_STUB'].r_new_copy
r_new_copy.restype = ctypes.POINTER(None)
r_new_copy.argtypes = [ctypes.c_int32, ctypes.POINTER(None)]

# values for enumeration 'c__EA_RSysArch'
c__EA_RSysArch__enumvalues = {
    0: 'R_SYS_ARCH_NONE',
    1: 'R_SYS_ARCH_X86',
    2: 'R_SYS_ARCH_ARM',
    3: 'R_SYS_ARCH_PPC',
    4: 'R_SYS_ARCH_M68K',
    5: 'R_SYS_ARCH_JAVA',
    6: 'R_SYS_ARCH_MIPS',
    7: 'R_SYS_ARCH_SPARC',
    8: 'R_SYS_ARCH_XAP',
    9: 'R_SYS_ARCH_MSIL',
    10: 'R_SYS_ARCH_OBJD',
    11: 'R_SYS_ARCH_BF',
    12: 'R_SYS_ARCH_SH',
    13: 'R_SYS_ARCH_AVR',
    14: 'R_SYS_ARCH_DALVIK',
    15: 'R_SYS_ARCH_Z80',
    16: 'R_SYS_ARCH_ARC',
    17: 'R_SYS_ARCH_I8080',
    18: 'R_SYS_ARCH_RAR',
    19: 'R_SYS_ARCH_8051',
    20: 'R_SYS_ARCH_TMS320',
    21: 'R_SYS_ARCH_EBC',
    22: 'R_SYS_ARCH_H8300',
    23: 'R_SYS_ARCH_CR16',
    24: 'R_SYS_ARCH_V850',
    25: 'R_SYS_ARCH_SYSZ',
    26: 'R_SYS_ARCH_XCORE',
    27: 'R_SYS_ARCH_PROPELLER',
    28: 'R_SYS_ARCH_MSP430',
    29: 'R_SYS_ARCH_CRIS',
    30: 'R_SYS_ARCH_HPPA',
    31: 'R_SYS_ARCH_V810',
    32: 'R_SYS_ARCH_LM32',
    33: 'R_SYS_ARCH_RISCV',
}
R_SYS_ARCH_NONE = 0
R_SYS_ARCH_X86 = 1
R_SYS_ARCH_ARM = 2
R_SYS_ARCH_PPC = 3
R_SYS_ARCH_M68K = 4
R_SYS_ARCH_JAVA = 5
R_SYS_ARCH_MIPS = 6
R_SYS_ARCH_SPARC = 7
R_SYS_ARCH_XAP = 8
R_SYS_ARCH_MSIL = 9
R_SYS_ARCH_OBJD = 10
R_SYS_ARCH_BF = 11
R_SYS_ARCH_SH = 12
R_SYS_ARCH_AVR = 13
R_SYS_ARCH_DALVIK = 14
R_SYS_ARCH_Z80 = 15
R_SYS_ARCH_ARC = 16
R_SYS_ARCH_I8080 = 17
R_SYS_ARCH_RAR = 18
R_SYS_ARCH_8051 = 19
R_SYS_ARCH_TMS320 = 20
R_SYS_ARCH_EBC = 21
R_SYS_ARCH_H8300 = 22
R_SYS_ARCH_CR16 = 23
R_SYS_ARCH_V850 = 24
R_SYS_ARCH_SYSZ = 25
R_SYS_ARCH_XCORE = 26
R_SYS_ARCH_PROPELLER = 27
R_SYS_ARCH_MSP430 = 28
R_SYS_ARCH_CRIS = 29
R_SYS_ARCH_HPPA = 30
R_SYS_ARCH_V810 = 31
R_SYS_ARCH_LM32 = 32
R_SYS_ARCH_RISCV = 33
c__EA_RSysArch = ctypes.c_uint32 # enum
RSysArch = c__EA_RSysArch
RSysArch__enumvalues = c__EA_RSysArch__enumvalues
r_run_call1 = _libraries['FIXME_STUB'].r_run_call1
r_run_call1.restype = None
r_run_call1.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None)]
r_run_call2 = _libraries['FIXME_STUB'].r_run_call2
r_run_call2.restype = None
r_run_call2.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None)]
r_run_call3 = _libraries['FIXME_STUB'].r_run_call3
r_run_call3.restype = None
r_run_call3.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None)]
r_run_call4 = _libraries['FIXME_STUB'].r_run_call4
r_run_call4.restype = None
r_run_call4.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None)]
r_run_call5 = _libraries['FIXME_STUB'].r_run_call5
r_run_call5.restype = None
r_run_call5.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None)]
r_run_call6 = _libraries['FIXME_STUB'].r_run_call6
r_run_call6.restype = None
r_run_call6.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None)]
r_run_call7 = _libraries['FIXME_STUB'].r_run_call7
r_run_call7.restype = None
r_run_call7.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None)]
r_run_call8 = _libraries['FIXME_STUB'].r_run_call8
r_run_call8.restype = None
r_run_call8.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None)]
r_run_call9 = _libraries['FIXME_STUB'].r_run_call9
r_run_call9.restype = None
r_run_call9.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None)]
r_run_call10 = _libraries['FIXME_STUB'].r_run_call10
r_run_call10.restype = None
r_run_call10.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None)]
RRef = ctypes.c_int32
r_diff_version = _libraries['FIXME_STUB'].r_diff_version
r_diff_version.restype = ctypes.POINTER(ctypes.c_char)
r_diff_version.argtypes = []
class struct_r_diff_op_t(Structure):
    pass

struct_r_diff_op_t._pack_ = 1 # source:False
struct_r_diff_op_t._fields_ = [
    ('a_off', ctypes.c_uint64),
    ('a_buf', ctypes.POINTER(ctypes.c_ubyte)),
    ('a_len', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('b_off', ctypes.c_uint64),
    ('b_buf', ctypes.POINTER(ctypes.c_ubyte)),
    ('b_len', ctypes.c_uint32),
    ('PADDING_1', ctypes.c_ubyte * 4),
]

RDiffOp = struct_r_diff_op_t
class struct_r_diff_t(Structure):
    pass

struct_r_diff_t._pack_ = 1 # source:False
struct_r_diff_t._fields_ = [
    ('off_a', ctypes.c_uint64),
    ('off_b', ctypes.c_uint64),
    ('delta', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('user', ctypes.POINTER(None)),
    ('verbose', ctypes.c_bool),
    ('PADDING_1', ctypes.c_ubyte * 3),
    ('type', ctypes.c_int32),
    ('diff_cmd', ctypes.POINTER(ctypes.c_char)),
    ('callback', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_diff_t), ctypes.POINTER(None), ctypes.POINTER(struct_r_diff_op_t))),
]

RDiff = struct_r_diff_t

# values for enumeration 'c__EA_RLevOp'
c__EA_RLevOp__enumvalues = {
    0: 'LEVEND',
    1: 'LEVNOP',
    2: 'LEVSUB',
    3: 'LEVADD',
    4: 'LEVDEL',
}
LEVEND = 0
LEVNOP = 1
LEVSUB = 2
LEVADD = 3
LEVDEL = 4
c__EA_RLevOp = ctypes.c_uint32 # enum
RLevOp = c__EA_RLevOp
RLevOp__enumvalues = c__EA_RLevOp__enumvalues
class struct_r_lev_buf(Structure):
    pass

struct_r_lev_buf._pack_ = 1 # source:False
struct_r_lev_buf._fields_ = [
    ('buf', ctypes.POINTER(None)),
    ('len', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

RLevBuf = struct_r_lev_buf
RLevMatches = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_lev_buf), ctypes.POINTER(struct_r_lev_buf), ctypes.c_uint32, ctypes.c_uint32)
RDiffCallback = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_diff_t), ctypes.POINTER(None), ctypes.POINTER(struct_r_diff_op_t))
class struct_r_diffchar_t(Structure):
    pass

struct_r_diffchar_t._pack_ = 1 # source:False
struct_r_diffchar_t._fields_ = [
    ('align_a', ctypes.POINTER(ctypes.c_ubyte)),
    ('align_b', ctypes.POINTER(ctypes.c_ubyte)),
    ('len_buf', ctypes.c_uint64),
    ('start_align', ctypes.c_uint64),
]

RDiffChar = struct_r_diffchar_t
r_diff_new = _libr_util.r_diff_new
r_diff_new.restype = ctypes.POINTER(struct_r_diff_t)
r_diff_new.argtypes = []
r_diff_new_from = _libr_util.r_diff_new_from
r_diff_new_from.restype = ctypes.POINTER(struct_r_diff_t)
r_diff_new_from.argtypes = [ctypes.c_uint64, ctypes.c_uint64]
r_diff_free = _libr_util.r_diff_free
r_diff_free.restype = ctypes.POINTER(struct_r_diff_t)
r_diff_free.argtypes = [ctypes.POINTER(struct_r_diff_t)]
r_diff_buffers = _libr_util.r_diff_buffers
r_diff_buffers.restype = ctypes.c_int32
r_diff_buffers.argtypes = [ctypes.POINTER(struct_r_diff_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32]
r_diff_buffers_static = _libr_util.r_diff_buffers_static
r_diff_buffers_static.restype = ctypes.c_int32
r_diff_buffers_static.argtypes = [ctypes.POINTER(struct_r_diff_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_diff_buffers_radiff = _libraries['FIXME_STUB'].r_diff_buffers_radiff
r_diff_buffers_radiff.restype = ctypes.c_int32
r_diff_buffers_radiff.argtypes = [ctypes.POINTER(struct_r_diff_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_diff_buffers_delta = _libr_util.r_diff_buffers_delta
r_diff_buffers_delta.restype = ctypes.c_int32
r_diff_buffers_delta.argtypes = [ctypes.POINTER(struct_r_diff_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_diff_buffers_to_string = _libr_util.r_diff_buffers_to_string
r_diff_buffers_to_string.restype = ctypes.POINTER(ctypes.c_char)
r_diff_buffers_to_string.argtypes = [ctypes.POINTER(struct_r_diff_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_diff_set_callback = _libr_util.r_diff_set_callback
r_diff_set_callback.restype = ctypes.c_int32
r_diff_set_callback.argtypes = [ctypes.POINTER(struct_r_diff_t), RDiffCallback, ctypes.POINTER(None)]
r_diff_buffers_distance = _libr_util.r_diff_buffers_distance
r_diff_buffers_distance.restype = ctypes.c_bool
r_diff_buffers_distance.argtypes = [ctypes.POINTER(struct_r_diff_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_double)]
r_diff_buffers_distance_myers = _libr_util.r_diff_buffers_distance_myers
r_diff_buffers_distance_myers.restype = ctypes.c_bool
r_diff_buffers_distance_myers.argtypes = [ctypes.POINTER(struct_r_diff_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_double)]
r_diff_buffers_distance_levenshtein = _libr_util.r_diff_buffers_distance_levenshtein
r_diff_buffers_distance_levenshtein.restype = ctypes.c_bool
r_diff_buffers_distance_levenshtein.argtypes = [ctypes.POINTER(struct_r_diff_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_double)]
r_diff_buffers_unified = _libr_util.r_diff_buffers_unified
r_diff_buffers_unified.restype = ctypes.POINTER(ctypes.c_char)
r_diff_buffers_unified.argtypes = [ctypes.POINTER(struct_r_diff_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_diff_lines = _libraries['FIXME_STUB'].r_diff_lines
r_diff_lines.restype = ctypes.c_int32
r_diff_lines.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_diff_set_delta = _libr_util.r_diff_set_delta
r_diff_set_delta.restype = ctypes.c_int32
r_diff_set_delta.argtypes = [ctypes.POINTER(struct_r_diff_t), ctypes.c_int32]
r_diff_gdiff = _libraries['FIXME_STUB'].r_diff_gdiff
r_diff_gdiff.restype = ctypes.c_int32
r_diff_gdiff.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32]
r_diffchar_new = _libr_util.r_diffchar_new
r_diffchar_new.restype = ctypes.POINTER(struct_r_diffchar_t)
r_diffchar_new.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
r_diffchar_print = _libr_util.r_diffchar_print
r_diffchar_print.restype = None
r_diffchar_print.argtypes = [ctypes.POINTER(struct_r_diffchar_t)]
r_diffchar_free = _libr_util.r_diffchar_free
r_diffchar_free.restype = None
r_diffchar_free.argtypes = [ctypes.POINTER(struct_r_diffchar_t)]
r_diff_levenshtein_path = _libr_util.r_diff_levenshtein_path
r_diff_levenshtein_path.restype = ctypes.c_int32
r_diff_levenshtein_path.argtypes = [ctypes.POINTER(struct_r_lev_buf), ctypes.POINTER(struct_r_lev_buf), ctypes.c_uint32, RLevMatches, ctypes.POINTER(ctypes.POINTER(c__EA_RLevOp))]
class struct_r_regex_t(Structure):
    pass

class struct_re_guts(Structure):
    pass

struct_r_regex_t._pack_ = 1 # source:False
struct_r_regex_t._fields_ = [
    ('re_magic', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('re_nsub', ctypes.c_uint64),
    ('re_endp', ctypes.POINTER(ctypes.c_char)),
    ('re_g', ctypes.POINTER(struct_re_guts)),
    ('re_flags', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
]

RRegex = struct_r_regex_t
class struct_r_regmatch_t(Structure):
    pass

struct_r_regmatch_t._pack_ = 1 # source:False
struct_r_regmatch_t._fields_ = [
    ('rm_so', ctypes.c_int64),
    ('rm_eo', ctypes.c_int64),
]

RRegexMatch = struct_r_regmatch_t
r_regex_run = _libraries['FIXME_STUB'].r_regex_run
r_regex_run.restype = ctypes.c_int32
r_regex_run.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_regex_match = _libr_util.r_regex_match
r_regex_match.restype = ctypes.c_bool
r_regex_match.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_regex_flags = _libr_util.r_regex_flags
r_regex_flags.restype = ctypes.c_int32
r_regex_flags.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_regex_new = _libr_util.r_regex_new
r_regex_new.restype = ctypes.POINTER(struct_r_regex_t)
r_regex_new.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_regex_free = _libr_util.r_regex_free
r_regex_free.restype = None
r_regex_free.argtypes = [ctypes.POINTER(struct_r_regex_t)]
r_regex_init = _libr_util.r_regex_init
r_regex_init.restype = ctypes.c_int32
r_regex_init.argtypes = [ctypes.POINTER(struct_r_regex_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_regex_fini = _libr_util.r_regex_fini
r_regex_fini.restype = None
r_regex_fini.argtypes = [ctypes.POINTER(struct_r_regex_t)]
r_regex_check = _libr_util.r_regex_check
r_regex_check.restype = ctypes.c_bool
r_regex_check.argtypes = [ctypes.POINTER(struct_r_regex_t), ctypes.POINTER(ctypes.c_char)]
size_t = ctypes.c_uint64
r_regex_exec = _libr_util.r_regex_exec
r_regex_exec.restype = ctypes.c_int32
r_regex_exec.argtypes = [ctypes.POINTER(struct_r_regex_t), ctypes.POINTER(ctypes.c_char), size_t, struct_r_regmatch_t * 0, ctypes.c_int32]
class struct_r_list_t(Structure):
    pass

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

r_regex_match_list = _libr_util.r_regex_match_list
r_regex_match_list.restype = ctypes.POINTER(struct_r_list_t)
r_regex_match_list.argtypes = [ctypes.POINTER(struct_r_regex_t), ctypes.POINTER(ctypes.c_char)]
r_regex_error = _libr_util.r_regex_error
r_regex_error.restype = ctypes.POINTER(ctypes.c_char)
r_regex_error.argtypes = [ctypes.POINTER(struct_r_regex_t), ctypes.c_int32]
class struct_r_getopt_t(Structure):
    pass

struct_r_getopt_t._pack_ = 1 # source:False
struct_r_getopt_t._fields_ = [
    ('err', ctypes.c_int32),
    ('ind', ctypes.c_int32),
    ('opt', ctypes.c_int32),
    ('reset', ctypes.c_int32),
    ('arg', ctypes.POINTER(ctypes.c_char)),
    ('argc', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('argv', ctypes.POINTER(ctypes.POINTER(ctypes.c_char))),
    ('ostr', ctypes.POINTER(ctypes.c_char)),
]

RGetopt = struct_r_getopt_t
r_getopt_init = _libr_util.r_getopt_init
r_getopt_init.restype = None
r_getopt_init.argtypes = [ctypes.POINTER(struct_r_getopt_t), ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.POINTER(ctypes.c_char)]
r_getopt_next = _libr_util.r_getopt_next
r_getopt_next.restype = ctypes.c_int32
r_getopt_next.argtypes = [ctypes.POINTER(struct_r_getopt_t)]
class struct_r_skiplist_node_t(Structure):
    pass

struct_r_skiplist_node_t._pack_ = 1 # source:False
struct_r_skiplist_node_t._fields_ = [
    ('data', ctypes.POINTER(None)),
    ('forward', ctypes.POINTER(ctypes.POINTER(struct_r_skiplist_node_t))),
]

RSkipListNode = struct_r_skiplist_node_t
class struct_r_skiplist_t(Structure):
    pass

struct_r_skiplist_t._pack_ = 1 # source:False
struct_r_skiplist_t._fields_ = [
    ('head', ctypes.POINTER(struct_r_skiplist_node_t)),
    ('list_level', ctypes.c_int32),
    ('size', ctypes.c_int32),
    ('freefn', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
    ('compare', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(None))),
]

RSkipList = struct_r_skiplist_t
RListFree = ctypes.CFUNCTYPE(None, ctypes.POINTER(None))
RListComparator = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(None))
r_skiplist_new = _libr_util.r_skiplist_new
r_skiplist_new.restype = ctypes.POINTER(struct_r_skiplist_t)
r_skiplist_new.argtypes = [RListFree, RListComparator]
r_skiplist_free = _libr_util.r_skiplist_free
r_skiplist_free.restype = None
r_skiplist_free.argtypes = [ctypes.POINTER(struct_r_skiplist_t)]
r_skiplist_purge = _libr_util.r_skiplist_purge
r_skiplist_purge.restype = None
r_skiplist_purge.argtypes = [ctypes.POINTER(struct_r_skiplist_t)]
r_skiplist_insert = _libr_util.r_skiplist_insert
r_skiplist_insert.restype = ctypes.POINTER(struct_r_skiplist_node_t)
r_skiplist_insert.argtypes = [ctypes.POINTER(struct_r_skiplist_t), ctypes.POINTER(None)]
r_skiplist_insert_autofree = _libr_util.r_skiplist_insert_autofree
r_skiplist_insert_autofree.restype = ctypes.c_bool
r_skiplist_insert_autofree.argtypes = [ctypes.POINTER(struct_r_skiplist_t), ctypes.POINTER(None)]
r_skiplist_delete = _libr_util.r_skiplist_delete
r_skiplist_delete.restype = ctypes.c_bool
r_skiplist_delete.argtypes = [ctypes.POINTER(struct_r_skiplist_t), ctypes.POINTER(None)]
r_skiplist_delete_node = _libr_util.r_skiplist_delete_node
r_skiplist_delete_node.restype = ctypes.c_bool
r_skiplist_delete_node.argtypes = [ctypes.POINTER(struct_r_skiplist_t), ctypes.POINTER(struct_r_skiplist_node_t)]
r_skiplist_find = _libr_util.r_skiplist_find
r_skiplist_find.restype = ctypes.POINTER(struct_r_skiplist_node_t)
r_skiplist_find.argtypes = [ctypes.POINTER(struct_r_skiplist_t), ctypes.POINTER(None)]
r_skiplist_find_geq = _libr_util.r_skiplist_find_geq
r_skiplist_find_geq.restype = ctypes.POINTER(struct_r_skiplist_node_t)
r_skiplist_find_geq.argtypes = [ctypes.POINTER(struct_r_skiplist_t), ctypes.POINTER(None)]
r_skiplist_find_leq = _libr_util.r_skiplist_find_leq
r_skiplist_find_leq.restype = ctypes.POINTER(struct_r_skiplist_node_t)
r_skiplist_find_leq.argtypes = [ctypes.POINTER(struct_r_skiplist_t), ctypes.POINTER(None)]
r_skiplist_join = _libr_util.r_skiplist_join
r_skiplist_join.restype = None
r_skiplist_join.argtypes = [ctypes.POINTER(struct_r_skiplist_t), ctypes.POINTER(struct_r_skiplist_t)]
r_skiplist_get_first = _libr_util.r_skiplist_get_first
r_skiplist_get_first.restype = ctypes.POINTER(None)
r_skiplist_get_first.argtypes = [ctypes.POINTER(struct_r_skiplist_t)]
r_skiplist_get_n = _libr_util.r_skiplist_get_n
r_skiplist_get_n.restype = ctypes.POINTER(None)
r_skiplist_get_n.argtypes = [ctypes.POINTER(struct_r_skiplist_t), ctypes.c_int32]
r_skiplist_get_geq = _libr_util.r_skiplist_get_geq
r_skiplist_get_geq.restype = ctypes.POINTER(None)
r_skiplist_get_geq.argtypes = [ctypes.POINTER(struct_r_skiplist_t), ctypes.POINTER(None)]
r_skiplist_get_leq = _libr_util.r_skiplist_get_leq
r_skiplist_get_leq.restype = ctypes.POINTER(None)
r_skiplist_get_leq.argtypes = [ctypes.POINTER(struct_r_skiplist_t), ctypes.POINTER(None)]
r_skiplist_empty = _libr_util.r_skiplist_empty
r_skiplist_empty.restype = ctypes.c_bool
r_skiplist_empty.argtypes = [ctypes.POINTER(struct_r_skiplist_t)]
r_skiplist_to_list = _libr_util.r_skiplist_to_list
r_skiplist_to_list.restype = ctypes.POINTER(struct_r_list_t)
r_skiplist_to_list.argtypes = [ctypes.POINTER(struct_r_skiplist_t)]
class struct_r_binheap_t(Structure):
    pass

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

struct_r_binheap_t._pack_ = 1 # source:False
struct_r_binheap_t._fields_ = [
    ('a', struct_r_pvector_t),
    ('cmp', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(None))),
]

RBinHeap = struct_r_binheap_t
r_binheap_clear = _libr_util.r_binheap_clear
r_binheap_clear.restype = None
r_binheap_clear.argtypes = [ctypes.POINTER(struct_r_binheap_t)]
RPVectorComparator = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(None))
r_binheap_init = _libr_util.r_binheap_init
r_binheap_init.restype = None
r_binheap_init.argtypes = [ctypes.POINTER(struct_r_binheap_t), RPVectorComparator]
r_binheap_new = _libr_util.r_binheap_new
r_binheap_new.restype = ctypes.POINTER(struct_r_binheap_t)
r_binheap_new.argtypes = [RPVectorComparator]
r_binheap_free = _libr_util.r_binheap_free
r_binheap_free.restype = None
r_binheap_free.argtypes = [ctypes.POINTER(struct_r_binheap_t)]
r_binheap_push = _libr_util.r_binheap_push
r_binheap_push.restype = ctypes.c_bool
r_binheap_push.argtypes = [ctypes.POINTER(struct_r_binheap_t), ctypes.POINTER(None)]
r_binheap_pop = _libr_util.r_binheap_pop
r_binheap_pop.restype = ctypes.POINTER(None)
r_binheap_pop.argtypes = [ctypes.POINTER(struct_r_binheap_t)]

# values for enumeration 'c__EA_RThreadFunctionRet'
c__EA_RThreadFunctionRet__enumvalues = {
    -1: 'R_TH_FREED',
    0: 'R_TH_STOP',
    1: 'R_TH_REPEAT',
}
R_TH_FREED = -1
R_TH_STOP = 0
R_TH_REPEAT = 1
c__EA_RThreadFunctionRet = ctypes.c_int32 # enum
RThreadFunctionRet = c__EA_RThreadFunctionRet
RThreadFunctionRet__enumvalues = c__EA_RThreadFunctionRet__enumvalues
class struct_r_th_sem_t(Structure):
    pass

class union_c__UA_sem_t(Union):
    pass

struct_r_th_sem_t._pack_ = 1 # source:False
struct_r_th_sem_t._fields_ = [
    ('sem', ctypes.POINTER(union_c__UA_sem_t)),
]

union_c__UA_sem_t._pack_ = 1 # source:False
union_c__UA_sem_t._fields_ = [
    ('__size', ctypes.c_char * 32),
    ('__align', ctypes.c_int64),
    ('PADDING_0', ctypes.c_ubyte * 24),
]

RThreadSemaphore = struct_r_th_sem_t
class struct_r_th_lock_t(Structure):
    pass

class union_c__UA_pthread_mutex_t(Union):
    pass

class struct___pthread_mutex_s(Structure):
    pass

class struct___pthread_internal_list(Structure):
    pass

struct___pthread_internal_list._pack_ = 1 # source:False
struct___pthread_internal_list._fields_ = [
    ('__prev', ctypes.POINTER(struct___pthread_internal_list)),
    ('__next', ctypes.POINTER(struct___pthread_internal_list)),
]

struct___pthread_mutex_s._pack_ = 1 # source:False
struct___pthread_mutex_s._fields_ = [
    ('__lock', ctypes.c_int32),
    ('__count', ctypes.c_uint32),
    ('__owner', ctypes.c_int32),
    ('__nusers', ctypes.c_uint32),
    ('__kind', ctypes.c_int32),
    ('__spins', ctypes.c_int16),
    ('__elision', ctypes.c_int16),
    ('__list', struct___pthread_internal_list),
]

union_c__UA_pthread_mutex_t._pack_ = 1 # source:False
union_c__UA_pthread_mutex_t._fields_ = [
    ('__data', struct___pthread_mutex_s),
    ('__size', ctypes.c_char * 40),
    ('__align', ctypes.c_int64),
    ('PADDING_0', ctypes.c_ubyte * 32),
]

struct_r_th_lock_t._pack_ = 1 # source:False
struct_r_th_lock_t._fields_ = [
    ('lock', union_c__UA_pthread_mutex_t),
]

RThreadLock = struct_r_th_lock_t
class struct_r_th_cond_t(Structure):
    pass

class union_c__UA_pthread_cond_t(Union):
    pass

class struct___pthread_cond_s(Structure):
    pass

class union___pthread_cond_s_1(Union):
    pass

class struct___pthread_cond_s_1_0(Structure):
    pass

struct___pthread_cond_s_1_0._pack_ = 1 # source:False
struct___pthread_cond_s_1_0._fields_ = [
    ('__low', ctypes.c_uint32),
    ('__high', ctypes.c_uint32),
]

union___pthread_cond_s_1._pack_ = 1 # source:False
union___pthread_cond_s_1._anonymous_ = ('_0',)
union___pthread_cond_s_1._fields_ = [
    ('__g1_start', ctypes.c_uint64),
    ('_0', struct___pthread_cond_s_1_0),
]

class union___pthread_cond_s_0(Union):
    pass

class struct___pthread_cond_s_0_0(Structure):
    pass

struct___pthread_cond_s_0_0._pack_ = 1 # source:False
struct___pthread_cond_s_0_0._fields_ = [
    ('__low', ctypes.c_uint32),
    ('__high', ctypes.c_uint32),
]

union___pthread_cond_s_0._pack_ = 1 # source:False
union___pthread_cond_s_0._anonymous_ = ('_0',)
union___pthread_cond_s_0._fields_ = [
    ('__wseq', ctypes.c_uint64),
    ('_0', struct___pthread_cond_s_0_0),
]

struct___pthread_cond_s._pack_ = 1 # source:False
struct___pthread_cond_s._anonymous_ = ('_0', '_1',)
struct___pthread_cond_s._fields_ = [
    ('_0', union___pthread_cond_s_0),
    ('_1', union___pthread_cond_s_1),
    ('__g_refs', ctypes.c_uint32 * 2),
    ('__g_size', ctypes.c_uint32 * 2),
    ('__g1_orig_size', ctypes.c_uint32),
    ('__wrefs', ctypes.c_uint32),
    ('__g_signals', ctypes.c_uint32 * 2),
]

union_c__UA_pthread_cond_t._pack_ = 1 # source:False
union_c__UA_pthread_cond_t._fields_ = [
    ('__data', struct___pthread_cond_s),
    ('__size', ctypes.c_char * 48),
    ('__align', ctypes.c_int64),
    ('PADDING_0', ctypes.c_ubyte * 40),
]

struct_r_th_cond_t._pack_ = 1 # source:False
struct_r_th_cond_t._fields_ = [
    ('cond', union_c__UA_pthread_cond_t),
]

RThreadCond = struct_r_th_cond_t
class struct_r_th_t(Structure):
    pass

struct_r_th_t._pack_ = 1 # source:False
struct_r_th_t._fields_ = [
    ('tid', ctypes.c_uint64),
    ('lock', ctypes.POINTER(struct_r_th_lock_t)),
    ('fun', ctypes.CFUNCTYPE(c__EA_RThreadFunctionRet, ctypes.POINTER(struct_r_th_t))),
    ('user', ctypes.POINTER(None)),
    ('running', ctypes.c_int32),
    ('breaked', ctypes.c_int32),
    ('delay', ctypes.c_int32),
    ('ready', ctypes.c_int32),
]

RThread = struct_r_th_t
class struct_r_th_pool_t(Structure):
    pass

struct_r_th_pool_t._pack_ = 1 # source:False
struct_r_th_pool_t._fields_ = [
    ('size', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('threads', ctypes.POINTER(ctypes.POINTER(struct_r_th_t))),
]

RThreadPool = struct_r_th_pool_t
r_th_new = _libr_util.r_th_new
r_th_new.restype = ctypes.POINTER(struct_r_th_t)
r_th_new.argtypes = [ctypes.CFUNCTYPE(c__EA_RThreadFunctionRet, ctypes.POINTER(struct_r_th_t)), ctypes.POINTER(None), ctypes.c_int32]
r_th_start = _libr_util.r_th_start
r_th_start.restype = ctypes.c_bool
r_th_start.argtypes = [ctypes.POINTER(struct_r_th_t), ctypes.c_int32]
r_th_wait = _libr_util.r_th_wait
r_th_wait.restype = ctypes.c_int32
r_th_wait.argtypes = [ctypes.POINTER(struct_r_th_t)]
r_th_wait_async = _libr_util.r_th_wait_async
r_th_wait_async.restype = ctypes.c_int32
r_th_wait_async.argtypes = [ctypes.POINTER(struct_r_th_t)]
r_th_break = _libr_util.r_th_break
r_th_break.restype = None
r_th_break.argtypes = [ctypes.POINTER(struct_r_th_t)]
r_th_free = _libr_util.r_th_free
r_th_free.restype = ctypes.POINTER(None)
r_th_free.argtypes = [ctypes.POINTER(struct_r_th_t)]
r_th_kill_free = _libr_util.r_th_kill_free
r_th_kill_free.restype = ctypes.POINTER(None)
r_th_kill_free.argtypes = [ctypes.POINTER(struct_r_th_t)]
r_th_kill = _libr_util.r_th_kill
r_th_kill.restype = ctypes.c_bool
r_th_kill.argtypes = [ctypes.POINTER(struct_r_th_t), ctypes.c_bool]
pthread_t = ctypes.c_uint64
r_th_self = _libr_util.r_th_self
r_th_self.restype = pthread_t
r_th_self.argtypes = []
r_th_setname = _libr_util.r_th_setname
r_th_setname.restype = ctypes.c_bool
r_th_setname.argtypes = [ctypes.POINTER(struct_r_th_t), ctypes.POINTER(ctypes.c_char)]
r_th_getname = _libr_util.r_th_getname
r_th_getname.restype = ctypes.c_bool
r_th_getname.argtypes = [ctypes.POINTER(struct_r_th_t), ctypes.POINTER(ctypes.c_char), size_t]
r_th_setaffinity = _libr_util.r_th_setaffinity
r_th_setaffinity.restype = ctypes.c_bool
r_th_setaffinity.argtypes = [ctypes.POINTER(struct_r_th_t), ctypes.c_int32]
r_th_sem_new = _libr_util.r_th_sem_new
r_th_sem_new.restype = ctypes.POINTER(struct_r_th_sem_t)
r_th_sem_new.argtypes = [ctypes.c_uint32]
r_th_sem_free = _libr_util.r_th_sem_free
r_th_sem_free.restype = None
r_th_sem_free.argtypes = [ctypes.POINTER(struct_r_th_sem_t)]
r_th_sem_post = _libr_util.r_th_sem_post
r_th_sem_post.restype = None
r_th_sem_post.argtypes = [ctypes.POINTER(struct_r_th_sem_t)]
r_th_sem_wait = _libr_util.r_th_sem_wait
r_th_sem_wait.restype = None
r_th_sem_wait.argtypes = [ctypes.POINTER(struct_r_th_sem_t)]
r_th_lock_new = _libr_util.r_th_lock_new
r_th_lock_new.restype = ctypes.POINTER(struct_r_th_lock_t)
r_th_lock_new.argtypes = [ctypes.c_bool]
r_th_lock_wait = _libr_util.r_th_lock_wait
r_th_lock_wait.restype = ctypes.c_int32
r_th_lock_wait.argtypes = [ctypes.POINTER(struct_r_th_lock_t)]
r_th_lock_tryenter = _libr_util.r_th_lock_tryenter
r_th_lock_tryenter.restype = ctypes.c_int32
r_th_lock_tryenter.argtypes = [ctypes.POINTER(struct_r_th_lock_t)]
r_th_lock_enter = _libr_util.r_th_lock_enter
r_th_lock_enter.restype = ctypes.c_int32
r_th_lock_enter.argtypes = [ctypes.POINTER(struct_r_th_lock_t)]
r_th_lock_leave = _libr_util.r_th_lock_leave
r_th_lock_leave.restype = ctypes.c_int32
r_th_lock_leave.argtypes = [ctypes.POINTER(struct_r_th_lock_t)]
r_th_lock_free = _libr_util.r_th_lock_free
r_th_lock_free.restype = ctypes.POINTER(None)
r_th_lock_free.argtypes = [ctypes.POINTER(struct_r_th_lock_t)]
r_th_cond_new = _libr_util.r_th_cond_new
r_th_cond_new.restype = ctypes.POINTER(struct_r_th_cond_t)
r_th_cond_new.argtypes = []
r_th_cond_signal = _libr_util.r_th_cond_signal
r_th_cond_signal.restype = None
r_th_cond_signal.argtypes = [ctypes.POINTER(struct_r_th_cond_t)]
r_th_cond_signal_all = _libr_util.r_th_cond_signal_all
r_th_cond_signal_all.restype = None
r_th_cond_signal_all.argtypes = [ctypes.POINTER(struct_r_th_cond_t)]
r_th_cond_wait = _libr_util.r_th_cond_wait
r_th_cond_wait.restype = None
r_th_cond_wait.argtypes = [ctypes.POINTER(struct_r_th_cond_t), ctypes.POINTER(struct_r_th_lock_t)]
r_th_cond_free = _libr_util.r_th_cond_free
r_th_cond_free.restype = None
r_th_cond_free.argtypes = [ctypes.POINTER(struct_r_th_cond_t)]
class struct_r_event_t(Structure):
    pass

class struct_ht_up_t(Structure):
    pass

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

REvent = struct_r_event_t
class struct_r_event_callback_handle_t(Structure):
    pass

struct_r_event_callback_handle_t._pack_ = 1 # source:False
struct_r_event_callback_handle_t._fields_ = [
    ('handle', ctypes.c_int32),
    ('type', ctypes.c_int32),
]

REventCallbackHandle = struct_r_event_callback_handle_t
REventCallback = ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_event_t), ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(None))

# values for enumeration 'c__EA_REventType'
c__EA_REventType__enumvalues = {
    0: 'R_EVENT_ALL',
    1: 'R_EVENT_META_SET',
    2: 'R_EVENT_META_DEL',
    3: 'R_EVENT_META_CLEAR',
    4: 'R_EVENT_CLASS_NEW',
    5: 'R_EVENT_CLASS_DEL',
    6: 'R_EVENT_CLASS_RENAME',
    7: 'R_EVENT_CLASS_ATTR_SET',
    8: 'R_EVENT_CLASS_ATTR_DEL',
    9: 'R_EVENT_CLASS_ATTR_RENAME',
    10: 'R_EVENT_DEBUG_PROCESS_FINISHED',
    11: 'R_EVENT_IO_WRITE',
    12: 'R_EVENT_MAX',
}
R_EVENT_ALL = 0
R_EVENT_META_SET = 1
R_EVENT_META_DEL = 2
R_EVENT_META_CLEAR = 3
R_EVENT_CLASS_NEW = 4
R_EVENT_CLASS_DEL = 5
R_EVENT_CLASS_RENAME = 6
R_EVENT_CLASS_ATTR_SET = 7
R_EVENT_CLASS_ATTR_DEL = 8
R_EVENT_CLASS_ATTR_RENAME = 9
R_EVENT_DEBUG_PROCESS_FINISHED = 10
R_EVENT_IO_WRITE = 11
R_EVENT_MAX = 12
c__EA_REventType = ctypes.c_uint32 # enum
REventType = c__EA_REventType
REventType__enumvalues = c__EA_REventType__enumvalues
class struct_r_event_meta_t(Structure):
    pass

struct_r_event_meta_t._pack_ = 1 # source:False
struct_r_event_meta_t._fields_ = [
    ('type', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('addr', ctypes.c_uint64),
    ('string', ctypes.POINTER(ctypes.c_char)),
]

REventMeta = struct_r_event_meta_t
class struct_r_event_class_t(Structure):
    pass

struct_r_event_class_t._pack_ = 1 # source:False
struct_r_event_class_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
]

REventClass = struct_r_event_class_t
class struct_r_event_class_rename_t(Structure):
    pass

struct_r_event_class_rename_t._pack_ = 1 # source:False
struct_r_event_class_rename_t._fields_ = [
    ('name_old', ctypes.POINTER(ctypes.c_char)),
    ('name_new', ctypes.POINTER(ctypes.c_char)),
]

REventClassRename = struct_r_event_class_rename_t
class struct_r_event_class_attr_t(Structure):
    pass

struct_r_event_class_attr_t._pack_ = 1 # source:False
struct_r_event_class_attr_t._fields_ = [
    ('class_name', ctypes.POINTER(ctypes.c_char)),
    ('attr_type', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('attr_id', ctypes.POINTER(ctypes.c_char)),
]

REventClassAttr = struct_r_event_class_attr_t
class struct_r_event_class_attr_set_t(Structure):
    pass

struct_r_event_class_attr_set_t._pack_ = 1 # source:False
struct_r_event_class_attr_set_t._fields_ = [
    ('attr', REventClassAttr),
    ('content', ctypes.POINTER(ctypes.c_char)),
]

REventClassAttrSet = struct_r_event_class_attr_set_t
class struct_r_event_class_attr_rename_t(Structure):
    pass

struct_r_event_class_attr_rename_t._pack_ = 1 # source:False
struct_r_event_class_attr_rename_t._fields_ = [
    ('attr', REventClassAttr),
    ('attr_id_new', ctypes.POINTER(ctypes.c_char)),
]

REventClassAttrRename = struct_r_event_class_attr_rename_t
class struct_r_event_debug_process_finished_t(Structure):
    pass

struct_r_event_debug_process_finished_t._pack_ = 1 # source:False
struct_r_event_debug_process_finished_t._fields_ = [
    ('pid', ctypes.c_int32),
]

REventDebugProcessFinished = struct_r_event_debug_process_finished_t
class struct_r_event_io_write_t(Structure):
    pass

struct_r_event_io_write_t._pack_ = 1 # source:False
struct_r_event_io_write_t._fields_ = [
    ('addr', ctypes.c_uint64),
    ('buf', ctypes.POINTER(ctypes.c_ubyte)),
    ('len', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

REventIOWrite = struct_r_event_io_write_t
r_event_new = _libr_util.r_event_new
r_event_new.restype = ctypes.POINTER(struct_r_event_t)
r_event_new.argtypes = [ctypes.POINTER(None)]
r_event_free = _libr_util.r_event_free
r_event_free.restype = None
r_event_free.argtypes = [ctypes.POINTER(struct_r_event_t)]
r_event_hook = _libr_util.r_event_hook
r_event_hook.restype = REventCallbackHandle
r_event_hook.argtypes = [ctypes.POINTER(struct_r_event_t), ctypes.c_int32, REventCallback, ctypes.POINTER(None)]
r_event_unhook = _libr_util.r_event_unhook
r_event_unhook.restype = None
r_event_unhook.argtypes = [ctypes.POINTER(struct_r_event_t), REventCallbackHandle]
r_event_send = _libr_util.r_event_send
r_event_send.restype = None
r_event_send.argtypes = [ctypes.POINTER(struct_r_event_t), ctypes.c_int32, ctypes.POINTER(None)]
class struct_r_interval_t(Structure):
    pass

struct_r_interval_t._pack_ = 1 # source:False
struct_r_interval_t._fields_ = [
    ('addr', ctypes.c_uint64),
    ('size', ctypes.c_uint64),
]

RInterval = struct_r_interval_t
r_itv_t = struct_r_interval_t
r_itv_new = _libraries['FIXME_STUB'].r_itv_new
r_itv_new.restype = ctypes.POINTER(struct_r_interval_t)
r_itv_new.argtypes = [ctypes.c_uint64, ctypes.c_uint64]
r_itv_free = _libraries['FIXME_STUB'].r_itv_free
r_itv_free.restype = None
r_itv_free.argtypes = [ctypes.POINTER(struct_r_interval_t)]
r_itv_begin = _libraries['FIXME_STUB'].r_itv_begin
r_itv_begin.restype = ctypes.c_uint64
r_itv_begin.argtypes = [RInterval]
r_itv_size = _libraries['FIXME_STUB'].r_itv_size
r_itv_size.restype = ctypes.c_uint64
r_itv_size.argtypes = [RInterval]
r_itv_end = _libraries['FIXME_STUB'].r_itv_end
r_itv_end.restype = ctypes.c_uint64
r_itv_end.argtypes = [RInterval]
r_itv_eq = _libraries['FIXME_STUB'].r_itv_eq
r_itv_eq.restype = ctypes.c_bool
r_itv_eq.argtypes = [RInterval, RInterval]
r_itv_contain = _libraries['FIXME_STUB'].r_itv_contain
r_itv_contain.restype = ctypes.c_bool
r_itv_contain.argtypes = [RInterval, ctypes.c_uint64]
r_itv_include = _libraries['FIXME_STUB'].r_itv_include
r_itv_include.restype = ctypes.c_bool
r_itv_include.argtypes = [RInterval, RInterval]
r_itv_overlap = _libraries['FIXME_STUB'].r_itv_overlap
r_itv_overlap.restype = ctypes.c_bool
r_itv_overlap.argtypes = [RInterval, RInterval]
r_itv_overlap2 = _libraries['FIXME_STUB'].r_itv_overlap2
r_itv_overlap2.restype = ctypes.c_bool
r_itv_overlap2.argtypes = [RInterval, ctypes.c_uint64, ctypes.c_uint64]
r_itv_intersect = _libraries['FIXME_STUB'].r_itv_intersect
r_itv_intersect.restype = RInterval
r_itv_intersect.argtypes = [RInterval, RInterval]
RMalloc = ctypes.CFUNCTYPE(ctypes.POINTER(None), ctypes.c_uint64)
RCalloc = ctypes.CFUNCTYPE(ctypes.POINTER(None), ctypes.c_uint64, ctypes.c_uint64)
RRealloc = ctypes.CFUNCTYPE(ctypes.POINTER(None), ctypes.POINTER(None), ctypes.c_uint64)
RFree = ctypes.CFUNCTYPE(None, ctypes.POINTER(None))
r_malloc_aligned = _libr_util.r_malloc_aligned
r_malloc_aligned.restype = ctypes.POINTER(None)
r_malloc_aligned.argtypes = [size_t, size_t]
r_free_aligned = _libr_util.r_free_aligned
r_free_aligned.restype = None
r_free_aligned.argtypes = [ctypes.POINTER(None)]
class struct_r_rb_node_t(Structure):
    pass

struct_r_rb_node_t._pack_ = 1 # source:False
struct_r_rb_node_t._fields_ = [
    ('parent', ctypes.POINTER(struct_r_rb_node_t)),
    ('child', ctypes.POINTER(struct_r_rb_node_t) * 2),
    ('red', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
]

RBNode = struct_r_rb_node_t
RBTree = ctypes.POINTER(struct_r_rb_node_t)
RBComparator = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(struct_r_rb_node_t), ctypes.POINTER(None))
RBNodeFree = ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_rb_node_t), ctypes.POINTER(None))
RBNodeSum = ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_rb_node_t))
class struct_r_rb_iter_t(Structure):
    pass

struct_r_rb_iter_t._pack_ = 1 # source:False
struct_r_rb_iter_t._fields_ = [
    ('len', ctypes.c_uint64),
    ('path', ctypes.POINTER(struct_r_rb_node_t) * 62),
]

RBIter = struct_r_rb_iter_t
RContRBCmp = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None))
RContRBFree = ctypes.CFUNCTYPE(None, ctypes.POINTER(None))
class struct_r_containing_rb_node_t(Structure):
    pass

struct_r_containing_rb_node_t._pack_ = 1 # source:False
struct_r_containing_rb_node_t._fields_ = [
    ('node', RBNode),
    ('data', ctypes.POINTER(None)),
]

RContRBNode = struct_r_containing_rb_node_t
class struct_r_containing_rb_tree_t(Structure):
    pass

struct_r_containing_rb_tree_t._pack_ = 1 # source:False
struct_r_containing_rb_tree_t._fields_ = [
    ('root', ctypes.POINTER(struct_r_containing_rb_node_t)),
    ('free', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
]

RContRBTree = struct_r_containing_rb_tree_t
r_rbtree_aug_delete = _libr_util.r_rbtree_aug_delete
r_rbtree_aug_delete.restype = ctypes.c_bool
r_rbtree_aug_delete.argtypes = [ctypes.POINTER(ctypes.POINTER(struct_r_rb_node_t)), ctypes.POINTER(None), RBComparator, ctypes.POINTER(None), RBNodeFree, ctypes.POINTER(None), RBNodeSum]
r_rbtree_aug_insert = _libr_util.r_rbtree_aug_insert
r_rbtree_aug_insert.restype = ctypes.c_bool
r_rbtree_aug_insert.argtypes = [ctypes.POINTER(ctypes.POINTER(struct_r_rb_node_t)), ctypes.POINTER(None), ctypes.POINTER(struct_r_rb_node_t), RBComparator, ctypes.POINTER(None), RBNodeSum]
r_rbtree_aug_update_sum = _libr_util.r_rbtree_aug_update_sum
r_rbtree_aug_update_sum.restype = ctypes.c_bool
r_rbtree_aug_update_sum.argtypes = [ctypes.POINTER(struct_r_rb_node_t), ctypes.POINTER(None), ctypes.POINTER(struct_r_rb_node_t), RBComparator, ctypes.POINTER(None), RBNodeSum]
r_rbtree_delete = _libr_util.r_rbtree_delete
r_rbtree_delete.restype = ctypes.c_bool
r_rbtree_delete.argtypes = [ctypes.POINTER(ctypes.POINTER(struct_r_rb_node_t)), ctypes.POINTER(None), RBComparator, ctypes.POINTER(None), RBNodeFree, ctypes.POINTER(None)]
r_rbtree_find = _libr_util.r_rbtree_find
r_rbtree_find.restype = ctypes.POINTER(struct_r_rb_node_t)
r_rbtree_find.argtypes = [ctypes.POINTER(struct_r_rb_node_t), ctypes.POINTER(None), RBComparator, ctypes.POINTER(None)]
r_rbtree_free = _libr_util.r_rbtree_free
r_rbtree_free.restype = None
r_rbtree_free.argtypes = [ctypes.POINTER(struct_r_rb_node_t), RBNodeFree, ctypes.POINTER(None)]
r_rbtree_insert = _libr_util.r_rbtree_insert
r_rbtree_insert.restype = None
r_rbtree_insert.argtypes = [ctypes.POINTER(ctypes.POINTER(struct_r_rb_node_t)), ctypes.POINTER(None), ctypes.POINTER(struct_r_rb_node_t), RBComparator, ctypes.POINTER(None)]
r_rbtree_lower_bound = _libr_util.r_rbtree_lower_bound
r_rbtree_lower_bound.restype = ctypes.POINTER(struct_r_rb_node_t)
r_rbtree_lower_bound.argtypes = [ctypes.POINTER(struct_r_rb_node_t), ctypes.POINTER(None), RBComparator, ctypes.POINTER(None)]
r_rbtree_upper_bound = _libr_util.r_rbtree_upper_bound
r_rbtree_upper_bound.restype = ctypes.POINTER(struct_r_rb_node_t)
r_rbtree_upper_bound.argtypes = [ctypes.POINTER(struct_r_rb_node_t), ctypes.POINTER(None), RBComparator, ctypes.POINTER(None)]
r_rbtree_first = _libr_util.r_rbtree_first
r_rbtree_first.restype = RBIter
r_rbtree_first.argtypes = [ctypes.POINTER(struct_r_rb_node_t)]
r_rbtree_last = _libr_util.r_rbtree_last
r_rbtree_last.restype = RBIter
r_rbtree_last.argtypes = [ctypes.POINTER(struct_r_rb_node_t)]
r_rbtree_lower_bound_forward = _libr_util.r_rbtree_lower_bound_forward
r_rbtree_lower_bound_forward.restype = RBIter
r_rbtree_lower_bound_forward.argtypes = [ctypes.POINTER(struct_r_rb_node_t), ctypes.POINTER(None), RBComparator, ctypes.POINTER(None)]
r_rbtree_upper_bound_backward = _libr_util.r_rbtree_upper_bound_backward
r_rbtree_upper_bound_backward.restype = RBIter
r_rbtree_upper_bound_backward.argtypes = [ctypes.POINTER(struct_r_rb_node_t), ctypes.POINTER(None), RBComparator, ctypes.POINTER(None)]
r_rbtree_iter_next = _libr_util.r_rbtree_iter_next
r_rbtree_iter_next.restype = None
r_rbtree_iter_next.argtypes = [ctypes.POINTER(struct_r_rb_iter_t)]
r_rbtree_iter_prev = _libr_util.r_rbtree_iter_prev
r_rbtree_iter_prev.restype = None
r_rbtree_iter_prev.argtypes = [ctypes.POINTER(struct_r_rb_iter_t)]
r_rbtree_cont_new = _libr_util.r_rbtree_cont_new
r_rbtree_cont_new.restype = ctypes.POINTER(struct_r_containing_rb_tree_t)
r_rbtree_cont_new.argtypes = []
r_rbtree_cont_newf = _libr_util.r_rbtree_cont_newf
r_rbtree_cont_newf.restype = ctypes.POINTER(struct_r_containing_rb_tree_t)
r_rbtree_cont_newf.argtypes = [RContRBFree]
r_rbtree_cont_insert = _libr_util.r_rbtree_cont_insert
r_rbtree_cont_insert.restype = ctypes.c_bool
r_rbtree_cont_insert.argtypes = [ctypes.POINTER(struct_r_containing_rb_tree_t), ctypes.POINTER(None), RContRBCmp, ctypes.POINTER(None)]
r_rbtree_cont_delete = _libr_util.r_rbtree_cont_delete
r_rbtree_cont_delete.restype = ctypes.c_bool
r_rbtree_cont_delete.argtypes = [ctypes.POINTER(struct_r_containing_rb_tree_t), ctypes.POINTER(None), RContRBCmp, ctypes.POINTER(None)]
r_rbtree_cont_find_node = _libr_util.r_rbtree_cont_find_node
r_rbtree_cont_find_node.restype = ctypes.POINTER(struct_r_containing_rb_node_t)
r_rbtree_cont_find_node.argtypes = [ctypes.POINTER(struct_r_containing_rb_tree_t), ctypes.POINTER(None), RContRBCmp, ctypes.POINTER(None)]
r_rbtree_cont_node_next = _libr_util.r_rbtree_cont_node_next
r_rbtree_cont_node_next.restype = ctypes.POINTER(struct_r_containing_rb_node_t)
r_rbtree_cont_node_next.argtypes = [ctypes.POINTER(struct_r_containing_rb_node_t)]
r_rbtree_cont_node_prev = _libr_util.r_rbtree_cont_node_prev
r_rbtree_cont_node_prev.restype = ctypes.POINTER(struct_r_containing_rb_node_t)
r_rbtree_cont_node_prev.argtypes = [ctypes.POINTER(struct_r_containing_rb_node_t)]
r_rbtree_cont_find = _libr_util.r_rbtree_cont_find
r_rbtree_cont_find.restype = ctypes.POINTER(None)
r_rbtree_cont_find.argtypes = [ctypes.POINTER(struct_r_containing_rb_tree_t), ctypes.POINTER(None), RContRBCmp, ctypes.POINTER(None)]
r_rbtree_cont_first = _libr_util.r_rbtree_cont_first
r_rbtree_cont_first.restype = ctypes.POINTER(None)
r_rbtree_cont_first.argtypes = [ctypes.POINTER(struct_r_containing_rb_tree_t)]
r_rbtree_cont_last = _libr_util.r_rbtree_cont_last
r_rbtree_cont_last.restype = ctypes.POINTER(None)
r_rbtree_cont_last.argtypes = [ctypes.POINTER(struct_r_containing_rb_tree_t)]
r_rbtree_cont_free = _libr_util.r_rbtree_cont_free
r_rbtree_cont_free.restype = None
r_rbtree_cont_free.argtypes = [ctypes.POINTER(struct_r_containing_rb_tree_t)]
class struct_r_interval_node_t(Structure):
    pass

struct_r_interval_node_t._pack_ = 1 # source:False
struct_r_interval_node_t._fields_ = [
    ('node', RBNode),
    ('start', ctypes.c_uint64),
    ('end', ctypes.c_uint64),
    ('max_end', ctypes.c_uint64),
    ('data', ctypes.POINTER(None)),
]

RIntervalNode = struct_r_interval_node_t
RIntervalNodeFree = ctypes.CFUNCTYPE(None, ctypes.POINTER(None))
class struct_r_interval_tree_t(Structure):
    pass

struct_r_interval_tree_t._pack_ = 1 # source:False
struct_r_interval_tree_t._fields_ = [
    ('root', ctypes.POINTER(struct_r_interval_node_t)),
    ('free', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
]

RIntervalTree = struct_r_interval_tree_t
r_interval_tree_init = _libr_util.r_interval_tree_init
r_interval_tree_init.restype = None
r_interval_tree_init.argtypes = [ctypes.POINTER(struct_r_interval_tree_t), RIntervalNodeFree]
r_interval_tree_fini = _libr_util.r_interval_tree_fini
r_interval_tree_fini.restype = None
r_interval_tree_fini.argtypes = [ctypes.POINTER(struct_r_interval_tree_t)]
r_interval_tree_insert = _libr_util.r_interval_tree_insert
r_interval_tree_insert.restype = ctypes.c_bool
r_interval_tree_insert.argtypes = [ctypes.POINTER(struct_r_interval_tree_t), ctypes.c_uint64, ctypes.c_uint64, ctypes.POINTER(None)]
r_interval_tree_delete = _libr_util.r_interval_tree_delete
r_interval_tree_delete.restype = ctypes.c_bool
r_interval_tree_delete.argtypes = [ctypes.POINTER(struct_r_interval_tree_t), ctypes.POINTER(struct_r_interval_node_t), ctypes.c_bool]
r_interval_tree_resize = _libr_util.r_interval_tree_resize
r_interval_tree_resize.restype = ctypes.c_bool
r_interval_tree_resize.argtypes = [ctypes.POINTER(struct_r_interval_tree_t), ctypes.POINTER(struct_r_interval_node_t), ctypes.c_uint64, ctypes.c_uint64]
r_interval_tree_first_at = _libr_util.r_interval_tree_first_at
r_interval_tree_first_at.restype = RBIter
r_interval_tree_first_at.argtypes = [ctypes.POINTER(struct_r_interval_tree_t), ctypes.c_uint64]
r_interval_tree_node_at = _libr_util.r_interval_tree_node_at
r_interval_tree_node_at.restype = ctypes.POINTER(struct_r_interval_node_t)
r_interval_tree_node_at.argtypes = [ctypes.POINTER(struct_r_interval_tree_t), ctypes.c_uint64]
r_interval_tree_node_at_data = _libr_util.r_interval_tree_node_at_data
r_interval_tree_node_at_data.restype = ctypes.POINTER(struct_r_interval_node_t)
r_interval_tree_node_at_data.argtypes = [ctypes.POINTER(struct_r_interval_tree_t), ctypes.c_uint64, ctypes.POINTER(None)]
r_interval_tree_at = _libraries['FIXME_STUB'].r_interval_tree_at
r_interval_tree_at.restype = ctypes.POINTER(None)
r_interval_tree_at.argtypes = [ctypes.POINTER(struct_r_interval_tree_t), ctypes.c_uint64]
RIntervalIterCb = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_interval_node_t), ctypes.POINTER(None))
r_interval_tree_all_at = _libr_util.r_interval_tree_all_at
r_interval_tree_all_at.restype = ctypes.c_bool
r_interval_tree_all_at.argtypes = [ctypes.POINTER(struct_r_interval_tree_t), ctypes.c_uint64, RIntervalIterCb, ctypes.POINTER(None)]
r_interval_tree_all_in = _libr_util.r_interval_tree_all_in
r_interval_tree_all_in.restype = ctypes.c_bool
r_interval_tree_all_in.argtypes = [ctypes.POINTER(struct_r_interval_tree_t), ctypes.c_uint64, ctypes.c_bool, RIntervalIterCb, ctypes.POINTER(None)]
r_interval_tree_all_intersect = _libr_util.r_interval_tree_all_intersect
r_interval_tree_all_intersect.restype = ctypes.c_bool
r_interval_tree_all_intersect.argtypes = [ctypes.POINTER(struct_r_interval_tree_t), ctypes.c_uint64, ctypes.c_uint64, ctypes.c_bool, RIntervalIterCb, ctypes.POINTER(None)]
RIntervalTreeIter = struct_r_rb_iter_t
r_interval_tree_iter_get = _libraries['FIXME_STUB'].r_interval_tree_iter_get
r_interval_tree_iter_get.restype = ctypes.POINTER(struct_r_interval_node_t)
r_interval_tree_iter_get.argtypes = [ctypes.POINTER(struct_r_rb_iter_t)]
class struct_r_num_big_t(Structure):
    pass

struct_r_num_big_t._pack_ = 1 # source:False
struct_r_num_big_t._fields_ = [
    ('array', ctypes.c_uint32 * 128),
    ('sign', ctypes.c_int32),
]

RNumBig = struct_r_num_big_t
r_big_new = _libr_util.r_big_new
r_big_new.restype = ctypes.POINTER(struct_r_num_big_t)
r_big_new.argtypes = []
r_big_free = _libr_util.r_big_free
r_big_free.restype = None
r_big_free.argtypes = [ctypes.POINTER(struct_r_num_big_t)]
r_big_init = _libr_util.r_big_init
r_big_init.restype = None
r_big_init.argtypes = [ctypes.POINTER(struct_r_num_big_t)]
r_big_fini = _libr_util.r_big_fini
r_big_fini.restype = None
r_big_fini.argtypes = [ctypes.POINTER(struct_r_num_big_t)]
r_big_from_int = _libr_util.r_big_from_int
r_big_from_int.restype = None
r_big_from_int.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.c_int64]
r_big_to_int = _libr_util.r_big_to_int
r_big_to_int.restype = ctypes.c_int64
r_big_to_int.argtypes = [ctypes.POINTER(struct_r_num_big_t)]
r_big_from_hexstr = _libr_util.r_big_from_hexstr
r_big_from_hexstr.restype = None
r_big_from_hexstr.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(ctypes.c_char)]
r_big_to_hexstr = _libr_util.r_big_to_hexstr
r_big_to_hexstr.restype = ctypes.POINTER(ctypes.c_char)
r_big_to_hexstr.argtypes = [ctypes.POINTER(struct_r_num_big_t)]
r_big_assign = _libr_util.r_big_assign
r_big_assign.restype = None
r_big_assign.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t)]
r_big_add = _libr_util.r_big_add
r_big_add.restype = None
r_big_add.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t)]
r_big_sub = _libr_util.r_big_sub
r_big_sub.restype = None
r_big_sub.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t)]
r_big_mul = _libr_util.r_big_mul
r_big_mul.restype = None
r_big_mul.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t)]
r_big_div = _libr_util.r_big_div
r_big_div.restype = None
r_big_div.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t)]
r_big_mod = _libr_util.r_big_mod
r_big_mod.restype = None
r_big_mod.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t)]
r_big_divmod = _libr_util.r_big_divmod
r_big_divmod.restype = None
r_big_divmod.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t)]
r_big_and = _libr_util.r_big_and
r_big_and.restype = None
r_big_and.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t)]
r_big_or = _libr_util.r_big_or
r_big_or.restype = None
r_big_or.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t)]
r_big_xor = _libr_util.r_big_xor
r_big_xor.restype = None
r_big_xor.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t)]
r_big_lshift = _libr_util.r_big_lshift
r_big_lshift.restype = None
r_big_lshift.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t), size_t]
r_big_rshift = _libr_util.r_big_rshift
r_big_rshift.restype = None
r_big_rshift.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t), size_t]
r_big_cmp = _libr_util.r_big_cmp
r_big_cmp.restype = ctypes.c_int32
r_big_cmp.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t)]
r_big_is_zero = _libr_util.r_big_is_zero
r_big_is_zero.restype = ctypes.c_int32
r_big_is_zero.argtypes = [ctypes.POINTER(struct_r_num_big_t)]
r_big_inc = _libr_util.r_big_inc
r_big_inc.restype = None
r_big_inc.argtypes = [ctypes.POINTER(struct_r_num_big_t)]
r_big_dec = _libr_util.r_big_dec
r_big_dec.restype = None
r_big_dec.argtypes = [ctypes.POINTER(struct_r_num_big_t)]
r_big_powm = _libr_util.r_big_powm
r_big_powm.restype = None
r_big_powm.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t)]
r_big_isqrt = _libr_util.r_big_isqrt
r_big_isqrt.restype = None
r_big_isqrt.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t)]
r_base64_encode = _libr_util.r_base64_encode
r_base64_encode.restype = ctypes.c_int32
r_base64_encode.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_base64_decode = _libr_util.r_base64_decode
r_base64_decode.restype = ctypes.c_int32
r_base64_decode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_base64_decode_dyn = _libr_util.r_base64_decode_dyn
r_base64_decode_dyn.restype = ctypes.POINTER(ctypes.c_ubyte)
r_base64_decode_dyn.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_base64_encode_dyn = _libr_util.r_base64_encode_dyn
r_base64_encode_dyn.restype = ctypes.POINTER(ctypes.c_char)
r_base64_encode_dyn.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_base91_encode = _libr_util.r_base91_encode
r_base91_encode.restype = ctypes.c_int32
r_base91_encode.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_base91_decode = _libr_util.r_base91_decode
r_base91_decode.restype = ctypes.c_int32
r_base91_decode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
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

RBuffer = struct_r_buf_t
RBufferInit = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(None))
RBufferFini = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_buf_t))
RBufferRead = ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64)
RBufferWrite = ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64)
RBufferGetSize = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(struct_r_buf_t))
RBufferResize = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_buf_t), ctypes.c_uint64)
RBufferSeek = ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.POINTER(struct_r_buf_t), ctypes.c_int64, ctypes.c_int32)
RBufferGetWholeBuf = ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_uint64))
RBufferFreeWholeBuf = ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_buf_t))
RBufferNonEmptyList = ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_buf_t))
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

RBufferMethods = struct_r_buffer_methods_t
class struct_r_buf_cache_t(Structure):
    pass

struct_r_buf_cache_t._pack_ = 1 # source:False
struct_r_buf_cache_t._fields_ = [
    ('from', ctypes.c_uint64),
    ('to', ctypes.c_uint64),
    ('size', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('data', ctypes.POINTER(ctypes.c_ubyte)),
    ('written', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
]

RBufferSparse = struct_r_buf_cache_t
r_buf_new = _libr_util.r_buf_new
r_buf_new.restype = ctypes.POINTER(struct_r_buf_t)
r_buf_new.argtypes = []
r_buf_new_with_io = _libr_util.r_buf_new_with_io
r_buf_new_with_io.restype = ctypes.POINTER(struct_r_buf_t)
r_buf_new_with_io.argtypes = [ctypes.POINTER(None), ctypes.c_int32]
r_buf_new_with_bytes = _libr_util.r_buf_new_with_bytes
r_buf_new_with_bytes.restype = ctypes.POINTER(struct_r_buf_t)
r_buf_new_with_bytes.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64]
r_buf_new_with_string = _libr_util.r_buf_new_with_string
r_buf_new_with_string.restype = ctypes.POINTER(struct_r_buf_t)
r_buf_new_with_string.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_buf_new_with_pointers = _libr_util.r_buf_new_with_pointers
r_buf_new_with_pointers.restype = ctypes.POINTER(struct_r_buf_t)
r_buf_new_with_pointers.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64, ctypes.c_bool]
r_buf_new_file = _libr_util.r_buf_new_file
r_buf_new_file.restype = ctypes.POINTER(struct_r_buf_t)
r_buf_new_file.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32]
r_buf_new_with_buf = _libr_util.r_buf_new_with_buf
r_buf_new_with_buf.restype = ctypes.POINTER(struct_r_buf_t)
r_buf_new_with_buf.argtypes = [ctypes.POINTER(struct_r_buf_t)]
r_buf_new_slurp = _libr_util.r_buf_new_slurp
r_buf_new_slurp.restype = ctypes.POINTER(struct_r_buf_t)
r_buf_new_slurp.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_buf_new_slice = _libr_util.r_buf_new_slice
r_buf_new_slice.restype = ctypes.POINTER(struct_r_buf_t)
r_buf_new_slice.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.c_uint64, ctypes.c_uint64]
r_buf_new_empty = _libr_util.r_buf_new_empty
r_buf_new_empty.restype = ctypes.POINTER(struct_r_buf_t)
r_buf_new_empty.argtypes = [ctypes.c_uint64]
r_buf_new_mmap = _libr_util.r_buf_new_mmap
r_buf_new_mmap.restype = ctypes.POINTER(struct_r_buf_t)
r_buf_new_mmap.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_buf_new_sparse = _libr_util.r_buf_new_sparse
r_buf_new_sparse.restype = ctypes.POINTER(struct_r_buf_t)
r_buf_new_sparse.argtypes = [ctypes.c_ubyte]
r_buf_dump = _libr_util.r_buf_dump
r_buf_dump.restype = ctypes.c_bool
r_buf_dump.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_char)]
r_buf_set_bytes = _libr_util.r_buf_set_bytes
r_buf_set_bytes.restype = ctypes.c_bool
r_buf_set_bytes.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64]
r_buf_append_string = _libr_util.r_buf_append_string
r_buf_append_string.restype = ctypes.c_int64
r_buf_append_string.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_char)]
r_buf_append_buf = _libr_util.r_buf_append_buf
r_buf_append_buf.restype = ctypes.c_bool
r_buf_append_buf.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(struct_r_buf_t)]
r_buf_append_bytes = _libr_util.r_buf_append_bytes
r_buf_append_bytes.restype = ctypes.c_bool
r_buf_append_bytes.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64]
r_buf_append_nbytes = _libr_util.r_buf_append_nbytes
r_buf_append_nbytes.restype = ctypes.c_bool
r_buf_append_nbytes.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.c_uint64]
r_buf_append_ut16 = _libr_util.r_buf_append_ut16
r_buf_append_ut16.restype = ctypes.c_bool
r_buf_append_ut16.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.c_uint16]
r_buf_append_buf_slice = _libr_util.r_buf_append_buf_slice
r_buf_append_buf_slice.restype = ctypes.c_bool
r_buf_append_buf_slice.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(struct_r_buf_t), ctypes.c_uint64, ctypes.c_uint64]
r_buf_append_ut32 = _libr_util.r_buf_append_ut32
r_buf_append_ut32.restype = ctypes.c_bool
r_buf_append_ut32.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.c_uint32]
r_buf_append_ut64 = _libr_util.r_buf_append_ut64
r_buf_append_ut64.restype = ctypes.c_bool
r_buf_append_ut64.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.c_uint64]
r_buf_prepend_bytes = _libr_util.r_buf_prepend_bytes
r_buf_prepend_bytes.restype = ctypes.c_bool
r_buf_prepend_bytes.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64]
r_buf_insert_bytes = _libr_util.r_buf_insert_bytes
r_buf_insert_bytes.restype = ctypes.c_int64
r_buf_insert_bytes.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64]
r_buf_to_string = _libr_util.r_buf_to_string
r_buf_to_string.restype = ctypes.POINTER(ctypes.c_char)
r_buf_to_string.argtypes = [ctypes.POINTER(struct_r_buf_t)]
r_buf_get_string = _libr_util.r_buf_get_string
r_buf_get_string.restype = ctypes.POINTER(ctypes.c_char)
r_buf_get_string.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.c_uint64]
r_buf_read = _libr_util.r_buf_read
r_buf_read.restype = ctypes.c_int64
r_buf_read.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64]
r_buf_read8 = _libr_util.r_buf_read8
r_buf_read8.restype = ctypes.c_ubyte
r_buf_read8.argtypes = [ctypes.POINTER(struct_r_buf_t)]
r_buf_fread = _libr_util.r_buf_fread
r_buf_fread.restype = ctypes.c_int64
r_buf_fread.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_buf_read_at = _libr_util.r_buf_read_at
r_buf_read_at.restype = ctypes.c_int64
r_buf_read_at.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64]
r_buf_read8_at = _libr_util.r_buf_read8_at
r_buf_read8_at.restype = ctypes.c_ubyte
r_buf_read8_at.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.c_uint64]
r_buf_tell = _libr_util.r_buf_tell
r_buf_tell.restype = ctypes.c_uint64
r_buf_tell.argtypes = [ctypes.POINTER(struct_r_buf_t)]
r_buf_seek = _libr_util.r_buf_seek
r_buf_seek.restype = ctypes.c_int64
r_buf_seek.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.c_int64, ctypes.c_int32]
r_buf_fread_at = _libr_util.r_buf_fread_at
r_buf_fread_at.restype = ctypes.c_int64
r_buf_fread_at.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_buf_write = _libr_util.r_buf_write
r_buf_write.restype = ctypes.c_int64
r_buf_write.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64]
r_buf_fwrite = _libr_util.r_buf_fwrite
r_buf_fwrite.restype = ctypes.c_int64
r_buf_fwrite.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_buf_write_at = _libr_util.r_buf_write_at
r_buf_write_at.restype = ctypes.c_int64
r_buf_write_at.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64]
r_buf_fwrite_at = _libr_util.r_buf_fwrite_at
r_buf_fwrite_at.restype = ctypes.c_int64
r_buf_fwrite_at.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_buf_data = _libr_util.r_buf_data
r_buf_data.restype = ctypes.POINTER(ctypes.c_ubyte)
r_buf_data.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_uint64)]
r_buf_size = _libr_util.r_buf_size
r_buf_size.restype = ctypes.c_uint64
r_buf_size.argtypes = [ctypes.POINTER(struct_r_buf_t)]
r_buf_resize = _libr_util.r_buf_resize
r_buf_resize.restype = ctypes.c_bool
r_buf_resize.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.c_uint64]
r_buf_ref = _libr_util.r_buf_ref
r_buf_ref.restype = ctypes.POINTER(struct_r_buf_t)
r_buf_ref.argtypes = [ctypes.POINTER(struct_r_buf_t)]
r_buf_free = _libr_util.r_buf_free
r_buf_free.restype = None
r_buf_free.argtypes = [ctypes.POINTER(struct_r_buf_t)]
r_buf_fini = _libr_util.r_buf_fini
r_buf_fini.restype = ctypes.c_bool
r_buf_fini.argtypes = [ctypes.POINTER(struct_r_buf_t)]
r_buf_nonempty_list = _libr_util.r_buf_nonempty_list
r_buf_nonempty_list.restype = ctypes.POINTER(struct_r_list_t)
r_buf_nonempty_list.argtypes = [ctypes.POINTER(struct_r_buf_t)]
r_buf_read_be16 = _libraries['FIXME_STUB'].r_buf_read_be16
r_buf_read_be16.restype = ctypes.c_uint16
r_buf_read_be16.argtypes = [ctypes.POINTER(struct_r_buf_t)]
r_buf_read_be16_at = _libraries['FIXME_STUB'].r_buf_read_be16_at
r_buf_read_be16_at.restype = ctypes.c_uint16
r_buf_read_be16_at.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.c_uint64]
r_buf_read_be32 = _libraries['FIXME_STUB'].r_buf_read_be32
r_buf_read_be32.restype = ctypes.c_uint32
r_buf_read_be32.argtypes = [ctypes.POINTER(struct_r_buf_t)]
r_buf_read_be32_at = _libraries['FIXME_STUB'].r_buf_read_be32_at
r_buf_read_be32_at.restype = ctypes.c_uint32
r_buf_read_be32_at.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.c_uint64]
r_buf_read_be64 = _libraries['FIXME_STUB'].r_buf_read_be64
r_buf_read_be64.restype = ctypes.c_uint64
r_buf_read_be64.argtypes = [ctypes.POINTER(struct_r_buf_t)]
r_buf_read_be64_at = _libraries['FIXME_STUB'].r_buf_read_be64_at
r_buf_read_be64_at.restype = ctypes.c_uint64
r_buf_read_be64_at.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.c_uint64]
r_buf_read_le16 = _libraries['FIXME_STUB'].r_buf_read_le16
r_buf_read_le16.restype = ctypes.c_uint16
r_buf_read_le16.argtypes = [ctypes.POINTER(struct_r_buf_t)]
r_buf_read_le16_at = _libraries['FIXME_STUB'].r_buf_read_le16_at
r_buf_read_le16_at.restype = ctypes.c_uint16
r_buf_read_le16_at.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.c_uint64]
r_buf_read_le32 = _libraries['FIXME_STUB'].r_buf_read_le32
r_buf_read_le32.restype = ctypes.c_uint32
r_buf_read_le32.argtypes = [ctypes.POINTER(struct_r_buf_t)]
r_buf_read_le32_at = _libraries['FIXME_STUB'].r_buf_read_le32_at
r_buf_read_le32_at.restype = ctypes.c_uint32
r_buf_read_le32_at.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.c_uint64]
r_buf_read_le64 = _libraries['FIXME_STUB'].r_buf_read_le64
r_buf_read_le64.restype = ctypes.c_uint64
r_buf_read_le64.argtypes = [ctypes.POINTER(struct_r_buf_t)]
r_buf_read_le64_at = _libraries['FIXME_STUB'].r_buf_read_le64_at
r_buf_read_le64_at.restype = ctypes.c_uint64
r_buf_read_le64_at.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.c_uint64]
r_buf_read_ble16_at = _libraries['FIXME_STUB'].r_buf_read_ble16_at
r_buf_read_ble16_at.restype = ctypes.c_uint16
r_buf_read_ble16_at.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.c_uint64, ctypes.c_bool]
r_buf_read_ble32_at = _libraries['FIXME_STUB'].r_buf_read_ble32_at
r_buf_read_ble32_at.restype = ctypes.c_uint32
r_buf_read_ble32_at.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.c_uint64, ctypes.c_bool]
r_buf_read_ble64_at = _libraries['FIXME_STUB'].r_buf_read_ble64_at
r_buf_read_ble64_at.restype = ctypes.c_uint64
r_buf_read_ble64_at.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.c_uint64, ctypes.c_bool]
r_buf_uleb128 = _libr_util.r_buf_uleb128
r_buf_uleb128.restype = ctypes.c_int64
r_buf_uleb128.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_uint64)]
r_buf_sleb128 = _libr_util.r_buf_sleb128
r_buf_sleb128.restype = ctypes.c_int64
r_buf_sleb128.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_int64)]
r_buf_uleb128_at = _libraries['FIXME_STUB'].r_buf_uleb128_at
r_buf_uleb128_at.restype = ctypes.c_int64
r_buf_uleb128_at.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64)]
r_buf_sleb128_at = _libraries['FIXME_STUB'].r_buf_sleb128_at
r_buf_sleb128_at.restype = ctypes.c_int64
r_buf_sleb128_at.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_int64)]
class struct_r_bitmap_t(Structure):
    pass

struct_r_bitmap_t._pack_ = 1 # source:False
struct_r_bitmap_t._fields_ = [
    ('length', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('bitmap', ctypes.POINTER(ctypes.c_uint64)),
]

RBitmap = struct_r_bitmap_t
r_bitmap_new = _libr_util.r_bitmap_new
r_bitmap_new.restype = ctypes.POINTER(struct_r_bitmap_t)
r_bitmap_new.argtypes = [size_t]
r_bitmap_set_bytes = _libr_util.r_bitmap_set_bytes
r_bitmap_set_bytes.restype = None
r_bitmap_set_bytes.argtypes = [ctypes.POINTER(struct_r_bitmap_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_bitmap_free = _libr_util.r_bitmap_free
r_bitmap_free.restype = None
r_bitmap_free.argtypes = [ctypes.POINTER(struct_r_bitmap_t)]
r_bitmap_set = _libr_util.r_bitmap_set
r_bitmap_set.restype = None
r_bitmap_set.argtypes = [ctypes.POINTER(struct_r_bitmap_t), size_t]
r_bitmap_unset = _libr_util.r_bitmap_unset
r_bitmap_unset.restype = None
r_bitmap_unset.argtypes = [ctypes.POINTER(struct_r_bitmap_t), size_t]
r_bitmap_test = _libr_util.r_bitmap_test
r_bitmap_test.restype = ctypes.c_int32
r_bitmap_test.argtypes = [ctypes.POINTER(struct_r_bitmap_t), size_t]
r_time_now = _libr_util.r_time_now
r_time_now.restype = ctypes.c_uint64
r_time_now.argtypes = []
r_time_now_mono = _libr_util.r_time_now_mono
r_time_now_mono.restype = ctypes.c_uint64
r_time_now_mono.argtypes = []
r_time_stamp_to_str = _libr_util.r_time_stamp_to_str
r_time_stamp_to_str.restype = ctypes.POINTER(ctypes.c_char)
r_time_stamp_to_str.argtypes = [ctypes.c_uint32]
r_time_dos_time_stamp_to_posix = _libr_util.r_time_dos_time_stamp_to_posix
r_time_dos_time_stamp_to_posix.restype = ctypes.c_uint32
r_time_dos_time_stamp_to_posix.argtypes = [ctypes.c_uint32]
r_time_stamp_is_dos_format = _libr_util.r_time_stamp_is_dos_format
r_time_stamp_is_dos_format.restype = ctypes.c_bool
r_time_stamp_is_dos_format.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
r_time_to_string = _libr_util.r_time_to_string
r_time_to_string.restype = ctypes.POINTER(ctypes.c_char)
r_time_to_string.argtypes = [ctypes.c_uint64]
class struct_tm(Structure):
    pass

struct_tm._pack_ = 1 # source:False
struct_tm._fields_ = [
    ('tm_sec', ctypes.c_int32),
    ('tm_min', ctypes.c_int32),
    ('tm_hour', ctypes.c_int32),
    ('tm_mday', ctypes.c_int32),
    ('tm_mon', ctypes.c_int32),
    ('tm_year', ctypes.c_int32),
    ('tm_wday', ctypes.c_int32),
    ('tm_yday', ctypes.c_int32),
    ('tm_isdst', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('tm_gmtoff', ctypes.c_int64),
    ('tm_zone', ctypes.POINTER(ctypes.c_char)),
]

r_asctime_r = _libr_util.r_asctime_r
r_asctime_r.restype = ctypes.POINTER(ctypes.c_char)
r_asctime_r.argtypes = [ctypes.POINTER(struct_tm), ctypes.POINTER(ctypes.c_char)]
r_ctime_r = _libr_util.r_ctime_r
r_ctime_r.restype = ctypes.POINTER(ctypes.c_char)
r_ctime_r.argtypes = [ctypes.POINTER(ctypes.c_int64), ctypes.POINTER(ctypes.c_char)]
r_debruijn_pattern = _libr_util.r_debruijn_pattern
r_debruijn_pattern.restype = ctypes.POINTER(ctypes.c_char)
r_debruijn_pattern.argtypes = [ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
r_debruijn_offset = _libr_util.r_debruijn_offset
r_debruijn_offset.restype = ctypes.c_int32
r_debruijn_offset.argtypes = [ctypes.c_uint64, ctypes.c_bool]
class struct_r_cache_t(Structure):
    pass

struct_r_cache_t._pack_ = 1 # source:False
struct_r_cache_t._fields_ = [
    ('base', ctypes.c_uint64),
    ('buf', ctypes.POINTER(ctypes.c_ubyte)),
    ('len', ctypes.c_uint64),
]

RCache = struct_r_cache_t
class struct_r_prof_t(Structure):
    pass

class struct_timeval(Structure):
    pass

struct_timeval._pack_ = 1 # source:False
struct_timeval._fields_ = [
    ('tv_sec', ctypes.c_int64),
    ('tv_usec', ctypes.c_int64),
]

struct_r_prof_t._pack_ = 1 # source:False
struct_r_prof_t._fields_ = [
    ('begin', struct_timeval),
    ('result', ctypes.c_double),
]

RProfile = struct_r_prof_t
r_cache_new = _libr_util.r_cache_new
r_cache_new.restype = ctypes.POINTER(struct_r_cache_t)
r_cache_new.argtypes = []
r_cache_free = _libr_util.r_cache_free
r_cache_free.restype = None
r_cache_free.argtypes = [ctypes.POINTER(struct_r_cache_t)]
r_cache_get = _libr_util.r_cache_get
r_cache_get.restype = ctypes.POINTER(ctypes.c_ubyte)
r_cache_get.argtypes = [ctypes.POINTER(struct_r_cache_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_int32)]
r_cache_set = _libr_util.r_cache_set
r_cache_set.restype = ctypes.c_int32
r_cache_set.argtypes = [ctypes.POINTER(struct_r_cache_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_cache_flush = _libr_util.r_cache_flush
r_cache_flush.restype = None
r_cache_flush.argtypes = [ctypes.POINTER(struct_r_cache_t)]
r_prof_start = _libr_util.r_prof_start
r_prof_start.restype = None
r_prof_start.argtypes = [ctypes.POINTER(struct_r_prof_t)]
r_prof_end = _libr_util.r_prof_end
r_prof_end.restype = ctypes.c_double
r_prof_end.argtypes = [ctypes.POINTER(struct_r_prof_t)]
class struct_r_type_enum(Structure):
    pass

struct_r_type_enum._pack_ = 1 # source:False
struct_r_type_enum._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('val', ctypes.POINTER(ctypes.c_char)),
]

RTypeEnum = struct_r_type_enum

# values for enumeration 'RTypeKind'
RTypeKind__enumvalues = {
    0: 'R_TYPE_BASIC',
    1: 'R_TYPE_ENUM',
    2: 'R_TYPE_STRUCT',
    3: 'R_TYPE_UNION',
    4: 'R_TYPE_TYPEDEF',
}
R_TYPE_BASIC = 0
R_TYPE_ENUM = 1
R_TYPE_STRUCT = 2
R_TYPE_UNION = 3
R_TYPE_TYPEDEF = 4
RTypeKind = ctypes.c_uint32 # enum
class struct_sdb_t(Structure):
    pass

class struct_ls_t(Structure):
    pass

class struct_ht_pp_t(Structure):
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

class struct_sdb_kv(Structure):
    pass

class struct_ht_pp_kv(Structure):
    pass

struct_ht_pp_kv._pack_ = 1 # source:False
struct_ht_pp_kv._fields_ = [
    ('key', ctypes.POINTER(None)),
    ('value', ctypes.POINTER(None)),
    ('key_len', ctypes.c_uint32),
    ('value_len', ctypes.c_uint32),
]

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

class struct_ht_pp_bucket_t(Structure):
    pass

class struct_ht_pp_options_t(Structure):
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

r_type_set = _libr_util.r_type_set
r_type_set.restype = ctypes.c_int32
r_type_set.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_char), ctypes.c_uint64]
r_type_del = _libr_util.r_type_del
r_type_del.restype = None
r_type_del.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
r_type_kind = _libr_util.r_type_kind
r_type_kind.restype = ctypes.c_int32
r_type_kind.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
r_type_enum_member = _libr_util.r_type_enum_member
r_type_enum_member.restype = ctypes.POINTER(ctypes.c_char)
r_type_enum_member.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64]
r_type_enum_getbitfield = _libr_util.r_type_enum_getbitfield
r_type_enum_getbitfield.restype = ctypes.POINTER(ctypes.c_char)
r_type_enum_getbitfield.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64]
r_type_get_enum = _libr_util.r_type_get_enum
r_type_get_enum.restype = ctypes.POINTER(struct_r_list_t)
r_type_get_enum.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
r_type_get_bitsize = _libr_util.r_type_get_bitsize
r_type_get_bitsize.restype = ctypes.c_uint64
r_type_get_bitsize.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
r_type_get_by_offset = _libr_util.r_type_get_by_offset
r_type_get_by_offset.restype = ctypes.POINTER(struct_r_list_t)
r_type_get_by_offset.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.c_uint64]
r_type_get_struct_memb = _libr_util.r_type_get_struct_memb
r_type_get_struct_memb.restype = ctypes.POINTER(ctypes.c_char)
r_type_get_struct_memb.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_type_link_at = _libr_util.r_type_link_at
r_type_link_at.restype = ctypes.POINTER(ctypes.c_char)
r_type_link_at.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.c_uint64]
r_type_set_link = _libr_util.r_type_set_link
r_type_set_link.restype = ctypes.c_int32
r_type_set_link.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64]
r_type_unlink = _libr_util.r_type_unlink
r_type_unlink.restype = ctypes.c_int32
r_type_unlink.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.c_uint64]
r_type_link_offset = _libr_util.r_type_link_offset
r_type_link_offset.restype = ctypes.c_int32
r_type_link_offset.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64]
r_type_format = _libr_util.r_type_format
r_type_format.restype = ctypes.POINTER(ctypes.c_char)
r_type_format.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
r_type_func_exist = _libr_util.r_type_func_exist
r_type_func_exist.restype = ctypes.c_int32
r_type_func_exist.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
r_type_func_cc = _libraries['FIXME_STUB'].r_type_func_cc
r_type_func_cc.restype = ctypes.POINTER(ctypes.c_char)
r_type_func_cc.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
r_type_func_ret = _libr_util.r_type_func_ret
r_type_func_ret.restype = ctypes.POINTER(ctypes.c_char)
r_type_func_ret.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
r_type_func_args_count = _libr_util.r_type_func_args_count
r_type_func_args_count.restype = ctypes.c_int32
r_type_func_args_count.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
r_type_func_args_type = _libr_util.r_type_func_args_type
r_type_func_args_type.restype = ctypes.POINTER(ctypes.c_char)
r_type_func_args_type.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_type_func_args_name = _libr_util.r_type_func_args_name
r_type_func_args_name.restype = ctypes.POINTER(ctypes.c_char)
r_type_func_args_name.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_type_func_guess = _libr_util.r_type_func_guess
r_type_func_guess.restype = ctypes.POINTER(ctypes.c_char)
r_type_func_guess.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
r_name_validate_print = _libr_util.r_name_validate_print
r_name_validate_print.restype = ctypes.c_bool
r_name_validate_print.argtypes = [ctypes.c_char]
r_name_validate_char = _libr_util.r_name_validate_char
r_name_validate_char.restype = ctypes.c_bool
r_name_validate_char.argtypes = [ctypes.c_char]
r_name_validate_first = _libr_util.r_name_validate_first
r_name_validate_first.restype = ctypes.c_bool
r_name_validate_first.argtypes = [ctypes.c_char]
r_name_check = _libr_util.r_name_check
r_name_check.restype = ctypes.c_bool
r_name_check.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_name_filter_ro = _libr_util.r_name_filter_ro
r_name_filter_ro.restype = ctypes.POINTER(ctypes.c_char)
r_name_filter_ro.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_name_filter_flag = _libraries['FIXME_STUB'].r_name_filter_flag
r_name_filter_flag.restype = ctypes.c_bool
r_name_filter_flag.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_name_filter_print = _libr_util.r_name_filter_print
r_name_filter_print.restype = ctypes.c_bool
r_name_filter_print.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_name_filter = _libr_util.r_name_filter
r_name_filter.restype = ctypes.c_bool
r_name_filter.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_name_filter2 = _libr_util.r_name_filter2
r_name_filter2.restype = ctypes.POINTER(ctypes.c_char)
r_name_filter2.argtypes = [ctypes.POINTER(ctypes.c_char)]
class struct_c__SA_RTableColumnType(Structure):
    pass

struct_c__SA_RTableColumnType._pack_ = 1 # source:False
struct_c__SA_RTableColumnType._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('cmp', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(None))),
]

RTableColumnType = struct_c__SA_RTableColumnType
class struct_c__SA_RTableColumn(Structure):
    pass

struct_c__SA_RTableColumn._pack_ = 1 # source:False
struct_c__SA_RTableColumn._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('type', ctypes.POINTER(struct_c__SA_RTableColumnType)),
    ('align', ctypes.c_int32),
    ('width', ctypes.c_int32),
    ('maxWidth', ctypes.c_int32),
    ('forceUppercase', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 3),
    ('total', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
]

RTableColumn = struct_c__SA_RTableColumn
class struct_c__SA_RListInfo(Structure):
    pass

struct_c__SA_RListInfo._pack_ = 1 # source:False
struct_c__SA_RListInfo._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('pitv', RInterval),
    ('vitv', RInterval),
    ('perm', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('extra', ctypes.POINTER(ctypes.c_char)),
]

RListInfo = struct_c__SA_RListInfo

# values for enumeration 'c__Ea_R_TABLE_ALIGN_LEFT'
c__Ea_R_TABLE_ALIGN_LEFT__enumvalues = {
    0: 'R_TABLE_ALIGN_LEFT',
    1: 'R_TABLE_ALIGN_RIGHT',
    2: 'R_TABLE_ALIGN_CENTER',
}
R_TABLE_ALIGN_LEFT = 0
R_TABLE_ALIGN_RIGHT = 1
R_TABLE_ALIGN_CENTER = 2
c__Ea_R_TABLE_ALIGN_LEFT = ctypes.c_uint32 # enum
class struct_c__SA_RTableRow(Structure):
    pass

struct_c__SA_RTableRow._pack_ = 1 # source:False
struct_c__SA_RTableRow._fields_ = [
    ('items', ctypes.POINTER(struct_r_list_t)),
]

RTableRow = struct_c__SA_RTableRow
class struct_c__SA_RTable(Structure):
    pass

struct_c__SA_RTable._pack_ = 1 # source:False
struct_c__SA_RTable._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('rows', ctypes.POINTER(struct_r_list_t)),
    ('cols', ctypes.POINTER(struct_r_list_t)),
    ('totalCols', ctypes.c_int32),
    ('showHeader', ctypes.c_bool),
    ('showFancy', ctypes.c_bool),
    ('showSQL', ctypes.c_bool),
    ('showJSON', ctypes.c_bool),
    ('showCSV', ctypes.c_bool),
    ('showR2', ctypes.c_bool),
    ('showSum', ctypes.c_bool),
    ('adjustedCols', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('cons', ctypes.POINTER(None)),
]

RTable = struct_c__SA_RTable
RTableSelector = ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_c__SA_RTableRow), ctypes.POINTER(struct_c__SA_RTableRow), ctypes.c_int32)
r_table_row_free = _libr_util.r_table_row_free
r_table_row_free.restype = None
r_table_row_free.argtypes = [ctypes.POINTER(None)]
r_table_column_free = _libr_util.r_table_column_free
r_table_column_free.restype = None
r_table_column_free.argtypes = [ctypes.POINTER(None)]
r_table_column_clone = _libr_util.r_table_column_clone
r_table_column_clone.restype = ctypes.POINTER(struct_c__SA_RTableColumn)
r_table_column_clone.argtypes = [ctypes.POINTER(struct_c__SA_RTableColumn)]
r_table_type = _libr_util.r_table_type
r_table_type.restype = ctypes.POINTER(struct_c__SA_RTableColumnType)
r_table_type.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_table_new = _libr_util.r_table_new
r_table_new.restype = ctypes.POINTER(struct_c__SA_RTable)
r_table_new.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_table_clone = _libr_util.r_table_clone
r_table_clone.restype = ctypes.POINTER(struct_c__SA_RTable)
r_table_clone.argtypes = [ctypes.POINTER(struct_c__SA_RTable)]
r_table_free = _libr_util.r_table_free
r_table_free.restype = None
r_table_free.argtypes = [ctypes.POINTER(struct_c__SA_RTable)]
r_table_column_nth = _libr_util.r_table_column_nth
r_table_column_nth.restype = ctypes.c_int32
r_table_column_nth.argtypes = [ctypes.POINTER(struct_c__SA_RTable), ctypes.POINTER(ctypes.c_char)]
r_table_add_column = _libr_util.r_table_add_column
r_table_add_column.restype = None
r_table_add_column.argtypes = [ctypes.POINTER(struct_c__SA_RTable), ctypes.POINTER(struct_c__SA_RTableColumnType), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_table_set_columnsf = _libr_util.r_table_set_columnsf
r_table_set_columnsf.restype = None
r_table_set_columnsf.argtypes = [ctypes.POINTER(struct_c__SA_RTable), ctypes.POINTER(ctypes.c_char)]
r_table_row_new = _libr_util.r_table_row_new
r_table_row_new.restype = ctypes.POINTER(struct_c__SA_RTableRow)
r_table_row_new.argtypes = [ctypes.POINTER(struct_r_list_t)]
r_table_add_row = _libr_util.r_table_add_row
r_table_add_row.restype = None
r_table_add_row.argtypes = [ctypes.POINTER(struct_c__SA_RTable), ctypes.POINTER(ctypes.c_char)]
r_table_add_rowf = _libr_util.r_table_add_rowf
r_table_add_rowf.restype = None
r_table_add_rowf.argtypes = [ctypes.POINTER(struct_c__SA_RTable), ctypes.POINTER(ctypes.c_char)]
r_table_add_row_list = _libr_util.r_table_add_row_list
r_table_add_row_list.restype = None
r_table_add_row_list.argtypes = [ctypes.POINTER(struct_c__SA_RTable), ctypes.POINTER(struct_r_list_t)]
r_table_tofancystring = _libr_util.r_table_tofancystring
r_table_tofancystring.restype = ctypes.POINTER(ctypes.c_char)
r_table_tofancystring.argtypes = [ctypes.POINTER(struct_c__SA_RTable)]
r_table_tosimplestring = _libr_util.r_table_tosimplestring
r_table_tosimplestring.restype = ctypes.POINTER(ctypes.c_char)
r_table_tosimplestring.argtypes = [ctypes.POINTER(struct_c__SA_RTable)]
r_table_tostring = _libr_util.r_table_tostring
r_table_tostring.restype = ctypes.POINTER(ctypes.c_char)
r_table_tostring.argtypes = [ctypes.POINTER(struct_c__SA_RTable)]
r_table_tosql = _libr_util.r_table_tosql
r_table_tosql.restype = ctypes.POINTER(ctypes.c_char)
r_table_tosql.argtypes = [ctypes.POINTER(struct_c__SA_RTable)]
r_table_tocsv = _libr_util.r_table_tocsv
r_table_tocsv.restype = ctypes.POINTER(ctypes.c_char)
r_table_tocsv.argtypes = [ctypes.POINTER(struct_c__SA_RTable)]
r_table_tor2cmds = _libr_util.r_table_tor2cmds
r_table_tor2cmds.restype = ctypes.POINTER(ctypes.c_char)
r_table_tor2cmds.argtypes = [ctypes.POINTER(struct_c__SA_RTable)]
r_table_tojson = _libr_util.r_table_tojson
r_table_tojson.restype = ctypes.POINTER(ctypes.c_char)
r_table_tojson.argtypes = [ctypes.POINTER(struct_c__SA_RTable)]
r_table_help = _libr_util.r_table_help
r_table_help.restype = ctypes.POINTER(ctypes.c_char)
r_table_help.argtypes = []
r_table_filter = _libr_util.r_table_filter
r_table_filter.restype = None
r_table_filter.argtypes = [ctypes.POINTER(struct_c__SA_RTable), ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
r_table_sort = _libr_util.r_table_sort
r_table_sort.restype = None
r_table_sort.argtypes = [ctypes.POINTER(struct_c__SA_RTable), ctypes.c_int32, ctypes.c_bool]
r_table_uniq = _libr_util.r_table_uniq
r_table_uniq.restype = None
r_table_uniq.argtypes = [ctypes.POINTER(struct_c__SA_RTable)]
r_table_group = _libr_util.r_table_group
r_table_group.restype = None
r_table_group.argtypes = [ctypes.POINTER(struct_c__SA_RTable), ctypes.c_int32, RTableSelector]
r_table_query = _libr_util.r_table_query
r_table_query.restype = ctypes.c_bool
r_table_query.argtypes = [ctypes.POINTER(struct_c__SA_RTable), ctypes.POINTER(ctypes.c_char)]
r_table_hide_header = _libr_util.r_table_hide_header
r_table_hide_header.restype = None
r_table_hide_header.argtypes = [ctypes.POINTER(struct_c__SA_RTable)]
r_table_align = _libr_util.r_table_align
r_table_align.restype = ctypes.c_bool
r_table_align.argtypes = [ctypes.POINTER(struct_c__SA_RTable), ctypes.c_int32, ctypes.c_int32]
r_table_visual_list = _libr_util.r_table_visual_list
r_table_visual_list.restype = None
r_table_visual_list.argtypes = [ctypes.POINTER(struct_c__SA_RTable), ctypes.POINTER(struct_r_list_t), ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int32, ctypes.c_bool]
r_table_push = _libraries['FIXME_STUB'].r_table_push
r_table_push.restype = ctypes.POINTER(struct_c__SA_RTable)
r_table_push.argtypes = [ctypes.POINTER(struct_c__SA_RTable)]
r_table_pop = _libraries['FIXME_STUB'].r_table_pop
r_table_pop.restype = ctypes.POINTER(struct_c__SA_RTable)
r_table_pop.argtypes = [ctypes.POINTER(struct_c__SA_RTable)]
r_table_fromjson = _libraries['FIXME_STUB'].r_table_fromjson
r_table_fromjson.restype = None
r_table_fromjson.argtypes = [ctypes.POINTER(struct_c__SA_RTable), ctypes.POINTER(ctypes.c_char)]
r_table_fromcsv = _libraries['FIXME_STUB'].r_table_fromcsv
r_table_fromcsv.restype = None
r_table_fromcsv.argtypes = [ctypes.POINTER(struct_c__SA_RTable), ctypes.POINTER(ctypes.c_char)]
r_table_tohtml = _libraries['FIXME_STUB'].r_table_tohtml
r_table_tohtml.restype = ctypes.POINTER(ctypes.c_char)
r_table_tohtml.argtypes = [ctypes.POINTER(struct_c__SA_RTable)]
r_table_transpose = _libraries['FIXME_STUB'].r_table_transpose
r_table_transpose.restype = None
r_table_transpose.argtypes = [ctypes.POINTER(struct_c__SA_RTable)]
r_table_format = _libraries['FIXME_STUB'].r_table_format
r_table_format.restype = None
r_table_format.argtypes = [ctypes.POINTER(struct_c__SA_RTable), ctypes.c_int32, ctypes.POINTER(struct_c__SA_RTableColumnType)]
r_table_reduce = _libraries['FIXME_STUB'].r_table_reduce
r_table_reduce.restype = ctypes.c_uint64
r_table_reduce.argtypes = [ctypes.POINTER(struct_c__SA_RTable), ctypes.c_int32]
r_table_columns = _libr_util.r_table_columns
r_table_columns.restype = None
r_table_columns.argtypes = [ctypes.POINTER(struct_c__SA_RTable), ctypes.POINTER(struct_r_list_t)]
class struct_r_mem_pool_factory_t(Structure):
    pass

class struct_r_mem_pool_t(Structure):
    pass

struct_r_mem_pool_factory_t._pack_ = 1 # source:False
struct_r_mem_pool_factory_t._fields_ = [
    ('limit', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('pools', ctypes.POINTER(ctypes.POINTER(struct_r_mem_pool_t))),
]

struct_r_mem_pool_t._pack_ = 1 # source:False
struct_r_mem_pool_t._fields_ = [
    ('nodes', ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))),
    ('ncount', ctypes.c_int32),
    ('npool', ctypes.c_int32),
    ('nodesize', ctypes.c_int32),
    ('poolsize', ctypes.c_int32),
    ('poolcount', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

RPoolFactory = struct_r_mem_pool_factory_t
r_poolfactory_instance = _libraries['FIXME_STUB'].r_poolfactory_instance
r_poolfactory_instance.restype = ctypes.POINTER(struct_r_mem_pool_factory_t)
r_poolfactory_instance.argtypes = []
r_poolfactory_init = _libraries['FIXME_STUB'].r_poolfactory_init
r_poolfactory_init.restype = None
r_poolfactory_init.argtypes = [ctypes.c_int32]
r_poolfactory_new = _libraries['FIXME_STUB'].r_poolfactory_new
r_poolfactory_new.restype = ctypes.POINTER(struct_r_mem_pool_factory_t)
r_poolfactory_new.argtypes = [ctypes.c_int32]
r_poolfactory_alloc = _libraries['FIXME_STUB'].r_poolfactory_alloc
r_poolfactory_alloc.restype = ctypes.POINTER(None)
r_poolfactory_alloc.argtypes = [ctypes.POINTER(struct_r_mem_pool_factory_t), ctypes.c_int32]
r_poolfactory_stats = _libraries['FIXME_STUB'].r_poolfactory_stats
r_poolfactory_stats.restype = None
r_poolfactory_stats.argtypes = [ctypes.POINTER(struct_r_mem_pool_factory_t)]
r_poolfactory_free = _libraries['FIXME_STUB'].r_poolfactory_free
r_poolfactory_free.restype = None
r_poolfactory_free.argtypes = [ctypes.POINTER(struct_r_mem_pool_factory_t)]
r_punycode_encode = _libr_util.r_punycode_encode
r_punycode_encode.restype = ctypes.POINTER(ctypes.c_char)
r_punycode_encode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_int32)]
r_punycode_decode = _libr_util.r_punycode_decode
r_punycode_decode.restype = ctypes.POINTER(ctypes.c_char)
r_punycode_decode.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(ctypes.c_int32)]
class struct_r_queue_t(Structure):
    pass

struct_r_queue_t._pack_ = 1 # source:False
struct_r_queue_t._fields_ = [
    ('elems', ctypes.POINTER(ctypes.POINTER(None))),
    ('capacity', ctypes.c_uint32),
    ('front', ctypes.c_uint32),
    ('rear', ctypes.c_int32),
    ('size', ctypes.c_uint32),
]

RQueue = struct_r_queue_t
r_queue_new = _libr_util.r_queue_new
r_queue_new.restype = ctypes.POINTER(struct_r_queue_t)
r_queue_new.argtypes = [ctypes.c_int32]
r_queue_free = _libr_util.r_queue_free
r_queue_free.restype = None
r_queue_free.argtypes = [ctypes.POINTER(struct_r_queue_t)]
r_queue_enqueue = _libr_util.r_queue_enqueue
r_queue_enqueue.restype = ctypes.c_int32
r_queue_enqueue.argtypes = [ctypes.POINTER(struct_r_queue_t), ctypes.POINTER(None)]
r_queue_dequeue = _libr_util.r_queue_dequeue
r_queue_dequeue.restype = ctypes.POINTER(None)
r_queue_dequeue.argtypes = [ctypes.POINTER(struct_r_queue_t)]
r_queue_is_empty = _libr_util.r_queue_is_empty
r_queue_is_empty.restype = ctypes.c_int32
r_queue_is_empty.argtypes = [ctypes.POINTER(struct_r_queue_t)]
class struct_r_range_item_t(Structure):
    pass

struct_r_range_item_t._pack_ = 1 # source:False
struct_r_range_item_t._fields_ = [
    ('fr', ctypes.c_uint64),
    ('to', ctypes.c_uint64),
    ('data', ctypes.POINTER(ctypes.c_ubyte)),
    ('datalen', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

RRangeItem = struct_r_range_item_t
class struct_r_range_t(Structure):
    pass

struct_r_range_t._pack_ = 1 # source:False
struct_r_range_t._fields_ = [
    ('count', ctypes.c_int32),
    ('changed', ctypes.c_int32),
    ('ranges', ctypes.POINTER(struct_r_list_t)),
]

RRange = struct_r_range_t
r_range_new = _libr_util.r_range_new
r_range_new.restype = ctypes.POINTER(struct_r_range_t)
r_range_new.argtypes = []
r_range_new_from_string = _libr_util.r_range_new_from_string
r_range_new_from_string.restype = ctypes.POINTER(struct_r_range_t)
r_range_new_from_string.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_range_free = _libr_util.r_range_free
r_range_free.restype = ctypes.POINTER(struct_r_range_t)
r_range_free.argtypes = [ctypes.POINTER(struct_r_range_t)]
r_range_item_get = _libr_util.r_range_item_get
r_range_item_get.restype = ctypes.POINTER(struct_r_range_item_t)
r_range_item_get.argtypes = [ctypes.POINTER(struct_r_range_t), ctypes.c_uint64]
r_range_size = _libr_util.r_range_size
r_range_size.restype = ctypes.c_uint64
r_range_size.argtypes = [ctypes.POINTER(struct_r_range_t)]
r_range_add_from_string = _libr_util.r_range_add_from_string
r_range_add_from_string.restype = ctypes.c_int32
r_range_add_from_string.argtypes = [ctypes.POINTER(struct_r_range_t), ctypes.POINTER(ctypes.c_char)]
r_range_add = _libr_util.r_range_add
r_range_add.restype = ctypes.POINTER(struct_r_range_item_t)
r_range_add.argtypes = [ctypes.POINTER(struct_r_range_t), ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int32]
r_range_sub = _libr_util.r_range_sub
r_range_sub.restype = ctypes.c_int32
r_range_sub.argtypes = [ctypes.POINTER(struct_r_range_t), ctypes.c_uint64, ctypes.c_uint64]
r_range_merge = _libraries['FIXME_STUB'].r_range_merge
r_range_merge.restype = None
r_range_merge.argtypes = [ctypes.POINTER(struct_r_range_t), ctypes.POINTER(struct_r_range_t)]
r_range_contains = _libr_util.r_range_contains
r_range_contains.restype = ctypes.c_int32
r_range_contains.argtypes = [ctypes.POINTER(struct_r_range_t), ctypes.c_uint64]
r_range_sort = _libr_util.r_range_sort
r_range_sort.restype = ctypes.c_int32
r_range_sort.argtypes = [ctypes.POINTER(struct_r_range_t)]
r_range_percent = _libr_util.r_range_percent
r_range_percent.restype = None
r_range_percent.argtypes = [ctypes.POINTER(struct_r_range_t)]
r_range_list = _libr_util.r_range_list
r_range_list.restype = ctypes.c_int32
r_range_list.argtypes = [ctypes.POINTER(struct_r_range_t), ctypes.c_int32]
r_range_get_n = _libr_util.r_range_get_n
r_range_get_n.restype = ctypes.c_int32
r_range_get_n.argtypes = [ctypes.POINTER(struct_r_range_t), ctypes.c_int32, ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint64)]
r_range_inverse = _libr_util.r_range_inverse
r_range_inverse.restype = ctypes.POINTER(struct_r_range_t)
r_range_inverse.argtypes = [ctypes.POINTER(struct_r_range_t), ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int32]
r_range_overlap = _libr_util.r_range_overlap
r_range_overlap.restype = ctypes.c_int32
r_range_overlap.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.POINTER(ctypes.c_int32)]
class struct_r_space_t(Structure):
    pass

struct_r_space_t._pack_ = 1 # source:False
struct_r_space_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('rb', RBNode),
]

RSpace = struct_r_space_t

# values for enumeration 'c__EA_RSpaceEventType'
c__EA_RSpaceEventType__enumvalues = {
    1: 'R_SPACE_EVENT_COUNT',
    2: 'R_SPACE_EVENT_RENAME',
    3: 'R_SPACE_EVENT_UNSET',
}
R_SPACE_EVENT_COUNT = 1
R_SPACE_EVENT_RENAME = 2
R_SPACE_EVENT_UNSET = 3
c__EA_RSpaceEventType = ctypes.c_uint32 # enum
RSpaceEventType = c__EA_RSpaceEventType
RSpaceEventType__enumvalues = c__EA_RSpaceEventType__enumvalues
class struct_r_space_event_t(Structure):
    pass

class union_r_space_event_t_0(Union):
    pass

class struct_r_space_event_t_0_0(Structure):
    pass

struct_r_space_event_t_0_0._pack_ = 1 # source:False
struct_r_space_event_t_0_0._fields_ = [
    ('space', ctypes.POINTER(struct_r_space_t)),
]

class struct_r_space_event_t_0_2(Structure):
    pass

struct_r_space_event_t_0_2._pack_ = 1 # source:False
struct_r_space_event_t_0_2._fields_ = [
    ('space', ctypes.POINTER(struct_r_space_t)),
    ('oldname', ctypes.POINTER(ctypes.c_char)),
    ('newname', ctypes.POINTER(ctypes.c_char)),
]

class struct_r_space_event_t_0_1(Structure):
    pass

struct_r_space_event_t_0_1._pack_ = 1 # source:False
struct_r_space_event_t_0_1._fields_ = [
    ('space', ctypes.POINTER(struct_r_space_t)),
]

union_r_space_event_t_0._pack_ = 1 # source:False
union_r_space_event_t_0._anonymous_ = ('_0', '_1', '_2',)
union_r_space_event_t_0._fields_ = [
    ('_0', struct_r_space_event_t_0_0),
    ('_1', struct_r_space_event_t_0_1),
    ('_2', struct_r_space_event_t_0_2),
]

struct_r_space_event_t._pack_ = 1 # source:False
struct_r_space_event_t._anonymous_ = ('_0',)
struct_r_space_event_t._fields_ = [
    ('_0', union_r_space_event_t_0),
    ('res', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

RSpaceEvent = struct_r_space_event_t
class struct_r_spaces_t(Structure):
    pass

struct_r_spaces_t._pack_ = 1 # source:False
struct_r_spaces_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('current', ctypes.POINTER(struct_r_space_t)),
    ('spaces', ctypes.POINTER(struct_r_rb_node_t)),
    ('spacestack', ctypes.POINTER(struct_r_list_t)),
    ('event', ctypes.POINTER(struct_r_event_t)),
]

RSpaces = struct_r_spaces_t
r_spaces_new = _libr_util.r_spaces_new
r_spaces_new.restype = ctypes.POINTER(struct_r_spaces_t)
r_spaces_new.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_spaces_init = _libr_util.r_spaces_init
r_spaces_init.restype = ctypes.c_bool
r_spaces_init.argtypes = [ctypes.POINTER(struct_r_spaces_t), ctypes.POINTER(ctypes.c_char)]
r_spaces_fini = _libr_util.r_spaces_fini
r_spaces_fini.restype = None
r_spaces_fini.argtypes = [ctypes.POINTER(struct_r_spaces_t)]
r_spaces_free = _libr_util.r_spaces_free
r_spaces_free.restype = None
r_spaces_free.argtypes = [ctypes.POINTER(struct_r_spaces_t)]
r_spaces_purge = _libr_util.r_spaces_purge
r_spaces_purge.restype = None
r_spaces_purge.argtypes = [ctypes.POINTER(struct_r_spaces_t)]
r_spaces_get = _libr_util.r_spaces_get
r_spaces_get.restype = ctypes.POINTER(struct_r_space_t)
r_spaces_get.argtypes = [ctypes.POINTER(struct_r_spaces_t), ctypes.POINTER(ctypes.c_char)]
r_spaces_add = _libr_util.r_spaces_add
r_spaces_add.restype = ctypes.POINTER(struct_r_space_t)
r_spaces_add.argtypes = [ctypes.POINTER(struct_r_spaces_t), ctypes.POINTER(ctypes.c_char)]
r_spaces_set = _libr_util.r_spaces_set
r_spaces_set.restype = ctypes.POINTER(struct_r_space_t)
r_spaces_set.argtypes = [ctypes.POINTER(struct_r_spaces_t), ctypes.POINTER(ctypes.c_char)]
r_spaces_unset = _libr_util.r_spaces_unset
r_spaces_unset.restype = ctypes.c_bool
r_spaces_unset.argtypes = [ctypes.POINTER(struct_r_spaces_t), ctypes.POINTER(ctypes.c_char)]
r_spaces_rename = _libr_util.r_spaces_rename
r_spaces_rename.restype = ctypes.c_bool
r_spaces_rename.argtypes = [ctypes.POINTER(struct_r_spaces_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_spaces_count = _libr_util.r_spaces_count
r_spaces_count.restype = ctypes.c_int32
r_spaces_count.argtypes = [ctypes.POINTER(struct_r_spaces_t), ctypes.POINTER(ctypes.c_char)]
r_spaces_push = _libr_util.r_spaces_push
r_spaces_push.restype = ctypes.c_bool
r_spaces_push.argtypes = [ctypes.POINTER(struct_r_spaces_t), ctypes.POINTER(ctypes.c_char)]
r_spaces_pop = _libr_util.r_spaces_pop
r_spaces_pop.restype = ctypes.c_bool
r_spaces_pop.argtypes = [ctypes.POINTER(struct_r_spaces_t)]
r_spaces_current = _libraries['FIXME_STUB'].r_spaces_current
r_spaces_current.restype = ctypes.POINTER(struct_r_space_t)
r_spaces_current.argtypes = [ctypes.POINTER(struct_r_spaces_t)]
r_spaces_current_name = _libraries['FIXME_STUB'].r_spaces_current_name
r_spaces_current_name.restype = ctypes.POINTER(ctypes.c_char)
r_spaces_current_name.argtypes = [ctypes.POINTER(struct_r_spaces_t)]
r_spaces_is_empty = _libraries['FIXME_STUB'].r_spaces_is_empty
r_spaces_is_empty.restype = ctypes.c_bool
r_spaces_is_empty.argtypes = [ctypes.POINTER(struct_r_spaces_t)]
RSpaceIter = struct_r_rb_iter_t
ret_ascii_table = _libr_util.ret_ascii_table
ret_ascii_table.restype = ctypes.POINTER(ctypes.c_char)
ret_ascii_table.argtypes = []
class struct_c__SA_RStrpool(Structure):
    pass

struct_c__SA_RStrpool._pack_ = 1 # source:False
struct_c__SA_RStrpool._fields_ = [
    ('str', ctypes.POINTER(ctypes.c_char)),
    ('len', ctypes.c_int32),
    ('size', ctypes.c_int32),
]

RStrpool = struct_c__SA_RStrpool
r_strpool_new = _libr_util.r_strpool_new
r_strpool_new.restype = ctypes.POINTER(struct_c__SA_RStrpool)
r_strpool_new.argtypes = [ctypes.c_int32]
r_strpool_alloc = _libr_util.r_strpool_alloc
r_strpool_alloc.restype = ctypes.POINTER(ctypes.c_char)
r_strpool_alloc.argtypes = [ctypes.POINTER(struct_c__SA_RStrpool), ctypes.c_int32]
r_strpool_memcat = _libr_util.r_strpool_memcat
r_strpool_memcat.restype = ctypes.c_int32
r_strpool_memcat.argtypes = [ctypes.POINTER(struct_c__SA_RStrpool), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_strpool_ansi_chop = _libr_util.r_strpool_ansi_chop
r_strpool_ansi_chop.restype = ctypes.c_int32
r_strpool_ansi_chop.argtypes = [ctypes.POINTER(struct_c__SA_RStrpool), ctypes.c_int32]
r_strpool_append = _libr_util.r_strpool_append
r_strpool_append.restype = ctypes.c_int32
r_strpool_append.argtypes = [ctypes.POINTER(struct_c__SA_RStrpool), ctypes.POINTER(ctypes.c_char)]
r_strpool_free = _libr_util.r_strpool_free
r_strpool_free.restype = None
r_strpool_free.argtypes = [ctypes.POINTER(struct_c__SA_RStrpool)]
r_strpool_fit = _libr_util.r_strpool_fit
r_strpool_fit.restype = ctypes.c_int32
r_strpool_fit.argtypes = [ctypes.POINTER(struct_c__SA_RStrpool)]
r_strpool_get = _libr_util.r_strpool_get
r_strpool_get.restype = ctypes.POINTER(ctypes.c_char)
r_strpool_get.argtypes = [ctypes.POINTER(struct_c__SA_RStrpool), ctypes.c_int32]
r_strpool_get_i = _libr_util.r_strpool_get_i
r_strpool_get_i.restype = ctypes.POINTER(ctypes.c_char)
r_strpool_get_i.argtypes = [ctypes.POINTER(struct_c__SA_RStrpool), ctypes.c_int32]
r_strpool_get_index = _libr_util.r_strpool_get_index
r_strpool_get_index.restype = ctypes.c_int32
r_strpool_get_index.argtypes = [ctypes.POINTER(struct_c__SA_RStrpool), ctypes.POINTER(ctypes.c_char)]
r_strpool_next = _libr_util.r_strpool_next
r_strpool_next.restype = ctypes.POINTER(ctypes.c_char)
r_strpool_next.argtypes = [ctypes.POINTER(struct_c__SA_RStrpool), ctypes.c_int32]
r_strpool_slice = _libr_util.r_strpool_slice
r_strpool_slice.restype = ctypes.POINTER(ctypes.c_char)
r_strpool_slice.argtypes = [ctypes.POINTER(struct_c__SA_RStrpool), ctypes.c_int32]
r_strpool_empty = _libr_util.r_strpool_empty
r_strpool_empty.restype = ctypes.POINTER(ctypes.c_char)
r_strpool_empty.argtypes = [ctypes.POINTER(struct_c__SA_RStrpool)]
class struct_r_tree_node_t(Structure):
    pass

class struct_r_tree_t(Structure):
    pass

struct_r_tree_node_t._pack_ = 1 # source:False
struct_r_tree_node_t._fields_ = [
    ('parent', ctypes.POINTER(struct_r_tree_node_t)),
    ('tree', ctypes.POINTER(struct_r_tree_t)),
    ('children', ctypes.POINTER(struct_r_list_t)),
    ('n_children', ctypes.c_uint32),
    ('depth', ctypes.c_int32),
    ('free', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
    ('data', ctypes.POINTER(None)),
]

RTreeNode = struct_r_tree_node_t
struct_r_tree_t._pack_ = 1 # source:False
struct_r_tree_t._fields_ = [
    ('root', ctypes.POINTER(struct_r_tree_node_t)),
]

RTree = struct_r_tree_t
class struct_r_tree_visitor_t(Structure):
    pass

struct_r_tree_visitor_t._pack_ = 1 # source:False
struct_r_tree_visitor_t._fields_ = [
    ('pre_visit', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_tree_node_t), ctypes.POINTER(struct_r_tree_visitor_t))),
    ('post_visit', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_tree_node_t), ctypes.POINTER(struct_r_tree_visitor_t))),
    ('discover_child', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_tree_node_t), ctypes.POINTER(struct_r_tree_visitor_t))),
    ('data', ctypes.POINTER(None)),
]

RTreeVisitor = struct_r_tree_visitor_t
RTreeNodeVisitCb = ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_tree_node_t), ctypes.POINTER(struct_r_tree_visitor_t))
r_tree_new = _libr_util.r_tree_new
r_tree_new.restype = ctypes.POINTER(struct_r_tree_t)
r_tree_new.argtypes = []
r_tree_add_node = _libr_util.r_tree_add_node
r_tree_add_node.restype = ctypes.POINTER(struct_r_tree_node_t)
r_tree_add_node.argtypes = [ctypes.POINTER(struct_r_tree_t), ctypes.POINTER(struct_r_tree_node_t), ctypes.POINTER(None)]
r_tree_reset = _libr_util.r_tree_reset
r_tree_reset.restype = None
r_tree_reset.argtypes = [ctypes.POINTER(struct_r_tree_t)]
r_tree_free = _libr_util.r_tree_free
r_tree_free.restype = None
r_tree_free.argtypes = [ctypes.POINTER(struct_r_tree_t)]
r_tree_dfs = _libr_util.r_tree_dfs
r_tree_dfs.restype = None
r_tree_dfs.argtypes = [ctypes.POINTER(struct_r_tree_t), ctypes.POINTER(struct_r_tree_visitor_t)]
r_tree_bfs = _libr_util.r_tree_bfs
r_tree_bfs.restype = None
r_tree_bfs.argtypes = [ctypes.POINTER(struct_r_tree_t), ctypes.POINTER(struct_r_tree_visitor_t)]
r_uleb128 = _libr_util.r_uleb128
r_uleb128.restype = ctypes.POINTER(ctypes.c_ubyte)
r_uleb128.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
r_uleb128_decode = _libr_util.r_uleb128_decode
r_uleb128_decode.restype = ctypes.POINTER(ctypes.c_ubyte)
r_uleb128_decode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_uint64)]
r_uleb128_len = _libr_util.r_uleb128_len
r_uleb128_len.restype = ctypes.c_int32
r_uleb128_len.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_uleb128_encode = _libr_util.r_uleb128_encode
r_uleb128_encode.restype = ctypes.POINTER(ctypes.c_ubyte)
r_uleb128_encode.argtypes = [ctypes.c_uint64, ctypes.POINTER(ctypes.c_int32)]
r_leb128 = _libr_util.r_leb128
r_leb128.restype = ctypes.POINTER(ctypes.c_ubyte)
r_leb128.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_int64)]
r_sleb128 = _libr_util.r_sleb128
r_sleb128.restype = ctypes.c_int64
r_sleb128.argtypes = [ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)), ctypes.POINTER(ctypes.c_ubyte)]
read_u32_leb128 = _libr_util.read_u32_leb128
read_u32_leb128.restype = size_t
read_u32_leb128.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_uint32)]
read_i32_leb128 = _libr_util.read_i32_leb128
read_i32_leb128.restype = size_t
read_i32_leb128.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_int32)]
read_u64_leb128 = _libr_util.read_u64_leb128
read_u64_leb128.restype = size_t
read_u64_leb128.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_uint64)]
read_i64_leb128 = _libr_util.read_i64_leb128
read_i64_leb128.restype = size_t
read_i64_leb128.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_int64)]
class struct_c__SA_RUtfBlock(Structure):
    pass

struct_c__SA_RUtfBlock._pack_ = 1 # source:False
struct_c__SA_RUtfBlock._fields_ = [
    ('from', ctypes.c_uint32),
    ('to', ctypes.c_uint32),
    ('name', ctypes.POINTER(ctypes.c_char)),
]

RUtfBlock = struct_c__SA_RUtfBlock
RRune = ctypes.c_uint32
r_utf8_encode = _libr_util.r_utf8_encode
r_utf8_encode.restype = ctypes.c_int32
r_utf8_encode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), RRune]
r_utf8_decode = _libr_util.r_utf8_decode
r_utf8_decode.restype = ctypes.c_int32
r_utf8_decode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_uint32)]
r_utf8_encode_str = _libr_util.r_utf8_encode_str
r_utf8_encode_str.restype = ctypes.c_int32
r_utf8_encode_str.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_utf8_size = _libr_util.r_utf8_size
r_utf8_size.restype = ctypes.c_int32
r_utf8_size.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
r_utf8_strlen = _libr_util.r_utf8_strlen
r_utf8_strlen.restype = ctypes.c_int32
r_utf8_strlen.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
r_isprint = _libr_util.r_isprint
r_isprint.restype = ctypes.c_int32
r_isprint.argtypes = [RRune]
r_utf16_to_utf8_l = _libraries['FIXME_STUB'].r_utf16_to_utf8_l
r_utf16_to_utf8_l.restype = ctypes.POINTER(ctypes.c_char)
r_utf16_to_utf8_l.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.c_int32]
r_utf_block_name = _libr_util.r_utf_block_name
r_utf_block_name.restype = ctypes.POINTER(ctypes.c_char)
r_utf_block_name.argtypes = [ctypes.c_int32]
r_utf8_to_utf16_l = _libraries['FIXME_STUB'].r_utf8_to_utf16_l
r_utf8_to_utf16_l.restype = ctypes.POINTER(ctypes.c_int32)
r_utf8_to_utf16_l.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_utf_block_idx = _libr_util.r_utf_block_idx
r_utf_block_idx.restype = ctypes.c_int32
r_utf_block_idx.argtypes = [RRune]
r_utf_block_list = _libr_util.r_utf_block_list
r_utf_block_list.restype = ctypes.POINTER(ctypes.c_int32)
r_utf_block_list.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_int32))]

# values for enumeration 'c__EA_RStrEnc'
c__EA_RStrEnc__enumvalues = {
    97: 'R_STRING_ENC_LATIN1',
    56: 'R_STRING_ENC_UTF8',
    117: 'R_STRING_ENC_UTF16LE',
    85: 'R_STRING_ENC_UTF32LE',
    98: 'R_STRING_ENC_UTF16BE',
    66: 'R_STRING_ENC_UTF32BE',
    103: 'R_STRING_ENC_GUESS',
}
R_STRING_ENC_LATIN1 = 97
R_STRING_ENC_UTF8 = 56
R_STRING_ENC_UTF16LE = 117
R_STRING_ENC_UTF32LE = 85
R_STRING_ENC_UTF16BE = 98
R_STRING_ENC_UTF32BE = 66
R_STRING_ENC_GUESS = 103
c__EA_RStrEnc = ctypes.c_uint32 # enum
RStrEnc = c__EA_RStrEnc
RStrEnc__enumvalues = c__EA_RStrEnc__enumvalues
r_utf_bom_encoding = _libr_util.r_utf_bom_encoding
r_utf_bom_encoding.restype = RStrEnc
r_utf_bom_encoding.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_utf16_decode = _libr_util.r_utf16_decode
r_utf16_decode.restype = ctypes.c_int32
r_utf16_decode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_bool]
r_utf16le_decode = _libr_util.r_utf16le_decode
r_utf16le_decode.restype = ctypes.c_int32
r_utf16le_decode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_uint32)]
r_utf16be_decode = _libr_util.r_utf16be_decode
r_utf16be_decode.restype = ctypes.c_int32
r_utf16be_decode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_uint32)]
r_utf16le_encode = _libr_util.r_utf16le_encode
r_utf16le_encode.restype = ctypes.c_int32
r_utf16le_encode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), RRune]
r_utf32_decode = _libr_util.r_utf32_decode
r_utf32_decode.restype = ctypes.c_int32
r_utf32_decode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_bool]
r_utf32le_decode = _libr_util.r_utf32le_decode
r_utf32le_decode.restype = ctypes.c_int32
r_utf32le_decode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_uint32)]
class struct_r_id_pool_t(Structure):
    pass

struct_r_id_pool_t._pack_ = 1 # source:False
struct_r_id_pool_t._fields_ = [
    ('start_id', ctypes.c_uint32),
    ('last_id', ctypes.c_uint32),
    ('next_id', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('freed_ids', ctypes.POINTER(struct_r_queue_t)),
]

RIDPool = struct_r_id_pool_t
r_id_pool_new = _libr_util.r_id_pool_new
r_id_pool_new.restype = ctypes.POINTER(struct_r_id_pool_t)
r_id_pool_new.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
r_id_pool_grab_id = _libr_util.r_id_pool_grab_id
r_id_pool_grab_id.restype = ctypes.c_bool
r_id_pool_grab_id.argtypes = [ctypes.POINTER(struct_r_id_pool_t), ctypes.POINTER(ctypes.c_uint32)]
r_id_pool_kick_id = _libr_util.r_id_pool_kick_id
r_id_pool_kick_id.restype = ctypes.c_bool
r_id_pool_kick_id.argtypes = [ctypes.POINTER(struct_r_id_pool_t), ctypes.c_uint32]
r_id_pool_free = _libr_util.r_id_pool_free
r_id_pool_free.restype = None
r_id_pool_free.argtypes = [ctypes.POINTER(struct_r_id_pool_t)]
class struct_r_id_storage_t(Structure):
    pass

struct_r_id_storage_t._pack_ = 1 # source:False
struct_r_id_storage_t._fields_ = [
    ('pool', ctypes.POINTER(struct_r_id_pool_t)),
    ('data', ctypes.POINTER(ctypes.POINTER(None))),
    ('top_id', ctypes.c_uint32),
    ('size', ctypes.c_uint32),
]

RIDStorage = struct_r_id_storage_t
RIDStorageForeachCb = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(None), ctypes.POINTER(None), ctypes.c_uint32)
ROIDStorageCompareCb = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(ctypes.c_int32))
r_id_storage_new = _libr_util.r_id_storage_new
r_id_storage_new.restype = ctypes.POINTER(struct_r_id_storage_t)
r_id_storage_new.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
r_id_storage_set = _libr_util.r_id_storage_set
r_id_storage_set.restype = ctypes.c_bool
r_id_storage_set.argtypes = [ctypes.POINTER(struct_r_id_storage_t), ctypes.POINTER(None), ctypes.c_uint32]
r_id_storage_add = _libr_util.r_id_storage_add
r_id_storage_add.restype = ctypes.c_bool
r_id_storage_add.argtypes = [ctypes.POINTER(struct_r_id_storage_t), ctypes.POINTER(None), ctypes.POINTER(ctypes.c_uint32)]
r_id_storage_get = _libr_util.r_id_storage_get
r_id_storage_get.restype = ctypes.POINTER(None)
r_id_storage_get.argtypes = [ctypes.POINTER(struct_r_id_storage_t), ctypes.c_uint32]
r_id_storage_get_next = _libr_util.r_id_storage_get_next
r_id_storage_get_next.restype = ctypes.c_bool
r_id_storage_get_next.argtypes = [ctypes.POINTER(struct_r_id_storage_t), ctypes.POINTER(ctypes.c_uint32)]
r_id_storage_get_prev = _libr_util.r_id_storage_get_prev
r_id_storage_get_prev.restype = ctypes.c_bool
r_id_storage_get_prev.argtypes = [ctypes.POINTER(struct_r_id_storage_t), ctypes.POINTER(ctypes.c_uint32)]
r_id_storage_delete = _libr_util.r_id_storage_delete
r_id_storage_delete.restype = None
r_id_storage_delete.argtypes = [ctypes.POINTER(struct_r_id_storage_t), ctypes.c_uint32]
r_id_storage_take = _libr_util.r_id_storage_take
r_id_storage_take.restype = ctypes.POINTER(None)
r_id_storage_take.argtypes = [ctypes.POINTER(struct_r_id_storage_t), ctypes.c_uint32]
r_id_storage_foreach = _libr_util.r_id_storage_foreach
r_id_storage_foreach.restype = ctypes.c_bool
r_id_storage_foreach.argtypes = [ctypes.POINTER(struct_r_id_storage_t), RIDStorageForeachCb, ctypes.POINTER(None)]
r_id_storage_free = _libr_util.r_id_storage_free
r_id_storage_free.restype = None
r_id_storage_free.argtypes = [ctypes.POINTER(struct_r_id_storage_t)]
r_id_storage_list = _libr_util.r_id_storage_list
r_id_storage_list.restype = ctypes.POINTER(struct_r_list_t)
r_id_storage_list.argtypes = [ctypes.POINTER(struct_r_id_storage_t)]
r_id_storage_get_lowest = _libr_util.r_id_storage_get_lowest
r_id_storage_get_lowest.restype = ctypes.c_bool
r_id_storage_get_lowest.argtypes = [ctypes.POINTER(struct_r_id_storage_t), ctypes.POINTER(ctypes.c_uint32)]
r_id_storage_get_highest = _libr_util.r_id_storage_get_highest
r_id_storage_get_highest.restype = ctypes.c_bool
r_id_storage_get_highest.argtypes = [ctypes.POINTER(struct_r_id_storage_t), ctypes.POINTER(ctypes.c_uint32)]
class struct_r_ordered_id_storage_t(Structure):
    pass

struct_r_ordered_id_storage_t._pack_ = 1 # source:False
struct_r_ordered_id_storage_t._fields_ = [
    ('permutation', ctypes.POINTER(ctypes.c_uint32)),
    ('psize', ctypes.c_uint32),
    ('ptop', ctypes.c_uint32),
    ('data', ctypes.POINTER(struct_r_id_storage_t)),
    ('cmp', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(ctypes.c_int32))),
]

ROIDStorage = struct_r_ordered_id_storage_t
r_oids_new = _libr_util.r_oids_new
r_oids_new.restype = ctypes.POINTER(struct_r_ordered_id_storage_t)
r_oids_new.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
r_oids_get = _libr_util.r_oids_get
r_oids_get.restype = ctypes.POINTER(None)
r_oids_get.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), ctypes.c_uint32]
r_oids_oget = _libr_util.r_oids_oget
r_oids_oget.restype = ctypes.POINTER(None)
r_oids_oget.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), ctypes.c_uint32]
r_oids_get_id = _libr_util.r_oids_get_id
r_oids_get_id.restype = ctypes.c_bool
r_oids_get_id.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
r_oids_get_od = _libr_util.r_oids_get_od
r_oids_get_od.restype = ctypes.c_bool
r_oids_get_od.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
r_oids_to_front = _libr_util.r_oids_to_front
r_oids_to_front.restype = ctypes.c_bool
r_oids_to_front.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), ctypes.c_uint32]
r_oids_to_rear = _libr_util.r_oids_to_rear
r_oids_to_rear.restype = ctypes.c_bool
r_oids_to_rear.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), ctypes.c_uint32]
r_oids_delete = _libr_util.r_oids_delete
r_oids_delete.restype = None
r_oids_delete.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), ctypes.c_uint32]
r_oids_odelete = _libr_util.r_oids_odelete
r_oids_odelete.restype = None
r_oids_odelete.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), ctypes.c_uint32]
r_oids_free = _libr_util.r_oids_free
r_oids_free.restype = None
r_oids_free.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t)]
r_oids_add = _libr_util.r_oids_add
r_oids_add.restype = ctypes.c_bool
r_oids_add.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), ctypes.POINTER(None), ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
r_oids_take = _libr_util.r_oids_take
r_oids_take.restype = ctypes.POINTER(None)
r_oids_take.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), ctypes.c_uint32]
r_oids_otake = _libr_util.r_oids_otake
r_oids_otake.restype = ctypes.POINTER(None)
r_oids_otake.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), ctypes.c_uint32]
r_oids_foreach = _libr_util.r_oids_foreach
r_oids_foreach.restype = ctypes.c_bool
r_oids_foreach.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), RIDStorageForeachCb, ctypes.POINTER(None)]
r_oids_foreach_prev = _libr_util.r_oids_foreach_prev
r_oids_foreach_prev.restype = ctypes.c_bool
r_oids_foreach_prev.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), RIDStorageForeachCb, ctypes.POINTER(None)]
r_oids_insert = _libr_util.r_oids_insert
r_oids_insert.restype = ctypes.c_bool
r_oids_insert.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), ctypes.POINTER(None), ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(None)]
r_oids_sort = _libr_util.r_oids_sort
r_oids_sort.restype = ctypes.c_bool
r_oids_sort.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), ctypes.POINTER(None)]
r_oids_find = _libr_util.r_oids_find
r_oids_find.restype = ctypes.c_uint32
r_oids_find.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), ctypes.POINTER(None), ctypes.POINTER(None)]
r_oids_last = _libr_util.r_oids_last
r_oids_last.restype = ctypes.POINTER(None)
r_oids_last.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t)]
r_oids_first = _libr_util.r_oids_first
r_oids_first.restype = ctypes.POINTER(None)
r_oids_first.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t)]
class struct_r_asn1_string_t(Structure):
    pass

struct_r_asn1_string_t._pack_ = 1 # source:False
struct_r_asn1_string_t._fields_ = [
    ('length', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('string', ctypes.POINTER(ctypes.c_char)),
    ('allocated', ctypes.c_bool),
    ('PADDING_1', ctypes.c_ubyte * 7),
]

RASN1String = struct_r_asn1_string_t
class struct_r_asn1_list_t(Structure):
    pass

class struct_r_asn1_object_t(Structure):
    pass

struct_r_asn1_list_t._pack_ = 1 # source:False
struct_r_asn1_list_t._fields_ = [
    ('length', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('objects', ctypes.POINTER(ctypes.POINTER(struct_r_asn1_object_t))),
]

struct_r_asn1_object_t._pack_ = 1 # source:False
struct_r_asn1_object_t._fields_ = [
    ('klass', ctypes.c_ubyte),
    ('form', ctypes.c_ubyte),
    ('tag', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte * 5),
    ('sector', ctypes.POINTER(ctypes.c_ubyte)),
    ('length', ctypes.c_uint32),
    ('PADDING_1', ctypes.c_ubyte * 4),
    ('offset', ctypes.c_uint64),
    ('list', struct_r_asn1_list_t),
]

ASN1List = struct_r_asn1_list_t
class struct_r_asn1_bin_t(Structure):
    pass

struct_r_asn1_bin_t._pack_ = 1 # source:False
struct_r_asn1_bin_t._fields_ = [
    ('length', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('binary', ctypes.POINTER(ctypes.c_ubyte)),
]

RASN1Binary = struct_r_asn1_bin_t
RASN1Object = struct_r_asn1_object_t
r_asn1_create_object = _libr_util.r_asn1_create_object
r_asn1_create_object.restype = ctypes.POINTER(struct_r_asn1_object_t)
r_asn1_create_object.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32, ctypes.POINTER(ctypes.c_ubyte)]
r_asn1_create_binary = _libr_util.r_asn1_create_binary
r_asn1_create_binary.restype = ctypes.POINTER(struct_r_asn1_bin_t)
r_asn1_create_binary.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32]
r_asn1_create_string = _libr_util.r_asn1_create_string
r_asn1_create_string.restype = ctypes.POINTER(struct_r_asn1_string_t)
r_asn1_create_string.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_bool, ctypes.c_uint32]
r_asn1_stringify_bits = _libr_util.r_asn1_stringify_bits
r_asn1_stringify_bits.restype = ctypes.POINTER(struct_r_asn1_string_t)
r_asn1_stringify_bits.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32]
r_asn1_stringify_utctime = _libr_util.r_asn1_stringify_utctime
r_asn1_stringify_utctime.restype = ctypes.POINTER(struct_r_asn1_string_t)
r_asn1_stringify_utctime.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32]
r_asn1_stringify_time = _libr_util.r_asn1_stringify_time
r_asn1_stringify_time.restype = ctypes.POINTER(struct_r_asn1_string_t)
r_asn1_stringify_time.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32]
r_asn1_stringify_integer = _libr_util.r_asn1_stringify_integer
r_asn1_stringify_integer.restype = ctypes.POINTER(struct_r_asn1_string_t)
r_asn1_stringify_integer.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32]
r_asn1_stringify_string = _libr_util.r_asn1_stringify_string
r_asn1_stringify_string.restype = ctypes.POINTER(struct_r_asn1_string_t)
r_asn1_stringify_string.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32]
r_asn1_stringify_bytes = _libr_util.r_asn1_stringify_bytes
r_asn1_stringify_bytes.restype = ctypes.POINTER(struct_r_asn1_string_t)
r_asn1_stringify_bytes.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32]
r_asn1_stringify_boolean = _libr_util.r_asn1_stringify_boolean
r_asn1_stringify_boolean.restype = ctypes.POINTER(struct_r_asn1_string_t)
r_asn1_stringify_boolean.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32]
r_asn1_stringify_oid = _libr_util.r_asn1_stringify_oid
r_asn1_stringify_oid.restype = ctypes.POINTER(struct_r_asn1_string_t)
r_asn1_stringify_oid.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32]
r_asn1_free_object = _libr_util.r_asn1_free_object
r_asn1_free_object.restype = None
r_asn1_free_object.argtypes = [ctypes.POINTER(struct_r_asn1_object_t)]
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

r_asn1_to_string = _libr_util.r_asn1_to_string
r_asn1_to_string.restype = ctypes.POINTER(ctypes.c_char)
r_asn1_to_string.argtypes = [ctypes.POINTER(struct_r_asn1_object_t), ctypes.c_uint32, ctypes.POINTER(struct_c__SA_RStrBuf)]
r_asn1_free_string = _libr_util.r_asn1_free_string
r_asn1_free_string.restype = None
r_asn1_free_string.argtypes = [ctypes.POINTER(struct_r_asn1_string_t)]
r_asn1_free_binary = _libr_util.r_asn1_free_binary
r_asn1_free_binary.restype = None
r_asn1_free_binary.argtypes = [ctypes.POINTER(struct_r_asn1_bin_t)]
asn1_setformat = _libr_util.asn1_setformat
asn1_setformat.restype = None
asn1_setformat.argtypes = [ctypes.c_int32]
class struct_r_x509_validity_t(Structure):
    pass

struct_r_x509_validity_t._pack_ = 1 # source:False
struct_r_x509_validity_t._fields_ = [
    ('notBefore', ctypes.POINTER(struct_r_asn1_string_t)),
    ('notAfter', ctypes.POINTER(struct_r_asn1_string_t)),
]

RX509Validity = struct_r_x509_validity_t
class struct_r_x509_name_t(Structure):
    pass

struct_r_x509_name_t._pack_ = 1 # source:False
struct_r_x509_name_t._fields_ = [
    ('length', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('oids', ctypes.POINTER(ctypes.POINTER(struct_r_asn1_string_t))),
    ('names', ctypes.POINTER(ctypes.POINTER(struct_r_asn1_string_t))),
]

RX509Name = struct_r_x509_name_t
class struct_r_x509_algorithmidentifier_t(Structure):
    pass

struct_r_x509_algorithmidentifier_t._pack_ = 1 # source:False
struct_r_x509_algorithmidentifier_t._fields_ = [
    ('algorithm', ctypes.POINTER(struct_r_asn1_string_t)),
    ('parameters', ctypes.POINTER(struct_r_asn1_string_t)),
]

RX509AlgorithmIdentifier = struct_r_x509_algorithmidentifier_t
class struct_r_x509_authoritykeyidentifier_t(Structure):
    pass

struct_r_x509_authoritykeyidentifier_t._pack_ = 1 # source:False
struct_r_x509_authoritykeyidentifier_t._fields_ = [
    ('keyIdentifier', ctypes.POINTER(struct_r_asn1_bin_t)),
    ('authorityCertIssuer', RX509Name),
    ('authorityCertSerialNumber', ctypes.POINTER(struct_r_asn1_bin_t)),
]

RX509AuthorityKeyIdentifier = struct_r_x509_authoritykeyidentifier_t
class struct_r_x509_subjectpublickeyinfo_t(Structure):
    pass

struct_r_x509_subjectpublickeyinfo_t._pack_ = 1 # source:False
struct_r_x509_subjectpublickeyinfo_t._fields_ = [
    ('algorithm', RX509AlgorithmIdentifier),
    ('subjectPublicKey', ctypes.POINTER(struct_r_asn1_bin_t)),
    ('subjectPublicKeyExponent', ctypes.POINTER(struct_r_asn1_bin_t)),
    ('subjectPublicKeyModule', ctypes.POINTER(struct_r_asn1_bin_t)),
]

RX509SubjectPublicKeyInfo = struct_r_x509_subjectpublickeyinfo_t
class struct_r_x509_extension_t(Structure):
    pass

struct_r_x509_extension_t._pack_ = 1 # source:False
struct_r_x509_extension_t._fields_ = [
    ('extnID', ctypes.POINTER(struct_r_asn1_string_t)),
    ('critical', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
    ('extnValue', ctypes.POINTER(struct_r_asn1_bin_t)),
]

RX509Extension = struct_r_x509_extension_t
class struct_r_x509_extensions_t(Structure):
    pass

struct_r_x509_extensions_t._pack_ = 1 # source:False
struct_r_x509_extensions_t._fields_ = [
    ('length', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('extensions', ctypes.POINTER(ctypes.POINTER(struct_r_x509_extension_t))),
]

RX509Extensions = struct_r_x509_extensions_t
class struct_r_x509_tbscertificate_t(Structure):
    pass

struct_r_x509_tbscertificate_t._pack_ = 1 # source:False
struct_r_x509_tbscertificate_t._fields_ = [
    ('version', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('serialNumber', ctypes.POINTER(struct_r_asn1_string_t)),
    ('signature', RX509AlgorithmIdentifier),
    ('issuer', RX509Name),
    ('validity', RX509Validity),
    ('subject', RX509Name),
    ('subjectPublicKeyInfo', RX509SubjectPublicKeyInfo),
    ('issuerUniqueID', ctypes.POINTER(struct_r_asn1_bin_t)),
    ('subjectUniqueID', ctypes.POINTER(struct_r_asn1_bin_t)),
    ('extensions', RX509Extensions),
]

RX509TBSCertificate = struct_r_x509_tbscertificate_t
class struct_r_x509_certificate_t(Structure):
    pass

struct_r_x509_certificate_t._pack_ = 1 # source:False
struct_r_x509_certificate_t._fields_ = [
    ('tbsCertificate', RX509TBSCertificate),
    ('algorithmIdentifier', RX509AlgorithmIdentifier),
    ('signature', ctypes.POINTER(struct_r_asn1_bin_t)),
]

RX509Certificate = struct_r_x509_certificate_t
class struct_r_x509_crlentry(Structure):
    pass

struct_r_x509_crlentry._pack_ = 1 # source:False
struct_r_x509_crlentry._fields_ = [
    ('userCertificate', ctypes.POINTER(struct_r_asn1_bin_t)),
    ('revocationDate', ctypes.POINTER(struct_r_asn1_string_t)),
]

RX509CRLEntry = struct_r_x509_crlentry
class struct_r_x509_certificaterevocationlist(Structure):
    pass

struct_r_x509_certificaterevocationlist._pack_ = 1 # source:False
struct_r_x509_certificaterevocationlist._fields_ = [
    ('signature', RX509AlgorithmIdentifier),
    ('issuer', RX509Name),
    ('lastUpdate', ctypes.POINTER(struct_r_asn1_string_t)),
    ('nextUpdate', ctypes.POINTER(struct_r_asn1_string_t)),
    ('length', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('revokedCertificates', ctypes.POINTER(ctypes.POINTER(struct_r_x509_crlentry))),
]

RX509CertificateRevocationList = struct_r_x509_certificaterevocationlist
r_x509_parse_crl = _libr_util.r_x509_parse_crl
r_x509_parse_crl.restype = ctypes.POINTER(struct_r_x509_certificaterevocationlist)
r_x509_parse_crl.argtypes = [ctypes.POINTER(struct_r_asn1_object_t)]
r_x509_crl_to_string = _libr_util.r_x509_crl_to_string
r_x509_crl_to_string.restype = ctypes.POINTER(ctypes.c_char)
r_x509_crl_to_string.argtypes = [ctypes.POINTER(struct_r_x509_certificaterevocationlist), ctypes.POINTER(ctypes.c_char)]
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

r_x509_crl_json = _libr_util.r_x509_crl_json
r_x509_crl_json.restype = None
r_x509_crl_json.argtypes = [ctypes.POINTER(struct_pj_t), ctypes.POINTER(struct_r_x509_certificaterevocationlist)]
r_x509_parse_certificate = _libr_util.r_x509_parse_certificate
r_x509_parse_certificate.restype = ctypes.POINTER(struct_r_x509_certificate_t)
r_x509_parse_certificate.argtypes = [ctypes.POINTER(struct_r_asn1_object_t)]
r_x509_parse_certificate2 = _libr_util.r_x509_parse_certificate2
r_x509_parse_certificate2.restype = ctypes.POINTER(struct_r_x509_certificate_t)
r_x509_parse_certificate2.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32]
r_x509_free_certificate = _libr_util.r_x509_free_certificate
r_x509_free_certificate.restype = None
r_x509_free_certificate.argtypes = [ctypes.POINTER(struct_r_x509_certificate_t)]
r_x509_certificate_to_string = _libraries['FIXME_STUB'].r_x509_certificate_to_string
r_x509_certificate_to_string.restype = ctypes.POINTER(ctypes.c_char)
r_x509_certificate_to_string.argtypes = [ctypes.POINTER(struct_r_x509_certificate_t), ctypes.POINTER(ctypes.c_char)]
r_x509_certificate_json = _libr_util.r_x509_certificate_json
r_x509_certificate_json.restype = None
r_x509_certificate_json.argtypes = [ctypes.POINTER(struct_pj_t), ctypes.POINTER(struct_r_x509_certificate_t)]
r_x509_certificate_dump = _libr_util.r_x509_certificate_dump
r_x509_certificate_dump.restype = None
r_x509_certificate_dump.argtypes = [ctypes.POINTER(struct_r_x509_certificate_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_c__SA_RStrBuf)]
class struct_r_pkcs7_certificaterevocationlists_t(Structure):
    pass

struct_r_pkcs7_certificaterevocationlists_t._pack_ = 1 # source:False
struct_r_pkcs7_certificaterevocationlists_t._fields_ = [
    ('length', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('elements', ctypes.POINTER(ctypes.POINTER(struct_r_x509_certificaterevocationlist))),
]

RPKCS7CertificateRevocationLists = struct_r_pkcs7_certificaterevocationlists_t
class struct_r_pkcs7_extendedcertificatesandcertificates_t(Structure):
    pass

struct_r_pkcs7_extendedcertificatesandcertificates_t._pack_ = 1 # source:False
struct_r_pkcs7_extendedcertificatesandcertificates_t._fields_ = [
    ('length', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('elements', ctypes.POINTER(ctypes.POINTER(struct_r_x509_certificate_t))),
]

RPKCS7ExtendedCertificatesAndCertificates = struct_r_pkcs7_extendedcertificatesandcertificates_t
class struct_r_pkcs7_digestalgorithmidentifiers_t(Structure):
    pass

struct_r_pkcs7_digestalgorithmidentifiers_t._pack_ = 1 # source:False
struct_r_pkcs7_digestalgorithmidentifiers_t._fields_ = [
    ('length', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('elements', ctypes.POINTER(ctypes.POINTER(struct_r_x509_algorithmidentifier_t))),
]

RPKCS7DigestAlgorithmIdentifiers = struct_r_pkcs7_digestalgorithmidentifiers_t
class struct_r_pkcs7_contentinfo_t(Structure):
    pass

struct_r_pkcs7_contentinfo_t._pack_ = 1 # source:False
struct_r_pkcs7_contentinfo_t._fields_ = [
    ('contentType', ctypes.POINTER(struct_r_asn1_string_t)),
    ('content', ctypes.POINTER(struct_r_asn1_bin_t)),
]

RPKCS7ContentInfo = struct_r_pkcs7_contentinfo_t
class struct_r_pkcs7_issuerandserialnumber_t(Structure):
    pass

struct_r_pkcs7_issuerandserialnumber_t._pack_ = 1 # source:False
struct_r_pkcs7_issuerandserialnumber_t._fields_ = [
    ('issuer', RX509Name),
    ('serialNumber', ctypes.POINTER(struct_r_asn1_bin_t)),
]

RPKCS7IssuerAndSerialNumber = struct_r_pkcs7_issuerandserialnumber_t
class struct_r_pkcs7_attribute_t(Structure):
    pass

struct_r_pkcs7_attribute_t._pack_ = 1 # source:False
struct_r_pkcs7_attribute_t._fields_ = [
    ('oid', ctypes.POINTER(struct_r_asn1_string_t)),
    ('data', ctypes.POINTER(struct_r_asn1_bin_t)),
]

RPKCS7Attribute = struct_r_pkcs7_attribute_t
class struct_r_pkcs7_attributes_t(Structure):
    pass

struct_r_pkcs7_attributes_t._pack_ = 1 # source:False
struct_r_pkcs7_attributes_t._fields_ = [
    ('length', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('elements', ctypes.POINTER(ctypes.POINTER(struct_r_pkcs7_attribute_t))),
]

RPKCS7Attributes = struct_r_pkcs7_attributes_t
class struct_r_pkcs7_signerinfo_t(Structure):
    pass

struct_r_pkcs7_signerinfo_t._pack_ = 1 # source:False
struct_r_pkcs7_signerinfo_t._fields_ = [
    ('version', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('issuerAndSerialNumber', RPKCS7IssuerAndSerialNumber),
    ('digestAlgorithm', RX509AlgorithmIdentifier),
    ('authenticatedAttributes', RPKCS7Attributes),
    ('digestEncryptionAlgorithm', RX509AlgorithmIdentifier),
    ('encryptedDigest', ctypes.POINTER(struct_r_asn1_bin_t)),
    ('unauthenticatedAttributes', RPKCS7Attributes),
]

RPKCS7SignerInfo = struct_r_pkcs7_signerinfo_t
class struct_r_pkcs7_signerinfos_t(Structure):
    pass

struct_r_pkcs7_signerinfos_t._pack_ = 1 # source:False
struct_r_pkcs7_signerinfos_t._fields_ = [
    ('length', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('elements', ctypes.POINTER(ctypes.POINTER(struct_r_pkcs7_signerinfo_t))),
]

RPKCS7SignerInfos = struct_r_pkcs7_signerinfos_t
class struct_r_pkcs7_signeddata_t(Structure):
    pass

struct_r_pkcs7_signeddata_t._pack_ = 1 # source:False
struct_r_pkcs7_signeddata_t._fields_ = [
    ('version', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('digestAlgorithms', RPKCS7DigestAlgorithmIdentifiers),
    ('contentInfo', RPKCS7ContentInfo),
    ('certificates', RPKCS7ExtendedCertificatesAndCertificates),
    ('crls', RPKCS7CertificateRevocationLists),
    ('signerinfos', RPKCS7SignerInfos),
]

RPKCS7SignedData = struct_r_pkcs7_signeddata_t
class struct_r_pkcs7_container_t(Structure):
    pass

struct_r_pkcs7_container_t._pack_ = 1 # source:False
struct_r_pkcs7_container_t._fields_ = [
    ('contentType', ctypes.POINTER(struct_r_asn1_string_t)),
    ('signedData', RPKCS7SignedData),
]

RCMS = struct_r_pkcs7_container_t
class struct_c__SA_SpcAttributeTypeAndOptionalValue(Structure):
    pass

struct_c__SA_SpcAttributeTypeAndOptionalValue._pack_ = 1 # source:False
struct_c__SA_SpcAttributeTypeAndOptionalValue._fields_ = [
    ('type', ctypes.POINTER(struct_r_asn1_string_t)),
    ('data', ctypes.POINTER(struct_r_asn1_bin_t)),
]

SpcAttributeTypeAndOptionalValue = struct_c__SA_SpcAttributeTypeAndOptionalValue
class struct_c__SA_SpcDigestInfo(Structure):
    pass

struct_c__SA_SpcDigestInfo._pack_ = 1 # source:False
struct_c__SA_SpcDigestInfo._fields_ = [
    ('digestAlgorithm', RX509AlgorithmIdentifier),
    ('digest', ctypes.POINTER(struct_r_asn1_bin_t)),
]

SpcDigestInfo = struct_c__SA_SpcDigestInfo
class struct_c__SA_SpcIndirectDataContent(Structure):
    _pack_ = 1 # source:False
    _fields_ = [
    ('data', SpcAttributeTypeAndOptionalValue),
    ('messageDigest', SpcDigestInfo),
     ]

SpcIndirectDataContent = struct_c__SA_SpcIndirectDataContent
r_pkcs7_parse_cms = _libr_util.r_pkcs7_parse_cms
r_pkcs7_parse_cms.restype = ctypes.POINTER(struct_r_pkcs7_container_t)
r_pkcs7_parse_cms.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32]
r_pkcs7_free_cms = _libr_util.r_pkcs7_free_cms
r_pkcs7_free_cms.restype = None
r_pkcs7_free_cms.argtypes = [ctypes.POINTER(struct_r_pkcs7_container_t)]
r_pkcs7_cms_to_string = _libr_util.r_pkcs7_cms_to_string
r_pkcs7_cms_to_string.restype = ctypes.POINTER(ctypes.c_char)
r_pkcs7_cms_to_string.argtypes = [ctypes.POINTER(struct_r_pkcs7_container_t)]
r_pkcs7_cms_json = _libr_util.r_pkcs7_cms_json
r_pkcs7_cms_json.restype = ctypes.POINTER(struct_pj_t)
r_pkcs7_cms_json.argtypes = [ctypes.POINTER(struct_r_pkcs7_container_t)]
r_pkcs7_parse_spcinfo = _libr_util.r_pkcs7_parse_spcinfo
r_pkcs7_parse_spcinfo.restype = ctypes.POINTER(struct_c__SA_SpcIndirectDataContent)
r_pkcs7_parse_spcinfo.argtypes = [ctypes.POINTER(struct_r_pkcs7_container_t)]
r_pkcs7_free_spcinfo = _libr_util.r_pkcs7_free_spcinfo
r_pkcs7_free_spcinfo.restype = None
r_pkcs7_free_spcinfo.argtypes = [ctypes.POINTER(struct_c__SA_SpcIndirectDataContent)]
r_protobuf_decode = _libr_util.r_protobuf_decode
r_protobuf_decode.restype = ctypes.POINTER(ctypes.c_char)
r_protobuf_decode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64, ctypes.c_bool]
r_axml_decode = _libr_util.r_axml_decode
r_axml_decode.restype = ctypes.POINTER(ctypes.c_char)
r_axml_decode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64]

# values for enumeration 'r_json_type_t'
r_json_type_t__enumvalues = {
    0: 'R_JSON_NULL',
    1: 'R_JSON_OBJECT',
    2: 'R_JSON_ARRAY',
    3: 'R_JSON_STRING',
    4: 'R_JSON_INTEGER',
    5: 'R_JSON_DOUBLE',
    6: 'R_JSON_BOOLEAN',
}
R_JSON_NULL = 0
R_JSON_OBJECT = 1
R_JSON_ARRAY = 2
R_JSON_STRING = 3
R_JSON_INTEGER = 4
R_JSON_DOUBLE = 5
R_JSON_BOOLEAN = 6
r_json_type_t = ctypes.c_uint32 # enum
RJsonType = r_json_type_t
RJsonType__enumvalues = r_json_type_t__enumvalues
class struct_r_json_t(Structure):
    pass

class union_r_json_t_0(Union):
    pass

class struct_r_json_t_0_1(Structure):
    pass

struct_r_json_t_0_1._pack_ = 1 # source:False
struct_r_json_t_0_1._fields_ = [
    ('count', ctypes.c_uint64),
    ('first', ctypes.POINTER(struct_r_json_t)),
    ('last', ctypes.POINTER(struct_r_json_t)),
]

class struct_r_json_t_0_0(Structure):
    pass

class union_r_json_t_0_0_0(Union):
    pass

union_r_json_t_0_0_0._pack_ = 1 # source:False
union_r_json_t_0_0_0._fields_ = [
    ('u_value', ctypes.c_uint64),
    ('s_value', ctypes.c_int64),
]

struct_r_json_t_0_0._pack_ = 1 # source:False
struct_r_json_t_0_0._anonymous_ = ('_0',)
struct_r_json_t_0_0._fields_ = [
    ('_0', union_r_json_t_0_0_0),
    ('dbl_value', ctypes.c_double),
]

union_r_json_t_0._pack_ = 1 # source:False
union_r_json_t_0._anonymous_ = ('_0', '_1',)
union_r_json_t_0._fields_ = [
    ('str_value', ctypes.POINTER(ctypes.c_char)),
    ('_0', struct_r_json_t_0_0),
    ('_1', struct_r_json_t_0_1),
]

struct_r_json_t._pack_ = 1 # source:False
struct_r_json_t._anonymous_ = ('_0',)
struct_r_json_t._fields_ = [
    ('type', RJsonType),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('key', ctypes.POINTER(ctypes.c_char)),
    ('_0', union_r_json_t_0),
    ('next', ctypes.POINTER(struct_r_json_t)),
]

RJson = struct_r_json_t
r_json_parse = _libr_util.r_json_parse
r_json_parse.restype = ctypes.POINTER(struct_r_json_t)
r_json_parse.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_json_free = _libr_util.r_json_free
r_json_free.restype = None
r_json_free.argtypes = [ctypes.POINTER(struct_r_json_t)]
r_json_get = _libr_util.r_json_get
r_json_get.restype = ctypes.POINTER(struct_r_json_t)
r_json_get.argtypes = [ctypes.POINTER(struct_r_json_t), ctypes.POINTER(ctypes.c_char)]
r_json_item = _libr_util.r_json_item
r_json_item.restype = ctypes.POINTER(struct_r_json_t)
r_json_item.argtypes = [ctypes.POINTER(struct_r_json_t), size_t]
class struct_r_anal_graph_node_info_t(Structure):
    pass

struct_r_anal_graph_node_info_t._pack_ = 1 # source:False
struct_r_anal_graph_node_info_t._fields_ = [
    ('title', ctypes.POINTER(ctypes.c_char)),
    ('body', ctypes.POINTER(ctypes.c_char)),
    ('offset', ctypes.c_uint64),
]

RGraphNodeInfo = struct_r_anal_graph_node_info_t
r_graph_free_node_info = _libr_util.r_graph_free_node_info
r_graph_free_node_info.restype = None
r_graph_free_node_info.argtypes = [ctypes.POINTER(None)]
r_graph_create_node_info = _libr_util.r_graph_create_node_info
r_graph_create_node_info.restype = ctypes.POINTER(struct_r_anal_graph_node_info_t)
r_graph_create_node_info.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64]
class struct_r_graph_node_t(Structure):
    pass

struct_r_graph_node_t._pack_ = 1 # source:False
struct_r_graph_node_t._fields_ = [
    ('idx', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('data', ctypes.POINTER(None)),
    ('out_nodes', ctypes.POINTER(struct_r_list_t)),
    ('in_nodes', ctypes.POINTER(struct_r_list_t)),
    ('all_neighbours', ctypes.POINTER(struct_r_list_t)),
    ('free', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
]

class struct_r_graph_t(Structure):
    pass

struct_r_graph_t._pack_ = 1 # source:False
struct_r_graph_t._fields_ = [
    ('n_nodes', ctypes.c_uint32),
    ('n_edges', ctypes.c_uint32),
    ('last_index', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('nodes', ctypes.POINTER(struct_r_list_t)),
]

r_graph_add_node_info = _libr_util.r_graph_add_node_info
r_graph_add_node_info.restype = ctypes.POINTER(struct_r_graph_node_t)
r_graph_add_node_info.argtypes = [ctypes.POINTER(struct_r_graph_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64]
r_graph_drawable_to_dot = _libr_util.r_graph_drawable_to_dot
r_graph_drawable_to_dot.restype = ctypes.POINTER(ctypes.c_char)
r_graph_drawable_to_dot.argtypes = [ctypes.POINTER(struct_r_graph_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_graph_drawable_to_json = _libr_util.r_graph_drawable_to_json
r_graph_drawable_to_json.restype = None
r_graph_drawable_to_json.argtypes = [ctypes.POINTER(struct_r_graph_t), ctypes.POINTER(struct_pj_t), ctypes.c_bool]
class struct_c__SA_RBraile(Structure):
    pass

struct_c__SA_RBraile._pack_ = 1 # source:False
struct_c__SA_RBraile._fields_ = [
    ('str', ctypes.c_char * 4),
]

RBraile = struct_c__SA_RBraile
r_print_braile = _libr_util.r_print_braile
r_print_braile.restype = RBraile
r_print_braile.argtypes = [ctypes.c_int32]
RPrintZoomCallback = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.c_int32, ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64)
RPrintNameCallback = ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.c_uint64)
RPrintSizeCallback = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.c_uint64)
RPrintCommentCallback = ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.c_uint64)
RPrintSectionGet = ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.c_uint64)
RPrintColorFor = ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.c_uint64, ctypes.c_bool)
RPrintHasRefs = ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.c_uint64, ctypes.c_int32)
class struct_r_print_zoom_t(Structure):
    pass

struct_r_print_zoom_t._pack_ = 1 # source:False
struct_r_print_zoom_t._fields_ = [
    ('buf', ctypes.POINTER(ctypes.c_ubyte)),
    ('from', ctypes.c_uint64),
    ('to', ctypes.c_uint64),
    ('size', ctypes.c_int32),
    ('mode', ctypes.c_int32),
]

RPrintZoom = struct_r_print_zoom_t
class struct_r_print_t(Structure):
    pass

class struct_r_cons_t(Structure):
    pass

class struct_r_reg_t(Structure):
    pass

class struct_r_num_t(Structure):
    pass

class struct_r_charset_t(Structure):
    pass

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

class struct_r_reg_item_t(Structure):
    pass

struct_r_print_t._pack_ = 1 # source:False
struct_r_print_t._fields_ = [
    ('user', ctypes.POINTER(None)),
    ('iob', struct_r_io_bind_t),
    ('pava', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
    ('coreb', struct_r_core_bind_t),
    ('cfmt', ctypes.POINTER(ctypes.c_char)),
    ('datefmt', ctypes.c_char * 32),
    ('datezone', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
    ('write', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)),
    ('cb_printf', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_char))),
    ('cb_eprintf', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_char))),
    ('cb_color', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32, ctypes.c_bool)),
    ('scr_prompt', ctypes.c_bool),
    ('PADDING_2', ctypes.c_ubyte * 7),
    ('disasm', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.c_uint64)),
    ('oprintf', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_char))),
    ('big_endian', ctypes.c_int32),
    ('width', ctypes.c_int32),
    ('limit', ctypes.c_int32),
    ('bits', ctypes.c_int32),
    ('histblock', ctypes.c_bool),
    ('cur_enabled', ctypes.c_bool),
    ('PADDING_3', ctypes.c_ubyte * 2),
    ('cur', ctypes.c_int32),
    ('ocur', ctypes.c_int32),
    ('cols', ctypes.c_int32),
    ('flags', ctypes.c_int32),
    ('seggrn', ctypes.c_int32),
    ('use_comments', ctypes.c_bool),
    ('PADDING_4', ctypes.c_ubyte * 3),
    ('addrmod', ctypes.c_int32),
    ('col', ctypes.c_int32),
    ('stride', ctypes.c_int32),
    ('bytespace', ctypes.c_int32),
    ('pairs', ctypes.c_int32),
    ('resetbg', ctypes.c_bool),
    ('PADDING_5', ctypes.c_ubyte * 7),
    ('zoom', ctypes.POINTER(struct_r_print_zoom_t)),
    ('offname', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.c_uint64)),
    ('offsize', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.c_uint64)),
    ('colorfor', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.c_uint64, ctypes.c_bool)),
    ('hasrefs', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.c_uint64, ctypes.c_int32)),
    ('get_comments', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.c_uint64)),
    ('get_section_name', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.c_uint64)),
    ('formats', ctypes.POINTER(struct_sdb_t)),
    ('sdb_types', ctypes.POINTER(struct_sdb_t)),
    ('cons', ctypes.POINTER(struct_r_cons_t)),
    ('consbind', struct_r_cons_bind_t),
    ('num', ctypes.POINTER(struct_r_num_t)),
    ('reg', ctypes.POINTER(struct_r_reg_t)),
    ('get_register', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_reg_item_t), ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32)),
    ('get_register_value', ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(struct_r_reg_item_t))),
    ('exists_var', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_print_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_char))),
    ('lines_cache', ctypes.POINTER(ctypes.c_uint64)),
    ('lines_cache_sz', ctypes.c_int32),
    ('lines_abs', ctypes.c_int32),
    ('esc_bslash', ctypes.c_bool),
    ('wide_offsets', ctypes.c_bool),
    ('PADDING_6', ctypes.c_ubyte * 6),
    ('strconv_mode', ctypes.POINTER(ctypes.c_char)),
    ('vars', ctypes.POINTER(struct_r_list_t)),
    ('io_unalloc_ch', ctypes.c_char),
    ('show_offset', ctypes.c_bool),
    ('calc_row_offsets', ctypes.c_bool),
    ('PADDING_7', ctypes.c_ubyte * 5),
    ('row_offsets', ctypes.POINTER(ctypes.c_uint32)),
    ('row_offsets_sz', ctypes.c_int32),
    ('vflush', ctypes.c_bool),
    ('PADDING_8', ctypes.c_ubyte * 3),
    ('screen_bounds', ctypes.c_uint64),
    ('enable_progressbar', ctypes.c_bool),
    ('PADDING_9', ctypes.c_ubyte * 7),
    ('charset', ctypes.POINTER(struct_r_charset_t)),
]

class struct_r_skyline_t(Structure):
    _pack_ = 1 # source:False
    _fields_ = [
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

struct_r_io_map_t._pack_ = 1 # source:False
struct_r_io_map_t._fields_ = [
    ('fd', ctypes.c_int32),
    ('perm', ctypes.c_int32),
    ('id', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('itv', RInterval),
    ('delta', ctypes.c_uint64),
    ('name', ctypes.POINTER(ctypes.c_char)),
]

class struct_r_cons_context_t(Structure):
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

class struct_c__SA_RConsCursorPos(Structure):
    pass

struct_c__SA_RConsCursorPos._pack_ = 1 # source:False
struct_c__SA_RConsCursorPos._fields_ = [
    ('x', ctypes.c_int32),
    ('y', ctypes.c_int32),
]

struct_r_cons_t._pack_ = 1 # source:False
struct_r_cons_t._fields_ = [
    ('context', ctypes.POINTER(struct_r_cons_context_t)),
    ('lastline', ctypes.POINTER(ctypes.c_char)),
    ('is_html', ctypes.c_bool),
    ('was_html', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 2),
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
    ('PADDING_1', ctypes.c_ubyte * 3),
    ('noflush', ctypes.c_int32),
    ('show_autocomplete_widget', ctypes.c_bool),
    ('PADDING_2', ctypes.c_ubyte * 7),
    ('fdin', ctypes.POINTER(struct__IO_FILE)),
    ('fdout', ctypes.c_int32),
    ('PADDING_3', ctypes.c_ubyte * 4),
    ('teefile', ctypes.POINTER(ctypes.c_char)),
    ('user_fgets', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.c_int32)),
    ('event_resize', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
    ('event_data', ctypes.POINTER(None)),
    ('mouse_event', ctypes.c_int32),
    ('PADDING_4', ctypes.c_ubyte * 4),
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
    ('PADDING_5', ctypes.c_ubyte * 4),
    ('highlight', ctypes.POINTER(ctypes.c_char)),
    ('enable_highlight', ctypes.c_bool),
    ('PADDING_6', ctypes.c_ubyte * 3),
    ('null', ctypes.c_int32),
    ('mouse', ctypes.c_int32),
    ('is_wine', ctypes.c_int32),
    ('line', ctypes.POINTER(struct_r_line_t)),
    ('vline', ctypes.POINTER(ctypes.POINTER(ctypes.c_char))),
    ('refcnt', ctypes.c_int32),
    ('newline', ctypes.c_bool),
    ('PADDING_7', ctypes.c_ubyte * 3),
    ('vtmode', ctypes.c_int32),
    ('flush', ctypes.c_bool),
    ('use_utf8', ctypes.c_bool),
    ('use_utf8_curvy', ctypes.c_bool),
    ('dotted_lines', ctypes.c_bool),
    ('linesleep', ctypes.c_int32),
    ('pagesize', ctypes.c_int32),
    ('break_word', ctypes.POINTER(ctypes.c_char)),
    ('break_word_len', ctypes.c_int32),
    ('PADDING_8', ctypes.c_ubyte * 4),
    ('timeout', ctypes.c_uint64),
    ('grep_color', ctypes.c_bool),
    ('grep_highlight', ctypes.c_bool),
    ('use_tts', ctypes.c_bool),
    ('filter', ctypes.c_bool),
    ('PADDING_9', ctypes.c_ubyte * 4),
    ('rgbstr', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64, ctypes.c_uint64)),
    ('click_set', ctypes.c_bool),
    ('PADDING_10', ctypes.c_ubyte * 3),
    ('click_x', ctypes.c_int32),
    ('click_y', ctypes.c_int32),
    ('show_vals', ctypes.c_bool),
    ('PADDING_11', ctypes.c_ubyte * 3),
    ('cpos', struct_c__SA_RConsCursorPos),
]

class struct_r_stack_t(Structure):
    pass

class struct_r_cons_palette_t(Structure):
    pass

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

struct_r_cons_palette_t._pack_ = 1 # source:False
struct_r_cons_palette_t._fields_ = [
    ('b0x00', struct_rcolor_t),
    ('b0x7f', struct_rcolor_t),
    ('b0xff', struct_rcolor_t),
    ('args', struct_rcolor_t),
    ('bin', struct_rcolor_t),
    ('btext', struct_rcolor_t),
    ('call', struct_rcolor_t),
    ('cjmp', struct_rcolor_t),
    ('cmp', struct_rcolor_t),
    ('comment', struct_rcolor_t),
    ('usercomment', struct_rcolor_t),
    ('creg', struct_rcolor_t),
    ('flag', struct_rcolor_t),
    ('fline', struct_rcolor_t),
    ('floc', struct_rcolor_t),
    ('flow', struct_rcolor_t),
    ('flow2', struct_rcolor_t),
    ('fname', struct_rcolor_t),
    ('help', struct_rcolor_t),
    ('input', struct_rcolor_t),
    ('invalid', struct_rcolor_t),
    ('jmp', struct_rcolor_t),
    ('label', struct_rcolor_t),
    ('math', struct_rcolor_t),
    ('mov', struct_rcolor_t),
    ('nop', struct_rcolor_t),
    ('num', struct_rcolor_t),
    ('offset', struct_rcolor_t),
    ('other', struct_rcolor_t),
    ('pop', struct_rcolor_t),
    ('prompt', struct_rcolor_t),
    ('push', struct_rcolor_t),
    ('crypto', struct_rcolor_t),
    ('reg', struct_rcolor_t),
    ('reset', struct_rcolor_t),
    ('ret', struct_rcolor_t),
    ('swi', struct_rcolor_t),
    ('trap', struct_rcolor_t),
    ('ucall', struct_rcolor_t),
    ('ujmp', struct_rcolor_t),
    ('ai_read', struct_rcolor_t),
    ('ai_write', struct_rcolor_t),
    ('ai_exec', struct_rcolor_t),
    ('ai_seq', struct_rcolor_t),
    ('ai_ascii', struct_rcolor_t),
    ('gui_cflow', struct_rcolor_t),
    ('gui_dataoffset', struct_rcolor_t),
    ('gui_background', struct_rcolor_t),
    ('gui_alt_background', struct_rcolor_t),
    ('gui_border', struct_rcolor_t),
    ('wordhl', struct_rcolor_t),
    ('linehl', struct_rcolor_t),
    ('func_var', struct_rcolor_t),
    ('func_var_type', struct_rcolor_t),
    ('func_var_addr', struct_rcolor_t),
    ('widget_bg', struct_rcolor_t),
    ('widget_sel', struct_rcolor_t),
    ('graph_box', struct_rcolor_t),
    ('graph_box2', struct_rcolor_t),
    ('graph_box3', struct_rcolor_t),
    ('graph_box4', struct_rcolor_t),
    ('graph_true', struct_rcolor_t),
    ('graph_false', struct_rcolor_t),
    ('graph_trufae', struct_rcolor_t),
    ('graph_traced', struct_rcolor_t),
    ('graph_current', struct_rcolor_t),
    ('graph_diff_match', struct_rcolor_t),
    ('graph_diff_unmatch', struct_rcolor_t),
    ('graph_diff_unknown', struct_rcolor_t),
    ('graph_diff_new', struct_rcolor_t),
]

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
    ('icase', ctypes.c_int32),
    ('PADDING_5', ctypes.c_ubyte * 4),
]

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
    ('grep', struct_r_cons_grep_t),
    ('cons_stack', ctypes.POINTER(struct_r_stack_t)),
    ('buffer', ctypes.POINTER(ctypes.c_char)),
    ('buffer_len', ctypes.c_uint64),
    ('buffer_sz', ctypes.c_uint64),
    ('error', ctypes.POINTER(struct_c__SA_RStrBuf)),
    ('errmode', ctypes.c_int32),
    ('breaked', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 3),
    ('break_stack', ctypes.POINTER(struct_r_stack_t)),
    ('event_interrupt', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
    ('event_interrupt_data', ctypes.POINTER(None)),
    ('cmd_depth', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
    ('log_callback', ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_uint32, r_log_level, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char))),
    ('lastOutput', ctypes.POINTER(ctypes.c_char)),
    ('lastLength', ctypes.c_int32),
    ('lastMode', ctypes.c_bool),
    ('lastEnabled', ctypes.c_bool),
    ('is_interactive', ctypes.c_bool),
    ('pageable', ctypes.c_bool),
    ('color_mode', ctypes.c_int32),
    ('cpal', struct_r_cons_palette_t),
    ('PADDING_2', ctypes.c_ubyte * 6),
    ('pal', struct_r_cons_printable_palette_t),
]

struct_r_stack_t._pack_ = 1 # source:False
struct_r_stack_t._fields_ = [
    ('elems', ctypes.POINTER(ctypes.POINTER(None))),
    ('n_elems', ctypes.c_uint32),
    ('top', ctypes.c_int32),
    ('free', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
]

class struct__IO_marker(Structure):
    pass

class struct__IO_wide_data(Structure):
    pass

class struct__IO_codecvt(Structure):
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


# values for enumeration 'c__EA_RNumCalcToken'
c__EA_RNumCalcToken__enumvalues = {
    0: 'RNCNAME',
    1: 'RNCNUMBER',
    2: 'RNCEND',
    3: 'RNCINC',
    4: 'RNCDEC',
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
class struct_c__SA_RNumCalcValue(Structure):
    pass

struct_c__SA_RNumCalcValue._pack_ = 1 # source:False
struct_c__SA_RNumCalcValue._fields_ = [
    ('d', ctypes.c_double),
    ('n', ctypes.c_uint64),
]

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

class struct_r_selection_widget_t(Structure):
    pass

class struct_r_hud_t(Structure):
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
class struct_r_line_comp_t(Structure):
    pass

class struct_r_line_buffer_t(Structure):
    pass

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
    ('echo', ctypes.c_int32),
    ('has_echo', ctypes.c_int32),
    ('prompt', ctypes.POINTER(ctypes.c_char)),
    ('kill_ring', ctypes.POINTER(struct_r_list_t)),
    ('kill_ring_ptr', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('clipboard', ctypes.POINTER(ctypes.c_char)),
    ('disable', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
    ('user', ctypes.POINTER(None)),
    ('hist_up', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None))),
    ('hist_down', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None))),
    ('contents', ctypes.POINTER(ctypes.c_char)),
    ('zerosep', ctypes.c_bool),
    ('enable_vi_mode', ctypes.c_bool),
    ('PADDING_2', ctypes.c_ubyte * 2),
    ('vi_mode', ctypes.c_int32),
    ('prompt_mode', ctypes.c_bool),
    ('PADDING_3', ctypes.c_ubyte * 3),
    ('prompt_type', c__EA_RLinePromptType),
    ('offset_hist_index', ctypes.c_int32),
    ('file_hist_index', ctypes.c_int32),
    ('hud', ctypes.POINTER(struct_r_hud_t)),
    ('sdbshell_hist', ctypes.POINTER(struct_r_list_t)),
    ('sdbshell_hist_iter', ctypes.POINTER(struct_r_list_iter_t)),
    ('vtmode', ctypes.c_int32),
    ('PADDING_4', ctypes.c_ubyte * 4),
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

class struct_r_reg_set_t(Structure):
    pass

class struct_r_reg_arena_t(Structure):
    pass

struct_r_reg_set_t._pack_ = 1 # source:False
struct_r_reg_set_t._fields_ = [
    ('arena', ctypes.POINTER(struct_r_reg_arena_t)),
    ('pool', ctypes.POINTER(struct_r_list_t)),
    ('regs', ctypes.POINTER(struct_r_list_t)),
    ('ht_regs', ctypes.POINTER(struct_ht_pp_t)),
    ('cur', ctypes.POINTER(struct_r_list_iter_t)),
    ('maskregstype', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

struct_r_reg_t._pack_ = 1 # source:False
struct_r_reg_t._fields_ = [
    ('profile', ctypes.POINTER(ctypes.c_char)),
    ('reg_profile_cmt', ctypes.POINTER(ctypes.c_char)),
    ('reg_profile_str', ctypes.POINTER(ctypes.c_char)),
    ('name', ctypes.POINTER(ctypes.c_char) * 25),
    ('regset', struct_r_reg_set_t * 8),
    ('allregs', ctypes.POINTER(struct_r_list_t)),
    ('roregs', ctypes.POINTER(struct_r_list_t)),
    ('iters', ctypes.c_int32),
    ('arch', ctypes.c_int32),
    ('bits', ctypes.c_int32),
    ('size', ctypes.c_int32),
    ('bits_default', ctypes.c_int32),
    ('is_thumb', ctypes.c_bool),
    ('big_endian', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 2),
]

struct_r_reg_arena_t._pack_ = 1 # source:False
struct_r_reg_arena_t._fields_ = [
    ('bytes', ctypes.POINTER(ctypes.c_ubyte)),
    ('size', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

struct_r_reg_item_t._pack_ = 1 # source:False
struct_r_reg_item_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('type', ctypes.c_int32),
    ('size', ctypes.c_int32),
    ('offset', ctypes.c_int32),
    ('packed_size', ctypes.c_int32),
    ('is_float', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
    ('flags', ctypes.POINTER(ctypes.c_char)),
    ('comment', ctypes.POINTER(ctypes.c_char)),
    ('index', ctypes.c_int32),
    ('arena', ctypes.c_int32),
]

class struct_r_charset_rune_t(Structure):
    pass

struct_r_charset_t._pack_ = 1 # source:False
struct_r_charset_t._fields_ = [
    ('db', ctypes.POINTER(struct_sdb_t)),
    ('db_char_to_hex', ctypes.POINTER(struct_sdb_t)),
    ('custom_charset', ctypes.POINTER(struct_r_charset_rune_t)),
    ('encode_maxkeylen', ctypes.c_uint64),
    ('decode_maxkeylen', ctypes.c_uint64),
]

struct_r_charset_rune_t._pack_ = 1 # source:False
struct_r_charset_rune_t._fields_ = [
    ('ch', ctypes.POINTER(ctypes.c_ubyte)),
    ('hx', ctypes.POINTER(ctypes.c_ubyte)),
    ('left', ctypes.POINTER(struct_r_charset_rune_t)),
    ('right', ctypes.POINTER(struct_r_charset_rune_t)),
]

RPrint = struct_r_print_t
RPrintIsInterruptedCallback = ctypes.CFUNCTYPE(ctypes.c_bool)
r_print_is_interrupted = _libr_util.r_print_is_interrupted
r_print_is_interrupted.restype = ctypes.c_bool
r_print_is_interrupted.argtypes = []
r_print_set_is_interrupted_cb = _libr_util.r_print_set_is_interrupted_cb
r_print_set_is_interrupted_cb.restype = None
r_print_set_is_interrupted_cb.argtypes = [RPrintIsInterruptedCallback]
r_print_hexpair = _libr_util.r_print_hexpair
r_print_hexpair.restype = ctypes.POINTER(ctypes.c_char)
r_print_hexpair.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_print_hex_from_bin = _libr_util.r_print_hex_from_bin
r_print_hex_from_bin.restype = None
r_print_hex_from_bin.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.POINTER(ctypes.c_char)]
r_print_new = _libr_util.r_print_new
r_print_new.restype = ctypes.POINTER(struct_r_print_t)
r_print_new.argtypes = []
r_print_free = _libr_util.r_print_free
r_print_free.restype = ctypes.POINTER(struct_r_print_t)
r_print_free.argtypes = [ctypes.POINTER(struct_r_print_t)]
r_print_mute = _libr_util.r_print_mute
r_print_mute.restype = ctypes.c_bool
r_print_mute.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.c_int32]
r_print_set_flags = _libr_util.r_print_set_flags
r_print_set_flags.restype = None
r_print_set_flags.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.c_int32]
r_print_unset_flags = _libr_util.r_print_unset_flags
r_print_unset_flags.restype = None
r_print_unset_flags.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.c_int32]
r_print_addr = _libr_util.r_print_addr
r_print_addr.restype = None
r_print_addr.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.c_uint64]
r_print_section = _libr_util.r_print_section
r_print_section.restype = None
r_print_section.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.c_uint64]
r_print_columns = _libr_util.r_print_columns
r_print_columns.restype = None
r_print_columns.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.c_int32]
r_print_hexii = _libr_util.r_print_hexii
r_print_hexii.restype = None
r_print_hexii.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.c_int32]
r_print_hexdump = _libr_util.r_print_hexdump
r_print_hexdump.restype = None
r_print_hexdump.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, size_t]
r_print_hexdump_simple = _libr_util.r_print_hexdump_simple
r_print_hexdump_simple.restype = None
r_print_hexdump_simple.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_print_jsondump = _libr_util.r_print_jsondump
r_print_jsondump.restype = ctypes.c_int32
r_print_jsondump.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.c_int32]
r_print_hexpairs = _libr_util.r_print_hexpairs
r_print_hexpairs.restype = None
r_print_hexpairs.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_print_hexdiff = _libr_util.r_print_hexdiff
r_print_hexdiff.restype = None
r_print_hexdiff.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.c_int32]
r_print_bytes = _libr_util.r_print_bytes
r_print_bytes.restype = None
r_print_bytes.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
r_print_fill = _libr_util.r_print_fill
r_print_fill.restype = None
r_print_fill.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.c_uint64, ctypes.c_int32]
r_print_byte = _libr_util.r_print_byte
r_print_byte.restype = None
r_print_byte.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_ubyte]
r_print_byte_color = _libr_util.r_print_byte_color
r_print_byte_color.restype = ctypes.POINTER(ctypes.c_char)
r_print_byte_color.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.c_int32]
r_print_c = _libr_util.r_print_c
r_print_c.restype = None
r_print_c.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_print_raw = _libr_util.r_print_raw
r_print_raw.restype = None
r_print_raw.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.c_int32]
r_print_have_cursor = _libr_util.r_print_have_cursor
r_print_have_cursor.restype = ctypes.c_bool
r_print_have_cursor.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.c_int32, ctypes.c_int32]
r_print_cursor_pointer = _libr_util.r_print_cursor_pointer
r_print_cursor_pointer.restype = ctypes.c_bool
r_print_cursor_pointer.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.c_int32, ctypes.c_int32]
r_print_cursor = _libr_util.r_print_cursor
r_print_cursor.restype = None
r_print_cursor.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
r_print_cursor_range = _libraries['FIXME_STUB'].r_print_cursor_range
r_print_cursor_range.restype = None
r_print_cursor_range.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
r_print_get_cursor = _libr_util.r_print_get_cursor
r_print_get_cursor.restype = ctypes.c_int32
r_print_get_cursor.argtypes = [ctypes.POINTER(struct_r_print_t)]
r_print_set_cursor = _libr_util.r_print_set_cursor
r_print_set_cursor.restype = None
r_print_set_cursor.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
r_print_code = _libr_util.r_print_code
r_print_code.restype = None
r_print_code.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.c_char]
r_print_format_struct_size = _libr_util.r_print_format_struct_size
r_print_format_struct_size.restype = ctypes.c_int32
r_print_format_struct_size.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32]
r_print_format = _libr_util.r_print_format
r_print_format.restype = ctypes.c_int32
r_print_format.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_print_format_byname = _libr_util.r_print_format_byname
r_print_format_byname.restype = ctypes.POINTER(ctypes.c_char)
r_print_format_byname.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.POINTER(ctypes.c_char)]
r_print_offset = _libr_core.r_print_offset
r_print_offset.restype = None
r_print_offset.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.c_uint64, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
r_print_offset_sg = _libr_core.r_print_offset_sg
r_print_offset_sg.restype = None
r_print_offset_sg.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.c_uint64, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
r_print_string = _libr_util.r_print_string
r_print_string.restype = ctypes.c_int32
r_print_string.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.c_int32]
r_print_date_dos = _libr_util.r_print_date_dos
r_print_date_dos.restype = ctypes.c_int32
r_print_date_dos.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_print_date_hfs = _libr_util.r_print_date_hfs
r_print_date_hfs.restype = ctypes.c_int32
r_print_date_hfs.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_print_date_w32 = _libr_util.r_print_date_w32
r_print_date_w32.restype = ctypes.c_int32
r_print_date_w32.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_print_date_unix = _libr_util.r_print_date_unix
r_print_date_unix.restype = ctypes.c_int32
r_print_date_unix.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_print_date_get_now = _libr_util.r_print_date_get_now
r_print_date_get_now.restype = ctypes.c_int32
r_print_date_get_now.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.POINTER(ctypes.c_char)]
r_print_zoom = _libr_util.r_print_zoom
r_print_zoom.restype = None
r_print_zoom.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.POINTER(None), RPrintZoomCallback, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int32, ctypes.c_int32]
r_print_zoom_buf = _libr_util.r_print_zoom_buf
r_print_zoom_buf.restype = None
r_print_zoom_buf.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.POINTER(None), RPrintZoomCallback, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int32, ctypes.c_int32]
r_print_progressbar = _libr_util.r_print_progressbar
r_print_progressbar.restype = None
r_print_progressbar.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.c_int32, ctypes.c_int32]
r_print_progressbar_with_count = _libr_util.r_print_progressbar_with_count
r_print_progressbar_with_count.restype = None
r_print_progressbar_with_count.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.c_uint32, ctypes.c_uint32, ctypes.c_int32, ctypes.c_bool]
r_print_portionbar = _libr_util.r_print_portionbar
r_print_portionbar.restype = None
r_print_portionbar.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.POINTER(ctypes.c_uint64), ctypes.c_int32]
r_print_rangebar = _libr_util.r_print_rangebar
r_print_rangebar.restype = None
r_print_rangebar.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int32]
r_print_randomart = _libr_util.r_print_randomart
r_print_randomart.restype = ctypes.POINTER(ctypes.c_char)
r_print_randomart.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32, ctypes.c_uint64]
r_print_2bpp_row = _libr_util.r_print_2bpp_row
r_print_2bpp_row.restype = None
r_print_2bpp_row.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
r_print_2bpp_tiles = _libr_util.r_print_2bpp_tiles
r_print_2bpp_tiles.restype = None
r_print_2bpp_tiles.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.POINTER(ctypes.c_ubyte), size_t, ctypes.c_uint32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
r_print_colorize_opcode = _libr_util.r_print_colorize_opcode
r_print_colorize_opcode.restype = ctypes.POINTER(ctypes.c_char)
r_print_colorize_opcode.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_bool, ctypes.c_uint64]
r_print_color_op_type = _libr_util.r_print_color_op_type
r_print_color_op_type.restype = ctypes.POINTER(ctypes.c_char)
r_print_color_op_type.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.c_uint32]
r_print_set_interrupted = _libraries['FIXME_STUB'].r_print_set_interrupted
r_print_set_interrupted.restype = None
r_print_set_interrupted.argtypes = [ctypes.c_int32]
r_print_init_rowoffsets = _libr_util.r_print_init_rowoffsets
r_print_init_rowoffsets.restype = None
r_print_init_rowoffsets.argtypes = [ctypes.POINTER(struct_r_print_t)]
r_print_rowoff = _libr_util.r_print_rowoff
r_print_rowoff.restype = ctypes.c_uint32
r_print_rowoff.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.c_int32]
r_print_set_rowoff = _libr_util.r_print_set_rowoff
r_print_set_rowoff.restype = None
r_print_set_rowoff.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.c_int32, ctypes.c_uint32, ctypes.c_bool]
r_print_row_at_off = _libr_util.r_print_row_at_off
r_print_row_at_off.restype = ctypes.c_int32
r_print_row_at_off.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.c_uint32]
r_print_pie = _libr_util.r_print_pie
r_print_pie.restype = ctypes.c_int32
r_print_pie.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.POINTER(ctypes.c_uint64), ctypes.c_int32, ctypes.c_int32]
r_print_rowlog = _libr_util.r_print_rowlog
r_print_rowlog.restype = ctypes.POINTER(ctypes.c_char)
r_print_rowlog.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.POINTER(ctypes.c_char)]
r_print_rowlog_done = _libr_util.r_print_rowlog_done
r_print_rowlog_done.restype = None
r_print_rowlog_done.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.POINTER(ctypes.c_char)]
r_print_graphline = _libr_util.r_print_graphline
r_print_graphline.restype = None
r_print_graphline.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.POINTER(ctypes.c_ubyte), size_t]
r_print_unpack7bit = _libr_util.r_print_unpack7bit
r_print_unpack7bit.restype = ctypes.c_int32
r_print_unpack7bit.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_print_pack7bit = _libr_util.r_print_pack7bit
r_print_pack7bit.restype = ctypes.c_int32
r_print_pack7bit.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_print_stereogram_bytes = _libr_util.r_print_stereogram_bytes
r_print_stereogram_bytes.restype = ctypes.POINTER(ctypes.c_char)
r_print_stereogram_bytes.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_print_stereogram = _libr_util.r_print_stereogram
r_print_stereogram.restype = ctypes.POINTER(ctypes.c_char)
r_print_stereogram.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32]
r_print_stereogram_print = _libr_util.r_print_stereogram_print
r_print_stereogram_print.restype = None
r_print_stereogram_print.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.POINTER(ctypes.c_char)]
r_print_set_screenbounds = _libr_util.r_print_set_screenbounds
r_print_set_screenbounds.restype = None
r_print_set_screenbounds.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.c_uint64]
r_util_lines_getline = _libr_util.r_util_lines_getline
r_util_lines_getline.restype = ctypes.c_int32
r_util_lines_getline.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.c_int32, ctypes.c_uint64]
r_print_json_indent = _libr_util.r_print_json_indent
r_print_json_indent.restype = ctypes.POINTER(ctypes.c_char)
r_print_json_indent.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_bool, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
r_print_json_human = _libr_util.r_print_json_human
r_print_json_human.restype = ctypes.POINTER(ctypes.c_char)
r_print_json_human.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_print_json_path = _libr_util.r_print_json_path
r_print_json_path.restype = ctypes.POINTER(ctypes.c_char)
r_print_json_path.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_util_version = _libr_util.r_util_version
r_util_version.restype = ctypes.POINTER(ctypes.c_char)
r_util_version.argtypes = []
__all__ = \
    ['ASN1List', 'LEVADD', 'LEVDEL', 'LEVEND', 'LEVNOP', 'LEVSUB',
    'PJEncodingNum', 'PJEncodingStr', 'PJ_ENCODING_NUM_DEFAULT',
    'PJ_ENCODING_NUM_HEX', 'PJ_ENCODING_NUM_STR',
    'PJ_ENCODING_STR_ARRAY', 'PJ_ENCODING_STR_BASE64',
    'PJ_ENCODING_STR_DEFAULT', 'PJ_ENCODING_STR_HEX',
    'PJ_ENCODING_STR_STRIP', 'PrintfCallback', 'RASN1Binary',
    'RASN1Object', 'RASN1String', 'RBComparator', 'RBIter', 'RBNode',
    'RBNodeFree', 'RBNodeSum', 'RBTree', 'RBinHeap', 'RBitmap',
    'RBraile', 'RBuffer', 'RBufferFini', 'RBufferFreeWholeBuf',
    'RBufferGetSize', 'RBufferGetWholeBuf', 'RBufferInit',
    'RBufferMethods', 'RBufferNonEmptyList', 'RBufferRead',
    'RBufferResize', 'RBufferSeek', 'RBufferSparse', 'RBufferWrite',
    'RCMS', 'RCache', 'RCalloc', 'RContRBCmp', 'RContRBFree',
    'RContRBNode', 'RContRBTree', 'RDiff', 'RDiffCallback',
    'RDiffChar', 'RDiffOp', 'REvent', 'REventCallback',
    'REventCallbackHandle', 'REventClass', 'REventClassAttr',
    'REventClassAttrRename', 'REventClassAttrSet',
    'REventClassRename', 'REventDebugProcessFinished',
    'REventIOWrite', 'REventMeta', 'REventType',
    'REventType__enumvalues', 'RFree', 'RGetopt', 'RGraphNodeInfo',
    'RIDPool', 'RIDStorage', 'RIDStorageForeachCb', 'RInterval',
    'RIntervalIterCb', 'RIntervalNode', 'RIntervalNodeFree',
    'RIntervalTree', 'RIntervalTreeIter', 'RJson', 'RJsonType',
    'RJsonType__enumvalues', 'RLevBuf', 'RLevMatches', 'RLevOp',
    'RLevOp__enumvalues', 'RListComparator', 'RListFree', 'RListInfo',
    'RMalloc', 'RNCAND', 'RNCASSIGN', 'RNCDEC', 'RNCDIV', 'RNCEND',
    'RNCINC', 'RNCLEFTP', 'RNCMINUS', 'RNCMOD', 'RNCMUL', 'RNCNAME',
    'RNCNEG', 'RNCNUMBER', 'RNCOR', 'RNCPLUS', 'RNCPRINT',
    'RNCRIGHTP', 'RNCROL', 'RNCROR', 'RNCSHL', 'RNCSHR', 'RNCXOR',
    'RNumBig', 'ROIDStorage', 'ROIDStorageCompareCb',
    'RPKCS7Attribute', 'RPKCS7Attributes',
    'RPKCS7CertificateRevocationLists', 'RPKCS7ContentInfo',
    'RPKCS7DigestAlgorithmIdentifiers',
    'RPKCS7ExtendedCertificatesAndCertificates',
    'RPKCS7IssuerAndSerialNumber', 'RPKCS7SignedData',
    'RPKCS7SignerInfo', 'RPKCS7SignerInfos', 'RPVectorComparator',
    'RPoolFactory', 'RPrint', 'RPrintColorFor',
    'RPrintCommentCallback', 'RPrintHasRefs',
    'RPrintIsInterruptedCallback', 'RPrintNameCallback',
    'RPrintSectionGet', 'RPrintSizeCallback', 'RPrintZoom',
    'RPrintZoomCallback', 'RProfile', 'RQueue', 'RRange',
    'RRangeItem', 'RRealloc', 'RRef', 'RRegex', 'RRegexMatch',
    'RRune', 'RSkipList', 'RSkipListNode', 'RSpace', 'RSpaceEvent',
    'RSpaceEventType', 'RSpaceEventType__enumvalues', 'RSpaceIter',
    'RSpaces', 'RStrEnc', 'RStrEnc__enumvalues', 'RStrpool',
    'RSysArch', 'RSysArch__enumvalues', 'RTable', 'RTableColumn',
    'RTableColumnType', 'RTableRow', 'RTableSelector', 'RThread',
    'RThreadCond', 'RThreadFunctionRet',
    'RThreadFunctionRet__enumvalues', 'RThreadLock', 'RThreadPool',
    'RThreadSemaphore', 'RTree', 'RTreeNode', 'RTreeNodeVisitCb',
    'RTreeVisitor', 'RTypeEnum', 'RTypeKind', 'RUtfBlock',
    'RX509AlgorithmIdentifier', 'RX509AuthorityKeyIdentifier',
    'RX509CRLEntry', 'RX509Certificate',
    'RX509CertificateRevocationList', 'RX509Extension',
    'RX509Extensions', 'RX509Name', 'RX509SubjectPublicKeyInfo',
    'RX509TBSCertificate', 'RX509Validity', 'R_EVENT_ALL',
    'R_EVENT_CLASS_ATTR_DEL', 'R_EVENT_CLASS_ATTR_RENAME',
    'R_EVENT_CLASS_ATTR_SET', 'R_EVENT_CLASS_DEL',
    'R_EVENT_CLASS_NEW', 'R_EVENT_CLASS_RENAME',
    'R_EVENT_DEBUG_PROCESS_FINISHED', 'R_EVENT_IO_WRITE',
    'R_EVENT_MAX', 'R_EVENT_META_CLEAR', 'R_EVENT_META_DEL',
    'R_EVENT_META_SET', 'R_JSON_ARRAY', 'R_JSON_BOOLEAN',
    'R_JSON_DOUBLE', 'R_JSON_INTEGER', 'R_JSON_NULL', 'R_JSON_OBJECT',
    'R_JSON_STRING', 'R_LINE_PROMPT_DEFAULT', 'R_LINE_PROMPT_FILE',
    'R_LINE_PROMPT_OFFSET', 'R_LOGLVL_DEBUG', 'R_LOGLVL_ERROR',
    'R_LOGLVL_FATAL', 'R_LOGLVL_INFO', 'R_LOGLVL_NONE',
    'R_LOGLVL_SILLY', 'R_LOGLVL_VERBOSE', 'R_LOGLVL_WARN',
    'R_SPACE_EVENT_COUNT', 'R_SPACE_EVENT_RENAME',
    'R_SPACE_EVENT_UNSET', 'R_STRING_ENC_GUESS',
    'R_STRING_ENC_LATIN1', 'R_STRING_ENC_UTF16BE',
    'R_STRING_ENC_UTF16LE', 'R_STRING_ENC_UTF32BE',
    'R_STRING_ENC_UTF32LE', 'R_STRING_ENC_UTF8', 'R_SYS_ARCH_8051',
    'R_SYS_ARCH_ARC', 'R_SYS_ARCH_ARM', 'R_SYS_ARCH_AVR',
    'R_SYS_ARCH_BF', 'R_SYS_ARCH_CR16', 'R_SYS_ARCH_CRIS',
    'R_SYS_ARCH_DALVIK', 'R_SYS_ARCH_EBC', 'R_SYS_ARCH_H8300',
    'R_SYS_ARCH_HPPA', 'R_SYS_ARCH_I8080', 'R_SYS_ARCH_JAVA',
    'R_SYS_ARCH_LM32', 'R_SYS_ARCH_M68K', 'R_SYS_ARCH_MIPS',
    'R_SYS_ARCH_MSIL', 'R_SYS_ARCH_MSP430', 'R_SYS_ARCH_NONE',
    'R_SYS_ARCH_OBJD', 'R_SYS_ARCH_PPC', 'R_SYS_ARCH_PROPELLER',
    'R_SYS_ARCH_RAR', 'R_SYS_ARCH_RISCV', 'R_SYS_ARCH_SH',
    'R_SYS_ARCH_SPARC', 'R_SYS_ARCH_SYSZ', 'R_SYS_ARCH_TMS320',
    'R_SYS_ARCH_V810', 'R_SYS_ARCH_V850', 'R_SYS_ARCH_X86',
    'R_SYS_ARCH_XAP', 'R_SYS_ARCH_XCORE', 'R_SYS_ARCH_Z80',
    'R_TABLE_ALIGN_CENTER', 'R_TABLE_ALIGN_LEFT',
    'R_TABLE_ALIGN_RIGHT', 'R_TH_FREED', 'R_TH_REPEAT', 'R_TH_STOP',
    'R_TYPE_BASIC', 'R_TYPE_ENUM', 'R_TYPE_STRUCT', 'R_TYPE_TYPEDEF',
    'R_TYPE_UNION', 'SpcAttributeTypeAndOptionalValue',
    'SpcDigestInfo', 'SpcIndirectDataContent', 'asn1_setformat',
    'c__EA_REventType', 'c__EA_RLevOp', 'c__EA_RLinePromptType',
    'c__EA_RNumCalcToken', 'c__EA_RSpaceEventType', 'c__EA_RStrEnc',
    'c__EA_RSysArch', 'c__EA_RThreadFunctionRet',
    'c__Ea_R_TABLE_ALIGN_LEFT', 'pthread_t', 'r_asctime_r',
    'r_asn1_create_binary', 'r_asn1_create_object',
    'r_asn1_create_string', 'r_asn1_free_binary',
    'r_asn1_free_object', 'r_asn1_free_string',
    'r_asn1_stringify_bits', 'r_asn1_stringify_boolean',
    'r_asn1_stringify_bytes', 'r_asn1_stringify_integer',
    'r_asn1_stringify_oid', 'r_asn1_stringify_string',
    'r_asn1_stringify_time', 'r_asn1_stringify_utctime',
    'r_asn1_to_string', 'r_axml_decode', 'r_base64_decode',
    'r_base64_decode_dyn', 'r_base64_encode', 'r_base64_encode_dyn',
    'r_base91_decode', 'r_base91_encode', 'r_big_add', 'r_big_and',
    'r_big_assign', 'r_big_cmp', 'r_big_dec', 'r_big_div',
    'r_big_divmod', 'r_big_fini', 'r_big_free', 'r_big_from_hexstr',
    'r_big_from_int', 'r_big_inc', 'r_big_init', 'r_big_is_zero',
    'r_big_isqrt', 'r_big_lshift', 'r_big_mod', 'r_big_mul',
    'r_big_new', 'r_big_or', 'r_big_powm', 'r_big_rshift',
    'r_big_sub', 'r_big_to_hexstr', 'r_big_to_int', 'r_big_xor',
    'r_binheap_clear', 'r_binheap_free', 'r_binheap_init',
    'r_binheap_new', 'r_binheap_pop', 'r_binheap_push',
    'r_bitmap_free', 'r_bitmap_new', 'r_bitmap_set',
    'r_bitmap_set_bytes', 'r_bitmap_test', 'r_bitmap_unset',
    'r_buf_append_buf', 'r_buf_append_buf_slice',
    'r_buf_append_bytes', 'r_buf_append_nbytes',
    'r_buf_append_string', 'r_buf_append_ut16', 'r_buf_append_ut32',
    'r_buf_append_ut64', 'r_buf_data', 'r_buf_dump', 'r_buf_fini',
    'r_buf_fread', 'r_buf_fread_at', 'r_buf_free', 'r_buf_fwrite',
    'r_buf_fwrite_at', 'r_buf_get_string', 'r_buf_insert_bytes',
    'r_buf_new', 'r_buf_new_empty', 'r_buf_new_file',
    'r_buf_new_mmap', 'r_buf_new_slice', 'r_buf_new_slurp',
    'r_buf_new_sparse', 'r_buf_new_with_buf', 'r_buf_new_with_bytes',
    'r_buf_new_with_io', 'r_buf_new_with_pointers',
    'r_buf_new_with_string', 'r_buf_nonempty_list',
    'r_buf_prepend_bytes', 'r_buf_read', 'r_buf_read8',
    'r_buf_read8_at', 'r_buf_read_at', 'r_buf_read_be16',
    'r_buf_read_be16_at', 'r_buf_read_be32', 'r_buf_read_be32_at',
    'r_buf_read_be64', 'r_buf_read_be64_at', 'r_buf_read_ble16_at',
    'r_buf_read_ble32_at', 'r_buf_read_ble64_at', 'r_buf_read_le16',
    'r_buf_read_le16_at', 'r_buf_read_le32', 'r_buf_read_le32_at',
    'r_buf_read_le64', 'r_buf_read_le64_at', 'r_buf_ref',
    'r_buf_resize', 'r_buf_seek', 'r_buf_set_bytes', 'r_buf_size',
    'r_buf_sleb128', 'r_buf_sleb128_at', 'r_buf_tell',
    'r_buf_to_string', 'r_buf_uleb128', 'r_buf_uleb128_at',
    'r_buf_write', 'r_buf_write_at', 'r_cache_flush', 'r_cache_free',
    'r_cache_get', 'r_cache_new', 'r_cache_set', 'r_ctime_r',
    'r_debruijn_offset', 'r_debruijn_pattern', 'r_diff_buffers',
    'r_diff_buffers_delta', 'r_diff_buffers_distance',
    'r_diff_buffers_distance_levenshtein',
    'r_diff_buffers_distance_myers', 'r_diff_buffers_radiff',
    'r_diff_buffers_static', 'r_diff_buffers_to_string',
    'r_diff_buffers_unified', 'r_diff_free', 'r_diff_gdiff',
    'r_diff_levenshtein_path', 'r_diff_lines', 'r_diff_new',
    'r_diff_new_from', 'r_diff_set_callback', 'r_diff_set_delta',
    'r_diff_version', 'r_diffchar_free', 'r_diffchar_new',
    'r_diffchar_print', 'r_event_free', 'r_event_hook', 'r_event_new',
    'r_event_send', 'r_event_unhook', 'r_free_aligned',
    'r_getopt_init', 'r_getopt_next', 'r_graph_add_node_info',
    'r_graph_create_node_info', 'r_graph_drawable_to_dot',
    'r_graph_drawable_to_json', 'r_graph_free_node_info',
    'r_id_pool_free', 'r_id_pool_grab_id', 'r_id_pool_kick_id',
    'r_id_pool_new', 'r_id_storage_add', 'r_id_storage_delete',
    'r_id_storage_foreach', 'r_id_storage_free', 'r_id_storage_get',
    'r_id_storage_get_highest', 'r_id_storage_get_lowest',
    'r_id_storage_get_next', 'r_id_storage_get_prev',
    'r_id_storage_list', 'r_id_storage_new', 'r_id_storage_set',
    'r_id_storage_take', 'r_interval_tree_all_at',
    'r_interval_tree_all_in', 'r_interval_tree_all_intersect',
    'r_interval_tree_at', 'r_interval_tree_delete',
    'r_interval_tree_fini', 'r_interval_tree_first_at',
    'r_interval_tree_init', 'r_interval_tree_insert',
    'r_interval_tree_iter_get', 'r_interval_tree_node_at',
    'r_interval_tree_node_at_data', 'r_interval_tree_resize',
    'r_isprint', 'r_itv_begin', 'r_itv_contain', 'r_itv_end',
    'r_itv_eq', 'r_itv_free', 'r_itv_include', 'r_itv_intersect',
    'r_itv_new', 'r_itv_overlap', 'r_itv_overlap2', 'r_itv_size',
    'r_itv_t', 'r_json_free', 'r_json_get', 'r_json_item',
    'r_json_parse', 'r_json_type_t', 'r_leb128', 'r_log_level',
    'r_malloc_aligned', 'r_name_check', 'r_name_filter',
    'r_name_filter2', 'r_name_filter_flag', 'r_name_filter_print',
    'r_name_filter_ro', 'r_name_validate_char',
    'r_name_validate_first', 'r_name_validate_print', 'r_new_copy',
    'r_oids_add', 'r_oids_delete', 'r_oids_find', 'r_oids_first',
    'r_oids_foreach', 'r_oids_foreach_prev', 'r_oids_free',
    'r_oids_get', 'r_oids_get_id', 'r_oids_get_od', 'r_oids_insert',
    'r_oids_last', 'r_oids_new', 'r_oids_odelete', 'r_oids_oget',
    'r_oids_otake', 'r_oids_sort', 'r_oids_take', 'r_oids_to_front',
    'r_oids_to_rear', 'r_pkcs7_cms_json', 'r_pkcs7_cms_to_string',
    'r_pkcs7_free_cms', 'r_pkcs7_free_spcinfo', 'r_pkcs7_parse_cms',
    'r_pkcs7_parse_spcinfo', 'r_poolfactory_alloc',
    'r_poolfactory_free', 'r_poolfactory_init',
    'r_poolfactory_instance', 'r_poolfactory_new',
    'r_poolfactory_stats', 'r_print_2bpp_row', 'r_print_2bpp_tiles',
    'r_print_addr', 'r_print_braile', 'r_print_byte',
    'r_print_byte_color', 'r_print_bytes', 'r_print_c',
    'r_print_code', 'r_print_color_op_type',
    'r_print_colorize_opcode', 'r_print_columns', 'r_print_cursor',
    'r_print_cursor_pointer', 'r_print_cursor_range',
    'r_print_date_dos', 'r_print_date_get_now', 'r_print_date_hfs',
    'r_print_date_unix', 'r_print_date_w32', 'r_print_fill',
    'r_print_format', 'r_print_format_byname',
    'r_print_format_struct_size', 'r_print_free',
    'r_print_get_cursor', 'r_print_graphline', 'r_print_have_cursor',
    'r_print_hex_from_bin', 'r_print_hexdiff', 'r_print_hexdump',
    'r_print_hexdump_simple', 'r_print_hexii', 'r_print_hexpair',
    'r_print_hexpairs', 'r_print_init_rowoffsets',
    'r_print_is_interrupted', 'r_print_json_human',
    'r_print_json_indent', 'r_print_json_path', 'r_print_jsondump',
    'r_print_mute', 'r_print_new', 'r_print_offset',
    'r_print_offset_sg', 'r_print_pack7bit', 'r_print_pie',
    'r_print_portionbar', 'r_print_progressbar',
    'r_print_progressbar_with_count', 'r_print_randomart',
    'r_print_rangebar', 'r_print_raw', 'r_print_row_at_off',
    'r_print_rowlog', 'r_print_rowlog_done', 'r_print_rowoff',
    'r_print_section', 'r_print_set_cursor', 'r_print_set_flags',
    'r_print_set_interrupted', 'r_print_set_is_interrupted_cb',
    'r_print_set_rowoff', 'r_print_set_screenbounds',
    'r_print_stereogram', 'r_print_stereogram_bytes',
    'r_print_stereogram_print', 'r_print_string',
    'r_print_unpack7bit', 'r_print_unset_flags', 'r_print_zoom',
    'r_print_zoom_buf', 'r_prof_end', 'r_prof_start',
    'r_protobuf_decode', 'r_punycode_decode', 'r_punycode_encode',
    'r_queue_dequeue', 'r_queue_enqueue', 'r_queue_free',
    'r_queue_is_empty', 'r_queue_new', 'r_range_add',
    'r_range_add_from_string', 'r_range_contains', 'r_range_free',
    'r_range_get_n', 'r_range_inverse', 'r_range_item_get',
    'r_range_list', 'r_range_merge', 'r_range_new',
    'r_range_new_from_string', 'r_range_overlap', 'r_range_percent',
    'r_range_size', 'r_range_sort', 'r_range_sub',
    'r_rbtree_aug_delete', 'r_rbtree_aug_insert',
    'r_rbtree_aug_update_sum', 'r_rbtree_cont_delete',
    'r_rbtree_cont_find', 'r_rbtree_cont_find_node',
    'r_rbtree_cont_first', 'r_rbtree_cont_free',
    'r_rbtree_cont_insert', 'r_rbtree_cont_last', 'r_rbtree_cont_new',
    'r_rbtree_cont_newf', 'r_rbtree_cont_node_next',
    'r_rbtree_cont_node_prev', 'r_rbtree_delete', 'r_rbtree_find',
    'r_rbtree_first', 'r_rbtree_free', 'r_rbtree_insert',
    'r_rbtree_iter_next', 'r_rbtree_iter_prev', 'r_rbtree_last',
    'r_rbtree_lower_bound', 'r_rbtree_lower_bound_forward',
    'r_rbtree_upper_bound', 'r_rbtree_upper_bound_backward',
    'r_regex_check', 'r_regex_error', 'r_regex_exec', 'r_regex_fini',
    'r_regex_flags', 'r_regex_free', 'r_regex_init', 'r_regex_match',
    'r_regex_match_list', 'r_regex_new', 'r_regex_run', 'r_run_call1',
    'r_run_call10', 'r_run_call2', 'r_run_call3', 'r_run_call4',
    'r_run_call5', 'r_run_call6', 'r_run_call7', 'r_run_call8',
    'r_run_call9', 'r_skiplist_delete', 'r_skiplist_delete_node',
    'r_skiplist_empty', 'r_skiplist_find', 'r_skiplist_find_geq',
    'r_skiplist_find_leq', 'r_skiplist_free', 'r_skiplist_get_first',
    'r_skiplist_get_geq', 'r_skiplist_get_leq', 'r_skiplist_get_n',
    'r_skiplist_insert', 'r_skiplist_insert_autofree',
    'r_skiplist_join', 'r_skiplist_new', 'r_skiplist_purge',
    'r_skiplist_to_list', 'r_sleb128', 'r_spaces_add',
    'r_spaces_count', 'r_spaces_current', 'r_spaces_current_name',
    'r_spaces_fini', 'r_spaces_free', 'r_spaces_get', 'r_spaces_init',
    'r_spaces_is_empty', 'r_spaces_new', 'r_spaces_pop',
    'r_spaces_purge', 'r_spaces_push', 'r_spaces_rename',
    'r_spaces_set', 'r_spaces_unset', 'r_strpool_alloc',
    'r_strpool_ansi_chop', 'r_strpool_append', 'r_strpool_empty',
    'r_strpool_fit', 'r_strpool_free', 'r_strpool_get',
    'r_strpool_get_i', 'r_strpool_get_index', 'r_strpool_memcat',
    'r_strpool_new', 'r_strpool_next', 'r_strpool_slice',
    'r_table_add_column', 'r_table_add_row', 'r_table_add_row_list',
    'r_table_add_rowf', 'r_table_align', 'r_table_clone',
    'r_table_column_clone', 'r_table_column_free',
    'r_table_column_nth', 'r_table_columns', 'r_table_filter',
    'r_table_format', 'r_table_free', 'r_table_fromcsv',
    'r_table_fromjson', 'r_table_group', 'r_table_help',
    'r_table_hide_header', 'r_table_new', 'r_table_pop',
    'r_table_push', 'r_table_query', 'r_table_reduce',
    'r_table_row_free', 'r_table_row_new', 'r_table_set_columnsf',
    'r_table_sort', 'r_table_tocsv', 'r_table_tofancystring',
    'r_table_tohtml', 'r_table_tojson', 'r_table_tor2cmds',
    'r_table_tosimplestring', 'r_table_tosql', 'r_table_tostring',
    'r_table_transpose', 'r_table_type', 'r_table_uniq',
    'r_table_visual_list', 'r_th_break', 'r_th_cond_free',
    'r_th_cond_new', 'r_th_cond_signal', 'r_th_cond_signal_all',
    'r_th_cond_wait', 'r_th_free', 'r_th_getname', 'r_th_kill',
    'r_th_kill_free', 'r_th_lock_enter', 'r_th_lock_free',
    'r_th_lock_leave', 'r_th_lock_new', 'r_th_lock_tryenter',
    'r_th_lock_wait', 'r_th_new', 'r_th_self', 'r_th_sem_free',
    'r_th_sem_new', 'r_th_sem_post', 'r_th_sem_wait',
    'r_th_setaffinity', 'r_th_setname', 'r_th_start', 'r_th_wait',
    'r_th_wait_async', 'r_time_dos_time_stamp_to_posix', 'r_time_now',
    'r_time_now_mono', 'r_time_stamp_is_dos_format',
    'r_time_stamp_to_str', 'r_time_to_string', 'r_tree_add_node',
    'r_tree_bfs', 'r_tree_dfs', 'r_tree_free', 'r_tree_new',
    'r_tree_reset', 'r_type_del', 'r_type_enum_getbitfield',
    'r_type_enum_member', 'r_type_format', 'r_type_func_args_count',
    'r_type_func_args_name', 'r_type_func_args_type',
    'r_type_func_cc', 'r_type_func_exist', 'r_type_func_guess',
    'r_type_func_ret', 'r_type_get_bitsize', 'r_type_get_by_offset',
    'r_type_get_enum', 'r_type_get_struct_memb', 'r_type_kind',
    'r_type_link_at', 'r_type_link_offset', 'r_type_set',
    'r_type_set_link', 'r_type_unlink', 'r_uleb128',
    'r_uleb128_decode', 'r_uleb128_encode', 'r_uleb128_len',
    'r_utf16_decode', 'r_utf16_to_utf8_l', 'r_utf16be_decode',
    'r_utf16le_decode', 'r_utf16le_encode', 'r_utf32_decode',
    'r_utf32le_decode', 'r_utf8_decode', 'r_utf8_encode',
    'r_utf8_encode_str', 'r_utf8_size', 'r_utf8_strlen',
    'r_utf8_to_utf16_l', 'r_utf_block_idx', 'r_utf_block_list',
    'r_utf_block_name', 'r_utf_bom_encoding', 'r_util_lines_getline',
    'r_util_version', 'r_x509_certificate_dump',
    'r_x509_certificate_json', 'r_x509_certificate_to_string',
    'r_x509_crl_json', 'r_x509_crl_to_string',
    'r_x509_free_certificate', 'r_x509_parse_certificate',
    'r_x509_parse_certificate2', 'r_x509_parse_crl',
    'read_i32_leb128', 'read_i64_leb128', 'read_u32_leb128',
    'read_u64_leb128', 'ret_ascii_table', 'size_t', 'struct__IO_FILE',
    'struct__IO_codecvt', 'struct__IO_marker', 'struct__IO_wide_data',
    'struct___pthread_cond_s', 'struct___pthread_cond_s_0_0',
    'struct___pthread_cond_s_1_0', 'struct___pthread_internal_list',
    'struct___pthread_mutex_s', 'struct_buffer',
    'struct_c__SA_RBraile', 'struct_c__SA_RConsCursorPos',
    'struct_c__SA_RListInfo', 'struct_c__SA_RNumCalcValue',
    'struct_c__SA_RStrBuf', 'struct_c__SA_RStrpool',
    'struct_c__SA_RTable', 'struct_c__SA_RTableColumn',
    'struct_c__SA_RTableColumnType', 'struct_c__SA_RTableRow',
    'struct_c__SA_RUtfBlock',
    'struct_c__SA_SpcAttributeTypeAndOptionalValue',
    'struct_c__SA_SpcDigestInfo',
    'struct_c__SA_SpcIndirectDataContent', 'struct_c__SA_dict',
    'struct_cdb', 'struct_cdb_hp', 'struct_cdb_hplist',
    'struct_cdb_make', 'struct_ht_pp_bucket_t', 'struct_ht_pp_kv',
    'struct_ht_pp_options_t', 'struct_ht_pp_t',
    'struct_ht_up_bucket_t', 'struct_ht_up_kv',
    'struct_ht_up_options_t', 'struct_ht_up_t', 'struct_ls_iter_t',
    'struct_ls_t', 'struct_pj_t', 'struct_r_anal_graph_node_info_t',
    'struct_r_asn1_bin_t', 'struct_r_asn1_list_t',
    'struct_r_asn1_object_t', 'struct_r_asn1_string_t',
    'struct_r_binheap_t', 'struct_r_bitmap_t', 'struct_r_buf_cache_t',
    'struct_r_buf_t', 'struct_r_buffer_methods_t', 'struct_r_cache_t',
    'struct_r_charset_rune_t', 'struct_r_charset_t',
    'struct_r_cons_bind_t', 'struct_r_cons_context_t',
    'struct_r_cons_grep_t', 'struct_r_cons_palette_t',
    'struct_r_cons_printable_palette_t', 'struct_r_cons_t',
    'struct_r_containing_rb_node_t', 'struct_r_containing_rb_tree_t',
    'struct_r_core_bind_t', 'struct_r_diff_op_t', 'struct_r_diff_t',
    'struct_r_diffchar_t', 'struct_r_event_callback_handle_t',
    'struct_r_event_class_attr_rename_t',
    'struct_r_event_class_attr_set_t', 'struct_r_event_class_attr_t',
    'struct_r_event_class_rename_t', 'struct_r_event_class_t',
    'struct_r_event_debug_process_finished_t',
    'struct_r_event_io_write_t', 'struct_r_event_meta_t',
    'struct_r_event_t', 'struct_r_getopt_t', 'struct_r_graph_node_t',
    'struct_r_graph_t', 'struct_r_hud_t', 'struct_r_id_pool_t',
    'struct_r_id_storage_t', 'struct_r_interval_node_t',
    'struct_r_interval_t', 'struct_r_interval_tree_t',
    'struct_r_io_bind_t', 'struct_r_io_desc_t', 'struct_r_io_map_t',
    'struct_r_io_plugin_t', 'struct_r_io_t', 'struct_r_io_undo_t',
    'struct_r_io_undos_t', 'struct_r_json_t', 'struct_r_json_t_0_0',
    'struct_r_json_t_0_1', 'struct_r_lev_buf',
    'struct_r_line_buffer_t', 'struct_r_line_comp_t',
    'struct_r_line_hist_t', 'struct_r_line_t', 'struct_r_list_iter_t',
    'struct_r_list_t', 'struct_r_mem_pool_factory_t',
    'struct_r_mem_pool_t', 'struct_r_num_big_t',
    'struct_r_num_calc_t', 'struct_r_num_t',
    'struct_r_ordered_id_storage_t', 'struct_r_pkcs7_attribute_t',
    'struct_r_pkcs7_attributes_t',
    'struct_r_pkcs7_certificaterevocationlists_t',
    'struct_r_pkcs7_container_t', 'struct_r_pkcs7_contentinfo_t',
    'struct_r_pkcs7_digestalgorithmidentifiers_t',
    'struct_r_pkcs7_extendedcertificatesandcertificates_t',
    'struct_r_pkcs7_issuerandserialnumber_t',
    'struct_r_pkcs7_signeddata_t', 'struct_r_pkcs7_signerinfo_t',
    'struct_r_pkcs7_signerinfos_t', 'struct_r_print_t',
    'struct_r_print_zoom_t', 'struct_r_prof_t', 'struct_r_pvector_t',
    'struct_r_queue_t', 'struct_r_range_item_t', 'struct_r_range_t',
    'struct_r_rb_iter_t', 'struct_r_rb_node_t',
    'struct_r_reg_arena_t', 'struct_r_reg_item_t',
    'struct_r_reg_set_t', 'struct_r_reg_t', 'struct_r_regex_t',
    'struct_r_regmatch_t', 'struct_r_selection_widget_t',
    'struct_r_skiplist_node_t', 'struct_r_skiplist_t',
    'struct_r_skyline_t', 'struct_r_space_event_t',
    'struct_r_space_event_t_0_0', 'struct_r_space_event_t_0_1',
    'struct_r_space_event_t_0_2', 'struct_r_space_t',
    'struct_r_spaces_t', 'struct_r_stack_t', 'struct_r_th_cond_t',
    'struct_r_th_lock_t', 'struct_r_th_pool_t', 'struct_r_th_sem_t',
    'struct_r_th_t', 'struct_r_tree_node_t', 'struct_r_tree_t',
    'struct_r_tree_visitor_t', 'struct_r_type_enum',
    'struct_r_vector_t', 'struct_r_x509_algorithmidentifier_t',
    'struct_r_x509_authoritykeyidentifier_t',
    'struct_r_x509_certificate_t',
    'struct_r_x509_certificaterevocationlist',
    'struct_r_x509_crlentry', 'struct_r_x509_extension_t',
    'struct_r_x509_extensions_t', 'struct_r_x509_name_t',
    'struct_r_x509_subjectpublickeyinfo_t',
    'struct_r_x509_tbscertificate_t', 'struct_r_x509_validity_t',
    'struct_rcolor_t', 'struct_re_guts', 'struct_sdb_gperf_t',
    'struct_sdb_kv', 'struct_sdb_t', 'struct_termios',
    'struct_timeval', 'struct_tm', 'union___pthread_cond_s_0',
    'union___pthread_cond_s_1', 'union_c__UA_pthread_cond_t',
    'union_c__UA_pthread_mutex_t', 'union_c__UA_sem_t',
    'union_r_json_t_0', 'union_r_json_t_0_0_0',
    'union_r_space_event_t_0']
