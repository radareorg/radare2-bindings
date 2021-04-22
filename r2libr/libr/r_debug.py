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


r_debug_version = _libr_debug.r_debug_version
r_debug_version.restype = ctypes.POINTER(ctypes.c_char)
r_debug_version.argtypes = []

# values for enumeration 'c__EA_RDebugPidState'
c__EA_RDebugPidState__enumvalues = {
    115: 'R_DBG_PROC_STOP',
    114: 'R_DBG_PROC_RUN',
    83: 'R_DBG_PROC_SLEEP',
    122: 'R_DBG_PROC_ZOMBIE',
    100: 'R_DBG_PROC_DEAD',
    82: 'R_DBG_PROC_RAISED',
}
R_DBG_PROC_STOP = 115
R_DBG_PROC_RUN = 114
R_DBG_PROC_SLEEP = 83
R_DBG_PROC_ZOMBIE = 122
R_DBG_PROC_DEAD = 100
R_DBG_PROC_RAISED = 82
c__EA_RDebugPidState = ctypes.c_uint32 # enum
RDebugPidState = c__EA_RDebugPidState
RDebugPidState__enumvalues = c__EA_RDebugPidState__enumvalues

# values for enumeration 'c__EA_RDebugSignalMode'
c__EA_RDebugSignalMode__enumvalues = {
    0: 'R_DBG_SIGNAL_IGNORE',
    1: 'R_DBG_SIGNAL_CONT',
    2: 'R_DBG_SIGNAL_SKIP',
}
R_DBG_SIGNAL_IGNORE = 0
R_DBG_SIGNAL_CONT = 1
R_DBG_SIGNAL_SKIP = 2
c__EA_RDebugSignalMode = ctypes.c_uint32 # enum
RDebugSignalMode = c__EA_RDebugSignalMode
RDebugSignalMode__enumvalues = c__EA_RDebugSignalMode__enumvalues

# values for enumeration 'c__EA_RDebugRecoilMode'
c__EA_RDebugRecoilMode__enumvalues = {
    0: 'R_DBG_RECOIL_NONE',
    1: 'R_DBG_RECOIL_STEP',
    2: 'R_DBG_RECOIL_CONTINUE',
}
R_DBG_RECOIL_NONE = 0
R_DBG_RECOIL_STEP = 1
R_DBG_RECOIL_CONTINUE = 2
c__EA_RDebugRecoilMode = ctypes.c_uint32 # enum
RDebugRecoilMode = c__EA_RDebugRecoilMode
RDebugRecoilMode__enumvalues = c__EA_RDebugRecoilMode__enumvalues

# values for enumeration 'c__EA_RDebugReasonType'
c__EA_RDebugReasonType__enumvalues = {
    -1: 'R_DEBUG_REASON_DEAD',
    0: 'R_DEBUG_REASON_NONE',
    1: 'R_DEBUG_REASON_SIGNAL',
    2: 'R_DEBUG_REASON_SEGFAULT',
    3: 'R_DEBUG_REASON_BREAKPOINT',
    4: 'R_DEBUG_REASON_TRACEPOINT',
    5: 'R_DEBUG_REASON_COND',
    6: 'R_DEBUG_REASON_READERR',
    7: 'R_DEBUG_REASON_STEP',
    8: 'R_DEBUG_REASON_ABORT',
    9: 'R_DEBUG_REASON_WRITERR',
    10: 'R_DEBUG_REASON_DIVBYZERO',
    11: 'R_DEBUG_REASON_ILLEGAL',
    12: 'R_DEBUG_REASON_UNKNOWN',
    13: 'R_DEBUG_REASON_ERROR',
    14: 'R_DEBUG_REASON_NEW_PID',
    15: 'R_DEBUG_REASON_NEW_TID',
    16: 'R_DEBUG_REASON_NEW_LIB',
    17: 'R_DEBUG_REASON_EXIT_PID',
    18: 'R_DEBUG_REASON_EXIT_TID',
    19: 'R_DEBUG_REASON_EXIT_LIB',
    20: 'R_DEBUG_REASON_TRAP',
    21: 'R_DEBUG_REASON_SWI',
    22: 'R_DEBUG_REASON_INT',
    23: 'R_DEBUG_REASON_FPU',
    24: 'R_DEBUG_REASON_USERSUSP',
}
R_DEBUG_REASON_DEAD = -1
R_DEBUG_REASON_NONE = 0
R_DEBUG_REASON_SIGNAL = 1
R_DEBUG_REASON_SEGFAULT = 2
R_DEBUG_REASON_BREAKPOINT = 3
R_DEBUG_REASON_TRACEPOINT = 4
R_DEBUG_REASON_COND = 5
R_DEBUG_REASON_READERR = 6
R_DEBUG_REASON_STEP = 7
R_DEBUG_REASON_ABORT = 8
R_DEBUG_REASON_WRITERR = 9
R_DEBUG_REASON_DIVBYZERO = 10
R_DEBUG_REASON_ILLEGAL = 11
R_DEBUG_REASON_UNKNOWN = 12
R_DEBUG_REASON_ERROR = 13
R_DEBUG_REASON_NEW_PID = 14
R_DEBUG_REASON_NEW_TID = 15
R_DEBUG_REASON_NEW_LIB = 16
R_DEBUG_REASON_EXIT_PID = 17
R_DEBUG_REASON_EXIT_TID = 18
R_DEBUG_REASON_EXIT_LIB = 19
R_DEBUG_REASON_TRAP = 20
R_DEBUG_REASON_SWI = 21
R_DEBUG_REASON_INT = 22
R_DEBUG_REASON_FPU = 23
R_DEBUG_REASON_USERSUSP = 24
c__EA_RDebugReasonType = ctypes.c_int32 # enum
RDebugReasonType = c__EA_RDebugReasonType
RDebugReasonType__enumvalues = c__EA_RDebugReasonType__enumvalues
class struct_r_debug_frame_t(Structure):
    pass

struct_r_debug_frame_t._pack_ = 1 # source:False
struct_r_debug_frame_t._fields_ = [
    ('addr', ctypes.c_uint64),
    ('size', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('sp', ctypes.c_uint64),
    ('bp', ctypes.c_uint64),
]

RDebugFrame = struct_r_debug_frame_t
class struct_r_debug_reason_t(Structure):
    pass

struct_r_debug_reason_t._pack_ = 1 # source:False
struct_r_debug_reason_t._fields_ = [
    ('type', ctypes.c_int32),
    ('tid', ctypes.c_int32),
    ('signum', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('bp_addr', ctypes.c_uint64),
    ('timestamp', ctypes.c_uint64),
    ('addr', ctypes.c_uint64),
    ('ptr', ctypes.c_uint64),
]

RDebugReason = struct_r_debug_reason_t
class struct_r_debug_map_t(Structure):
    pass

struct_r_debug_map_t._pack_ = 1 # source:False
struct_r_debug_map_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('addr', ctypes.c_uint64),
    ('addr_end', ctypes.c_uint64),
    ('size', ctypes.c_uint64),
    ('offset', ctypes.c_uint64),
    ('file', ctypes.POINTER(ctypes.c_char)),
    ('perm', ctypes.c_int32),
    ('user', ctypes.c_int32),
    ('shared', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
]

RDebugMap = struct_r_debug_map_t
class struct_r_debug_signal_t(Structure):
    pass

struct_r_debug_signal_t._pack_ = 1 # source:False
struct_r_debug_signal_t._fields_ = [
    ('type', ctypes.c_int32),
    ('num', ctypes.c_int32),
    ('handler', ctypes.c_uint64),
]

RDebugSignal = struct_r_debug_signal_t
class struct_r_debug_desc_t(Structure):
    pass

struct_r_debug_desc_t._pack_ = 1 # source:False
struct_r_debug_desc_t._fields_ = [
    ('fd', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('path', ctypes.POINTER(ctypes.c_char)),
    ('perm', ctypes.c_int32),
    ('type', ctypes.c_int32),
    ('off', ctypes.c_uint64),
]

RDebugDesc = struct_r_debug_desc_t
class struct_r_debug_snap_t(Structure):
    pass

struct_r_debug_snap_t._pack_ = 1 # source:False
struct_r_debug_snap_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('addr', ctypes.c_uint64),
    ('addr_end', ctypes.c_uint64),
    ('size', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('data', ctypes.POINTER(ctypes.c_ubyte)),
    ('perm', ctypes.c_int32),
    ('user', ctypes.c_int32),
    ('shared', ctypes.c_bool),
    ('PADDING_1', ctypes.c_ubyte * 7),
]

RDebugSnap = struct_r_debug_snap_t
class struct_c__SA_RDebugChangeReg(Structure):
    pass

struct_c__SA_RDebugChangeReg._pack_ = 1 # source:False
struct_c__SA_RDebugChangeReg._fields_ = [
    ('cnum', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('data', ctypes.c_uint64),
]

RDebugChangeReg = struct_c__SA_RDebugChangeReg
class struct_c__SA_RDebugChangeMem(Structure):
    pass

struct_c__SA_RDebugChangeMem._pack_ = 1 # source:False
struct_c__SA_RDebugChangeMem._fields_ = [
    ('cnum', ctypes.c_int32),
    ('data', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte * 3),
]

RDebugChangeMem = struct_c__SA_RDebugChangeMem
class struct_r_debug_checkpoint_t(Structure):
    pass

class struct_r_list_t(Structure):
    pass

class struct_r_reg_arena_t(Structure):
    pass

struct_r_debug_checkpoint_t._pack_ = 1 # source:False
struct_r_debug_checkpoint_t._fields_ = [
    ('cnum', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('arena', ctypes.POINTER(struct_r_reg_arena_t) * 8),
    ('snaps', ctypes.POINTER(struct_r_list_t)),
]

struct_r_reg_arena_t._pack_ = 1 # source:False
struct_r_reg_arena_t._fields_ = [
    ('bytes', ctypes.POINTER(ctypes.c_ubyte)),
    ('size', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
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

RDebugCheckpoint = struct_r_debug_checkpoint_t
class struct_r_debug_session_t(Structure):
    pass

class struct_ht_up_t(Structure):
    pass

class struct_r_vector_t(Structure):
    pass

class struct_r_bp_item_t(Structure):
    pass

struct_r_debug_session_t._pack_ = 1 # source:False
struct_r_debug_session_t._fields_ = [
    ('cnum', ctypes.c_uint32),
    ('maxcnum', ctypes.c_uint32),
    ('cur_chkpt', ctypes.POINTER(struct_r_debug_checkpoint_t)),
    ('checkpoints', ctypes.POINTER(struct_r_vector_t)),
    ('memory', ctypes.POINTER(struct_ht_up_t)),
    ('registers', ctypes.POINTER(struct_ht_up_t)),
    ('reasontype', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('bp', ctypes.POINTER(struct_r_bp_item_t)),
]

struct_r_vector_t._pack_ = 1 # source:False
struct_r_vector_t._fields_ = [
    ('a', ctypes.POINTER(None)),
    ('len', ctypes.c_uint64),
    ('capacity', ctypes.c_uint64),
    ('elem_size', ctypes.c_uint64),
    ('free', ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(None))),
    ('free_user', ctypes.POINTER(None)),
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

struct_r_bp_item_t._pack_ = 1 # source:False
struct_r_bp_item_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('module_name', ctypes.POINTER(ctypes.c_char)),
    ('module_delta', ctypes.c_int64),
    ('addr', ctypes.c_uint64),
    ('delta', ctypes.c_uint64),
    ('size', ctypes.c_int32),
    ('swstep', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 3),
    ('perm', ctypes.c_int32),
    ('hw', ctypes.c_int32),
    ('trace', ctypes.c_int32),
    ('internal', ctypes.c_int32),
    ('enabled', ctypes.c_int32),
    ('togglehits', ctypes.c_int32),
    ('hits', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
    ('obytes', ctypes.POINTER(ctypes.c_ubyte)),
    ('bbytes', ctypes.POINTER(ctypes.c_ubyte)),
    ('pids', ctypes.c_int32 * 10),
    ('data', ctypes.POINTER(ctypes.c_char)),
    ('cond', ctypes.POINTER(ctypes.c_char)),
    ('expr', ctypes.POINTER(ctypes.c_char)),
]

RDebugSession = struct_r_debug_session_t
class struct_r_session_header(Structure):
    pass

struct_r_session_header._pack_ = 1 # source:False
struct_r_session_header._fields_ = [
    ('addr', ctypes.c_uint64),
    ('id', ctypes.c_uint32),
    ('difflist_len', ctypes.c_uint32),
]

RSessionHeader = struct_r_session_header
class struct_r_diff_entry(Structure):
    pass

struct_r_diff_entry._pack_ = 1 # source:False
struct_r_diff_entry._fields_ = [
    ('base_idx', ctypes.c_uint32),
    ('pages_len', ctypes.c_uint32),
]

RDiffEntry = struct_r_diff_entry
class struct_r_snap_entry(Structure):
    pass

struct_r_snap_entry._pack_ = 1 # source:False
struct_r_snap_entry._fields_ = [
    ('addr', ctypes.c_uint64),
    ('size', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('timestamp', ctypes.c_uint64),
    ('perm', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
]

RSnapEntry = struct_r_snap_entry
class struct_r_debug_trace_t(Structure):
    pass

class struct_ht_pp_t(Structure):
    pass

struct_r_debug_trace_t._pack_ = 1 # source:False
struct_r_debug_trace_t._fields_ = [
    ('traces', ctypes.POINTER(struct_r_list_t)),
    ('count', ctypes.c_int32),
    ('enabled', ctypes.c_int32),
    ('tag', ctypes.c_int32),
    ('dup', ctypes.c_int32),
    ('addresses', ctypes.POINTER(ctypes.c_char)),
    ('ht', ctypes.POINTER(struct_ht_pp_t)),
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

RDebugTrace = struct_r_debug_trace_t
class struct_r_debug_tracepoint_t(Structure):
    pass

struct_r_debug_tracepoint_t._pack_ = 1 # source:False
struct_r_debug_tracepoint_t._fields_ = [
    ('addr', ctypes.c_uint64),
    ('tags', ctypes.c_uint64),
    ('tag', ctypes.c_int32),
    ('size', ctypes.c_int32),
    ('count', ctypes.c_int32),
    ('times', ctypes.c_int32),
    ('stamp', ctypes.c_uint64),
]

RDebugTracepoint = struct_r_debug_tracepoint_t
class struct_r_debug_t(Structure):
    pass

class struct_r_anal_t(Structure):
    pass

class struct_r_debug_plugin_t(Structure):
    pass

class struct_sdb_t(Structure):
    pass

class struct_r_egg_t(Structure):
    pass

class struct_r_anal_op_t(Structure):
    pass

class struct_r_num_t(Structure):
    pass

class struct_r_tree_t(Structure):
    pass

class struct_r_event_t(Structure):
    pass

class struct_r_bp_t(Structure):
    pass

class struct_r_reg_t(Structure):
    pass

class struct_pj_t(Structure):
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

struct_r_debug_t._pack_ = 1 # source:False
struct_r_debug_t._fields_ = [
    ('arch', ctypes.POINTER(ctypes.c_char)),
    ('bits', ctypes.c_int32),
    ('hitinfo', ctypes.c_int32),
    ('main_pid', ctypes.c_int32),
    ('pid', ctypes.c_int32),
    ('tid', ctypes.c_int32),
    ('forked_pid', ctypes.c_int32),
    ('n_threads', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('threads', ctypes.POINTER(struct_r_list_t)),
    ('malloc', ctypes.POINTER(ctypes.c_char)),
    ('bpsize', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
    ('btalgo', ctypes.POINTER(ctypes.c_char)),
    ('btdepth', ctypes.c_int32),
    ('regcols', ctypes.c_int32),
    ('swstep', ctypes.c_int32),
    ('stop_all_threads', ctypes.c_int32),
    ('trace_forks', ctypes.c_int32),
    ('trace_execs', ctypes.c_int32),
    ('trace_aftersyscall', ctypes.c_int32),
    ('trace_clone', ctypes.c_int32),
    ('follow_child', ctypes.c_int32),
    ('PADDING_2', ctypes.c_ubyte * 4),
    ('glob_libs', ctypes.POINTER(ctypes.c_char)),
    ('glob_unlibs', ctypes.POINTER(ctypes.c_char)),
    ('consbreak', ctypes.c_bool),
    ('continue_all_threads', ctypes.c_bool),
    ('PADDING_3', ctypes.c_ubyte * 2),
    ('steps', ctypes.c_int32),
    ('reason', RDebugReason),
    ('recoil_mode', RDebugRecoilMode),
    ('PADDING_4', ctypes.c_ubyte * 4),
    ('stopaddr', ctypes.c_uint64),
    ('trace', ctypes.POINTER(struct_r_debug_trace_t)),
    ('tracenodes', ctypes.POINTER(struct_sdb_t)),
    ('tree', ctypes.POINTER(struct_r_tree_t)),
    ('call_frames', ctypes.POINTER(struct_r_list_t)),
    ('reg', ctypes.POINTER(struct_r_reg_t)),
    ('q_regs', ctypes.POINTER(struct_r_list_t)),
    ('creg', ctypes.POINTER(ctypes.c_char)),
    ('bp', ctypes.POINTER(struct_r_bp_t)),
    ('user', ctypes.POINTER(None)),
    ('snap_path', ctypes.POINTER(ctypes.c_char)),
    ('cb_printf', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_char))),
    ('iob', struct_r_io_bind_t),
    ('h', ctypes.POINTER(struct_r_debug_plugin_t)),
    ('plugins', ctypes.POINTER(struct_r_list_t)),
    ('pc_at_bp', ctypes.c_bool),
    ('pc_at_bp_set', ctypes.c_bool),
    ('PADDING_5', ctypes.c_ubyte * 6),
    ('ev', ctypes.POINTER(struct_r_event_t)),
    ('anal', ctypes.POINTER(struct_r_anal_t)),
    ('maps', ctypes.POINTER(struct_r_list_t)),
    ('maps_user', ctypes.POINTER(struct_r_list_t)),
    ('trace_continue', ctypes.c_bool),
    ('PADDING_6', ctypes.c_ubyte * 7),
    ('cur_op', ctypes.POINTER(struct_r_anal_op_t)),
    ('session', ctypes.POINTER(struct_r_debug_session_t)),
    ('sgnls', ctypes.POINTER(struct_sdb_t)),
    ('corebind', struct_r_core_bind_t),
    ('pj', ctypes.POINTER(struct_pj_t)),
    ('_mode', ctypes.c_int32),
    ('PADDING_7', ctypes.c_ubyte * 4),
    ('num', ctypes.POINTER(struct_r_num_t)),
    ('egg', ctypes.POINTER(struct_r_egg_t)),
    ('verbose', ctypes.c_bool),
    ('PADDING_8', ctypes.c_ubyte * 7),
    ('maxsnapsize', ctypes.c_uint64),
    ('main_arena_resolved', ctypes.c_bool),
    ('PADDING_9', ctypes.c_ubyte * 3),
    ('glibc_version', ctypes.c_int32),
]

class struct_ls_t(Structure):
    pass

class struct_sdb_gperf_t(Structure):
    pass

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

class struct_c__SA_dict(Structure):
    pass

struct_c__SA_dict._pack_ = 1 # source:False
struct_c__SA_dict._fields_ = [
    ('table', ctypes.POINTER(ctypes.POINTER(None))),
    ('f', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
    ('size', ctypes.c_uint32),
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

class struct_r_tree_node_t(Structure):
    pass

struct_r_tree_t._pack_ = 1 # source:False
struct_r_tree_t._fields_ = [
    ('root', ctypes.POINTER(struct_r_tree_node_t)),
]

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

class struct_r_reg_set_t(Structure):
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

class struct_r_bp_plugin_t(Structure):
    pass

struct_r_bp_t._pack_ = 1 # source:False
struct_r_bp_t._fields_ = [
    ('user', ctypes.POINTER(None)),
    ('stepcont', ctypes.c_int32),
    ('endian', ctypes.c_int32),
    ('bits', ctypes.c_int32),
    ('bpinmaps', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 3),
    ('corebind', struct_r_core_bind_t),
    ('iob', struct_r_io_bind_t),
    ('cur', ctypes.POINTER(struct_r_bp_plugin_t)),
    ('traces', ctypes.POINTER(struct_r_list_t)),
    ('plugins', ctypes.POINTER(struct_r_list_t)),
    ('cb_printf', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_char))),
    ('breakpoint', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_bp_t), ctypes.POINTER(struct_r_bp_item_t), ctypes.c_bool)),
    ('nbps', ctypes.c_int32),
    ('nhwbps', ctypes.c_int32),
    ('bps', ctypes.POINTER(struct_r_list_t)),
    ('bps_idx', ctypes.POINTER(ctypes.POINTER(struct_r_bp_item_t))),
    ('bps_idx_count', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
    ('delta', ctypes.c_int64),
    ('baddr', ctypes.c_uint64),
]

class struct_r_cache_t(Structure):
    pass

class struct_r_id_pool_t(Structure):
    pass

class struct_r_id_storage_t(Structure):
    pass

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

class struct_r_skyline_t(Structure):
    _pack_ = 1 # source:False
    _fields_ = [
    ('v', struct_r_vector_t),
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

class struct_r_bp_arch_t(Structure):
    pass

struct_r_bp_plugin_t._pack_ = 1 # source:False
struct_r_bp_plugin_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('arch', ctypes.POINTER(ctypes.c_char)),
    ('type', ctypes.c_int32),
    ('nbps', ctypes.c_int32),
    ('bps', ctypes.POINTER(struct_r_bp_arch_t)),
]

struct_r_bp_arch_t._pack_ = 1 # source:False
struct_r_bp_arch_t._fields_ = [
    ('bits', ctypes.c_int32),
    ('length', ctypes.c_int32),
    ('endian', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('bytes', ctypes.POINTER(ctypes.c_ubyte)),
]

class struct_r_buf_t(Structure):
    pass

class struct_r_debug_desc_plugin_t(Structure):
    pass

struct_r_debug_desc_plugin_t._pack_ = 1 # source:False
struct_r_debug_desc_plugin_t._fields_ = [
    ('open', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_char))),
    ('close', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_int32)),
    ('read', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_int32, ctypes.c_uint64, ctypes.c_int32)),
    ('write', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_int32, ctypes.c_uint64, ctypes.c_int32)),
    ('seek', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_int32, ctypes.c_uint64)),
    ('dup', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_int32, ctypes.c_int32)),
    ('list', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.c_int32)),
]

class struct_r_debug_info_t(Structure):
    pass

struct_r_debug_plugin_t._pack_ = 1 # source:False
struct_r_debug_plugin_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('license', ctypes.POINTER(ctypes.c_char)),
    ('author', ctypes.POINTER(ctypes.c_char)),
    ('version', ctypes.POINTER(ctypes.c_char)),
    ('bits', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('arch', ctypes.POINTER(ctypes.c_char)),
    ('canstep', ctypes.c_int32),
    ('keepio', ctypes.c_int32),
    ('info', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_debug_info_t), ctypes.POINTER(struct_r_debug_t), ctypes.POINTER(ctypes.c_char))),
    ('startv', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char)))),
    ('attach', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_debug_t), ctypes.c_int32)),
    ('detach', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_debug_t), ctypes.c_int32)),
    ('select', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_debug_t), ctypes.c_int32, ctypes.c_int32)),
    ('threads', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_debug_t), ctypes.c_int32)),
    ('pids', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_debug_t), ctypes.c_int32)),
    ('tids', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_debug_t), ctypes.c_int32)),
    ('backtrace', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.POINTER(None)), ctypes.POINTER(struct_r_debug_t), ctypes.c_int32)),
    ('stop', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_debug_t))),
    ('step', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_debug_t))),
    ('step_over', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_debug_t))),
    ('cont', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_debug_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32)),
    ('wait', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_debug_t), ctypes.c_int32)),
    ('gcore', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_debug_t), ctypes.POINTER(struct_r_buf_t))),
    ('kill', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_debug_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32)),
    ('kill_list', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_debug_t))),
    ('contsc', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_debug_t), ctypes.c_int32, ctypes.c_int32)),
    ('frames', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_debug_t), ctypes.c_uint64)),
    ('breakpoint', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_bp_t), ctypes.POINTER(struct_r_bp_item_t), ctypes.c_bool)),
    ('reg_read', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_debug_t), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)),
    ('reg_write', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_debug_t), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)),
    ('reg_profile', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_debug_t))),
    ('set_reg_profile', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_char))),
    ('map_get', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_debug_t))),
    ('modules_get', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_debug_t))),
    ('map_alloc', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_debug_map_t), ctypes.POINTER(struct_r_debug_t), ctypes.c_uint64, ctypes.c_int32, ctypes.c_bool)),
    ('map_dealloc', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_debug_t), ctypes.c_uint64, ctypes.c_int32)),
    ('map_protect', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_debug_t), ctypes.c_uint64, ctypes.c_int32, ctypes.c_int32)),
    ('init', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_debug_t))),
    ('drx', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_debug_t), ctypes.c_int32, ctypes.c_uint64, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32)),
    ('desc', struct_r_debug_desc_plugin_t),
]

struct_r_debug_info_t._pack_ = 1 # source:False
struct_r_debug_info_t._fields_ = [
    ('pid', ctypes.c_int32),
    ('tid', ctypes.c_int32),
    ('uid', ctypes.c_int32),
    ('gid', ctypes.c_int32),
    ('usr', ctypes.POINTER(ctypes.c_char)),
    ('exe', ctypes.POINTER(ctypes.c_char)),
    ('cmdline', ctypes.POINTER(ctypes.c_char)),
    ('libname', ctypes.POINTER(ctypes.c_char)),
    ('cwd', ctypes.POINTER(ctypes.c_char)),
    ('status', ctypes.c_int32),
    ('signum', ctypes.c_int32),
    ('lib', ctypes.POINTER(None)),
    ('thread', ctypes.POINTER(None)),
    ('kernel_stack', ctypes.POINTER(ctypes.c_char)),
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

class struct_r_syscall_t(Structure):
    pass

class struct_r_anal_esil_t(Structure):
    pass

class struct_r_rb_node_t(Structure):
    pass

class struct_r_anal_range_t(Structure):
    pass

class struct_r_anal_plugin_t(Structure):
    pass

class struct_r_anal_esil_plugin_t(Structure):
    pass

class struct_r_anal_options_t(Structure):
    pass

struct_r_anal_options_t._pack_ = 1 # source:False
struct_r_anal_options_t._fields_ = [
    ('depth', ctypes.c_int32),
    ('graph_depth', ctypes.c_int32),
    ('vars', ctypes.c_bool),
    ('varname_stack', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 2),
    ('cjmpref', ctypes.c_int32),
    ('jmpref', ctypes.c_int32),
    ('jmpabove', ctypes.c_int32),
    ('ijmp', ctypes.c_bool),
    ('jmpmid', ctypes.c_bool),
    ('loads', ctypes.c_bool),
    ('ignbithints', ctypes.c_bool),
    ('followdatarefs', ctypes.c_int32),
    ('searchstringrefs', ctypes.c_int32),
    ('followbrokenfcnsrefs', ctypes.c_int32),
    ('bb_max_size', ctypes.c_int32),
    ('trycatch', ctypes.c_bool),
    ('norevisit', ctypes.c_bool),
    ('PADDING_1', ctypes.c_ubyte * 2),
    ('afterjmp', ctypes.c_int32),
    ('recont', ctypes.c_int32),
    ('noncode', ctypes.c_int32),
    ('nopskip', ctypes.c_int32),
    ('hpskip', ctypes.c_int32),
    ('jmptbl', ctypes.c_int32),
    ('nonull', ctypes.c_int32),
    ('pushret', ctypes.c_bool),
    ('armthumb', ctypes.c_bool),
    ('endsize', ctypes.c_bool),
    ('delay', ctypes.c_bool),
    ('tailcall', ctypes.c_int32),
    ('retpoline', ctypes.c_bool),
    ('PADDING_2', ctypes.c_ubyte * 3),
]

class struct_r_spaces_t(Structure):
    pass

class struct_r_space_t(Structure):
    pass

struct_r_spaces_t._pack_ = 1 # source:False
struct_r_spaces_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('current', ctypes.POINTER(struct_r_space_t)),
    ('spaces', ctypes.POINTER(struct_r_rb_node_t)),
    ('spacestack', ctypes.POINTER(struct_r_list_t)),
    ('event', ctypes.POINTER(struct_r_event_t)),
]


# values for enumeration 'c__EA_RAnalCPPABI'
c__EA_RAnalCPPABI__enumvalues = {
    0: 'R_ANAL_CPP_ABI_ITANIUM',
    1: 'R_ANAL_CPP_ABI_MSVC',
}
R_ANAL_CPP_ABI_ITANIUM = 0
R_ANAL_CPP_ABI_MSVC = 1
c__EA_RAnalCPPABI = ctypes.c_uint32 # enum
class struct_r_bin_bind_t(Structure):
    pass

class struct_r_bin_t(Structure):
    pass

class struct_r_bin_section_t(Structure):
    pass

class struct_r_bin_file_t(Structure):
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

class struct_r_flag_item_t(Structure):
    pass

class struct_r_flag_t(Structure):
    pass

class struct_r_str_constpool_t(Structure):
    pass

struct_r_str_constpool_t._pack_ = 1 # source:False
struct_r_str_constpool_t._fields_ = [
    ('ht', ctypes.POINTER(struct_ht_pp_t)),
]

class struct_r_anal_hint_cb_t(Structure):
    pass

struct_r_anal_hint_cb_t._pack_ = 1 # source:False
struct_r_anal_hint_cb_t._fields_ = [
    ('on_bits', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_int32, ctypes.c_bool)),
]

class struct_r_flag_bind_t(Structure):
    pass

struct_r_flag_bind_t._pack_ = 1 # source:False
struct_r_flag_bind_t._fields_ = [
    ('init', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('f', ctypes.POINTER(struct_r_flag_t)),
    ('exist_at', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint16, ctypes.c_uint64)),
    ('get', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_flag_item_t), ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char))),
    ('get_at', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_flag_item_t), ctypes.POINTER(struct_r_flag_t), ctypes.c_uint64, ctypes.c_bool)),
    ('get_list', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_flag_t), ctypes.c_uint64)),
    ('set', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_flag_item_t), ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64, ctypes.c_uint32)),
    ('unset', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(struct_r_flag_item_t))),
    ('unset_name', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char))),
    ('unset_off', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_flag_t), ctypes.c_uint64)),
    ('set_fs', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_space_t), ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char))),
    ('push_fs', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char))),
    ('pop_fs', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_flag_t))),
]

class struct_r_anal_callbacks_t(Structure):
    pass

class struct_r_anal_function_t(Structure):
    pass

class struct_r_anal_bb_t(Structure):
    pass

struct_r_anal_callbacks_t._pack_ = 1 # source:False
struct_r_anal_callbacks_t._fields_ = [
    ('on_fcn_new', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(None), ctypes.POINTER(struct_r_anal_function_t))),
    ('on_fcn_delete', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(None), ctypes.POINTER(struct_r_anal_function_t))),
    ('on_fcn_rename', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(None), ctypes.POINTER(struct_r_anal_function_t), ctypes.POINTER(ctypes.c_char))),
    ('on_fcn_bb_new', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(None), ctypes.POINTER(struct_r_anal_function_t), ctypes.POINTER(struct_r_anal_bb_t))),
]

class struct_r_interval_tree_t(Structure):
    pass

class struct_r_interval_node_t(Structure):
    pass

struct_r_interval_tree_t._pack_ = 1 # source:False
struct_r_interval_tree_t._fields_ = [
    ('root', ctypes.POINTER(struct_r_interval_node_t)),
    ('free', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
]

struct_r_anal_t._pack_ = 1 # source:False
struct_r_anal_t._fields_ = [
    ('cpu', ctypes.POINTER(ctypes.c_char)),
    ('os', ctypes.POINTER(ctypes.c_char)),
    ('bits', ctypes.c_int32),
    ('lineswidth', ctypes.c_int32),
    ('big_endian', ctypes.c_int32),
    ('sleep', ctypes.c_int32),
    ('cpp_abi', c__EA_RAnalCPPABI),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('user', ctypes.POINTER(None)),
    ('gp', ctypes.c_uint64),
    ('bb_tree', ctypes.POINTER(struct_r_rb_node_t)),
    ('fcns', ctypes.POINTER(struct_r_list_t)),
    ('ht_addr_fun', ctypes.POINTER(struct_ht_up_t)),
    ('ht_name_fun', ctypes.POINTER(struct_ht_pp_t)),
    ('reg', ctypes.POINTER(struct_r_reg_t)),
    ('last_disasm_reg', ctypes.POINTER(ctypes.c_ubyte)),
    ('syscall', ctypes.POINTER(struct_r_syscall_t)),
    ('diff_ops', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
    ('diff_thbb', ctypes.c_double),
    ('diff_thfcn', ctypes.c_double),
    ('iob', struct_r_io_bind_t),
    ('flb', struct_r_flag_bind_t),
    ('flg_class_set', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_flag_item_t), ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64, ctypes.c_uint32)),
    ('flg_class_get', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_flag_item_t), ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char))),
    ('flg_fcn_set', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_flag_item_t), ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64, ctypes.c_uint32)),
    ('binb', struct_r_bin_bind_t),
    ('coreb', struct_r_core_bind_t),
    ('maxreflines', ctypes.c_int32),
    ('esil_goto_limit', ctypes.c_int32),
    ('pcalign', ctypes.c_int32),
    ('PADDING_2', ctypes.c_ubyte * 4),
    ('esil', ctypes.POINTER(struct_r_anal_esil_t)),
    ('cur', ctypes.POINTER(struct_r_anal_plugin_t)),
    ('esil_cur', ctypes.POINTER(struct_r_anal_esil_plugin_t)),
    ('limit', ctypes.POINTER(struct_r_anal_range_t)),
    ('plugins', ctypes.POINTER(struct_r_list_t)),
    ('esil_plugins', ctypes.POINTER(struct_r_list_t)),
    ('sdb_types', ctypes.POINTER(struct_sdb_t)),
    ('sdb_fmts', ctypes.POINTER(struct_sdb_t)),
    ('sdb_zigns', ctypes.POINTER(struct_sdb_t)),
    ('dict_refs', ctypes.POINTER(struct_ht_up_t)),
    ('dict_xrefs', ctypes.POINTER(struct_ht_up_t)),
    ('recursive_noreturn', ctypes.c_bool),
    ('PADDING_3', ctypes.c_ubyte * 7),
    ('zign_spaces', struct_r_spaces_t),
    ('zign_path', ctypes.POINTER(ctypes.c_char)),
    ('cb_printf', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_char))),
    ('sdb', ctypes.POINTER(struct_sdb_t)),
    ('sdb_pins', ctypes.POINTER(struct_sdb_t)),
    ('addr_hints', ctypes.POINTER(struct_ht_up_t)),
    ('arch_hints', ctypes.POINTER(struct_r_rb_node_t)),
    ('bits_hints', ctypes.POINTER(struct_r_rb_node_t)),
    ('hint_cbs', struct_r_anal_hint_cb_t),
    ('meta', struct_r_interval_tree_t),
    ('meta_spaces', struct_r_spaces_t),
    ('sdb_cc', ctypes.POINTER(struct_sdb_t)),
    ('sdb_classes', ctypes.POINTER(struct_sdb_t)),
    ('sdb_classes_attrs', ctypes.POINTER(struct_sdb_t)),
    ('cb', struct_r_anal_callbacks_t),
    ('opt', struct_r_anal_options_t),
    ('reflines', ctypes.POINTER(struct_r_list_t)),
    ('columnSort', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(None))),
    ('stackptr', ctypes.c_int32),
    ('PADDING_4', ctypes.c_ubyte * 4),
    ('log', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char))),
    ('read_at', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)),
    ('verbose', ctypes.c_bool),
    ('PADDING_5', ctypes.c_ubyte * 3),
    ('seggrn', ctypes.c_int32),
    ('flag_get', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_flag_item_t), ctypes.POINTER(struct_r_flag_t), ctypes.c_uint64)),
    ('ev', ctypes.POINTER(struct_r_event_t)),
    ('imports', ctypes.POINTER(struct_r_list_t)),
    ('visited', ctypes.POINTER(struct_ht_up_t)),
    ('constpool', struct_r_str_constpool_t),
    ('leaddrs', ctypes.POINTER(struct_r_list_t)),
]

struct_r_rb_node_t._pack_ = 1 # source:False
struct_r_rb_node_t._fields_ = [
    ('parent', ctypes.POINTER(struct_r_rb_node_t)),
    ('child', ctypes.POINTER(struct_r_rb_node_t) * 2),
    ('red', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
]

class struct_r_syscall_item_t(Structure):
    pass

class struct__IO_FILE(Structure):
    pass

class struct_r_syscall_port_t(Structure):
    pass

struct_r_syscall_t._pack_ = 1 # source:False
struct_r_syscall_t._fields_ = [
    ('fd', ctypes.POINTER(struct__IO_FILE)),
    ('arch', ctypes.POINTER(ctypes.c_char)),
    ('os', ctypes.POINTER(ctypes.c_char)),
    ('bits', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('cpu', ctypes.POINTER(ctypes.c_char)),
    ('sysptr', ctypes.POINTER(struct_r_syscall_item_t)),
    ('sysport', ctypes.POINTER(struct_r_syscall_port_t)),
    ('db', ctypes.POINTER(struct_sdb_t)),
    ('srdb', ctypes.POINTER(struct_sdb_t)),
    ('refs', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
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

struct_r_syscall_item_t._pack_ = 1 # source:False
struct_r_syscall_item_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('swi', ctypes.c_int32),
    ('num', ctypes.c_int32),
    ('args', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('sargs', ctypes.POINTER(ctypes.c_char)),
]

struct_r_syscall_port_t._pack_ = 1 # source:False
struct_r_syscall_port_t._fields_ = [
    ('port', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('name', ctypes.POINTER(ctypes.c_char)),
]

class struct_r_skiplist_t(Structure):
    pass

struct_r_flag_t._pack_ = 1 # source:False
struct_r_flag_t._fields_ = [
    ('spaces', struct_r_spaces_t),
    ('base', ctypes.c_int64),
    ('realnames', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
    ('tags', ctypes.POINTER(struct_sdb_t)),
    ('num', ctypes.POINTER(struct_r_num_t)),
    ('by_off', ctypes.POINTER(struct_r_skiplist_t)),
    ('ht_name', ctypes.POINTER(struct_ht_pp_t)),
    ('cb_printf', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_char))),
    ('zones', ctypes.POINTER(struct_r_list_t)),
    ('mask', ctypes.c_uint64),
]

struct_r_space_t._pack_ = 1 # source:False
struct_r_space_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('rb', struct_r_rb_node_t),
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

class struct_r_skiplist_node_t(Structure):
    pass

struct_r_skiplist_t._pack_ = 1 # source:False
struct_r_skiplist_t._fields_ = [
    ('head', ctypes.POINTER(struct_r_skiplist_node_t)),
    ('list_level', ctypes.c_int32),
    ('size', ctypes.c_int32),
    ('freefn', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
    ('compare', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(None))),
]

struct_r_skiplist_node_t._pack_ = 1 # source:False
struct_r_skiplist_node_t._fields_ = [
    ('data', ctypes.POINTER(None)),
    ('forward', ctypes.POINTER(ctypes.POINTER(struct_r_skiplist_node_t))),
]

struct_r_flag_item_t._pack_ = 1 # source:False
struct_r_flag_item_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('realname', ctypes.POINTER(ctypes.c_char)),
    ('demangled', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
    ('offset', ctypes.c_uint64),
    ('size', ctypes.c_uint64),
    ('space', ctypes.POINTER(struct_r_space_t)),
    ('color', ctypes.POINTER(ctypes.c_char)),
    ('comment', ctypes.POINTER(ctypes.c_char)),
    ('alias', ctypes.POINTER(ctypes.c_char)),
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

class struct_r_bin_object_t(Structure):
    pass

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

class struct_r_bin_info_t(Structure):
    pass

class struct_r_bin_plugin_t(Structure):
    pass

class struct_r_bin_addr_t(Structure):
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

struct_r_bin_addr_t._pack_ = 1 # source:False
struct_r_bin_addr_t._fields_ = [
    ('vaddr', ctypes.c_uint64),
    ('paddr', ctypes.c_uint64),
    ('hvaddr', ctypes.c_uint64),
    ('hpaddr', ctypes.c_uint64),
    ('type', ctypes.c_int32),
    ('bits', ctypes.c_int32),
]

class struct_r_bin_dbginfo_t(Structure):
    pass

class struct_r_bin_write_t(Structure):
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

class struct_r_anal_reil(Structure):
    pass

class struct_r_anal_esil_handler_t(Structure):
    pass

class struct_r_anal_esil_trace_t(Structure):
    pass

class struct_r_anal_esil_callbacks_t(Structure):
    pass

struct_r_anal_esil_callbacks_t._pack_ = 1 # source:False
struct_r_anal_esil_callbacks_t._fields_ = [
    ('user', ctypes.POINTER(None)),
    ('hook_flag_read', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_anal_esil_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_uint64))),
    ('hook_command', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_anal_esil_t), ctypes.POINTER(ctypes.c_char))),
    ('hook_mem_read', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_anal_esil_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)),
    ('mem_read', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_anal_esil_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)),
    ('hook_mem_write', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_anal_esil_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)),
    ('mem_write', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_anal_esil_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)),
    ('hook_reg_read', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_anal_esil_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_int32))),
    ('reg_read', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_anal_esil_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_int32))),
    ('hook_reg_write', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_anal_esil_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_uint64))),
    ('reg_write', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_anal_esil_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64)),
]

struct_r_anal_esil_t._pack_ = 1 # source:False
struct_r_anal_esil_t._fields_ = [
    ('anal', ctypes.POINTER(struct_r_anal_t)),
    ('stack', ctypes.POINTER(ctypes.POINTER(ctypes.c_char))),
    ('addrmask', ctypes.c_uint64),
    ('stacksize', ctypes.c_int32),
    ('stackptr', ctypes.c_int32),
    ('skip', ctypes.c_uint32),
    ('nowrite', ctypes.c_int32),
    ('iotrap', ctypes.c_int32),
    ('exectrap', ctypes.c_int32),
    ('repeat', ctypes.c_int32),
    ('parse_stop', ctypes.c_int32),
    ('parse_goto', ctypes.c_int32),
    ('parse_goto_count', ctypes.c_int32),
    ('verbose', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('flags', ctypes.c_uint64),
    ('address', ctypes.c_uint64),
    ('stack_addr', ctypes.c_uint64),
    ('stack_size', ctypes.c_uint32),
    ('delay', ctypes.c_int32),
    ('jump_target', ctypes.c_uint64),
    ('jump_target_set', ctypes.c_int32),
    ('trap', ctypes.c_int32),
    ('trap_code', ctypes.c_uint32),
    ('PADDING_1', ctypes.c_ubyte * 4),
    ('old', ctypes.c_uint64),
    ('cur', ctypes.c_uint64),
    ('lastsz', ctypes.c_ubyte),
    ('PADDING_2', ctypes.c_ubyte * 7),
    ('ops', ctypes.POINTER(struct_ht_pp_t)),
    ('current_opstr', ctypes.POINTER(ctypes.c_char)),
    ('interrupts', ctypes.POINTER(struct_c__SA_dict)),
    ('syscalls', ctypes.POINTER(struct_c__SA_dict)),
    ('intr0', ctypes.POINTER(struct_r_anal_esil_handler_t)),
    ('sysc0', ctypes.POINTER(struct_r_anal_esil_handler_t)),
    ('plugins', ctypes.POINTER(struct_r_list_t)),
    ('active_plugins', ctypes.POINTER(struct_r_list_t)),
    ('stats', ctypes.POINTER(struct_sdb_t)),
    ('trace', ctypes.POINTER(struct_r_anal_esil_trace_t)),
    ('cb', struct_r_anal_esil_callbacks_t),
    ('Reil', ctypes.POINTER(struct_r_anal_reil)),
    ('cmd_step', ctypes.POINTER(ctypes.c_char)),
    ('cmd_step_out', ctypes.POINTER(ctypes.c_char)),
    ('cmd_intr', ctypes.POINTER(ctypes.c_char)),
    ('cmd_trap', ctypes.POINTER(ctypes.c_char)),
    ('cmd_mdev', ctypes.POINTER(ctypes.c_char)),
    ('cmd_todo', ctypes.POINTER(ctypes.c_char)),
    ('cmd_ioer', ctypes.POINTER(ctypes.c_char)),
    ('mdev_range', ctypes.POINTER(ctypes.c_char)),
    ('cmd', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_anal_esil_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64, ctypes.c_uint64)),
    ('user', ctypes.POINTER(None)),
    ('stack_fd', ctypes.c_int32),
    ('PADDING_3', ctypes.c_ubyte * 4),
]

struct_r_anal_esil_handler_t._pack_ = 1 # source:False
struct_r_anal_esil_handler_t._fields_ = [
    ('cb', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_anal_esil_t), ctypes.c_uint32, ctypes.POINTER(None))),
    ('user', ctypes.POINTER(None)),
]

struct_r_anal_esil_trace_t._pack_ = 1 # source:False
struct_r_anal_esil_trace_t._fields_ = [
    ('idx', ctypes.c_int32),
    ('end_idx', ctypes.c_int32),
    ('registers', ctypes.POINTER(struct_ht_up_t)),
    ('memory', ctypes.POINTER(struct_ht_up_t)),
    ('arena', ctypes.POINTER(struct_r_reg_arena_t) * 8),
    ('stack_addr', ctypes.c_uint64),
    ('stack_size', ctypes.c_uint64),
    ('stack_data', ctypes.POINTER(ctypes.c_ubyte)),
    ('db', ctypes.POINTER(struct_sdb_t)),
]

struct_r_anal_reil._pack_ = 1 # source:False
struct_r_anal_reil._fields_ = [
    ('old', ctypes.c_char * 32),
    ('cur', ctypes.c_char * 32),
    ('lastsz', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte * 7),
    ('reilNextTemp', ctypes.c_uint64),
    ('addr', ctypes.c_uint64),
    ('seq_num', ctypes.c_ubyte),
    ('PADDING_1', ctypes.c_ubyte * 3),
    ('skip', ctypes.c_int32),
    ('cmd_count', ctypes.c_int32),
    ('if_buf', ctypes.c_char * 64),
    ('pc', ctypes.c_char * 8),
    ('PADDING_2', ctypes.c_ubyte * 4),
]


# values for enumeration 'c__EA_RAnalOpMask'
c__EA_RAnalOpMask__enumvalues = {
    0: 'R_ANAL_OP_MASK_BASIC',
    1: 'R_ANAL_OP_MASK_ESIL',
    2: 'R_ANAL_OP_MASK_VAL',
    4: 'R_ANAL_OP_MASK_HINT',
    8: 'R_ANAL_OP_MASK_OPEX',
    16: 'R_ANAL_OP_MASK_DISASM',
    31: 'R_ANAL_OP_MASK_ALL',
}
R_ANAL_OP_MASK_BASIC = 0
R_ANAL_OP_MASK_ESIL = 1
R_ANAL_OP_MASK_VAL = 2
R_ANAL_OP_MASK_HINT = 4
R_ANAL_OP_MASK_OPEX = 8
R_ANAL_OP_MASK_DISASM = 16
R_ANAL_OP_MASK_ALL = 31
c__EA_RAnalOpMask = ctypes.c_uint32 # enum
struct_r_anal_plugin_t._pack_ = 1 # source:False
struct_r_anal_plugin_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('desc', ctypes.POINTER(ctypes.c_char)),
    ('license', ctypes.POINTER(ctypes.c_char)),
    ('arch', ctypes.POINTER(ctypes.c_char)),
    ('author', ctypes.POINTER(ctypes.c_char)),
    ('version', ctypes.POINTER(ctypes.c_char)),
    ('bits', ctypes.c_int32),
    ('esil', ctypes.c_int32),
    ('fileformat_type', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('init', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None))),
    ('fini', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None))),
    ('archinfo', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_anal_t), ctypes.c_int32)),
    ('anal_mask', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(struct_r_anal_t), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64)),
    ('preludes', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_anal_t))),
    ('op', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_op_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, c__EA_RAnalOpMask)),
    ('cmd_ext', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char))),
    ('set_reg_profile', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_anal_t))),
    ('get_reg_profile', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_anal_t))),
    ('fingerprint_bb', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_bb_t))),
    ('fingerprint_fcn', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_function_t))),
    ('diff_bb', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_function_t), ctypes.POINTER(struct_r_anal_function_t))),
    ('diff_fcn', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_list_t))),
    ('diff_eval', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_anal_t))),
    ('esil_init', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_anal_esil_t))),
    ('esil_post_loop', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_anal_esil_t), ctypes.POINTER(struct_r_anal_op_t))),
    ('esil_trap', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_anal_esil_t), ctypes.c_int32, ctypes.c_int32)),
    ('esil_fini', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_anal_esil_t))),
]

class struct_r_anal_value_t(Structure):
    pass

class struct_r_anal_switch_obj_t(Structure):
    pass


# values for enumeration 'c__EA_RAnalOpPrefix'
c__EA_RAnalOpPrefix__enumvalues = {
    1: 'R_ANAL_OP_PREFIX_COND',
    2: 'R_ANAL_OP_PREFIX_REP',
    4: 'R_ANAL_OP_PREFIX_REPNE',
    8: 'R_ANAL_OP_PREFIX_LOCK',
    16: 'R_ANAL_OP_PREFIX_LIKELY',
    32: 'R_ANAL_OP_PREFIX_UNLIKELY',
}
R_ANAL_OP_PREFIX_COND = 1
R_ANAL_OP_PREFIX_REP = 2
R_ANAL_OP_PREFIX_REPNE = 4
R_ANAL_OP_PREFIX_LOCK = 8
R_ANAL_OP_PREFIX_LIKELY = 16
R_ANAL_OP_PREFIX_UNLIKELY = 32
c__EA_RAnalOpPrefix = ctypes.c_uint32 # enum

# values for enumeration 'c__EA_RAnalStackOp'
c__EA_RAnalStackOp__enumvalues = {
    0: 'R_ANAL_STACK_NULL',
    1: 'R_ANAL_STACK_NOP',
    2: 'R_ANAL_STACK_INC',
    3: 'R_ANAL_STACK_GET',
    4: 'R_ANAL_STACK_SET',
    5: 'R_ANAL_STACK_RESET',
    6: 'R_ANAL_STACK_ALIGN',
}
R_ANAL_STACK_NULL = 0
R_ANAL_STACK_NOP = 1
R_ANAL_STACK_INC = 2
R_ANAL_STACK_GET = 3
R_ANAL_STACK_SET = 4
R_ANAL_STACK_RESET = 5
R_ANAL_STACK_ALIGN = 6
c__EA_RAnalStackOp = ctypes.c_uint32 # enum
class struct_r_anal_hint_t(Structure):
    pass

struct_r_anal_hint_t._pack_ = 1 # source:False
struct_r_anal_hint_t._fields_ = [
    ('addr', ctypes.c_uint64),
    ('ptr', ctypes.c_uint64),
    ('val', ctypes.c_uint64),
    ('jump', ctypes.c_uint64),
    ('fail', ctypes.c_uint64),
    ('ret', ctypes.c_uint64),
    ('arch', ctypes.POINTER(ctypes.c_char)),
    ('opcode', ctypes.POINTER(ctypes.c_char)),
    ('syntax', ctypes.POINTER(ctypes.c_char)),
    ('esil', ctypes.POINTER(ctypes.c_char)),
    ('offset', ctypes.POINTER(ctypes.c_char)),
    ('type', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('size', ctypes.c_uint64),
    ('bits', ctypes.c_int32),
    ('new_bits', ctypes.c_int32),
    ('immbase', ctypes.c_int32),
    ('high', ctypes.c_bool),
    ('PADDING_1', ctypes.c_ubyte * 3),
    ('nword', ctypes.c_int32),
    ('PADDING_2', ctypes.c_ubyte * 4),
    ('stackframe', ctypes.c_uint64),
]


# values for enumeration 'c__EA_RAnalOpDirection'
c__EA_RAnalOpDirection__enumvalues = {
    1: 'R_ANAL_OP_DIR_READ',
    2: 'R_ANAL_OP_DIR_WRITE',
    4: 'R_ANAL_OP_DIR_EXEC',
    8: 'R_ANAL_OP_DIR_REF',
}
R_ANAL_OP_DIR_READ = 1
R_ANAL_OP_DIR_WRITE = 2
R_ANAL_OP_DIR_EXEC = 4
R_ANAL_OP_DIR_REF = 8
c__EA_RAnalOpDirection = ctypes.c_uint32 # enum

# values for enumeration 'c__EA__RAnalCond'
c__EA__RAnalCond__enumvalues = {
    0: 'R_ANAL_COND_AL',
    1: 'R_ANAL_COND_EQ',
    2: 'R_ANAL_COND_NE',
    3: 'R_ANAL_COND_GE',
    4: 'R_ANAL_COND_GT',
    5: 'R_ANAL_COND_LE',
    6: 'R_ANAL_COND_LT',
    7: 'R_ANAL_COND_NV',
    8: 'R_ANAL_COND_HS',
    9: 'R_ANAL_COND_LO',
    10: 'R_ANAL_COND_MI',
    11: 'R_ANAL_COND_PL',
    12: 'R_ANAL_COND_VS',
    13: 'R_ANAL_COND_VC',
    14: 'R_ANAL_COND_HI',
    15: 'R_ANAL_COND_LS',
}
R_ANAL_COND_AL = 0
R_ANAL_COND_EQ = 1
R_ANAL_COND_NE = 2
R_ANAL_COND_GE = 3
R_ANAL_COND_GT = 4
R_ANAL_COND_LE = 5
R_ANAL_COND_LT = 6
R_ANAL_COND_NV = 7
R_ANAL_COND_HS = 8
R_ANAL_COND_LO = 9
R_ANAL_COND_MI = 10
R_ANAL_COND_PL = 11
R_ANAL_COND_VS = 12
R_ANAL_COND_VC = 13
R_ANAL_COND_HI = 14
R_ANAL_COND_LS = 15
c__EA__RAnalCond = ctypes.c_uint32 # enum

# values for enumeration 'r_anal_data_type_t'
r_anal_data_type_t__enumvalues = {
    0: 'R_ANAL_DATATYPE_NULL',
    1: 'R_ANAL_DATATYPE_ARRAY',
    2: 'R_ANAL_DATATYPE_OBJECT',
    3: 'R_ANAL_DATATYPE_STRING',
    4: 'R_ANAL_DATATYPE_CLASS',
    5: 'R_ANAL_DATATYPE_BOOLEAN',
    6: 'R_ANAL_DATATYPE_INT16',
    7: 'R_ANAL_DATATYPE_INT32',
    8: 'R_ANAL_DATATYPE_INT64',
    9: 'R_ANAL_DATATYPE_FLOAT',
}
R_ANAL_DATATYPE_NULL = 0
R_ANAL_DATATYPE_ARRAY = 1
R_ANAL_DATATYPE_OBJECT = 2
R_ANAL_DATATYPE_STRING = 3
R_ANAL_DATATYPE_CLASS = 4
R_ANAL_DATATYPE_BOOLEAN = 5
R_ANAL_DATATYPE_INT16 = 6
R_ANAL_DATATYPE_INT32 = 7
R_ANAL_DATATYPE_INT64 = 8
R_ANAL_DATATYPE_FLOAT = 9
r_anal_data_type_t = ctypes.c_uint32 # enum
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


# values for enumeration 'c__EA_RAnalOpFamily'
c__EA_RAnalOpFamily__enumvalues = {
    -1: 'R_ANAL_OP_FAMILY_UNKNOWN',
    0: 'R_ANAL_OP_FAMILY_CPU',
    1: 'R_ANAL_OP_FAMILY_FPU',
    2: 'R_ANAL_OP_FAMILY_MMX',
    3: 'R_ANAL_OP_FAMILY_SSE',
    4: 'R_ANAL_OP_FAMILY_PRIV',
    5: 'R_ANAL_OP_FAMILY_CRYPTO',
    6: 'R_ANAL_OP_FAMILY_THREAD',
    7: 'R_ANAL_OP_FAMILY_VIRT',
    8: 'R_ANAL_OP_FAMILY_SECURITY',
    9: 'R_ANAL_OP_FAMILY_IO',
    10: 'R_ANAL_OP_FAMILY_LAST',
}
R_ANAL_OP_FAMILY_UNKNOWN = -1
R_ANAL_OP_FAMILY_CPU = 0
R_ANAL_OP_FAMILY_FPU = 1
R_ANAL_OP_FAMILY_MMX = 2
R_ANAL_OP_FAMILY_SSE = 3
R_ANAL_OP_FAMILY_PRIV = 4
R_ANAL_OP_FAMILY_CRYPTO = 5
R_ANAL_OP_FAMILY_THREAD = 6
R_ANAL_OP_FAMILY_VIRT = 7
R_ANAL_OP_FAMILY_SECURITY = 8
R_ANAL_OP_FAMILY_IO = 9
R_ANAL_OP_FAMILY_LAST = 10
c__EA_RAnalOpFamily = ctypes.c_int32 # enum
struct_r_anal_op_t._pack_ = 1 # source:False
struct_r_anal_op_t._fields_ = [
    ('mnemonic', ctypes.POINTER(ctypes.c_char)),
    ('addr', ctypes.c_uint64),
    ('type', ctypes.c_uint32),
    ('prefix', c__EA_RAnalOpPrefix),
    ('type2', ctypes.c_uint32),
    ('stackop', c__EA_RAnalStackOp),
    ('cond', c__EA__RAnalCond),
    ('size', ctypes.c_int32),
    ('nopcode', ctypes.c_int32),
    ('cycles', ctypes.c_int32),
    ('failcycles', ctypes.c_int32),
    ('family', c__EA_RAnalOpFamily),
    ('id', ctypes.c_int32),
    ('eob', ctypes.c_bool),
    ('sign', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 2),
    ('delay', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
    ('jump', ctypes.c_uint64),
    ('fail', ctypes.c_uint64),
    ('direction', c__EA_RAnalOpDirection),
    ('PADDING_2', ctypes.c_ubyte * 4),
    ('ptr', ctypes.c_int64),
    ('val', ctypes.c_uint64),
    ('ptrsize', ctypes.c_int32),
    ('PADDING_3', ctypes.c_ubyte * 4),
    ('stackptr', ctypes.c_int64),
    ('refptr', ctypes.c_int32),
    ('PADDING_4', ctypes.c_ubyte * 4),
    ('src', ctypes.POINTER(struct_r_anal_value_t) * 3),
    ('dst', ctypes.POINTER(struct_r_anal_value_t)),
    ('access', ctypes.POINTER(struct_r_list_t)),
    ('esil', struct_c__SA_RStrBuf),
    ('opex', struct_c__SA_RStrBuf),
    ('reg', ctypes.POINTER(ctypes.c_char)),
    ('ireg', ctypes.POINTER(ctypes.c_char)),
    ('scale', ctypes.c_int32),
    ('PADDING_5', ctypes.c_ubyte * 4),
    ('disp', ctypes.c_uint64),
    ('switch_op', ctypes.POINTER(struct_r_anal_switch_obj_t)),
    ('hint', struct_r_anal_hint_t),
    ('datatype', r_anal_data_type_t),
    ('PADDING_6', ctypes.c_ubyte * 4),
]

class struct_r_reg_item_t(Structure):
    pass


# values for enumeration 'c__EA_RAnalValueType'
c__EA_RAnalValueType__enumvalues = {
    0: 'R_ANAL_VAL_REG',
    1: 'R_ANAL_VAL_MEM',
    2: 'R_ANAL_VAL_IMM',
}
R_ANAL_VAL_REG = 0
R_ANAL_VAL_MEM = 1
R_ANAL_VAL_IMM = 2
c__EA_RAnalValueType = ctypes.c_uint32 # enum

# values for enumeration 'c__EA_RAnalValueAccess'
c__EA_RAnalValueAccess__enumvalues = {
    0: 'R_ANAL_ACC_UNKNOWN',
    1: 'R_ANAL_ACC_R',
    2: 'R_ANAL_ACC_W',
}
R_ANAL_ACC_UNKNOWN = 0
R_ANAL_ACC_R = 1
R_ANAL_ACC_W = 2
c__EA_RAnalValueAccess = ctypes.c_uint32 # enum
struct_r_anal_value_t._pack_ = 1 # source:False
struct_r_anal_value_t._fields_ = [
    ('type', c__EA_RAnalValueType),
    ('access', c__EA_RAnalValueAccess),
    ('absolute', ctypes.c_int32),
    ('memref', ctypes.c_int32),
    ('base', ctypes.c_uint64),
    ('delta', ctypes.c_int64),
    ('imm', ctypes.c_int64),
    ('mul', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('seg', ctypes.POINTER(struct_r_reg_item_t)),
    ('reg', ctypes.POINTER(struct_r_reg_item_t)),
    ('regdelta', ctypes.POINTER(struct_r_reg_item_t)),
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

struct_r_anal_switch_obj_t._pack_ = 1 # source:False
struct_r_anal_switch_obj_t._fields_ = [
    ('addr', ctypes.c_uint64),
    ('min_val', ctypes.c_uint64),
    ('def_val', ctypes.c_uint64),
    ('max_val', ctypes.c_uint64),
    ('cases', ctypes.POINTER(struct_r_list_t)),
]

class struct_r_anal_diff_t(Structure):
    pass

class struct_r_anal_cond_t(Structure):
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

struct_r_anal_bb_t._pack_ = 1 # source:False
struct_r_anal_bb_t._fields_ = [
    ('_rb', struct_r_rb_node_t),
    ('_max_end', ctypes.c_uint64),
    ('addr', ctypes.c_uint64),
    ('size', ctypes.c_uint64),
    ('jump', ctypes.c_uint64),
    ('fail', ctypes.c_uint64),
    ('traced', ctypes.c_bool),
    ('folded', ctypes.c_bool),
    ('color', struct_rcolor_t),
    ('PADDING_0', ctypes.c_ubyte * 5),
    ('fingerprint', ctypes.POINTER(ctypes.c_ubyte)),
    ('diff', ctypes.POINTER(struct_r_anal_diff_t)),
    ('cond', ctypes.POINTER(struct_r_anal_cond_t)),
    ('switch_op', ctypes.POINTER(struct_r_anal_switch_obj_t)),
    ('op_pos', ctypes.POINTER(ctypes.c_uint16)),
    ('op_bytes', ctypes.POINTER(ctypes.c_ubyte)),
    ('parent_reg_arena', ctypes.POINTER(ctypes.c_ubyte)),
    ('op_pos_size', ctypes.c_int32),
    ('ninstr', ctypes.c_int32),
    ('stackptr', ctypes.c_int32),
    ('parent_stackptr', ctypes.c_int32),
    ('cmpval', ctypes.c_uint64),
    ('cmpreg', ctypes.POINTER(ctypes.c_char)),
    ('bbhash', ctypes.c_uint32),
    ('PADDING_1', ctypes.c_ubyte * 4),
    ('fcns', ctypes.POINTER(struct_r_list_t)),
    ('anal', ctypes.POINTER(struct_r_anal_t)),
    ('ref', ctypes.c_int32),
    ('PADDING_2', ctypes.c_ubyte * 4),
]

struct_r_anal_diff_t._pack_ = 1 # source:False
struct_r_anal_diff_t._fields_ = [
    ('type', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('addr', ctypes.c_uint64),
    ('dist', ctypes.c_double),
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('size', ctypes.c_uint32),
    ('PADDING_1', ctypes.c_ubyte * 4),
]

struct_r_anal_cond_t._pack_ = 1 # source:False
struct_r_anal_cond_t._fields_ = [
    ('type', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('arg', ctypes.POINTER(struct_r_anal_value_t) * 2),
]

class struct_r_anal_fcn_meta_t(Structure):
    pass

struct_r_anal_fcn_meta_t._pack_ = 1 # source:False
struct_r_anal_fcn_meta_t._fields_ = [
    ('_min', ctypes.c_uint64),
    ('_max', ctypes.c_uint64),
    ('numrefs', ctypes.c_int32),
    ('numcallrefs', ctypes.c_int32),
]

struct_r_anal_function_t._pack_ = 1 # source:False
struct_r_anal_function_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('bits', ctypes.c_int32),
    ('type', ctypes.c_int32),
    ('cc', ctypes.POINTER(ctypes.c_char)),
    ('addr', ctypes.c_uint64),
    ('labels', ctypes.POINTER(struct_ht_up_t)),
    ('label_addrs', ctypes.POINTER(struct_ht_pp_t)),
    ('vars', struct_r_pvector_t),
    ('inst_vars', ctypes.POINTER(struct_ht_up_t)),
    ('reg_save_area', ctypes.c_uint64),
    ('bp_off', ctypes.c_int64),
    ('stack', ctypes.c_int64),
    ('maxstack', ctypes.c_int32),
    ('ninstr', ctypes.c_int32),
    ('folded', ctypes.c_bool),
    ('is_pure', ctypes.c_bool),
    ('is_variadic', ctypes.c_bool),
    ('has_changed', ctypes.c_bool),
    ('bp_frame', ctypes.c_bool),
    ('is_noreturn', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 2),
    ('fingerprint', ctypes.POINTER(ctypes.c_ubyte)),
    ('fingerprint_size', ctypes.c_uint64),
    ('diff', ctypes.POINTER(struct_r_anal_diff_t)),
    ('bbs', ctypes.POINTER(struct_r_list_t)),
    ('meta', struct_r_anal_fcn_meta_t),
    ('imports', ctypes.POINTER(struct_r_list_t)),
    ('anal', ctypes.POINTER(struct_r_anal_t)),
]

struct_r_anal_esil_plugin_t._pack_ = 1 # source:False
struct_r_anal_esil_plugin_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('desc', ctypes.POINTER(ctypes.c_char)),
    ('license', ctypes.POINTER(ctypes.c_char)),
    ('arch', ctypes.POINTER(ctypes.c_char)),
    ('author', ctypes.POINTER(ctypes.c_char)),
    ('version', ctypes.POINTER(ctypes.c_char)),
    ('init', ctypes.CFUNCTYPE(ctypes.POINTER(None), ctypes.POINTER(struct_r_anal_esil_t))),
    ('fini', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_anal_esil_t), ctypes.POINTER(None))),
]

struct_r_anal_range_t._pack_ = 1 # source:False
struct_r_anal_range_t._fields_ = [
    ('from', ctypes.c_uint64),
    ('to', ctypes.c_uint64),
    ('bits', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('rb_max_addr', ctypes.c_uint64),
    ('rb', struct_r_rb_node_t),
]

struct_r_interval_node_t._pack_ = 1 # source:False
struct_r_interval_node_t._fields_ = [
    ('node', struct_r_rb_node_t),
    ('start', ctypes.c_uint64),
    ('end', ctypes.c_uint64),
    ('max_end', ctypes.c_uint64),
    ('data', ctypes.POINTER(None)),
]


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

class struct_r_egg_emit_t(Structure):
    pass

class struct_r_asm_t(Structure):
    pass

class struct_r_egg_lang_t(Structure):
    pass

class struct_r_egg_lang_t_2(Structure):
    pass

struct_r_egg_lang_t_2._pack_ = 1 # source:False
struct_r_egg_lang_t_2._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('content', ctypes.POINTER(ctypes.c_char)),
]

class struct_r_egg_lang_t_0(Structure):
    pass

struct_r_egg_lang_t_0._pack_ = 1 # source:False
struct_r_egg_lang_t_0._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('body', ctypes.POINTER(ctypes.c_char)),
]

class struct_r_egg_lang_t_1(Structure):
    pass

struct_r_egg_lang_t_1._pack_ = 1 # source:False
struct_r_egg_lang_t_1._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('arg', ctypes.POINTER(ctypes.c_char)),
]

struct_r_egg_lang_t._pack_ = 1 # source:False
struct_r_egg_lang_t._fields_ = [
    ('pushargs', ctypes.c_int32),
    ('nalias', ctypes.c_int32),
    ('nsyscalls', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('conditionstr', ctypes.POINTER(ctypes.c_char)),
    ('syscallbody', ctypes.POINTER(ctypes.c_char)),
    ('includefile', ctypes.POINTER(ctypes.c_char)),
    ('setenviron', ctypes.POINTER(ctypes.c_char)),
    ('mathline', ctypes.POINTER(ctypes.c_char)),
    ('commentmode', ctypes.c_int32),
    ('varsize', ctypes.c_int32),
    ('varxs', ctypes.c_int32),
    ('lastctxdelta', ctypes.c_int32),
    ('nargs', ctypes.c_int32),
    ('docall', ctypes.c_int32),
    ('nfunctions', ctypes.c_int32),
    ('nbrackets', ctypes.c_int32),
    ('slurpin', ctypes.c_int32),
    ('slurp', ctypes.c_int32),
    ('line', ctypes.c_int32),
    ('elem', ctypes.c_char * 1024),
    ('attsyntax', ctypes.c_int32),
    ('elem_n', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
    ('callname', ctypes.POINTER(ctypes.c_char)),
    ('endframe', ctypes.POINTER(ctypes.c_char)),
    ('ctxpush', ctypes.POINTER(ctypes.c_char) * 32),
    ('file', ctypes.POINTER(ctypes.c_char)),
    ('dstvar', ctypes.POINTER(ctypes.c_char)),
    ('dstval', ctypes.POINTER(ctypes.c_char)),
    ('includedir', ctypes.POINTER(ctypes.c_char)),
    ('ifelse_table', ctypes.POINTER(ctypes.c_char) * 32 * 32),
    ('ndstval', ctypes.c_int32),
    ('skipline', ctypes.c_int32),
    ('quoteline', ctypes.c_int32),
    ('quotelinevar', ctypes.c_int32),
    ('stackframe', ctypes.c_int32),
    ('stackfixed', ctypes.c_int32),
    ('oc', ctypes.c_int32),
    ('mode', ctypes.c_int32),
    ('inlinectr', ctypes.c_int32),
    ('PADDING_2', ctypes.c_ubyte * 4),
    ('inlines', struct_r_egg_lang_t_0 * 256),
    ('ninlines', ctypes.c_int32),
    ('PADDING_3', ctypes.c_ubyte * 4),
    ('syscalls', struct_r_egg_lang_t_1 * 256),
    ('aliases', struct_r_egg_lang_t_2 * 256),
    ('nested', ctypes.POINTER(ctypes.c_char) * 32),
    ('nested_callname', ctypes.POINTER(ctypes.c_char) * 32),
    ('nestedi', ctypes.c_int32 * 32),
]

struct_r_egg_t._pack_ = 1 # source:False
struct_r_egg_t._fields_ = [
    ('src', ctypes.POINTER(struct_r_buf_t)),
    ('buf', ctypes.POINTER(struct_r_buf_t)),
    ('bin', ctypes.POINTER(struct_r_buf_t)),
    ('list', ctypes.POINTER(struct_r_list_t)),
    ('rasm', ctypes.POINTER(struct_r_asm_t)),
    ('syscall', ctypes.POINTER(struct_r_syscall_t)),
    ('lang', struct_r_egg_lang_t),
    ('db', ctypes.POINTER(struct_sdb_t)),
    ('plugins', ctypes.POINTER(struct_r_list_t)),
    ('patches', ctypes.POINTER(struct_r_list_t)),
    ('remit', ctypes.POINTER(struct_r_egg_emit_t)),
    ('arch', ctypes.c_int32),
    ('endian', ctypes.c_int32),
    ('bits', ctypes.c_int32),
    ('os', ctypes.c_uint32),
    ('context', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

class struct_r_asm_plugin_t(Structure):
    pass

class struct_r_parse_t(Structure):
    pass

struct_r_asm_t._pack_ = 1 # source:False
struct_r_asm_t._fields_ = [
    ('cpu', ctypes.POINTER(ctypes.c_char)),
    ('bits', ctypes.c_int32),
    ('big_endian', ctypes.c_int32),
    ('syntax', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('pc', ctypes.c_uint64),
    ('user', ctypes.POINTER(None)),
    ('cur', ctypes.POINTER(struct_r_asm_plugin_t)),
    ('acur', ctypes.POINTER(struct_r_asm_plugin_t)),
    ('plugins', ctypes.POINTER(struct_r_list_t)),
    ('binb', struct_r_bin_bind_t),
    ('ifilter', ctypes.POINTER(struct_r_parse_t)),
    ('ofilter', ctypes.POINTER(struct_r_parse_t)),
    ('pair', ctypes.POINTER(struct_sdb_t)),
    ('syscall', ctypes.POINTER(struct_r_syscall_t)),
    ('num', ctypes.POINTER(struct_r_num_t)),
    ('features', ctypes.POINTER(ctypes.c_char)),
    ('invhex', ctypes.c_int32),
    ('pcalign', ctypes.c_int32),
    ('dataalign', ctypes.c_int32),
    ('bitshift', ctypes.c_int32),
    ('immdisp', ctypes.c_bool),
    ('PADDING_1', ctypes.c_ubyte * 7),
    ('flags', ctypes.POINTER(struct_ht_pp_t)),
    ('seggrn', ctypes.c_int32),
    ('pseudo', ctypes.c_bool),
    ('PADDING_2', ctypes.c_ubyte * 3),
]

class struct_r_asm_op_t(Structure):
    pass

struct_r_asm_plugin_t._pack_ = 1 # source:False
struct_r_asm_plugin_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('arch', ctypes.POINTER(ctypes.c_char)),
    ('author', ctypes.POINTER(ctypes.c_char)),
    ('version', ctypes.POINTER(ctypes.c_char)),
    ('cpus', ctypes.POINTER(ctypes.c_char)),
    ('desc', ctypes.POINTER(ctypes.c_char)),
    ('license', ctypes.POINTER(ctypes.c_char)),
    ('user', ctypes.POINTER(None)),
    ('bits', ctypes.c_int32),
    ('endian', ctypes.c_int32),
    ('init', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(None))),
    ('fini', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(None))),
    ('disassemble', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_asm_t), ctypes.POINTER(struct_r_asm_op_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)),
    ('assemble', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_asm_t), ctypes.POINTER(struct_r_asm_op_t), ctypes.POINTER(ctypes.c_char))),
    ('modify', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_asm_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.c_uint64)),
    ('mnemonics', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_asm_t), ctypes.c_int32, ctypes.c_bool)),
    ('features', ctypes.POINTER(ctypes.c_char)),
]

struct_r_asm_op_t._pack_ = 1 # source:False
struct_r_asm_op_t._fields_ = [
    ('size', ctypes.c_int32),
    ('bitsize', ctypes.c_int32),
    ('payload', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('buf', struct_c__SA_RStrBuf),
    ('buf_asm', struct_c__SA_RStrBuf),
    ('buf_inc', ctypes.POINTER(struct_r_buf_t)),
]

class struct_r_parse_plugin_t(Structure):
    pass

class struct_r_anal_bind_t(Structure):
    pass

struct_r_anal_bind_t._pack_ = 1 # source:False
struct_r_anal_bind_t._fields_ = [
    ('anal', ctypes.POINTER(struct_r_anal_t)),
    ('get_fcn_in', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_anal_function_t), ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_int32)),
    ('get_hint', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_anal_hint_t), ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64)),
]

struct_r_parse_t._pack_ = 1 # source:False
struct_r_parse_t._fields_ = [
    ('user', ctypes.POINTER(None)),
    ('flagspace', ctypes.POINTER(struct_r_space_t)),
    ('notin_flagspace', ctypes.POINTER(struct_r_space_t)),
    ('pseudo', ctypes.c_bool),
    ('subreg', ctypes.c_bool),
    ('subrel', ctypes.c_bool),
    ('subtail', ctypes.c_bool),
    ('localvar_only', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 3),
    ('subrel_addr', ctypes.c_uint64),
    ('maxflagnamelen', ctypes.c_int32),
    ('minval', ctypes.c_int32),
    ('retleave_asm', ctypes.POINTER(ctypes.c_char)),
    ('cur', ctypes.POINTER(struct_r_parse_plugin_t)),
    ('parsers', ctypes.POINTER(struct_r_list_t)),
    ('varlist', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_anal_function_t), ctypes.c_int32)),
    ('get_ptr_at', ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.POINTER(struct_r_anal_function_t), ctypes.c_int64, ctypes.c_uint64)),
    ('get_reg_at', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_anal_function_t), ctypes.c_int64, ctypes.c_uint64)),
    ('get_op_ireg', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.c_uint64)),
    ('analb', struct_r_anal_bind_t),
    ('flag_get', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_flag_item_t), ctypes.POINTER(struct_r_flag_t), ctypes.c_uint64)),
    ('label_get', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_anal_function_t), ctypes.c_uint64)),
]

struct_r_parse_plugin_t._pack_ = 1 # source:False
struct_r_parse_plugin_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('desc', ctypes.POINTER(ctypes.c_char)),
    ('init', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_parse_t), ctypes.POINTER(None))),
    ('fini', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_parse_t), ctypes.POINTER(None))),
    ('parse', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_parse_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char))),
    ('assemble', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_parse_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char))),
    ('filter', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_parse_t), ctypes.c_uint64, ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_bool)),
    ('subvar', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_parse_t), ctypes.POINTER(struct_r_anal_function_t), ctypes.c_uint64, ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32)),
    ('replace', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.POINTER(ctypes.c_char))),
]

struct_r_egg_emit_t._pack_ = 1 # source:False
struct_r_egg_emit_t._fields_ = [
    ('arch', ctypes.POINTER(ctypes.c_char)),
    ('size', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('retvar', ctypes.POINTER(ctypes.c_char)),
    ('regs', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_egg_t), ctypes.c_int32)),
    ('init', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_egg_t))),
    ('call', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_egg_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32)),
    ('jmp', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_egg_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32)),
    ('frame', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_egg_t), ctypes.c_int32)),
    ('syscall', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_egg_t), ctypes.c_int32)),
    ('trap', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_egg_t))),
    ('frame_end', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_egg_t), ctypes.c_int32, ctypes.c_int32)),
    ('comment', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_egg_t), ctypes.POINTER(ctypes.c_char))),
    ('push_arg', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_egg_t), ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.c_char))),
    ('set_string', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_egg_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32)),
    ('equ', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_egg_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char))),
    ('get_result', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_egg_t), ctypes.POINTER(ctypes.c_char))),
    ('restore_stack', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_egg_t), ctypes.c_int32)),
    ('syscall_args', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_egg_t), ctypes.c_int32)),
    ('get_var', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_egg_t), ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.c_int32)),
    ('get_ar', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_egg_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32)),
    ('while_end', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_egg_t), ctypes.POINTER(ctypes.c_char))),
    ('load', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_egg_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32)),
    ('load_ptr', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_egg_t), ctypes.POINTER(ctypes.c_char))),
    ('branch', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_egg_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(ctypes.c_char))),
    ('mathop', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_egg_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char))),
    ('get_while_end', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_egg_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char))),
]

RDebug = struct_r_debug_t
RDebugDescPlugin = struct_r_debug_desc_plugin_t
RDebugInfo = struct_r_debug_info_t
RDebugPlugin = struct_r_debug_plugin_t
class struct_r_debug_pid_t(Structure):
    pass

struct_r_debug_pid_t._pack_ = 1 # source:False
struct_r_debug_pid_t._fields_ = [
    ('pid', ctypes.c_int32),
    ('ppid', ctypes.c_int32),
    ('status', ctypes.c_char),
    ('PADDING_0', ctypes.c_ubyte * 3),
    ('runnable', ctypes.c_int32),
    ('signalled', ctypes.c_bool),
    ('PADDING_1', ctypes.c_ubyte * 7),
    ('path', ctypes.POINTER(ctypes.c_char)),
    ('uid', ctypes.c_int32),
    ('gid', ctypes.c_int32),
    ('pc', ctypes.c_uint64),
]

RDebugPid = struct_r_debug_pid_t
r_debug_new = _libr_debug.r_debug_new
r_debug_new.restype = ctypes.POINTER(struct_r_debug_t)
r_debug_new.argtypes = [ctypes.c_int32]
r_debug_free = _libr_debug.r_debug_free
r_debug_free.restype = ctypes.POINTER(struct_r_debug_t)
r_debug_free.argtypes = [ctypes.POINTER(struct_r_debug_t)]
r_debug_attach = _libr_debug.r_debug_attach
r_debug_attach.restype = ctypes.c_int32
r_debug_attach.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32]
r_debug_detach = _libr_debug.r_debug_detach
r_debug_detach.restype = ctypes.c_int32
r_debug_detach.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32]
r_debug_startv = _libr_debug.r_debug_startv
r_debug_startv.restype = ctypes.c_int32
r_debug_startv.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
r_debug_start = _libr_debug.r_debug_start
r_debug_start.restype = ctypes.c_int32
r_debug_start.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.POINTER(ctypes.c_char)]
r_debug_stop_reason = _libr_debug.r_debug_stop_reason
r_debug_stop_reason.restype = RDebugReasonType
r_debug_stop_reason.argtypes = [ctypes.POINTER(struct_r_debug_t)]
r_debug_reason_to_string = _libr_debug.r_debug_reason_to_string
r_debug_reason_to_string.restype = ctypes.POINTER(ctypes.c_char)
r_debug_reason_to_string.argtypes = [ctypes.c_int32]
r_debug_wait = _libr_debug.r_debug_wait
r_debug_wait.restype = RDebugReasonType
r_debug_wait.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.POINTER(ctypes.POINTER(struct_r_bp_item_t))]
r_debug_step = _libr_debug.r_debug_step
r_debug_step.restype = ctypes.c_int32
r_debug_step.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32]
r_debug_step_over = _libr_debug.r_debug_step_over
r_debug_step_over.restype = ctypes.c_int32
r_debug_step_over.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32]
r_debug_continue_until = _libr_debug.r_debug_continue_until
r_debug_continue_until.restype = ctypes.c_int32
r_debug_continue_until.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_uint64]
r_debug_continue_until_nonblock = _libr_debug.r_debug_continue_until_nonblock
r_debug_continue_until_nonblock.restype = ctypes.c_int32
r_debug_continue_until_nonblock.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_uint64]
r_debug_continue_until_optype = _libr_debug.r_debug_continue_until_optype
r_debug_continue_until_optype.restype = ctypes.c_int32
r_debug_continue_until_optype.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32, ctypes.c_int32]
r_debug_continue_until_nontraced = _libr_debug.r_debug_continue_until_nontraced
r_debug_continue_until_nontraced.restype = ctypes.c_int32
r_debug_continue_until_nontraced.argtypes = [ctypes.POINTER(struct_r_debug_t)]
r_debug_continue_syscall = _libr_debug.r_debug_continue_syscall
r_debug_continue_syscall.restype = ctypes.c_int32
r_debug_continue_syscall.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32]
r_debug_continue_syscalls = _libr_debug.r_debug_continue_syscalls
r_debug_continue_syscalls.restype = ctypes.c_int32
r_debug_continue_syscalls.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.POINTER(ctypes.c_int32), ctypes.c_int32]
r_debug_continue = _libr_debug.r_debug_continue
r_debug_continue.restype = ctypes.c_int32
r_debug_continue.argtypes = [ctypes.POINTER(struct_r_debug_t)]
r_debug_continue_kill = _libr_debug.r_debug_continue_kill
r_debug_continue_kill.restype = ctypes.c_int32
r_debug_continue_kill.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32]
r_debug_select = _libr_debug.r_debug_select
r_debug_select.restype = ctypes.c_bool
r_debug_select.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32, ctypes.c_int32]
r_debug_pid_list = _libr_debug.r_debug_pid_list
r_debug_pid_list.restype = ctypes.c_int32
r_debug_pid_list.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32, ctypes.c_char]
r_debug_pid_new = _libr_debug.r_debug_pid_new
r_debug_pid_new.restype = ctypes.POINTER(struct_r_debug_pid_t)
r_debug_pid_new.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32, ctypes.c_char, ctypes.c_uint64]
r_debug_pid_free = _libr_debug.r_debug_pid_free
r_debug_pid_free.restype = ctypes.POINTER(struct_r_debug_pid_t)
r_debug_pid_free.argtypes = [ctypes.POINTER(struct_r_debug_pid_t)]
r_debug_pids = _libr_debug.r_debug_pids
r_debug_pids.restype = ctypes.POINTER(struct_r_list_t)
r_debug_pids.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32]
r_debug_set_arch = _libr_debug.r_debug_set_arch
r_debug_set_arch.restype = ctypes.c_bool
r_debug_set_arch.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_debug_use = _libr_debug.r_debug_use
r_debug_use.restype = ctypes.c_bool
r_debug_use.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.POINTER(ctypes.c_char)]
r_debug_info = _libr_debug.r_debug_info
r_debug_info.restype = ctypes.POINTER(struct_r_debug_info_t)
r_debug_info.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.POINTER(ctypes.c_char)]
r_debug_info_free = _libr_debug.r_debug_info_free
r_debug_info_free.restype = None
r_debug_info_free.argtypes = [ctypes.POINTER(struct_r_debug_info_t)]
r_debug_get_baddr = _libr_debug.r_debug_get_baddr
r_debug_get_baddr.restype = ctypes.c_uint64
r_debug_get_baddr.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.POINTER(ctypes.c_char)]
r_debug_signal_init = _libr_debug.r_debug_signal_init
r_debug_signal_init.restype = None
r_debug_signal_init.argtypes = [ctypes.POINTER(struct_r_debug_t)]
r_debug_signal_send = _libr_debug.r_debug_signal_send
r_debug_signal_send.restype = ctypes.c_int32
r_debug_signal_send.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32]
r_debug_signal_what = _libr_debug.r_debug_signal_what
r_debug_signal_what.restype = ctypes.c_int32
r_debug_signal_what.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32]
r_debug_signal_resolve = _libraries['FIXME_STUB'].r_debug_signal_resolve
r_debug_signal_resolve.restype = ctypes.c_int32
r_debug_signal_resolve.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.POINTER(ctypes.c_char)]
r_debug_signal_resolve_i = _libraries['FIXME_STUB'].r_debug_signal_resolve_i
r_debug_signal_resolve_i.restype = ctypes.POINTER(ctypes.c_char)
r_debug_signal_resolve_i.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32]
r_debug_signal_setup = _libr_debug.r_debug_signal_setup
r_debug_signal_setup.restype = None
r_debug_signal_setup.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32, ctypes.c_int32]
r_debug_signal_set = _libr_debug.r_debug_signal_set
r_debug_signal_set.restype = ctypes.c_int32
r_debug_signal_set.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32, ctypes.c_uint64]
r_debug_signal_list = _libr_debug.r_debug_signal_list
r_debug_signal_list.restype = None
r_debug_signal_list.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32]
r_debug_kill = _libr_debug.r_debug_kill
r_debug_kill.restype = ctypes.c_int32
r_debug_kill.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
r_debug_kill_list = _libr_debug.r_debug_kill_list
r_debug_kill_list.restype = ctypes.POINTER(struct_r_list_t)
r_debug_kill_list.argtypes = [ctypes.POINTER(struct_r_debug_t)]
r_debug_kill_setup = _libr_debug.r_debug_kill_setup
r_debug_kill_setup.restype = ctypes.c_int32
r_debug_kill_setup.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32, ctypes.c_int32]
r_debug_plugin_init = _libr_debug.r_debug_plugin_init
r_debug_plugin_init.restype = None
r_debug_plugin_init.argtypes = [ctypes.POINTER(struct_r_debug_t)]
r_debug_plugin_set = _libraries['FIXME_STUB'].r_debug_plugin_set
r_debug_plugin_set.restype = ctypes.c_int32
r_debug_plugin_set.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.POINTER(ctypes.c_char)]
r_debug_plugin_list = _libr_debug.r_debug_plugin_list
r_debug_plugin_list.restype = ctypes.c_bool
r_debug_plugin_list.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32]
r_debug_plugin_add = _libr_debug.r_debug_plugin_add
r_debug_plugin_add.restype = ctypes.c_bool
r_debug_plugin_add.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.POINTER(struct_r_debug_plugin_t)]
r_debug_plugin_set_reg_profile = _libr_debug.r_debug_plugin_set_reg_profile
r_debug_plugin_set_reg_profile.restype = ctypes.c_bool
r_debug_plugin_set_reg_profile.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.POINTER(ctypes.c_char)]
r_debug_modules_list = _libr_debug.r_debug_modules_list
r_debug_modules_list.restype = ctypes.POINTER(struct_r_list_t)
r_debug_modules_list.argtypes = [ctypes.POINTER(struct_r_debug_t)]
r_debug_map_alloc = _libr_debug.r_debug_map_alloc
r_debug_map_alloc.restype = ctypes.POINTER(struct_r_debug_map_t)
r_debug_map_alloc.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_uint64, ctypes.c_int32, ctypes.c_bool]
r_debug_map_dealloc = _libr_debug.r_debug_map_dealloc
r_debug_map_dealloc.restype = ctypes.c_int32
r_debug_map_dealloc.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.POINTER(struct_r_debug_map_t)]
r_debug_map_list_new = _libr_debug.r_debug_map_list_new
r_debug_map_list_new.restype = ctypes.POINTER(struct_r_list_t)
r_debug_map_list_new.argtypes = []
r_debug_map_get = _libr_debug.r_debug_map_get
r_debug_map_get.restype = ctypes.POINTER(struct_r_debug_map_t)
r_debug_map_get.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_uint64]
r_debug_map_new = _libr_debug.r_debug_map_new
r_debug_map_new.restype = ctypes.POINTER(struct_r_debug_map_t)
r_debug_map_new.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int32, ctypes.c_int32]
r_debug_map_free = _libr_debug.r_debug_map_free
r_debug_map_free.restype = None
r_debug_map_free.argtypes = [ctypes.POINTER(struct_r_debug_map_t)]
r_debug_map_list = _libr_debug.r_debug_map_list
r_debug_map_list.restype = None
r_debug_map_list.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_char)]
r_debug_map_list_visual = _libr_debug.r_debug_map_list_visual
r_debug_map_list_visual.restype = None
r_debug_map_list_visual.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_debug_desc_new = _libr_debug.r_debug_desc_new
r_debug_desc_new.restype = ctypes.POINTER(struct_r_debug_desc_t)
r_debug_desc_new.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
r_debug_desc_free = _libr_debug.r_debug_desc_free
r_debug_desc_free.restype = None
r_debug_desc_free.argtypes = [ctypes.POINTER(struct_r_debug_desc_t)]
r_debug_desc_open = _libr_debug.r_debug_desc_open
r_debug_desc_open.restype = ctypes.c_int32
r_debug_desc_open.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.POINTER(ctypes.c_char)]
r_debug_desc_close = _libr_debug.r_debug_desc_close
r_debug_desc_close.restype = ctypes.c_int32
r_debug_desc_close.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32]
r_debug_desc_dup = _libr_debug.r_debug_desc_dup
r_debug_desc_dup.restype = ctypes.c_int32
r_debug_desc_dup.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32, ctypes.c_int32]
r_debug_desc_read = _libr_debug.r_debug_desc_read
r_debug_desc_read.restype = ctypes.c_int32
r_debug_desc_read.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32, ctypes.c_uint64, ctypes.c_int32]
r_debug_desc_seek = _libr_debug.r_debug_desc_seek
r_debug_desc_seek.restype = ctypes.c_int32
r_debug_desc_seek.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32, ctypes.c_uint64]
r_debug_desc_write = _libr_debug.r_debug_desc_write
r_debug_desc_write.restype = ctypes.c_int32
r_debug_desc_write.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32, ctypes.c_uint64, ctypes.c_int32]
r_debug_desc_list = _libr_debug.r_debug_desc_list
r_debug_desc_list.restype = ctypes.c_int32
r_debug_desc_list.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32]
r_debug_reg_sync = _libr_debug.r_debug_reg_sync
r_debug_reg_sync.restype = ctypes.c_int32
r_debug_reg_sync.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32, ctypes.c_int32]
r_debug_reg_list = _libr_debug.r_debug_reg_list
r_debug_reg_list.restype = ctypes.c_bool
r_debug_reg_list.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(struct_pj_t), ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
r_debug_reg_set = _libr_debug.r_debug_reg_set
r_debug_reg_set.restype = ctypes.c_int32
r_debug_reg_set.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64]
r_debug_reg_get = _libr_debug.r_debug_reg_get
r_debug_reg_get.restype = ctypes.c_uint64
r_debug_reg_get.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.POINTER(ctypes.c_char)]
class struct__utX(Structure):
    pass

class struct__ut80(Structure):
    pass

struct__ut80._pack_ = 1 # source:False
struct__ut80._fields_ = [
    ('Low', ctypes.c_uint64),
    ('High', ctypes.c_uint16),
    ('PADDING_0', ctypes.c_ubyte * 6),
]

class struct__ut256(Structure):
    pass

class struct__ut128(Structure):
    pass

struct__ut128._pack_ = 1 # source:False
struct__ut128._fields_ = [
    ('Low', ctypes.c_uint64),
    ('High', ctypes.c_int64),
]

struct__ut256._pack_ = 1 # source:False
struct__ut256._fields_ = [
    ('Low', struct__ut128),
    ('High', struct__ut128),
]

class struct__ut96(Structure):
    pass

struct__ut96._pack_ = 1 # source:False
struct__ut96._fields_ = [
    ('Low', ctypes.c_uint64),
    ('High', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

struct__utX._pack_ = 1 # source:False
struct__utX._fields_ = [
    ('v80', struct__ut80),
    ('v96', struct__ut96),
    ('v128', struct__ut128),
    ('v256', struct__ut256),
]

r_debug_reg_get_err = _libr_debug.r_debug_reg_get_err
r_debug_reg_get_err.restype = ctypes.c_uint64
r_debug_reg_get_err.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(struct__utX)]
r_debug_execute = _libr_debug.r_debug_execute
r_debug_execute.restype = ctypes.c_uint64
r_debug_execute.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.c_int32]
r_debug_map_sync = _libr_debug.r_debug_map_sync
r_debug_map_sync.restype = ctypes.c_bool
r_debug_map_sync.argtypes = [ctypes.POINTER(struct_r_debug_t)]
r_debug_stop = _libr_debug.r_debug_stop
r_debug_stop.restype = ctypes.c_int32
r_debug_stop.argtypes = [ctypes.POINTER(struct_r_debug_t)]
r_debug_frames = _libr_debug.r_debug_frames
r_debug_frames.restype = ctypes.POINTER(struct_r_list_t)
r_debug_frames.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_uint64]
r_debug_is_dead = _libr_debug.r_debug_is_dead
r_debug_is_dead.restype = ctypes.c_bool
r_debug_is_dead.argtypes = [ctypes.POINTER(struct_r_debug_t)]
r_debug_map_protect = _libr_debug.r_debug_map_protect
r_debug_map_protect.restype = ctypes.c_int32
r_debug_map_protect.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_uint64, ctypes.c_int32, ctypes.c_int32]
r_debug_arg_get = _libr_debug.r_debug_arg_get
r_debug_arg_get.restype = ctypes.c_uint64
r_debug_arg_get.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_debug_arg_set = _libr_debug.r_debug_arg_set
r_debug_arg_set.restype = ctypes.c_bool
r_debug_arg_set.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_uint64]
r_debug_bp_add = _libr_debug.r_debug_bp_add
r_debug_bp_add.restype = ctypes.POINTER(struct_r_bp_item_t)
r_debug_bp_add.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_uint64, ctypes.c_int32, ctypes.c_bool, ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.c_int64]
r_debug_bp_rebase = _libr_debug.r_debug_bp_rebase
r_debug_bp_rebase.restype = None
r_debug_bp_rebase.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_uint64, ctypes.c_uint64]
r_debug_bp_update = _libr_debug.r_debug_bp_update
r_debug_bp_update.restype = None
r_debug_bp_update.argtypes = [ctypes.POINTER(struct_r_debug_t)]
r_debug_thread_list = _libr_debug.r_debug_thread_list
r_debug_thread_list.restype = ctypes.c_int32
r_debug_thread_list.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32, ctypes.c_char]
r_debug_tracenodes_reset = _libr_debug.r_debug_tracenodes_reset
r_debug_tracenodes_reset.restype = None
r_debug_tracenodes_reset.argtypes = [ctypes.POINTER(struct_r_debug_t)]
r_debug_trace_reset = _libr_debug.r_debug_trace_reset
r_debug_trace_reset.restype = None
r_debug_trace_reset.argtypes = [ctypes.POINTER(struct_r_debug_t)]
r_debug_trace_pc = _libr_debug.r_debug_trace_pc
r_debug_trace_pc.restype = ctypes.c_int32
r_debug_trace_pc.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_uint64]
r_debug_trace_op = _libr_debug.r_debug_trace_op
r_debug_trace_op.restype = None
r_debug_trace_op.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.POINTER(struct_r_anal_op_t)]
r_debug_trace_at = _libr_debug.r_debug_trace_at
r_debug_trace_at.restype = None
r_debug_trace_at.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.POINTER(ctypes.c_char)]
r_debug_trace_get = _libr_debug.r_debug_trace_get
r_debug_trace_get.restype = ctypes.POINTER(struct_r_debug_tracepoint_t)
r_debug_trace_get.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_uint64]
r_debug_trace_list = _libr_debug.r_debug_trace_list
r_debug_trace_list.restype = None
r_debug_trace_list.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32, ctypes.c_uint64]
r_debug_trace_add = _libr_debug.r_debug_trace_add
r_debug_trace_add.restype = ctypes.POINTER(struct_r_debug_tracepoint_t)
r_debug_trace_add.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_uint64, ctypes.c_int32]
r_debug_trace_new = _libr_debug.r_debug_trace_new
r_debug_trace_new.restype = ctypes.POINTER(struct_r_debug_trace_t)
r_debug_trace_new.argtypes = []
r_debug_trace_free = _libr_debug.r_debug_trace_free
r_debug_trace_free.restype = None
r_debug_trace_free.argtypes = [ctypes.POINTER(struct_r_debug_trace_t)]
r_debug_trace_tag = _libr_debug.r_debug_trace_tag
r_debug_trace_tag.restype = ctypes.c_int32
r_debug_trace_tag.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32]
r_debug_child_fork = _libr_debug.r_debug_child_fork
r_debug_child_fork.restype = ctypes.c_int32
r_debug_child_fork.argtypes = [ctypes.POINTER(struct_r_debug_t)]
r_debug_child_clone = _libr_debug.r_debug_child_clone
r_debug_child_clone.restype = ctypes.c_int32
r_debug_child_clone.argtypes = [ctypes.POINTER(struct_r_debug_t)]
r_debug_drx_list = _libr_debug.r_debug_drx_list
r_debug_drx_list.restype = None
r_debug_drx_list.argtypes = [ctypes.POINTER(struct_r_debug_t)]
r_debug_drx_set = _libr_debug.r_debug_drx_set
r_debug_drx_set.restype = ctypes.c_int32
r_debug_drx_set.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32, ctypes.c_uint64, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
r_debug_drx_unset = _libr_debug.r_debug_drx_unset
r_debug_drx_unset.restype = ctypes.c_int32
r_debug_drx_unset.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32]
r_debug_num_callback = _libr_debug.r_debug_num_callback
r_debug_num_callback.restype = ctypes.c_uint64
r_debug_num_callback.argtypes = [ctypes.POINTER(struct_r_num_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_int32)]
r_debug_esil_stepi = _libr_debug.r_debug_esil_stepi
r_debug_esil_stepi.restype = ctypes.c_bool
r_debug_esil_stepi.argtypes = [ctypes.POINTER(struct_r_debug_t)]
r_debug_esil_step = _libr_debug.r_debug_esil_step
r_debug_esil_step.restype = ctypes.c_uint64
r_debug_esil_step.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_uint32]
r_debug_esil_continue = _libr_debug.r_debug_esil_continue
r_debug_esil_continue.restype = ctypes.c_uint64
r_debug_esil_continue.argtypes = [ctypes.POINTER(struct_r_debug_t)]
r_debug_esil_watch = _libr_debug.r_debug_esil_watch
r_debug_esil_watch.restype = None
r_debug_esil_watch.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
r_debug_esil_watch_reset = _libr_debug.r_debug_esil_watch_reset
r_debug_esil_watch_reset.restype = None
r_debug_esil_watch_reset.argtypes = [ctypes.POINTER(struct_r_debug_t)]
r_debug_esil_watch_list = _libr_debug.r_debug_esil_watch_list
r_debug_esil_watch_list.restype = None
r_debug_esil_watch_list.argtypes = [ctypes.POINTER(struct_r_debug_t)]
r_debug_esil_watch_empty = _libr_debug.r_debug_esil_watch_empty
r_debug_esil_watch_empty.restype = ctypes.c_bool
r_debug_esil_watch_empty.argtypes = [ctypes.POINTER(struct_r_debug_t)]
r_debug_esil_prestep = _libr_debug.r_debug_esil_prestep
r_debug_esil_prestep.restype = None
r_debug_esil_prestep.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32]
r_debug_add_checkpoint = _libr_debug.r_debug_add_checkpoint
r_debug_add_checkpoint.restype = ctypes.c_bool
r_debug_add_checkpoint.argtypes = [ctypes.POINTER(struct_r_debug_t)]
r_debug_session_add_reg_change = _libr_debug.r_debug_session_add_reg_change
r_debug_session_add_reg_change.restype = ctypes.c_bool
r_debug_session_add_reg_change.argtypes = [ctypes.POINTER(struct_r_debug_session_t), ctypes.c_int32, ctypes.c_uint64, ctypes.c_uint64]
r_debug_session_add_mem_change = _libr_debug.r_debug_session_add_mem_change
r_debug_session_add_mem_change.restype = ctypes.c_bool
r_debug_session_add_mem_change.argtypes = [ctypes.POINTER(struct_r_debug_session_t), ctypes.c_uint64, ctypes.c_ubyte]
r_debug_session_restore_reg_mem = _libr_debug.r_debug_session_restore_reg_mem
r_debug_session_restore_reg_mem.restype = None
r_debug_session_restore_reg_mem.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_uint32]
r_debug_session_list_memory = _libr_debug.r_debug_session_list_memory
r_debug_session_list_memory.restype = None
r_debug_session_list_memory.argtypes = [ctypes.POINTER(struct_r_debug_t)]
r_debug_session_serialize = _libr_debug.r_debug_session_serialize
r_debug_session_serialize.restype = None
r_debug_session_serialize.argtypes = [ctypes.POINTER(struct_r_debug_session_t), ctypes.POINTER(struct_sdb_t)]
r_debug_session_deserialize = _libr_debug.r_debug_session_deserialize
r_debug_session_deserialize.restype = None
r_debug_session_deserialize.argtypes = [ctypes.POINTER(struct_r_debug_session_t), ctypes.POINTER(struct_sdb_t)]
r_debug_session_save = _libr_debug.r_debug_session_save
r_debug_session_save.restype = ctypes.c_bool
r_debug_session_save.argtypes = [ctypes.POINTER(struct_r_debug_session_t), ctypes.POINTER(ctypes.c_char)]
r_debug_session_load = _libr_debug.r_debug_session_load
r_debug_session_load.restype = ctypes.c_bool
r_debug_session_load.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.POINTER(ctypes.c_char)]
r_debug_trace_ins_before = _libr_debug.r_debug_trace_ins_before
r_debug_trace_ins_before.restype = ctypes.c_bool
r_debug_trace_ins_before.argtypes = [ctypes.POINTER(struct_r_debug_t)]
r_debug_trace_ins_after = _libr_debug.r_debug_trace_ins_after
r_debug_trace_ins_after.restype = ctypes.c_bool
r_debug_trace_ins_after.argtypes = [ctypes.POINTER(struct_r_debug_t)]
r_debug_session_new = _libr_debug.r_debug_session_new
r_debug_session_new.restype = ctypes.POINTER(struct_r_debug_session_t)
r_debug_session_new.argtypes = []
r_debug_session_free = _libr_debug.r_debug_session_free
r_debug_session_free.restype = None
r_debug_session_free.argtypes = [ctypes.POINTER(struct_r_debug_session_t)]
r_debug_snap_map = _libr_debug.r_debug_snap_map
r_debug_snap_map.restype = ctypes.POINTER(struct_r_debug_snap_t)
r_debug_snap_map.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.POINTER(struct_r_debug_map_t)]
r_debug_snap_contains = _libr_debug.r_debug_snap_contains
r_debug_snap_contains.restype = ctypes.c_bool
r_debug_snap_contains.argtypes = [ctypes.POINTER(struct_r_debug_snap_t), ctypes.c_uint64]
r_debug_snap_get_hash = _libr_debug.r_debug_snap_get_hash
r_debug_snap_get_hash.restype = ctypes.POINTER(ctypes.c_ubyte)
r_debug_snap_get_hash.argtypes = [ctypes.POINTER(struct_r_debug_snap_t)]
r_debug_snap_is_equal = _libr_debug.r_debug_snap_is_equal
r_debug_snap_is_equal.restype = ctypes.c_bool
r_debug_snap_is_equal.argtypes = [ctypes.POINTER(struct_r_debug_snap_t), ctypes.POINTER(struct_r_debug_snap_t)]
r_debug_snap_free = _libr_debug.r_debug_snap_free
r_debug_snap_free.restype = None
r_debug_snap_free.argtypes = [ctypes.POINTER(struct_r_debug_snap_t)]
r_debug_step_back = _libr_debug.r_debug_step_back
r_debug_step_back.restype = ctypes.c_int32
r_debug_step_back.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32]
r_debug_goto_cnum = _libr_debug.r_debug_goto_cnum
r_debug_goto_cnum.restype = ctypes.c_bool
r_debug_goto_cnum.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_uint32]
r_debug_step_cnum = _libr_debug.r_debug_step_cnum
r_debug_step_cnum.restype = ctypes.c_int32
r_debug_step_cnum.argtypes = [ctypes.POINTER(struct_r_debug_t), ctypes.c_int32]
r_debug_continue_back = _libr_debug.r_debug_continue_back
r_debug_continue_back.restype = ctypes.c_bool
r_debug_continue_back.argtypes = [ctypes.POINTER(struct_r_debug_t)]
r_debug_plugin_native = struct_r_debug_plugin_t # Variable struct_r_debug_plugin_t
r_debug_plugin_esil = struct_r_debug_plugin_t # Variable struct_r_debug_plugin_t
r_debug_plugin_rap = struct_r_debug_plugin_t # Variable struct_r_debug_plugin_t
r_debug_plugin_gdb = struct_r_debug_plugin_t # Variable struct_r_debug_plugin_t
r_debug_plugin_bf = struct_r_debug_plugin_t # Variable struct_r_debug_plugin_t
r_debug_plugin_io = struct_r_debug_plugin_t # Variable struct_r_debug_plugin_t
r_debug_plugin_winkd = struct_r_debug_plugin_t # Variable struct_r_debug_plugin_t
r_debug_plugin_windbg = struct_r_debug_plugin_t # Variable struct_r_debug_plugin_t
r_debug_plugin_bochs = struct_r_debug_plugin_t # Variable struct_r_debug_plugin_t
r_debug_plugin_qnx = struct_r_debug_plugin_t # Variable struct_r_debug_plugin_t
r_debug_plugin_null = struct_r_debug_plugin_t # Variable struct_r_debug_plugin_t
__all__ = \
    ['PJEncodingNum', 'PJEncodingStr', 'PJ_ENCODING_NUM_DEFAULT',
    'PJ_ENCODING_NUM_HEX', 'PJ_ENCODING_NUM_STR',
    'PJ_ENCODING_STR_ARRAY', 'PJ_ENCODING_STR_BASE64',
    'PJ_ENCODING_STR_DEFAULT', 'PJ_ENCODING_STR_HEX',
    'PJ_ENCODING_STR_STRIP', 'RDebug', 'RDebugChangeMem',
    'RDebugChangeReg', 'RDebugCheckpoint', 'RDebugDesc',
    'RDebugDescPlugin', 'RDebugFrame', 'RDebugInfo', 'RDebugMap',
    'RDebugPid', 'RDebugPidState', 'RDebugPidState__enumvalues',
    'RDebugPlugin', 'RDebugReason', 'RDebugReasonType',
    'RDebugReasonType__enumvalues', 'RDebugRecoilMode',
    'RDebugRecoilMode__enumvalues', 'RDebugSession', 'RDebugSignal',
    'RDebugSignalMode', 'RDebugSignalMode__enumvalues', 'RDebugSnap',
    'RDebugTrace', 'RDebugTracepoint', 'RDiffEntry', 'RNCAND',
    'RNCASSIGN', 'RNCDEC', 'RNCDIV', 'RNCEND', 'RNCINC', 'RNCLEFTP',
    'RNCMINUS', 'RNCMOD', 'RNCMUL', 'RNCNAME', 'RNCNEG', 'RNCNUMBER',
    'RNCOR', 'RNCPLUS', 'RNCPRINT', 'RNCRIGHTP', 'RNCROL', 'RNCROR',
    'RNCSHL', 'RNCSHR', 'RNCXOR', 'RSessionHeader', 'RSnapEntry',
    'R_ANAL_ACC_R', 'R_ANAL_ACC_UNKNOWN', 'R_ANAL_ACC_W',
    'R_ANAL_COND_AL', 'R_ANAL_COND_EQ', 'R_ANAL_COND_GE',
    'R_ANAL_COND_GT', 'R_ANAL_COND_HI', 'R_ANAL_COND_HS',
    'R_ANAL_COND_LE', 'R_ANAL_COND_LO', 'R_ANAL_COND_LS',
    'R_ANAL_COND_LT', 'R_ANAL_COND_MI', 'R_ANAL_COND_NE',
    'R_ANAL_COND_NV', 'R_ANAL_COND_PL', 'R_ANAL_COND_VC',
    'R_ANAL_COND_VS', 'R_ANAL_CPP_ABI_ITANIUM', 'R_ANAL_CPP_ABI_MSVC',
    'R_ANAL_DATATYPE_ARRAY', 'R_ANAL_DATATYPE_BOOLEAN',
    'R_ANAL_DATATYPE_CLASS', 'R_ANAL_DATATYPE_FLOAT',
    'R_ANAL_DATATYPE_INT16', 'R_ANAL_DATATYPE_INT32',
    'R_ANAL_DATATYPE_INT64', 'R_ANAL_DATATYPE_NULL',
    'R_ANAL_DATATYPE_OBJECT', 'R_ANAL_DATATYPE_STRING',
    'R_ANAL_OP_DIR_EXEC', 'R_ANAL_OP_DIR_READ', 'R_ANAL_OP_DIR_REF',
    'R_ANAL_OP_DIR_WRITE', 'R_ANAL_OP_FAMILY_CPU',
    'R_ANAL_OP_FAMILY_CRYPTO', 'R_ANAL_OP_FAMILY_FPU',
    'R_ANAL_OP_FAMILY_IO', 'R_ANAL_OP_FAMILY_LAST',
    'R_ANAL_OP_FAMILY_MMX', 'R_ANAL_OP_FAMILY_PRIV',
    'R_ANAL_OP_FAMILY_SECURITY', 'R_ANAL_OP_FAMILY_SSE',
    'R_ANAL_OP_FAMILY_THREAD', 'R_ANAL_OP_FAMILY_UNKNOWN',
    'R_ANAL_OP_FAMILY_VIRT', 'R_ANAL_OP_MASK_ALL',
    'R_ANAL_OP_MASK_BASIC', 'R_ANAL_OP_MASK_DISASM',
    'R_ANAL_OP_MASK_ESIL', 'R_ANAL_OP_MASK_HINT',
    'R_ANAL_OP_MASK_OPEX', 'R_ANAL_OP_MASK_VAL',
    'R_ANAL_OP_PREFIX_COND', 'R_ANAL_OP_PREFIX_LIKELY',
    'R_ANAL_OP_PREFIX_LOCK', 'R_ANAL_OP_PREFIX_REP',
    'R_ANAL_OP_PREFIX_REPNE', 'R_ANAL_OP_PREFIX_UNLIKELY',
    'R_ANAL_STACK_ALIGN', 'R_ANAL_STACK_GET', 'R_ANAL_STACK_INC',
    'R_ANAL_STACK_NOP', 'R_ANAL_STACK_NULL', 'R_ANAL_STACK_RESET',
    'R_ANAL_STACK_SET', 'R_ANAL_VAL_IMM', 'R_ANAL_VAL_MEM',
    'R_ANAL_VAL_REG', 'R_DBG_PROC_DEAD', 'R_DBG_PROC_RAISED',
    'R_DBG_PROC_RUN', 'R_DBG_PROC_SLEEP', 'R_DBG_PROC_STOP',
    'R_DBG_PROC_ZOMBIE', 'R_DBG_RECOIL_CONTINUE', 'R_DBG_RECOIL_NONE',
    'R_DBG_RECOIL_STEP', 'R_DBG_SIGNAL_CONT', 'R_DBG_SIGNAL_IGNORE',
    'R_DBG_SIGNAL_SKIP', 'R_DEBUG_REASON_ABORT',
    'R_DEBUG_REASON_BREAKPOINT', 'R_DEBUG_REASON_COND',
    'R_DEBUG_REASON_DEAD', 'R_DEBUG_REASON_DIVBYZERO',
    'R_DEBUG_REASON_ERROR', 'R_DEBUG_REASON_EXIT_LIB',
    'R_DEBUG_REASON_EXIT_PID', 'R_DEBUG_REASON_EXIT_TID',
    'R_DEBUG_REASON_FPU', 'R_DEBUG_REASON_ILLEGAL',
    'R_DEBUG_REASON_INT', 'R_DEBUG_REASON_NEW_LIB',
    'R_DEBUG_REASON_NEW_PID', 'R_DEBUG_REASON_NEW_TID',
    'R_DEBUG_REASON_NONE', 'R_DEBUG_REASON_READERR',
    'R_DEBUG_REASON_SEGFAULT', 'R_DEBUG_REASON_SIGNAL',
    'R_DEBUG_REASON_STEP', 'R_DEBUG_REASON_SWI',
    'R_DEBUG_REASON_TRACEPOINT', 'R_DEBUG_REASON_TRAP',
    'R_DEBUG_REASON_UNKNOWN', 'R_DEBUG_REASON_USERSUSP',
    'R_DEBUG_REASON_WRITERR', 'c__EA_RAnalCPPABI',
    'c__EA_RAnalOpDirection', 'c__EA_RAnalOpFamily',
    'c__EA_RAnalOpMask', 'c__EA_RAnalOpPrefix', 'c__EA_RAnalStackOp',
    'c__EA_RAnalValueAccess', 'c__EA_RAnalValueType',
    'c__EA_RDebugPidState', 'c__EA_RDebugReasonType',
    'c__EA_RDebugRecoilMode', 'c__EA_RDebugSignalMode',
    'c__EA_RNumCalcToken', 'c__EA__RAnalCond', 'r_anal_data_type_t',
    'r_debug_add_checkpoint', 'r_debug_arg_get', 'r_debug_arg_set',
    'r_debug_attach', 'r_debug_bp_add', 'r_debug_bp_rebase',
    'r_debug_bp_update', 'r_debug_child_clone', 'r_debug_child_fork',
    'r_debug_continue', 'r_debug_continue_back',
    'r_debug_continue_kill', 'r_debug_continue_syscall',
    'r_debug_continue_syscalls', 'r_debug_continue_until',
    'r_debug_continue_until_nonblock',
    'r_debug_continue_until_nontraced',
    'r_debug_continue_until_optype', 'r_debug_desc_close',
    'r_debug_desc_dup', 'r_debug_desc_free', 'r_debug_desc_list',
    'r_debug_desc_new', 'r_debug_desc_open', 'r_debug_desc_read',
    'r_debug_desc_seek', 'r_debug_desc_write', 'r_debug_detach',
    'r_debug_drx_list', 'r_debug_drx_set', 'r_debug_drx_unset',
    'r_debug_esil_continue', 'r_debug_esil_prestep',
    'r_debug_esil_step', 'r_debug_esil_stepi', 'r_debug_esil_watch',
    'r_debug_esil_watch_empty', 'r_debug_esil_watch_list',
    'r_debug_esil_watch_reset', 'r_debug_execute', 'r_debug_frames',
    'r_debug_free', 'r_debug_get_baddr', 'r_debug_goto_cnum',
    'r_debug_info', 'r_debug_info_free', 'r_debug_is_dead',
    'r_debug_kill', 'r_debug_kill_list', 'r_debug_kill_setup',
    'r_debug_map_alloc', 'r_debug_map_dealloc', 'r_debug_map_free',
    'r_debug_map_get', 'r_debug_map_list', 'r_debug_map_list_new',
    'r_debug_map_list_visual', 'r_debug_map_new',
    'r_debug_map_protect', 'r_debug_map_sync', 'r_debug_modules_list',
    'r_debug_new', 'r_debug_num_callback', 'r_debug_pid_free',
    'r_debug_pid_list', 'r_debug_pid_new', 'r_debug_pids',
    'r_debug_plugin_add', 'r_debug_plugin_bf', 'r_debug_plugin_bochs',
    'r_debug_plugin_esil', 'r_debug_plugin_gdb',
    'r_debug_plugin_init', 'r_debug_plugin_io', 'r_debug_plugin_list',
    'r_debug_plugin_native', 'r_debug_plugin_null',
    'r_debug_plugin_qnx', 'r_debug_plugin_rap', 'r_debug_plugin_set',
    'r_debug_plugin_set_reg_profile', 'r_debug_plugin_windbg',
    'r_debug_plugin_winkd', 'r_debug_reason_to_string',
    'r_debug_reg_get', 'r_debug_reg_get_err', 'r_debug_reg_list',
    'r_debug_reg_set', 'r_debug_reg_sync', 'r_debug_select',
    'r_debug_session_add_mem_change',
    'r_debug_session_add_reg_change', 'r_debug_session_deserialize',
    'r_debug_session_free', 'r_debug_session_list_memory',
    'r_debug_session_load', 'r_debug_session_new',
    'r_debug_session_restore_reg_mem', 'r_debug_session_save',
    'r_debug_session_serialize', 'r_debug_set_arch',
    'r_debug_signal_init', 'r_debug_signal_list',
    'r_debug_signal_resolve', 'r_debug_signal_resolve_i',
    'r_debug_signal_send', 'r_debug_signal_set',
    'r_debug_signal_setup', 'r_debug_signal_what',
    'r_debug_snap_contains', 'r_debug_snap_free',
    'r_debug_snap_get_hash', 'r_debug_snap_is_equal',
    'r_debug_snap_map', 'r_debug_start', 'r_debug_startv',
    'r_debug_step', 'r_debug_step_back', 'r_debug_step_cnum',
    'r_debug_step_over', 'r_debug_stop', 'r_debug_stop_reason',
    'r_debug_thread_list', 'r_debug_trace_add', 'r_debug_trace_at',
    'r_debug_trace_free', 'r_debug_trace_get',
    'r_debug_trace_ins_after', 'r_debug_trace_ins_before',
    'r_debug_trace_list', 'r_debug_trace_new', 'r_debug_trace_op',
    'r_debug_trace_pc', 'r_debug_trace_reset', 'r_debug_trace_tag',
    'r_debug_tracenodes_reset', 'r_debug_use', 'r_debug_version',
    'r_debug_wait', 'struct__IO_FILE', 'struct__IO_codecvt',
    'struct__IO_marker', 'struct__IO_wide_data', 'struct__ut128',
    'struct__ut256', 'struct__ut80', 'struct__ut96', 'struct__utX',
    'struct_buffer', 'struct_c__SA_RDebugChangeMem',
    'struct_c__SA_RDebugChangeReg', 'struct_c__SA_RNumCalcValue',
    'struct_c__SA_RStrBuf', 'struct_c__SA_dict', 'struct_cdb',
    'struct_cdb_hp', 'struct_cdb_hplist', 'struct_cdb_make',
    'struct_ht_pp_bucket_t', 'struct_ht_pp_kv',
    'struct_ht_pp_options_t', 'struct_ht_pp_t',
    'struct_ht_up_bucket_t', 'struct_ht_up_kv',
    'struct_ht_up_options_t', 'struct_ht_up_t', 'struct_ls_iter_t',
    'struct_ls_t', 'struct_pj_t', 'struct_r_anal_bb_t',
    'struct_r_anal_bind_t', 'struct_r_anal_callbacks_t',
    'struct_r_anal_cond_t', 'struct_r_anal_diff_t',
    'struct_r_anal_esil_callbacks_t', 'struct_r_anal_esil_handler_t',
    'struct_r_anal_esil_plugin_t', 'struct_r_anal_esil_t',
    'struct_r_anal_esil_trace_t', 'struct_r_anal_fcn_meta_t',
    'struct_r_anal_function_t', 'struct_r_anal_hint_cb_t',
    'struct_r_anal_hint_t', 'struct_r_anal_op_t',
    'struct_r_anal_options_t', 'struct_r_anal_plugin_t',
    'struct_r_anal_range_t', 'struct_r_anal_reil',
    'struct_r_anal_switch_obj_t', 'struct_r_anal_t',
    'struct_r_anal_value_t', 'struct_r_asm_op_t',
    'struct_r_asm_plugin_t', 'struct_r_asm_t', 'struct_r_bin_addr_t',
    'struct_r_bin_arch_options_t', 'struct_r_bin_bind_t',
    'struct_r_bin_dbginfo_t', 'struct_r_bin_file_t',
    'struct_r_bin_hash_t', 'struct_r_bin_info_t',
    'struct_r_bin_object_t', 'struct_r_bin_plugin_t',
    'struct_r_bin_section_t', 'struct_r_bin_t',
    'struct_r_bin_write_t', 'struct_r_bin_xtr_extract_t',
    'struct_r_bin_xtr_metadata_t', 'struct_r_bin_xtr_plugin_t',
    'struct_r_bp_arch_t', 'struct_r_bp_item_t',
    'struct_r_bp_plugin_t', 'struct_r_bp_t', 'struct_r_buf_t',
    'struct_r_buffer_methods_t', 'struct_r_cache_t',
    'struct_r_cons_bind_t', 'struct_r_core_bind_t',
    'struct_r_debug_checkpoint_t', 'struct_r_debug_desc_plugin_t',
    'struct_r_debug_desc_t', 'struct_r_debug_frame_t',
    'struct_r_debug_info_t', 'struct_r_debug_map_t',
    'struct_r_debug_pid_t', 'struct_r_debug_plugin_t',
    'struct_r_debug_reason_t', 'struct_r_debug_session_t',
    'struct_r_debug_signal_t', 'struct_r_debug_snap_t',
    'struct_r_debug_t', 'struct_r_debug_trace_t',
    'struct_r_debug_tracepoint_t', 'struct_r_diff_entry',
    'struct_r_egg_emit_t', 'struct_r_egg_lang_t',
    'struct_r_egg_lang_t_0', 'struct_r_egg_lang_t_1',
    'struct_r_egg_lang_t_2', 'struct_r_egg_t', 'struct_r_event_t',
    'struct_r_flag_bind_t', 'struct_r_flag_item_t', 'struct_r_flag_t',
    'struct_r_id_pool_t', 'struct_r_id_storage_t',
    'struct_r_interval_node_t', 'struct_r_interval_t',
    'struct_r_interval_tree_t', 'struct_r_io_bind_t',
    'struct_r_io_desc_t', 'struct_r_io_map_t', 'struct_r_io_plugin_t',
    'struct_r_io_t', 'struct_r_io_undo_t', 'struct_r_io_undos_t',
    'struct_r_list_iter_t', 'struct_r_list_t', 'struct_r_num_calc_t',
    'struct_r_num_t', 'struct_r_parse_plugin_t', 'struct_r_parse_t',
    'struct_r_pvector_t', 'struct_r_queue_t', 'struct_r_rb_node_t',
    'struct_r_reg_arena_t', 'struct_r_reg_item_t',
    'struct_r_reg_set_t', 'struct_r_reg_t', 'struct_r_session_header',
    'struct_r_skiplist_node_t', 'struct_r_skiplist_t',
    'struct_r_skyline_t', 'struct_r_snap_entry', 'struct_r_space_t',
    'struct_r_spaces_t', 'struct_r_str_constpool_t',
    'struct_r_syscall_item_t', 'struct_r_syscall_port_t',
    'struct_r_syscall_t', 'struct_r_tree_node_t', 'struct_r_tree_t',
    'struct_r_vector_t', 'struct_rcolor_t', 'struct_sdb_gperf_t',
    'struct_sdb_kv', 'struct_sdb_t']
