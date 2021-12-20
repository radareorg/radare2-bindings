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


r_core_version = _libr_core.r_core_version
r_core_version.restype = ctypes.POINTER(ctypes.c_char)
r_core_version.argtypes = []

# values for enumeration 'c__EA_RCoreVisualMode'
c__EA_RCoreVisualMode__enumvalues = {
    0: 'R_CORE_VISUAL_MODE_PX',
    1: 'R_CORE_VISUAL_MODE_PD',
    2: 'R_CORE_VISUAL_MODE_DB',
    3: 'R_CORE_VISUAL_MODE_OV',
    4: 'R_CORE_VISUAL_MODE_CD',
}
R_CORE_VISUAL_MODE_PX = 0
R_CORE_VISUAL_MODE_PD = 1
R_CORE_VISUAL_MODE_DB = 2
R_CORE_VISUAL_MODE_OV = 3
R_CORE_VISUAL_MODE_CD = 4
c__EA_RCoreVisualMode = ctypes.c_uint32 # enum
RCoreVisualMode = c__EA_RCoreVisualMode
RCoreVisualMode__enumvalues = c__EA_RCoreVisualMode__enumvalues
class struct_r_core_plugin_t(Structure):
    pass

struct_r_core_plugin_t._pack_ = 1 # source:False
struct_r_core_plugin_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('desc', ctypes.POINTER(ctypes.c_char)),
    ('license', ctypes.POINTER(ctypes.c_char)),
    ('author', ctypes.POINTER(ctypes.c_char)),
    ('version', ctypes.POINTER(ctypes.c_char)),
    ('call', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))),
    ('init', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))),
    ('fini', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))),
]

RCorePlugin = struct_r_core_plugin_t
class struct_r_core_rtr_host_t(Structure):
    pass

class struct_r_socket_t(Structure):
    pass

struct_r_core_rtr_host_t._pack_ = 1 # source:False
struct_r_core_rtr_host_t._fields_ = [
    ('proto', ctypes.c_int32),
    ('host', ctypes.c_char * 512),
    ('port', ctypes.c_int32),
    ('file', ctypes.c_char * 1024),
    ('fd', ctypes.POINTER(struct_r_socket_t)),
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

RCoreRtrHost = struct_r_core_rtr_host_t
class struct_r_core_undo_t(Structure):
    pass

struct_r_core_undo_t._pack_ = 1 # source:False
struct_r_core_undo_t._fields_ = [
    ('action', ctypes.POINTER(ctypes.c_char)),
    ('revert', ctypes.POINTER(ctypes.c_char)),
    ('tstamp', ctypes.c_uint64),
    ('offset', ctypes.c_uint64),
]

RCoreUndo = struct_r_core_undo_t

# values for enumeration 'c__EA_RAutocompleteType'
c__EA_RAutocompleteType__enumvalues = {
    0: 'AUTOCOMPLETE_DEFAULT',
    1: 'AUTOCOMPLETE_MS',
}
AUTOCOMPLETE_DEFAULT = 0
AUTOCOMPLETE_MS = 1
c__EA_RAutocompleteType = ctypes.c_uint32 # enum
RAutocompleteType = c__EA_RAutocompleteType
RAutocompleteType__enumvalues = c__EA_RAutocompleteType__enumvalues
class struct_c__SA_RCoreUndoCondition(Structure):
    pass

struct_c__SA_RCoreUndoCondition._pack_ = 1 # source:False
struct_c__SA_RCoreUndoCondition._fields_ = [
    ('addr', ctypes.c_uint64),
    ('glob', ctypes.POINTER(ctypes.c_char)),
    ('minstamp', ctypes.c_uint64),
]

RCoreUndoCondition = struct_c__SA_RCoreUndoCondition
class struct_r_core_log_t(Structure):
    pass

class struct_c__SA_RStrpool(Structure):
    pass

struct_r_core_log_t._pack_ = 1 # source:False
struct_r_core_log_t._fields_ = [
    ('first', ctypes.c_int32),
    ('last', ctypes.c_int32),
    ('sp', ctypes.POINTER(struct_c__SA_RStrpool)),
]

struct_c__SA_RStrpool._pack_ = 1 # source:False
struct_c__SA_RStrpool._fields_ = [
    ('str', ctypes.POINTER(ctypes.c_char)),
    ('len', ctypes.c_int32),
    ('size', ctypes.c_int32),
]

RCoreLog = struct_r_core_log_t
class struct_r_core_times_t(Structure):
    pass

struct_r_core_times_t._pack_ = 1 # source:False
struct_r_core_times_t._fields_ = [
    ('loadlibs_init_time', ctypes.c_uint64),
    ('loadlibs_time', ctypes.c_uint64),
    ('file_open_time', ctypes.c_uint64),
]

RCoreTimes = struct_r_core_times_t

# values for enumeration 'r_core_autocomplete_types_t'
r_core_autocomplete_types_t__enumvalues = {
    0: 'R_CORE_AUTOCMPLT_DFLT',
    1: 'R_CORE_AUTOCMPLT_FLAG',
    2: 'R_CORE_AUTOCMPLT_FLSP',
    3: 'R_CORE_AUTOCMPLT_SEEK',
    4: 'R_CORE_AUTOCMPLT_FCN',
    5: 'R_CORE_AUTOCMPLT_ZIGN',
    6: 'R_CORE_AUTOCMPLT_EVAL',
    7: 'R_CORE_AUTOCMPLT_VARS',
    8: 'R_CORE_AUTOCMPLT_PRJT',
    9: 'R_CORE_AUTOCMPLT_MINS',
    10: 'R_CORE_AUTOCMPLT_BRKP',
    11: 'R_CORE_AUTOCMPLT_MACR',
    12: 'R_CORE_AUTOCMPLT_FILE',
    13: 'R_CORE_AUTOCMPLT_THME',
    14: 'R_CORE_AUTOCMPLT_OPTN',
    15: 'R_CORE_AUTOCMPLT_MS',
    16: 'R_CORE_AUTOCMPLT_SDB',
    17: 'R_CORE_AUTOCMPLT_CHRS',
    18: 'R_CORE_AUTOCMPLT_END',
}
R_CORE_AUTOCMPLT_DFLT = 0
R_CORE_AUTOCMPLT_FLAG = 1
R_CORE_AUTOCMPLT_FLSP = 2
R_CORE_AUTOCMPLT_SEEK = 3
R_CORE_AUTOCMPLT_FCN = 4
R_CORE_AUTOCMPLT_ZIGN = 5
R_CORE_AUTOCMPLT_EVAL = 6
R_CORE_AUTOCMPLT_VARS = 7
R_CORE_AUTOCMPLT_PRJT = 8
R_CORE_AUTOCMPLT_MINS = 9
R_CORE_AUTOCMPLT_BRKP = 10
R_CORE_AUTOCMPLT_MACR = 11
R_CORE_AUTOCMPLT_FILE = 12
R_CORE_AUTOCMPLT_THME = 13
R_CORE_AUTOCMPLT_OPTN = 14
R_CORE_AUTOCMPLT_MS = 15
R_CORE_AUTOCMPLT_SDB = 16
R_CORE_AUTOCMPLT_CHRS = 17
R_CORE_AUTOCMPLT_END = 18
r_core_autocomplete_types_t = ctypes.c_uint32 # enum
RCoreAutocompleteType = r_core_autocomplete_types_t
RCoreAutocompleteType__enumvalues = r_core_autocomplete_types_t__enumvalues
class struct_r_core_autocomplete_t(Structure):
    pass

struct_r_core_autocomplete_t._pack_ = 1 # source:False
struct_r_core_autocomplete_t._fields_ = [
    ('cmd', ctypes.POINTER(ctypes.c_char)),
    ('length', ctypes.c_int32),
    ('n_subcmds', ctypes.c_int32),
    ('locked', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 3),
    ('type', ctypes.c_int32),
    ('subcmds', ctypes.POINTER(ctypes.POINTER(struct_r_core_autocomplete_t))),
]

RCoreAutocomplete = struct_r_core_autocomplete_t
class struct_r_core_visual_tab_t(Structure):
    pass

struct_r_core_visual_tab_t._pack_ = 1 # source:False
struct_r_core_visual_tab_t._fields_ = [
    ('printidx', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('offset', ctypes.c_uint64),
    ('cur_enabled', ctypes.c_bool),
    ('PADDING_1', ctypes.c_ubyte * 3),
    ('cur', ctypes.c_int32),
    ('ocur', ctypes.c_int32),
    ('cols', ctypes.c_int32),
    ('disMode', ctypes.c_int32),
    ('hexMode', ctypes.c_int32),
    ('asm_offset', ctypes.c_int32),
    ('asm_instr', ctypes.c_int32),
    ('asm_indent', ctypes.c_int32),
    ('asm_bytes', ctypes.c_int32),
    ('asm_cmt_col', ctypes.c_int32),
    ('printMode', ctypes.c_int32),
    ('current3format', ctypes.c_int32),
    ('current4format', ctypes.c_int32),
    ('current5format', ctypes.c_int32),
    ('dumpCols', ctypes.c_int32),
    ('name', ctypes.c_char * 32),
]

RCoreVisualTab = struct_r_core_visual_tab_t
class struct_r_core_visual_t(Structure):
    pass

class struct_r_list_t(Structure):
    pass

struct_r_core_visual_t._pack_ = 1 # source:False
struct_r_core_visual_t._fields_ = [
    ('tabs', ctypes.POINTER(struct_r_list_t)),
    ('tab', ctypes.c_int32),
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

RCoreVisual = struct_r_core_visual_t
class struct_c__SA_RCoreGadget(Structure):
    pass

struct_c__SA_RCoreGadget._pack_ = 1 # source:False
struct_c__SA_RCoreGadget._fields_ = [
    ('x', ctypes.c_int32),
    ('y', ctypes.c_int32),
    ('w', ctypes.c_int32),
    ('h', ctypes.c_int32),
    ('cmd', ctypes.POINTER(ctypes.c_char)),
]

RCoreGadget = struct_c__SA_RCoreGadget
r_core_gadget_free = _libr_core.r_core_gadget_free
r_core_gadget_free.restype = None
r_core_gadget_free.argtypes = [ctypes.POINTER(struct_c__SA_RCoreGadget)]
class struct_r_core_tasks_t(Structure):
    pass

class struct_r_core_task_t(Structure):
    pass

class struct_r_th_lock_t(Structure):
    pass

struct_r_core_tasks_t._pack_ = 1 # source:False
struct_r_core_tasks_t._fields_ = [
    ('task_id_next', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('tasks', ctypes.POINTER(struct_r_list_t)),
    ('tasks_queue', ctypes.POINTER(struct_r_list_t)),
    ('oneshot_queue', ctypes.POINTER(struct_r_list_t)),
    ('oneshots_enqueued', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
    ('current_task', ctypes.POINTER(struct_r_core_task_t)),
    ('main_task', ctypes.POINTER(struct_r_core_task_t)),
    ('lock', ctypes.POINTER(struct_r_th_lock_t)),
    ('tasks_running', ctypes.c_int32),
    ('oneshot_running', ctypes.c_bool),
    ('PADDING_2', ctypes.c_ubyte * 3),
]

class struct_r_cons_context_t(Structure):
    pass

class struct_r_th_cond_t(Structure):
    pass

class struct_r_th_t(Structure):
    pass

class struct_r_core_t(Structure):
    pass

class struct_r_th_sem_t(Structure):
    pass


# values for enumeration 'c__EA_RTaskState'
c__EA_RTaskState__enumvalues = {
    0: 'R_CORE_TASK_STATE_BEFORE_START',
    1: 'R_CORE_TASK_STATE_RUNNING',
    2: 'R_CORE_TASK_STATE_SLEEPING',
    3: 'R_CORE_TASK_STATE_DONE',
}
R_CORE_TASK_STATE_BEFORE_START = 0
R_CORE_TASK_STATE_RUNNING = 1
R_CORE_TASK_STATE_SLEEPING = 2
R_CORE_TASK_STATE_DONE = 3
c__EA_RTaskState = ctypes.c_uint32 # enum
struct_r_core_task_t._pack_ = 1 # source:False
struct_r_core_task_t._fields_ = [
    ('id', ctypes.c_int32),
    ('state', c__EA_RTaskState),
    ('transient', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 3),
    ('refcount', ctypes.c_int32),
    ('running_sem', ctypes.POINTER(struct_r_th_sem_t)),
    ('user', ctypes.POINTER(None)),
    ('core', ctypes.POINTER(struct_r_core_t)),
    ('dispatched', ctypes.c_bool),
    ('PADDING_1', ctypes.c_ubyte * 7),
    ('dispatch_cond', ctypes.POINTER(struct_r_th_cond_t)),
    ('dispatch_lock', ctypes.POINTER(struct_r_th_lock_t)),
    ('thread', ctypes.POINTER(struct_r_th_t)),
    ('cmd', ctypes.POINTER(ctypes.c_char)),
    ('res', ctypes.POINTER(ctypes.c_char)),
    ('cmd_log', ctypes.c_bool),
    ('PADDING_2', ctypes.c_ubyte * 7),
    ('cons_context', ctypes.POINTER(struct_r_cons_context_t)),
    ('cb', ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))),
]

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

class struct_r_parse_t(Structure):
    pass

class struct_r_lang_t(Structure):
    pass

class struct_r_buf_t(Structure):
    pass

class struct_r_print_t(Structure):
    pass

class struct_r_panels_t(Structure):
    pass

class struct_r_num_t(Structure):
    pass

class struct_r_cmd_t(Structure):
    pass

class struct_r_anal_t(Structure):
    pass

class struct_r_flag_t(Structure):
    pass

class struct_r_config_t(Structure):
    pass

class struct_r_fs_t(Structure):
    pass

class struct_r_panels_root_t(Structure):
    pass

class struct_r_asm_t(Structure):
    pass

class struct_r_debug_t(Structure):
    pass

class struct_r_cons_t(Structure):
    pass

class struct_r_io_t(Structure):
    pass

class struct_r_core_project_t(Structure):
    pass

class struct_r_search_t(Structure):
    pass

class struct_r_egg_t(Structure):
    pass

class struct_c__SA_RTable(Structure):
    pass

class struct_r_lib_t(Structure):
    pass

class struct_sdb_t(Structure):
    pass

class struct_r_event_t(Structure):
    pass

class struct_r_bin_t(Structure):
    pass

class struct_r_fs_shell_t(Structure):
    pass

class struct_r_ascii_graph_t(Structure):
    pass

class struct_r_cmd_descriptor_t(Structure):
    pass

struct_r_cmd_descriptor_t._pack_ = 1 # source:False
struct_r_cmd_descriptor_t._fields_ = [
    ('cmd', ctypes.POINTER(ctypes.c_char)),
    ('help_msg', ctypes.POINTER(ctypes.POINTER(ctypes.c_char))),
    ('help_detail', ctypes.POINTER(ctypes.POINTER(ctypes.c_char))),
    ('help_detail2', ctypes.POINTER(ctypes.POINTER(ctypes.c_char))),
    ('sub', ctypes.POINTER(struct_r_cmd_descriptor_t) * 127),
]

struct_r_core_t._pack_ = 1 # source:False
struct_r_core_t._fields_ = [
    ('bin', ctypes.POINTER(struct_r_bin_t)),
    ('config', ctypes.POINTER(struct_r_config_t)),
    ('prj', ctypes.POINTER(struct_r_core_project_t)),
    ('offset', ctypes.c_uint64),
    ('prompt_offset', ctypes.c_uint64),
    ('blocksize', ctypes.c_uint32),
    ('blocksize_max', ctypes.c_uint32),
    ('block', ctypes.POINTER(ctypes.c_ubyte)),
    ('yank_buf', ctypes.POINTER(struct_r_buf_t)),
    ('yank_addr', ctypes.c_uint64),
    ('tmpseek', ctypes.c_bool),
    ('vmode', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 2),
    ('interrupted', ctypes.c_int32),
    ('cons', ctypes.POINTER(struct_r_cons_t)),
    ('io', ctypes.POINTER(struct_r_io_t)),
    ('num', ctypes.POINTER(struct_r_num_t)),
    ('rc', ctypes.c_uint64),
    ('lib', ctypes.POINTER(struct_r_lib_t)),
    ('rcmd', ctypes.POINTER(struct_r_cmd_t)),
    ('root_cmd_descriptor', struct_r_cmd_descriptor_t),
    ('cmd_descriptors', ctypes.POINTER(struct_r_list_t)),
    ('anal', ctypes.POINTER(struct_r_anal_t)),
    ('rasm', ctypes.POINTER(struct_r_asm_t)),
    ('times', ctypes.POINTER(struct_r_core_times_t)),
    ('parser', ctypes.POINTER(struct_r_parse_t)),
    ('print', ctypes.POINTER(struct_r_print_t)),
    ('lang', ctypes.POINTER(struct_r_lang_t)),
    ('dbg', ctypes.POINTER(struct_r_debug_t)),
    ('flags', ctypes.POINTER(struct_r_flag_t)),
    ('search', ctypes.POINTER(struct_r_search_t)),
    ('fs', ctypes.POINTER(struct_r_fs_t)),
    ('rfs', ctypes.POINTER(struct_r_fs_shell_t)),
    ('egg', ctypes.POINTER(struct_r_egg_t)),
    ('log', ctypes.POINTER(struct_r_core_log_t)),
    ('graph', ctypes.POINTER(struct_r_ascii_graph_t)),
    ('panels_root', ctypes.POINTER(struct_r_panels_root_t)),
    ('panels', ctypes.POINTER(struct_r_panels_t)),
    ('cmdqueue', ctypes.POINTER(struct_r_list_t)),
    ('lastcmd', ctypes.POINTER(ctypes.c_char)),
    ('cmdlog', ctypes.POINTER(ctypes.c_char)),
    ('cfglog', ctypes.c_bool),
    ('PADDING_1', ctypes.c_ubyte * 3),
    ('cmdrepeat', ctypes.c_int32),
    ('cmdtimes', ctypes.POINTER(ctypes.c_char)),
    ('cmd_in_backticks', ctypes.c_bool),
    ('PADDING_2', ctypes.c_ubyte * 3),
    ('rtr_n', ctypes.c_int32),
    ('rtr_host', struct_r_core_rtr_host_t * 255),
    ('asmqjmps', ctypes.POINTER(ctypes.c_uint64)),
    ('asmqjmps_count', ctypes.c_int32),
    ('asmqjmps_size', ctypes.c_int32),
    ('is_asmqjmps_letter', ctypes.c_bool),
    ('keep_asmqjmps', ctypes.c_bool),
    ('PADDING_3', ctypes.c_ubyte * 6),
    ('visual', RCoreVisual),
    ('http_up', ctypes.c_int32),
    ('gdbserver_up', ctypes.c_int32),
    ('printidx', RCoreVisualMode),
    ('PADDING_4', ctypes.c_ubyte * 4),
    ('stkcmd', ctypes.POINTER(ctypes.c_char)),
    ('in_search', ctypes.c_bool),
    ('PADDING_5', ctypes.c_ubyte * 7),
    ('watchers', ctypes.POINTER(struct_r_list_t)),
    ('scriptstack', ctypes.POINTER(struct_r_list_t)),
    ('tasks', struct_r_core_tasks_t),
    ('max_cmd_depth', ctypes.c_int32),
    ('switch_file_view', ctypes.c_ubyte),
    ('PADDING_6', ctypes.c_ubyte * 3),
    ('sdb', ctypes.POINTER(struct_sdb_t)),
    ('incomment', ctypes.c_int32),
    ('curtab', ctypes.c_int32),
    ('seltab', ctypes.c_int32),
    ('PADDING_7', ctypes.c_ubyte * 4),
    ('cmdremote', ctypes.POINTER(ctypes.c_char)),
    ('lastsearch', ctypes.POINTER(ctypes.c_char)),
    ('cmdfilter', ctypes.POINTER(ctypes.c_char)),
    ('break_loop', ctypes.c_bool),
    ('PADDING_8', ctypes.c_ubyte * 7),
    ('undos', ctypes.POINTER(struct_r_list_t)),
    ('binat', ctypes.c_bool),
    ('fixedbits', ctypes.c_bool),
    ('fixedarch', ctypes.c_bool),
    ('fixedblock', ctypes.c_bool),
    ('PADDING_9', ctypes.c_ubyte * 4),
    ('table_query', ctypes.POINTER(ctypes.c_char)),
    ('sync_index', ctypes.c_int32),
    ('PADDING_10', ctypes.c_ubyte * 4),
    ('c2', ctypes.POINTER(struct_r_core_t)),
    ('table', ctypes.POINTER(struct_c__SA_RTable)),
    ('autocomplete', ctypes.POINTER(struct_r_core_autocomplete_t)),
    ('autocomplete_type', ctypes.c_int32),
    ('maxtab', ctypes.c_int32),
    ('ev', ctypes.POINTER(struct_r_event_t)),
    ('gadgets', ctypes.POINTER(struct_r_list_t)),
    ('scr_gadgets', ctypes.c_bool),
    ('log_events', ctypes.c_bool),
    ('PADDING_11', ctypes.c_ubyte * 6),
    ('ropchain', ctypes.POINTER(struct_r_list_t)),
    ('theme', ctypes.POINTER(ctypes.c_char)),
    ('themepath', ctypes.POINTER(ctypes.c_char)),
    ('allbins', ctypes.c_bool),
    ('marks_init', ctypes.c_bool),
    ('PADDING_12', ctypes.c_ubyte * 6),
    ('marks', ctypes.c_uint64 * 256),
    ('r_main_radare2', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char)))),
    ('r_main_rafind2', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char)))),
    ('r_main_radiff2', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char)))),
    ('r_main_rabin2', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char)))),
    ('r_main_rarun2', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char)))),
    ('r_main_ragg2', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char)))),
    ('r_main_rasm2', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char)))),
    ('r_main_rax2', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char)))),
]

class struct_r_bin_file_t(Structure):
    pass

class struct_r_id_storage_t(Structure):
    pass

class struct_r_io_bind_t(Structure):
    pass

class struct_r_io_map_t(Structure):
    pass

class struct_r_io_desc_t(Structure):
    pass

class struct_r_io_bank_t(Structure):
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

class struct_r_str_constpool_t(Structure):
    pass

class struct_ht_pp_t(Structure):
    pass

struct_r_str_constpool_t._pack_ = 1 # source:False
struct_r_str_constpool_t._fields_ = [
    ('ht', ctypes.POINTER(struct_ht_pp_t)),
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
    ('demangle_usecmd', ctypes.c_bool),
    ('demangle_trylib', ctypes.c_bool),
    ('verbose', ctypes.c_bool),
    ('use_xtr', ctypes.c_bool),
    ('use_ldr', ctypes.c_bool),
    ('PADDING_6', ctypes.c_ubyte * 3),
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

class struct_r_bin_plugin_t(Structure):
    pass

class struct_r_crbtree_t(Structure):
    pass

class struct_ht_up_t(Structure):
    pass

class struct_r_bin_info_t(Structure):
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
    ('relocs', ctypes.POINTER(struct_r_crbtree_t)),
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

class struct_r_crbtree_node(Structure):
    pass

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
    ('check_buffer', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_bin_file_t), ctypes.POINTER(struct_r_buf_t))),
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

class struct_sdb_kv(Structure):
    pass

struct_sdb_kv._pack_ = 1 # source:False
struct_sdb_kv._fields_ = [
    ('base', struct_ht_pp_kv),
    ('cas', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('expire', ctypes.c_uint64),
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
    ('check_buffer', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_bin_file_t), ctypes.POINTER(struct_r_buf_t))),
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
    ('loaded', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 3),
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
    ('undo', struct_r_io_undo_t),
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
    ('init', ctypes.CFUNCTYPE(ctypes.c_bool)),
    ('undo', struct_r_io_undo_t),
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

struct_r_config_t._pack_ = 1 # source:False
struct_r_config_t._fields_ = [
    ('user', ctypes.POINTER(None)),
    ('num', ctypes.POINTER(struct_r_num_t)),
    ('cb_printf', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_char))),
    ('nodes', ctypes.POINTER(struct_r_list_t)),
    ('ht', ctypes.POINTER(struct_ht_pp_t)),
    ('lock', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
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

struct_r_core_project_t._pack_ = 1 # source:False
struct_r_core_project_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('path', ctypes.POINTER(ctypes.c_char)),
]

class struct__IO_FILE(Structure):
    pass

class struct_r_line_t(Structure):
    pass

class struct_c__SA_RConsCursorPos(Structure):
    pass

struct_c__SA_RConsCursorPos._pack_ = 1 # source:False
struct_c__SA_RConsCursorPos._fields_ = [
    ('x', ctypes.c_int32),
    ('y', ctypes.c_int32),
]

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
    ('cpos', struct_c__SA_RConsCursorPos),
]

class struct_r_stack_t(Structure):
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
    ('cpal', struct_r_cons_palette_t),
    ('PADDING_2', ctypes.c_ubyte * 6),
    ('pal', struct_r_cons_printable_palette_t),
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

class struct_r_selection_widget_t(Structure):
    pass

class struct_r_hud_t(Structure):
    pass

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

struct_r_lib_t._pack_ = 1 # source:False
struct_r_lib_t._fields_ = [
    ('symname', ctypes.POINTER(ctypes.c_char)),
    ('symnamefunc', ctypes.POINTER(ctypes.c_char)),
    ('plugins', ctypes.POINTER(struct_r_list_t)),
    ('handlers', ctypes.POINTER(struct_r_list_t)),
    ('ignore_version', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
]

class struct_r_cmd_desc_t(Structure):
    pass

class struct_r_cmd_macro_t(Structure):
    pass

class struct_r_cmd_macro_label_t(Structure):
    pass

struct_r_cmd_macro_label_t._pack_ = 1 # source:False
struct_r_cmd_macro_label_t._fields_ = [
    ('name', ctypes.c_char * 80),
    ('ptr', ctypes.POINTER(ctypes.c_char)),
]

struct_r_cmd_macro_t._pack_ = 1 # source:False
struct_r_cmd_macro_t._fields_ = [
    ('counter', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('brk_value', ctypes.POINTER(ctypes.c_uint64)),
    ('_brk_value', ctypes.c_uint64),
    ('brk', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
    ('cmd', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))),
    ('cb_printf', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_char))),
    ('user', ctypes.POINTER(None)),
    ('num', ctypes.POINTER(struct_r_num_t)),
    ('labels_n', ctypes.c_int32),
    ('PADDING_2', ctypes.c_ubyte * 4),
    ('labels', struct_r_cmd_macro_label_t * 20),
    ('macros', ctypes.POINTER(struct_r_list_t)),
]

class struct_r_cmd_item_t(Structure):
    pass

struct_r_cmd_t._pack_ = 1 # source:False
struct_r_cmd_t._fields_ = [
    ('data', ctypes.POINTER(None)),
    ('nullcallback', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None))),
    ('cmds', ctypes.POINTER(struct_r_cmd_item_t) * 255),
    ('macro', struct_r_cmd_macro_t),
    ('lcmds', ctypes.POINTER(struct_r_list_t)),
    ('plist', ctypes.POINTER(struct_r_list_t)),
    ('aliases', ctypes.POINTER(struct_ht_pp_t)),
    ('language', ctypes.POINTER(None)),
    ('ts_symbols_ht', ctypes.POINTER(struct_ht_up_t)),
    ('root_cmd_desc', ctypes.POINTER(struct_r_cmd_desc_t)),
    ('ht_cmds', ctypes.POINTER(struct_ht_pp_t)),
]

struct_r_cmd_item_t._pack_ = 1 # source:False
struct_r_cmd_item_t._fields_ = [
    ('cmd', ctypes.c_char * 64),
    ('callback', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))),
]

class struct_r_cmd_desc_help_t(Structure):
    pass

class union_r_cmd_desc_t_0(Union):
    pass

class struct_r_cmd_desc_t_0_1(Structure):
    pass


# values for enumeration 'r_cmd_status_t'
r_cmd_status_t__enumvalues = {
    0: 'R_CMD_STATUS_OK',
    1: 'R_CMD_STATUS_WRONG_ARGS',
    2: 'R_CMD_STATUS_ERROR',
    3: 'R_CMD_STATUS_INVALID',
    4: 'R_CMD_STATUS_EXIT',
}
R_CMD_STATUS_OK = 0
R_CMD_STATUS_WRONG_ARGS = 1
R_CMD_STATUS_ERROR = 2
R_CMD_STATUS_INVALID = 3
R_CMD_STATUS_EXIT = 4
r_cmd_status_t = ctypes.c_uint32 # enum
struct_r_cmd_desc_t_0_1._pack_ = 1 # source:False
struct_r_cmd_desc_t_0_1._fields_ = [
    ('cb', ctypes.CFUNCTYPE(r_cmd_status_t, ctypes.POINTER(struct_r_core_t), ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char)))),
]

class struct_r_cmd_desc_t_0_0(Structure):
    pass

struct_r_cmd_desc_t_0_0._pack_ = 1 # source:False
struct_r_cmd_desc_t_0_0._fields_ = [
    ('cb', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))),
]

class struct_r_cmd_desc_t_0_2(Structure):
    pass

struct_r_cmd_desc_t_0_2._pack_ = 1 # source:False
struct_r_cmd_desc_t_0_2._fields_ = [
    ('exec_cd', ctypes.POINTER(struct_r_cmd_desc_t)),
]

union_r_cmd_desc_t_0._pack_ = 1 # source:False
union_r_cmd_desc_t_0._anonymous_ = ('_0', '_1', '_2',)
union_r_cmd_desc_t_0._fields_ = [
    ('_0', struct_r_cmd_desc_t_0_0),
    ('_1', struct_r_cmd_desc_t_0_1),
    ('_2', struct_r_cmd_desc_t_0_2),
]


# values for enumeration 'c__EA_RCmdDescType'
c__EA_RCmdDescType__enumvalues = {
    0: 'R_CMD_DESC_TYPE_OLDINPUT',
    1: 'R_CMD_DESC_TYPE_ARGV',
    2: 'R_CMD_DESC_TYPE_INNER',
    3: 'R_CMD_DESC_TYPE_GROUP',
}
R_CMD_DESC_TYPE_OLDINPUT = 0
R_CMD_DESC_TYPE_ARGV = 1
R_CMD_DESC_TYPE_INNER = 2
R_CMD_DESC_TYPE_GROUP = 3
c__EA_RCmdDescType = ctypes.c_uint32 # enum
struct_r_cmd_desc_t._pack_ = 1 # source:False
struct_r_cmd_desc_t._anonymous_ = ('_0',)
struct_r_cmd_desc_t._fields_ = [
    ('type', c__EA_RCmdDescType),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('parent', ctypes.POINTER(struct_r_cmd_desc_t)),
    ('n_children', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
    ('children', struct_r_pvector_t),
    ('help', ctypes.POINTER(struct_r_cmd_desc_help_t)),
    ('_0', union_r_cmd_desc_t_0),
]

class struct_r_cmd_desc_example_t(Structure):
    pass

struct_r_cmd_desc_help_t._pack_ = 1 # source:False
struct_r_cmd_desc_help_t._fields_ = [
    ('summary', ctypes.POINTER(ctypes.c_char)),
    ('description', ctypes.POINTER(ctypes.c_char)),
    ('args_str', ctypes.POINTER(ctypes.c_char)),
    ('usage', ctypes.POINTER(ctypes.c_char)),
    ('options', ctypes.POINTER(ctypes.c_char)),
    ('examples', ctypes.POINTER(struct_r_cmd_desc_example_t)),
]

struct_r_cmd_desc_example_t._pack_ = 1 # source:False
struct_r_cmd_desc_example_t._fields_ = [
    ('example', ctypes.POINTER(ctypes.c_char)),
    ('comment', ctypes.POINTER(ctypes.c_char)),
]

class struct_r_anal_esil_t(Structure):
    pass

class struct_r_anal_esil_plugin_t(Structure):
    pass

class struct_r_rb_node_t(Structure):
    pass

class struct_r_anal_range_t(Structure):
    pass

class struct_r_reg_t(Structure):
    pass

class struct_r_syscall_t(Structure):
    pass

class struct_r_anal_plugin_t(Structure):
    pass

class struct_r_interval_tree_t(Structure):
    pass

class struct_r_interval_node_t(Structure):
    pass

struct_r_interval_tree_t._pack_ = 1 # source:False
struct_r_interval_tree_t._fields_ = [
    ('root', ctypes.POINTER(struct_r_interval_node_t)),
    ('free', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
]

class struct_r_flag_item_t(Structure):
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

class struct_r_spaces_t(Structure):
    pass

class struct_r_space_t(Structure):
    pass

struct_r_spaces_t._pack_ = 1 # source:False
struct_r_spaces_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('current', ctypes.POINTER(struct_r_space_t)),
    ('spaces', ctypes.POINTER(struct_r_crbtree_t)),
    ('spacestack', ctypes.POINTER(struct_r_list_t)),
    ('event', ctypes.POINTER(struct_r_event_t)),
]

class struct_r_anal_hint_cb_t(Structure):
    pass

struct_r_anal_hint_cb_t._pack_ = 1 # source:False
struct_r_anal_hint_cb_t._fields_ = [
    ('on_bits', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_int32, ctypes.c_bool)),
]

class struct_r_bin_bind_t(Structure):
    pass

class struct_r_bin_section_t(Structure):
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


# values for enumeration 'c__EA_RAnalCPPABI'
c__EA_RAnalCPPABI__enumvalues = {
    0: 'R_ANAL_CPP_ABI_ITANIUM',
    1: 'R_ANAL_CPP_ABI_MSVC',
}
R_ANAL_CPP_ABI_ITANIUM = 0
R_ANAL_CPP_ABI_MSVC = 1
c__EA_RAnalCPPABI = ctypes.c_uint32 # enum
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
    ('last_disasm_reg_size', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
    ('syscall', ctypes.POINTER(struct_r_syscall_t)),
    ('diff_ops', ctypes.c_int32),
    ('PADDING_2', ctypes.c_ubyte * 4),
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
    ('PADDING_3', ctypes.c_ubyte * 4),
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
    ('PADDING_4', ctypes.c_ubyte * 7),
    ('zign_spaces', struct_r_spaces_t),
    ('zign_path', ctypes.POINTER(ctypes.c_char)),
    ('cb_printf', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_char))),
    ('print', ctypes.POINTER(struct_r_print_t)),
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
    ('PADDING_5', ctypes.c_ubyte * 4),
    ('reflines', ctypes.POINTER(struct_r_list_t)),
    ('columnSort', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(None))),
    ('stackptr', ctypes.c_int32),
    ('PADDING_6', ctypes.c_ubyte * 4),
    ('log', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char))),
    ('read_at', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)),
    ('verbose', ctypes.c_bool),
    ('PADDING_7', ctypes.c_ubyte * 3),
    ('seggrn', ctypes.c_int32),
    ('flag_get', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_flag_item_t), ctypes.POINTER(struct_r_flag_t), ctypes.c_uint64)),
    ('ev', ctypes.POINTER(struct_r_event_t)),
    ('imports', ctypes.POINTER(struct_r_list_t)),
    ('visited', ctypes.POINTER(struct_ht_up_t)),
    ('constpool', struct_r_str_constpool_t),
    ('leaddrs', ctypes.POINTER(struct_r_list_t)),
    ('pincmd', ctypes.POINTER(ctypes.c_char)),
]

struct_r_rb_node_t._pack_ = 1 # source:False
struct_r_rb_node_t._fields_ = [
    ('parent', ctypes.POINTER(struct_r_rb_node_t)),
    ('child', ctypes.POINTER(struct_r_rb_node_t) * 2),
    ('red', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
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

class struct_r_syscall_port_t(Structure):
    pass

class struct_r_syscall_item_t(Structure):
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
    ('type', ctypes.POINTER(ctypes.c_char)),
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

class struct_r_anal_esil_handler_t(Structure):
    pass

class struct_r_anal_reil(Structure):
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
    ('parse_stop', ctypes.c_int32),
    ('parse_goto', ctypes.c_int32),
    ('parse_goto_count', ctypes.c_int32),
    ('verbose', ctypes.c_int32),
    ('flags', ctypes.c_uint64),
    ('address', ctypes.c_uint64),
    ('stack_addr', ctypes.c_uint64),
    ('stack_size', ctypes.c_uint32),
    ('delay', ctypes.c_int32),
    ('jump_target', ctypes.c_uint64),
    ('jump_target_set', ctypes.c_int32),
    ('trap', ctypes.c_int32),
    ('trap_code', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('old', ctypes.c_uint64),
    ('cur', ctypes.c_uint64),
    ('lastsz', ctypes.c_ubyte),
    ('PADDING_1', ctypes.c_ubyte * 7),
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
    ('pending', ctypes.POINTER(ctypes.c_char)),
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
    ('PADDING_2', ctypes.c_ubyte * 4),
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

class struct_r_anal_op_t(Structure):
    pass


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
    ('cpus', ctypes.POINTER(ctypes.c_char)),
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
    ('vliw', ctypes.c_int32),
]

class struct_r_reg_item_t(Structure):
    pass


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

class struct_r_anal_cond_t(Structure):
    pass

class struct_r_anal_diff_t(Structure):
    pass

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
    ('parent_reg_arena_size', ctypes.c_int32),
    ('op_pos_size', ctypes.c_int32),
    ('ninstr', ctypes.c_int32),
    ('stackptr', ctypes.c_int32),
    ('parent_stackptr', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
    ('cmpval', ctypes.c_uint64),
    ('cmpreg', ctypes.POINTER(ctypes.c_char)),
    ('bbhash', ctypes.c_uint32),
    ('PADDING_2', ctypes.c_ubyte * 4),
    ('fcns', ctypes.POINTER(struct_r_list_t)),
    ('anal', ctypes.POINTER(struct_r_anal_t)),
    ('ref', ctypes.c_int32),
    ('PADDING_3', ctypes.c_ubyte * 4),
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

class struct_r_anal_function_meta_t(Structure):
    pass

struct_r_anal_function_meta_t._pack_ = 1 # source:False
struct_r_anal_function_meta_t._fields_ = [
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
    ('meta', struct_r_anal_function_meta_t),
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

class struct_r_print_zoom_t(Structure):
    pass

class struct_r_charset_t(Structure):
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
    ('use_comments', ctypes.c_bool),
    ('PADDING_4', ctypes.c_ubyte * 3),
    ('addrmod', ctypes.c_int32),
    ('col', ctypes.c_int32),
    ('stride', ctypes.c_int32),
    ('bytespace', ctypes.c_int32),
    ('pairs', ctypes.c_int32),
    ('resetbg', ctypes.c_bool),
    ('PADDING_5', ctypes.c_ubyte * 3),
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
    ('seggrn', ctypes.c_int32),
    ('segbas', ctypes.c_int32),
    ('nbcolor', ctypes.c_int32),
    ('PADDING_10', ctypes.c_ubyte * 4),
]

struct_r_print_zoom_t._pack_ = 1 # source:False
struct_r_print_zoom_t._fields_ = [
    ('buf', ctypes.POINTER(ctypes.c_ubyte)),
    ('from', ctypes.c_uint64),
    ('to', ctypes.c_uint64),
    ('size', ctypes.c_int32),
    ('mode', ctypes.c_int32),
]

class struct_r_charset_rune_t(Structure):
    pass

struct_r_charset_t._pack_ = 1 # source:False
struct_r_charset_t._fields_ = [
    ('loaded', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
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

struct_r_interval_node_t._pack_ = 1 # source:False
struct_r_interval_node_t._fields_ = [
    ('node', struct_r_rb_node_t),
    ('start', ctypes.c_uint64),
    ('end', ctypes.c_uint64),
    ('max_end', ctypes.c_uint64),
    ('data', ctypes.POINTER(None)),
]

class struct_r_asm_plugin_t(Structure):
    pass

class struct_r_anal_bind_t(Structure):
    pass

struct_r_anal_bind_t._pack_ = 1 # source:False
struct_r_anal_bind_t._fields_ = [
    ('anal', ctypes.POINTER(struct_r_anal_t)),
    ('get_fcn_in', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_anal_function_t), ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_int32)),
    ('get_hint', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_anal_hint_t), ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64)),
    ('decode', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_op_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, c__EA_RAnalOpMask)),
    ('opinit', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_anal_op_t))),
    ('opfini', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_anal_op_t))),
]

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
    ('analb', struct_r_anal_bind_t),
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

class struct_r_bp_t(Structure):
    pass

class struct_r_tree_t(Structure):
    pass

class struct_r_debug_plugin_t(Structure):
    pass

class struct_r_debug_session_t(Structure):
    pass

class struct_r_debug_trace_t(Structure):
    pass

class struct_pj_t(Structure):
    pass

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
    ('reason', struct_r_debug_reason_t),
    ('recoil_mode', c__EA_RDebugRecoilMode),
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

class struct_r_bp_plugin_t(Structure):
    pass

class struct_r_bp_item_t(Structure):
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


# values for enumeration 'c__EA_RDebugReasonType'
c__EA_RDebugReasonType__enumvalues = {
    -1: 'R_DEBUG_REASON_DEAD',
    0: 'R_DEBUG_REASON_NONE',
    1: 'R_DEBUG_REASON_SIGNAL',
    2: 'R_DEBUG_REASON_BREAKPOINT',
    3: 'R_DEBUG_REASON_TRACEPOINT',
    4: 'R_DEBUG_REASON_COND',
    5: 'R_DEBUG_REASON_READERR',
    6: 'R_DEBUG_REASON_STEP',
    7: 'R_DEBUG_REASON_ABORT',
    8: 'R_DEBUG_REASON_WRITERR',
    9: 'R_DEBUG_REASON_DIVBYZERO',
    10: 'R_DEBUG_REASON_ILLEGAL',
    11: 'R_DEBUG_REASON_UNKNOWN',
    12: 'R_DEBUG_REASON_ERROR',
    13: 'R_DEBUG_REASON_NEW_PID',
    14: 'R_DEBUG_REASON_NEW_TID',
    15: 'R_DEBUG_REASON_NEW_LIB',
    16: 'R_DEBUG_REASON_EXIT_PID',
    17: 'R_DEBUG_REASON_EXIT_TID',
    18: 'R_DEBUG_REASON_EXIT_LIB',
    19: 'R_DEBUG_REASON_TRAP',
    20: 'R_DEBUG_REASON_SWI',
    21: 'R_DEBUG_REASON_INT',
    22: 'R_DEBUG_REASON_FPU',
    23: 'R_DEBUG_REASON_USERSUSP',
    24: 'R_DEBUG_REASON_SEGFAULT',
    25: 'R_DEBUG_REASON_STOPPED',
    26: 'R_DEBUG_REASON_TERMINATED',
}
R_DEBUG_REASON_DEAD = -1
R_DEBUG_REASON_NONE = 0
R_DEBUG_REASON_SIGNAL = 1
R_DEBUG_REASON_BREAKPOINT = 2
R_DEBUG_REASON_TRACEPOINT = 3
R_DEBUG_REASON_COND = 4
R_DEBUG_REASON_READERR = 5
R_DEBUG_REASON_STEP = 6
R_DEBUG_REASON_ABORT = 7
R_DEBUG_REASON_WRITERR = 8
R_DEBUG_REASON_DIVBYZERO = 9
R_DEBUG_REASON_ILLEGAL = 10
R_DEBUG_REASON_UNKNOWN = 11
R_DEBUG_REASON_ERROR = 12
R_DEBUG_REASON_NEW_PID = 13
R_DEBUG_REASON_NEW_TID = 14
R_DEBUG_REASON_NEW_LIB = 15
R_DEBUG_REASON_EXIT_PID = 16
R_DEBUG_REASON_EXIT_TID = 17
R_DEBUG_REASON_EXIT_LIB = 18
R_DEBUG_REASON_TRAP = 19
R_DEBUG_REASON_SWI = 20
R_DEBUG_REASON_INT = 21
R_DEBUG_REASON_FPU = 22
R_DEBUG_REASON_USERSUSP = 23
R_DEBUG_REASON_SEGFAULT = 24
R_DEBUG_REASON_STOPPED = 25
R_DEBUG_REASON_TERMINATED = 26
c__EA_RDebugReasonType = ctypes.c_int32 # enum
class struct_r_debug_map_t(Structure):
    pass

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
    ('attach', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_debug_t), ctypes.c_int32)),
    ('detach', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_debug_t), ctypes.c_int32)),
    ('select', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_debug_t), ctypes.c_int32, ctypes.c_int32)),
    ('threads', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_debug_t), ctypes.c_int32)),
    ('pids', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_debug_t), ctypes.c_int32)),
    ('tids', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_debug_t), ctypes.c_int32)),
    ('backtrace', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.POINTER(None)), ctypes.POINTER(struct_r_debug_t), ctypes.c_int32)),
    ('stop', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_debug_t))),
    ('step', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_debug_t))),
    ('step_over', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_debug_t))),
    ('cont', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_debug_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32)),
    ('wait', ctypes.CFUNCTYPE(c__EA_RDebugReasonType, ctypes.POINTER(struct_r_debug_t), ctypes.c_int32)),
    ('gcore', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_debug_t), ctypes.POINTER(struct_r_buf_t))),
    ('kill', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_debug_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32)),
    ('kill_list', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_debug_t))),
    ('contsc', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_debug_t), ctypes.c_int32, ctypes.c_int32)),
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
    ('init', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_debug_t))),
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

class struct_r_debug_checkpoint_t(Structure):
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

struct_r_debug_checkpoint_t._pack_ = 1 # source:False
struct_r_debug_checkpoint_t._fields_ = [
    ('cnum', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('arena', ctypes.POINTER(struct_r_reg_arena_t) * 8),
    ('snaps', ctypes.POINTER(struct_r_list_t)),
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

class struct_r_egg_lang_t(Structure):
    pass

class struct_r_egg_lang_t_2(Structure):
    pass

struct_r_egg_lang_t_2._pack_ = 1 # source:False
struct_r_egg_lang_t_2._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('content', ctypes.POINTER(ctypes.c_char)),
]

class struct_r_egg_lang_t_1(Structure):
    pass

struct_r_egg_lang_t_1._pack_ = 1 # source:False
struct_r_egg_lang_t_1._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('arg', ctypes.POINTER(ctypes.c_char)),
]

class struct_r_egg_lang_t_0(Structure):
    pass

struct_r_egg_lang_t_0._pack_ = 1 # source:False
struct_r_egg_lang_t_0._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('body', ctypes.POINTER(ctypes.c_char)),
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

class struct_r_search_keyword_t(Structure):
    pass

struct_r_search_t._pack_ = 1 # source:False
struct_r_search_t._fields_ = [
    ('n_kws', ctypes.c_int32),
    ('mode', ctypes.c_int32),
    ('longest', ctypes.c_int32),
    ('pattern_size', ctypes.c_uint32),
    ('string_min', ctypes.c_uint32),
    ('string_max', ctypes.c_uint32),
    ('data', ctypes.POINTER(None)),
    ('datafree', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
    ('user', ctypes.POINTER(None)),
    ('callback', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_search_keyword_t), ctypes.POINTER(None), ctypes.c_uint64)),
    ('nhits', ctypes.c_uint64),
    ('maxhits', ctypes.c_uint64),
    ('hits', ctypes.POINTER(struct_r_list_t)),
    ('distance', ctypes.c_int32),
    ('inverse', ctypes.c_int32),
    ('overlap', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 3),
    ('contiguous', ctypes.c_int32),
    ('align', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
    ('update', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_search_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)),
    ('kws', ctypes.POINTER(struct_r_list_t)),
    ('iob', struct_r_io_bind_t),
    ('bckwrds', ctypes.c_char),
    ('PADDING_2', ctypes.c_ubyte * 7),
]

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

struct_r_fs_t._pack_ = 1 # source:False
struct_r_fs_t._fields_ = [
    ('iob', struct_r_io_bind_t),
    ('cob', struct_r_core_bind_t),
    ('csb', struct_r_cons_bind_t),
    ('plugins', ctypes.POINTER(struct_r_list_t)),
    ('roots', ctypes.POINTER(struct_r_list_t)),
    ('view', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('ptr', ctypes.POINTER(None)),
]

struct_r_fs_shell_t._pack_ = 1 # source:False
struct_r_fs_shell_t._fields_ = [
    ('cwd', ctypes.POINTER(ctypes.POINTER(ctypes.c_char))),
    ('set_prompt', ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_char))),
    ('readline', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char))),
    ('hist_add', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_char))),
]

class struct_layer_t(Structure):
    pass

class struct_r_ascii_node_t(Structure):
    pass

class struct_r_graph_t(Structure):
    pass

class struct_r_graph_node_t(Structure):
    pass

class struct_r_cons_canvas_t(Structure):
    pass

class struct_r_core_graph_hits_t(Structure):
    pass

struct_r_core_graph_hits_t._pack_ = 1 # source:False
struct_r_core_graph_hits_t._fields_ = [
    ('old_word', ctypes.POINTER(ctypes.c_char)),
    ('word_list', struct_r_vector_t),
    ('word_nth', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

struct_r_ascii_graph_t._pack_ = 1 # source:False
struct_r_ascii_graph_t._fields_ = [
    ('can', ctypes.POINTER(struct_r_cons_canvas_t)),
    ('graph', ctypes.POINTER(struct_r_graph_t)),
    ('curnode', ctypes.POINTER(struct_r_graph_node_t)),
    ('title', ctypes.POINTER(ctypes.c_char)),
    ('db', ctypes.POINTER(struct_sdb_t)),
    ('nodes', ctypes.POINTER(struct_sdb_t)),
    ('layout', ctypes.c_int32),
    ('is_instep', ctypes.c_int32),
    ('is_tiny', ctypes.c_bool),
    ('is_dis', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 2),
    ('edgemode', ctypes.c_int32),
    ('mode', ctypes.c_int32),
    ('is_callgraph', ctypes.c_bool),
    ('is_interactive', ctypes.c_bool),
    ('PADDING_1', ctypes.c_ubyte * 2),
    ('zoom', ctypes.c_int32),
    ('movspeed', ctypes.c_int32),
    ('hints', ctypes.c_bool),
    ('PADDING_2', ctypes.c_ubyte * 7),
    ('update_seek_on', ctypes.POINTER(struct_r_ascii_node_t)),
    ('need_reload_nodes', ctypes.c_bool),
    ('need_set_layout', ctypes.c_bool),
    ('PADDING_3', ctypes.c_ubyte * 2),
    ('need_update_dim', ctypes.c_int32),
    ('force_update_seek', ctypes.c_int32),
    ('PADDING_4', ctypes.c_ubyte * 4),
    ('on_curnode_change', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_ascii_node_t), ctypes.POINTER(None))),
    ('on_curnode_change_data', ctypes.POINTER(None)),
    ('dummy', ctypes.c_bool),
    ('show_node_titles', ctypes.c_bool),
    ('show_node_body', ctypes.c_bool),
    ('show_node_bubble', ctypes.c_bool),
    ('x', ctypes.c_int32),
    ('y', ctypes.c_int32),
    ('w', ctypes.c_int32),
    ('h', ctypes.c_int32),
    ('PADDING_5', ctypes.c_ubyte * 4),
    ('back_edges', ctypes.POINTER(struct_r_list_t)),
    ('long_edges', ctypes.POINTER(struct_r_list_t)),
    ('layers', ctypes.POINTER(struct_layer_t)),
    ('n_layers', ctypes.c_uint32),
    ('PADDING_6', ctypes.c_ubyte * 4),
    ('dists', ctypes.POINTER(struct_r_list_t)),
    ('edges', ctypes.POINTER(struct_r_list_t)),
    ('ghits', struct_r_core_graph_hits_t),
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

struct_r_graph_t._pack_ = 1 # source:False
struct_r_graph_t._fields_ = [
    ('n_nodes', ctypes.c_uint32),
    ('n_edges', ctypes.c_uint32),
    ('last_index', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('nodes', ctypes.POINTER(struct_r_list_t)),
]

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

struct_r_ascii_node_t._pack_ = 1 # source:False
struct_r_ascii_node_t._fields_ = [
    ('gnode', ctypes.POINTER(struct_r_graph_node_t)),
    ('title', ctypes.POINTER(ctypes.c_char)),
    ('body', ctypes.POINTER(ctypes.c_char)),
    ('color', ctypes.POINTER(ctypes.c_char)),
    ('x', ctypes.c_int32),
    ('y', ctypes.c_int32),
    ('w', ctypes.c_int32),
    ('h', ctypes.c_int32),
    ('layer', ctypes.c_int32),
    ('layer_height', ctypes.c_int32),
    ('layer_width', ctypes.c_int32),
    ('pos_in_layer', ctypes.c_int32),
    ('is_dummy', ctypes.c_int32),
    ('is_reversed', ctypes.c_int32),
    ('klass', ctypes.c_int32),
    ('difftype', ctypes.c_int32),
    ('is_mini', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
]


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
struct_r_panels_root_t._pack_ = 1 # source:False
struct_r_panels_root_t._fields_ = [
    ('n_panels', ctypes.c_int32),
    ('cur_panels', ctypes.c_int32),
    ('pdc_caches', ctypes.POINTER(struct_sdb_t)),
    ('cur_pdc_cache', ctypes.POINTER(struct_sdb_t)),
    ('panels', ctypes.POINTER(ctypes.POINTER(struct_r_panels_t))),
    ('root_state', c__EA_RPanelsRootState),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

class struct_r_panels_menu_t(Structure):
    pass


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

# values for enumeration 'c__EA_RPanelsLayout'
c__EA_RPanelsLayout__enumvalues = {
    0: 'PANEL_LAYOUT_DEFAULT_STATIC',
    1: 'PANEL_LAYOUT_DEFAULT_DYNAMIC',
}
PANEL_LAYOUT_DEFAULT_STATIC = 0
PANEL_LAYOUT_DEFAULT_DYNAMIC = 1
c__EA_RPanelsLayout = ctypes.c_uint32 # enum
class struct_r_panel_t(Structure):
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
    ('mode', c__EA_RPanelsMode),
    ('fun', c__EA_RPanelsFun),
    ('prevMode', c__EA_RPanelsMode),
    ('layout', c__EA_RPanelsLayout),
    ('snows', ctypes.POINTER(struct_r_list_t)),
    ('name', ctypes.POINTER(ctypes.c_char)),
]

class struct_r_panel_view_t(Structure):
    pass

class struct_r_panel_model_t(Structure):
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

class struct_r_panels_menu_item(Structure):
    pass

struct_r_panels_menu_t._pack_ = 1 # source:False
struct_r_panels_menu_t._fields_ = [
    ('root', ctypes.POINTER(struct_r_panels_menu_item)),
    ('history', ctypes.POINTER(ctypes.POINTER(struct_r_panels_menu_item))),
    ('depth', ctypes.c_int32),
    ('n_refresh', ctypes.c_int32),
    ('refreshPanels', ctypes.POINTER(ctypes.POINTER(struct_r_panel_t))),
]

struct_r_panels_menu_item._pack_ = 1 # source:False
struct_r_panels_menu_item._fields_ = [
    ('n_sub', ctypes.c_int32),
    ('selectedIndex', ctypes.c_int32),
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('sub', ctypes.POINTER(ctypes.POINTER(struct_r_panels_menu_item))),
    ('cb', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None))),
    ('p', ctypes.POINTER(struct_r_panel_t)),
]

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

class union_c__UA_pthread_cond_t(Union):
    pass

class struct___pthread_cond_s(Structure):
    pass

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

RCoreTaskScheduler = struct_r_core_tasks_t
RProject = struct_r_core_project_t
r_project_new = _libr_core.r_project_new
r_project_new.restype = ctypes.POINTER(struct_r_core_project_t)
r_project_new.argtypes = []
r_project_rename = _libr_core.r_project_rename
r_project_rename.restype = ctypes.c_bool
r_project_rename.argtypes = [ctypes.POINTER(struct_r_core_project_t), ctypes.POINTER(ctypes.c_char)]
r_project_is_git = _libr_core.r_project_is_git
r_project_is_git.restype = ctypes.c_bool
r_project_is_git.argtypes = [ctypes.POINTER(struct_r_core_project_t)]
r_project_close = _libr_core.r_project_close
r_project_close.restype = None
r_project_close.argtypes = [ctypes.POINTER(struct_r_core_project_t)]
r_project_open = _libr_core.r_project_open
r_project_open.restype = ctypes.c_bool
r_project_open.argtypes = [ctypes.POINTER(struct_r_core_project_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_project_save = _libr_core.r_project_save
r_project_save.restype = None
r_project_save.argtypes = [ctypes.POINTER(struct_r_core_project_t)]
r_project_free = _libr_core.r_project_free
r_project_free.restype = None
r_project_free.argtypes = [ctypes.POINTER(struct_r_core_project_t)]
r_project_is_loaded = _libr_core.r_project_is_loaded
r_project_is_loaded.restype = ctypes.c_bool
r_project_is_loaded.argtypes = [ctypes.POINTER(struct_r_core_project_t)]
r_core_project_is_saved = _libr_core.r_core_project_is_saved
r_core_project_is_saved.restype = ctypes.c_bool
r_core_project_is_saved.argtypes = [ctypes.POINTER(struct_r_core_t)]
class struct_r_core_item_t(Structure):
    pass

struct_r_core_item_t._pack_ = 1 # source:False
struct_r_core_item_t._fields_ = [
    ('type', ctypes.POINTER(ctypes.c_char)),
    ('addr', ctypes.c_uint64),
    ('next', ctypes.c_uint64),
    ('prev', ctypes.c_uint64),
    ('size', ctypes.c_int32),
    ('perm', ctypes.c_int32),
    ('data', ctypes.POINTER(ctypes.c_char)),
    ('comment', ctypes.POINTER(ctypes.c_char)),
    ('sectname', ctypes.POINTER(ctypes.c_char)),
    ('fcnname', ctypes.POINTER(ctypes.c_char)),
]

RCoreItem = struct_r_core_item_t
r_core_item_at = _libr_core.r_core_item_at
r_core_item_at.restype = ctypes.POINTER(struct_r_core_item_t)
r_core_item_at.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
r_core_item_free = _libr_core.r_core_item_free
r_core_item_free.restype = None
r_core_item_free.argtypes = [ctypes.POINTER(struct_r_core_item_t)]
r_core_bind = _libr_core.r_core_bind
r_core_bind.restype = ctypes.c_int32
r_core_bind.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(struct_r_core_bind_t)]
class struct_r_core_cmpwatch_t(Structure):
    pass

struct_r_core_cmpwatch_t._pack_ = 1 # source:False
struct_r_core_cmpwatch_t._fields_ = [
    ('addr', ctypes.c_uint64),
    ('size', ctypes.c_int32),
    ('cmd', ctypes.c_char * 32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('odata', ctypes.POINTER(ctypes.c_ubyte)),
    ('ndata', ctypes.POINTER(ctypes.c_ubyte)),
]

RCoreCmpWatcher = struct_r_core_cmpwatch_t
RCoreSearchCallback = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)
r_core_list_themes = _libr_core.r_core_list_themes
r_core_list_themes.restype = ctypes.POINTER(struct_r_list_t)
r_core_list_themes.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_get_theme = _libr_core.r_core_get_theme
r_core_get_theme.restype = ctypes.POINTER(ctypes.c_char)
r_core_get_theme.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_get_section_name = _libr_core.r_core_get_section_name
r_core_get_section_name.restype = ctypes.POINTER(ctypes.c_char)
r_core_get_section_name.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
r_core_get_cons = _libr_core.r_core_get_cons
r_core_get_cons.restype = ctypes.POINTER(struct_r_cons_t)
r_core_get_cons.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_get_bin = _libr_core.r_core_get_bin
r_core_get_bin.restype = ctypes.POINTER(struct_r_bin_t)
r_core_get_bin.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_get_config = _libr_core.r_core_get_config
r_core_get_config.restype = ctypes.POINTER(struct_r_config_t)
r_core_get_config.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_init = _libr_core.r_core_init
r_core_init.restype = ctypes.c_bool
r_core_init.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_bind_cons = _libr_core.r_core_bind_cons
r_core_bind_cons.restype = None
r_core_bind_cons.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_new = _libr_core.r_core_new
r_core_new.restype = ctypes.POINTER(struct_r_core_t)
r_core_new.argtypes = []
r_core_free = _libr_core.r_core_free
r_core_free.restype = None
r_core_free.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_fini = _libr_core.r_core_fini
r_core_fini.restype = None
r_core_fini.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_wait = _libr_core.r_core_wait
r_core_wait.restype = None
r_core_wait.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_ncast = _libr_core.r_core_ncast
r_core_ncast.restype = ctypes.POINTER(struct_r_core_t)
r_core_ncast.argtypes = [ctypes.c_uint64]
r_core_cast = _libr_core.r_core_cast
r_core_cast.restype = ctypes.POINTER(struct_r_core_t)
r_core_cast.argtypes = [ctypes.POINTER(None)]
r_core_bin_load_structs = _libr_core.r_core_bin_load_structs
r_core_bin_load_structs.restype = ctypes.c_bool
r_core_bin_load_structs.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_config_init = _libr_core.r_core_config_init
r_core_config_init.restype = ctypes.c_int32
r_core_config_init.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_config_update = _libr_core.r_core_config_update
r_core_config_update.restype = None
r_core_config_update.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_parse_radare2rc = _libr_core.r_core_parse_radare2rc
r_core_parse_radare2rc.restype = None
r_core_parse_radare2rc.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_prompt = _libr_core.r_core_prompt
r_core_prompt.restype = ctypes.c_int32
r_core_prompt.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_int32]
r_core_prompt_exec = _libr_core.r_core_prompt_exec
r_core_prompt_exec.restype = ctypes.c_int32
r_core_prompt_exec.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_lines_initcache = _libr_core.r_core_lines_initcache
r_core_lines_initcache.restype = ctypes.c_int32
r_core_lines_initcache.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_uint64]
r_core_lines_currline = _libr_core.r_core_lines_currline
r_core_lines_currline.restype = ctypes.c_int32
r_core_lines_currline.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_prompt_loop = _libr_core.r_core_prompt_loop
r_core_prompt_loop.restype = ctypes.c_bool
r_core_prompt_loop.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_pava = _libr_core.r_core_pava
r_core_pava.restype = ctypes.c_uint64
r_core_pava.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
r_core_cmd = _libr_core.r_core_cmd
r_core_cmd.restype = ctypes.c_int32
r_core_cmd.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), ctypes.c_bool]
r_core_cmd_task_sync = _libr_core.r_core_cmd_task_sync
r_core_cmd_task_sync.restype = ctypes.c_int32
r_core_cmd_task_sync.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), ctypes.c_bool]
r_core_editor = _libr_core.r_core_editor
r_core_editor.restype = ctypes.POINTER(ctypes.c_char)
r_core_editor.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_core_fgets = _libr_core.r_core_fgets
r_core_fgets.restype = ctypes.c_int32
r_core_fgets.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_core_flag_get_by_spaces = _libr_core.r_core_flag_get_by_spaces
r_core_flag_get_by_spaces.restype = ctypes.POINTER(struct_r_flag_item_t)
r_core_flag_get_by_spaces.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.c_uint64]
r_core_cmdf = _libr_core.r_core_cmdf
r_core_cmdf.restype = ctypes.c_int32
r_core_cmdf.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_cmd0 = _libr_core.r_core_cmd0
r_core_cmd0.restype = ctypes.c_int32
r_core_cmd0.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_cmd_queue = _libr_core.r_core_cmd_queue
r_core_cmd_queue.restype = None
r_core_cmd_queue.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_cmd_queue_wait = _libr_core.r_core_cmd_queue_wait
r_core_cmd_queue_wait.restype = None
r_core_cmd_queue_wait.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_cmd_init = _libr_core.r_core_cmd_init
r_core_cmd_init.restype = None
r_core_cmd_init.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_cmd_pipe = _libr_core.r_core_cmd_pipe
r_core_cmd_pipe.restype = ctypes.c_int32
r_core_cmd_pipe.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_core_cmd_str = _libr_core.r_core_cmd_str
r_core_cmd_str.restype = ctypes.POINTER(ctypes.c_char)
r_core_cmd_str.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_cmd_strf = _libr_core.r_core_cmd_strf
r_core_cmd_strf.restype = ctypes.POINTER(ctypes.c_char)
r_core_cmd_strf.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_cmd_str_pipe = _libr_core.r_core_cmd_str_pipe
r_core_cmd_str_pipe.restype = ctypes.POINTER(ctypes.c_char)
r_core_cmd_str_pipe.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_cmd_tobuf = _libr_core.r_core_cmd_tobuf
r_core_cmd_tobuf.restype = ctypes.POINTER(struct_r_buf_t)
r_core_cmd_tobuf.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_cmd_file = _libr_core.r_core_cmd_file
r_core_cmd_file.restype = ctypes.c_int32
r_core_cmd_file.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_cmd_lines = _libr_core.r_core_cmd_lines
r_core_cmd_lines.restype = ctypes.c_int32
r_core_cmd_lines.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_cmd_command = _libr_core.r_core_cmd_command
r_core_cmd_command.restype = ctypes.c_int32
r_core_cmd_command.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_af = _libr_core.r_core_af
r_core_af.restype = None
r_core_af.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_char), ctypes.c_bool]
r_core_run_script = _libr_core.r_core_run_script
r_core_run_script.restype = ctypes.c_bool
r_core_run_script.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_seek = _libr_core.r_core_seek
r_core_seek.restype = ctypes.c_bool
r_core_seek.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_bool]
r_core_visual_bit_editor = _libr_core.r_core_visual_bit_editor
r_core_visual_bit_editor.restype = ctypes.c_bool
r_core_visual_bit_editor.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_seek_base = _libr_core.r_core_seek_base
r_core_seek_base.restype = ctypes.c_int32
r_core_seek_base.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_seek_previous = _libr_core.r_core_seek_previous
r_core_seek_previous.restype = None
r_core_seek_previous.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_seek_next = _libr_core.r_core_seek_next
r_core_seek_next.restype = None
r_core_seek_next.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_seek_align = _libr_core.r_core_seek_align
r_core_seek_align.restype = ctypes.c_int32
r_core_seek_align.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_int32]
r_core_arch_bits_at = _libr_core.r_core_arch_bits_at
r_core_arch_bits_at.restype = None
r_core_arch_bits_at.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
r_core_seek_arch_bits = _libr_core.r_core_seek_arch_bits
r_core_seek_arch_bits.restype = None
r_core_seek_arch_bits.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
r_core_block_read = _libr_core.r_core_block_read
r_core_block_read.restype = ctypes.c_int32
r_core_block_read.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_block_size = _libr_core.r_core_block_size
r_core_block_size.restype = ctypes.c_int32
r_core_block_size.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_int32]
r_core_seek_size = _libr_core.r_core_seek_size
r_core_seek_size.restype = ctypes.c_int32
r_core_seek_size.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_int32]
r_core_is_valid_offset = _libraries['FIXME_STUB'].r_core_is_valid_offset
r_core_is_valid_offset.restype = ctypes.c_int32
r_core_is_valid_offset.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
r_core_shift_block = _libr_core.r_core_shift_block
r_core_shift_block.restype = ctypes.c_int32
r_core_shift_block.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int64]
RLinePromptType = c__EA_RLinePromptType
RLinePromptType__enumvalues = c__EA_RLinePromptType__enumvalues
r_core_autocomplete = _libr_core.r_core_autocomplete
r_core_autocomplete.restype = None
r_core_autocomplete.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(struct_r_line_comp_t), ctypes.POINTER(struct_r_line_buffer_t), RLinePromptType]
r_core_print_scrollbar = _libr_core.r_core_print_scrollbar
r_core_print_scrollbar.restype = None
r_core_print_scrollbar.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_print_scrollbar_bottom = _libr_core.r_core_print_scrollbar_bottom
r_core_print_scrollbar_bottom.restype = None
r_core_print_scrollbar_bottom.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_visual_prompt_input = _libr_core.r_core_visual_prompt_input
r_core_visual_prompt_input.restype = None
r_core_visual_prompt_input.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_visual_toggle_decompiler_disasm = _libr_core.r_core_visual_toggle_decompiler_disasm
r_core_visual_toggle_decompiler_disasm.restype = None
r_core_visual_toggle_decompiler_disasm.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_bool, ctypes.c_bool]
r_core_visual_applyDisMode = _libr_core.r_core_visual_applyDisMode
r_core_visual_applyDisMode.restype = None
r_core_visual_applyDisMode.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_int32]
r_core_visual_applyHexMode = _libr_core.r_core_visual_applyHexMode
r_core_visual_applyHexMode.restype = None
r_core_visual_applyHexMode.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_int32]
r_core_visual_refs = _libr_core.r_core_visual_refs
r_core_visual_refs.restype = ctypes.c_int32
r_core_visual_refs.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_bool, ctypes.c_bool]
r_core_visual_append_help = _libr_core.r_core_visual_append_help
r_core_visual_append_help.restype = None
r_core_visual_append_help.argtypes = [ctypes.POINTER(struct_c__SA_RStrBuf), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
r_core_prevop_addr = _libr_core.r_core_prevop_addr
r_core_prevop_addr.restype = ctypes.c_bool
r_core_prevop_addr.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_int32, ctypes.POINTER(ctypes.c_uint64)]
r_core_prevop_addr_force = _libr_core.r_core_prevop_addr_force
r_core_prevop_addr_force.restype = ctypes.c_uint64
r_core_prevop_addr_force.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_int32]
r_core_visual_hudstuff = _libr_core.r_core_visual_hudstuff
r_core_visual_hudstuff.restype = ctypes.c_bool
r_core_visual_hudstuff.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_visual_classes = _libr_core.r_core_visual_classes
r_core_visual_classes.restype = ctypes.c_int32
r_core_visual_classes.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_visual_anal_classes = _libr_core.r_core_visual_anal_classes
r_core_visual_anal_classes.restype = ctypes.c_int32
r_core_visual_anal_classes.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_visual_types = _libr_core.r_core_visual_types
r_core_visual_types.restype = ctypes.c_int32
r_core_visual_types.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_visual = _libr_core.r_core_visual
r_core_visual.restype = ctypes.c_int32
r_core_visual.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_visual_graph = _libr_core.r_core_visual_graph
r_core_visual_graph.restype = ctypes.c_int32
r_core_visual_graph.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(struct_r_ascii_graph_t), ctypes.POINTER(struct_r_anal_function_t), ctypes.c_int32]
r_core_visual_browse = _libr_core.r_core_visual_browse
r_core_visual_browse.restype = None
r_core_visual_browse.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_visual_cmd = _libr_core.r_core_visual_cmd
r_core_visual_cmd.restype = ctypes.c_int32
r_core_visual_cmd.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_visual_seek_animation = _libr_core.r_core_visual_seek_animation
r_core_visual_seek_animation.restype = None
r_core_visual_seek_animation.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
r_core_visual_asm = _libr_core.r_core_visual_asm
r_core_visual_asm.restype = None
r_core_visual_asm.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
r_core_visual_colors = _libr_core.r_core_visual_colors
r_core_visual_colors.restype = None
r_core_visual_colors.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_visual_xrefs_x = _libraries['FIXME_STUB'].r_core_visual_xrefs_x
r_core_visual_xrefs_x.restype = ctypes.c_int32
r_core_visual_xrefs_x.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_visual_xrefs_X = _libraries['FIXME_STUB'].r_core_visual_xrefs_X
r_core_visual_xrefs_X.restype = ctypes.c_int32
r_core_visual_xrefs_X.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_visual_showcursor = _libr_core.r_core_visual_showcursor
r_core_visual_showcursor.restype = None
r_core_visual_showcursor.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_int32]
r_core_visual_offset = _libr_core.r_core_visual_offset
r_core_visual_offset.restype = None
r_core_visual_offset.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_visual_hud = _libr_core.r_core_visual_hud
r_core_visual_hud.restype = ctypes.c_int32
r_core_visual_hud.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_visual_jump = _libr_core.r_core_visual_jump
r_core_visual_jump.restype = None
r_core_visual_jump.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_ubyte]
r_core_visual_disasm_up = _libr_core.r_core_visual_disasm_up
r_core_visual_disasm_up.restype = None
r_core_visual_disasm_up.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_int32)]
r_core_visual_disasm_down = _libr_core.r_core_visual_disasm_down
r_core_visual_disasm_down.restype = None
r_core_visual_disasm_down.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(struct_r_asm_op_t), ctypes.POINTER(ctypes.c_int32)]
class struct_r_bin_reloc_t(Structure):
    pass

class struct_r_bin_symbol_t(Structure):
    pass

class struct_r_bin_import_t(Structure):
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
]

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

r_core_getreloc = _libr_core.r_core_getreloc
r_core_getreloc.restype = ctypes.POINTER(struct_r_bin_reloc_t)
r_core_getreloc.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_int32]
r_core_get_asmqjmps = _libr_core.r_core_get_asmqjmps
r_core_get_asmqjmps.restype = ctypes.c_uint64
r_core_get_asmqjmps.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
size_t = ctypes.c_uint64
r_core_set_asmqjmps = _libr_core.r_core_set_asmqjmps
r_core_set_asmqjmps.restype = None
r_core_set_asmqjmps.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), size_t, ctypes.c_int32]
r_core_add_asmqjmp = _libr_core.r_core_add_asmqjmp
r_core_add_asmqjmp.restype = ctypes.POINTER(ctypes.c_char)
r_core_add_asmqjmp.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
r_core_panels_root = _libr_core.r_core_panels_root
r_core_panels_root.restype = ctypes.c_bool
r_core_panels_root.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(struct_r_panels_root_t)]
r_core_panels_save = _libr_core.r_core_panels_save
r_core_panels_save.restype = None
r_core_panels_save.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_panels_load = _libr_core.r_core_panels_load
r_core_panels_load.restype = ctypes.c_bool
r_core_panels_load.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_anal_type_init = _libr_core.r_core_anal_type_init
r_core_anal_type_init.restype = None
r_core_anal_type_init.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_anal_hasrefs_to_depth = _libr_core.r_core_anal_hasrefs_to_depth
r_core_anal_hasrefs_to_depth.restype = ctypes.POINTER(ctypes.c_char)
r_core_anal_hasrefs_to_depth.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.POINTER(struct_pj_t), ctypes.c_int32]
r_core_link_stroff = _libr_core.r_core_link_stroff
r_core_link_stroff.restype = None
r_core_link_stroff.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(struct_r_anal_function_t)]
r_core_anal_inflags = _libr_core.r_core_anal_inflags
r_core_anal_inflags.restype = None
r_core_anal_inflags.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
cmd_anal_objc = _libr_core.cmd_anal_objc
cmd_anal_objc.restype = ctypes.c_bool
cmd_anal_objc.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), ctypes.c_bool]
r_core_anal_cc_init = _libr_core.r_core_anal_cc_init
r_core_anal_cc_init.restype = None
r_core_anal_cc_init.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_anal_paths = _libr_core.r_core_anal_paths
r_core_anal_paths.restype = None
r_core_anal_paths.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_uint64, ctypes.c_bool, ctypes.c_int32, ctypes.c_bool]
r_core_list_io = _libraries['FIXME_STUB'].r_core_list_io
r_core_list_io.restype = None
r_core_list_io.argtypes = [ctypes.POINTER(struct_r_core_t)]
class struct_c__SA_RListInfo(Structure):
    pass

struct_c__SA_RListInfo._pack_ = 1 # source:False
struct_c__SA_RListInfo._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('pitv', struct_r_interval_t),
    ('vitv', struct_r_interval_t),
    ('perm', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('extra', ctypes.POINTER(ctypes.c_char)),
]

RInterval = struct_r_interval_t
r_listinfo_new = _libr_core.r_listinfo_new
r_listinfo_new.restype = ctypes.POINTER(struct_c__SA_RListInfo)
r_listinfo_new.argtypes = [ctypes.POINTER(ctypes.c_char), RInterval, RInterval, ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
r_listinfo_free = _libr_core.r_listinfo_free
r_listinfo_free.restype = None
r_listinfo_free.argtypes = [ctypes.POINTER(struct_c__SA_RListInfo)]
r_core_visual_slides = _libr_core.r_core_visual_slides
r_core_visual_slides.restype = None
r_core_visual_slides.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_visual_mark_seek = _libr_core.r_core_visual_mark_seek
r_core_visual_mark_seek.restype = None
r_core_visual_mark_seek.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_ubyte]
r_core_visual_mark = _libr_core.r_core_visual_mark
r_core_visual_mark.restype = None
r_core_visual_mark.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_ubyte]
r_core_visual_mark_set = _libr_core.r_core_visual_mark_set
r_core_visual_mark_set.restype = None
r_core_visual_mark_set.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_ubyte, ctypes.c_uint64]
r_core_visual_mark_del = _libr_core.r_core_visual_mark_del
r_core_visual_mark_del.restype = None
r_core_visual_mark_del.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_ubyte]
r_core_visual_mark_dump = _libr_core.r_core_visual_mark_dump
r_core_visual_mark_dump.restype = ctypes.c_bool
r_core_visual_mark_dump.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_visual_mark_reset = _libr_core.r_core_visual_mark_reset
r_core_visual_mark_reset.restype = None
r_core_visual_mark_reset.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_search_cb = _libr_core.r_core_search_cb
r_core_search_cb.restype = ctypes.c_int32
r_core_search_cb.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_uint64, RCoreSearchCallback]
r_core_serve = _libr_core.r_core_serve
r_core_serve.restype = ctypes.c_bool
r_core_serve.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(struct_r_io_desc_t)]
r_core_file_reopen = _libr_core.r_core_file_reopen
r_core_file_reopen.restype = ctypes.c_bool
r_core_file_reopen.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32]
r_core_file_reopen_debug = _libr_core.r_core_file_reopen_debug
r_core_file_reopen_debug.restype = None
r_core_file_reopen_debug.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_file_reopen_remote_debug = _libr_core.r_core_file_reopen_remote_debug
r_core_file_reopen_remote_debug.restype = None
r_core_file_reopen_remote_debug.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64]
r_core_file_open = _libr_core.r_core_file_open
r_core_file_open.restype = ctypes.POINTER(struct_r_io_desc_t)
r_core_file_open.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_uint64]
r_core_file_open_many = _libr_core.r_core_file_open_many
r_core_file_open_many.restype = ctypes.POINTER(struct_r_io_desc_t)
r_core_file_open_many.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_uint64]
r_core_file_close_all_but = _libr_core.r_core_file_close_all_but
r_core_file_close_all_but.restype = ctypes.c_bool
r_core_file_close_all_but.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_setup_debugger = _libr_core.r_core_setup_debugger
r_core_setup_debugger.restype = ctypes.c_int32
r_core_setup_debugger.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), ctypes.c_bool]
r_core_seek_delta = _libr_core.r_core_seek_delta
r_core_seek_delta.restype = ctypes.c_int32
r_core_seek_delta.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_int64]
r_core_extend_at = _libr_core.r_core_extend_at
r_core_extend_at.restype = ctypes.c_bool
r_core_extend_at.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_int32]
r_core_write_at = _libr_core.r_core_write_at
r_core_write_at.restype = ctypes.c_bool
r_core_write_at.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_core_write_op = _libr_core.r_core_write_op
r_core_write_op.restype = ctypes.c_int32
r_core_write_op.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), ctypes.c_char]
r_core_transform_op = _libr_core.r_core_transform_op
r_core_transform_op.restype = ctypes.POINTER(ctypes.c_ubyte)
r_core_transform_op.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), ctypes.c_char]
r_core_set_file_by_fd = _libraries['FIXME_STUB'].r_core_set_file_by_fd
r_core_set_file_by_fd.restype = ctypes.c_int32
r_core_set_file_by_fd.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
r_core_set_file_by_name = _libraries['FIXME_STUB'].r_core_set_file_by_name
r_core_set_file_by_name.restype = ctypes.c_int32
r_core_set_file_by_name.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.POINTER(ctypes.c_char)]
r_core_debug_rr = _libr_core.r_core_debug_rr
r_core_debug_rr.restype = None
r_core_debug_rr.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(struct_r_reg_t), ctypes.c_int32]
r_core_fortune_list_types = _libr_core.r_core_fortune_list_types
r_core_fortune_list_types.restype = None
r_core_fortune_list_types.argtypes = []
r_core_fortune_list = _libr_core.r_core_fortune_list
r_core_fortune_list.restype = None
r_core_fortune_list.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_fortune_print_random = _libr_core.r_core_fortune_print_random
r_core_fortune_print_random.restype = None
r_core_fortune_print_random.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_project_execute_cmds = _libr_core.r_core_project_execute_cmds
r_core_project_execute_cmds.restype = None
r_core_project_execute_cmds.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_yank = _libr_core.r_core_yank
r_core_yank.restype = ctypes.c_int32
r_core_yank.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_int32]
r_core_yank_string = _libr_core.r_core_yank_string
r_core_yank_string.restype = ctypes.c_int32
r_core_yank_string.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_int32]
r_core_yank_hexpair = _libr_core.r_core_yank_hexpair
r_core_yank_hexpair.restype = ctypes.c_bool
r_core_yank_hexpair.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_yank_paste = _libr_core.r_core_yank_paste
r_core_yank_paste.restype = ctypes.c_int32
r_core_yank_paste.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_int32]
r_core_yank_set = _libr_core.r_core_yank_set
r_core_yank_set.restype = ctypes.c_int32
r_core_yank_set.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32]
r_core_yank_set_str = _libr_core.r_core_yank_set_str
r_core_yank_set_str.restype = ctypes.c_int32
r_core_yank_set_str.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_char), ctypes.c_uint32]
r_core_yank_to = _libr_core.r_core_yank_to
r_core_yank_to.restype = ctypes.c_int32
r_core_yank_to.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_yank_dump = _libr_core.r_core_yank_dump
r_core_yank_dump.restype = ctypes.c_bool
r_core_yank_dump.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_int32]
r_core_yank_hexdump = _libr_core.r_core_yank_hexdump
r_core_yank_hexdump.restype = ctypes.c_int32
r_core_yank_hexdump.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
r_core_yank_cat = _libr_core.r_core_yank_cat
r_core_yank_cat.restype = ctypes.c_int32
r_core_yank_cat.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
r_core_yank_cat_string = _libr_core.r_core_yank_cat_string
r_core_yank_cat_string.restype = ctypes.c_int32
r_core_yank_cat_string.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
r_core_yank_hud_file = _libr_core.r_core_yank_hud_file
r_core_yank_hud_file.restype = ctypes.c_int32
r_core_yank_hud_file.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_yank_hud_path = _libr_core.r_core_yank_hud_path
r_core_yank_hud_path.restype = ctypes.c_int32
r_core_yank_hud_path.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_core_yank_file_ex = _libr_core.r_core_yank_file_ex
r_core_yank_file_ex.restype = ctypes.c_bool
r_core_yank_file_ex.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_yank_file_all = _libr_core.r_core_yank_file_all
r_core_yank_file_all.restype = ctypes.c_int32
r_core_yank_file_all.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_loadlibs_init = _libr_core.r_core_loadlibs_init
r_core_loadlibs_init.restype = None
r_core_loadlibs_init.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_loadlibs = _libr_core.r_core_loadlibs
r_core_loadlibs.restype = ctypes.c_bool
r_core_loadlibs.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
r_core_cmd_buffer = _libr_core.r_core_cmd_buffer
r_core_cmd_buffer.restype = ctypes.c_int32
r_core_cmd_buffer.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_cmd_foreach = _libr_core.r_core_cmd_foreach
r_core_cmd_foreach.restype = ctypes.c_int32
r_core_cmd_foreach.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_core_cmd_foreach3 = _libr_core.r_core_cmd_foreach3
r_core_cmd_foreach3.restype = ctypes.c_int32
r_core_cmd_foreach3.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_core_op_str = _libr_core.r_core_op_str
r_core_op_str.restype = ctypes.POINTER(ctypes.c_char)
r_core_op_str.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
RAnalOpMask = c__EA_RAnalOpMask
RAnalOpMask__enumvalues = c__EA_RAnalOpMask__enumvalues
r_core_op_anal = _libr_core.r_core_op_anal
r_core_op_anal.restype = ctypes.POINTER(struct_r_anal_op_t)
r_core_op_anal.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, RAnalOpMask]
r_core_disassemble_instr = _libr_core.r_core_disassemble_instr
r_core_disassemble_instr.restype = ctypes.POINTER(ctypes.c_char)
r_core_disassemble_instr.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_int32]
r_core_disassemble_bytes = _libr_core.r_core_disassemble_bytes
r_core_disassemble_bytes.restype = ctypes.POINTER(ctypes.c_char)
r_core_disassemble_bytes.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_int32]
r_core_get_func_args = _libr_core.r_core_get_func_args
r_core_get_func_args.restype = ctypes.POINTER(struct_r_list_t)
r_core_get_func_args.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_print_func_args = _libr_core.r_core_print_func_args
r_core_print_func_args.restype = None
r_core_print_func_args.argtypes = [ctypes.POINTER(struct_r_core_t)]
resolve_fcn_name = _libr_core.resolve_fcn_name
resolve_fcn_name.restype = ctypes.POINTER(ctypes.c_char)
resolve_fcn_name.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_core_get_stacksz = _libr_core.r_core_get_stacksz
r_core_get_stacksz.restype = ctypes.c_int32
r_core_get_stacksz.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_uint64]
r_core_anal_op = _libr_core.r_core_anal_op
r_core_anal_op.restype = ctypes.POINTER(struct_r_anal_op_t)
r_core_anal_op.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_int32]
core_type_by_addr = _libraries['FIXME_STUB'].core_type_by_addr
core_type_by_addr.restype = ctypes.c_int32
core_type_by_addr.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
r_core_anal_esil = _libr_core.r_core_anal_esil
r_core_anal_esil.restype = None
r_core_anal_esil.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_core_anal_fcn_merge = _libr_core.r_core_anal_fcn_merge
r_core_anal_fcn_merge.restype = None
r_core_anal_fcn_merge.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_uint64]
r_core_anal_optype_colorfor = _libr_core.r_core_anal_optype_colorfor
r_core_anal_optype_colorfor.restype = ctypes.POINTER(ctypes.c_char)
r_core_anal_optype_colorfor.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_bool]
r_core_anal_address = _libr_core.r_core_anal_address
r_core_anal_address.restype = ctypes.c_uint64
r_core_anal_address.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
r_core_anal_undefine = _libr_core.r_core_anal_undefine
r_core_anal_undefine.restype = None
r_core_anal_undefine.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
r_core_anal_hint_print = _libr_core.r_core_anal_hint_print
r_core_anal_hint_print.restype = None
r_core_anal_hint_print.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_int32]
r_core_anal_hint_list = _libr_core.r_core_anal_hint_list
r_core_anal_hint_list.restype = None
r_core_anal_hint_list.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_int32]
r_core_anal_search = _libr_core.r_core_anal_search
r_core_anal_search.restype = ctypes.c_int32
r_core_anal_search.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int32]
r_core_anal_search_xrefs = _libr_core.r_core_anal_search_xrefs
r_core_anal_search_xrefs.restype = ctypes.c_int32
r_core_anal_search_xrefs.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_uint64, ctypes.POINTER(struct_pj_t), ctypes.c_int32]
r_core_anal_data = _libr_core.r_core_anal_data
r_core_anal_data.restype = ctypes.c_int32
r_core_anal_data.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
r_core_anal_datarefs = _libr_core.r_core_anal_datarefs
r_core_anal_datarefs.restype = None
r_core_anal_datarefs.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
r_core_anal_coderefs = _libr_core.r_core_anal_coderefs
r_core_anal_coderefs.restype = None
r_core_anal_coderefs.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
r_core_anal_codexrefs = _libr_core.r_core_anal_codexrefs
r_core_anal_codexrefs.restype = ctypes.POINTER(struct_r_graph_t)
r_core_anal_codexrefs.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
r_core_anal_importxrefs = _libr_core.r_core_anal_importxrefs
r_core_anal_importxrefs.restype = ctypes.POINTER(struct_r_graph_t)
r_core_anal_importxrefs.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_anal_callgraph = _libr_core.r_core_anal_callgraph
r_core_anal_callgraph.restype = None
r_core_anal_callgraph.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_int32]
r_core_anal_refs = _libr_core.r_core_anal_refs
r_core_anal_refs.restype = ctypes.c_int32
r_core_anal_refs.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_agraph_print = _libr_core.r_core_agraph_print
r_core_agraph_print.restype = None
r_core_agraph_print.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
r_core_esil_cmd = _libr_core.r_core_esil_cmd
r_core_esil_cmd.restype = ctypes.c_bool
r_core_esil_cmd.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64, ctypes.c_uint64]
r_core_esil_step = _libr_core.r_core_esil_step
r_core_esil_step.restype = ctypes.c_int32
r_core_esil_step.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_uint64), ctypes.c_bool]
r_core_esil_step_back = _libr_core.r_core_esil_step_back
r_core_esil_step_back.restype = ctypes.c_int32
r_core_esil_step_back.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_anal_get_bbaddr = _libraries['FIXME_STUB'].r_core_anal_get_bbaddr
r_core_anal_get_bbaddr.restype = ctypes.c_uint64
r_core_anal_get_bbaddr.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
r_core_anal_bb_seek = _libr_core.r_core_anal_bb_seek
r_core_anal_bb_seek.restype = ctypes.c_bool
r_core_anal_bb_seek.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
r_core_anal_fcn = _libr_core.r_core_anal_fcn
r_core_anal_fcn.restype = ctypes.c_bool
r_core_anal_fcn.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int32, ctypes.c_int32]
r_core_anal_fcn_autoname = _libr_core.r_core_anal_fcn_autoname
r_core_anal_fcn_autoname.restype = ctypes.POINTER(ctypes.c_char)
r_core_anal_fcn_autoname.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_int32, ctypes.c_int32]
r_core_anal_autoname_all_fcns = _libr_core.r_core_anal_autoname_all_fcns
r_core_anal_autoname_all_fcns.restype = None
r_core_anal_autoname_all_fcns.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_anal_autoname_all_golang_fcns = _libr_core.r_core_anal_autoname_all_golang_fcns
r_core_anal_autoname_all_golang_fcns.restype = None
r_core_anal_autoname_all_golang_fcns.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_anal_fcn_list = _libr_core.r_core_anal_fcn_list
r_core_anal_fcn_list.restype = ctypes.c_int32
r_core_anal_fcn_list.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_core_anal_fcn_name = _libr_core.r_core_anal_fcn_name
r_core_anal_fcn_name.restype = ctypes.POINTER(ctypes.c_char)
r_core_anal_fcn_name.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(struct_r_anal_function_t)]
r_core_anal_fcn_list_size = _libr_core.r_core_anal_fcn_list_size
r_core_anal_fcn_list_size.restype = ctypes.c_uint64
r_core_anal_fcn_list_size.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_anal_fcn_labels = _libraries['FIXME_STUB'].r_core_anal_fcn_labels
r_core_anal_fcn_labels.restype = None
r_core_anal_fcn_labels.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(struct_r_anal_function_t), ctypes.c_int32]
r_core_anal_fcn_clean = _libr_core.r_core_anal_fcn_clean
r_core_anal_fcn_clean.restype = ctypes.c_int32
r_core_anal_fcn_clean.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
r_core_print_bb_custom = _libr_core.r_core_print_bb_custom
r_core_print_bb_custom.restype = ctypes.c_int32
r_core_print_bb_custom.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(struct_r_anal_function_t)]
r_core_print_bb_gml = _libr_core.r_core_print_bb_gml
r_core_print_bb_gml.restype = ctypes.c_int32
r_core_print_bb_gml.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(struct_r_anal_function_t)]
r_core_anal_graph = _libr_core.r_core_anal_graph
r_core_anal_graph.restype = ctypes.c_int32
r_core_anal_graph.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_int32]
r_core_anal_graph_fcn = _libraries['FIXME_STUB'].r_core_anal_graph_fcn
r_core_anal_graph_fcn.restype = ctypes.c_int32
r_core_anal_graph_fcn.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_core_anal_graph_to = _libr_core.r_core_anal_graph_to
r_core_anal_graph_to.restype = ctypes.POINTER(struct_r_list_t)
r_core_anal_graph_to.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_int32]
r_core_anal_ref_list = _libraries['FIXME_STUB'].r_core_anal_ref_list
r_core_anal_ref_list.restype = ctypes.c_int32
r_core_anal_ref_list.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_int32]
r_core_anal_all = _libr_core.r_core_anal_all
r_core_anal_all.restype = ctypes.c_int32
r_core_anal_all.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_anal_cycles = _libr_core.r_core_anal_cycles
r_core_anal_cycles.restype = ctypes.POINTER(struct_r_list_t)
r_core_anal_cycles.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_int32]
r_core_anal_fcn_get_calls = _libr_core.r_core_anal_fcn_get_calls
r_core_anal_fcn_get_calls.restype = ctypes.POINTER(struct_r_list_t)
r_core_anal_fcn_get_calls.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(struct_r_anal_function_t)]
r_core_anal_type_match = _libr_core.r_core_anal_type_match
r_core_anal_type_match.restype = None
r_core_anal_type_match.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(struct_r_anal_function_t)]
class struct_r_core_asm_hit(Structure):
    pass

struct_r_core_asm_hit._pack_ = 1 # source:False
struct_r_core_asm_hit._fields_ = [
    ('code', ctypes.POINTER(ctypes.c_char)),
    ('len', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('addr', ctypes.c_uint64),
    ('valid', ctypes.c_ubyte),
    ('PADDING_1', ctypes.c_ubyte * 7),
]

RCoreAsmHit = struct_r_core_asm_hit
r_core_syscall = _libr_core.r_core_syscall
r_core_syscall.restype = ctypes.POINTER(struct_r_buf_t)
r_core_syscall.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_core_syscallf = _libr_core.r_core_syscallf
r_core_syscallf.restype = ctypes.POINTER(struct_r_buf_t)
r_core_syscallf.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_core_asm_hit_new = _libr_core.r_core_asm_hit_new
r_core_asm_hit_new.restype = ctypes.POINTER(struct_r_core_asm_hit)
r_core_asm_hit_new.argtypes = []
r_core_asm_hit_list_new = _libr_core.r_core_asm_hit_list_new
r_core_asm_hit_list_new.restype = ctypes.POINTER(struct_r_list_t)
r_core_asm_hit_list_new.argtypes = []
r_core_asm_hit_free = _libr_core.r_core_asm_hit_free
r_core_asm_hit_free.restype = None
r_core_asm_hit_free.argtypes = [ctypes.POINTER(None)]
r_core_set_asm_configs = _libr_core.r_core_set_asm_configs
r_core_set_asm_configs.restype = None
r_core_set_asm_configs.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint32, ctypes.c_int32]
r_core_asm_search = _libr_core.r_core_asm_search
r_core_asm_search.restype = ctypes.POINTER(ctypes.c_char)
r_core_asm_search.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_asm_strsearch = _libr_core.r_core_asm_strsearch
r_core_asm_strsearch.restype = ctypes.POINTER(struct_r_list_t)
r_core_asm_strsearch.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
r_core_asm_bwdisassemble = _libr_core.r_core_asm_bwdisassemble
r_core_asm_bwdisassemble.restype = ctypes.POINTER(struct_r_list_t)
r_core_asm_bwdisassemble.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_int32, ctypes.c_int32]
r_core_asm_back_disassemble_instr = _libr_core.r_core_asm_back_disassemble_instr
r_core_asm_back_disassemble_instr.restype = ctypes.POINTER(struct_r_list_t)
r_core_asm_back_disassemble_instr.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_int32, ctypes.c_uint32, ctypes.c_uint32]
r_core_asm_back_disassemble_byte = _libr_core.r_core_asm_back_disassemble_byte
r_core_asm_back_disassemble_byte.restype = ctypes.POINTER(struct_r_list_t)
r_core_asm_back_disassemble_byte.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_int32, ctypes.c_uint32, ctypes.c_uint32]
r_core_asm_bwdis_len = _libr_core.r_core_asm_bwdis_len
r_core_asm_bwdis_len.restype = ctypes.c_uint32
r_core_asm_bwdis_len.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_uint64), ctypes.c_uint32]
r_core_print_disasm = _libr_core.r_core_print_disasm
r_core_print_disasm.restype = ctypes.c_int32
r_core_print_disasm.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.c_int32, ctypes.c_bool, ctypes.c_bool, ctypes.POINTER(struct_pj_t), ctypes.POINTER(struct_r_anal_function_t)]
r_core_print_disasm_json = _libr_core.r_core_print_disasm_json
r_core_print_disasm_json.restype = ctypes.c_int32
r_core_print_disasm_json.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(struct_pj_t)]
r_core_print_disasm_instructions_with_buf = _libr_core.r_core_print_disasm_instructions_with_buf
r_core_print_disasm_instructions_with_buf.restype = ctypes.c_int32
r_core_print_disasm_instructions_with_buf.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.c_int32]
r_core_print_disasm_instructions = _libr_core.r_core_print_disasm_instructions
r_core_print_disasm_instructions.restype = ctypes.c_int32
r_core_print_disasm_instructions.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_int32, ctypes.c_int32]
r_core_print_disasm_all = _libr_core.r_core_print_disasm_all
r_core_print_disasm_all.restype = ctypes.c_int32
r_core_print_disasm_all.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
r_core_disasm_pdi_with_buf = _libr_core.r_core_disasm_pdi_with_buf
r_core_disasm_pdi_with_buf.restype = ctypes.c_int32
r_core_disasm_pdi_with_buf.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32, ctypes.c_uint32, ctypes.c_int32]
r_core_disasm_pdi = _libr_core.r_core_disasm_pdi
r_core_disasm_pdi.restype = ctypes.c_int32
r_core_disasm_pdi.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
r_core_disasm_pde = _libr_core.r_core_disasm_pde
r_core_disasm_pde.restype = ctypes.c_int32
r_core_disasm_pde.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_int32, ctypes.c_int32]
r_core_print_fcn_disasm = _libraries['FIXME_STUB'].r_core_print_fcn_disasm
r_core_print_fcn_disasm.restype = ctypes.c_int32
r_core_print_fcn_disasm.argtypes = [ctypes.POINTER(struct_r_print_t), ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
r_core_get_prc_cols = _libraries['FIXME_STUB'].r_core_get_prc_cols
r_core_get_prc_cols.restype = ctypes.c_int32
r_core_get_prc_cols.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_flag_in_middle = _libr_core.r_core_flag_in_middle
r_core_flag_in_middle.restype = ctypes.c_int32
r_core_flag_in_middle.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_int32, ctypes.POINTER(ctypes.c_int32)]
r_core_bb_starts_in_middle = _libr_core.r_core_bb_starts_in_middle
r_core_bb_starts_in_middle.restype = ctypes.c_int32
r_core_bb_starts_in_middle.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_int32]
r_core_bin_raise = _libr_core.r_core_bin_raise
r_core_bin_raise.restype = ctypes.c_bool
r_core_bin_raise.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint32]
r_core_bin_set_cur = _libr_core.r_core_bin_set_cur
r_core_bin_set_cur.restype = ctypes.c_bool
r_core_bin_set_cur.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(struct_r_bin_file_t)]
r_core_bin_set_env = _libr_core.r_core_bin_set_env
r_core_bin_set_env.restype = ctypes.c_bool
r_core_bin_set_env.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(struct_r_bin_file_t)]
r_core_bin_set_by_fd = _libr_core.r_core_bin_set_by_fd
r_core_bin_set_by_fd.restype = ctypes.c_bool
r_core_bin_set_by_fd.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
r_core_bin_set_by_name = _libr_core.r_core_bin_set_by_name
r_core_bin_set_by_name.restype = ctypes.c_bool
r_core_bin_set_by_name.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_bin_load = _libr_core.r_core_bin_load
r_core_bin_load.restype = ctypes.c_bool
r_core_bin_load.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64]
r_core_bin_rebase = _libr_core.r_core_bin_rebase
r_core_bin_rebase.restype = ctypes.c_bool
r_core_bin_rebase.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
r_core_bin_export_info = _libr_core.r_core_bin_export_info
r_core_bin_export_info.restype = None
r_core_bin_export_info.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_int32]
r_core_bin_list = _libr_core.r_core_bin_list
r_core_bin_list.restype = ctypes.c_bool
r_core_bin_list.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_int32]
r_core_bin_delete = _libr_core.r_core_bin_delete
r_core_bin_delete.restype = ctypes.c_bool
r_core_bin_delete.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint32]
r_core_bin_impaddr = _libr_core.r_core_bin_impaddr
r_core_bin_impaddr.restype = ctypes.c_uint64
r_core_bin_impaddr.argtypes = [ctypes.POINTER(struct_r_bin_t), ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
r_core_pseudo_code = _libr_core.r_core_pseudo_code
r_core_pseudo_code.restype = ctypes.c_int32
r_core_pseudo_code.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_zdiff = _libr_core.r_core_zdiff
r_core_zdiff.restype = ctypes.c_int32
r_core_zdiff.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(struct_r_core_t)]
r_core_gdiff = _libr_core.r_core_gdiff
r_core_gdiff.restype = ctypes.c_int32
r_core_gdiff.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(struct_r_core_t)]
r_core_gdiff_fcn = _libr_core.r_core_gdiff_fcn
r_core_gdiff_fcn.restype = ctypes.c_int32
r_core_gdiff_fcn.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_uint64]
r_core_project_open = _libr_core.r_core_project_open
r_core_project_open.restype = ctypes.c_bool
r_core_project_open.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_project_cat = _libr_core.r_core_project_cat
r_core_project_cat.restype = ctypes.c_int32
r_core_project_cat.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_project_delete = _libr_core.r_core_project_delete
r_core_project_delete.restype = ctypes.c_int32
r_core_project_delete.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_project_list = _libr_core.r_core_project_list
r_core_project_list.restype = ctypes.c_int32
r_core_project_list.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_int32]
r_core_project_save_script = _libr_core.r_core_project_save_script
r_core_project_save_script.restype = ctypes.c_bool
r_core_project_save_script.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_core_project_save = _libr_core.r_core_project_save
r_core_project_save.restype = ctypes.c_bool
r_core_project_save.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_project_name = _libr_core.r_core_project_name
r_core_project_name.restype = ctypes.POINTER(ctypes.c_char)
r_core_project_name.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_project_notes_file = _libr_core.r_core_project_notes_file
r_core_project_notes_file.restype = ctypes.POINTER(ctypes.c_char)
r_core_project_notes_file.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_sysenv_begin = _libr_core.r_core_sysenv_begin
r_core_sysenv_begin.restype = ctypes.POINTER(ctypes.c_char)
r_core_sysenv_begin.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_sysenv_end = _libr_core.r_core_sysenv_end
r_core_sysenv_end.restype = None
r_core_sysenv_end.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_recover_vars = _libr_core.r_core_recover_vars
r_core_recover_vars.restype = None
r_core_recover_vars.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(struct_r_anal_function_t), ctypes.c_bool]
class struct_r_core_bin_filter_t(Structure):
    pass

struct_r_core_bin_filter_t._pack_ = 1 # source:False
struct_r_core_bin_filter_t._fields_ = [
    ('offset', ctypes.c_uint64),
    ('name', ctypes.POINTER(ctypes.c_char)),
]

RCoreBinFilter = struct_r_core_bin_filter_t
r_core_bin_info = _libr_core.r_core_bin_info
r_core_bin_info.restype = ctypes.c_bool
r_core_bin_info.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_int32, ctypes.POINTER(struct_pj_t), ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(struct_r_core_bin_filter_t), ctypes.POINTER(ctypes.c_char)]
r_core_bin_set_arch_bits = _libr_core.r_core_bin_set_arch_bits
r_core_bin_set_arch_bits.restype = ctypes.c_bool
r_core_bin_set_arch_bits.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_uint16]
r_core_bin_update_arch_bits = _libr_core.r_core_bin_update_arch_bits
r_core_bin_update_arch_bits.restype = ctypes.c_bool
r_core_bin_update_arch_bits.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_bin_method_flags_str = _libr_core.r_core_bin_method_flags_str
r_core_bin_method_flags_str.restype = ctypes.POINTER(ctypes.c_char)
r_core_bin_method_flags_str.argtypes = [ctypes.c_uint64, ctypes.c_int32]
r_core_pdb_info = _libr_core.r_core_pdb_info
r_core_pdb_info.restype = ctypes.c_bool
r_core_pdb_info.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_pj_t), ctypes.c_int32]
r_core_rtr_cmds = _libr_core.r_core_rtr_cmds
r_core_rtr_cmds.restype = ctypes.c_int32
r_core_rtr_cmds.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_rtr_cmds_query = _libr_core.r_core_rtr_cmds_query
r_core_rtr_cmds_query.restype = ctypes.POINTER(ctypes.c_char)
r_core_rtr_cmds_query.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_core_rtr_help = _libraries['FIXME_STUB'].r_core_rtr_help
r_core_rtr_help.restype = None
r_core_rtr_help.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_rtr_pushout = _libr_core.r_core_rtr_pushout
r_core_rtr_pushout.restype = None
r_core_rtr_pushout.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_rtr_list = _libr_core.r_core_rtr_list
r_core_rtr_list.restype = None
r_core_rtr_list.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_rtr_add = _libr_core.r_core_rtr_add
r_core_rtr_add.restype = None
r_core_rtr_add.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_rtr_remove = _libr_core.r_core_rtr_remove
r_core_rtr_remove.restype = None
r_core_rtr_remove.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_rtr_session = _libr_core.r_core_rtr_session
r_core_rtr_session.restype = None
r_core_rtr_session.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_rtr_event = _libr_core.r_core_rtr_event
r_core_rtr_event.restype = None
r_core_rtr_event.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_rtr_cmd = _libr_core.r_core_rtr_cmd
r_core_rtr_cmd.restype = None
r_core_rtr_cmd.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_rtr_http = _libr_core.r_core_rtr_http
r_core_rtr_http.restype = ctypes.c_int32
r_core_rtr_http.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
r_core_rtr_http_stop = _libr_core.r_core_rtr_http_stop
r_core_rtr_http_stop.restype = ctypes.c_int32
r_core_rtr_http_stop.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_rtr_gdb = _libr_core.r_core_rtr_gdb
r_core_rtr_gdb.restype = ctypes.c_int32
r_core_rtr_gdb.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
r_core_visual_prevopsz = _libr_core.r_core_visual_prevopsz
r_core_visual_prevopsz.restype = ctypes.c_int32
r_core_visual_prevopsz.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
r_core_visual_config = _libr_core.r_core_visual_config
r_core_visual_config.restype = None
r_core_visual_config.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_visual_mounts = _libr_core.r_core_visual_mounts
r_core_visual_mounts.restype = None
r_core_visual_mounts.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_visual_anal = _libr_core.r_core_visual_anal
r_core_visual_anal.restype = None
r_core_visual_anal.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_visual_debugtraces = _libr_core.r_core_visual_debugtraces
r_core_visual_debugtraces.restype = None
r_core_visual_debugtraces.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_visual_define = _libr_core.r_core_visual_define
r_core_visual_define.restype = None
r_core_visual_define.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_core_visual_trackflags = _libr_core.r_core_visual_trackflags
r_core_visual_trackflags.restype = ctypes.c_int32
r_core_visual_trackflags.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_visual_view_graph = _libr_core.r_core_visual_view_graph
r_core_visual_view_graph.restype = ctypes.c_int32
r_core_visual_view_graph.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_visual_view_zigns = _libr_core.r_core_visual_view_zigns
r_core_visual_view_zigns.restype = ctypes.c_int32
r_core_visual_view_zigns.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_visual_view_rop = _libr_core.r_core_visual_view_rop
r_core_visual_view_rop.restype = ctypes.c_int32
r_core_visual_view_rop.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_visual_comments = _libr_core.r_core_visual_comments
r_core_visual_comments.restype = ctypes.c_int32
r_core_visual_comments.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_visual_prompt = _libr_core.r_core_visual_prompt
r_core_visual_prompt.restype = ctypes.c_int32
r_core_visual_prompt.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_visual_esil = _libr_core.r_core_visual_esil
r_core_visual_esil.restype = ctypes.c_bool
r_core_visual_esil.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_search_preludes = _libr_core.r_core_search_preludes
r_core_search_preludes.restype = ctypes.c_int32
r_core_search_preludes.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_bool]
r_core_search_prelude = _libr_core.r_core_search_prelude
r_core_search_prelude.restype = ctypes.c_int32
r_core_search_prelude.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_core_get_boundaries_prot = _libr_core.r_core_get_boundaries_prot
r_core_get_boundaries_prot.restype = ctypes.POINTER(struct_r_list_t)
r_core_get_boundaries_prot.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_core_patch = _libr_core.r_core_patch
r_core_patch.restype = ctypes.c_int32
r_core_patch.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_hack_help = _libr_core.r_core_hack_help
r_core_hack_help.restype = None
r_core_hack_help.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_hack = _libr_core.r_core_hack
r_core_hack.restype = ctypes.c_int32
r_core_hack.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_dump = _libr_core.r_core_dump
r_core_dump.restype = ctypes.c_bool
r_core_dump.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int32]
r_core_diff_show = _libr_core.r_core_diff_show
r_core_diff_show.restype = None
r_core_diff_show.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(struct_r_core_t)]
r_core_clippy = _libr_core.r_core_clippy
r_core_clippy.restype = None
r_core_clippy.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_cmpwatch_free = _libr_core.r_core_cmpwatch_free
r_core_cmpwatch_free.restype = None
r_core_cmpwatch_free.argtypes = [ctypes.POINTER(struct_r_core_cmpwatch_t)]
r_core_cmpwatch_get = _libr_core.r_core_cmpwatch_get
r_core_cmpwatch_get.restype = ctypes.POINTER(struct_r_core_cmpwatch_t)
r_core_cmpwatch_get.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
r_core_cmpwatch_add = _libr_core.r_core_cmpwatch_add
r_core_cmpwatch_add.restype = ctypes.c_int32
r_core_cmpwatch_add.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
r_core_cmpwatch_del = _libr_core.r_core_cmpwatch_del
r_core_cmpwatch_del.restype = ctypes.c_int32
r_core_cmpwatch_del.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
r_core_cmpwatch_update = _libr_core.r_core_cmpwatch_update
r_core_cmpwatch_update.restype = ctypes.c_int32
r_core_cmpwatch_update.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
r_core_cmpwatch_show = _libr_core.r_core_cmpwatch_show
r_core_cmpwatch_show.restype = ctypes.c_int32
r_core_cmpwatch_show.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_int32]
r_core_cmpwatch_revert = _libr_core.r_core_cmpwatch_revert
r_core_cmpwatch_revert.restype = ctypes.c_int32
r_core_cmpwatch_revert.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
r_core_undo_new = _libr_core.r_core_undo_new
r_core_undo_new.restype = ctypes.POINTER(struct_r_core_undo_t)
r_core_undo_new.argtypes = [ctypes.c_uint64, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_core_undo_print = _libr_core.r_core_undo_print
r_core_undo_print.restype = None
r_core_undo_print.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_int32, ctypes.POINTER(struct_c__SA_RCoreUndoCondition)]
r_core_undo_free = _libr_core.r_core_undo_free
r_core_undo_free.restype = None
r_core_undo_free.argtypes = [ctypes.POINTER(struct_r_core_undo_t)]
r_core_undo_push = _libr_core.r_core_undo_push
r_core_undo_push.restype = None
r_core_undo_push.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(struct_r_core_undo_t)]
r_core_undo_pop = _libr_core.r_core_undo_pop
r_core_undo_pop.restype = None
r_core_undo_pop.argtypes = [ctypes.POINTER(struct_r_core_t)]
RCoreLogCallback = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_core_t), ctypes.c_int32, ctypes.POINTER(ctypes.c_char))
r_core_log_free = _libr_core.r_core_log_free
r_core_log_free.restype = None
r_core_log_free.argtypes = [ctypes.POINTER(struct_r_core_log_t)]
r_core_log_init = _libr_core.r_core_log_init
r_core_log_init.restype = None
r_core_log_init.argtypes = [ctypes.POINTER(struct_r_core_log_t)]
r_core_log_get = _libr_core.r_core_log_get
r_core_log_get.restype = ctypes.POINTER(ctypes.c_char)
r_core_log_get.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_int32]
r_core_log_new = _libr_core.r_core_log_new
r_core_log_new.restype = ctypes.POINTER(struct_r_core_log_t)
r_core_log_new.argtypes = []
r_core_log_run = _libr_core.r_core_log_run
r_core_log_run.restype = ctypes.c_bool
r_core_log_run.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), RCoreLogCallback]
r_core_log_list = _libr_core.r_core_log_list
r_core_log_list.restype = ctypes.c_int32
r_core_log_list.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_char]
r_core_log_add = _libr_core.r_core_log_add
r_core_log_add.restype = None
r_core_log_add.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_log_del = _libr_core.r_core_log_del
r_core_log_del.restype = None
r_core_log_del.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_int32]
PrintItemCallback = ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.c_bool)
r_str_widget_list = _libr_core.r_str_widget_list
r_str_widget_list.restype = ctypes.POINTER(ctypes.c_char)
r_str_widget_list.argtypes = [ctypes.POINTER(None), ctypes.POINTER(struct_r_list_t), ctypes.c_int32, ctypes.c_int32, PrintItemCallback]
r_core_pj_new = _libr_core.r_core_pj_new
r_core_pj_new.restype = ctypes.POINTER(struct_pj_t)
r_core_pj_new.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_cmd_help = _libr_core.r_core_cmd_help
r_core_cmd_help.restype = None
r_core_cmd_help.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char) * 0]
class struct_c__SA_RCoreAnalStatsItem(Structure):
    pass

struct_c__SA_RCoreAnalStatsItem._pack_ = 1 # source:False
struct_c__SA_RCoreAnalStatsItem._fields_ = [
    ('youarehere', ctypes.c_uint32),
    ('flags', ctypes.c_uint32),
    ('comments', ctypes.c_uint32),
    ('functions', ctypes.c_uint32),
    ('blocks', ctypes.c_uint32),
    ('in_functions', ctypes.c_uint32),
    ('symbols', ctypes.c_uint32),
    ('strings', ctypes.c_uint32),
    ('perm', ctypes.c_uint32),
]

RCoreAnalStatsItem = struct_c__SA_RCoreAnalStatsItem
class struct_c__SA_RCoreAnalStats(Structure):
    pass

struct_c__SA_RCoreAnalStats._pack_ = 1 # source:False
struct_c__SA_RCoreAnalStats._fields_ = [
    ('block', ctypes.POINTER(struct_c__SA_RCoreAnalStatsItem)),
]

RCoreAnalStats = struct_c__SA_RCoreAnalStats
core_anal_bbs = _libr_core.core_anal_bbs
core_anal_bbs.restype = ctypes.c_bool
core_anal_bbs.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
core_anal_bbs_range = _libr_core.core_anal_bbs_range
core_anal_bbs_range.restype = ctypes.c_bool
core_anal_bbs_range.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_anal_hasrefs = _libr_core.r_core_anal_hasrefs
r_core_anal_hasrefs.restype = ctypes.POINTER(ctypes.c_char)
r_core_anal_hasrefs.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_int32]
r_core_anal_get_comments = _libr_core.r_core_anal_get_comments
r_core_anal_get_comments.restype = ctypes.POINTER(ctypes.c_char)
r_core_anal_get_comments.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
r_core_anal_get_stats = _libr_core.r_core_anal_get_stats
r_core_anal_get_stats.restype = ctypes.POINTER(struct_c__SA_RCoreAnalStats)
r_core_anal_get_stats.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64]
r_core_anal_stats_free = _libr_core.r_core_anal_stats_free
r_core_anal_stats_free.restype = None
r_core_anal_stats_free.argtypes = [ctypes.POINTER(struct_c__SA_RCoreAnalStats)]
r_core_syscmd_ls = _libraries['FIXME_STUB'].r_core_syscmd_ls
r_core_syscmd_ls.restype = None
r_core_syscmd_ls.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_core_syscmd_cat = _libraries['FIXME_STUB'].r_core_syscmd_cat
r_core_syscmd_cat.restype = None
r_core_syscmd_cat.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_core_syscmd_mkdir = _libraries['FIXME_STUB'].r_core_syscmd_mkdir
r_core_syscmd_mkdir.restype = None
r_core_syscmd_mkdir.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_line_hist_offset_up = _libr_core.r_line_hist_offset_up
r_line_hist_offset_up.restype = ctypes.c_int32
r_line_hist_offset_up.argtypes = [ctypes.POINTER(struct_r_line_t)]
r_line_hist_offset_down = _libr_core.r_line_hist_offset_down
r_line_hist_offset_down.restype = ctypes.c_int32
r_line_hist_offset_down.argtypes = [ctypes.POINTER(struct_r_line_t)]
cmd_syscall_dostr = _libr_core.cmd_syscall_dostr
cmd_syscall_dostr.restype = ctypes.POINTER(ctypes.c_char)
cmd_syscall_dostr.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_int64, ctypes.c_uint64]
cmd_agfb = _libr_core.cmd_agfb
cmd_agfb.restype = None
cmd_agfb.argtypes = [ctypes.POINTER(struct_r_core_t)]
cmd_agfb2 = _libr_core.cmd_agfb2
cmd_agfb2.restype = None
cmd_agfb2.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
cmd_agfb3 = _libr_core.cmd_agfb3
cmd_agfb3.restype = None
cmd_agfb3.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32]
RCoreTaskCallback = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))
RTaskState = c__EA_RTaskState
RTaskState__enumvalues = c__EA_RTaskState__enumvalues
RCoreTask = struct_r_core_task_t
RCoreTaskOneShot = ctypes.CFUNCTYPE(None, ctypes.POINTER(None))
r_core_echo = _libr_core.r_core_echo
r_core_echo.restype = None
r_core_echo.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_table = _libr_core.r_core_table
r_core_table.restype = ctypes.POINTER(struct_c__SA_RTable)
r_core_table.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(ctypes.c_char)]
r_core_task_scheduler_init = _libr_core.r_core_task_scheduler_init
r_core_task_scheduler_init.restype = None
r_core_task_scheduler_init.argtypes = [ctypes.POINTER(struct_r_core_tasks_t), ctypes.POINTER(struct_r_core_t)]
r_core_task_scheduler_fini = _libr_core.r_core_task_scheduler_fini
r_core_task_scheduler_fini.restype = None
r_core_task_scheduler_fini.argtypes = [ctypes.POINTER(struct_r_core_tasks_t)]
r_core_task_get = _libraries['FIXME_STUB'].r_core_task_get
r_core_task_get.restype = ctypes.POINTER(struct_r_core_task_t)
r_core_task_get.argtypes = [ctypes.POINTER(struct_r_core_tasks_t), ctypes.c_int32]
r_core_task_get_incref = _libr_core.r_core_task_get_incref
r_core_task_get_incref.restype = ctypes.POINTER(struct_r_core_task_t)
r_core_task_get_incref.argtypes = [ctypes.POINTER(struct_r_core_tasks_t), ctypes.c_int32]
r_core_task_print = _libr_core.r_core_task_print
r_core_task_print.restype = None
r_core_task_print.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.POINTER(struct_r_core_task_t), ctypes.POINTER(struct_pj_t), ctypes.c_int32]
r_core_task_list = _libr_core.r_core_task_list
r_core_task_list.restype = None
r_core_task_list.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_int32]
r_core_task_running_tasks_count = _libr_core.r_core_task_running_tasks_count
r_core_task_running_tasks_count.restype = ctypes.c_int32
r_core_task_running_tasks_count.argtypes = [ctypes.POINTER(struct_r_core_tasks_t)]
r_core_task_status = _libr_core.r_core_task_status
r_core_task_status.restype = ctypes.POINTER(ctypes.c_char)
r_core_task_status.argtypes = [ctypes.POINTER(struct_r_core_task_t)]
r_core_task_new = _libr_core.r_core_task_new
r_core_task_new.restype = ctypes.POINTER(struct_r_core_task_t)
r_core_task_new.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_bool, ctypes.POINTER(ctypes.c_char), RCoreTaskCallback, ctypes.POINTER(None)]
r_core_task_incref = _libr_core.r_core_task_incref
r_core_task_incref.restype = None
r_core_task_incref.argtypes = [ctypes.POINTER(struct_r_core_task_t)]
r_core_task_decref = _libr_core.r_core_task_decref
r_core_task_decref.restype = None
r_core_task_decref.argtypes = [ctypes.POINTER(struct_r_core_task_t)]
r_core_task_enqueue = _libr_core.r_core_task_enqueue
r_core_task_enqueue.restype = None
r_core_task_enqueue.argtypes = [ctypes.POINTER(struct_r_core_tasks_t), ctypes.POINTER(struct_r_core_task_t)]
r_core_task_enqueue_oneshot = _libr_core.r_core_task_enqueue_oneshot
r_core_task_enqueue_oneshot.restype = None
r_core_task_enqueue_oneshot.argtypes = [ctypes.POINTER(struct_r_core_tasks_t), RCoreTaskOneShot, ctypes.POINTER(None)]
r_core_task_run_sync = _libr_core.r_core_task_run_sync
r_core_task_run_sync.restype = ctypes.c_int32
r_core_task_run_sync.argtypes = [ctypes.POINTER(struct_r_core_tasks_t), ctypes.POINTER(struct_r_core_task_t)]
r_core_task_sync_begin = _libr_core.r_core_task_sync_begin
r_core_task_sync_begin.restype = None
r_core_task_sync_begin.argtypes = [ctypes.POINTER(struct_r_core_tasks_t)]
r_core_task_sync_end = _libr_core.r_core_task_sync_end
r_core_task_sync_end.restype = None
r_core_task_sync_end.argtypes = [ctypes.POINTER(struct_r_core_tasks_t)]
r_core_task_yield = _libr_core.r_core_task_yield
r_core_task_yield.restype = None
r_core_task_yield.argtypes = [ctypes.POINTER(struct_r_core_tasks_t)]
r_core_task_sleep_begin = _libr_core.r_core_task_sleep_begin
r_core_task_sleep_begin.restype = None
r_core_task_sleep_begin.argtypes = [ctypes.POINTER(struct_r_core_task_t)]
r_core_task_sleep_end = _libr_core.r_core_task_sleep_end
r_core_task_sleep_end.restype = None
r_core_task_sleep_end.argtypes = [ctypes.POINTER(struct_r_core_task_t)]
r_core_task_break = _libr_core.r_core_task_break
r_core_task_break.restype = None
r_core_task_break.argtypes = [ctypes.POINTER(struct_r_core_tasks_t), ctypes.c_int32]
r_core_task_break_all = _libr_core.r_core_task_break_all
r_core_task_break_all.restype = None
r_core_task_break_all.argtypes = [ctypes.POINTER(struct_r_core_tasks_t)]
r_core_task_del = _libr_core.r_core_task_del
r_core_task_del.restype = ctypes.c_int32
r_core_task_del.argtypes = [ctypes.POINTER(struct_r_core_tasks_t), ctypes.c_int32]
r_core_task_del_all_done = _libr_core.r_core_task_del_all_done
r_core_task_del_all_done.restype = None
r_core_task_del_all_done.argtypes = [ctypes.POINTER(struct_r_core_tasks_t)]
r_core_task_self = _libr_core.r_core_task_self
r_core_task_self.restype = ctypes.POINTER(struct_r_core_task_t)
r_core_task_self.argtypes = [ctypes.POINTER(struct_r_core_tasks_t)]
r_core_task_join = _libr_core.r_core_task_join
r_core_task_join.restype = None
r_core_task_join.argtypes = [ctypes.POINTER(struct_r_core_tasks_t), ctypes.POINTER(struct_r_core_task_t), ctypes.c_int32]
inRangeCb = ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_core_t), ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int32, ctypes.POINTER(None))
r_core_search_value_in_range = _libr_core.r_core_search_value_in_range
r_core_search_value_in_range.restype = ctypes.c_int32
r_core_search_value_in_range.argtypes = [ctypes.POINTER(struct_r_core_t), RInterval, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int32, inRangeCb, ctypes.POINTER(None)]
r_core_autocomplete_add = _libr_core.r_core_autocomplete_add
r_core_autocomplete_add.restype = ctypes.POINTER(struct_r_core_autocomplete_t)
r_core_autocomplete_add.argtypes = [ctypes.POINTER(struct_r_core_autocomplete_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_bool]
r_core_autocomplete_free = _libr_core.r_core_autocomplete_free
r_core_autocomplete_free.restype = None
r_core_autocomplete_free.argtypes = [ctypes.POINTER(struct_r_core_autocomplete_t)]
r_core_autocomplete_reload = _libr_core.r_core_autocomplete_reload
r_core_autocomplete_reload.restype = None
r_core_autocomplete_reload.argtypes = [ctypes.POINTER(struct_r_core_t)]
r_core_autocomplete_find = _libr_core.r_core_autocomplete_find
r_core_autocomplete_find.restype = ctypes.POINTER(struct_r_core_autocomplete_t)
r_core_autocomplete_find.argtypes = [ctypes.POINTER(struct_r_core_autocomplete_t), ctypes.POINTER(ctypes.c_char), ctypes.c_bool]
r_core_autocomplete_remove = _libr_core.r_core_autocomplete_remove
r_core_autocomplete_remove.restype = ctypes.c_bool
r_core_autocomplete_remove.argtypes = [ctypes.POINTER(struct_r_core_autocomplete_t), ctypes.POINTER(ctypes.c_char)]
r_core_anal_propagate_noreturn = _libr_core.r_core_anal_propagate_noreturn
r_core_anal_propagate_noreturn.restype = None
r_core_anal_propagate_noreturn.argtypes = [ctypes.POINTER(struct_r_core_t), ctypes.c_uint64]
r_core_plugin_java = struct_r_core_plugin_t # Variable struct_r_core_plugin_t
r_core_plugin_a2f = struct_r_core_plugin_t # Variable struct_r_core_plugin_t
r_core_plugin_sixref = struct_r_core_plugin_t # Variable struct_r_core_plugin_t
r_core_plugin_init = _libr_core.r_core_plugin_init
r_core_plugin_init.restype = ctypes.c_bool
r_core_plugin_init.argtypes = [ctypes.POINTER(struct_r_cmd_t)]
r_core_plugin_add = _libr_core.r_core_plugin_add
r_core_plugin_add.restype = ctypes.c_bool
r_core_plugin_add.argtypes = [ctypes.POINTER(struct_r_cmd_t), ctypes.POINTER(struct_r_core_plugin_t)]
r_core_plugin_check = _libr_core.r_core_plugin_check
r_core_plugin_check.restype = ctypes.c_bool
r_core_plugin_check.argtypes = [ctypes.POINTER(struct_r_cmd_t), ctypes.POINTER(ctypes.c_char)]
r_core_plugin_fini = _libr_core.r_core_plugin_fini
r_core_plugin_fini.restype = None
r_core_plugin_fini.argtypes = [ctypes.POINTER(struct_r_cmd_t)]
__all__ = \
    ['AUTOCOMPLETE_DEFAULT', 'AUTOCOMPLETE_MS', 'DEFAULT', 'DEL',
    'PANEL_FUN_NOFUN', 'PANEL_FUN_SAKURA', 'PANEL_FUN_SNOW',
    'PANEL_LAYOUT_DEFAULT_DYNAMIC', 'PANEL_LAYOUT_DEFAULT_STATIC',
    'PANEL_MODE_DEFAULT', 'PANEL_MODE_HELP', 'PANEL_MODE_MENU',
    'PANEL_MODE_WINDOW', 'PANEL_MODE_ZOOM', 'PANEL_TYPE_DEFAULT',
    'PANEL_TYPE_MENU', 'PJEncodingNum', 'PJEncodingStr',
    'PJ_ENCODING_NUM_DEFAULT', 'PJ_ENCODING_NUM_HEX',
    'PJ_ENCODING_NUM_STR', 'PJ_ENCODING_STR_ARRAY',
    'PJ_ENCODING_STR_BASE64', 'PJ_ENCODING_STR_DEFAULT',
    'PJ_ENCODING_STR_HEX', 'PJ_ENCODING_STR_STRIP',
    'PrintItemCallback', 'QUIT', 'RAnalOpMask',
    'RAnalOpMask__enumvalues', 'RAutocompleteType',
    'RAutocompleteType__enumvalues', 'RCoreAnalStats',
    'RCoreAnalStatsItem', 'RCoreAsmHit', 'RCoreAutocomplete',
    'RCoreAutocompleteType', 'RCoreAutocompleteType__enumvalues',
    'RCoreBinFilter', 'RCoreCmpWatcher', 'RCoreGadget', 'RCoreItem',
    'RCoreLog', 'RCoreLogCallback', 'RCorePlugin', 'RCoreRtrHost',
    'RCoreSearchCallback', 'RCoreTask', 'RCoreTaskCallback',
    'RCoreTaskOneShot', 'RCoreTaskScheduler', 'RCoreTimes',
    'RCoreUndo', 'RCoreUndoCondition', 'RCoreVisual',
    'RCoreVisualMode', 'RCoreVisualMode__enumvalues',
    'RCoreVisualTab', 'RInterval', 'RLinePromptType',
    'RLinePromptType__enumvalues', 'RNCAND', 'RNCASSIGN', 'RNCDEC',
    'RNCDIV', 'RNCEND', 'RNCGT', 'RNCINC', 'RNCLEFTP', 'RNCLT',
    'RNCMINUS', 'RNCMOD', 'RNCMUL', 'RNCNAME', 'RNCNEG', 'RNCNUMBER',
    'RNCOR', 'RNCPLUS', 'RNCPRINT', 'RNCRIGHTP', 'RNCROL', 'RNCROR',
    'RNCSHL', 'RNCSHR', 'RNCXOR', 'ROTATE', 'RProject', 'RTaskState',
    'RTaskState__enumvalues', 'R_ANAL_ACC_R', 'R_ANAL_ACC_UNKNOWN',
    'R_ANAL_ACC_W', 'R_ANAL_COND_AL', 'R_ANAL_COND_EQ',
    'R_ANAL_COND_GE', 'R_ANAL_COND_GT', 'R_ANAL_COND_HI',
    'R_ANAL_COND_HS', 'R_ANAL_COND_LE', 'R_ANAL_COND_LO',
    'R_ANAL_COND_LS', 'R_ANAL_COND_LT', 'R_ANAL_COND_MI',
    'R_ANAL_COND_NE', 'R_ANAL_COND_NV', 'R_ANAL_COND_PL',
    'R_ANAL_COND_VC', 'R_ANAL_COND_VS', 'R_ANAL_CPP_ABI_ITANIUM',
    'R_ANAL_CPP_ABI_MSVC', 'R_ANAL_DATATYPE_ARRAY',
    'R_ANAL_DATATYPE_BOOLEAN', 'R_ANAL_DATATYPE_CLASS',
    'R_ANAL_DATATYPE_FLOAT', 'R_ANAL_DATATYPE_INT16',
    'R_ANAL_DATATYPE_INT32', 'R_ANAL_DATATYPE_INT64',
    'R_ANAL_DATATYPE_NULL', 'R_ANAL_DATATYPE_OBJECT',
    'R_ANAL_DATATYPE_STRING', 'R_ANAL_OP_DIR_EXEC',
    'R_ANAL_OP_DIR_READ', 'R_ANAL_OP_DIR_REF', 'R_ANAL_OP_DIR_WRITE',
    'R_ANAL_OP_FAMILY_CPU', 'R_ANAL_OP_FAMILY_CRYPTO',
    'R_ANAL_OP_FAMILY_FPU', 'R_ANAL_OP_FAMILY_IO',
    'R_ANAL_OP_FAMILY_LAST', 'R_ANAL_OP_FAMILY_MMX',
    'R_ANAL_OP_FAMILY_PRIV', 'R_ANAL_OP_FAMILY_SECURITY',
    'R_ANAL_OP_FAMILY_SSE', 'R_ANAL_OP_FAMILY_THREAD',
    'R_ANAL_OP_FAMILY_UNKNOWN', 'R_ANAL_OP_FAMILY_VIRT',
    'R_ANAL_OP_MASK_ALL', 'R_ANAL_OP_MASK_BASIC',
    'R_ANAL_OP_MASK_DISASM', 'R_ANAL_OP_MASK_ESIL',
    'R_ANAL_OP_MASK_HINT', 'R_ANAL_OP_MASK_OPEX',
    'R_ANAL_OP_MASK_VAL', 'R_ANAL_OP_PREFIX_COND',
    'R_ANAL_OP_PREFIX_LIKELY', 'R_ANAL_OP_PREFIX_LOCK',
    'R_ANAL_OP_PREFIX_REP', 'R_ANAL_OP_PREFIX_REPNE',
    'R_ANAL_OP_PREFIX_UNLIKELY', 'R_ANAL_STACK_ALIGN',
    'R_ANAL_STACK_GET', 'R_ANAL_STACK_INC', 'R_ANAL_STACK_NOP',
    'R_ANAL_STACK_NULL', 'R_ANAL_STACK_RESET', 'R_ANAL_STACK_SET',
    'R_ANAL_VAL_IMM', 'R_ANAL_VAL_MEM', 'R_ANAL_VAL_REG',
    'R_CMD_DESC_TYPE_ARGV', 'R_CMD_DESC_TYPE_GROUP',
    'R_CMD_DESC_TYPE_INNER', 'R_CMD_DESC_TYPE_OLDINPUT',
    'R_CMD_STATUS_ERROR', 'R_CMD_STATUS_EXIT', 'R_CMD_STATUS_INVALID',
    'R_CMD_STATUS_OK', 'R_CMD_STATUS_WRONG_ARGS',
    'R_CORE_AUTOCMPLT_BRKP', 'R_CORE_AUTOCMPLT_CHRS',
    'R_CORE_AUTOCMPLT_DFLT', 'R_CORE_AUTOCMPLT_END',
    'R_CORE_AUTOCMPLT_EVAL', 'R_CORE_AUTOCMPLT_FCN',
    'R_CORE_AUTOCMPLT_FILE', 'R_CORE_AUTOCMPLT_FLAG',
    'R_CORE_AUTOCMPLT_FLSP', 'R_CORE_AUTOCMPLT_MACR',
    'R_CORE_AUTOCMPLT_MINS', 'R_CORE_AUTOCMPLT_MS',
    'R_CORE_AUTOCMPLT_OPTN', 'R_CORE_AUTOCMPLT_PRJT',
    'R_CORE_AUTOCMPLT_SDB', 'R_CORE_AUTOCMPLT_SEEK',
    'R_CORE_AUTOCMPLT_THME', 'R_CORE_AUTOCMPLT_VARS',
    'R_CORE_AUTOCMPLT_ZIGN', 'R_CORE_TASK_STATE_BEFORE_START',
    'R_CORE_TASK_STATE_DONE', 'R_CORE_TASK_STATE_RUNNING',
    'R_CORE_TASK_STATE_SLEEPING', 'R_CORE_VISUAL_MODE_CD',
    'R_CORE_VISUAL_MODE_DB', 'R_CORE_VISUAL_MODE_OV',
    'R_CORE_VISUAL_MODE_PD', 'R_CORE_VISUAL_MODE_PX',
    'R_DBG_RECOIL_CONTINUE', 'R_DBG_RECOIL_NONE', 'R_DBG_RECOIL_STEP',
    'R_DEBUG_REASON_ABORT', 'R_DEBUG_REASON_BREAKPOINT',
    'R_DEBUG_REASON_COND', 'R_DEBUG_REASON_DEAD',
    'R_DEBUG_REASON_DIVBYZERO', 'R_DEBUG_REASON_ERROR',
    'R_DEBUG_REASON_EXIT_LIB', 'R_DEBUG_REASON_EXIT_PID',
    'R_DEBUG_REASON_EXIT_TID', 'R_DEBUG_REASON_FPU',
    'R_DEBUG_REASON_ILLEGAL', 'R_DEBUG_REASON_INT',
    'R_DEBUG_REASON_NEW_LIB', 'R_DEBUG_REASON_NEW_PID',
    'R_DEBUG_REASON_NEW_TID', 'R_DEBUG_REASON_NONE',
    'R_DEBUG_REASON_READERR', 'R_DEBUG_REASON_SEGFAULT',
    'R_DEBUG_REASON_SIGNAL', 'R_DEBUG_REASON_STEP',
    'R_DEBUG_REASON_STOPPED', 'R_DEBUG_REASON_SWI',
    'R_DEBUG_REASON_TERMINATED', 'R_DEBUG_REASON_TRACEPOINT',
    'R_DEBUG_REASON_TRAP', 'R_DEBUG_REASON_UNKNOWN',
    'R_DEBUG_REASON_USERSUSP', 'R_DEBUG_REASON_WRITERR',
    'R_LINE_PROMPT_DEFAULT', 'R_LINE_PROMPT_FILE',
    'R_LINE_PROMPT_OFFSET', 'R_LOGLVL_DEBUG', 'R_LOGLVL_ERROR',
    'R_LOGLVL_FATAL', 'R_LOGLVL_INFO', 'R_LOGLVL_NONE',
    'R_LOGLVL_SILLY', 'R_LOGLVL_VERBOSE', 'R_LOGLVL_WARN',
    'R_TH_FREED', 'R_TH_REPEAT', 'R_TH_STOP', 'c__EA_RAnalCPPABI',
    'c__EA_RAnalOpDirection', 'c__EA_RAnalOpFamily',
    'c__EA_RAnalOpMask', 'c__EA_RAnalOpPrefix', 'c__EA_RAnalStackOp',
    'c__EA_RAnalValueAccess', 'c__EA_RAnalValueType',
    'c__EA_RAutocompleteType', 'c__EA_RCmdDescType',
    'c__EA_RCoreVisualMode', 'c__EA_RDebugReasonType',
    'c__EA_RDebugRecoilMode', 'c__EA_RLinePromptType',
    'c__EA_RNumCalcToken', 'c__EA_RPanelType', 'c__EA_RPanelsFun',
    'c__EA_RPanelsLayout', 'c__EA_RPanelsMode',
    'c__EA_RPanelsRootState', 'c__EA_RTaskState',
    'c__EA_RThreadFunctionRet', 'c__EA__RAnalCond', 'cmd_agfb',
    'cmd_agfb2', 'cmd_agfb3', 'cmd_anal_objc', 'cmd_syscall_dostr',
    'core_anal_bbs', 'core_anal_bbs_range', 'core_type_by_addr',
    'inRangeCb', 'r_anal_data_type_t', 'r_cmd_status_t',
    'r_core_add_asmqjmp', 'r_core_af', 'r_core_agraph_print',
    'r_core_anal_address', 'r_core_anal_all',
    'r_core_anal_autoname_all_fcns',
    'r_core_anal_autoname_all_golang_fcns', 'r_core_anal_bb_seek',
    'r_core_anal_callgraph', 'r_core_anal_cc_init',
    'r_core_anal_coderefs', 'r_core_anal_codexrefs',
    'r_core_anal_cycles', 'r_core_anal_data', 'r_core_anal_datarefs',
    'r_core_anal_esil', 'r_core_anal_fcn', 'r_core_anal_fcn_autoname',
    'r_core_anal_fcn_clean', 'r_core_anal_fcn_get_calls',
    'r_core_anal_fcn_labels', 'r_core_anal_fcn_list',
    'r_core_anal_fcn_list_size', 'r_core_anal_fcn_merge',
    'r_core_anal_fcn_name', 'r_core_anal_get_bbaddr',
    'r_core_anal_get_comments', 'r_core_anal_get_stats',
    'r_core_anal_graph', 'r_core_anal_graph_fcn',
    'r_core_anal_graph_to', 'r_core_anal_hasrefs',
    'r_core_anal_hasrefs_to_depth', 'r_core_anal_hint_list',
    'r_core_anal_hint_print', 'r_core_anal_importxrefs',
    'r_core_anal_inflags', 'r_core_anal_op',
    'r_core_anal_optype_colorfor', 'r_core_anal_paths',
    'r_core_anal_propagate_noreturn', 'r_core_anal_ref_list',
    'r_core_anal_refs', 'r_core_anal_search',
    'r_core_anal_search_xrefs', 'r_core_anal_stats_free',
    'r_core_anal_type_init', 'r_core_anal_type_match',
    'r_core_anal_undefine', 'r_core_arch_bits_at',
    'r_core_asm_back_disassemble_byte',
    'r_core_asm_back_disassemble_instr', 'r_core_asm_bwdis_len',
    'r_core_asm_bwdisassemble', 'r_core_asm_hit_free',
    'r_core_asm_hit_list_new', 'r_core_asm_hit_new',
    'r_core_asm_search', 'r_core_asm_strsearch',
    'r_core_autocomplete', 'r_core_autocomplete_add',
    'r_core_autocomplete_find', 'r_core_autocomplete_free',
    'r_core_autocomplete_reload', 'r_core_autocomplete_remove',
    'r_core_autocomplete_types_t', 'r_core_bb_starts_in_middle',
    'r_core_bin_delete', 'r_core_bin_export_info',
    'r_core_bin_impaddr', 'r_core_bin_info', 'r_core_bin_list',
    'r_core_bin_load', 'r_core_bin_load_structs',
    'r_core_bin_method_flags_str', 'r_core_bin_raise',
    'r_core_bin_rebase', 'r_core_bin_set_arch_bits',
    'r_core_bin_set_by_fd', 'r_core_bin_set_by_name',
    'r_core_bin_set_cur', 'r_core_bin_set_env',
    'r_core_bin_update_arch_bits', 'r_core_bind', 'r_core_bind_cons',
    'r_core_block_read', 'r_core_block_size', 'r_core_cast',
    'r_core_clippy', 'r_core_cmd', 'r_core_cmd0', 'r_core_cmd_buffer',
    'r_core_cmd_command', 'r_core_cmd_file', 'r_core_cmd_foreach',
    'r_core_cmd_foreach3', 'r_core_cmd_help', 'r_core_cmd_init',
    'r_core_cmd_lines', 'r_core_cmd_pipe', 'r_core_cmd_queue',
    'r_core_cmd_queue_wait', 'r_core_cmd_str', 'r_core_cmd_str_pipe',
    'r_core_cmd_strf', 'r_core_cmd_task_sync', 'r_core_cmd_tobuf',
    'r_core_cmdf', 'r_core_cmpwatch_add', 'r_core_cmpwatch_del',
    'r_core_cmpwatch_free', 'r_core_cmpwatch_get',
    'r_core_cmpwatch_revert', 'r_core_cmpwatch_show',
    'r_core_cmpwatch_update', 'r_core_config_init',
    'r_core_config_update', 'r_core_debug_rr', 'r_core_diff_show',
    'r_core_disasm_pde', 'r_core_disasm_pdi',
    'r_core_disasm_pdi_with_buf', 'r_core_disassemble_bytes',
    'r_core_disassemble_instr', 'r_core_dump', 'r_core_echo',
    'r_core_editor', 'r_core_esil_cmd', 'r_core_esil_step',
    'r_core_esil_step_back', 'r_core_extend_at', 'r_core_fgets',
    'r_core_file_close_all_but', 'r_core_file_open',
    'r_core_file_open_many', 'r_core_file_reopen',
    'r_core_file_reopen_debug', 'r_core_file_reopen_remote_debug',
    'r_core_fini', 'r_core_flag_get_by_spaces',
    'r_core_flag_in_middle', 'r_core_fortune_list',
    'r_core_fortune_list_types', 'r_core_fortune_print_random',
    'r_core_free', 'r_core_gadget_free', 'r_core_gdiff',
    'r_core_gdiff_fcn', 'r_core_get_asmqjmps', 'r_core_get_bin',
    'r_core_get_boundaries_prot', 'r_core_get_config',
    'r_core_get_cons', 'r_core_get_func_args', 'r_core_get_prc_cols',
    'r_core_get_section_name', 'r_core_get_stacksz',
    'r_core_get_theme', 'r_core_getreloc', 'r_core_hack',
    'r_core_hack_help', 'r_core_init', 'r_core_is_valid_offset',
    'r_core_item_at', 'r_core_item_free', 'r_core_lines_currline',
    'r_core_lines_initcache', 'r_core_link_stroff', 'r_core_list_io',
    'r_core_list_themes', 'r_core_loadlibs', 'r_core_loadlibs_init',
    'r_core_log_add', 'r_core_log_del', 'r_core_log_free',
    'r_core_log_get', 'r_core_log_init', 'r_core_log_list',
    'r_core_log_new', 'r_core_log_run', 'r_core_ncast', 'r_core_new',
    'r_core_op_anal', 'r_core_op_str', 'r_core_panels_load',
    'r_core_panels_root', 'r_core_panels_save',
    'r_core_parse_radare2rc', 'r_core_patch', 'r_core_pava',
    'r_core_pdb_info', 'r_core_pj_new', 'r_core_plugin_a2f',
    'r_core_plugin_add', 'r_core_plugin_check', 'r_core_plugin_fini',
    'r_core_plugin_init', 'r_core_plugin_java',
    'r_core_plugin_sixref', 'r_core_prevop_addr',
    'r_core_prevop_addr_force', 'r_core_print_bb_custom',
    'r_core_print_bb_gml', 'r_core_print_disasm',
    'r_core_print_disasm_all', 'r_core_print_disasm_instructions',
    'r_core_print_disasm_instructions_with_buf',
    'r_core_print_disasm_json', 'r_core_print_fcn_disasm',
    'r_core_print_func_args', 'r_core_print_scrollbar',
    'r_core_print_scrollbar_bottom', 'r_core_project_cat',
    'r_core_project_delete', 'r_core_project_execute_cmds',
    'r_core_project_is_saved', 'r_core_project_list',
    'r_core_project_name', 'r_core_project_notes_file',
    'r_core_project_open', 'r_core_project_save',
    'r_core_project_save_script', 'r_core_prompt',
    'r_core_prompt_exec', 'r_core_prompt_loop', 'r_core_pseudo_code',
    'r_core_recover_vars', 'r_core_rtr_add', 'r_core_rtr_cmd',
    'r_core_rtr_cmds', 'r_core_rtr_cmds_query', 'r_core_rtr_event',
    'r_core_rtr_gdb', 'r_core_rtr_help', 'r_core_rtr_http',
    'r_core_rtr_http_stop', 'r_core_rtr_list', 'r_core_rtr_pushout',
    'r_core_rtr_remove', 'r_core_rtr_session', 'r_core_run_script',
    'r_core_search_cb', 'r_core_search_prelude',
    'r_core_search_preludes', 'r_core_search_value_in_range',
    'r_core_seek', 'r_core_seek_align', 'r_core_seek_arch_bits',
    'r_core_seek_base', 'r_core_seek_delta', 'r_core_seek_next',
    'r_core_seek_previous', 'r_core_seek_size', 'r_core_serve',
    'r_core_set_asm_configs', 'r_core_set_asmqjmps',
    'r_core_set_file_by_fd', 'r_core_set_file_by_name',
    'r_core_setup_debugger', 'r_core_shift_block', 'r_core_syscall',
    'r_core_syscallf', 'r_core_syscmd_cat', 'r_core_syscmd_ls',
    'r_core_syscmd_mkdir', 'r_core_sysenv_begin', 'r_core_sysenv_end',
    'r_core_table', 'r_core_task_break', 'r_core_task_break_all',
    'r_core_task_decref', 'r_core_task_del',
    'r_core_task_del_all_done', 'r_core_task_enqueue',
    'r_core_task_enqueue_oneshot', 'r_core_task_get',
    'r_core_task_get_incref', 'r_core_task_incref',
    'r_core_task_join', 'r_core_task_list', 'r_core_task_new',
    'r_core_task_print', 'r_core_task_run_sync',
    'r_core_task_running_tasks_count', 'r_core_task_scheduler_fini',
    'r_core_task_scheduler_init', 'r_core_task_self',
    'r_core_task_sleep_begin', 'r_core_task_sleep_end',
    'r_core_task_status', 'r_core_task_sync_begin',
    'r_core_task_sync_end', 'r_core_task_yield',
    'r_core_transform_op', 'r_core_undo_free', 'r_core_undo_new',
    'r_core_undo_pop', 'r_core_undo_print', 'r_core_undo_push',
    'r_core_version', 'r_core_visual', 'r_core_visual_anal',
    'r_core_visual_anal_classes', 'r_core_visual_append_help',
    'r_core_visual_applyDisMode', 'r_core_visual_applyHexMode',
    'r_core_visual_asm', 'r_core_visual_bit_editor',
    'r_core_visual_browse', 'r_core_visual_classes',
    'r_core_visual_cmd', 'r_core_visual_colors',
    'r_core_visual_comments', 'r_core_visual_config',
    'r_core_visual_debugtraces', 'r_core_visual_define',
    'r_core_visual_disasm_down', 'r_core_visual_disasm_up',
    'r_core_visual_esil', 'r_core_visual_graph', 'r_core_visual_hud',
    'r_core_visual_hudstuff', 'r_core_visual_jump',
    'r_core_visual_mark', 'r_core_visual_mark_del',
    'r_core_visual_mark_dump', 'r_core_visual_mark_reset',
    'r_core_visual_mark_seek', 'r_core_visual_mark_set',
    'r_core_visual_mounts', 'r_core_visual_offset',
    'r_core_visual_prevopsz', 'r_core_visual_prompt',
    'r_core_visual_prompt_input', 'r_core_visual_refs',
    'r_core_visual_seek_animation', 'r_core_visual_showcursor',
    'r_core_visual_slides', 'r_core_visual_toggle_decompiler_disasm',
    'r_core_visual_trackflags', 'r_core_visual_types',
    'r_core_visual_view_graph', 'r_core_visual_view_rop',
    'r_core_visual_view_zigns', 'r_core_visual_xrefs_X',
    'r_core_visual_xrefs_x', 'r_core_wait', 'r_core_write_at',
    'r_core_write_op', 'r_core_yank', 'r_core_yank_cat',
    'r_core_yank_cat_string', 'r_core_yank_dump',
    'r_core_yank_file_all', 'r_core_yank_file_ex',
    'r_core_yank_hexdump', 'r_core_yank_hexpair',
    'r_core_yank_hud_file', 'r_core_yank_hud_path',
    'r_core_yank_paste', 'r_core_yank_set', 'r_core_yank_set_str',
    'r_core_yank_string', 'r_core_yank_to', 'r_core_zdiff',
    'r_line_hist_offset_down', 'r_line_hist_offset_up',
    'r_listinfo_free', 'r_listinfo_new', 'r_log_level',
    'r_project_close', 'r_project_free', 'r_project_is_git',
    'r_project_is_loaded', 'r_project_new', 'r_project_open',
    'r_project_rename', 'r_project_save', 'r_str_widget_list',
    'resolve_fcn_name', 'size_t', 'struct__IO_FILE',
    'struct__IO_codecvt', 'struct__IO_marker', 'struct__IO_wide_data',
    'struct___pthread_cond_s', 'struct___pthread_cond_s_0_0',
    'struct___pthread_cond_s_1_0', 'struct___pthread_internal_list',
    'struct___pthread_mutex_s', 'struct_buffer',
    'struct_c__SA_RConsCursorPos', 'struct_c__SA_RCoreAnalStats',
    'struct_c__SA_RCoreAnalStatsItem', 'struct_c__SA_RCoreGadget',
    'struct_c__SA_RCoreUndoCondition', 'struct_c__SA_RListInfo',
    'struct_c__SA_RNumCalcValue', 'struct_c__SA_RStrBuf',
    'struct_c__SA_RStrpool', 'struct_c__SA_RTable',
    'struct_c__SA_dict', 'struct_cdb', 'struct_cdb_hp',
    'struct_cdb_hplist', 'struct_cdb_make', 'struct_ht_pp_bucket_t',
    'struct_ht_pp_kv', 'struct_ht_pp_options_t', 'struct_ht_pp_t',
    'struct_ht_up_bucket_t', 'struct_ht_up_kv',
    'struct_ht_up_options_t', 'struct_ht_up_t', 'struct_in_addr',
    'struct_layer_t', 'struct_ls_iter_t', 'struct_ls_t',
    'struct_pj_t', 'struct_r_anal_bb_t', 'struct_r_anal_bind_t',
    'struct_r_anal_callbacks_t', 'struct_r_anal_cond_t',
    'struct_r_anal_diff_t', 'struct_r_anal_esil_callbacks_t',
    'struct_r_anal_esil_handler_t', 'struct_r_anal_esil_plugin_t',
    'struct_r_anal_esil_t', 'struct_r_anal_esil_trace_t',
    'struct_r_anal_function_meta_t', 'struct_r_anal_function_t',
    'struct_r_anal_hint_cb_t', 'struct_r_anal_hint_t',
    'struct_r_anal_op_t', 'struct_r_anal_options_t',
    'struct_r_anal_plugin_t', 'struct_r_anal_range_t',
    'struct_r_anal_reil', 'struct_r_anal_switch_obj_t',
    'struct_r_anal_t', 'struct_r_anal_value_t',
    'struct_r_ascii_graph_t', 'struct_r_ascii_node_t',
    'struct_r_asm_op_t', 'struct_r_asm_plugin_t', 'struct_r_asm_t',
    'struct_r_bin_addr_t', 'struct_r_bin_arch_options_t',
    'struct_r_bin_bind_t', 'struct_r_bin_dbginfo_t',
    'struct_r_bin_file_t', 'struct_r_bin_hash_t',
    'struct_r_bin_import_t', 'struct_r_bin_info_t',
    'struct_r_bin_object_t', 'struct_r_bin_plugin_t',
    'struct_r_bin_reloc_t', 'struct_r_bin_section_t',
    'struct_r_bin_symbol_t', 'struct_r_bin_t', 'struct_r_bin_write_t',
    'struct_r_bin_xtr_extract_t', 'struct_r_bin_xtr_metadata_t',
    'struct_r_bin_xtr_plugin_t', 'struct_r_bp_arch_t',
    'struct_r_bp_item_t', 'struct_r_bp_plugin_t', 'struct_r_bp_t',
    'struct_r_buf_t', 'struct_r_buffer_methods_t', 'struct_r_cache_t',
    'struct_r_charset_rune_t', 'struct_r_charset_t',
    'struct_r_cmd_desc_example_t', 'struct_r_cmd_desc_help_t',
    'struct_r_cmd_desc_t', 'struct_r_cmd_desc_t_0_0',
    'struct_r_cmd_desc_t_0_1', 'struct_r_cmd_desc_t_0_2',
    'struct_r_cmd_descriptor_t', 'struct_r_cmd_item_t',
    'struct_r_cmd_macro_label_t', 'struct_r_cmd_macro_t',
    'struct_r_cmd_t', 'struct_r_config_t', 'struct_r_cons_bind_t',
    'struct_r_cons_canvas_t', 'struct_r_cons_context_t',
    'struct_r_cons_grep_t', 'struct_r_cons_palette_t',
    'struct_r_cons_printable_palette_t', 'struct_r_cons_t',
    'struct_r_core_asm_hit', 'struct_r_core_autocomplete_t',
    'struct_r_core_bin_filter_t', 'struct_r_core_bind_t',
    'struct_r_core_cmpwatch_t', 'struct_r_core_graph_hits_t',
    'struct_r_core_item_t', 'struct_r_core_log_t',
    'struct_r_core_plugin_t', 'struct_r_core_project_t',
    'struct_r_core_rtr_host_t', 'struct_r_core_t',
    'struct_r_core_task_t', 'struct_r_core_tasks_t',
    'struct_r_core_times_t', 'struct_r_core_undo_t',
    'struct_r_core_visual_t', 'struct_r_core_visual_tab_t',
    'struct_r_crbtree_node', 'struct_r_crbtree_t',
    'struct_r_debug_checkpoint_t', 'struct_r_debug_desc_plugin_t',
    'struct_r_debug_info_t', 'struct_r_debug_map_t',
    'struct_r_debug_plugin_t', 'struct_r_debug_reason_t',
    'struct_r_debug_session_t', 'struct_r_debug_t',
    'struct_r_debug_trace_t', 'struct_r_egg_emit_t',
    'struct_r_egg_lang_t', 'struct_r_egg_lang_t_0',
    'struct_r_egg_lang_t_1', 'struct_r_egg_lang_t_2',
    'struct_r_egg_t', 'struct_r_event_t', 'struct_r_flag_bind_t',
    'struct_r_flag_item_t', 'struct_r_flag_t', 'struct_r_fs_shell_t',
    'struct_r_fs_t', 'struct_r_graph_node_t', 'struct_r_graph_t',
    'struct_r_hud_t', 'struct_r_id_pool_t', 'struct_r_id_storage_t',
    'struct_r_interval_node_t', 'struct_r_interval_t',
    'struct_r_interval_tree_t', 'struct_r_io_bank_t',
    'struct_r_io_bind_t', 'struct_r_io_desc_t', 'struct_r_io_map_t',
    'struct_r_io_plugin_t', 'struct_r_io_t', 'struct_r_io_undo_t',
    'struct_r_io_undos_t', 'struct_r_lang_plugin_t',
    'struct_r_lang_t', 'struct_r_lib_t', 'struct_r_line_buffer_t',
    'struct_r_line_comp_t', 'struct_r_line_hist_t', 'struct_r_line_t',
    'struct_r_list_iter_t', 'struct_r_list_t', 'struct_r_num_calc_t',
    'struct_r_num_t', 'struct_r_panel_model_t',
    'struct_r_panel_pos_t', 'struct_r_panel_t',
    'struct_r_panel_view_t', 'struct_r_panels_menu_item',
    'struct_r_panels_menu_t', 'struct_r_panels_root_t',
    'struct_r_panels_t', 'struct_r_parse_plugin_t',
    'struct_r_parse_t', 'struct_r_print_t', 'struct_r_print_zoom_t',
    'struct_r_pvector_t', 'struct_r_queue_t', 'struct_r_rb_node_t',
    'struct_r_reg_arena_t', 'struct_r_reg_item_t',
    'struct_r_reg_set_t', 'struct_r_reg_t',
    'struct_r_search_keyword_t', 'struct_r_search_t',
    'struct_r_selection_widget_t', 'struct_r_skiplist_node_t',
    'struct_r_skiplist_t', 'struct_r_skyline_t', 'struct_r_socket_t',
    'struct_r_space_t', 'struct_r_spaces_t', 'struct_r_stack_t',
    'struct_r_str_constpool_t', 'struct_r_syscall_item_t',
    'struct_r_syscall_port_t', 'struct_r_syscall_t',
    'struct_r_th_cond_t', 'struct_r_th_lock_t', 'struct_r_th_sem_t',
    'struct_r_th_t', 'struct_r_tree_node_t', 'struct_r_tree_t',
    'struct_r_vector_t', 'struct_rcolor_t', 'struct_sdb_gperf_t',
    'struct_sdb_kv', 'struct_sdb_t', 'struct_sockaddr_in',
    'struct_termios', 'union___pthread_cond_s_0',
    'union___pthread_cond_s_1', 'union_c__UA_pthread_cond_t',
    'union_c__UA_pthread_mutex_t', 'union_c__UA_sem_t',
    'union_r_cmd_desc_t_0']
