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



r_parse_version = _libr_parse.r_parse_version
r_parse_version.restype = ctypes.POINTER(ctypes.c_char)
r_parse_version.argtypes = []
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

class struct_r_anal_function_t(Structure):
    pass

class struct_ht_pp_t(Structure):
    pass

class struct_ht_up_t(Structure):
    pass

class struct_r_anal_t(Structure):
    pass

class struct_r_anal_diff_t(Structure):
    pass

class struct_r_anal_function_meta_t(Structure):
    pass

struct_r_anal_function_meta_t._pack_ = 1 # source:False
struct_r_anal_function_meta_t._fields_ = [
    ('_min', ctypes.c_uint64),
    ('_max', ctypes.c_uint64),
    ('numrefs', ctypes.c_int32),
    ('numcallrefs', ctypes.c_int32),
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

class struct_sdb_t(Structure):
    pass

class struct_r_anal_esil_plugin_t(Structure):
    pass

class struct_r_anal_range_t(Structure):
    pass

class struct_r_anal_plugin_t(Structure):
    pass

class struct_r_rb_node_t(Structure):
    pass

class struct_r_syscall_t(Structure):
    pass

class struct_r_reg_t(Structure):
    pass

class struct_r_print_t(Structure):
    pass

class struct_r_anal_esil_t(Structure):
    pass

class struct_r_event_t(Structure):
    pass

class struct_r_flag_bind_t(Structure):
    pass

class struct_r_flag_t(Structure):
    pass

class struct_r_space_t(Structure):
    pass

class struct_r_flag_item_t(Structure):
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

class struct_r_io_bind_t(Structure):
    pass

class struct_r_io_t(Structure):
    pass

class struct_r_io_desc_t(Structure):
    pass

class struct_r_io_map_t(Structure):
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


# values for enumeration 'c__EA_RAnalCPPABI'
c__EA_RAnalCPPABI__enumvalues = {
    0: 'R_ANAL_CPP_ABI_ITANIUM',
    1: 'R_ANAL_CPP_ABI_MSVC',
}
R_ANAL_CPP_ABI_ITANIUM = 0
R_ANAL_CPP_ABI_MSVC = 1
c__EA_RAnalCPPABI = ctypes.c_uint32 # enum
class struct_r_anal_callbacks_t(Structure):
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

class struct_r_spaces_t(Structure):
    pass

class struct_r_crbtree_t(Structure):
    pass

struct_r_spaces_t._pack_ = 1 # source:False
struct_r_spaces_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('current', ctypes.POINTER(struct_r_space_t)),
    ('spaces', ctypes.POINTER(struct_r_crbtree_t)),
    ('spacestack', ctypes.POINTER(struct_r_list_t)),
    ('event', ctypes.POINTER(struct_r_event_t)),
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

class struct_r_bin_bind_t(Structure):
    pass

class struct_r_bin_t(Structure):
    pass

class struct_r_bin_file_t(Structure):
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

class struct__IO_FILE(Structure):
    pass

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

class struct_r_cache_t(Structure):
    pass

class struct_r_id_storage_t(Structure):
    pass

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

class struct_r_skiplist_t(Structure):
    pass

class struct_r_num_t(Structure):
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

class struct_r_num_calc_t(Structure):
    pass


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
    ('type', ctypes.POINTER(ctypes.c_char)),
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

class struct_r_buf_t(Structure):
    pass

class struct_r_bin_xtr_plugin_t(Structure):
    pass

class struct_r_bin_object_t(Structure):
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

class struct_r_bin_write_t(Structure):
    pass

class struct_r_bin_dbginfo_t(Structure):
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

class struct_r_anal_esil_trace_t(Structure):
    pass

class struct_r_anal_esil_handler_t(Structure):
    pass

class struct_r_anal_reil(Structure):
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

struct_r_anal_cond_t._pack_ = 1 # source:False
struct_r_anal_cond_t._fields_ = [
    ('type', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('arg', ctypes.POINTER(struct_r_anal_value_t) * 2),
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

class struct_r_cons_t(Structure):
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

class struct_r_cons_context_t(Structure):
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
class struct_r_cons_palette_t(Structure):
    _pack_ = 1 # source:False
    _fields_ = [
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

class struct_r_hud_t(Structure):
    pass

class struct_r_selection_widget_t(Structure):
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
class struct_r_line_buffer_t(Structure):
    pass

struct_r_line_buffer_t._pack_ = 1 # source:False
struct_r_line_buffer_t._fields_ = [
    ('data', ctypes.c_char * 4096),
    ('index', ctypes.c_int32),
    ('length', ctypes.c_int32),
]

class struct_r_line_comp_t(Structure):
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

RAnalVarList = ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_anal_function_t), ctypes.c_int32)
class struct_r_parse_t(Structure):
    pass

class struct_r_parse_plugin_t(Structure):
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

RParse = struct_r_parse_t
RParsePlugin = struct_r_parse_plugin_t
r_parse_new = _libr_parse.r_parse_new
r_parse_new.restype = ctypes.POINTER(struct_r_parse_t)
r_parse_new.argtypes = []
r_parse_free = _libr_parse.r_parse_free
r_parse_free.restype = None
r_parse_free.argtypes = [ctypes.POINTER(struct_r_parse_t)]
r_parse_set_user_ptr = _libr_parse.r_parse_set_user_ptr
r_parse_set_user_ptr.restype = None
r_parse_set_user_ptr.argtypes = [ctypes.POINTER(struct_r_parse_t), ctypes.POINTER(None)]
r_parse_add = _libr_parse.r_parse_add
r_parse_add.restype = ctypes.c_bool
r_parse_add.argtypes = [ctypes.POINTER(struct_r_parse_t), ctypes.POINTER(struct_r_parse_plugin_t)]
r_parse_use = _libr_parse.r_parse_use
r_parse_use.restype = ctypes.c_bool
r_parse_use.argtypes = [ctypes.POINTER(struct_r_parse_t), ctypes.POINTER(ctypes.c_char)]
r_parse_parse = _libr_parse.r_parse_parse
r_parse_parse.restype = ctypes.c_bool
r_parse_parse.argtypes = [ctypes.POINTER(struct_r_parse_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_parse_assemble = _libr_parse.r_parse_assemble
r_parse_assemble.restype = ctypes.c_bool
r_parse_assemble.argtypes = [ctypes.POINTER(struct_r_parse_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_parse_filter = _libr_parse.r_parse_filter
r_parse_filter.restype = ctypes.c_bool
r_parse_filter.argtypes = [ctypes.POINTER(struct_r_parse_t), ctypes.c_uint64, ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(struct_r_anal_hint_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_bool]
r_parse_subvar = _libr_parse.r_parse_subvar
r_parse_subvar.restype = ctypes.c_bool
r_parse_subvar.argtypes = [ctypes.POINTER(struct_r_parse_t), ctypes.POINTER(struct_r_anal_function_t), ctypes.c_uint64, ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_parse_immtrim = _libr_parse.r_parse_immtrim
r_parse_immtrim.restype = ctypes.POINTER(ctypes.c_char)
r_parse_immtrim.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_parse_c_string = _libr_parse.r_parse_c_string
r_parse_c_string.restype = ctypes.POINTER(ctypes.c_char)
r_parse_c_string.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
r_parse_c_file = _libr_parse.r_parse_c_file
r_parse_c_file.restype = ctypes.POINTER(ctypes.c_char)
r_parse_c_file.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
r_parse_c_reset = _libr_parse.r_parse_c_reset
r_parse_c_reset.restype = None
r_parse_c_reset.argtypes = [ctypes.POINTER(struct_r_parse_t)]
r_parse_plugin_6502_pseudo = struct_r_parse_plugin_t # Variable struct_r_parse_plugin_t
r_parse_plugin_arm_pseudo = struct_r_parse_plugin_t # Variable struct_r_parse_plugin_t
r_parse_plugin_att2intel = struct_r_parse_plugin_t # Variable struct_r_parse_plugin_t
r_parse_plugin_avr_pseudo = struct_r_parse_plugin_t # Variable struct_r_parse_plugin_t
r_parse_plugin_chip8_pseudo = struct_r_parse_plugin_t # Variable struct_r_parse_plugin_t
r_parse_plugin_dalvik_pseudo = struct_r_parse_plugin_t # Variable struct_r_parse_plugin_t
r_parse_plugin_dummy = struct_r_parse_plugin_t # Variable struct_r_parse_plugin_t
r_parse_plugin_m68k_pseudo = struct_r_parse_plugin_t # Variable struct_r_parse_plugin_t
r_parse_plugin_mips_pseudo = struct_r_parse_plugin_t # Variable struct_r_parse_plugin_t
r_parse_plugin_ppc_pseudo = struct_r_parse_plugin_t # Variable struct_r_parse_plugin_t
r_parse_plugin_sh_pseudo = struct_r_parse_plugin_t # Variable struct_r_parse_plugin_t
r_parse_plugin_wasm_pseudo = struct_r_parse_plugin_t # Variable struct_r_parse_plugin_t
r_parse_plugin_riscv_pseudo = struct_r_parse_plugin_t # Variable struct_r_parse_plugin_t
r_parse_plugin_x86_pseudo = struct_r_parse_plugin_t # Variable struct_r_parse_plugin_t
r_parse_plugin_z80_pseudo = struct_r_parse_plugin_t # Variable struct_r_parse_plugin_t
r_parse_plugin_tms320_pseudo = struct_r_parse_plugin_t # Variable struct_r_parse_plugin_t
r_parse_plugin_v850_pseudo = struct_r_parse_plugin_t # Variable struct_r_parse_plugin_t
__all__ = \
    ['RAnalVarList', 'RNCAND', 'RNCASSIGN', 'RNCDEC', 'RNCDIV',
    'RNCEND', 'RNCGT', 'RNCINC', 'RNCLEFTP', 'RNCLT', 'RNCMINUS',
    'RNCMOD', 'RNCMUL', 'RNCNAME', 'RNCNEG', 'RNCNUMBER', 'RNCOR',
    'RNCPLUS', 'RNCPRINT', 'RNCRIGHTP', 'RNCROL', 'RNCROR', 'RNCSHL',
    'RNCSHR', 'RNCXOR', 'RParse', 'RParsePlugin', 'R_ANAL_ACC_R',
    'R_ANAL_ACC_UNKNOWN', 'R_ANAL_ACC_W', 'R_ANAL_COND_AL',
    'R_ANAL_COND_EQ', 'R_ANAL_COND_GE', 'R_ANAL_COND_GT',
    'R_ANAL_COND_HI', 'R_ANAL_COND_HS', 'R_ANAL_COND_LE',
    'R_ANAL_COND_LO', 'R_ANAL_COND_LS', 'R_ANAL_COND_LT',
    'R_ANAL_COND_MI', 'R_ANAL_COND_NE', 'R_ANAL_COND_NV',
    'R_ANAL_COND_PL', 'R_ANAL_COND_VC', 'R_ANAL_COND_VS',
    'R_ANAL_CPP_ABI_ITANIUM', 'R_ANAL_CPP_ABI_MSVC',
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
    'R_ANAL_VAL_REG', 'R_LINE_PROMPT_DEFAULT', 'R_LINE_PROMPT_FILE',
    'R_LINE_PROMPT_OFFSET', 'R_LOGLVL_DEBUG', 'R_LOGLVL_ERROR',
    'R_LOGLVL_FATAL', 'R_LOGLVL_INFO', 'R_LOGLVL_NONE',
    'R_LOGLVL_SILLY', 'R_LOGLVL_VERBOSE', 'R_LOGLVL_WARN',
    'c__EA_RAnalCPPABI', 'c__EA_RAnalOpDirection',
    'c__EA_RAnalOpFamily', 'c__EA_RAnalOpMask', 'c__EA_RAnalOpPrefix',
    'c__EA_RAnalStackOp', 'c__EA_RAnalValueAccess',
    'c__EA_RAnalValueType', 'c__EA_RLinePromptType',
    'c__EA_RNumCalcToken', 'c__EA__RAnalCond', 'r_anal_data_type_t',
    'r_log_level', 'r_parse_add', 'r_parse_assemble',
    'r_parse_c_file', 'r_parse_c_reset', 'r_parse_c_string',
    'r_parse_filter', 'r_parse_free', 'r_parse_immtrim',
    'r_parse_new', 'r_parse_parse', 'r_parse_plugin_6502_pseudo',
    'r_parse_plugin_arm_pseudo', 'r_parse_plugin_att2intel',
    'r_parse_plugin_avr_pseudo', 'r_parse_plugin_chip8_pseudo',
    'r_parse_plugin_dalvik_pseudo', 'r_parse_plugin_dummy',
    'r_parse_plugin_m68k_pseudo', 'r_parse_plugin_mips_pseudo',
    'r_parse_plugin_ppc_pseudo', 'r_parse_plugin_riscv_pseudo',
    'r_parse_plugin_sh_pseudo', 'r_parse_plugin_tms320_pseudo',
    'r_parse_plugin_v850_pseudo', 'r_parse_plugin_wasm_pseudo',
    'r_parse_plugin_x86_pseudo', 'r_parse_plugin_z80_pseudo',
    'r_parse_set_user_ptr', 'r_parse_subvar', 'r_parse_use',
    'r_parse_version', 'struct__IO_FILE', 'struct__IO_codecvt',
    'struct__IO_marker', 'struct__IO_wide_data', 'struct_buffer',
    'struct_c__SA_RConsCursorPos', 'struct_c__SA_RNumCalcValue',
    'struct_c__SA_RStrBuf', 'struct_c__SA_dict', 'struct_cdb',
    'struct_cdb_hp', 'struct_cdb_hplist', 'struct_cdb_make',
    'struct_ht_pp_bucket_t', 'struct_ht_pp_kv',
    'struct_ht_pp_options_t', 'struct_ht_pp_t',
    'struct_ht_up_bucket_t', 'struct_ht_up_kv',
    'struct_ht_up_options_t', 'struct_ht_up_t', 'struct_ls_iter_t',
    'struct_ls_t', 'struct_r_anal_bb_t', 'struct_r_anal_bind_t',
    'struct_r_anal_callbacks_t', 'struct_r_anal_cond_t',
    'struct_r_anal_diff_t', 'struct_r_anal_esil_callbacks_t',
    'struct_r_anal_esil_handler_t', 'struct_r_anal_esil_plugin_t',
    'struct_r_anal_esil_t', 'struct_r_anal_esil_trace_t',
    'struct_r_anal_function_meta_t', 'struct_r_anal_function_t',
    'struct_r_anal_hint_cb_t', 'struct_r_anal_hint_t',
    'struct_r_anal_op_t', 'struct_r_anal_options_t',
    'struct_r_anal_plugin_t', 'struct_r_anal_range_t',
    'struct_r_anal_reil', 'struct_r_anal_switch_obj_t',
    'struct_r_anal_t', 'struct_r_anal_value_t', 'struct_r_bin_addr_t',
    'struct_r_bin_arch_options_t', 'struct_r_bin_bind_t',
    'struct_r_bin_dbginfo_t', 'struct_r_bin_file_t',
    'struct_r_bin_hash_t', 'struct_r_bin_info_t',
    'struct_r_bin_object_t', 'struct_r_bin_plugin_t',
    'struct_r_bin_section_t', 'struct_r_bin_t',
    'struct_r_bin_write_t', 'struct_r_bin_xtr_extract_t',
    'struct_r_bin_xtr_metadata_t', 'struct_r_bin_xtr_plugin_t',
    'struct_r_buf_t', 'struct_r_buffer_methods_t', 'struct_r_cache_t',
    'struct_r_charset_rune_t', 'struct_r_charset_t',
    'struct_r_cons_bind_t', 'struct_r_cons_context_t',
    'struct_r_cons_grep_t', 'struct_r_cons_palette_t',
    'struct_r_cons_printable_palette_t', 'struct_r_cons_t',
    'struct_r_core_bind_t', 'struct_r_crbtree_node',
    'struct_r_crbtree_t', 'struct_r_event_t', 'struct_r_flag_bind_t',
    'struct_r_flag_item_t', 'struct_r_flag_t', 'struct_r_hud_t',
    'struct_r_id_pool_t', 'struct_r_id_storage_t',
    'struct_r_interval_node_t', 'struct_r_interval_t',
    'struct_r_interval_tree_t', 'struct_r_io_bank_t',
    'struct_r_io_bind_t', 'struct_r_io_desc_t', 'struct_r_io_map_t',
    'struct_r_io_plugin_t', 'struct_r_io_t', 'struct_r_io_undo_t',
    'struct_r_io_undos_t', 'struct_r_line_buffer_t',
    'struct_r_line_comp_t', 'struct_r_line_hist_t', 'struct_r_line_t',
    'struct_r_list_iter_t', 'struct_r_list_t', 'struct_r_num_calc_t',
    'struct_r_num_t', 'struct_r_parse_plugin_t', 'struct_r_parse_t',
    'struct_r_print_t', 'struct_r_print_zoom_t', 'struct_r_pvector_t',
    'struct_r_queue_t', 'struct_r_rb_node_t', 'struct_r_reg_arena_t',
    'struct_r_reg_item_t', 'struct_r_reg_set_t', 'struct_r_reg_t',
    'struct_r_selection_widget_t', 'struct_r_skiplist_node_t',
    'struct_r_skiplist_t', 'struct_r_skyline_t', 'struct_r_space_t',
    'struct_r_spaces_t', 'struct_r_stack_t',
    'struct_r_str_constpool_t', 'struct_r_syscall_item_t',
    'struct_r_syscall_port_t', 'struct_r_syscall_t',
    'struct_r_vector_t', 'struct_rcolor_t', 'struct_sdb_gperf_t',
    'struct_sdb_kv', 'struct_sdb_t', 'struct_termios']
