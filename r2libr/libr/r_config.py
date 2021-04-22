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





r_config_version = _libraries['FIXME_STUB'].r_config_version
r_config_version.restype = ctypes.POINTER(ctypes.c_char)
r_config_version.argtypes = []
RConfigCallback = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(None), ctypes.POINTER(None))
class struct_r_config_node_t(Structure):
    pass

class struct_r_list_t(Structure):
    pass

struct_r_config_node_t._pack_ = 1 # source:False
struct_r_config_node_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('flags', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('value', ctypes.POINTER(ctypes.c_char)),
    ('i_value', ctypes.c_uint64),
    ('cb_ptr_q', ctypes.POINTER(ctypes.c_uint64)),
    ('cb_ptr_i', ctypes.POINTER(ctypes.c_int32)),
    ('cb_ptr_s', ctypes.POINTER(ctypes.POINTER(ctypes.c_char))),
    ('getter', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(None), ctypes.POINTER(None))),
    ('setter', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(None), ctypes.POINTER(None))),
    ('desc', ctypes.POINTER(ctypes.c_char)),
    ('options', ctypes.POINTER(struct_r_list_t)),
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

RConfigNode = struct_r_config_node_t
r_config_node_type = _libr_config.r_config_node_type
r_config_node_type.restype = ctypes.POINTER(ctypes.c_char)
r_config_node_type.argtypes = [ctypes.POINTER(struct_r_config_node_t)]
class struct_r_config_t(Structure):
    pass

class struct_r_num_t(Structure):
    pass

class struct_ht_pp_t(Structure):
    pass

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

RConfig = struct_r_config_t
class struct_r_config_hold_t(Structure):
    pass

struct_r_config_hold_t._pack_ = 1 # source:False
struct_r_config_hold_t._fields_ = [
    ('cfg', ctypes.POINTER(struct_r_config_t)),
    ('list', ctypes.POINTER(struct_r_list_t)),
]

RConfigHold = struct_r_config_hold_t
r_config_hold_new = _libr_config.r_config_hold_new
r_config_hold_new.restype = ctypes.POINTER(struct_r_config_hold_t)
r_config_hold_new.argtypes = [ctypes.POINTER(struct_r_config_t)]
r_config_hold = _libr_config.r_config_hold
r_config_hold.restype = ctypes.c_bool
r_config_hold.argtypes = [ctypes.POINTER(struct_r_config_hold_t)]
r_config_hold_free = _libr_config.r_config_hold_free
r_config_hold_free.restype = None
r_config_hold_free.argtypes = [ctypes.POINTER(struct_r_config_hold_t)]
r_config_hold_restore = _libr_config.r_config_hold_restore
r_config_hold_restore.restype = None
r_config_hold_restore.argtypes = [ctypes.POINTER(struct_r_config_hold_t)]
r_config_new = _libr_config.r_config_new
r_config_new.restype = ctypes.POINTER(struct_r_config_t)
r_config_new.argtypes = [ctypes.POINTER(None)]
r_config_clone = _libr_config.r_config_clone
r_config_clone.restype = ctypes.POINTER(struct_r_config_t)
r_config_clone.argtypes = [ctypes.POINTER(struct_r_config_t)]
r_config_free = _libr_config.r_config_free
r_config_free.restype = None
r_config_free.argtypes = [ctypes.POINTER(struct_r_config_t)]
r_config_lock = _libr_config.r_config_lock
r_config_lock.restype = None
r_config_lock.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.c_bool]
r_config_eval = _libr_config.r_config_eval
r_config_eval.restype = ctypes.c_bool
r_config_eval.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char), ctypes.c_bool]
r_config_bump = _libr_config.r_config_bump
r_config_bump.restype = None
r_config_bump.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char)]
r_config_get_b = _libr_config.r_config_get_b
r_config_get_b.restype = ctypes.c_bool
r_config_get_b.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char)]
r_config_set_b = _libr_config.r_config_set_b
r_config_set_b.restype = ctypes.POINTER(struct_r_config_node_t)
r_config_set_b.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char), ctypes.c_bool]
r_config_set_i = _libr_config.r_config_set_i
r_config_set_i.restype = ctypes.POINTER(struct_r_config_node_t)
r_config_set_i.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64]
r_config_set_cb = _libr_config.r_config_set_cb
r_config_set_cb.restype = ctypes.POINTER(struct_r_config_node_t)
r_config_set_cb.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), RConfigCallback]
r_config_set_i_cb = _libr_config.r_config_set_i_cb
r_config_set_i_cb.restype = ctypes.POINTER(struct_r_config_node_t)
r_config_set_i_cb.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, RConfigCallback]
r_config_set = _libr_config.r_config_set
r_config_set.restype = ctypes.POINTER(struct_r_config_node_t)
r_config_set.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_config_rm = _libr_config.r_config_rm
r_config_rm.restype = ctypes.c_bool
r_config_rm.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char)]
r_config_get_i = _libr_config.r_config_get_i
r_config_get_i.restype = ctypes.c_uint64
r_config_get_i.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char)]
r_config_get = _libr_config.r_config_get
r_config_get.restype = ctypes.POINTER(ctypes.c_char)
r_config_get.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char)]
r_config_desc = _libr_config.r_config_desc
r_config_desc.restype = ctypes.POINTER(ctypes.c_char)
r_config_desc.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_config_list = _libr_config.r_config_list
r_config_list.restype = None
r_config_list.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_config_toggle = _libr_config.r_config_toggle
r_config_toggle.restype = ctypes.c_bool
r_config_toggle.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char)]
r_config_readonly = _libr_config.r_config_readonly
r_config_readonly.restype = ctypes.c_bool
r_config_readonly.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char)]
r_config_set_setter = _libr_config.r_config_set_setter
r_config_set_setter.restype = ctypes.c_bool
r_config_set_setter.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char), RConfigCallback]
r_config_set_getter = _libr_config.r_config_set_getter
r_config_set_getter.restype = ctypes.c_bool
r_config_set_getter.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char), RConfigCallback]
class struct_sdb_t(Structure):
    pass

class struct_ls_t(Structure):
    pass

class struct_sdb_gperf_t(Structure):
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

class struct_sdb_kv(Structure):
    pass

struct_sdb_kv._pack_ = 1 # source:False
struct_sdb_kv._fields_ = [
    ('base', struct_ht_pp_kv),
    ('cas', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('expire', ctypes.c_uint64),
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

r_config_serialize = _libr_config.r_config_serialize
r_config_serialize.restype = None
r_config_serialize.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(struct_sdb_t)]
r_config_unserialize = _libr_config.r_config_unserialize
r_config_unserialize.restype = ctypes.c_bool
r_config_unserialize.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
r_config_node_desc = _libr_config.r_config_node_desc
r_config_node_desc.restype = ctypes.POINTER(ctypes.c_char)
r_config_node_desc.argtypes = [ctypes.POINTER(struct_r_config_node_t), ctypes.POINTER(ctypes.c_char)]
r_config_node_to_string = _libr_config.r_config_node_to_string
r_config_node_to_string.restype = ctypes.POINTER(ctypes.c_char)
r_config_node_to_string.argtypes = [ctypes.POINTER(struct_r_config_node_t)]
r_config_node_add_option = _libr_config.r_config_node_add_option
r_config_node_add_option.restype = None
r_config_node_add_option.argtypes = [ctypes.POINTER(struct_r_config_node_t), ctypes.POINTER(ctypes.c_char)]
r_config_node_purge_options = _libr_config.r_config_node_purge_options
r_config_node_purge_options.restype = None
r_config_node_purge_options.argtypes = [ctypes.POINTER(struct_r_config_node_t)]
r_config_node_get = _libr_config.r_config_node_get
r_config_node_get.restype = ctypes.POINTER(struct_r_config_node_t)
r_config_node_get.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char)]
r_config_node_new = _libr_config.r_config_node_new
r_config_node_new.restype = ctypes.POINTER(struct_r_config_node_t)
r_config_node_new.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_config_node_free = _libr_config.r_config_node_free
r_config_node_free.restype = None
r_config_node_free.argtypes = [ctypes.POINTER(None)]
size_t = ctypes.c_uint64
r_config_node_value_format_i = _libr_config.r_config_node_value_format_i
r_config_node_value_format_i.restype = None
r_config_node_value_format_i.argtypes = [ctypes.POINTER(ctypes.c_char), size_t, ctypes.c_uint64, ctypes.POINTER(struct_r_config_node_t)]
r_config_node_is_bool = _libraries['FIXME_STUB'].r_config_node_is_bool
r_config_node_is_bool.restype = ctypes.c_bool
r_config_node_is_bool.argtypes = [ctypes.POINTER(struct_r_config_node_t)]
r_config_node_is_int = _libraries['FIXME_STUB'].r_config_node_is_int
r_config_node_is_int.restype = ctypes.c_bool
r_config_node_is_int.argtypes = [ctypes.POINTER(struct_r_config_node_t)]
r_config_node_is_ro = _libraries['FIXME_STUB'].r_config_node_is_ro
r_config_node_is_ro.restype = ctypes.c_bool
r_config_node_is_ro.argtypes = [ctypes.POINTER(struct_r_config_node_t)]
r_config_node_is_str = _libraries['FIXME_STUB'].r_config_node_is_str
r_config_node_is_str.restype = ctypes.c_bool
r_config_node_is_str.argtypes = [ctypes.POINTER(struct_r_config_node_t)]
__all__ = \
    ['RConfig', 'RConfigCallback', 'RConfigHold', 'RConfigNode',
    'RNCAND', 'RNCASSIGN', 'RNCDEC', 'RNCDIV', 'RNCEND', 'RNCINC',
    'RNCLEFTP', 'RNCMINUS', 'RNCMOD', 'RNCMUL', 'RNCNAME', 'RNCNEG',
    'RNCNUMBER', 'RNCOR', 'RNCPLUS', 'RNCPRINT', 'RNCRIGHTP',
    'RNCROL', 'RNCROR', 'RNCSHL', 'RNCSHR', 'RNCXOR',
    'c__EA_RNumCalcToken', 'r_config_bump', 'r_config_clone',
    'r_config_desc', 'r_config_eval', 'r_config_free', 'r_config_get',
    'r_config_get_b', 'r_config_get_i', 'r_config_hold',
    'r_config_hold_free', 'r_config_hold_new',
    'r_config_hold_restore', 'r_config_list', 'r_config_lock',
    'r_config_new', 'r_config_node_add_option', 'r_config_node_desc',
    'r_config_node_free', 'r_config_node_get',
    'r_config_node_is_bool', 'r_config_node_is_int',
    'r_config_node_is_ro', 'r_config_node_is_str',
    'r_config_node_new', 'r_config_node_purge_options',
    'r_config_node_to_string', 'r_config_node_type',
    'r_config_node_value_format_i', 'r_config_readonly',
    'r_config_rm', 'r_config_serialize', 'r_config_set',
    'r_config_set_b', 'r_config_set_cb', 'r_config_set_getter',
    'r_config_set_i', 'r_config_set_i_cb', 'r_config_set_setter',
    'r_config_toggle', 'r_config_unserialize', 'r_config_version',
    'size_t', 'struct_buffer', 'struct_c__SA_RNumCalcValue',
    'struct_c__SA_dict', 'struct_cdb', 'struct_cdb_hp',
    'struct_cdb_hplist', 'struct_cdb_make', 'struct_ht_pp_bucket_t',
    'struct_ht_pp_kv', 'struct_ht_pp_options_t', 'struct_ht_pp_t',
    'struct_ls_iter_t', 'struct_ls_t', 'struct_r_config_hold_t',
    'struct_r_config_node_t', 'struct_r_config_t',
    'struct_r_list_iter_t', 'struct_r_list_t', 'struct_r_num_calc_t',
    'struct_r_num_t', 'struct_sdb_gperf_t', 'struct_sdb_kv',
    'struct_sdb_t']
