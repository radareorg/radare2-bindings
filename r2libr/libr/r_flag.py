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


r_flag_version = _libr_flag.r_flag_version
r_flag_version.restype = ctypes.POINTER(ctypes.c_char)
r_flag_version.argtypes = []
class struct_r_flag_zone_item_t(Structure):
    pass

struct_r_flag_zone_item_t._pack_ = 1 # source:False
struct_r_flag_zone_item_t._fields_ = [
    ('from', ctypes.c_uint64),
    ('to', ctypes.c_uint64),
    ('name', ctypes.POINTER(ctypes.c_char)),
]

RFlagZoneItem = struct_r_flag_zone_item_t
class struct_r_flags_at_offset_t(Structure):
    pass

class struct_r_list_t(Structure):
    pass

struct_r_flags_at_offset_t._pack_ = 1 # source:False
struct_r_flags_at_offset_t._fields_ = [
    ('off', ctypes.c_uint64),
    ('flags', ctypes.POINTER(struct_r_list_t)),
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

RFlagsAtOffset = struct_r_flags_at_offset_t
class struct_r_flag_item_t(Structure):
    pass

class struct_r_space_t(Structure):
    pass

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

struct_r_space_t._pack_ = 1 # source:False
struct_r_space_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
]

RFlagItem = struct_r_flag_item_t
class struct_r_flag_t(Structure):
    pass

class struct_ht_pp_t(Structure):
    pass

class struct_r_num_t(Structure):
    pass

class struct_sdb_t(Structure):
    pass

class struct_r_skiplist_t(Structure):
    pass

class struct_r_spaces_t(Structure):
    pass

class struct_r_event_t(Structure):
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

class struct_ht_up_t(Structure):
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

RFlag = struct_r_flag_t
RFlagExistAt = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint16, ctypes.c_uint64)
RFlagGet = ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_flag_item_t), ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char))
RFlagGetAtAddr = ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_flag_item_t), ctypes.POINTER(struct_r_flag_t), ctypes.c_uint64)
RFlagGetAt = ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_flag_item_t), ctypes.POINTER(struct_r_flag_t), ctypes.c_uint64, ctypes.c_bool)
RFlagGetList = ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_flag_t), ctypes.c_uint64)
RFlagSet = ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_flag_item_t), ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64, ctypes.c_uint32)
RFlagUnset = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(struct_r_flag_item_t))
RFlagUnsetName = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char))
RFlagUnsetOff = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_flag_t), ctypes.c_uint64)
RFlagSetSpace = ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_space_t), ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char))
RFlagPopSpace = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_flag_t))
RFlagPushSpace = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char))
RFlagItemCb = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_flag_item_t), ctypes.POINTER(None))
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

RFlagBind = struct_r_flag_bind_t
r_flag_bind = _libr_flag.r_flag_bind
r_flag_bind.restype = None
r_flag_bind.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(struct_r_flag_bind_t)]
r_flag_new = _libr_flag.r_flag_new
r_flag_new.restype = ctypes.POINTER(struct_r_flag_t)
r_flag_new.argtypes = []
r_flag_free = _libr_flag.r_flag_free
r_flag_free.restype = ctypes.POINTER(struct_r_flag_t)
r_flag_free.argtypes = [ctypes.POINTER(struct_r_flag_t)]
r_flag_list = _libr_flag.r_flag_list
r_flag_list.restype = None
r_flag_list.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
r_flag_exist_at = _libr_flag.r_flag_exist_at
r_flag_exist_at.restype = ctypes.c_bool
r_flag_exist_at.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint16, ctypes.c_uint64]
r_flag_get = _libr_flag.r_flag_get
r_flag_get.restype = ctypes.POINTER(struct_r_flag_item_t)
r_flag_get.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char)]
r_flag_get_i = _libr_flag.r_flag_get_i
r_flag_get_i.restype = ctypes.POINTER(struct_r_flag_item_t)
r_flag_get_i.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.c_uint64]
r_flag_get_by_spaces = _libr_flag.r_flag_get_by_spaces
r_flag_get_by_spaces.restype = ctypes.POINTER(struct_r_flag_item_t)
r_flag_get_by_spaces.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.c_uint64]
r_flag_get_at = _libr_flag.r_flag_get_at
r_flag_get_at.restype = ctypes.POINTER(struct_r_flag_item_t)
r_flag_get_at.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.c_uint64, ctypes.c_bool]
r_flag_all_list = _libr_flag.r_flag_all_list
r_flag_all_list.restype = ctypes.POINTER(struct_r_list_t)
r_flag_all_list.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.c_bool]
r_flag_get_list = _libr_flag.r_flag_get_list
r_flag_get_list.restype = ctypes.POINTER(struct_r_list_t)
r_flag_get_list.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.c_uint64]
r_flag_get_liststr = _libr_flag.r_flag_get_liststr
r_flag_get_liststr.restype = ctypes.POINTER(ctypes.c_char)
r_flag_get_liststr.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.c_uint64]
r_flag_unset = _libr_flag.r_flag_unset
r_flag_unset.restype = ctypes.c_bool
r_flag_unset.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(struct_r_flag_item_t)]
r_flag_unset_name = _libr_flag.r_flag_unset_name
r_flag_unset_name.restype = ctypes.c_bool
r_flag_unset_name.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char)]
r_flag_item_set_type = _libr_flag.r_flag_item_set_type
r_flag_item_set_type.restype = None
r_flag_item_set_type.argtypes = [ctypes.POINTER(struct_r_flag_item_t), ctypes.POINTER(ctypes.c_char)]
r_flag_unset_off = _libr_flag.r_flag_unset_off
r_flag_unset_off.restype = ctypes.c_bool
r_flag_unset_off.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.c_uint64]
r_flag_unset_all = _libr_flag.r_flag_unset_all
r_flag_unset_all.restype = None
r_flag_unset_all.argtypes = [ctypes.POINTER(struct_r_flag_t)]
r_flag_set = _libr_flag.r_flag_set
r_flag_set.restype = ctypes.POINTER(struct_r_flag_item_t)
r_flag_set.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64, ctypes.c_uint32]
r_flag_set_inspace = _libr_flag.r_flag_set_inspace
r_flag_set_inspace.restype = ctypes.POINTER(struct_r_flag_item_t)
r_flag_set_inspace.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64, ctypes.c_uint32]
r_flag_set_next = _libr_flag.r_flag_set_next
r_flag_set_next.restype = ctypes.POINTER(struct_r_flag_item_t)
r_flag_set_next.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64, ctypes.c_uint32]
r_flag_item_set_alias = _libr_flag.r_flag_item_set_alias
r_flag_item_set_alias.restype = None
r_flag_item_set_alias.argtypes = [ctypes.POINTER(struct_r_flag_item_t), ctypes.POINTER(ctypes.c_char)]
r_flag_item_free = _libr_flag.r_flag_item_free
r_flag_item_free.restype = None
r_flag_item_free.argtypes = [ctypes.POINTER(struct_r_flag_item_t)]
r_flag_item_set_comment = _libr_flag.r_flag_item_set_comment
r_flag_item_set_comment.restype = None
r_flag_item_set_comment.argtypes = [ctypes.POINTER(struct_r_flag_item_t), ctypes.POINTER(ctypes.c_char)]
r_flag_item_set_realname = _libr_flag.r_flag_item_set_realname
r_flag_item_set_realname.restype = None
r_flag_item_set_realname.argtypes = [ctypes.POINTER(struct_r_flag_item_t), ctypes.POINTER(ctypes.c_char)]
r_flag_item_set_color = _libr_flag.r_flag_item_set_color
r_flag_item_set_color.restype = ctypes.POINTER(ctypes.c_char)
r_flag_item_set_color.argtypes = [ctypes.POINTER(struct_r_flag_item_t), ctypes.POINTER(ctypes.c_char)]
r_flag_item_clone = _libr_flag.r_flag_item_clone
r_flag_item_clone.restype = ctypes.POINTER(struct_r_flag_item_t)
r_flag_item_clone.argtypes = [ctypes.POINTER(struct_r_flag_item_t)]
r_flag_unset_glob = _libr_flag.r_flag_unset_glob
r_flag_unset_glob.restype = ctypes.c_int32
r_flag_unset_glob.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char)]
r_flag_rename = _libr_flag.r_flag_rename
r_flag_rename.restype = ctypes.c_int32
r_flag_rename.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(struct_r_flag_item_t), ctypes.POINTER(ctypes.c_char)]
r_flag_relocate = _libr_flag.r_flag_relocate
r_flag_relocate.restype = ctypes.c_int32
r_flag_relocate.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64]
r_flag_move = _libr_flag.r_flag_move
r_flag_move.restype = ctypes.c_bool
r_flag_move.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.c_uint64, ctypes.c_uint64]
r_flag_count = _libr_flag.r_flag_count
r_flag_count.restype = ctypes.c_int32
r_flag_count.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char)]
r_flag_foreach = _libr_flag.r_flag_foreach
r_flag_foreach.restype = None
r_flag_foreach.argtypes = [ctypes.POINTER(struct_r_flag_t), RFlagItemCb, ctypes.POINTER(None)]
r_flag_foreach_prefix = _libr_flag.r_flag_foreach_prefix
r_flag_foreach_prefix.restype = None
r_flag_foreach_prefix.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, RFlagItemCb, ctypes.POINTER(None)]
r_flag_foreach_range = _libr_flag.r_flag_foreach_range
r_flag_foreach_range.restype = None
r_flag_foreach_range.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.c_uint64, ctypes.c_uint64, RFlagItemCb, ctypes.POINTER(None)]
r_flag_foreach_glob = _libr_flag.r_flag_foreach_glob
r_flag_foreach_glob.restype = None
r_flag_foreach_glob.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char), RFlagItemCb, ctypes.POINTER(None)]
r_flag_foreach_space = _libr_flag.r_flag_foreach_space
r_flag_foreach_space.restype = None
r_flag_foreach_space.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(struct_r_space_t), RFlagItemCb, ctypes.POINTER(None)]
r_flag_foreach_space_glob = _libr_flag.r_flag_foreach_space_glob
r_flag_foreach_space_glob.restype = None
r_flag_foreach_space_glob.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_space_t), RFlagItemCb, ctypes.POINTER(None)]
r_flag_space_get = _libraries['FIXME_STUB'].r_flag_space_get
r_flag_space_get.restype = ctypes.POINTER(struct_r_space_t)
r_flag_space_get.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char)]
r_flag_space_cur = _libraries['FIXME_STUB'].r_flag_space_cur
r_flag_space_cur.restype = ctypes.POINTER(struct_r_space_t)
r_flag_space_cur.argtypes = [ctypes.POINTER(struct_r_flag_t)]
r_flag_space_cur_name = _libraries['FIXME_STUB'].r_flag_space_cur_name
r_flag_space_cur_name.restype = ctypes.POINTER(ctypes.c_char)
r_flag_space_cur_name.argtypes = [ctypes.POINTER(struct_r_flag_t)]
r_flag_space_set = _libraries['FIXME_STUB'].r_flag_space_set
r_flag_space_set.restype = ctypes.POINTER(struct_r_space_t)
r_flag_space_set.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char)]
r_flag_space_unset = _libraries['FIXME_STUB'].r_flag_space_unset
r_flag_space_unset.restype = ctypes.c_bool
r_flag_space_unset.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char)]
r_flag_space_rename = _libraries['FIXME_STUB'].r_flag_space_rename
r_flag_space_rename.restype = ctypes.c_bool
r_flag_space_rename.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_flag_space_push = _libraries['FIXME_STUB'].r_flag_space_push
r_flag_space_push.restype = ctypes.c_bool
r_flag_space_push.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char)]
r_flag_space_pop = _libraries['FIXME_STUB'].r_flag_space_pop
r_flag_space_pop.restype = ctypes.c_bool
r_flag_space_pop.argtypes = [ctypes.POINTER(struct_r_flag_t)]
r_flag_space_count = _libraries['FIXME_STUB'].r_flag_space_count
r_flag_space_count.restype = ctypes.c_int32
r_flag_space_count.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char)]
r_flag_space_is_empty = _libraries['FIXME_STUB'].r_flag_space_is_empty
r_flag_space_is_empty.restype = ctypes.c_bool
r_flag_space_is_empty.argtypes = [ctypes.POINTER(struct_r_flag_t)]
r_flag_tags_list = _libr_flag.r_flag_tags_list
r_flag_tags_list.restype = ctypes.POINTER(struct_r_list_t)
r_flag_tags_list.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char)]
r_flag_tags_set = _libr_flag.r_flag_tags_set
r_flag_tags_set.restype = ctypes.POINTER(struct_r_list_t)
r_flag_tags_set.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_flag_tags_reset = _libr_flag.r_flag_tags_reset
r_flag_tags_reset.restype = None
r_flag_tags_reset.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char)]
r_flag_tags_get = _libr_flag.r_flag_tags_get
r_flag_tags_get.restype = ctypes.POINTER(struct_r_list_t)
r_flag_tags_get.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char)]
r_flag_zone_item_free = _libr_flag.r_flag_zone_item_free
r_flag_zone_item_free.restype = None
r_flag_zone_item_free.argtypes = [ctypes.POINTER(None)]
r_flag_zone_add = _libr_flag.r_flag_zone_add
r_flag_zone_add.restype = ctypes.c_bool
r_flag_zone_add.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64]
r_flag_zone_del = _libr_flag.r_flag_zone_del
r_flag_zone_del.restype = ctypes.c_bool
r_flag_zone_del.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(ctypes.c_char)]
r_flag_zone_around = _libr_flag.r_flag_zone_around
r_flag_zone_around.restype = ctypes.c_bool
r_flag_zone_around.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.c_uint64, ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
r_flag_zone_list = _libr_flag.r_flag_zone_list
r_flag_zone_list.restype = ctypes.c_bool
r_flag_zone_list.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.c_int32]
r_flag_zone_reset = _libr_flag.r_flag_zone_reset
r_flag_zone_reset.restype = ctypes.c_bool
r_flag_zone_reset.argtypes = [ctypes.POINTER(struct_r_flag_t)]
r_flag_zone_barlist = _libr_flag.r_flag_zone_barlist
r_flag_zone_barlist.restype = ctypes.POINTER(struct_r_list_t)
r_flag_zone_barlist.argtypes = [ctypes.POINTER(struct_r_flag_t), ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int32]
__all__ = \
    ['RFlag', 'RFlagBind', 'RFlagExistAt', 'RFlagGet', 'RFlagGetAt',
    'RFlagGetAtAddr', 'RFlagGetList', 'RFlagItem', 'RFlagItemCb',
    'RFlagPopSpace', 'RFlagPushSpace', 'RFlagSet', 'RFlagSetSpace',
    'RFlagUnset', 'RFlagUnsetName', 'RFlagUnsetOff', 'RFlagZoneItem',
    'RFlagsAtOffset', 'RNCAND', 'RNCASSIGN', 'RNCDEC', 'RNCDIV',
    'RNCEND', 'RNCGT', 'RNCINC', 'RNCLEFTP', 'RNCLT', 'RNCMINUS',
    'RNCMOD', 'RNCMUL', 'RNCNAME', 'RNCNEG', 'RNCNUMBER', 'RNCOR',
    'RNCPLUS', 'RNCPRINT', 'RNCRIGHTP', 'RNCROL', 'RNCROR', 'RNCSHL',
    'RNCSHR', 'RNCXOR', 'c__EA_RNumCalcToken', 'r_flag_all_list',
    'r_flag_bind', 'r_flag_count', 'r_flag_exist_at',
    'r_flag_foreach', 'r_flag_foreach_glob', 'r_flag_foreach_prefix',
    'r_flag_foreach_range', 'r_flag_foreach_space',
    'r_flag_foreach_space_glob', 'r_flag_free', 'r_flag_get',
    'r_flag_get_at', 'r_flag_get_by_spaces', 'r_flag_get_i',
    'r_flag_get_list', 'r_flag_get_liststr', 'r_flag_item_clone',
    'r_flag_item_free', 'r_flag_item_set_alias',
    'r_flag_item_set_color', 'r_flag_item_set_comment',
    'r_flag_item_set_realname', 'r_flag_item_set_type', 'r_flag_list',
    'r_flag_move', 'r_flag_new', 'r_flag_relocate', 'r_flag_rename',
    'r_flag_set', 'r_flag_set_inspace', 'r_flag_set_next',
    'r_flag_space_count', 'r_flag_space_cur', 'r_flag_space_cur_name',
    'r_flag_space_get', 'r_flag_space_is_empty', 'r_flag_space_pop',
    'r_flag_space_push', 'r_flag_space_rename', 'r_flag_space_set',
    'r_flag_space_unset', 'r_flag_tags_get', 'r_flag_tags_list',
    'r_flag_tags_reset', 'r_flag_tags_set', 'r_flag_unset',
    'r_flag_unset_all', 'r_flag_unset_glob', 'r_flag_unset_name',
    'r_flag_unset_off', 'r_flag_version', 'r_flag_zone_add',
    'r_flag_zone_around', 'r_flag_zone_barlist', 'r_flag_zone_del',
    'r_flag_zone_item_free', 'r_flag_zone_list', 'r_flag_zone_reset',
    'struct_buffer', 'struct_c__SA_RNumCalcValue',
    'struct_c__SA_dict', 'struct_cdb', 'struct_cdb_hp',
    'struct_cdb_hplist', 'struct_cdb_make', 'struct_ht_pp_bucket_t',
    'struct_ht_pp_kv', 'struct_ht_pp_options_t', 'struct_ht_pp_t',
    'struct_ht_up_bucket_t', 'struct_ht_up_kv',
    'struct_ht_up_options_t', 'struct_ht_up_t', 'struct_ls_iter_t',
    'struct_ls_t', 'struct_r_crbtree_node', 'struct_r_crbtree_t',
    'struct_r_event_t', 'struct_r_flag_bind_t',
    'struct_r_flag_item_t', 'struct_r_flag_t',
    'struct_r_flag_zone_item_t', 'struct_r_flags_at_offset_t',
    'struct_r_list_iter_t', 'struct_r_list_t', 'struct_r_num_calc_t',
    'struct_r_num_t', 'struct_r_skiplist_node_t',
    'struct_r_skiplist_t', 'struct_r_space_t', 'struct_r_spaces_t',
    'struct_r_vector_t', 'struct_sdb_gperf_t', 'struct_sdb_kv',
    'struct_sdb_t']
