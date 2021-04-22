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



r_reg_version = _libr_reg.r_reg_version
r_reg_version.restype = ctypes.POINTER(ctypes.c_char)
r_reg_version.argtypes = []

# values for enumeration 'c__EA_RRegisterType'
c__EA_RRegisterType__enumvalues = {
    0: 'R_REG_TYPE_GPR',
    1: 'R_REG_TYPE_DRX',
    2: 'R_REG_TYPE_FPU',
    3: 'R_REG_TYPE_MMX',
    4: 'R_REG_TYPE_XMM',
    5: 'R_REG_TYPE_YMM',
    6: 'R_REG_TYPE_FLG',
    7: 'R_REG_TYPE_SEG',
    8: 'R_REG_TYPE_LAST',
    -1: 'R_REG_TYPE_ALL',
}
R_REG_TYPE_GPR = 0
R_REG_TYPE_DRX = 1
R_REG_TYPE_FPU = 2
R_REG_TYPE_MMX = 3
R_REG_TYPE_XMM = 4
R_REG_TYPE_YMM = 5
R_REG_TYPE_FLG = 6
R_REG_TYPE_SEG = 7
R_REG_TYPE_LAST = 8
R_REG_TYPE_ALL = -1
c__EA_RRegisterType = ctypes.c_int32 # enum
RRegisterType = c__EA_RRegisterType
RRegisterType__enumvalues = c__EA_RRegisterType__enumvalues

# values for enumeration 'c__EA_RRegisterId'
c__EA_RRegisterId__enumvalues = {
    0: 'R_REG_NAME_PC',
    1: 'R_REG_NAME_SP',
    2: 'R_REG_NAME_SR',
    3: 'R_REG_NAME_BP',
    4: 'R_REG_NAME_LR',
    5: 'R_REG_NAME_RS',
    6: 'R_REG_NAME_A0',
    7: 'R_REG_NAME_A1',
    8: 'R_REG_NAME_A2',
    9: 'R_REG_NAME_A3',
    10: 'R_REG_NAME_A4',
    11: 'R_REG_NAME_A5',
    12: 'R_REG_NAME_A6',
    13: 'R_REG_NAME_A7',
    14: 'R_REG_NAME_A8',
    15: 'R_REG_NAME_A9',
    16: 'R_REG_NAME_R0',
    17: 'R_REG_NAME_R1',
    18: 'R_REG_NAME_R2',
    19: 'R_REG_NAME_R3',
    20: 'R_REG_NAME_ZF',
    21: 'R_REG_NAME_SF',
    22: 'R_REG_NAME_CF',
    23: 'R_REG_NAME_OF',
    24: 'R_REG_NAME_SN',
    25: 'R_REG_NAME_LAST',
}
R_REG_NAME_PC = 0
R_REG_NAME_SP = 1
R_REG_NAME_SR = 2
R_REG_NAME_BP = 3
R_REG_NAME_LR = 4
R_REG_NAME_RS = 5
R_REG_NAME_A0 = 6
R_REG_NAME_A1 = 7
R_REG_NAME_A2 = 8
R_REG_NAME_A3 = 9
R_REG_NAME_A4 = 10
R_REG_NAME_A5 = 11
R_REG_NAME_A6 = 12
R_REG_NAME_A7 = 13
R_REG_NAME_A8 = 14
R_REG_NAME_A9 = 15
R_REG_NAME_R0 = 16
R_REG_NAME_R1 = 17
R_REG_NAME_R2 = 18
R_REG_NAME_R3 = 19
R_REG_NAME_ZF = 20
R_REG_NAME_SF = 21
R_REG_NAME_CF = 22
R_REG_NAME_OF = 23
R_REG_NAME_SN = 24
R_REG_NAME_LAST = 25
c__EA_RRegisterId = ctypes.c_uint32 # enum
RRegisterId = c__EA_RRegisterId
RRegisterId__enumvalues = c__EA_RRegisterId__enumvalues
class struct_r_reg_item_t(Structure):
    pass

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

RRegItem = struct_r_reg_item_t
class struct_r_reg_arena_t(Structure):
    pass

struct_r_reg_arena_t._pack_ = 1 # source:False
struct_r_reg_arena_t._fields_ = [
    ('bytes', ctypes.POINTER(ctypes.c_ubyte)),
    ('size', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

RRegArena = struct_r_reg_arena_t
class struct_r_reg_set_t(Structure):
    pass

class struct_ht_pp_t(Structure):
    pass

class struct_r_list_iter_t(Structure):
    pass

class struct_r_list_t(Structure):
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

RRegSet = struct_r_reg_set_t
class struct_r_reg_t(Structure):
    pass

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

RReg = struct_r_reg_t
class struct_r_reg_flags_t(Structure):
    pass

struct_r_reg_flags_t._pack_ = 1 # source:False
struct_r_reg_flags_t._fields_ = [
    ('s', ctypes.c_bool),
    ('z', ctypes.c_bool),
    ('a', ctypes.c_bool),
    ('c', ctypes.c_bool),
    ('o', ctypes.c_bool),
    ('p', ctypes.c_bool),
]

RRegFlags = struct_r_reg_flags_t
r_reg_free = _libr_reg.r_reg_free
r_reg_free.restype = None
r_reg_free.argtypes = [ctypes.POINTER(struct_r_reg_t)]
r_reg_free_internal = _libr_reg.r_reg_free_internal
r_reg_free_internal.restype = None
r_reg_free_internal.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.c_bool]
r_reg_new = _libr_reg.r_reg_new
r_reg_new.restype = ctypes.POINTER(struct_r_reg_t)
r_reg_new.argtypes = []
r_reg_init = _libr_reg.r_reg_init
r_reg_init.restype = ctypes.POINTER(struct_r_reg_t)
r_reg_init.argtypes = [ctypes.POINTER(struct_r_reg_t)]
r_reg_set_name = _libr_reg.r_reg_set_name
r_reg_set_name.restype = ctypes.c_bool
r_reg_set_name.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
r_reg_set_profile_string = _libr_reg.r_reg_set_profile_string
r_reg_set_profile_string.restype = ctypes.c_bool
r_reg_set_profile_string.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(ctypes.c_char)]
r_reg_profile_to_cc = _libr_reg.r_reg_profile_to_cc
r_reg_profile_to_cc.restype = ctypes.POINTER(ctypes.c_char)
r_reg_profile_to_cc.argtypes = [ctypes.POINTER(struct_r_reg_t)]
r_reg_set_profile = _libr_reg.r_reg_set_profile
r_reg_set_profile.restype = ctypes.c_bool
r_reg_set_profile.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(ctypes.c_char)]
r_reg_parse_gdb_profile = _libr_reg.r_reg_parse_gdb_profile
r_reg_parse_gdb_profile.restype = ctypes.POINTER(ctypes.c_char)
r_reg_parse_gdb_profile.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_reg_is_readonly = _libr_reg.r_reg_is_readonly
r_reg_is_readonly.restype = ctypes.c_bool
r_reg_is_readonly.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(struct_r_reg_item_t)]
r_reg_regset_get = _libr_reg.r_reg_regset_get
r_reg_regset_get.restype = ctypes.POINTER(struct_r_reg_set_t)
r_reg_regset_get.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.c_int32]
r_reg_getv = _libr_reg.r_reg_getv
r_reg_getv.restype = ctypes.c_uint64
r_reg_getv.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(ctypes.c_char)]
r_reg_setv = _libr_reg.r_reg_setv
r_reg_setv.restype = ctypes.c_uint64
r_reg_setv.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64]
r_reg_32_to_64 = _libr_reg.r_reg_32_to_64
r_reg_32_to_64.restype = ctypes.POINTER(ctypes.c_char)
r_reg_32_to_64.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(ctypes.c_char)]
r_reg_64_to_32 = _libr_reg.r_reg_64_to_32
r_reg_64_to_32.restype = ctypes.POINTER(ctypes.c_char)
r_reg_64_to_32.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(ctypes.c_char)]
r_reg_get_name_by_type = _libr_reg.r_reg_get_name_by_type
r_reg_get_name_by_type.restype = ctypes.POINTER(ctypes.c_char)
r_reg_get_name_by_type.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(ctypes.c_char)]
r_reg_get_type = _libr_reg.r_reg_get_type
r_reg_get_type.restype = ctypes.POINTER(ctypes.c_char)
r_reg_get_type.argtypes = [ctypes.c_int32]
r_reg_get_name = _libr_reg.r_reg_get_name
r_reg_get_name.restype = ctypes.POINTER(ctypes.c_char)
r_reg_get_name.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.c_int32]
r_reg_get_role = _libr_reg.r_reg_get_role
r_reg_get_role.restype = ctypes.POINTER(ctypes.c_char)
r_reg_get_role.argtypes = [ctypes.c_int32]
r_reg_get = _libr_reg.r_reg_get
r_reg_get.restype = ctypes.POINTER(struct_r_reg_item_t)
r_reg_get.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_reg_get_list = _libr_reg.r_reg_get_list
r_reg_get_list.restype = ctypes.POINTER(struct_r_list_t)
r_reg_get_list.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.c_int32]
r_reg_get_at = _libr_reg.r_reg_get_at
r_reg_get_at.restype = ctypes.POINTER(struct_r_reg_item_t)
r_reg_get_at.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
r_reg_next_diff = _libr_reg.r_reg_next_diff
r_reg_next_diff.restype = ctypes.POINTER(struct_r_reg_item_t)
r_reg_next_diff.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(struct_r_reg_item_t), ctypes.c_int32]
r_reg_reindex = _libr_reg.r_reg_reindex
r_reg_reindex.restype = None
r_reg_reindex.argtypes = [ctypes.POINTER(struct_r_reg_t)]
r_reg_index_get = _libr_reg.r_reg_index_get
r_reg_index_get.restype = ctypes.POINTER(struct_r_reg_item_t)
r_reg_index_get.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.c_int32]
r_reg_item_free = _libr_reg.r_reg_item_free
r_reg_item_free.restype = None
r_reg_item_free.argtypes = [ctypes.POINTER(struct_r_reg_item_t)]
r_reg_type_by_name = _libr_reg.r_reg_type_by_name
r_reg_type_by_name.restype = ctypes.c_int32
r_reg_type_by_name.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_reg_get_name_idx = _libr_reg.r_reg_get_name_idx
r_reg_get_name_idx.restype = ctypes.c_int32
r_reg_get_name_idx.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_reg_cond_get = _libr_reg.r_reg_cond_get
r_reg_cond_get.restype = ctypes.POINTER(struct_r_reg_item_t)
r_reg_cond_get.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(ctypes.c_char)]
r_reg_cond_apply = _libr_reg.r_reg_cond_apply
r_reg_cond_apply.restype = None
r_reg_cond_apply.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(struct_r_reg_flags_t)]
r_reg_cond_set = _libr_reg.r_reg_cond_set
r_reg_cond_set.restype = ctypes.c_bool
r_reg_cond_set.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(ctypes.c_char), ctypes.c_bool]
r_reg_cond_get_value = _libr_reg.r_reg_cond_get_value
r_reg_cond_get_value.restype = ctypes.c_bool
r_reg_cond_get_value.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(ctypes.c_char)]
r_reg_cond_bits_set = _libr_reg.r_reg_cond_bits_set
r_reg_cond_bits_set.restype = ctypes.c_bool
r_reg_cond_bits_set.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.c_int32, ctypes.POINTER(struct_r_reg_flags_t), ctypes.c_bool]
r_reg_cond_bits = _libr_reg.r_reg_cond_bits
r_reg_cond_bits.restype = ctypes.c_int32
r_reg_cond_bits.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.c_int32, ctypes.POINTER(struct_r_reg_flags_t)]
r_reg_cond_retrieve = _libr_reg.r_reg_cond_retrieve
r_reg_cond_retrieve.restype = ctypes.POINTER(struct_r_reg_flags_t)
r_reg_cond_retrieve.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(struct_r_reg_flags_t)]
r_reg_cond = _libr_reg.r_reg_cond
r_reg_cond.restype = ctypes.c_int32
r_reg_cond.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.c_int32]
r_reg_get_value = _libr_reg.r_reg_get_value
r_reg_get_value.restype = ctypes.c_uint64
r_reg_get_value.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(struct_r_reg_item_t)]
class struct__utX(Structure):
    pass

class struct__ut128(Structure):
    pass

struct__ut128._pack_ = 1 # source:False
struct__ut128._fields_ = [
    ('Low', ctypes.c_uint64),
    ('High', ctypes.c_int64),
]

class struct__ut96(Structure):
    pass

struct__ut96._pack_ = 1 # source:False
struct__ut96._fields_ = [
    ('Low', ctypes.c_uint64),
    ('High', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

class struct__ut80(Structure):
    pass

struct__ut80._pack_ = 1 # source:False
struct__ut80._fields_ = [
    ('Low', ctypes.c_uint64),
    ('High', ctypes.c_uint16),
    ('PADDING_0', ctypes.c_ubyte * 6),
]

class struct__ut256(Structure):
    _pack_ = 1 # source:False
    _fields_ = [
    ('Low', struct__ut128),
    ('High', struct__ut128),
     ]

struct__utX._pack_ = 1 # source:False
struct__utX._fields_ = [
    ('v80', struct__ut80),
    ('v96', struct__ut96),
    ('v128', struct__ut128),
    ('v256', struct__ut256),
]

r_reg_get_value_big = _libr_reg.r_reg_get_value_big
r_reg_get_value_big.restype = ctypes.c_uint64
r_reg_get_value_big.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(struct_r_reg_item_t), ctypes.POINTER(struct__utX)]
r_reg_get_value_by_role = _libr_reg.r_reg_get_value_by_role
r_reg_get_value_by_role.restype = ctypes.c_uint64
r_reg_get_value_by_role.argtypes = [ctypes.POINTER(struct_r_reg_t), RRegisterId]
r_reg_set_value = _libr_reg.r_reg_set_value
r_reg_set_value.restype = ctypes.c_bool
r_reg_set_value.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(struct_r_reg_item_t), ctypes.c_uint64]
r_reg_set_value_by_role = _libr_reg.r_reg_set_value_by_role
r_reg_set_value_by_role.restype = ctypes.c_bool
r_reg_set_value_by_role.argtypes = [ctypes.POINTER(struct_r_reg_t), RRegisterId, ctypes.c_uint64]
r_reg_get_float = _libr_reg.r_reg_get_float
r_reg_get_float.restype = ctypes.c_float
r_reg_get_float.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(struct_r_reg_item_t)]
r_reg_set_float = _libr_reg.r_reg_set_float
r_reg_set_float.restype = ctypes.c_bool
r_reg_set_float.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(struct_r_reg_item_t), ctypes.c_float]
r_reg_get_double = _libr_reg.r_reg_get_double
r_reg_get_double.restype = ctypes.c_double
r_reg_get_double.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(struct_r_reg_item_t)]
r_reg_set_double = _libr_reg.r_reg_set_double
r_reg_set_double.restype = ctypes.c_bool
r_reg_set_double.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(struct_r_reg_item_t), ctypes.c_double]
r_reg_get_longdouble = _libr_reg.r_reg_get_longdouble
r_reg_get_longdouble.restype = c_long_double_t
r_reg_get_longdouble.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(struct_r_reg_item_t)]
r_reg_set_longdouble = _libr_reg.r_reg_set_longdouble
r_reg_set_longdouble.restype = ctypes.c_bool
r_reg_set_longdouble.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(struct_r_reg_item_t), c_long_double_t]
r_reg_get_bvalue = _libr_reg.r_reg_get_bvalue
r_reg_get_bvalue.restype = ctypes.POINTER(ctypes.c_char)
r_reg_get_bvalue.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(struct_r_reg_item_t)]
r_reg_set_bvalue = _libr_reg.r_reg_set_bvalue
r_reg_set_bvalue.restype = ctypes.c_uint64
r_reg_set_bvalue.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(struct_r_reg_item_t), ctypes.POINTER(ctypes.c_char)]
r_reg_set_pack = _libr_reg.r_reg_set_pack
r_reg_set_pack.restype = ctypes.c_int32
r_reg_set_pack.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(struct_r_reg_item_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_uint64]
r_reg_get_pack = _libr_reg.r_reg_get_pack
r_reg_get_pack.restype = ctypes.c_uint64
r_reg_get_pack.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(struct_r_reg_item_t), ctypes.c_int32, ctypes.c_int32]
r_reg_default_bits = _libr_reg.r_reg_default_bits
r_reg_default_bits.restype = ctypes.c_int32
r_reg_default_bits.argtypes = [ctypes.POINTER(struct_r_reg_t)]
r_reg_get_bytes = _libr_reg.r_reg_get_bytes
r_reg_get_bytes.restype = ctypes.POINTER(ctypes.c_ubyte)
r_reg_get_bytes.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.c_int32, ctypes.POINTER(ctypes.c_int32)]
r_reg_set_bytes = _libr_reg.r_reg_set_bytes
r_reg_set_bytes.restype = ctypes.c_bool
r_reg_set_bytes.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_reg_read_regs = _libr_reg.r_reg_read_regs
r_reg_read_regs.restype = ctypes.c_bool
r_reg_read_regs.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_reg_arena_set_bytes = _libr_reg.r_reg_arena_set_bytes
r_reg_arena_set_bytes.restype = ctypes.c_int32
r_reg_arena_set_bytes.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(ctypes.c_char)]
r_reg_arena_new = _libr_reg.r_reg_arena_new
r_reg_arena_new.restype = ctypes.POINTER(struct_r_reg_arena_t)
r_reg_arena_new.argtypes = [ctypes.c_int32]
r_reg_arena_free = _libr_reg.r_reg_arena_free
r_reg_arena_free.restype = None
r_reg_arena_free.argtypes = [ctypes.POINTER(struct_r_reg_arena_t)]
r_reg_fit_arena = _libr_reg.r_reg_fit_arena
r_reg_fit_arena.restype = ctypes.c_int32
r_reg_fit_arena.argtypes = [ctypes.POINTER(struct_r_reg_t)]
r_reg_arena_swap = _libr_reg.r_reg_arena_swap
r_reg_arena_swap.restype = None
r_reg_arena_swap.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.c_int32]
r_reg_arena_push = _libr_reg.r_reg_arena_push
r_reg_arena_push.restype = ctypes.c_int32
r_reg_arena_push.argtypes = [ctypes.POINTER(struct_r_reg_t)]
r_reg_arena_pop = _libr_reg.r_reg_arena_pop
r_reg_arena_pop.restype = None
r_reg_arena_pop.argtypes = [ctypes.POINTER(struct_r_reg_t)]
r_reg_arena_zero = _libr_reg.r_reg_arena_zero
r_reg_arena_zero.restype = None
r_reg_arena_zero.argtypes = [ctypes.POINTER(struct_r_reg_t)]
r_reg_arena_peek = _libr_reg.r_reg_arena_peek
r_reg_arena_peek.restype = ctypes.POINTER(ctypes.c_ubyte)
r_reg_arena_peek.argtypes = [ctypes.POINTER(struct_r_reg_t)]
r_reg_arena_poke = _libr_reg.r_reg_arena_poke
r_reg_arena_poke.restype = None
r_reg_arena_poke.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(ctypes.c_ubyte)]
r_reg_arena_dup = _libr_reg.r_reg_arena_dup
r_reg_arena_dup.restype = ctypes.POINTER(ctypes.c_ubyte)
r_reg_arena_dup.argtypes = [ctypes.POINTER(struct_r_reg_t), ctypes.POINTER(ctypes.c_ubyte)]
r_reg_cond_to_string = _libr_reg.r_reg_cond_to_string
r_reg_cond_to_string.restype = ctypes.POINTER(ctypes.c_char)
r_reg_cond_to_string.argtypes = [ctypes.c_int32]
r_reg_cond_from_string = _libr_reg.r_reg_cond_from_string
r_reg_cond_from_string.restype = ctypes.c_int32
r_reg_cond_from_string.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_reg_arena_shrink = _libr_reg.r_reg_arena_shrink
r_reg_arena_shrink.restype = None
r_reg_arena_shrink.argtypes = [ctypes.POINTER(struct_r_reg_t)]
__all__ = \
    ['RReg', 'RRegArena', 'RRegFlags', 'RRegItem', 'RRegSet',
    'RRegisterId', 'RRegisterId__enumvalues', 'RRegisterType',
    'RRegisterType__enumvalues', 'R_REG_NAME_A0', 'R_REG_NAME_A1',
    'R_REG_NAME_A2', 'R_REG_NAME_A3', 'R_REG_NAME_A4',
    'R_REG_NAME_A5', 'R_REG_NAME_A6', 'R_REG_NAME_A7',
    'R_REG_NAME_A8', 'R_REG_NAME_A9', 'R_REG_NAME_BP',
    'R_REG_NAME_CF', 'R_REG_NAME_LAST', 'R_REG_NAME_LR',
    'R_REG_NAME_OF', 'R_REG_NAME_PC', 'R_REG_NAME_R0',
    'R_REG_NAME_R1', 'R_REG_NAME_R2', 'R_REG_NAME_R3',
    'R_REG_NAME_RS', 'R_REG_NAME_SF', 'R_REG_NAME_SN',
    'R_REG_NAME_SP', 'R_REG_NAME_SR', 'R_REG_NAME_ZF',
    'R_REG_TYPE_ALL', 'R_REG_TYPE_DRX', 'R_REG_TYPE_FLG',
    'R_REG_TYPE_FPU', 'R_REG_TYPE_GPR', 'R_REG_TYPE_LAST',
    'R_REG_TYPE_MMX', 'R_REG_TYPE_SEG', 'R_REG_TYPE_XMM',
    'R_REG_TYPE_YMM', 'c__EA_RRegisterId', 'c__EA_RRegisterType',
    'r_reg_32_to_64', 'r_reg_64_to_32', 'r_reg_arena_dup',
    'r_reg_arena_free', 'r_reg_arena_new', 'r_reg_arena_peek',
    'r_reg_arena_poke', 'r_reg_arena_pop', 'r_reg_arena_push',
    'r_reg_arena_set_bytes', 'r_reg_arena_shrink', 'r_reg_arena_swap',
    'r_reg_arena_zero', 'r_reg_cond', 'r_reg_cond_apply',
    'r_reg_cond_bits', 'r_reg_cond_bits_set',
    'r_reg_cond_from_string', 'r_reg_cond_get',
    'r_reg_cond_get_value', 'r_reg_cond_retrieve', 'r_reg_cond_set',
    'r_reg_cond_to_string', 'r_reg_default_bits', 'r_reg_fit_arena',
    'r_reg_free', 'r_reg_free_internal', 'r_reg_get', 'r_reg_get_at',
    'r_reg_get_bvalue', 'r_reg_get_bytes', 'r_reg_get_double',
    'r_reg_get_float', 'r_reg_get_list', 'r_reg_get_longdouble',
    'r_reg_get_name', 'r_reg_get_name_by_type', 'r_reg_get_name_idx',
    'r_reg_get_pack', 'r_reg_get_role', 'r_reg_get_type',
    'r_reg_get_value', 'r_reg_get_value_big',
    'r_reg_get_value_by_role', 'r_reg_getv', 'r_reg_index_get',
    'r_reg_init', 'r_reg_is_readonly', 'r_reg_item_free', 'r_reg_new',
    'r_reg_next_diff', 'r_reg_parse_gdb_profile',
    'r_reg_profile_to_cc', 'r_reg_read_regs', 'r_reg_regset_get',
    'r_reg_reindex', 'r_reg_set_bvalue', 'r_reg_set_bytes',
    'r_reg_set_double', 'r_reg_set_float', 'r_reg_set_longdouble',
    'r_reg_set_name', 'r_reg_set_pack', 'r_reg_set_profile',
    'r_reg_set_profile_string', 'r_reg_set_value',
    'r_reg_set_value_by_role', 'r_reg_setv', 'r_reg_type_by_name',
    'r_reg_version', 'struct__ut128', 'struct__ut256', 'struct__ut80',
    'struct__ut96', 'struct__utX', 'struct_ht_pp_bucket_t',
    'struct_ht_pp_kv', 'struct_ht_pp_options_t', 'struct_ht_pp_t',
    'struct_r_list_iter_t', 'struct_r_list_t', 'struct_r_reg_arena_t',
    'struct_r_reg_flags_t', 'struct_r_reg_item_t',
    'struct_r_reg_set_t', 'struct_r_reg_t']
