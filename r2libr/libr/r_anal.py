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


r_anal_version = _libr_anal.r_anal_version
r_anal_version.restype = ctypes.POINTER(ctypes.c_char)
r_anal_version.argtypes = []
class struct_r_anal_dwarf_context(Structure):
    pass

class struct_ht_up_t(Structure):
    pass

class struct_c__SA_RBinDwarfDebugInfo(Structure):
    pass

struct_r_anal_dwarf_context._pack_ = 1 # source:False
struct_r_anal_dwarf_context._fields_ = [
    ('info', ctypes.POINTER(struct_c__SA_RBinDwarfDebugInfo)),
    ('loc', ctypes.POINTER(struct_ht_up_t)),
]

class struct_c__SA_RBinDwarfCompUnit(Structure):
    pass

struct_c__SA_RBinDwarfDebugInfo._pack_ = 1 # source:False
struct_c__SA_RBinDwarfDebugInfo._fields_ = [
    ('count', ctypes.c_uint64),
    ('capacity', ctypes.c_uint64),
    ('comp_units', ctypes.POINTER(struct_c__SA_RBinDwarfCompUnit)),
    ('lookup_table', ctypes.POINTER(struct_ht_up_t)),
]

class struct_c__SA_RBinDwarfDie(Structure):
    pass

class struct_c__SA_RBinDwarfCompUnitHdr(Structure):
    pass

struct_c__SA_RBinDwarfCompUnitHdr._pack_ = 1 # source:False
struct_c__SA_RBinDwarfCompUnitHdr._fields_ = [
    ('length', ctypes.c_uint64),
    ('version', ctypes.c_uint16),
    ('PADDING_0', ctypes.c_ubyte * 6),
    ('abbrev_offset', ctypes.c_uint64),
    ('address_size', ctypes.c_ubyte),
    ('unit_type', ctypes.c_ubyte),
    ('dwo_id', ctypes.c_ubyte),
    ('PADDING_1', ctypes.c_ubyte * 5),
    ('type_sig', ctypes.c_uint64),
    ('type_offset', ctypes.c_uint64),
    ('header_size', ctypes.c_uint64),
    ('unit_offset', ctypes.c_uint64),
    ('is_64bit', ctypes.c_bool),
    ('PADDING_2', ctypes.c_ubyte * 7),
]

struct_c__SA_RBinDwarfCompUnit._pack_ = 1 # source:False
struct_c__SA_RBinDwarfCompUnit._fields_ = [
    ('hdr', struct_c__SA_RBinDwarfCompUnitHdr),
    ('offset', ctypes.c_uint64),
    ('count', ctypes.c_uint64),
    ('capacity', ctypes.c_uint64),
    ('dies', ctypes.POINTER(struct_c__SA_RBinDwarfDie)),
]

class struct_dwarf_attr_kind(Structure):
    pass

struct_c__SA_RBinDwarfDie._pack_ = 1 # source:False
struct_c__SA_RBinDwarfDie._fields_ = [
    ('tag', ctypes.c_uint64),
    ('abbrev_code', ctypes.c_uint64),
    ('count', ctypes.c_uint64),
    ('capacity', ctypes.c_uint64),
    ('offset', ctypes.c_uint64),
    ('has_children', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
    ('attr_values', ctypes.POINTER(struct_dwarf_attr_kind)),
]

class union_dwarf_attr_kind_0(Union):
    pass

class struct_dwarf_attr_kind_0_0(Structure):
    pass

struct_dwarf_attr_kind_0_0._pack_ = 1 # source:False
struct_dwarf_attr_kind_0_0._fields_ = [
    ('content', ctypes.POINTER(ctypes.c_char)),
    ('offset', ctypes.c_uint64),
]

class struct_c__SA_RBinDwarfBlock(Structure):
    pass

struct_c__SA_RBinDwarfBlock._pack_ = 1 # source:False
struct_c__SA_RBinDwarfBlock._fields_ = [
    ('length', ctypes.c_uint64),
    ('data', ctypes.POINTER(ctypes.c_ubyte)),
]

union_dwarf_attr_kind_0._pack_ = 1 # source:False
union_dwarf_attr_kind_0._anonymous_ = ('_0',)
union_dwarf_attr_kind_0._fields_ = [
    ('address', ctypes.c_uint64),
    ('block', struct_c__SA_RBinDwarfBlock),
    ('uconstant', ctypes.c_uint64),
    ('sconstant', ctypes.c_int64),
    ('flag', ctypes.c_ubyte),
    ('reference', ctypes.c_uint64),
    ('_0', struct_dwarf_attr_kind_0_0),
]


# values for enumeration 'c__EA_RBinDwarfAttrKind'
c__EA_RBinDwarfAttrKind__enumvalues = {
    0: 'DW_AT_KIND_ADDRESS',
    1: 'DW_AT_KIND_BLOCK',
    2: 'DW_AT_KIND_CONSTANT',
    3: 'DW_AT_KIND_EXPRLOC',
    4: 'DW_AT_KIND_FLAG',
    5: 'DW_AT_KIND_LINEPTR',
    6: 'DW_AT_KIND_LOCLISTPTR',
    7: 'DW_AT_KIND_MACPTR',
    8: 'DW_AT_KIND_RANGELISTPTR',
    9: 'DW_AT_KIND_REFERENCE',
    10: 'DW_AT_KIND_STRING',
}
DW_AT_KIND_ADDRESS = 0
DW_AT_KIND_BLOCK = 1
DW_AT_KIND_CONSTANT = 2
DW_AT_KIND_EXPRLOC = 3
DW_AT_KIND_FLAG = 4
DW_AT_KIND_LINEPTR = 5
DW_AT_KIND_LOCLISTPTR = 6
DW_AT_KIND_MACPTR = 7
DW_AT_KIND_RANGELISTPTR = 8
DW_AT_KIND_REFERENCE = 9
DW_AT_KIND_STRING = 10
c__EA_RBinDwarfAttrKind = ctypes.c_uint32 # enum
struct_dwarf_attr_kind._pack_ = 1 # source:False
struct_dwarf_attr_kind._anonymous_ = ('_0',)
struct_dwarf_attr_kind._fields_ = [
    ('attr_name', ctypes.c_uint64),
    ('attr_form', ctypes.c_uint64),
    ('kind', c__EA_RBinDwarfAttrKind),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('_0', union_dwarf_attr_kind_0),
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

RAnalDwarfContext = struct_r_anal_dwarf_context
class struct_c__SA_RAnalMetaUserItem(Structure):
    pass

class struct_pj_t(Structure):
    pass

class struct_r_anal_function_t(Structure):
    pass

class struct_r_anal_t(Structure):
    pass

struct_c__SA_RAnalMetaUserItem._pack_ = 1 # source:False
struct_c__SA_RAnalMetaUserItem._fields_ = [
    ('anal', ctypes.POINTER(struct_r_anal_t)),
    ('type', ctypes.c_int32),
    ('rad', ctypes.c_int32),
    ('cb', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char))),
    ('user', ctypes.POINTER(None)),
    ('count', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('fcn', ctypes.POINTER(struct_r_anal_function_t)),
    ('pj', ctypes.POINTER(struct_pj_t)),
]

class struct_sdb_t(Structure):
    pass

class struct_r_reg_t(Structure):
    pass

class struct_r_rb_node_t(Structure):
    pass

class struct_r_anal_esil_plugin_t(Structure):
    pass

class struct_r_event_t(Structure):
    pass

class struct_r_anal_range_t(Structure):
    pass

class struct_r_list_t(Structure):
    pass

class struct_r_syscall_t(Structure):
    pass

class struct_ht_pp_t(Structure):
    pass

class struct_r_anal_plugin_t(Structure):
    pass

class struct_r_anal_esil_t(Structure):
    pass

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

class struct_r_flag_t(Structure):
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

class struct_r_io_bind_t(Structure):
    pass

class struct_r_io_t(Structure):
    pass

class struct_r_io_map_t(Structure):
    pass

class struct_r_io_desc_t(Structure):
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

class struct_r_str_constpool_t(Structure):
    pass

struct_r_str_constpool_t._pack_ = 1 # source:False
struct_r_str_constpool_t._fields_ = [
    ('ht', ctypes.POINTER(struct_ht_pp_t)),
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

class struct_r_anal_hint_cb_t(Structure):
    pass

struct_r_anal_hint_cb_t._pack_ = 1 # source:False
struct_r_anal_hint_cb_t._fields_ = [
    ('on_bits', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_int32, ctypes.c_bool)),
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

class struct_r_id_pool_t(Structure):
    pass

class struct_r_cache_t(Structure):
    pass

class struct_r_id_storage_t(Structure):
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

class struct_r_num_t(Structure):
    pass

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

class struct_r_buf_t(Structure):
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

RAnalMetaUserItem = struct_c__SA_RAnalMetaUserItem
RAnalRange = struct_r_anal_range_t

# values for enumeration 'c__Ea_R_ANAL_DATA_TYPE_NULL'
c__Ea_R_ANAL_DATA_TYPE_NULL__enumvalues = {
    0: 'R_ANAL_DATA_TYPE_NULL',
    1: 'R_ANAL_DATA_TYPE_UNKNOWN',
    2: 'R_ANAL_DATA_TYPE_STRING',
    3: 'R_ANAL_DATA_TYPE_WIDE_STRING',
    4: 'R_ANAL_DATA_TYPE_POINTER',
    5: 'R_ANAL_DATA_TYPE_NUMBER',
    6: 'R_ANAL_DATA_TYPE_INVALID',
    7: 'R_ANAL_DATA_TYPE_HEADER',
    8: 'R_ANAL_DATA_TYPE_SEQUENCE',
    9: 'R_ANAL_DATA_TYPE_PATTERN',
}
R_ANAL_DATA_TYPE_NULL = 0
R_ANAL_DATA_TYPE_UNKNOWN = 1
R_ANAL_DATA_TYPE_STRING = 2
R_ANAL_DATA_TYPE_WIDE_STRING = 3
R_ANAL_DATA_TYPE_POINTER = 4
R_ANAL_DATA_TYPE_NUMBER = 5
R_ANAL_DATA_TYPE_INVALID = 6
R_ANAL_DATA_TYPE_HEADER = 7
R_ANAL_DATA_TYPE_SEQUENCE = 8
R_ANAL_DATA_TYPE_PATTERN = 9
c__Ea_R_ANAL_DATA_TYPE_NULL = ctypes.c_uint32 # enum
class struct_r_anal_type_var_t(Structure):
    pass

class union_r_anal_type_var_t_0(Union):
    pass

union_r_anal_type_var_t_0._pack_ = 1 # source:False
union_r_anal_type_var_t_0._fields_ = [
    ('v8', ctypes.c_ubyte),
    ('v16', ctypes.c_uint16),
    ('v32', ctypes.c_uint32),
    ('v64', ctypes.c_uint64),
]

struct_r_anal_type_var_t._pack_ = 1 # source:False
struct_r_anal_type_var_t._anonymous_ = ('_0',)
struct_r_anal_type_var_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('index', ctypes.c_int32),
    ('scope', ctypes.c_int32),
    ('type', ctypes.c_uint16),
    ('size', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte * 5),
    ('_0', union_r_anal_type_var_t_0),
]

RAnalTypeVar = struct_r_anal_type_var_t
class struct_r_anal_type_ptr_t(Structure):
    pass

class union_r_anal_type_ptr_t_0(Union):
    pass

union_r_anal_type_ptr_t_0._pack_ = 1 # source:False
union_r_anal_type_ptr_t_0._fields_ = [
    ('v8', ctypes.c_ubyte),
    ('v16', ctypes.c_uint16),
    ('v32', ctypes.c_uint32),
    ('v64', ctypes.c_uint64),
]

struct_r_anal_type_ptr_t._pack_ = 1 # source:False
struct_r_anal_type_ptr_t._anonymous_ = ('_0',)
struct_r_anal_type_ptr_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('type', ctypes.c_uint16),
    ('size', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte * 5),
    ('_0', union_r_anal_type_ptr_t_0),
]

RAnalTypePtr = struct_r_anal_type_ptr_t
class struct_r_anal_type_array_t(Structure):
    pass

class union_r_anal_type_array_t_0(Union):
    pass

union_r_anal_type_array_t_0._pack_ = 1 # source:False
union_r_anal_type_array_t_0._fields_ = [
    ('v8', ctypes.POINTER(ctypes.c_ubyte)),
    ('v16', ctypes.POINTER(ctypes.c_uint16)),
    ('v32', ctypes.POINTER(ctypes.c_uint32)),
    ('v64', ctypes.POINTER(ctypes.c_uint64)),
]

struct_r_anal_type_array_t._pack_ = 1 # source:False
struct_r_anal_type_array_t._anonymous_ = ('_0',)
struct_r_anal_type_array_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('type', ctypes.c_uint16),
    ('size', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte * 5),
    ('count', ctypes.c_uint64),
    ('_0', union_r_anal_type_array_t_0),
]

RAnalTypeArray = struct_r_anal_type_array_t
class struct_r_anal_type_struct_t(Structure):
    pass

class struct_r_anal_type_t(Structure):
    pass

struct_r_anal_type_struct_t._pack_ = 1 # source:False
struct_r_anal_type_struct_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('type', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte * 3),
    ('size', ctypes.c_uint32),
    ('parent', ctypes.POINTER(None)),
    ('items', ctypes.POINTER(struct_r_anal_type_t)),
]

RAnalTypeStruct = struct_r_anal_type_struct_t
struct_r_anal_type_t._pack_ = 1 # source:False
struct_r_anal_type_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('type', ctypes.c_uint32),
    ('size', ctypes.c_uint32),
    ('content', ctypes.POINTER(struct_r_list_t)),
]

RAnalType = struct_r_anal_type_t
class struct_r_anal_type_union_t(Structure):
    pass

struct_r_anal_type_union_t._pack_ = 1 # source:False
struct_r_anal_type_union_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('type', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte * 3),
    ('size', ctypes.c_uint32),
    ('parent', ctypes.POINTER(None)),
    ('items', ctypes.POINTER(struct_r_anal_type_t)),
]

RAnalTypeUnion = struct_r_anal_type_union_t
class struct_r_anal_type_alloca_t(Structure):
    pass

struct_r_anal_type_alloca_t._pack_ = 1 # source:False
struct_r_anal_type_alloca_t._fields_ = [
    ('address', ctypes.c_int64),
    ('size', ctypes.c_int64),
    ('parent', ctypes.POINTER(None)),
    ('items', ctypes.POINTER(struct_r_anal_type_t)),
]

RAnalTypeAlloca = struct_r_anal_type_alloca_t

# values for enumeration 'c__Ea_R_ANAL_FQUALIFIER_NONE'
c__Ea_R_ANAL_FQUALIFIER_NONE__enumvalues = {
    0: 'R_ANAL_FQUALIFIER_NONE',
    1: 'R_ANAL_FQUALIFIER_STATIC',
    2: 'R_ANAL_FQUALIFIER_VOLATILE',
    3: 'R_ANAL_FQUALIFIER_INLINE',
    4: 'R_ANAL_FQUALIFIER_NAKED',
    5: 'R_ANAL_FQUALIFIER_VIRTUAL',
}
R_ANAL_FQUALIFIER_NONE = 0
R_ANAL_FQUALIFIER_STATIC = 1
R_ANAL_FQUALIFIER_VOLATILE = 2
R_ANAL_FQUALIFIER_INLINE = 3
R_ANAL_FQUALIFIER_NAKED = 4
R_ANAL_FQUALIFIER_VIRTUAL = 5
c__Ea_R_ANAL_FQUALIFIER_NONE = ctypes.c_uint32 # enum

# values for enumeration 'c__Ea_R_ANAL_FCN_TYPE_NULL'
c__Ea_R_ANAL_FCN_TYPE_NULL__enumvalues = {
    0: 'R_ANAL_FCN_TYPE_NULL',
    1: 'R_ANAL_FCN_TYPE_FCN',
    2: 'R_ANAL_FCN_TYPE_LOC',
    4: 'R_ANAL_FCN_TYPE_SYM',
    8: 'R_ANAL_FCN_TYPE_IMP',
    16: 'R_ANAL_FCN_TYPE_INT',
    32: 'R_ANAL_FCN_TYPE_ROOT',
    -1: 'R_ANAL_FCN_TYPE_ANY',
}
R_ANAL_FCN_TYPE_NULL = 0
R_ANAL_FCN_TYPE_FCN = 1
R_ANAL_FCN_TYPE_LOC = 2
R_ANAL_FCN_TYPE_SYM = 4
R_ANAL_FCN_TYPE_IMP = 8
R_ANAL_FCN_TYPE_INT = 16
R_ANAL_FCN_TYPE_ROOT = 32
R_ANAL_FCN_TYPE_ANY = -1
c__Ea_R_ANAL_FCN_TYPE_NULL = ctypes.c_int32 # enum

# values for enumeration 'c__Ea_R_ANAL_DIFF_TYPE_NULL'
c__Ea_R_ANAL_DIFF_TYPE_NULL__enumvalues = {
    0: 'R_ANAL_DIFF_TYPE_NULL',
    109: 'R_ANAL_DIFF_TYPE_MATCH',
    117: 'R_ANAL_DIFF_TYPE_UNMATCH',
}
R_ANAL_DIFF_TYPE_NULL = 0
R_ANAL_DIFF_TYPE_MATCH = 109
R_ANAL_DIFF_TYPE_UNMATCH = 117
c__Ea_R_ANAL_DIFF_TYPE_NULL = ctypes.c_uint32 # enum
class struct_r_anal_enum_case_t(Structure):
    pass

struct_r_anal_enum_case_t._pack_ = 1 # source:False
struct_r_anal_enum_case_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('val', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

RAnalEnumCase = struct_r_anal_enum_case_t
class struct_r_anal_struct_member_t(Structure):
    pass

struct_r_anal_struct_member_t._pack_ = 1 # source:False
struct_r_anal_struct_member_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('type', ctypes.POINTER(ctypes.c_char)),
    ('offset', ctypes.c_uint64),
    ('size', ctypes.c_uint64),
]

RAnalStructMember = struct_r_anal_struct_member_t
class struct_r_anal_union_member_t(Structure):
    pass

struct_r_anal_union_member_t._pack_ = 1 # source:False
struct_r_anal_union_member_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('type', ctypes.POINTER(ctypes.c_char)),
    ('offset', ctypes.c_uint64),
    ('size', ctypes.c_uint64),
]

RAnalUnionMember = struct_r_anal_union_member_t

# values for enumeration 'c__EA_RAnalBaseTypeKind'
c__EA_RAnalBaseTypeKind__enumvalues = {
    0: 'R_ANAL_BASE_TYPE_KIND_STRUCT',
    1: 'R_ANAL_BASE_TYPE_KIND_UNION',
    2: 'R_ANAL_BASE_TYPE_KIND_ENUM',
    3: 'R_ANAL_BASE_TYPE_KIND_TYPEDEF',
    4: 'R_ANAL_BASE_TYPE_KIND_ATOMIC',
}
R_ANAL_BASE_TYPE_KIND_STRUCT = 0
R_ANAL_BASE_TYPE_KIND_UNION = 1
R_ANAL_BASE_TYPE_KIND_ENUM = 2
R_ANAL_BASE_TYPE_KIND_TYPEDEF = 3
R_ANAL_BASE_TYPE_KIND_ATOMIC = 4
c__EA_RAnalBaseTypeKind = ctypes.c_uint32 # enum
RAnalBaseTypeKind = c__EA_RAnalBaseTypeKind
RAnalBaseTypeKind__enumvalues = c__EA_RAnalBaseTypeKind__enumvalues
class struct_r_anal_base_type_struct_t(Structure):
    _pack_ = 1 # source:False
    _fields_ = [
    ('members', struct_r_vector_t),
     ]

RAnalBaseTypeStruct = struct_r_anal_base_type_struct_t
class struct_r_anal_base_type_union_t(Structure):
    _pack_ = 1 # source:False
    _fields_ = [
    ('members', struct_r_vector_t),
     ]

RAnalBaseTypeUnion = struct_r_anal_base_type_union_t
class struct_r_anal_base_type_enum_t(Structure):
    _pack_ = 1 # source:False
    _fields_ = [
    ('cases', struct_r_vector_t),
     ]

RAnalBaseTypeEnum = struct_r_anal_base_type_enum_t
class struct_r_anal_base_type_t(Structure):
    pass

class union_r_anal_base_type_t_0(Union):
    _pack_ = 1 # source:False
    _fields_ = [
    ('struct_data', RAnalBaseTypeStruct),
    ('enum_data', RAnalBaseTypeEnum),
    ('union_data', RAnalBaseTypeUnion),
     ]

struct_r_anal_base_type_t._pack_ = 1 # source:False
struct_r_anal_base_type_t._anonymous_ = ('_0',)
struct_r_anal_base_type_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('type', ctypes.POINTER(ctypes.c_char)),
    ('size', ctypes.c_uint64),
    ('kind', RAnalBaseTypeKind),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('_0', union_r_anal_base_type_t_0),
]

RAnalBaseType = struct_r_anal_base_type_t
RAnalDiff = struct_r_anal_diff_t
class struct_r_anal_attr_t(Structure):
    pass

struct_r_anal_attr_t._pack_ = 1 # source:False
struct_r_anal_attr_t._fields_ = [
    ('key', ctypes.POINTER(ctypes.c_char)),
    ('value', ctypes.c_int64),
    ('next', ctypes.POINTER(struct_r_anal_attr_t)),
]

RAnalAttr = struct_r_anal_attr_t
RAnalFcnMeta = struct_r_anal_fcn_meta_t
RAnalFunction = struct_r_anal_function_t
class struct_r_anal_func_arg_t(Structure):
    pass

struct_r_anal_func_arg_t._pack_ = 1 # source:False
struct_r_anal_func_arg_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('fmt', ctypes.POINTER(ctypes.c_char)),
    ('cc_source', ctypes.POINTER(ctypes.c_char)),
    ('orig_c_type', ctypes.POINTER(ctypes.c_char)),
    ('c_type', ctypes.POINTER(ctypes.c_char)),
    ('size', ctypes.c_uint64),
    ('src', ctypes.c_uint64),
]

RAnalFuncArg = struct_r_anal_func_arg_t

# values for enumeration 'c__EA_RAnalMetaType'
c__EA_RAnalMetaType__enumvalues = {
    -1: 'R_META_TYPE_ANY',
    100: 'R_META_TYPE_DATA',
    99: 'R_META_TYPE_CODE',
    115: 'R_META_TYPE_STRING',
    102: 'R_META_TYPE_FORMAT',
    109: 'R_META_TYPE_MAGIC',
    104: 'R_META_TYPE_HIDE',
    67: 'R_META_TYPE_COMMENT',
    114: 'R_META_TYPE_RUN',
    72: 'R_META_TYPE_HIGHLIGHT',
    116: 'R_META_TYPE_VARTYPE',
}
R_META_TYPE_ANY = -1
R_META_TYPE_DATA = 100
R_META_TYPE_CODE = 99
R_META_TYPE_STRING = 115
R_META_TYPE_FORMAT = 102
R_META_TYPE_MAGIC = 109
R_META_TYPE_HIDE = 104
R_META_TYPE_COMMENT = 67
R_META_TYPE_RUN = 114
R_META_TYPE_HIGHLIGHT = 72
R_META_TYPE_VARTYPE = 116
c__EA_RAnalMetaType = ctypes.c_int32 # enum
RAnalMetaType = c__EA_RAnalMetaType
RAnalMetaType__enumvalues = c__EA_RAnalMetaType__enumvalues
class struct_r_anal_meta_item_t(Structure):
    pass

struct_r_anal_meta_item_t._pack_ = 1 # source:False
struct_r_anal_meta_item_t._fields_ = [
    ('type', RAnalMetaType),
    ('subtype', ctypes.c_int32),
    ('str', ctypes.POINTER(ctypes.c_char)),
    ('space', ctypes.POINTER(struct_r_space_t)),
]

RAnalMetaItem = struct_r_anal_meta_item_t
RAnalOpFamily = c__EA_RAnalOpFamily
RAnalOpFamily__enumvalues = c__EA_RAnalOpFamily__enumvalues
RAnalOpPrefix = c__EA_RAnalOpPrefix
RAnalOpPrefix__enumvalues = c__EA_RAnalOpPrefix__enumvalues

# values for enumeration 'c__EA__RAnalOpType'
c__EA__RAnalOpType__enumvalues = {
    2147483648: 'R_ANAL_OP_TYPE_COND',
    1073741824: 'R_ANAL_OP_TYPE_REP',
    536870912: 'R_ANAL_OP_TYPE_MEM',
    268435456: 'R_ANAL_OP_TYPE_REG',
    134217728: 'R_ANAL_OP_TYPE_IND',
    0: 'R_ANAL_OP_TYPE_NULL',
    1: 'R_ANAL_OP_TYPE_JMP',
    2: 'R_ANAL_OP_TYPE_UJMP',
    268435458: 'R_ANAL_OP_TYPE_RJMP',
    134217730: 'R_ANAL_OP_TYPE_IJMP',
    402653186: 'R_ANAL_OP_TYPE_IRJMP',
    2147483649: 'R_ANAL_OP_TYPE_CJMP',
    2415919105: 'R_ANAL_OP_TYPE_RCJMP',
    536870913: 'R_ANAL_OP_TYPE_MJMP',
    2684354561: 'R_ANAL_OP_TYPE_MCJMP',
    2147483650: 'R_ANAL_OP_TYPE_UCJMP',
    3: 'R_ANAL_OP_TYPE_CALL',
    4: 'R_ANAL_OP_TYPE_UCALL',
    268435460: 'R_ANAL_OP_TYPE_RCALL',
    134217732: 'R_ANAL_OP_TYPE_ICALL',
    402653188: 'R_ANAL_OP_TYPE_IRCALL',
    2147483651: 'R_ANAL_OP_TYPE_CCALL',
    2147483652: 'R_ANAL_OP_TYPE_UCCALL',
    5: 'R_ANAL_OP_TYPE_RET',
    2147483653: 'R_ANAL_OP_TYPE_CRET',
    6: 'R_ANAL_OP_TYPE_ILL',
    7: 'R_ANAL_OP_TYPE_UNK',
    8: 'R_ANAL_OP_TYPE_NOP',
    9: 'R_ANAL_OP_TYPE_MOV',
    2147483657: 'R_ANAL_OP_TYPE_CMOV',
    10: 'R_ANAL_OP_TYPE_TRAP',
    11: 'R_ANAL_OP_TYPE_SWI',
    2147483659: 'R_ANAL_OP_TYPE_CSWI',
    12: 'R_ANAL_OP_TYPE_UPUSH',
    268435468: 'R_ANAL_OP_TYPE_RPUSH',
    13: 'R_ANAL_OP_TYPE_PUSH',
    14: 'R_ANAL_OP_TYPE_POP',
    15: 'R_ANAL_OP_TYPE_CMP',
    16: 'R_ANAL_OP_TYPE_ACMP',
    17: 'R_ANAL_OP_TYPE_ADD',
    18: 'R_ANAL_OP_TYPE_SUB',
    19: 'R_ANAL_OP_TYPE_IO',
    20: 'R_ANAL_OP_TYPE_MUL',
    21: 'R_ANAL_OP_TYPE_DIV',
    22: 'R_ANAL_OP_TYPE_SHR',
    23: 'R_ANAL_OP_TYPE_SHL',
    24: 'R_ANAL_OP_TYPE_SAL',
    25: 'R_ANAL_OP_TYPE_SAR',
    26: 'R_ANAL_OP_TYPE_OR',
    27: 'R_ANAL_OP_TYPE_AND',
    28: 'R_ANAL_OP_TYPE_XOR',
    29: 'R_ANAL_OP_TYPE_NOR',
    30: 'R_ANAL_OP_TYPE_NOT',
    31: 'R_ANAL_OP_TYPE_STORE',
    32: 'R_ANAL_OP_TYPE_LOAD',
    33: 'R_ANAL_OP_TYPE_LEA',
    34: 'R_ANAL_OP_TYPE_LEAVE',
    35: 'R_ANAL_OP_TYPE_ROR',
    36: 'R_ANAL_OP_TYPE_ROL',
    37: 'R_ANAL_OP_TYPE_XCHG',
    38: 'R_ANAL_OP_TYPE_MOD',
    39: 'R_ANAL_OP_TYPE_SWITCH',
    40: 'R_ANAL_OP_TYPE_CASE',
    41: 'R_ANAL_OP_TYPE_LENGTH',
    42: 'R_ANAL_OP_TYPE_CAST',
    43: 'R_ANAL_OP_TYPE_NEW',
    44: 'R_ANAL_OP_TYPE_ABS',
    45: 'R_ANAL_OP_TYPE_CPL',
    46: 'R_ANAL_OP_TYPE_CRYPTO',
    47: 'R_ANAL_OP_TYPE_SYNC',
}
R_ANAL_OP_TYPE_COND = 2147483648
R_ANAL_OP_TYPE_REP = 1073741824
R_ANAL_OP_TYPE_MEM = 536870912
R_ANAL_OP_TYPE_REG = 268435456
R_ANAL_OP_TYPE_IND = 134217728
R_ANAL_OP_TYPE_NULL = 0
R_ANAL_OP_TYPE_JMP = 1
R_ANAL_OP_TYPE_UJMP = 2
R_ANAL_OP_TYPE_RJMP = 268435458
R_ANAL_OP_TYPE_IJMP = 134217730
R_ANAL_OP_TYPE_IRJMP = 402653186
R_ANAL_OP_TYPE_CJMP = 2147483649
R_ANAL_OP_TYPE_RCJMP = 2415919105
R_ANAL_OP_TYPE_MJMP = 536870913
R_ANAL_OP_TYPE_MCJMP = 2684354561
R_ANAL_OP_TYPE_UCJMP = 2147483650
R_ANAL_OP_TYPE_CALL = 3
R_ANAL_OP_TYPE_UCALL = 4
R_ANAL_OP_TYPE_RCALL = 268435460
R_ANAL_OP_TYPE_ICALL = 134217732
R_ANAL_OP_TYPE_IRCALL = 402653188
R_ANAL_OP_TYPE_CCALL = 2147483651
R_ANAL_OP_TYPE_UCCALL = 2147483652
R_ANAL_OP_TYPE_RET = 5
R_ANAL_OP_TYPE_CRET = 2147483653
R_ANAL_OP_TYPE_ILL = 6
R_ANAL_OP_TYPE_UNK = 7
R_ANAL_OP_TYPE_NOP = 8
R_ANAL_OP_TYPE_MOV = 9
R_ANAL_OP_TYPE_CMOV = 2147483657
R_ANAL_OP_TYPE_TRAP = 10
R_ANAL_OP_TYPE_SWI = 11
R_ANAL_OP_TYPE_CSWI = 2147483659
R_ANAL_OP_TYPE_UPUSH = 12
R_ANAL_OP_TYPE_RPUSH = 268435468
R_ANAL_OP_TYPE_PUSH = 13
R_ANAL_OP_TYPE_POP = 14
R_ANAL_OP_TYPE_CMP = 15
R_ANAL_OP_TYPE_ACMP = 16
R_ANAL_OP_TYPE_ADD = 17
R_ANAL_OP_TYPE_SUB = 18
R_ANAL_OP_TYPE_IO = 19
R_ANAL_OP_TYPE_MUL = 20
R_ANAL_OP_TYPE_DIV = 21
R_ANAL_OP_TYPE_SHR = 22
R_ANAL_OP_TYPE_SHL = 23
R_ANAL_OP_TYPE_SAL = 24
R_ANAL_OP_TYPE_SAR = 25
R_ANAL_OP_TYPE_OR = 26
R_ANAL_OP_TYPE_AND = 27
R_ANAL_OP_TYPE_XOR = 28
R_ANAL_OP_TYPE_NOR = 29
R_ANAL_OP_TYPE_NOT = 30
R_ANAL_OP_TYPE_STORE = 31
R_ANAL_OP_TYPE_LOAD = 32
R_ANAL_OP_TYPE_LEA = 33
R_ANAL_OP_TYPE_LEAVE = 34
R_ANAL_OP_TYPE_ROR = 35
R_ANAL_OP_TYPE_ROL = 36
R_ANAL_OP_TYPE_XCHG = 37
R_ANAL_OP_TYPE_MOD = 38
R_ANAL_OP_TYPE_SWITCH = 39
R_ANAL_OP_TYPE_CASE = 40
R_ANAL_OP_TYPE_LENGTH = 41
R_ANAL_OP_TYPE_CAST = 42
R_ANAL_OP_TYPE_NEW = 43
R_ANAL_OP_TYPE_ABS = 44
R_ANAL_OP_TYPE_CPL = 45
R_ANAL_OP_TYPE_CRYPTO = 46
R_ANAL_OP_TYPE_SYNC = 47
c__EA__RAnalOpType = ctypes.c_uint32 # enum
_RAnalOpType = c__EA__RAnalOpType
_RAnalOpType__enumvalues = c__EA__RAnalOpType__enumvalues
RAnalOpMask = c__EA_RAnalOpMask
RAnalOpMask__enumvalues = c__EA_RAnalOpMask__enumvalues
_RAnalCond = c__EA__RAnalCond
_RAnalCond__enumvalues = c__EA__RAnalCond__enumvalues

# values for enumeration 'c__EA__RAnalVarScope'
c__EA__RAnalVarScope__enumvalues = {
    1: 'R_ANAL_VAR_SCOPE_LOCAL',
}
R_ANAL_VAR_SCOPE_LOCAL = 1
c__EA__RAnalVarScope = ctypes.c_uint32 # enum
_RAnalVarScope = c__EA__RAnalVarScope
_RAnalVarScope__enumvalues = c__EA__RAnalVarScope__enumvalues
RAnalStackOp = c__EA_RAnalStackOp
RAnalStackOp__enumvalues = c__EA_RAnalStackOp__enumvalues

# values for enumeration 'c__Ea_R_ANAL_REFLINE_TYPE_UTF8'
c__Ea_R_ANAL_REFLINE_TYPE_UTF8__enumvalues = {
    1: 'R_ANAL_REFLINE_TYPE_UTF8',
    2: 'R_ANAL_REFLINE_TYPE_WIDE',
    4: 'R_ANAL_REFLINE_TYPE_MIDDLE_BEFORE',
    8: 'R_ANAL_REFLINE_TYPE_MIDDLE_AFTER',
}
R_ANAL_REFLINE_TYPE_UTF8 = 1
R_ANAL_REFLINE_TYPE_WIDE = 2
R_ANAL_REFLINE_TYPE_MIDDLE_BEFORE = 4
R_ANAL_REFLINE_TYPE_MIDDLE_AFTER = 8
c__Ea_R_ANAL_REFLINE_TYPE_UTF8 = ctypes.c_uint32 # enum

# values for enumeration 'c__Ea_R_ANAL_RET_NOP'
c__Ea_R_ANAL_RET_NOP__enumvalues = {
    0: 'R_ANAL_RET_NOP',
    -1: 'R_ANAL_RET_ERROR',
    -2: 'R_ANAL_RET_DUP',
    -3: 'R_ANAL_RET_NEW',
    -4: 'R_ANAL_RET_END',
}
R_ANAL_RET_NOP = 0
R_ANAL_RET_ERROR = -1
R_ANAL_RET_DUP = -2
R_ANAL_RET_NEW = -3
R_ANAL_RET_END = -4
c__Ea_R_ANAL_RET_NOP = ctypes.c_int32 # enum
class struct_r_anal_case_obj_t(Structure):
    pass

struct_r_anal_case_obj_t._pack_ = 1 # source:False
struct_r_anal_case_obj_t._fields_ = [
    ('addr', ctypes.c_uint64),
    ('jump', ctypes.c_uint64),
    ('value', ctypes.c_uint64),
]

RAnalCaseOp = struct_r_anal_case_obj_t
RAnalSwitchOp = struct_r_anal_switch_obj_t
RAnalCallbacks = struct_r_anal_callbacks_t
RAnalOptions = struct_r_anal_options_t
RAnalCPPABI = c__EA_RAnalCPPABI
RAnalCPPABI__enumvalues = c__EA_RAnalCPPABI__enumvalues
RHintCb = struct_r_anal_hint_cb_t
RAnal = struct_r_anal_t

# values for enumeration 'r_anal_addr_hint_type_t'
r_anal_addr_hint_type_t__enumvalues = {
    0: 'R_ANAL_ADDR_HINT_TYPE_IMMBASE',
    1: 'R_ANAL_ADDR_HINT_TYPE_JUMP',
    2: 'R_ANAL_ADDR_HINT_TYPE_FAIL',
    3: 'R_ANAL_ADDR_HINT_TYPE_STACKFRAME',
    4: 'R_ANAL_ADDR_HINT_TYPE_PTR',
    5: 'R_ANAL_ADDR_HINT_TYPE_NWORD',
    6: 'R_ANAL_ADDR_HINT_TYPE_RET',
    7: 'R_ANAL_ADDR_HINT_TYPE_NEW_BITS',
    8: 'R_ANAL_ADDR_HINT_TYPE_SIZE',
    9: 'R_ANAL_ADDR_HINT_TYPE_SYNTAX',
    10: 'R_ANAL_ADDR_HINT_TYPE_OPTYPE',
    11: 'R_ANAL_ADDR_HINT_TYPE_OPCODE',
    12: 'R_ANAL_ADDR_HINT_TYPE_TYPE_OFFSET',
    13: 'R_ANAL_ADDR_HINT_TYPE_ESIL',
    14: 'R_ANAL_ADDR_HINT_TYPE_HIGH',
    15: 'R_ANAL_ADDR_HINT_TYPE_VAL',
}
R_ANAL_ADDR_HINT_TYPE_IMMBASE = 0
R_ANAL_ADDR_HINT_TYPE_JUMP = 1
R_ANAL_ADDR_HINT_TYPE_FAIL = 2
R_ANAL_ADDR_HINT_TYPE_STACKFRAME = 3
R_ANAL_ADDR_HINT_TYPE_PTR = 4
R_ANAL_ADDR_HINT_TYPE_NWORD = 5
R_ANAL_ADDR_HINT_TYPE_RET = 6
R_ANAL_ADDR_HINT_TYPE_NEW_BITS = 7
R_ANAL_ADDR_HINT_TYPE_SIZE = 8
R_ANAL_ADDR_HINT_TYPE_SYNTAX = 9
R_ANAL_ADDR_HINT_TYPE_OPTYPE = 10
R_ANAL_ADDR_HINT_TYPE_OPCODE = 11
R_ANAL_ADDR_HINT_TYPE_TYPE_OFFSET = 12
R_ANAL_ADDR_HINT_TYPE_ESIL = 13
R_ANAL_ADDR_HINT_TYPE_HIGH = 14
R_ANAL_ADDR_HINT_TYPE_VAL = 15
r_anal_addr_hint_type_t = ctypes.c_uint32 # enum
RAnalAddrHintType = r_anal_addr_hint_type_t
RAnalAddrHintType__enumvalues = r_anal_addr_hint_type_t__enumvalues
class struct_r_anal_addr_hint_record_t(Structure):
    pass

class union_r_anal_addr_hint_record_t_0(Union):
    pass

union_r_anal_addr_hint_record_t_0._pack_ = 1 # source:False
union_r_anal_addr_hint_record_t_0._fields_ = [
    ('type_offset', ctypes.POINTER(ctypes.c_char)),
    ('nword', ctypes.c_int32),
    ('jump', ctypes.c_uint64),
    ('fail', ctypes.c_uint64),
    ('newbits', ctypes.c_int32),
    ('immbase', ctypes.c_int32),
    ('ptr', ctypes.c_uint64),
    ('retval', ctypes.c_uint64),
    ('syntax', ctypes.POINTER(ctypes.c_char)),
    ('opcode', ctypes.POINTER(ctypes.c_char)),
    ('esil', ctypes.POINTER(ctypes.c_char)),
    ('optype', ctypes.c_int32),
    ('size', ctypes.c_uint64),
    ('stackframe', ctypes.c_uint64),
    ('val', ctypes.c_uint64),
]

struct_r_anal_addr_hint_record_t._pack_ = 1 # source:False
struct_r_anal_addr_hint_record_t._anonymous_ = ('_0',)
struct_r_anal_addr_hint_record_t._fields_ = [
    ('type', RAnalAddrHintType),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('_0', union_r_anal_addr_hint_record_t_0),
]

RAnalAddrHintRecord = struct_r_anal_addr_hint_record_t
RAnalHint = struct_r_anal_hint_t
RAnalGetFcnIn = ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_anal_function_t), ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_int32)
RAnalGetHint = ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_anal_hint_t), ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64)
class struct_r_anal_bind_t(Structure):
    pass

struct_r_anal_bind_t._pack_ = 1 # source:False
struct_r_anal_bind_t._fields_ = [
    ('anal', ctypes.POINTER(struct_r_anal_t)),
    ('get_fcn_in', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_anal_function_t), ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_int32)),
    ('get_hint', ctypes.CFUNCTYPE(ctypes.POINTER(struct_r_anal_hint_t), ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64)),
]

RAnalBind = struct_r_anal_bind_t
RAnalLabelAt = ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_anal_function_t), ctypes.c_uint64)

# values for enumeration 'c__EA_RAnalVarKind'
c__EA_RAnalVarKind__enumvalues = {
    114: 'R_ANAL_VAR_KIND_REG',
    98: 'R_ANAL_VAR_KIND_BPV',
    115: 'R_ANAL_VAR_KIND_SPV',
}
R_ANAL_VAR_KIND_REG = 114
R_ANAL_VAR_KIND_BPV = 98
R_ANAL_VAR_KIND_SPV = 115
c__EA_RAnalVarKind = ctypes.c_uint32 # enum
RAnalVarKind = c__EA_RAnalVarKind
RAnalVarKind__enumvalues = c__EA_RAnalVarKind__enumvalues

# values for enumeration 'c__EA_RAnalVarAccessType'
c__EA_RAnalVarAccessType__enumvalues = {
    0: 'R_ANAL_VAR_ACCESS_TYPE_PTR',
    1: 'R_ANAL_VAR_ACCESS_TYPE_READ',
    2: 'R_ANAL_VAR_ACCESS_TYPE_WRITE',
}
R_ANAL_VAR_ACCESS_TYPE_PTR = 0
R_ANAL_VAR_ACCESS_TYPE_READ = 1
R_ANAL_VAR_ACCESS_TYPE_WRITE = 2
c__EA_RAnalVarAccessType = ctypes.c_uint32 # enum
RAnalVarAccessType = c__EA_RAnalVarAccessType
RAnalVarAccessType__enumvalues = c__EA_RAnalVarAccessType__enumvalues
class struct_r_anal_var_access_t(Structure):
    pass

struct_r_anal_var_access_t._pack_ = 1 # source:False
struct_r_anal_var_access_t._fields_ = [
    ('reg', ctypes.POINTER(ctypes.c_char)),
    ('offset', ctypes.c_int64),
    ('stackptr', ctypes.c_int64),
    ('type', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte * 7),
]

RAnalVarAccess = struct_r_anal_var_access_t
class struct_r_anal_var_constraint_t(Structure):
    pass

struct_r_anal_var_constraint_t._pack_ = 1 # source:False
struct_r_anal_var_constraint_t._fields_ = [
    ('cond', _RAnalCond),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('val', ctypes.c_uint64),
]

RAnalVarConstraint = struct_r_anal_var_constraint_t
class struct_r_anal_var_t(Structure):
    pass

struct_r_anal_var_t._pack_ = 1 # source:False
struct_r_anal_var_t._fields_ = [
    ('fcn', ctypes.POINTER(struct_r_anal_function_t)),
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('type', ctypes.POINTER(ctypes.c_char)),
    ('kind', RAnalVarKind),
    ('isarg', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 3),
    ('delta', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
    ('regname', ctypes.POINTER(ctypes.c_char)),
    ('accesses', struct_r_vector_t),
    ('comment', ctypes.POINTER(ctypes.c_char)),
    ('constraints', struct_r_vector_t),
    ('argnum', ctypes.c_int32),
    ('PADDING_2', ctypes.c_ubyte * 4),
]

RAnalVar = struct_r_anal_var_t
class struct_r_anal_var_field_t(Structure):
    pass

struct_r_anal_var_field_t._pack_ = 1 # source:False
struct_r_anal_var_field_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('delta', ctypes.c_int64),
    ('field', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
]

RAnalVarField = struct_r_anal_var_field_t
RAnalValueAccess = c__EA_RAnalValueAccess
RAnalValueAccess__enumvalues = c__EA_RAnalValueAccess__enumvalues
RAnalValueType = c__EA_RAnalValueType
RAnalValueType__enumvalues = c__EA_RAnalValueType__enumvalues
RAnalValue = struct_r_anal_value_t
RAnalOpDirection = c__EA_RAnalOpDirection
RAnalOpDirection__enumvalues = c__EA_RAnalOpDirection__enumvalues
RAnalDataType = r_anal_data_type_t
RAnalDataType__enumvalues = r_anal_data_type_t__enumvalues
RAnalOp = struct_r_anal_op_t
RAnalCond = struct_r_anal_cond_t
RAnalBlock = struct_r_anal_bb_t

# values for enumeration 'c__EA_RAnalRefType'
c__EA_RAnalRefType__enumvalues = {
    0: 'R_ANAL_REF_TYPE_NULL',
    99: 'R_ANAL_REF_TYPE_CODE',
    67: 'R_ANAL_REF_TYPE_CALL',
    100: 'R_ANAL_REF_TYPE_DATA',
    115: 'R_ANAL_REF_TYPE_STRING',
}
R_ANAL_REF_TYPE_NULL = 0
R_ANAL_REF_TYPE_CODE = 99
R_ANAL_REF_TYPE_CALL = 67
R_ANAL_REF_TYPE_DATA = 100
R_ANAL_REF_TYPE_STRING = 115
c__EA_RAnalRefType = ctypes.c_uint32 # enum
RAnalRefType = c__EA_RAnalRefType
RAnalRefType__enumvalues = c__EA_RAnalRefType__enumvalues
class struct_r_anal_ref_t(Structure):
    pass

struct_r_anal_ref_t._pack_ = 1 # source:False
struct_r_anal_ref_t._fields_ = [
    ('addr', ctypes.c_uint64),
    ('at', ctypes.c_uint64),
    ('type', RAnalRefType),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

RAnalRef = struct_r_anal_ref_t
r_anal_ref_type_tostring = _libr_anal.r_anal_ref_type_tostring
r_anal_ref_type_tostring.restype = ctypes.POINTER(ctypes.c_char)
r_anal_ref_type_tostring.argtypes = [RAnalRefType]
class struct_r_anal_refline_t(Structure):
    pass

struct_r_anal_refline_t._pack_ = 1 # source:False
struct_r_anal_refline_t._fields_ = [
    ('from', ctypes.c_uint64),
    ('to', ctypes.c_uint64),
    ('index', ctypes.c_int32),
    ('level', ctypes.c_int32),
    ('type', ctypes.c_int32),
    ('direction', ctypes.c_int32),
]

RAnalRefline = struct_r_anal_refline_t
class struct_r_anal_cycle_frame_t(Structure):
    pass

struct_r_anal_cycle_frame_t._pack_ = 1 # source:False
struct_r_anal_cycle_frame_t._fields_ = [
    ('naddr', ctypes.c_uint64),
    ('hooks', ctypes.POINTER(struct_r_list_t)),
    ('prev', ctypes.POINTER(struct_r_anal_cycle_frame_t)),
]

RAnalCycleFrame = struct_r_anal_cycle_frame_t
class struct_r_anal_cycle_hook_t(Structure):
    pass

struct_r_anal_cycle_hook_t._pack_ = 1 # source:False
struct_r_anal_cycle_hook_t._fields_ = [
    ('addr', ctypes.c_uint64),
    ('cycles', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

RAnalCycleHook = struct_r_anal_cycle_hook_t
class struct_r_anal_esil_word_t(Structure):
    pass

struct_r_anal_esil_word_t._pack_ = 1 # source:False
struct_r_anal_esil_word_t._fields_ = [
    ('type', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('str', ctypes.POINTER(ctypes.c_char)),
]

RAnalEsilWord = struct_r_anal_esil_word_t

# values for enumeration 'c__Ea_R_ANAL_ESIL_FLAG_ZERO'
c__Ea_R_ANAL_ESIL_FLAG_ZERO__enumvalues = {
    1: 'R_ANAL_ESIL_FLAG_ZERO',
    2: 'R_ANAL_ESIL_FLAG_CARRY',
    4: 'R_ANAL_ESIL_FLAG_OVERFLOW',
    8: 'R_ANAL_ESIL_FLAG_PARITY',
    16: 'R_ANAL_ESIL_FLAG_SIGN',
}
R_ANAL_ESIL_FLAG_ZERO = 1
R_ANAL_ESIL_FLAG_CARRY = 2
R_ANAL_ESIL_FLAG_OVERFLOW = 4
R_ANAL_ESIL_FLAG_PARITY = 8
R_ANAL_ESIL_FLAG_SIGN = 16
c__Ea_R_ANAL_ESIL_FLAG_ZERO = ctypes.c_uint32 # enum

# values for enumeration 'c__Ea_R_ANAL_TRAP_NONE'
c__Ea_R_ANAL_TRAP_NONE__enumvalues = {
    0: 'R_ANAL_TRAP_NONE',
    1: 'R_ANAL_TRAP_UNHANDLED',
    2: 'R_ANAL_TRAP_BREAKPOINT',
    3: 'R_ANAL_TRAP_DIVBYZERO',
    4: 'R_ANAL_TRAP_WRITE_ERR',
    5: 'R_ANAL_TRAP_READ_ERR',
    6: 'R_ANAL_TRAP_EXEC_ERR',
    7: 'R_ANAL_TRAP_INVALID',
    8: 'R_ANAL_TRAP_UNALIGNED',
    9: 'R_ANAL_TRAP_TODO',
    10: 'R_ANAL_TRAP_HALT',
}
R_ANAL_TRAP_NONE = 0
R_ANAL_TRAP_UNHANDLED = 1
R_ANAL_TRAP_BREAKPOINT = 2
R_ANAL_TRAP_DIVBYZERO = 3
R_ANAL_TRAP_WRITE_ERR = 4
R_ANAL_TRAP_READ_ERR = 5
R_ANAL_TRAP_EXEC_ERR = 6
R_ANAL_TRAP_INVALID = 7
R_ANAL_TRAP_UNALIGNED = 8
R_ANAL_TRAP_TODO = 9
R_ANAL_TRAP_HALT = 10
c__Ea_R_ANAL_TRAP_NONE = ctypes.c_uint32 # enum

# values for enumeration 'c__Ea_R_ANAL_ESIL_PARM_INVALID'
c__Ea_R_ANAL_ESIL_PARM_INVALID__enumvalues = {
    0: 'R_ANAL_ESIL_PARM_INVALID',
    1: 'R_ANAL_ESIL_PARM_REG',
    2: 'R_ANAL_ESIL_PARM_NUM',
}
R_ANAL_ESIL_PARM_INVALID = 0
R_ANAL_ESIL_PARM_REG = 1
R_ANAL_ESIL_PARM_NUM = 2
c__Ea_R_ANAL_ESIL_PARM_INVALID = ctypes.c_uint32 # enum

# values for enumeration 'c__EA_RAnalReilOpcode'
c__EA_RAnalReilOpcode__enumvalues = {
    0: 'REIL_NOP',
    1: 'REIL_UNK',
    2: 'REIL_JCC',
    3: 'REIL_STR',
    4: 'REIL_STM',
    5: 'REIL_LDM',
    6: 'REIL_ADD',
    7: 'REIL_SUB',
    8: 'REIL_NEG',
    9: 'REIL_MUL',
    10: 'REIL_DIV',
    11: 'REIL_MOD',
    12: 'REIL_SMUL',
    13: 'REIL_SDIV',
    14: 'REIL_SMOD',
    15: 'REIL_SHL',
    16: 'REIL_SHR',
    17: 'REIL_AND',
    18: 'REIL_OR',
    19: 'REIL_XOR',
    20: 'REIL_NOT',
    21: 'REIL_EQ',
    22: 'REIL_LT',
}
REIL_NOP = 0
REIL_UNK = 1
REIL_JCC = 2
REIL_STR = 3
REIL_STM = 4
REIL_LDM = 5
REIL_ADD = 6
REIL_SUB = 7
REIL_NEG = 8
REIL_MUL = 9
REIL_DIV = 10
REIL_MOD = 11
REIL_SMUL = 12
REIL_SDIV = 13
REIL_SMOD = 14
REIL_SHL = 15
REIL_SHR = 16
REIL_AND = 17
REIL_OR = 18
REIL_XOR = 19
REIL_NOT = 20
REIL_EQ = 21
REIL_LT = 22
c__EA_RAnalReilOpcode = ctypes.c_uint32 # enum
RAnalReilOpcode = c__EA_RAnalReilOpcode
RAnalReilOpcode__enumvalues = c__EA_RAnalReilOpcode__enumvalues

# values for enumeration 'c__EA_RAnalReilArgType'
c__EA_RAnalReilArgType__enumvalues = {
    0: 'ARG_REG',
    1: 'ARG_TEMP',
    2: 'ARG_CONST',
    3: 'ARG_ESIL_INTERNAL',
    4: 'ARG_NONE',
}
ARG_REG = 0
ARG_TEMP = 1
ARG_CONST = 2
ARG_ESIL_INTERNAL = 3
ARG_NONE = 4
c__EA_RAnalReilArgType = ctypes.c_uint32 # enum
RAnalReilArgType = c__EA_RAnalReilArgType
RAnalReilArgType__enumvalues = c__EA_RAnalReilArgType__enumvalues
class struct_r_anal_reil_arg(Structure):
    pass

struct_r_anal_reil_arg._pack_ = 1 # source:False
struct_r_anal_reil_arg._fields_ = [
    ('type', RAnalReilArgType),
    ('size', ctypes.c_ubyte),
    ('name', ctypes.c_char * 32),
    ('PADDING_0', ctypes.c_ubyte * 3),
]

RAnalReilArg = struct_r_anal_reil_arg
class struct_r_anal_ref_char(Structure):
    pass

struct_r_anal_ref_char._pack_ = 1 # source:False
struct_r_anal_ref_char._fields_ = [
    ('str', ctypes.POINTER(ctypes.c_char)),
    ('cols', ctypes.POINTER(ctypes.c_char)),
]

RAnalRefStr = struct_r_anal_ref_char
class struct_r_anal_reil_inst(Structure):
    pass

struct_r_anal_reil_inst._pack_ = 1 # source:False
struct_r_anal_reil_inst._fields_ = [
    ('opcode', RAnalReilOpcode),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('arg', ctypes.POINTER(struct_r_anal_reil_arg) * 3),
]

RAnalReilInst = struct_r_anal_reil_inst
RAnalReil = struct_r_anal_reil
RAnalEsilHandlerCB = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_anal_esil_t), ctypes.c_uint32, ctypes.POINTER(None))
RAnalEsilHandler = struct_r_anal_esil_handler_t
class struct_r_anal_esil_change_reg_t(Structure):
    pass

struct_r_anal_esil_change_reg_t._pack_ = 1 # source:False
struct_r_anal_esil_change_reg_t._fields_ = [
    ('idx', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('data', ctypes.c_uint64),
]

RAnalEsilRegChange = struct_r_anal_esil_change_reg_t
class struct_r_anal_esil_change_mem_t(Structure):
    pass

struct_r_anal_esil_change_mem_t._pack_ = 1 # source:False
struct_r_anal_esil_change_mem_t._fields_ = [
    ('idx', ctypes.c_int32),
    ('data', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte * 3),
]

RAnalEsilMemChange = struct_r_anal_esil_change_mem_t
RAnalEsilTrace = struct_r_anal_esil_trace_t
RAnalEsilHookRegWriteCB = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_anal_esil_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_uint64))
RAnalEsilCallbacks = struct_r_anal_esil_callbacks_t
RAnalEsil = struct_r_anal_esil_t

# values for enumeration 'c__Ea_R_ANAL_ESIL_OP_TYPE_UNKNOWN'
c__Ea_R_ANAL_ESIL_OP_TYPE_UNKNOWN__enumvalues = {
    1: 'R_ANAL_ESIL_OP_TYPE_UNKNOWN',
    2: 'R_ANAL_ESIL_OP_TYPE_CONTROL_FLOW',
    4: 'R_ANAL_ESIL_OP_TYPE_MEM_READ',
    8: 'R_ANAL_ESIL_OP_TYPE_MEM_WRITE',
    16: 'R_ANAL_ESIL_OP_TYPE_REG_WRITE',
    32: 'R_ANAL_ESIL_OP_TYPE_MATH',
    64: 'R_ANAL_ESIL_OP_TYPE_CUSTOM',
}
R_ANAL_ESIL_OP_TYPE_UNKNOWN = 1
R_ANAL_ESIL_OP_TYPE_CONTROL_FLOW = 2
R_ANAL_ESIL_OP_TYPE_MEM_READ = 4
R_ANAL_ESIL_OP_TYPE_MEM_WRITE = 8
R_ANAL_ESIL_OP_TYPE_REG_WRITE = 16
R_ANAL_ESIL_OP_TYPE_MATH = 32
R_ANAL_ESIL_OP_TYPE_CUSTOM = 64
c__Ea_R_ANAL_ESIL_OP_TYPE_UNKNOWN = ctypes.c_uint32 # enum
RAnalEsilOpCb = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_anal_esil_t))
class struct_r_anal_esil_operation_t(Structure):
    pass

struct_r_anal_esil_operation_t._pack_ = 1 # source:False
struct_r_anal_esil_operation_t._fields_ = [
    ('code', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_anal_esil_t))),
    ('push', ctypes.c_uint32),
    ('pop', ctypes.c_uint32),
    ('type', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

RAnalEsilOp = struct_r_anal_esil_operation_t
class struct_r_anal_esil_expr_offset_t(Structure):
    pass

struct_r_anal_esil_expr_offset_t._pack_ = 1 # source:False
struct_r_anal_esil_expr_offset_t._fields_ = [
    ('off', ctypes.c_uint64),
    ('idx', ctypes.c_uint16),
    ('PADDING_0', ctypes.c_ubyte * 6),
]

RAnalEsilEOffset = struct_r_anal_esil_expr_offset_t

# values for enumeration 'c__EA_RAnalEsilBlockEnterType'
c__EA_RAnalEsilBlockEnterType__enumvalues = {
    0: 'R_ANAL_ESIL_BLOCK_ENTER_NORMAL',
    1: 'R_ANAL_ESIL_BLOCK_ENTER_TRUE',
    2: 'R_ANAL_ESIL_BLOCK_ENTER_FALSE',
    3: 'R_ANAL_ESIL_BLOCK_ENTER_GLUE',
}
R_ANAL_ESIL_BLOCK_ENTER_NORMAL = 0
R_ANAL_ESIL_BLOCK_ENTER_TRUE = 1
R_ANAL_ESIL_BLOCK_ENTER_FALSE = 2
R_ANAL_ESIL_BLOCK_ENTER_GLUE = 3
c__EA_RAnalEsilBlockEnterType = ctypes.c_uint32 # enum
RAnalEsilBlockEnterType = c__EA_RAnalEsilBlockEnterType
RAnalEsilBlockEnterType__enumvalues = c__EA_RAnalEsilBlockEnterType__enumvalues
class struct_r_anal_esil_basic_block_t(Structure):
    pass

struct_r_anal_esil_basic_block_t._pack_ = 1 # source:False
struct_r_anal_esil_basic_block_t._fields_ = [
    ('first', RAnalEsilEOffset),
    ('last', RAnalEsilEOffset),
    ('expr', ctypes.POINTER(ctypes.c_char)),
    ('enter', RAnalEsilBlockEnterType),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

RAnalEsilBB = struct_r_anal_esil_basic_block_t
class struct_r_anal_esil_cfg_t(Structure):
    pass

class struct_r_graph_t(Structure):
    pass

class struct_r_graph_node_t(Structure):
    pass

struct_r_anal_esil_cfg_t._pack_ = 1 # source:False
struct_r_anal_esil_cfg_t._fields_ = [
    ('start', ctypes.POINTER(struct_r_graph_node_t)),
    ('end', ctypes.POINTER(struct_r_graph_node_t)),
    ('g', ctypes.POINTER(struct_r_graph_t)),
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

struct_r_graph_t._pack_ = 1 # source:False
struct_r_graph_t._fields_ = [
    ('n_nodes', ctypes.c_uint32),
    ('n_edges', ctypes.c_uint32),
    ('last_index', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('nodes', ctypes.POINTER(struct_r_list_t)),
]

RAnalEsilCFG = struct_r_anal_esil_cfg_t

# values for enumeration 'c__Ea_R_ANAL_ESIL_DFG_BLOCK_CONST'
c__Ea_R_ANAL_ESIL_DFG_BLOCK_CONST__enumvalues = {
    1: 'R_ANAL_ESIL_DFG_BLOCK_CONST',
    2: 'R_ANAL_ESIL_DFG_BLOCK_VAR',
    4: 'R_ANAL_ESIL_DFG_BLOCK_PTR',
    8: 'R_ANAL_ESIL_DFG_BLOCK_RESULT',
    16: 'R_ANAL_ESIL_DFG_BLOCK_GENERATIVE',
}
R_ANAL_ESIL_DFG_BLOCK_CONST = 1
R_ANAL_ESIL_DFG_BLOCK_VAR = 2
R_ANAL_ESIL_DFG_BLOCK_PTR = 4
R_ANAL_ESIL_DFG_BLOCK_RESULT = 8
R_ANAL_ESIL_DFG_BLOCK_GENERATIVE = 16
c__Ea_R_ANAL_ESIL_DFG_BLOCK_CONST = ctypes.c_uint32 # enum
class struct_r_anal_esil_dfg_t(Structure):
    pass

class struct_r_containing_rb_tree_t(Structure):
    pass

struct_r_anal_esil_dfg_t._pack_ = 1 # source:False
struct_r_anal_esil_dfg_t._fields_ = [
    ('idx', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('regs', ctypes.POINTER(struct_sdb_t)),
    ('reg_vars', ctypes.POINTER(struct_r_containing_rb_tree_t)),
    ('todo', ctypes.POINTER(struct_r_queue_t)),
    ('insert', ctypes.POINTER(None)),
    ('flow', ctypes.POINTER(struct_r_graph_t)),
    ('cur', ctypes.POINTER(struct_r_graph_node_t)),
    ('old', ctypes.POINTER(struct_r_graph_node_t)),
    ('malloc_failed', ctypes.c_bool),
    ('PADDING_1', ctypes.c_ubyte * 7),
]

class struct_r_containing_rb_node_t(Structure):
    pass

struct_r_containing_rb_tree_t._pack_ = 1 # source:False
struct_r_containing_rb_tree_t._fields_ = [
    ('root', ctypes.POINTER(struct_r_containing_rb_node_t)),
    ('free', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
]

struct_r_containing_rb_node_t._pack_ = 1 # source:False
struct_r_containing_rb_node_t._fields_ = [
    ('node', struct_r_rb_node_t),
    ('data', ctypes.POINTER(None)),
]

RAnalEsilDFG = struct_r_anal_esil_dfg_t
class struct_r_anal_esil_dfg_node_t(Structure):
    pass

struct_r_anal_esil_dfg_node_t._pack_ = 1 # source:False
struct_r_anal_esil_dfg_node_t._fields_ = [
    ('idx', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('content', ctypes.POINTER(struct_c__SA_RStrBuf)),
    ('type', ctypes.c_uint32),
    ('PADDING_1', ctypes.c_ubyte * 4),
]

RAnalEsilDFGNode = struct_r_anal_esil_dfg_node_t
RAnalCmdExt = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char))
RAnalOpCallback = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_op_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, c__EA_RAnalOpMask)
RAnalRegProfCallback = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_anal_t))
RAnalRegProfGetCallback = ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_anal_t))
RAnalFPBBCallback = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_bb_t))
RAnalFPFcnCallback = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_function_t))
RAnalDiffBBCallback = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_function_t), ctypes.POINTER(struct_r_anal_function_t))
RAnalDiffFcnCallback = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_list_t))
RAnalDiffEvalCallback = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_anal_t))
RAnalEsilCB = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_anal_esil_t))
RAnalEsilLoopCB = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_anal_esil_t), ctypes.POINTER(struct_r_anal_op_t))
RAnalEsilTrapCB = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_anal_esil_t), ctypes.c_int32, ctypes.c_int32)
RAnalPlugin = struct_r_anal_plugin_t
RAnalEsilPlugin = struct_r_anal_esil_plugin_t
class struct_r_anal_esil_active_plugin_t(Structure):
    pass

struct_r_anal_esil_active_plugin_t._pack_ = 1 # source:False
struct_r_anal_esil_active_plugin_t._fields_ = [
    ('plugin', ctypes.POINTER(struct_r_anal_esil_plugin_t)),
    ('user', ctypes.POINTER(None)),
]

RAnalEsilActivePlugin = struct_r_anal_esil_active_plugin_t
r_anal_compare = _libraries['FIXME_STUB'].r_anal_compare
r_anal_compare.restype = ctypes.POINTER(ctypes.c_int32)
r_anal_compare.argtypes = [RAnalFunction, RAnalFunction]
class struct_r_list_range_t(Structure):
    pass

struct_r_list_range_t._pack_ = 1 # source:False
struct_r_list_range_t._fields_ = [
    ('h', ctypes.POINTER(struct_ht_pp_t)),
    ('l', ctypes.POINTER(struct_r_list_t)),
]

r_listrange_new = _libraries['FIXME_STUB'].r_listrange_new
r_listrange_new.restype = ctypes.POINTER(struct_r_list_range_t)
r_listrange_new.argtypes = []
r_listrange_free = _libraries['FIXME_STUB'].r_listrange_free
r_listrange_free.restype = None
r_listrange_free.argtypes = [ctypes.POINTER(struct_r_list_range_t)]
r_listrange_add = _libraries['FIXME_STUB'].r_listrange_add
r_listrange_add.restype = None
r_listrange_add.argtypes = [ctypes.POINTER(struct_r_list_range_t), ctypes.POINTER(struct_r_anal_function_t)]
r_listrange_del = _libraries['FIXME_STUB'].r_listrange_del
r_listrange_del.restype = None
r_listrange_del.argtypes = [ctypes.POINTER(struct_r_list_range_t), ctypes.POINTER(struct_r_anal_function_t)]
r_listrange_resize = _libraries['FIXME_STUB'].r_listrange_resize
r_listrange_resize.restype = None
r_listrange_resize.argtypes = [ctypes.POINTER(struct_r_list_range_t), ctypes.POINTER(struct_r_anal_function_t), ctypes.c_int32]
r_listrange_find_in_range = _libraries['FIXME_STUB'].r_listrange_find_in_range
r_listrange_find_in_range.restype = ctypes.POINTER(struct_r_anal_function_t)
r_listrange_find_in_range.argtypes = [ctypes.POINTER(struct_r_list_range_t), ctypes.c_uint64]
r_listrange_find_root = _libraries['FIXME_STUB'].r_listrange_find_root
r_listrange_find_root.restype = ctypes.POINTER(struct_r_anal_function_t)
r_listrange_find_root.argtypes = [ctypes.POINTER(struct_r_list_range_t), ctypes.c_uint64]
r_anal_type_new = _libraries['FIXME_STUB'].r_anal_type_new
r_anal_type_new.restype = ctypes.POINTER(struct_r_anal_type_t)
r_anal_type_new.argtypes = []
r_anal_type_add = _libraries['FIXME_STUB'].r_anal_type_add
r_anal_type_add.restype = None
r_anal_type_add.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_type_t)]
r_anal_type_find = _libraries['FIXME_STUB'].r_anal_type_find
r_anal_type_find.restype = ctypes.POINTER(struct_r_anal_type_t)
r_anal_type_find.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_type_list = _libraries['FIXME_STUB'].r_anal_type_list
r_anal_type_list.restype = None
r_anal_type_list.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_int16, ctypes.c_int16]
r_anal_datatype_to_string = _libr_anal.r_anal_datatype_to_string
r_anal_datatype_to_string.restype = ctypes.POINTER(ctypes.c_char)
r_anal_datatype_to_string.argtypes = [RAnalDataType]
r_anal_str_to_type = _libraries['FIXME_STUB'].r_anal_str_to_type
r_anal_str_to_type.restype = ctypes.POINTER(struct_r_anal_type_t)
r_anal_str_to_type.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_op_nonlinear = _libr_anal.r_anal_op_nonlinear
r_anal_op_nonlinear.restype = ctypes.c_bool
r_anal_op_nonlinear.argtypes = [ctypes.c_int32]
r_anal_op_ismemref = _libr_anal.r_anal_op_ismemref
r_anal_op_ismemref.restype = ctypes.c_bool
r_anal_op_ismemref.argtypes = [ctypes.c_int32]
r_anal_optype_to_string = _libr_anal.r_anal_optype_to_string
r_anal_optype_to_string.restype = ctypes.POINTER(ctypes.c_char)
r_anal_optype_to_string.argtypes = [ctypes.c_int32]
r_anal_optype_from_string = _libr_anal.r_anal_optype_from_string
r_anal_optype_from_string.restype = ctypes.c_int32
r_anal_optype_from_string.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_anal_op_family_to_string = _libr_anal.r_anal_op_family_to_string
r_anal_op_family_to_string.restype = ctypes.POINTER(ctypes.c_char)
r_anal_op_family_to_string.argtypes = [ctypes.c_int32]
r_anal_op_family_from_string = _libr_anal.r_anal_op_family_from_string
r_anal_op_family_from_string.restype = ctypes.c_int32
r_anal_op_family_from_string.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_anal_op_hint = _libr_anal.r_anal_op_hint
r_anal_op_hint.restype = ctypes.c_int32
r_anal_op_hint.argtypes = [ctypes.POINTER(struct_r_anal_op_t), ctypes.POINTER(struct_r_anal_hint_t)]
r_anal_type_free = _libraries['FIXME_STUB'].r_anal_type_free
r_anal_type_free.restype = ctypes.POINTER(struct_r_anal_type_t)
r_anal_type_free.argtypes = [ctypes.POINTER(struct_r_anal_type_t)]
r_anal_type_loadfile = _libraries['FIXME_STUB'].r_anal_type_loadfile
r_anal_type_loadfile.restype = ctypes.POINTER(struct_r_anal_type_t)
r_anal_type_loadfile.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
RAnalBlockCb = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_anal_bb_t), ctypes.POINTER(None))
RAnalAddrCb = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_uint64, ctypes.POINTER(None))
r_anal_block_ref = _libr_anal.r_anal_block_ref
r_anal_block_ref.restype = None
r_anal_block_ref.argtypes = [ctypes.POINTER(struct_r_anal_bb_t)]
r_anal_block_unref = _libr_anal.r_anal_block_unref
r_anal_block_unref.restype = None
r_anal_block_unref.argtypes = [ctypes.POINTER(struct_r_anal_bb_t)]
r_anal_create_block = _libr_anal.r_anal_create_block
r_anal_create_block.restype = ctypes.POINTER(struct_r_anal_bb_t)
r_anal_create_block.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_uint64]
r_anal_block_contains = _libraries['FIXME_STUB'].r_anal_block_contains
r_anal_block_contains.restype = ctypes.c_bool
r_anal_block_contains.argtypes = [ctypes.POINTER(struct_r_anal_bb_t), ctypes.c_uint64]
r_anal_block_split = _libr_anal.r_anal_block_split
r_anal_block_split.restype = ctypes.POINTER(struct_r_anal_bb_t)
r_anal_block_split.argtypes = [ctypes.POINTER(struct_r_anal_bb_t), ctypes.c_uint64]
r_anal_block_is_contiguous = _libraries['FIXME_STUB'].r_anal_block_is_contiguous
r_anal_block_is_contiguous.restype = ctypes.c_bool
r_anal_block_is_contiguous.argtypes = [ctypes.POINTER(struct_r_anal_bb_t), ctypes.POINTER(struct_r_anal_bb_t)]
r_anal_block_merge = _libr_anal.r_anal_block_merge
r_anal_block_merge.restype = ctypes.c_bool
r_anal_block_merge.argtypes = [ctypes.POINTER(struct_r_anal_bb_t), ctypes.POINTER(struct_r_anal_bb_t)]
r_anal_delete_block = _libr_anal.r_anal_delete_block
r_anal_delete_block.restype = None
r_anal_delete_block.argtypes = [ctypes.POINTER(struct_r_anal_bb_t)]
r_anal_block_set_size = _libr_anal.r_anal_block_set_size
r_anal_block_set_size.restype = None
r_anal_block_set_size.argtypes = [ctypes.POINTER(struct_r_anal_bb_t), ctypes.c_uint64]
r_anal_block_relocate = _libr_anal.r_anal_block_relocate
r_anal_block_relocate.restype = ctypes.c_bool
r_anal_block_relocate.argtypes = [ctypes.POINTER(struct_r_anal_bb_t), ctypes.c_uint64, ctypes.c_uint64]
r_anal_get_block_at = _libr_anal.r_anal_get_block_at
r_anal_get_block_at.restype = ctypes.POINTER(struct_r_anal_bb_t)
r_anal_get_block_at.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_blocks_foreach_in = _libr_anal.r_anal_blocks_foreach_in
r_anal_blocks_foreach_in.restype = ctypes.c_bool
r_anal_blocks_foreach_in.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, RAnalBlockCb, ctypes.POINTER(None)]
r_anal_get_blocks_in = _libr_anal.r_anal_get_blocks_in
r_anal_get_blocks_in.restype = ctypes.POINTER(struct_r_list_t)
r_anal_get_blocks_in.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_blocks_foreach_intersect = _libr_anal.r_anal_blocks_foreach_intersect
r_anal_blocks_foreach_intersect.restype = None
r_anal_blocks_foreach_intersect.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_uint64, RAnalBlockCb, ctypes.POINTER(None)]
r_anal_get_blocks_intersect = _libr_anal.r_anal_get_blocks_intersect
r_anal_get_blocks_intersect.restype = ctypes.POINTER(struct_r_list_t)
r_anal_get_blocks_intersect.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_uint64]
r_anal_block_successor_addrs_foreach = _libr_anal.r_anal_block_successor_addrs_foreach
r_anal_block_successor_addrs_foreach.restype = ctypes.c_bool
r_anal_block_successor_addrs_foreach.argtypes = [ctypes.POINTER(struct_r_anal_bb_t), RAnalAddrCb, ctypes.POINTER(None)]
r_anal_block_recurse = _libr_anal.r_anal_block_recurse
r_anal_block_recurse.restype = ctypes.c_bool
r_anal_block_recurse.argtypes = [ctypes.POINTER(struct_r_anal_bb_t), RAnalBlockCb, ctypes.POINTER(None)]
r_anal_block_recurse_followthrough = _libr_anal.r_anal_block_recurse_followthrough
r_anal_block_recurse_followthrough.restype = ctypes.c_bool
r_anal_block_recurse_followthrough.argtypes = [ctypes.POINTER(struct_r_anal_bb_t), RAnalBlockCb, ctypes.POINTER(None)]
r_anal_block_recurse_depth_first = _libr_anal.r_anal_block_recurse_depth_first
r_anal_block_recurse_depth_first.restype = ctypes.c_bool
r_anal_block_recurse_depth_first.argtypes = [ctypes.POINTER(struct_r_anal_bb_t), RAnalBlockCb, RAnalBlockCb, ctypes.POINTER(None)]
r_anal_block_recurse_list = _libr_anal.r_anal_block_recurse_list
r_anal_block_recurse_list.restype = ctypes.POINTER(struct_r_list_t)
r_anal_block_recurse_list.argtypes = [ctypes.POINTER(struct_r_anal_bb_t)]
r_anal_block_shortest_path = _libr_anal.r_anal_block_shortest_path
r_anal_block_shortest_path.restype = ctypes.POINTER(struct_r_list_t)
r_anal_block_shortest_path.argtypes = [ctypes.POINTER(struct_r_anal_bb_t), ctypes.c_uint64]
r_anal_block_add_switch_case = _libr_anal.r_anal_block_add_switch_case
r_anal_block_add_switch_case.restype = None
r_anal_block_add_switch_case.argtypes = [ctypes.POINTER(struct_r_anal_bb_t), ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64]
r_anal_block_chop_noreturn = _libr_anal.r_anal_block_chop_noreturn
r_anal_block_chop_noreturn.restype = ctypes.POINTER(struct_r_anal_bb_t)
r_anal_block_chop_noreturn.argtypes = [ctypes.POINTER(struct_r_anal_bb_t), ctypes.c_uint64]
r_anal_block_automerge = _libr_anal.r_anal_block_automerge
r_anal_block_automerge.restype = None
r_anal_block_automerge.argtypes = [ctypes.POINTER(struct_r_list_t)]
r_anal_block_op_starts_at = _libr_anal.r_anal_block_op_starts_at
r_anal_block_op_starts_at.restype = ctypes.c_bool
r_anal_block_op_starts_at.argtypes = [ctypes.POINTER(struct_r_anal_bb_t), ctypes.c_uint64]
r_anal_block_update_hash = _libr_anal.r_anal_block_update_hash
r_anal_block_update_hash.restype = None
r_anal_block_update_hash.argtypes = [ctypes.POINTER(struct_r_anal_bb_t)]
r_anal_block_was_modified = _libr_anal.r_anal_block_was_modified
r_anal_block_was_modified.restype = ctypes.c_bool
r_anal_block_was_modified.argtypes = [ctypes.POINTER(struct_r_anal_bb_t)]
r_anal_function_new = _libr_anal.r_anal_function_new
r_anal_function_new.restype = ctypes.POINTER(struct_r_anal_function_t)
r_anal_function_new.argtypes = [ctypes.POINTER(struct_r_anal_t)]
r_anal_function_free = _libr_anal.r_anal_function_free
r_anal_function_free.restype = None
r_anal_function_free.argtypes = [ctypes.POINTER(struct_r_anal_function_t)]
r_anal_add_function = _libr_anal.r_anal_add_function
r_anal_add_function.restype = ctypes.c_bool
r_anal_add_function.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_function_t)]
r_anal_create_function = _libr_anal.r_anal_create_function
r_anal_create_function.restype = ctypes.POINTER(struct_r_anal_function_t)
r_anal_create_function.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64, ctypes.c_int32, ctypes.POINTER(struct_r_anal_diff_t)]
r_anal_get_functions_in = _libr_anal.r_anal_get_functions_in
r_anal_get_functions_in.restype = ctypes.POINTER(struct_r_list_t)
r_anal_get_functions_in.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_get_function_at = _libr_anal.r_anal_get_function_at
r_anal_get_function_at.restype = ctypes.POINTER(struct_r_anal_function_t)
r_anal_get_function_at.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_function_delete = _libr_anal.r_anal_function_delete
r_anal_function_delete.restype = ctypes.c_bool
r_anal_function_delete.argtypes = [ctypes.POINTER(struct_r_anal_function_t)]
r_anal_function_relocate = _libr_anal.r_anal_function_relocate
r_anal_function_relocate.restype = ctypes.c_bool
r_anal_function_relocate.argtypes = [ctypes.POINTER(struct_r_anal_function_t), ctypes.c_uint64]
r_anal_function_rename = _libr_anal.r_anal_function_rename
r_anal_function_rename.restype = ctypes.c_bool
r_anal_function_rename.argtypes = [ctypes.POINTER(struct_r_anal_function_t), ctypes.POINTER(ctypes.c_char)]
r_anal_function_add_block = _libr_anal.r_anal_function_add_block
r_anal_function_add_block.restype = None
r_anal_function_add_block.argtypes = [ctypes.POINTER(struct_r_anal_function_t), ctypes.POINTER(struct_r_anal_bb_t)]
r_anal_function_remove_block = _libr_anal.r_anal_function_remove_block
r_anal_function_remove_block.restype = None
r_anal_function_remove_block.argtypes = [ctypes.POINTER(struct_r_anal_function_t), ctypes.POINTER(struct_r_anal_bb_t)]
r_anal_function_linear_size = _libr_anal.r_anal_function_linear_size
r_anal_function_linear_size.restype = ctypes.c_uint64
r_anal_function_linear_size.argtypes = [ctypes.POINTER(struct_r_anal_function_t)]
r_anal_function_min_addr = _libr_anal.r_anal_function_min_addr
r_anal_function_min_addr.restype = ctypes.c_uint64
r_anal_function_min_addr.argtypes = [ctypes.POINTER(struct_r_anal_function_t)]
r_anal_function_max_addr = _libr_anal.r_anal_function_max_addr
r_anal_function_max_addr.restype = ctypes.c_uint64
r_anal_function_max_addr.argtypes = [ctypes.POINTER(struct_r_anal_function_t)]
r_anal_function_size_from_entry = _libr_anal.r_anal_function_size_from_entry
r_anal_function_size_from_entry.restype = ctypes.c_uint64
r_anal_function_size_from_entry.argtypes = [ctypes.POINTER(struct_r_anal_function_t)]
r_anal_function_realsize = _libr_anal.r_anal_function_realsize
r_anal_function_realsize.restype = ctypes.c_uint64
r_anal_function_realsize.argtypes = [ctypes.POINTER(struct_r_anal_function_t)]
r_anal_function_contains = _libr_anal.r_anal_function_contains
r_anal_function_contains.restype = ctypes.c_bool
r_anal_function_contains.argtypes = [ctypes.POINTER(struct_r_anal_function_t), ctypes.c_uint64]
r_anal_function_was_modified = _libr_anal.r_anal_function_was_modified
r_anal_function_was_modified.restype = ctypes.c_bool
r_anal_function_was_modified.argtypes = [ctypes.POINTER(struct_r_anal_function_t)]
r_anal_new = _libr_anal.r_anal_new
r_anal_new.restype = ctypes.POINTER(struct_r_anal_t)
r_anal_new.argtypes = []
r_anal_purge = _libr_anal.r_anal_purge
r_anal_purge.restype = None
r_anal_purge.argtypes = [ctypes.POINTER(struct_r_anal_t)]
r_anal_free = _libr_anal.r_anal_free
r_anal_free.restype = ctypes.POINTER(struct_r_anal_t)
r_anal_free.argtypes = [ctypes.POINTER(struct_r_anal_t)]
r_anal_set_user_ptr = _libr_anal.r_anal_set_user_ptr
r_anal_set_user_ptr.restype = None
r_anal_set_user_ptr.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(None)]
r_anal_plugin_free = _libr_anal.r_anal_plugin_free
r_anal_plugin_free.restype = None
r_anal_plugin_free.argtypes = [ctypes.POINTER(struct_r_anal_plugin_t)]
r_anal_add = _libr_anal.r_anal_add
r_anal_add.restype = ctypes.c_int32
r_anal_add.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_plugin_t)]
r_anal_archinfo = _libr_anal.r_anal_archinfo
r_anal_archinfo.restype = ctypes.c_int32
r_anal_archinfo.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_int32]
r_anal_use = _libr_anal.r_anal_use
r_anal_use.restype = ctypes.c_bool
r_anal_use.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_esil_use = _libr_anal.r_anal_esil_use
r_anal_esil_use.restype = ctypes.c_bool
r_anal_esil_use.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_set_reg_profile = _libr_anal.r_anal_set_reg_profile
r_anal_set_reg_profile.restype = ctypes.c_bool
r_anal_set_reg_profile.argtypes = [ctypes.POINTER(struct_r_anal_t)]
r_anal_get_reg_profile = _libr_anal.r_anal_get_reg_profile
r_anal_get_reg_profile.restype = ctypes.POINTER(ctypes.c_char)
r_anal_get_reg_profile.argtypes = [ctypes.POINTER(struct_r_anal_t)]
r_anal_get_bbaddr = _libr_anal.r_anal_get_bbaddr
r_anal_get_bbaddr.restype = ctypes.c_uint64
r_anal_get_bbaddr.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_set_bits = _libr_anal.r_anal_set_bits
r_anal_set_bits.restype = ctypes.c_bool
r_anal_set_bits.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_int32]
r_anal_set_os = _libr_anal.r_anal_set_os
r_anal_set_os.restype = ctypes.c_bool
r_anal_set_os.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_set_cpu = _libr_anal.r_anal_set_cpu
r_anal_set_cpu.restype = None
r_anal_set_cpu.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_set_big_endian = _libr_anal.r_anal_set_big_endian
r_anal_set_big_endian.restype = None
r_anal_set_big_endian.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_int32]
r_anal_mask = _libr_anal.r_anal_mask
r_anal_mask.restype = ctypes.POINTER(ctypes.c_ubyte)
r_anal_mask.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64]
r_anal_trace_bb = _libr_anal.r_anal_trace_bb
r_anal_trace_bb.restype = None
r_anal_trace_bb.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_fcntype_tostring = _libr_anal.r_anal_fcntype_tostring
r_anal_fcntype_tostring.restype = ctypes.POINTER(ctypes.c_char)
r_anal_fcntype_tostring.argtypes = [ctypes.c_int32]
r_anal_fcn_bb = _libr_anal.r_anal_fcn_bb
r_anal_fcn_bb.restype = ctypes.c_int32
r_anal_fcn_bb.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_function_t), ctypes.c_uint64, ctypes.c_int32]
r_anal_bind = _libr_anal.r_anal_bind
r_anal_bind.restype = None
r_anal_bind.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_bind_t)]
r_anal_set_triplet = _libr_anal.r_anal_set_triplet
r_anal_set_triplet.restype = ctypes.c_bool
r_anal_set_triplet.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_anal_add_import = _libr_anal.r_anal_add_import
r_anal_add_import.restype = None
r_anal_add_import.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_remove_import = _libr_anal.r_anal_remove_import
r_anal_remove_import.restype = None
r_anal_remove_import.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_purge_imports = _libr_anal.r_anal_purge_imports
r_anal_purge_imports.restype = None
r_anal_purge_imports.argtypes = [ctypes.POINTER(struct_r_anal_t)]
r_anal_bb_from_offset = _libr_anal.r_anal_bb_from_offset
r_anal_bb_from_offset.restype = ctypes.POINTER(struct_r_anal_bb_t)
r_anal_bb_from_offset.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_bb_set_offset = _libr_anal.r_anal_bb_set_offset
r_anal_bb_set_offset.restype = ctypes.c_bool
r_anal_bb_set_offset.argtypes = [ctypes.POINTER(struct_r_anal_bb_t), ctypes.c_int32, ctypes.c_uint16]
r_anal_bb_offset_inst = _libr_anal.r_anal_bb_offset_inst
r_anal_bb_offset_inst.restype = ctypes.c_uint16
r_anal_bb_offset_inst.argtypes = [ctypes.POINTER(struct_r_anal_bb_t), ctypes.c_int32]
r_anal_bb_opaddr_i = _libr_anal.r_anal_bb_opaddr_i
r_anal_bb_opaddr_i.restype = ctypes.c_uint64
r_anal_bb_opaddr_i.argtypes = [ctypes.POINTER(struct_r_anal_bb_t), ctypes.c_int32]
r_anal_bb_opaddr_at = _libr_anal.r_anal_bb_opaddr_at
r_anal_bb_opaddr_at.restype = ctypes.c_uint64
r_anal_bb_opaddr_at.argtypes = [ctypes.POINTER(struct_r_anal_bb_t), ctypes.c_uint64]
r_anal_bb_size_i = _libr_anal.r_anal_bb_size_i
r_anal_bb_size_i.restype = ctypes.c_uint64
r_anal_bb_size_i.argtypes = [ctypes.POINTER(struct_r_anal_bb_t), ctypes.c_int32]
r_anal_stackop_tostring = _libr_anal.r_anal_stackop_tostring
r_anal_stackop_tostring.restype = ctypes.POINTER(ctypes.c_char)
r_anal_stackop_tostring.argtypes = [ctypes.c_int32]
r_anal_op_new = _libr_anal.r_anal_op_new
r_anal_op_new.restype = ctypes.POINTER(struct_r_anal_op_t)
r_anal_op_new.argtypes = []
r_anal_op_free = _libr_anal.r_anal_op_free
r_anal_op_free.restype = None
r_anal_op_free.argtypes = [ctypes.POINTER(None)]
r_anal_op_init = _libr_anal.r_anal_op_init
r_anal_op_init.restype = None
r_anal_op_init.argtypes = [ctypes.POINTER(struct_r_anal_op_t)]
r_anal_op_fini = _libr_anal.r_anal_op_fini
r_anal_op_fini.restype = ctypes.c_bool
r_anal_op_fini.argtypes = [ctypes.POINTER(struct_r_anal_op_t)]
r_anal_op_reg_delta = _libr_anal.r_anal_op_reg_delta
r_anal_op_reg_delta.restype = ctypes.c_int32
r_anal_op_reg_delta.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_char)]
r_anal_op_is_eob = _libr_anal.r_anal_op_is_eob
r_anal_op_is_eob.restype = ctypes.c_bool
r_anal_op_is_eob.argtypes = [ctypes.POINTER(struct_r_anal_op_t)]
r_anal_op_list_new = _libr_anal.r_anal_op_list_new
r_anal_op_list_new.restype = ctypes.POINTER(struct_r_list_t)
r_anal_op_list_new.argtypes = []
r_anal_op = _libr_anal.r_anal_op
r_anal_op.restype = ctypes.c_int32
r_anal_op.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_op_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, RAnalOpMask]
r_anal_op_hexstr = _libr_anal.r_anal_op_hexstr
r_anal_op_hexstr.restype = ctypes.POINTER(struct_r_anal_op_t)
r_anal_op_hexstr.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_char)]
r_anal_op_to_string = _libr_anal.r_anal_op_to_string
r_anal_op_to_string.restype = ctypes.POINTER(ctypes.c_char)
r_anal_op_to_string.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_op_t)]
r_anal_esil_new = _libr_anal.r_anal_esil_new
r_anal_esil_new.restype = ctypes.POINTER(struct_r_anal_esil_t)
r_anal_esil_new.argtypes = [ctypes.c_int32, ctypes.c_int32, ctypes.c_uint32]
r_anal_esil_set_pc = _libr_anal.r_anal_esil_set_pc
r_anal_esil_set_pc.restype = ctypes.c_bool
r_anal_esil_set_pc.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.c_uint64]
r_anal_esil_setup = _libr_anal.r_anal_esil_setup
r_anal_esil_setup.restype = ctypes.c_bool
r_anal_esil_setup.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.POINTER(struct_r_anal_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
r_anal_esil_free = _libr_anal.r_anal_esil_free
r_anal_esil_free.restype = None
r_anal_esil_free.argtypes = [ctypes.POINTER(struct_r_anal_esil_t)]
r_anal_esil_runword = _libr_anal.r_anal_esil_runword
r_anal_esil_runword.restype = ctypes.c_bool
r_anal_esil_runword.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.POINTER(ctypes.c_char)]
r_anal_esil_parse = _libr_anal.r_anal_esil_parse
r_anal_esil_parse.restype = ctypes.c_bool
r_anal_esil_parse.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.POINTER(ctypes.c_char)]
r_anal_esil_dumpstack = _libr_anal.r_anal_esil_dumpstack
r_anal_esil_dumpstack.restype = ctypes.c_bool
r_anal_esil_dumpstack.argtypes = [ctypes.POINTER(struct_r_anal_esil_t)]
r_anal_esil_mem_read = _libr_anal.r_anal_esil_mem_read
r_anal_esil_mem_read.restype = ctypes.c_bool
r_anal_esil_mem_read.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_anal_esil_mem_write = _libr_anal.r_anal_esil_mem_write
r_anal_esil_mem_write.restype = ctypes.c_bool
r_anal_esil_mem_write.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_anal_esil_reg_read = _libr_anal.r_anal_esil_reg_read
r_anal_esil_reg_read.restype = ctypes.c_bool
r_anal_esil_reg_read.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_int32)]
r_anal_esil_reg_write = _libr_anal.r_anal_esil_reg_write
r_anal_esil_reg_write.restype = ctypes.c_bool
r_anal_esil_reg_write.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64]
r_anal_esil_pushnum = _libr_anal.r_anal_esil_pushnum
r_anal_esil_pushnum.restype = ctypes.c_bool
r_anal_esil_pushnum.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.c_uint64]
r_anal_esil_push = _libr_anal.r_anal_esil_push
r_anal_esil_push.restype = ctypes.c_bool
r_anal_esil_push.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.POINTER(ctypes.c_char)]
r_anal_esil_pop = _libr_anal.r_anal_esil_pop
r_anal_esil_pop.restype = ctypes.POINTER(ctypes.c_char)
r_anal_esil_pop.argtypes = [ctypes.POINTER(struct_r_anal_esil_t)]
r_anal_esil_set_op = _libr_anal.r_anal_esil_set_op
r_anal_esil_set_op.restype = ctypes.c_bool
r_anal_esil_set_op.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.POINTER(ctypes.c_char), RAnalEsilOpCb, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
r_anal_esil_get_op = _libr_anal.r_anal_esil_get_op
r_anal_esil_get_op.restype = ctypes.POINTER(struct_r_anal_esil_operation_t)
r_anal_esil_get_op.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.POINTER(ctypes.c_char)]
r_anal_esil_del_op = _libr_anal.r_anal_esil_del_op
r_anal_esil_del_op.restype = None
r_anal_esil_del_op.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.POINTER(ctypes.c_char)]
r_anal_esil_stack_free = _libr_anal.r_anal_esil_stack_free
r_anal_esil_stack_free.restype = None
r_anal_esil_stack_free.argtypes = [ctypes.POINTER(struct_r_anal_esil_t)]
r_anal_esil_get_parm_type = _libr_anal.r_anal_esil_get_parm_type
r_anal_esil_get_parm_type.restype = ctypes.c_int32
r_anal_esil_get_parm_type.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.POINTER(ctypes.c_char)]
r_anal_esil_get_parm = _libr_anal.r_anal_esil_get_parm
r_anal_esil_get_parm.restype = ctypes.c_int32
r_anal_esil_get_parm.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_uint64)]
r_anal_esil_condition = _libr_anal.r_anal_esil_condition
r_anal_esil_condition.restype = ctypes.c_int32
r_anal_esil_condition.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.POINTER(ctypes.c_char)]
r_anal_esil_handlers_init = _libr_anal.r_anal_esil_handlers_init
r_anal_esil_handlers_init.restype = None
r_anal_esil_handlers_init.argtypes = [ctypes.POINTER(struct_r_anal_esil_t)]
r_anal_esil_set_interrupt = _libr_anal.r_anal_esil_set_interrupt
r_anal_esil_set_interrupt.restype = ctypes.c_bool
r_anal_esil_set_interrupt.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.c_uint32, RAnalEsilHandlerCB, ctypes.POINTER(None)]
r_anal_esil_get_interrupt = _libr_anal.r_anal_esil_get_interrupt
r_anal_esil_get_interrupt.restype = RAnalEsilHandlerCB
r_anal_esil_get_interrupt.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.c_uint32]
r_anal_esil_del_interrupt = _libr_anal.r_anal_esil_del_interrupt
r_anal_esil_del_interrupt.restype = None
r_anal_esil_del_interrupt.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.c_uint32]
r_anal_esil_set_syscall = _libr_anal.r_anal_esil_set_syscall
r_anal_esil_set_syscall.restype = ctypes.c_bool
r_anal_esil_set_syscall.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.c_uint32, RAnalEsilHandlerCB, ctypes.POINTER(None)]
r_anal_esil_get_syscall = _libr_anal.r_anal_esil_get_syscall
r_anal_esil_get_syscall.restype = RAnalEsilHandlerCB
r_anal_esil_get_syscall.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.c_uint32]
r_anal_esil_del_syscall = _libr_anal.r_anal_esil_del_syscall
r_anal_esil_del_syscall.restype = None
r_anal_esil_del_syscall.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.c_uint32]
r_anal_esil_fire_interrupt = _libr_anal.r_anal_esil_fire_interrupt
r_anal_esil_fire_interrupt.restype = ctypes.c_int32
r_anal_esil_fire_interrupt.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.c_uint32]
r_anal_esil_do_syscall = _libr_anal.r_anal_esil_do_syscall
r_anal_esil_do_syscall.restype = ctypes.c_int32
r_anal_esil_do_syscall.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.c_uint32]
r_anal_esil_handlers_fini = _libr_anal.r_anal_esil_handlers_fini
r_anal_esil_handlers_fini.restype = None
r_anal_esil_handlers_fini.argtypes = [ctypes.POINTER(struct_r_anal_esil_t)]
r_anal_esil_plugins_init = _libr_anal.r_anal_esil_plugins_init
r_anal_esil_plugins_init.restype = None
r_anal_esil_plugins_init.argtypes = [ctypes.POINTER(struct_r_anal_esil_t)]
r_anal_esil_plugins_fini = _libr_anal.r_anal_esil_plugins_fini
r_anal_esil_plugins_fini.restype = None
r_anal_esil_plugins_fini.argtypes = [ctypes.POINTER(struct_r_anal_esil_t)]
r_anal_esil_plugin_add = _libr_anal.r_anal_esil_plugin_add
r_anal_esil_plugin_add.restype = ctypes.c_bool
r_anal_esil_plugin_add.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.POINTER(struct_r_anal_esil_plugin_t)]
r_anal_esil_plugin_activate = _libr_anal.r_anal_esil_plugin_activate
r_anal_esil_plugin_activate.restype = ctypes.c_bool
r_anal_esil_plugin_activate.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.POINTER(ctypes.c_char)]
r_anal_esil_plugin_deactivate = _libr_anal.r_anal_esil_plugin_deactivate
r_anal_esil_plugin_deactivate.restype = None
r_anal_esil_plugin_deactivate.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.POINTER(ctypes.c_char)]
r_anal_esil_mem_ro = _libr_anal.r_anal_esil_mem_ro
r_anal_esil_mem_ro.restype = None
r_anal_esil_mem_ro.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.c_int32]
r_anal_esil_stats = _libr_anal.r_anal_esil_stats
r_anal_esil_stats.restype = None
r_anal_esil_stats.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.c_int32]
r_anal_esil_trace_new = _libr_anal.r_anal_esil_trace_new
r_anal_esil_trace_new.restype = ctypes.POINTER(struct_r_anal_esil_trace_t)
r_anal_esil_trace_new.argtypes = [ctypes.POINTER(struct_r_anal_esil_t)]
r_anal_esil_trace_free = _libr_anal.r_anal_esil_trace_free
r_anal_esil_trace_free.restype = None
r_anal_esil_trace_free.argtypes = [ctypes.POINTER(struct_r_anal_esil_trace_t)]
r_anal_esil_trace_op = _libr_anal.r_anal_esil_trace_op
r_anal_esil_trace_op.restype = None
r_anal_esil_trace_op.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.POINTER(struct_r_anal_op_t)]
r_anal_esil_trace_list = _libr_anal.r_anal_esil_trace_list
r_anal_esil_trace_list.restype = None
r_anal_esil_trace_list.argtypes = [ctypes.POINTER(struct_r_anal_esil_t)]
r_anal_esil_trace_show = _libr_anal.r_anal_esil_trace_show
r_anal_esil_trace_show.restype = None
r_anal_esil_trace_show.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.c_int32]
r_anal_esil_trace_restore = _libr_anal.r_anal_esil_trace_restore
r_anal_esil_trace_restore.restype = None
r_anal_esil_trace_restore.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.c_int32]
r_anal_pin_init = _libr_anal.r_anal_pin_init
r_anal_pin_init.restype = None
r_anal_pin_init.argtypes = [ctypes.POINTER(struct_r_anal_t)]
r_anal_pin_fini = _libr_anal.r_anal_pin_fini
r_anal_pin_fini.restype = None
r_anal_pin_fini.argtypes = [ctypes.POINTER(struct_r_anal_t)]
r_anal_pin = _libr_anal.r_anal_pin
r_anal_pin.restype = None
r_anal_pin.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_char)]
r_anal_pin_unset = _libr_anal.r_anal_pin_unset
r_anal_pin_unset.restype = None
r_anal_pin_unset.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_pin_call = _libr_anal.r_anal_pin_call
r_anal_pin_call.restype = ctypes.POINTER(ctypes.c_char)
r_anal_pin_call.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_pin_list = _libr_anal.r_anal_pin_list
r_anal_pin_list.restype = None
r_anal_pin_list.argtypes = [ctypes.POINTER(struct_r_anal_t)]
r_anal_function_cost = _libr_anal.r_anal_function_cost
r_anal_function_cost.restype = ctypes.c_uint32
r_anal_function_cost.argtypes = [ctypes.POINTER(struct_r_anal_function_t)]
r_anal_function_count_edges = _libr_anal.r_anal_function_count_edges
r_anal_function_count_edges.restype = ctypes.c_int32
r_anal_function_count_edges.argtypes = [ctypes.POINTER(struct_r_anal_function_t), ctypes.POINTER(ctypes.c_int32)]
r_anal_get_fcn_in = _libr_anal.r_anal_get_fcn_in
r_anal_get_fcn_in.restype = ctypes.POINTER(struct_r_anal_function_t)
r_anal_get_fcn_in.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_int32]
r_anal_get_fcn_in_bounds = _libr_anal.r_anal_get_fcn_in_bounds
r_anal_get_fcn_in_bounds.restype = ctypes.POINTER(struct_r_anal_function_t)
r_anal_get_fcn_in_bounds.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_int32]
r_anal_get_function_byname = _libr_anal.r_anal_get_function_byname
r_anal_get_function_byname.restype = ctypes.POINTER(struct_r_anal_function_t)
r_anal_get_function_byname.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_fcn = _libr_anal.r_anal_fcn
r_anal_fcn.restype = ctypes.c_int32
r_anal_fcn.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_function_t), ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int32]
r_anal_fcn_del = _libr_anal.r_anal_fcn_del
r_anal_fcn_del.restype = ctypes.c_int32
r_anal_fcn_del.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_fcn_del_locs = _libr_anal.r_anal_fcn_del_locs
r_anal_fcn_del_locs.restype = ctypes.c_int32
r_anal_fcn_del_locs.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_fcn_add_bb = _libr_anal.r_anal_fcn_add_bb
r_anal_fcn_add_bb.restype = ctypes.c_bool
r_anal_fcn_add_bb.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_function_t), ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.POINTER(struct_r_anal_diff_t)]
r_anal_check_fcn = _libr_anal.r_anal_check_fcn
r_anal_check_fcn.restype = ctypes.c_bool
r_anal_check_fcn.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint16, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64]
r_anal_fcn_invalidate_read_ahead_cache = _libr_anal.r_anal_fcn_invalidate_read_ahead_cache
r_anal_fcn_invalidate_read_ahead_cache.restype = None
r_anal_fcn_invalidate_read_ahead_cache.argtypes = []
r_anal_function_check_bp_use = _libr_anal.r_anal_function_check_bp_use
r_anal_function_check_bp_use.restype = None
r_anal_function_check_bp_use.argtypes = [ctypes.POINTER(struct_r_anal_function_t)]
r_anal_update_analysis_range = _libr_anal.r_anal_update_analysis_range
r_anal_update_analysis_range.restype = None
r_anal_update_analysis_range.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_int32]
r_anal_function_update_analysis = _libr_anal.r_anal_function_update_analysis
r_anal_function_update_analysis.restype = None
r_anal_function_update_analysis.argtypes = [ctypes.POINTER(struct_r_anal_function_t)]
r_anal_fcn_var_del_byindex = _libraries['FIXME_STUB'].r_anal_fcn_var_del_byindex
r_anal_fcn_var_del_byindex.restype = ctypes.c_int32
r_anal_fcn_var_del_byindex.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_char, ctypes.c_int32, ctypes.c_uint32]
r_anal_var_count = _libr_anal.r_anal_var_count
r_anal_var_count.restype = ctypes.c_int32
r_anal_var_count.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_function_t), ctypes.c_int32, ctypes.c_int32]
r_anal_var_display = _libr_anal.r_anal_var_display
r_anal_var_display.restype = ctypes.c_bool
r_anal_var_display.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_var_t)]
r_anal_function_complexity = _libr_anal.r_anal_function_complexity
r_anal_function_complexity.restype = ctypes.c_int32
r_anal_function_complexity.argtypes = [ctypes.POINTER(struct_r_anal_function_t)]
r_anal_function_loops = _libr_anal.r_anal_function_loops
r_anal_function_loops.restype = ctypes.c_int32
r_anal_function_loops.argtypes = [ctypes.POINTER(struct_r_anal_function_t)]
r_anal_trim_jmprefs = _libr_anal.r_anal_trim_jmprefs
r_anal_trim_jmprefs.restype = None
r_anal_trim_jmprefs.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_function_t)]
r_anal_del_jmprefs = _libr_anal.r_anal_del_jmprefs
r_anal_del_jmprefs.restype = None
r_anal_del_jmprefs.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_function_t)]
r_anal_function_get_json = _libr_anal.r_anal_function_get_json
r_anal_function_get_json.restype = ctypes.POINTER(ctypes.c_char)
r_anal_function_get_json.argtypes = [ctypes.POINTER(struct_r_anal_function_t)]
r_anal_fcn_next = _libr_anal.r_anal_fcn_next
r_anal_fcn_next.restype = ctypes.POINTER(struct_r_anal_function_t)
r_anal_fcn_next.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_function_get_signature = _libr_anal.r_anal_function_get_signature
r_anal_function_get_signature.restype = ctypes.POINTER(ctypes.c_char)
r_anal_function_get_signature.argtypes = [ctypes.POINTER(struct_r_anal_function_t)]
r_anal_str_to_fcn = _libr_anal.r_anal_str_to_fcn
r_anal_str_to_fcn.restype = ctypes.c_int32
r_anal_str_to_fcn.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_function_t), ctypes.POINTER(ctypes.c_char)]
r_anal_fcn_count = _libr_anal.r_anal_fcn_count
r_anal_fcn_count.restype = ctypes.c_int32
r_anal_fcn_count.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_uint64]
r_anal_fcn_bbget_in = _libr_anal.r_anal_fcn_bbget_in
r_anal_fcn_bbget_in.restype = ctypes.POINTER(struct_r_anal_bb_t)
r_anal_fcn_bbget_in.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_function_t), ctypes.c_uint64]
r_anal_fcn_bbget_at = _libr_anal.r_anal_fcn_bbget_at
r_anal_fcn_bbget_at.restype = ctypes.POINTER(struct_r_anal_bb_t)
r_anal_fcn_bbget_at.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_function_t), ctypes.c_uint64]
r_anal_fcn_bbadd = _libraries['FIXME_STUB'].r_anal_fcn_bbadd
r_anal_fcn_bbadd.restype = ctypes.c_bool
r_anal_fcn_bbadd.argtypes = [ctypes.POINTER(struct_r_anal_function_t), ctypes.POINTER(struct_r_anal_bb_t)]
r_anal_function_resize = _libr_anal.r_anal_function_resize
r_anal_function_resize.restype = ctypes.c_int32
r_anal_function_resize.argtypes = [ctypes.POINTER(struct_r_anal_function_t), ctypes.c_int32]
r_anal_function_purity = _libr_anal.r_anal_function_purity
r_anal_function_purity.restype = ctypes.c_bool
r_anal_function_purity.argtypes = [ctypes.POINTER(struct_r_anal_function_t)]
RAnalRefCmp = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_anal_ref_t), ctypes.POINTER(None))
r_anal_ref_list_new = _libr_anal.r_anal_ref_list_new
r_anal_ref_list_new.restype = ctypes.POINTER(struct_r_list_t)
r_anal_ref_list_new.argtypes = []
r_anal_xrefs_count = _libr_anal.r_anal_xrefs_count
r_anal_xrefs_count.restype = ctypes.c_uint64
r_anal_xrefs_count.argtypes = [ctypes.POINTER(struct_r_anal_t)]
r_anal_xrefs_type_tostring = _libr_anal.r_anal_xrefs_type_tostring
r_anal_xrefs_type_tostring.restype = ctypes.POINTER(ctypes.c_char)
r_anal_xrefs_type_tostring.argtypes = [RAnalRefType]
r_anal_xrefs_type = _libr_anal.r_anal_xrefs_type
r_anal_xrefs_type.restype = RAnalRefType
r_anal_xrefs_type.argtypes = [ctypes.c_char]
r_anal_xrefs_get = _libr_anal.r_anal_xrefs_get
r_anal_xrefs_get.restype = ctypes.POINTER(struct_r_list_t)
r_anal_xrefs_get.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_refs_get = _libr_anal.r_anal_refs_get
r_anal_refs_get.restype = ctypes.POINTER(struct_r_list_t)
r_anal_refs_get.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_xrefs_get_from = _libr_anal.r_anal_xrefs_get_from
r_anal_xrefs_get_from.restype = ctypes.POINTER(struct_r_list_t)
r_anal_xrefs_get_from.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_xrefs_list = _libr_anal.r_anal_xrefs_list
r_anal_xrefs_list.restype = None
r_anal_xrefs_list.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_int32]
r_anal_function_get_refs = _libr_anal.r_anal_function_get_refs
r_anal_function_get_refs.restype = ctypes.POINTER(struct_r_list_t)
r_anal_function_get_refs.argtypes = [ctypes.POINTER(struct_r_anal_function_t)]
r_anal_function_get_xrefs = _libr_anal.r_anal_function_get_xrefs
r_anal_function_get_xrefs.restype = ctypes.POINTER(struct_r_list_t)
r_anal_function_get_xrefs.argtypes = [ctypes.POINTER(struct_r_anal_function_t)]
r_anal_xrefs_from = _libr_anal.r_anal_xrefs_from
r_anal_xrefs_from.restype = ctypes.c_int32
r_anal_xrefs_from.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_list_t), ctypes.POINTER(ctypes.c_char), RAnalRefType, ctypes.c_uint64]
r_anal_xrefs_set = _libr_anal.r_anal_xrefs_set
r_anal_xrefs_set.restype = ctypes.c_int32
r_anal_xrefs_set.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_uint64, RAnalRefType]
r_anal_xrefs_deln = _libr_anal.r_anal_xrefs_deln
r_anal_xrefs_deln.restype = ctypes.c_int32
r_anal_xrefs_deln.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_uint64, RAnalRefType]
r_anal_xref_del = _libr_anal.r_anal_xref_del
r_anal_xref_del.restype = ctypes.c_int32
r_anal_xref_del.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_uint64]
r_anal_get_fcns = _libr_anal.r_anal_get_fcns
r_anal_get_fcns.restype = ctypes.POINTER(struct_r_list_t)
r_anal_get_fcns.argtypes = [ctypes.POINTER(struct_r_anal_t)]
r_anal_remove_parsed_type = _libr_anal.r_anal_remove_parsed_type
r_anal_remove_parsed_type.restype = None
r_anal_remove_parsed_type.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_save_parsed_type = _libr_anal.r_anal_save_parsed_type
r_anal_save_parsed_type.restype = None
r_anal_save_parsed_type.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_function_autoname_var = _libr_anal.r_anal_function_autoname_var
r_anal_function_autoname_var.restype = ctypes.POINTER(ctypes.c_char)
r_anal_function_autoname_var.argtypes = [ctypes.POINTER(struct_r_anal_function_t), ctypes.c_char, ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_anal_function_set_var = _libr_anal.r_anal_function_set_var
r_anal_function_set_var.restype = ctypes.POINTER(struct_r_anal_var_t)
r_anal_function_set_var.argtypes = [ctypes.POINTER(struct_r_anal_function_t), ctypes.c_int32, ctypes.c_char, ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_bool, ctypes.POINTER(ctypes.c_char)]
r_anal_function_get_var = _libr_anal.r_anal_function_get_var
r_anal_function_get_var.restype = ctypes.POINTER(struct_r_anal_var_t)
r_anal_function_get_var.argtypes = [ctypes.POINTER(struct_r_anal_function_t), ctypes.c_char, ctypes.c_int32]
r_anal_function_get_var_byname = _libr_anal.r_anal_function_get_var_byname
r_anal_function_get_var_byname.restype = ctypes.POINTER(struct_r_anal_var_t)
r_anal_function_get_var_byname.argtypes = [ctypes.POINTER(struct_r_anal_function_t), ctypes.POINTER(ctypes.c_char)]
r_anal_function_delete_vars_by_kind = _libr_anal.r_anal_function_delete_vars_by_kind
r_anal_function_delete_vars_by_kind.restype = None
r_anal_function_delete_vars_by_kind.argtypes = [ctypes.POINTER(struct_r_anal_function_t), RAnalVarKind]
r_anal_function_delete_all_vars = _libr_anal.r_anal_function_delete_all_vars
r_anal_function_delete_all_vars.restype = None
r_anal_function_delete_all_vars.argtypes = [ctypes.POINTER(struct_r_anal_function_t)]
r_anal_function_delete_unused_vars = _libr_anal.r_anal_function_delete_unused_vars
r_anal_function_delete_unused_vars.restype = None
r_anal_function_delete_unused_vars.argtypes = [ctypes.POINTER(struct_r_anal_function_t)]
r_anal_function_delete_var = _libr_anal.r_anal_function_delete_var
r_anal_function_delete_var.restype = None
r_anal_function_delete_var.argtypes = [ctypes.POINTER(struct_r_anal_function_t), ctypes.POINTER(struct_r_anal_var_t)]
r_anal_function_rebase_vars = _libr_anal.r_anal_function_rebase_vars
r_anal_function_rebase_vars.restype = ctypes.c_bool
r_anal_function_rebase_vars.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_function_t)]
r_anal_function_get_var_stackptr_at = _libr_anal.r_anal_function_get_var_stackptr_at
r_anal_function_get_var_stackptr_at.restype = ctypes.c_int64
r_anal_function_get_var_stackptr_at.argtypes = [ctypes.POINTER(struct_r_anal_function_t), ctypes.c_int64, ctypes.c_uint64]
r_anal_function_get_var_reg_at = _libr_anal.r_anal_function_get_var_reg_at
r_anal_function_get_var_reg_at.restype = ctypes.POINTER(ctypes.c_char)
r_anal_function_get_var_reg_at.argtypes = [ctypes.POINTER(struct_r_anal_function_t), ctypes.c_int64, ctypes.c_uint64]
r_anal_function_get_vars_used_at = _libr_anal.r_anal_function_get_vars_used_at
r_anal_function_get_vars_used_at.restype = ctypes.POINTER(struct_r_pvector_t)
r_anal_function_get_vars_used_at.argtypes = [ctypes.POINTER(struct_r_anal_function_t), ctypes.c_uint64]
r_anal_get_used_function_var = _libr_anal.r_anal_get_used_function_var
r_anal_get_used_function_var.restype = ctypes.POINTER(struct_r_anal_var_t)
r_anal_get_used_function_var.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_var_rename = _libr_anal.r_anal_var_rename
r_anal_var_rename.restype = ctypes.c_bool
r_anal_var_rename.argtypes = [ctypes.POINTER(struct_r_anal_var_t), ctypes.POINTER(ctypes.c_char), ctypes.c_bool]
r_anal_var_set_type = _libr_anal.r_anal_var_set_type
r_anal_var_set_type.restype = None
r_anal_var_set_type.argtypes = [ctypes.POINTER(struct_r_anal_var_t), ctypes.POINTER(ctypes.c_char)]
r_anal_var_delete = _libr_anal.r_anal_var_delete
r_anal_var_delete.restype = None
r_anal_var_delete.argtypes = [ctypes.POINTER(struct_r_anal_var_t)]
r_anal_var_addr = _libr_anal.r_anal_var_addr
r_anal_var_addr.restype = ctypes.c_uint64
r_anal_var_addr.argtypes = [ctypes.POINTER(struct_r_anal_var_t)]
r_anal_var_set_access = _libr_anal.r_anal_var_set_access
r_anal_var_set_access.restype = None
r_anal_var_set_access.argtypes = [ctypes.POINTER(struct_r_anal_var_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64, ctypes.c_int32, ctypes.c_int64]
r_anal_var_remove_access_at = _libr_anal.r_anal_var_remove_access_at
r_anal_var_remove_access_at.restype = None
r_anal_var_remove_access_at.argtypes = [ctypes.POINTER(struct_r_anal_var_t), ctypes.c_uint64]
r_anal_var_clear_accesses = _libr_anal.r_anal_var_clear_accesses
r_anal_var_clear_accesses.restype = None
r_anal_var_clear_accesses.argtypes = [ctypes.POINTER(struct_r_anal_var_t)]
r_anal_var_add_constraint = _libr_anal.r_anal_var_add_constraint
r_anal_var_add_constraint.restype = None
r_anal_var_add_constraint.argtypes = [ctypes.POINTER(struct_r_anal_var_t), ctypes.POINTER(struct_r_anal_var_constraint_t)]
r_anal_var_get_constraints_readable = _libr_anal.r_anal_var_get_constraints_readable
r_anal_var_get_constraints_readable.restype = ctypes.POINTER(ctypes.c_char)
r_anal_var_get_constraints_readable.argtypes = [ctypes.POINTER(struct_r_anal_var_t)]
r_anal_var_get_access_at = _libr_anal.r_anal_var_get_access_at
r_anal_var_get_access_at.restype = ctypes.POINTER(struct_r_anal_var_access_t)
r_anal_var_get_access_at.argtypes = [ctypes.POINTER(struct_r_anal_var_t), ctypes.c_uint64]
r_anal_var_get_argnum = _libr_anal.r_anal_var_get_argnum
r_anal_var_get_argnum.restype = ctypes.c_int32
r_anal_var_get_argnum.argtypes = [ctypes.POINTER(struct_r_anal_var_t)]
r_anal_extract_vars = _libr_anal.r_anal_extract_vars
r_anal_extract_vars.restype = None
r_anal_extract_vars.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_function_t), ctypes.POINTER(struct_r_anal_op_t)]
r_anal_extract_rarg = _libr_anal.r_anal_extract_rarg
r_anal_extract_rarg.restype = None
r_anal_extract_rarg.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_op_t), ctypes.POINTER(struct_r_anal_function_t), ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32)]
r_anal_var_get_dst_var = _libr_anal.r_anal_var_get_dst_var
r_anal_var_get_dst_var.restype = ctypes.POINTER(struct_r_anal_var_t)
r_anal_var_get_dst_var.argtypes = [ctypes.POINTER(struct_r_anal_var_t)]
class struct_r_anal_fcn_vars_cache(Structure):
    pass

struct_r_anal_fcn_vars_cache._pack_ = 1 # source:False
struct_r_anal_fcn_vars_cache._fields_ = [
    ('bvars', ctypes.POINTER(struct_r_list_t)),
    ('rvars', ctypes.POINTER(struct_r_list_t)),
    ('svars', ctypes.POINTER(struct_r_list_t)),
]

RAnalFcnVarsCache = struct_r_anal_fcn_vars_cache
r_anal_fcn_vars_cache_init = _libr_anal.r_anal_fcn_vars_cache_init
r_anal_fcn_vars_cache_init.restype = None
r_anal_fcn_vars_cache_init.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_fcn_vars_cache), ctypes.POINTER(struct_r_anal_function_t)]
r_anal_fcn_vars_cache_fini = _libr_anal.r_anal_fcn_vars_cache_fini
r_anal_fcn_vars_cache_fini.restype = None
r_anal_fcn_vars_cache_fini.argtypes = [ctypes.POINTER(struct_r_anal_fcn_vars_cache)]
r_anal_fcn_format_sig = _libr_anal.r_anal_fcn_format_sig
r_anal_fcn_format_sig.restype = ctypes.POINTER(ctypes.c_char)
r_anal_fcn_format_sig.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_function_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_anal_fcn_vars_cache), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_anal_xrefs_init = _libr_anal.r_anal_xrefs_init
r_anal_xrefs_init.restype = ctypes.c_bool
r_anal_xrefs_init.argtypes = [ctypes.POINTER(struct_r_anal_t)]
r_anal_diff_new = _libr_anal.r_anal_diff_new
r_anal_diff_new.restype = ctypes.POINTER(struct_r_anal_diff_t)
r_anal_diff_new.argtypes = []
r_anal_diff_setup = _libr_anal.r_anal_diff_setup
r_anal_diff_setup.restype = None
r_anal_diff_setup.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_int32, ctypes.c_double, ctypes.c_double]
r_anal_diff_setup_i = _libr_anal.r_anal_diff_setup_i
r_anal_diff_setup_i.restype = None
r_anal_diff_setup_i.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
r_anal_diff_free = _libr_anal.r_anal_diff_free
r_anal_diff_free.restype = ctypes.POINTER(None)
r_anal_diff_free.argtypes = [ctypes.POINTER(struct_r_anal_diff_t)]
r_anal_diff_fingerprint_bb = _libr_anal.r_anal_diff_fingerprint_bb
r_anal_diff_fingerprint_bb.restype = ctypes.c_int32
r_anal_diff_fingerprint_bb.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_bb_t)]
size_t = ctypes.c_uint64
r_anal_diff_fingerprint_fcn = _libr_anal.r_anal_diff_fingerprint_fcn
r_anal_diff_fingerprint_fcn.restype = size_t
r_anal_diff_fingerprint_fcn.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_function_t)]
r_anal_diff_bb = _libr_anal.r_anal_diff_bb
r_anal_diff_bb.restype = ctypes.c_bool
r_anal_diff_bb.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_function_t), ctypes.POINTER(struct_r_anal_function_t)]
r_anal_diff_fcn = _libr_anal.r_anal_diff_fcn
r_anal_diff_fcn.restype = ctypes.c_int32
r_anal_diff_fcn.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_list_t)]
r_anal_diff_eval = _libr_anal.r_anal_diff_eval
r_anal_diff_eval.restype = ctypes.c_int32
r_anal_diff_eval.argtypes = [ctypes.POINTER(struct_r_anal_t)]
r_anal_value_new = _libr_anal.r_anal_value_new
r_anal_value_new.restype = ctypes.POINTER(struct_r_anal_value_t)
r_anal_value_new.argtypes = []
r_anal_value_copy = _libr_anal.r_anal_value_copy
r_anal_value_copy.restype = ctypes.POINTER(struct_r_anal_value_t)
r_anal_value_copy.argtypes = [ctypes.POINTER(struct_r_anal_value_t)]
r_anal_value_new_from_string = _libr_anal.r_anal_value_new_from_string
r_anal_value_new_from_string.restype = ctypes.POINTER(struct_r_anal_value_t)
r_anal_value_new_from_string.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_anal_value_eval = _libraries['FIXME_STUB'].r_anal_value_eval
r_anal_value_eval.restype = ctypes.c_int64
r_anal_value_eval.argtypes = [ctypes.POINTER(struct_r_anal_value_t)]
r_anal_value_to_string = _libr_anal.r_anal_value_to_string
r_anal_value_to_string.restype = ctypes.POINTER(ctypes.c_char)
r_anal_value_to_string.argtypes = [ctypes.POINTER(struct_r_anal_value_t)]
r_anal_value_to_ut64 = _libr_anal.r_anal_value_to_ut64
r_anal_value_to_ut64.restype = ctypes.c_uint64
r_anal_value_to_ut64.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_value_t)]
r_anal_value_set_ut64 = _libr_anal.r_anal_value_set_ut64
r_anal_value_set_ut64.restype = ctypes.c_int32
r_anal_value_set_ut64.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_value_t), ctypes.c_uint64]
r_anal_value_free = _libr_anal.r_anal_value_free
r_anal_value_free.restype = None
r_anal_value_free.argtypes = [ctypes.POINTER(struct_r_anal_value_t)]
r_anal_cond_new = _libr_anal.r_anal_cond_new
r_anal_cond_new.restype = ctypes.POINTER(struct_r_anal_cond_t)
r_anal_cond_new.argtypes = []
r_anal_cond_new_from_op = _libr_anal.r_anal_cond_new_from_op
r_anal_cond_new_from_op.restype = ctypes.POINTER(struct_r_anal_cond_t)
r_anal_cond_new_from_op.argtypes = [ctypes.POINTER(struct_r_anal_op_t)]
r_anal_cond_fini = _libr_anal.r_anal_cond_fini
r_anal_cond_fini.restype = None
r_anal_cond_fini.argtypes = [ctypes.POINTER(struct_r_anal_cond_t)]
r_anal_cond_free = _libr_anal.r_anal_cond_free
r_anal_cond_free.restype = None
r_anal_cond_free.argtypes = [ctypes.POINTER(struct_r_anal_cond_t)]
r_anal_cond_to_string = _libr_anal.r_anal_cond_to_string
r_anal_cond_to_string.restype = ctypes.POINTER(ctypes.c_char)
r_anal_cond_to_string.argtypes = [ctypes.POINTER(struct_r_anal_cond_t)]
r_anal_cond_eval = _libr_anal.r_anal_cond_eval
r_anal_cond_eval.restype = ctypes.c_int32
r_anal_cond_eval.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_cond_t)]
r_anal_cond_new_from_string = _libr_anal.r_anal_cond_new_from_string
r_anal_cond_new_from_string.restype = ctypes.POINTER(struct_r_anal_cond_t)
r_anal_cond_new_from_string.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_anal_cond_tostring = _libr_anal.r_anal_cond_tostring
r_anal_cond_tostring.restype = ctypes.POINTER(ctypes.c_char)
r_anal_cond_tostring.argtypes = [ctypes.c_int32]
r_anal_jmptbl = _libr_anal.r_anal_jmptbl
r_anal_jmptbl.restype = ctypes.c_bool
r_anal_jmptbl.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_function_t), ctypes.POINTER(struct_r_anal_bb_t), ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64]
try_get_delta_jmptbl_info = _libr_anal.try_get_delta_jmptbl_info
try_get_delta_jmptbl_info.restype = ctypes.c_bool
try_get_delta_jmptbl_info.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_function_t), ctypes.c_uint64, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_int64)]
try_walkthrough_jmptbl = _libr_anal.try_walkthrough_jmptbl
try_walkthrough_jmptbl.restype = ctypes.c_bool
try_walkthrough_jmptbl.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_function_t), ctypes.POINTER(struct_r_anal_bb_t), ctypes.c_int32, ctypes.c_uint64, ctypes.c_int64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_bool]
try_walkthrough_casetbl = _libr_anal.try_walkthrough_casetbl
try_walkthrough_casetbl.restype = ctypes.c_bool
try_walkthrough_casetbl.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_function_t), ctypes.POINTER(struct_r_anal_bb_t), ctypes.c_int32, ctypes.c_uint64, ctypes.c_int64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_bool]
try_get_jmptbl_info = _libr_anal.try_get_jmptbl_info
try_get_jmptbl_info.restype = ctypes.c_bool
try_get_jmptbl_info.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_function_t), ctypes.c_uint64, ctypes.POINTER(struct_r_anal_bb_t), ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_int64)]
walkthrough_arm_jmptbl_style = _libr_anal.walkthrough_arm_jmptbl_style
walkthrough_arm_jmptbl_style.restype = ctypes.c_int32
walkthrough_arm_jmptbl_style.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_function_t), ctypes.POINTER(struct_r_anal_bb_t), ctypes.c_int32, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int32]
r_anal_reflines_get = _libr_anal.r_anal_reflines_get
r_anal_reflines_get.restype = ctypes.POINTER(struct_r_list_t)
r_anal_reflines_get.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
r_anal_reflines_middle = _libr_anal.r_anal_reflines_middle
r_anal_reflines_middle.restype = ctypes.c_int32
r_anal_reflines_middle.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_list_t), ctypes.c_uint64, ctypes.c_int32]
r_anal_reflines_str = _libr_anal.r_anal_reflines_str
r_anal_reflines_str.restype = ctypes.POINTER(struct_r_anal_ref_char)
r_anal_reflines_str.argtypes = [ctypes.POINTER(None), ctypes.c_uint64, ctypes.c_int32]
r_anal_reflines_str_free = _libr_anal.r_anal_reflines_str_free
r_anal_reflines_str_free.restype = None
r_anal_reflines_str_free.argtypes = [ctypes.POINTER(struct_r_anal_ref_char)]
r_anal_var_list_show = _libr_anal.r_anal_var_list_show
r_anal_var_list_show.restype = None
r_anal_var_list_show.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_function_t), ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(struct_pj_t)]
r_anal_var_list = _libr_anal.r_anal_var_list
r_anal_var_list.restype = ctypes.POINTER(struct_r_list_t)
r_anal_var_list.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_function_t), ctypes.c_int32]
r_anal_var_all_list = _libr_anal.r_anal_var_all_list
r_anal_var_all_list.restype = ctypes.POINTER(struct_r_list_t)
r_anal_var_all_list.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_function_t)]
r_anal_function_get_var_fields = _libr_anal.r_anal_function_get_var_fields
r_anal_function_get_var_fields.restype = ctypes.POINTER(struct_r_list_t)
r_anal_function_get_var_fields.argtypes = [ctypes.POINTER(struct_r_anal_function_t), ctypes.c_int32]
r_anal_cc_exist = _libr_anal.r_anal_cc_exist
r_anal_cc_exist.restype = ctypes.c_bool
r_anal_cc_exist.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_cc_del = _libr_anal.r_anal_cc_del
r_anal_cc_del.restype = None
r_anal_cc_del.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_cc_set = _libr_anal.r_anal_cc_set
r_anal_cc_set.restype = ctypes.c_bool
r_anal_cc_set.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_cc_get = _libr_anal.r_anal_cc_get
r_anal_cc_get.restype = ctypes.POINTER(ctypes.c_char)
r_anal_cc_get.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_cc_once = _libr_anal.r_anal_cc_once
r_anal_cc_once.restype = ctypes.c_bool
r_anal_cc_once.argtypes = [ctypes.POINTER(struct_r_anal_t)]
r_anal_cc_get_json = _libr_anal.r_anal_cc_get_json
r_anal_cc_get_json.restype = None
r_anal_cc_get_json.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_pj_t), ctypes.POINTER(ctypes.c_char)]
r_anal_cc_arg = _libr_anal.r_anal_cc_arg
r_anal_cc_arg.restype = ctypes.POINTER(ctypes.c_char)
r_anal_cc_arg.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_anal_cc_self = _libr_anal.r_anal_cc_self
r_anal_cc_self.restype = ctypes.POINTER(ctypes.c_char)
r_anal_cc_self.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_cc_set_self = _libr_anal.r_anal_cc_set_self
r_anal_cc_set_self.restype = None
r_anal_cc_set_self.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_anal_cc_error = _libr_anal.r_anal_cc_error
r_anal_cc_error.restype = ctypes.POINTER(ctypes.c_char)
r_anal_cc_error.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_cc_set_error = _libr_anal.r_anal_cc_set_error
r_anal_cc_set_error.restype = None
r_anal_cc_set_error.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_anal_cc_max_arg = _libr_anal.r_anal_cc_max_arg
r_anal_cc_max_arg.restype = ctypes.c_int32
r_anal_cc_max_arg.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_cc_ret = _libr_anal.r_anal_cc_ret
r_anal_cc_ret.restype = ctypes.POINTER(ctypes.c_char)
r_anal_cc_ret.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_cc_default = _libr_anal.r_anal_cc_default
r_anal_cc_default.restype = ctypes.POINTER(ctypes.c_char)
r_anal_cc_default.argtypes = [ctypes.POINTER(struct_r_anal_t)]
r_anal_set_cc_default = _libr_anal.r_anal_set_cc_default
r_anal_set_cc_default.restype = None
r_anal_set_cc_default.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_syscc_default = _libr_anal.r_anal_syscc_default
r_anal_syscc_default.restype = ctypes.POINTER(ctypes.c_char)
r_anal_syscc_default.argtypes = [ctypes.POINTER(struct_r_anal_t)]
r_anal_set_syscc_default = _libr_anal.r_anal_set_syscc_default
r_anal_set_syscc_default.restype = None
r_anal_set_syscc_default.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_cc_func = _libr_anal.r_anal_cc_func
r_anal_cc_func.restype = ctypes.POINTER(ctypes.c_char)
r_anal_cc_func.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_noreturn_at = _libr_anal.r_anal_noreturn_at
r_anal_noreturn_at.restype = ctypes.c_bool
r_anal_noreturn_at.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
class struct_r_anal_data_t(Structure):
    pass

struct_r_anal_data_t._pack_ = 1 # source:False
struct_r_anal_data_t._fields_ = [
    ('addr', ctypes.c_uint64),
    ('type', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('ptr', ctypes.c_uint64),
    ('str', ctypes.POINTER(ctypes.c_char)),
    ('len', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
    ('buf', ctypes.POINTER(ctypes.c_ubyte)),
    ('sbuf', ctypes.c_ubyte * 8),
]

RAnalData = struct_r_anal_data_t
r_anal_data = _libr_anal.r_anal_data
r_anal_data.restype = ctypes.POINTER(struct_r_anal_data_t)
r_anal_data.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.c_int32]
r_anal_data_kind = _libr_anal.r_anal_data_kind
r_anal_data_kind.restype = ctypes.POINTER(ctypes.c_char)
r_anal_data_kind.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_anal_data_new_string = _libr_anal.r_anal_data_new_string
r_anal_data_new_string.restype = ctypes.POINTER(struct_r_anal_data_t)
r_anal_data_new_string.argtypes = [ctypes.c_uint64, ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32]
r_anal_data_new = _libr_anal.r_anal_data_new
r_anal_data_new.restype = ctypes.POINTER(struct_r_anal_data_t)
r_anal_data_new.argtypes = [ctypes.c_uint64, ctypes.c_int32, ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_anal_data_free = _libr_anal.r_anal_data_free
r_anal_data_free.restype = None
r_anal_data_free.argtypes = [ctypes.POINTER(struct_r_anal_data_t)]
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

r_anal_data_to_string = _libr_anal.r_anal_data_to_string
r_anal_data_to_string.restype = ctypes.POINTER(ctypes.c_char)
r_anal_data_to_string.argtypes = [ctypes.POINTER(struct_r_anal_data_t), ctypes.POINTER(struct_r_cons_printable_palette_t)]
r_meta_item_size = _libraries['FIXME_STUB'].r_meta_item_size
r_meta_item_size.restype = ctypes.c_uint64
r_meta_item_size.argtypes = [ctypes.c_uint64, ctypes.c_uint64]
r_meta_node_size = _libraries['FIXME_STUB'].r_meta_node_size
r_meta_node_size.restype = ctypes.c_uint64
r_meta_node_size.argtypes = [ctypes.POINTER(struct_r_interval_node_t)]
r_meta_set = _libr_anal.r_meta_set
r_meta_set.restype = ctypes.c_bool
r_meta_set.argtypes = [ctypes.POINTER(struct_r_anal_t), RAnalMetaType, ctypes.c_uint64, ctypes.c_uint64, ctypes.POINTER(ctypes.c_char)]
r_meta_set_with_subtype = _libr_anal.r_meta_set_with_subtype
r_meta_set_with_subtype.restype = ctypes.c_bool
r_meta_set_with_subtype.argtypes = [ctypes.POINTER(struct_r_anal_t), RAnalMetaType, ctypes.c_int32, ctypes.c_uint64, ctypes.c_uint64, ctypes.POINTER(ctypes.c_char)]
r_meta_del = _libr_anal.r_meta_del
r_meta_del.restype = None
r_meta_del.argtypes = [ctypes.POINTER(struct_r_anal_t), RAnalMetaType, ctypes.c_uint64, ctypes.c_uint64]
r_meta_set_string = _libr_anal.r_meta_set_string
r_meta_set_string.restype = ctypes.c_bool
r_meta_set_string.argtypes = [ctypes.POINTER(struct_r_anal_t), RAnalMetaType, ctypes.c_uint64, ctypes.POINTER(ctypes.c_char)]
r_meta_get_string = _libr_anal.r_meta_get_string
r_meta_get_string.restype = ctypes.POINTER(ctypes.c_char)
r_meta_get_string.argtypes = [ctypes.POINTER(struct_r_anal_t), RAnalMetaType, ctypes.c_uint64]
r_meta_set_data_at = _libr_anal.r_meta_set_data_at
r_meta_set_data_at.restype = None
r_meta_set_data_at.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_uint64]
r_meta_get_at = _libr_anal.r_meta_get_at
r_meta_get_at.restype = ctypes.POINTER(struct_r_anal_meta_item_t)
r_meta_get_at.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, RAnalMetaType, ctypes.POINTER(ctypes.c_uint64)]
r_meta_get_in = _libr_anal.r_meta_get_in
r_meta_get_in.restype = ctypes.POINTER(struct_r_interval_node_t)
r_meta_get_in.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, RAnalMetaType]
r_meta_get_all_at = _libr_anal.r_meta_get_all_at
r_meta_get_all_at.restype = ctypes.POINTER(struct_r_pvector_t)
r_meta_get_all_at.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_meta_get_all_in = _libr_anal.r_meta_get_all_in
r_meta_get_all_in.restype = ctypes.POINTER(struct_r_pvector_t)
r_meta_get_all_in.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, RAnalMetaType]
r_meta_get_all_intersect = _libr_anal.r_meta_get_all_intersect
r_meta_get_all_intersect.restype = ctypes.POINTER(struct_r_pvector_t)
r_meta_get_all_intersect.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_uint64, RAnalMetaType]
r_meta_space_unset_for = _libr_anal.r_meta_space_unset_for
r_meta_space_unset_for.restype = None
r_meta_space_unset_for.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_space_t)]
r_meta_space_count_for = _libr_anal.r_meta_space_count_for
r_meta_space_count_for.restype = ctypes.c_int32
r_meta_space_count_for.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_space_t)]
r_meta_rebase = _libr_anal.r_meta_rebase
r_meta_rebase.restype = None
r_meta_rebase.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_meta_get_size = _libr_anal.r_meta_get_size
r_meta_get_size.restype = ctypes.c_uint64
r_meta_get_size.argtypes = [ctypes.POINTER(struct_r_anal_t), RAnalMetaType]
r_meta_type_to_string = _libr_anal.r_meta_type_to_string
r_meta_type_to_string.restype = ctypes.POINTER(ctypes.c_char)
r_meta_type_to_string.argtypes = [ctypes.c_int32]
r_meta_print = _libr_anal.r_meta_print
r_meta_print.restype = None
r_meta_print.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_meta_item_t), ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int32, ctypes.POINTER(struct_pj_t), ctypes.c_bool]
r_meta_print_list_all = _libr_anal.r_meta_print_list_all
r_meta_print_list_all.restype = None
r_meta_print_list_all.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
r_meta_print_list_at = _libr_anal.r_meta_print_list_at
r_meta_print_list_at.restype = None
r_meta_print_list_at.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
r_meta_print_list_in_function = _libr_anal.r_meta_print_list_in_function
r_meta_print_list_in_function.restype = None
r_meta_print_list_in_function.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_uint64, ctypes.POINTER(ctypes.c_char)]
r_anal_hint_del = _libr_anal.r_anal_hint_del
r_anal_hint_del.restype = None
r_anal_hint_del.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_uint64]
r_anal_hint_clear = _libr_anal.r_anal_hint_clear
r_anal_hint_clear.restype = None
r_anal_hint_clear.argtypes = [ctypes.POINTER(struct_r_anal_t)]
r_anal_hint_free = _libr_anal.r_anal_hint_free
r_anal_hint_free.restype = None
r_anal_hint_free.argtypes = [ctypes.POINTER(struct_r_anal_hint_t)]
r_anal_hint_set_syntax = _libr_anal.r_anal_hint_set_syntax
r_anal_hint_set_syntax.restype = None
r_anal_hint_set_syntax.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_char)]
r_anal_hint_set_type = _libr_anal.r_anal_hint_set_type
r_anal_hint_set_type.restype = None
r_anal_hint_set_type.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_int32]
r_anal_hint_set_jump = _libr_anal.r_anal_hint_set_jump
r_anal_hint_set_jump.restype = None
r_anal_hint_set_jump.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_uint64]
r_anal_hint_set_fail = _libr_anal.r_anal_hint_set_fail
r_anal_hint_set_fail.restype = None
r_anal_hint_set_fail.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_uint64]
r_anal_hint_set_newbits = _libr_anal.r_anal_hint_set_newbits
r_anal_hint_set_newbits.restype = None
r_anal_hint_set_newbits.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_int32]
r_anal_hint_set_nword = _libr_anal.r_anal_hint_set_nword
r_anal_hint_set_nword.restype = None
r_anal_hint_set_nword.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_int32]
r_anal_hint_set_offset = _libr_anal.r_anal_hint_set_offset
r_anal_hint_set_offset.restype = None
r_anal_hint_set_offset.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_char)]
r_anal_hint_set_immbase = _libr_anal.r_anal_hint_set_immbase
r_anal_hint_set_immbase.restype = None
r_anal_hint_set_immbase.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_int32]
r_anal_hint_set_size = _libr_anal.r_anal_hint_set_size
r_anal_hint_set_size.restype = None
r_anal_hint_set_size.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_uint64]
r_anal_hint_set_opcode = _libr_anal.r_anal_hint_set_opcode
r_anal_hint_set_opcode.restype = None
r_anal_hint_set_opcode.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_char)]
r_anal_hint_set_esil = _libr_anal.r_anal_hint_set_esil
r_anal_hint_set_esil.restype = None
r_anal_hint_set_esil.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_char)]
r_anal_hint_set_pointer = _libr_anal.r_anal_hint_set_pointer
r_anal_hint_set_pointer.restype = None
r_anal_hint_set_pointer.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_uint64]
r_anal_hint_set_ret = _libr_anal.r_anal_hint_set_ret
r_anal_hint_set_ret.restype = None
r_anal_hint_set_ret.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_uint64]
r_anal_hint_set_high = _libr_anal.r_anal_hint_set_high
r_anal_hint_set_high.restype = None
r_anal_hint_set_high.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_hint_set_stackframe = _libr_anal.r_anal_hint_set_stackframe
r_anal_hint_set_stackframe.restype = None
r_anal_hint_set_stackframe.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_uint64]
r_anal_hint_set_val = _libr_anal.r_anal_hint_set_val
r_anal_hint_set_val.restype = None
r_anal_hint_set_val.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_uint64]
r_anal_hint_set_arch = _libr_anal.r_anal_hint_set_arch
r_anal_hint_set_arch.restype = None
r_anal_hint_set_arch.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_char)]
r_anal_hint_set_bits = _libr_anal.r_anal_hint_set_bits
r_anal_hint_set_bits.restype = None
r_anal_hint_set_bits.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_int32]
r_anal_hint_unset_val = _libr_anal.r_anal_hint_unset_val
r_anal_hint_unset_val.restype = None
r_anal_hint_unset_val.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_hint_unset_high = _libr_anal.r_anal_hint_unset_high
r_anal_hint_unset_high.restype = None
r_anal_hint_unset_high.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_hint_unset_immbase = _libr_anal.r_anal_hint_unset_immbase
r_anal_hint_unset_immbase.restype = None
r_anal_hint_unset_immbase.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_hint_unset_nword = _libr_anal.r_anal_hint_unset_nword
r_anal_hint_unset_nword.restype = None
r_anal_hint_unset_nword.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_hint_unset_size = _libr_anal.r_anal_hint_unset_size
r_anal_hint_unset_size.restype = None
r_anal_hint_unset_size.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_hint_unset_type = _libr_anal.r_anal_hint_unset_type
r_anal_hint_unset_type.restype = None
r_anal_hint_unset_type.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_hint_unset_esil = _libr_anal.r_anal_hint_unset_esil
r_anal_hint_unset_esil.restype = None
r_anal_hint_unset_esil.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_hint_unset_opcode = _libr_anal.r_anal_hint_unset_opcode
r_anal_hint_unset_opcode.restype = None
r_anal_hint_unset_opcode.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_hint_unset_syntax = _libr_anal.r_anal_hint_unset_syntax
r_anal_hint_unset_syntax.restype = None
r_anal_hint_unset_syntax.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_hint_unset_pointer = _libr_anal.r_anal_hint_unset_pointer
r_anal_hint_unset_pointer.restype = None
r_anal_hint_unset_pointer.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_hint_unset_ret = _libr_anal.r_anal_hint_unset_ret
r_anal_hint_unset_ret.restype = None
r_anal_hint_unset_ret.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_hint_unset_offset = _libr_anal.r_anal_hint_unset_offset
r_anal_hint_unset_offset.restype = None
r_anal_hint_unset_offset.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_hint_unset_jump = _libr_anal.r_anal_hint_unset_jump
r_anal_hint_unset_jump.restype = None
r_anal_hint_unset_jump.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_hint_unset_fail = _libr_anal.r_anal_hint_unset_fail
r_anal_hint_unset_fail.restype = None
r_anal_hint_unset_fail.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_hint_unset_newbits = _libr_anal.r_anal_hint_unset_newbits
r_anal_hint_unset_newbits.restype = None
r_anal_hint_unset_newbits.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_hint_unset_stackframe = _libr_anal.r_anal_hint_unset_stackframe
r_anal_hint_unset_stackframe.restype = None
r_anal_hint_unset_stackframe.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_hint_unset_arch = _libr_anal.r_anal_hint_unset_arch
r_anal_hint_unset_arch.restype = None
r_anal_hint_unset_arch.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_hint_unset_bits = _libr_anal.r_anal_hint_unset_bits
r_anal_hint_unset_bits.restype = None
r_anal_hint_unset_bits.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_addr_hints_at = _libr_anal.r_anal_addr_hints_at
r_anal_addr_hints_at.restype = ctypes.POINTER(struct_r_vector_t)
r_anal_addr_hints_at.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
RAnalAddrHintRecordsCb = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_uint64, ctypes.POINTER(struct_r_vector_t), ctypes.POINTER(None))
r_anal_addr_hints_foreach = _libr_anal.r_anal_addr_hints_foreach
r_anal_addr_hints_foreach.restype = None
r_anal_addr_hints_foreach.argtypes = [ctypes.POINTER(struct_r_anal_t), RAnalAddrHintRecordsCb, ctypes.POINTER(None)]
RAnalArchHintCb = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_uint64, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None))
r_anal_arch_hints_foreach = _libr_anal.r_anal_arch_hints_foreach
r_anal_arch_hints_foreach.restype = None
r_anal_arch_hints_foreach.argtypes = [ctypes.POINTER(struct_r_anal_t), RAnalArchHintCb, ctypes.POINTER(None)]
RAnalBitsHintCb = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_uint64, ctypes.c_int32, ctypes.POINTER(None))
r_anal_bits_hints_foreach = _libr_anal.r_anal_bits_hints_foreach
r_anal_bits_hints_foreach.restype = None
r_anal_bits_hints_foreach.argtypes = [ctypes.POINTER(struct_r_anal_t), RAnalBitsHintCb, ctypes.POINTER(None)]
r_anal_hint_arch_at = _libr_anal.r_anal_hint_arch_at
r_anal_hint_arch_at.restype = ctypes.POINTER(ctypes.c_char)
r_anal_hint_arch_at.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64)]
r_anal_hint_bits_at = _libr_anal.r_anal_hint_bits_at
r_anal_hint_bits_at.restype = ctypes.c_int32
r_anal_hint_bits_at.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64)]
r_anal_hint_get = _libr_anal.r_anal_hint_get
r_anal_hint_get.restype = ctypes.POINTER(struct_r_anal_hint_t)
r_anal_hint_get.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_anal_switch_op_new = _libr_anal.r_anal_switch_op_new
r_anal_switch_op_new.restype = ctypes.POINTER(struct_r_anal_switch_obj_t)
r_anal_switch_op_new.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64]
r_anal_switch_op_free = _libr_anal.r_anal_switch_op_free
r_anal_switch_op_free.restype = None
r_anal_switch_op_free.argtypes = [ctypes.POINTER(struct_r_anal_switch_obj_t)]
r_anal_switch_op_add_case = _libr_anal.r_anal_switch_op_add_case
r_anal_switch_op_add_case.restype = ctypes.POINTER(struct_r_anal_case_obj_t)
r_anal_switch_op_add_case.argtypes = [ctypes.POINTER(struct_r_anal_switch_obj_t), ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64]
r_anal_cycle_frame_new = _libr_anal.r_anal_cycle_frame_new
r_anal_cycle_frame_new.restype = ctypes.POINTER(struct_r_anal_cycle_frame_t)
r_anal_cycle_frame_new.argtypes = []
r_anal_cycle_frame_free = _libr_anal.r_anal_cycle_frame_free
r_anal_cycle_frame_free.restype = None
r_anal_cycle_frame_free.argtypes = [ctypes.POINTER(struct_r_anal_cycle_frame_t)]
r_anal_function_get_label = _libr_anal.r_anal_function_get_label
r_anal_function_get_label.restype = ctypes.c_uint64
r_anal_function_get_label.argtypes = [ctypes.POINTER(struct_r_anal_function_t), ctypes.POINTER(ctypes.c_char)]
r_anal_function_get_label_at = _libr_anal.r_anal_function_get_label_at
r_anal_function_get_label_at.restype = ctypes.POINTER(ctypes.c_char)
r_anal_function_get_label_at.argtypes = [ctypes.POINTER(struct_r_anal_function_t), ctypes.c_uint64]
r_anal_function_set_label = _libr_anal.r_anal_function_set_label
r_anal_function_set_label.restype = ctypes.c_bool
r_anal_function_set_label.argtypes = [ctypes.POINTER(struct_r_anal_function_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64]
r_anal_function_delete_label = _libr_anal.r_anal_function_delete_label
r_anal_function_delete_label.restype = ctypes.c_bool
r_anal_function_delete_label.argtypes = [ctypes.POINTER(struct_r_anal_function_t), ctypes.POINTER(ctypes.c_char)]
r_anal_function_delete_label_at = _libr_anal.r_anal_function_delete_label_at
r_anal_function_delete_label_at.restype = ctypes.c_bool
r_anal_function_delete_label_at.argtypes = [ctypes.POINTER(struct_r_anal_function_t), ctypes.c_uint64]
r_anal_set_limits = _libr_anal.r_anal_set_limits
r_anal_set_limits.restype = None
r_anal_set_limits.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_uint64]
r_anal_unset_limits = _libr_anal.r_anal_unset_limits
r_anal_unset_limits.restype = None
r_anal_unset_limits.argtypes = [ctypes.POINTER(struct_r_anal_t)]
r_anal_esil_to_reil_setup = _libraries['FIXME_STUB'].r_anal_esil_to_reil_setup
r_anal_esil_to_reil_setup.restype = ctypes.c_int32
r_anal_esil_to_reil_setup.argtypes = [ctypes.POINTER(struct_r_anal_esil_t), ctypes.POINTER(struct_r_anal_t), ctypes.c_int32, ctypes.c_int32]
r_anal_noreturn_list = _libr_anal.r_anal_noreturn_list
r_anal_noreturn_list.restype = None
r_anal_noreturn_list.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_int32]
r_anal_noreturn_add = _libr_anal.r_anal_noreturn_add
r_anal_noreturn_add.restype = ctypes.c_bool
r_anal_noreturn_add.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64]
r_anal_noreturn_drop = _libr_anal.r_anal_noreturn_drop
r_anal_noreturn_drop.restype = ctypes.c_bool
r_anal_noreturn_drop.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_noreturn_at_addr = _libr_anal.r_anal_noreturn_at_addr
r_anal_noreturn_at_addr.restype = ctypes.c_bool
r_anal_noreturn_at_addr.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64]
r_sign_space_count_for = _libr_anal.r_sign_space_count_for
r_sign_space_count_for.restype = ctypes.c_int32
r_sign_space_count_for.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_space_t)]
r_sign_space_unset_for = _libr_anal.r_sign_space_unset_for
r_sign_space_unset_for.restype = None
r_sign_space_unset_for.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_space_t)]
r_sign_space_rename_for = _libr_anal.r_sign_space_rename_for
r_sign_space_rename_for.restype = None
r_sign_space_rename_for.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_space_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
class struct_c__SA_RVTableContext(Structure):
    pass

struct_c__SA_RVTableContext._pack_ = 1 # source:False
struct_c__SA_RVTableContext._fields_ = [
    ('anal', ctypes.POINTER(struct_r_anal_t)),
    ('abi', RAnalCPPABI),
    ('word_size', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte * 3),
    ('read_addr', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64))),
]

RVTableContext = struct_c__SA_RVTableContext
class struct_vtable_info_t(Structure):
    pass

struct_vtable_info_t._pack_ = 1 # source:False
struct_vtable_info_t._fields_ = [
    ('saddr', ctypes.c_uint64),
    ('methods', struct_r_vector_t),
]

RVTableInfo = struct_vtable_info_t
class struct_vtable_method_info_t(Structure):
    pass

struct_vtable_method_info_t._pack_ = 1 # source:False
struct_vtable_method_info_t._fields_ = [
    ('addr', ctypes.c_uint64),
    ('vtable_offset', ctypes.c_uint64),
]

RVTableMethodInfo = struct_vtable_method_info_t
r_anal_vtable_info_free = _libr_anal.r_anal_vtable_info_free
r_anal_vtable_info_free.restype = None
r_anal_vtable_info_free.argtypes = [ctypes.POINTER(struct_vtable_info_t)]
r_anal_vtable_info_get_size = _libr_anal.r_anal_vtable_info_get_size
r_anal_vtable_info_get_size.restype = ctypes.c_uint64
r_anal_vtable_info_get_size.argtypes = [ctypes.POINTER(struct_c__SA_RVTableContext), ctypes.POINTER(struct_vtable_info_t)]
r_anal_vtable_begin = _libr_anal.r_anal_vtable_begin
r_anal_vtable_begin.restype = ctypes.c_bool
r_anal_vtable_begin.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_c__SA_RVTableContext)]
r_anal_vtable_parse_at = _libr_anal.r_anal_vtable_parse_at
r_anal_vtable_parse_at.restype = ctypes.POINTER(struct_vtable_info_t)
r_anal_vtable_parse_at.argtypes = [ctypes.POINTER(struct_c__SA_RVTableContext), ctypes.c_uint64]
r_anal_vtable_search = _libr_anal.r_anal_vtable_search
r_anal_vtable_search.restype = ctypes.POINTER(struct_r_list_t)
r_anal_vtable_search.argtypes = [ctypes.POINTER(struct_c__SA_RVTableContext)]
r_anal_list_vtables = _libr_anal.r_anal_list_vtables
r_anal_list_vtables.restype = None
r_anal_list_vtables.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_int32]
r_anal_rtti_msvc_demangle_class_name = _libr_anal.r_anal_rtti_msvc_demangle_class_name
r_anal_rtti_msvc_demangle_class_name.restype = ctypes.POINTER(ctypes.c_char)
r_anal_rtti_msvc_demangle_class_name.argtypes = [ctypes.POINTER(struct_c__SA_RVTableContext), ctypes.POINTER(ctypes.c_char)]
r_anal_rtti_msvc_print_complete_object_locator = _libr_anal.r_anal_rtti_msvc_print_complete_object_locator
r_anal_rtti_msvc_print_complete_object_locator.restype = None
r_anal_rtti_msvc_print_complete_object_locator.argtypes = [ctypes.POINTER(struct_c__SA_RVTableContext), ctypes.c_uint64, ctypes.c_int32]
r_anal_rtti_msvc_print_type_descriptor = _libr_anal.r_anal_rtti_msvc_print_type_descriptor
r_anal_rtti_msvc_print_type_descriptor.restype = None
r_anal_rtti_msvc_print_type_descriptor.argtypes = [ctypes.POINTER(struct_c__SA_RVTableContext), ctypes.c_uint64, ctypes.c_int32]
r_anal_rtti_msvc_print_class_hierarchy_descriptor = _libr_anal.r_anal_rtti_msvc_print_class_hierarchy_descriptor
r_anal_rtti_msvc_print_class_hierarchy_descriptor.restype = None
r_anal_rtti_msvc_print_class_hierarchy_descriptor.argtypes = [ctypes.POINTER(struct_c__SA_RVTableContext), ctypes.c_uint64, ctypes.c_int32]
r_anal_rtti_msvc_print_base_class_descriptor = _libr_anal.r_anal_rtti_msvc_print_base_class_descriptor
r_anal_rtti_msvc_print_base_class_descriptor.restype = None
r_anal_rtti_msvc_print_base_class_descriptor.argtypes = [ctypes.POINTER(struct_c__SA_RVTableContext), ctypes.c_uint64, ctypes.c_int32]
r_anal_rtti_msvc_print_at_vtable = _libr_anal.r_anal_rtti_msvc_print_at_vtable
r_anal_rtti_msvc_print_at_vtable.restype = ctypes.c_bool
r_anal_rtti_msvc_print_at_vtable.argtypes = [ctypes.POINTER(struct_c__SA_RVTableContext), ctypes.c_uint64, ctypes.c_int32, ctypes.c_bool]
r_anal_rtti_msvc_recover_all = _libr_anal.r_anal_rtti_msvc_recover_all
r_anal_rtti_msvc_recover_all.restype = None
r_anal_rtti_msvc_recover_all.argtypes = [ctypes.POINTER(struct_c__SA_RVTableContext), ctypes.POINTER(struct_r_list_t)]
r_anal_rtti_itanium_demangle_class_name = _libr_anal.r_anal_rtti_itanium_demangle_class_name
r_anal_rtti_itanium_demangle_class_name.restype = ctypes.POINTER(ctypes.c_char)
r_anal_rtti_itanium_demangle_class_name.argtypes = [ctypes.POINTER(struct_c__SA_RVTableContext), ctypes.POINTER(ctypes.c_char)]
r_anal_rtti_itanium_print_class_type_info = _libraries['FIXME_STUB'].r_anal_rtti_itanium_print_class_type_info
r_anal_rtti_itanium_print_class_type_info.restype = None
r_anal_rtti_itanium_print_class_type_info.argtypes = [ctypes.POINTER(struct_c__SA_RVTableContext), ctypes.c_uint64, ctypes.c_int32]
r_anal_rtti_itanium_print_si_class_type_info = _libraries['FIXME_STUB'].r_anal_rtti_itanium_print_si_class_type_info
r_anal_rtti_itanium_print_si_class_type_info.restype = None
r_anal_rtti_itanium_print_si_class_type_info.argtypes = [ctypes.POINTER(struct_c__SA_RVTableContext), ctypes.c_uint64, ctypes.c_int32]
r_anal_rtti_itanium_print_vmi_class_type_info = _libraries['FIXME_STUB'].r_anal_rtti_itanium_print_vmi_class_type_info
r_anal_rtti_itanium_print_vmi_class_type_info.restype = None
r_anal_rtti_itanium_print_vmi_class_type_info.argtypes = [ctypes.POINTER(struct_c__SA_RVTableContext), ctypes.c_uint64, ctypes.c_int32]
r_anal_rtti_itanium_print_at_vtable = _libr_anal.r_anal_rtti_itanium_print_at_vtable
r_anal_rtti_itanium_print_at_vtable.restype = ctypes.c_bool
r_anal_rtti_itanium_print_at_vtable.argtypes = [ctypes.POINTER(struct_c__SA_RVTableContext), ctypes.c_uint64, ctypes.c_int32]
r_anal_rtti_itanium_recover_all = _libr_anal.r_anal_rtti_itanium_recover_all
r_anal_rtti_itanium_recover_all.restype = None
r_anal_rtti_itanium_recover_all.argtypes = [ctypes.POINTER(struct_c__SA_RVTableContext), ctypes.POINTER(struct_r_list_t)]
r_anal_rtti_demangle_class_name = _libr_anal.r_anal_rtti_demangle_class_name
r_anal_rtti_demangle_class_name.restype = ctypes.POINTER(ctypes.c_char)
r_anal_rtti_demangle_class_name.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_rtti_print_at_vtable = _libr_anal.r_anal_rtti_print_at_vtable
r_anal_rtti_print_at_vtable.restype = None
r_anal_rtti_print_at_vtable.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.c_int32]
r_anal_rtti_print_all = _libr_anal.r_anal_rtti_print_all
r_anal_rtti_print_all.restype = None
r_anal_rtti_print_all.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_int32]
r_anal_rtti_recover_all = _libr_anal.r_anal_rtti_recover_all
r_anal_rtti_recover_all.restype = None
r_anal_rtti_recover_all.argtypes = [ctypes.POINTER(struct_r_anal_t)]
r_anal_preludes = _libr_anal.r_anal_preludes
r_anal_preludes.restype = ctypes.POINTER(struct_r_list_t)
r_anal_preludes.argtypes = [ctypes.POINTER(struct_r_anal_t)]
r_anal_is_prelude = _libr_anal.r_anal_is_prelude
r_anal_is_prelude.restype = ctypes.c_bool
r_anal_is_prelude.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
class struct_r_anal_method_t(Structure):
    pass

struct_r_anal_method_t._pack_ = 1 # source:False
struct_r_anal_method_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('addr', ctypes.c_uint64),
    ('vtable_offset', ctypes.c_int64),
]

RAnalMethod = struct_r_anal_method_t
class struct_r_anal_base_class_t(Structure):
    pass

struct_r_anal_base_class_t._pack_ = 1 # source:False
struct_r_anal_base_class_t._fields_ = [
    ('id', ctypes.POINTER(ctypes.c_char)),
    ('offset', ctypes.c_uint64),
    ('class_name', ctypes.POINTER(ctypes.c_char)),
]

RAnalBaseClass = struct_r_anal_base_class_t
class struct_r_anal_vtable_t(Structure):
    pass

struct_r_anal_vtable_t._pack_ = 1 # source:False
struct_r_anal_vtable_t._fields_ = [
    ('id', ctypes.POINTER(ctypes.c_char)),
    ('offset', ctypes.c_uint64),
    ('addr', ctypes.c_uint64),
    ('size', ctypes.c_uint64),
]

RAnalVTable = struct_r_anal_vtable_t

# values for enumeration 'c__EA_RAnalClassErr'
c__EA_RAnalClassErr__enumvalues = {
    0: 'R_ANAL_CLASS_ERR_SUCCESS',
    1: 'R_ANAL_CLASS_ERR_CLASH',
    2: 'R_ANAL_CLASS_ERR_NONEXISTENT_ATTR',
    3: 'R_ANAL_CLASS_ERR_NONEXISTENT_CLASS',
    4: 'R_ANAL_CLASS_ERR_OTHER',
}
R_ANAL_CLASS_ERR_SUCCESS = 0
R_ANAL_CLASS_ERR_CLASH = 1
R_ANAL_CLASS_ERR_NONEXISTENT_ATTR = 2
R_ANAL_CLASS_ERR_NONEXISTENT_CLASS = 3
R_ANAL_CLASS_ERR_OTHER = 4
c__EA_RAnalClassErr = ctypes.c_uint32 # enum
RAnalClassErr = c__EA_RAnalClassErr
RAnalClassErr__enumvalues = c__EA_RAnalClassErr__enumvalues
r_anal_class_create = _libr_anal.r_anal_class_create
r_anal_class_create.restype = None
r_anal_class_create.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_class_delete = _libr_anal.r_anal_class_delete
r_anal_class_delete.restype = None
r_anal_class_delete.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_class_exists = _libr_anal.r_anal_class_exists
r_anal_class_exists.restype = ctypes.c_bool
r_anal_class_exists.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_class_get_all = _libr_anal.r_anal_class_get_all
r_anal_class_get_all.restype = ctypes.POINTER(struct_ls_t)
r_anal_class_get_all.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_bool]
SdbForeachCallback = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char))
r_anal_class_foreach = _libr_anal.r_anal_class_foreach
r_anal_class_foreach.restype = None
r_anal_class_foreach.argtypes = [ctypes.POINTER(struct_r_anal_t), SdbForeachCallback, ctypes.POINTER(None)]
r_anal_class_rename = _libr_anal.r_anal_class_rename
r_anal_class_rename.restype = RAnalClassErr
r_anal_class_rename.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_anal_class_method_fini = _libr_anal.r_anal_class_method_fini
r_anal_class_method_fini.restype = None
r_anal_class_method_fini.argtypes = [ctypes.POINTER(struct_r_anal_method_t)]
r_anal_class_method_get = _libr_anal.r_anal_class_method_get
r_anal_class_method_get.restype = RAnalClassErr
r_anal_class_method_get.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_anal_method_t)]
r_anal_class_method_get_all = _libr_anal.r_anal_class_method_get_all
r_anal_class_method_get_all.restype = ctypes.POINTER(struct_r_vector_t)
r_anal_class_method_get_all.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_class_method_set = _libr_anal.r_anal_class_method_set
r_anal_class_method_set.restype = RAnalClassErr
r_anal_class_method_set.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_anal_method_t)]
r_anal_class_method_rename = _libr_anal.r_anal_class_method_rename
r_anal_class_method_rename.restype = RAnalClassErr
r_anal_class_method_rename.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_anal_class_method_delete = _libr_anal.r_anal_class_method_delete
r_anal_class_method_delete.restype = RAnalClassErr
r_anal_class_method_delete.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_anal_class_base_fini = _libr_anal.r_anal_class_base_fini
r_anal_class_base_fini.restype = None
r_anal_class_base_fini.argtypes = [ctypes.POINTER(struct_r_anal_base_class_t)]
r_anal_class_base_get = _libr_anal.r_anal_class_base_get
r_anal_class_base_get.restype = RAnalClassErr
r_anal_class_base_get.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_anal_base_class_t)]
r_anal_class_base_get_all = _libr_anal.r_anal_class_base_get_all
r_anal_class_base_get_all.restype = ctypes.POINTER(struct_r_vector_t)
r_anal_class_base_get_all.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_class_base_set = _libr_anal.r_anal_class_base_set
r_anal_class_base_set.restype = RAnalClassErr
r_anal_class_base_set.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_anal_base_class_t)]
r_anal_class_base_delete = _libr_anal.r_anal_class_base_delete
r_anal_class_base_delete.restype = RAnalClassErr
r_anal_class_base_delete.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_anal_class_vtable_fini = _libr_anal.r_anal_class_vtable_fini
r_anal_class_vtable_fini.restype = None
r_anal_class_vtable_fini.argtypes = [ctypes.POINTER(struct_r_anal_vtable_t)]
r_anal_class_vtable_get = _libr_anal.r_anal_class_vtable_get
r_anal_class_vtable_get.restype = RAnalClassErr
r_anal_class_vtable_get.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_anal_vtable_t)]
r_anal_class_vtable_get_all = _libr_anal.r_anal_class_vtable_get_all
r_anal_class_vtable_get_all.restype = ctypes.POINTER(struct_r_vector_t)
r_anal_class_vtable_get_all.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_class_vtable_set = _libr_anal.r_anal_class_vtable_set
r_anal_class_vtable_set.restype = RAnalClassErr
r_anal_class_vtable_set.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_anal_vtable_t)]
r_anal_class_vtable_delete = _libr_anal.r_anal_class_vtable_delete
r_anal_class_vtable_delete.restype = RAnalClassErr
r_anal_class_vtable_delete.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_anal_class_print = _libr_anal.r_anal_class_print
r_anal_class_print.restype = None
r_anal_class_print.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char), ctypes.c_bool]
r_anal_class_json = _libr_anal.r_anal_class_json
r_anal_class_json.restype = None
r_anal_class_json.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_pj_t), ctypes.POINTER(ctypes.c_char)]
r_anal_class_list = _libr_anal.r_anal_class_list
r_anal_class_list.restype = None
r_anal_class_list.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.c_int32]
r_anal_class_list_bases = _libr_anal.r_anal_class_list_bases
r_anal_class_list_bases.restype = None
r_anal_class_list_bases.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_class_list_vtables = _libr_anal.r_anal_class_list_vtables
r_anal_class_list_vtables.restype = None
r_anal_class_list_vtables.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
r_anal_class_list_vtable_offset_functions = _libr_anal.r_anal_class_list_vtable_offset_functions
r_anal_class_list_vtable_offset_functions.restype = None
r_anal_class_list_vtable_offset_functions.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64]
r_anal_class_get_inheritance_graph = _libr_anal.r_anal_class_get_inheritance_graph
r_anal_class_get_inheritance_graph.restype = ctypes.POINTER(struct_r_graph_t)
r_anal_class_get_inheritance_graph.argtypes = [ctypes.POINTER(struct_r_anal_t)]
r_anal_esil_cfg_expr = _libr_anal.r_anal_esil_cfg_expr
r_anal_esil_cfg_expr.restype = ctypes.POINTER(struct_r_anal_esil_cfg_t)
r_anal_esil_cfg_expr.argtypes = [ctypes.POINTER(struct_r_anal_esil_cfg_t), ctypes.POINTER(struct_r_anal_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_char)]
r_anal_esil_cfg_op = _libr_anal.r_anal_esil_cfg_op
r_anal_esil_cfg_op.restype = ctypes.POINTER(struct_r_anal_esil_cfg_t)
r_anal_esil_cfg_op.argtypes = [ctypes.POINTER(struct_r_anal_esil_cfg_t), ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_op_t)]
r_anal_esil_cfg_merge_blocks = _libr_anal.r_anal_esil_cfg_merge_blocks
r_anal_esil_cfg_merge_blocks.restype = None
r_anal_esil_cfg_merge_blocks.argtypes = [ctypes.POINTER(struct_r_anal_esil_cfg_t)]
r_anal_esil_cfg_free = _libr_anal.r_anal_esil_cfg_free
r_anal_esil_cfg_free.restype = None
r_anal_esil_cfg_free.argtypes = [ctypes.POINTER(struct_r_anal_esil_cfg_t)]
r_anal_esil_dfg_node_new = _libr_anal.r_anal_esil_dfg_node_new
r_anal_esil_dfg_node_new.restype = ctypes.POINTER(struct_r_anal_esil_dfg_node_t)
r_anal_esil_dfg_node_new.argtypes = [ctypes.POINTER(struct_r_anal_esil_dfg_t), ctypes.POINTER(ctypes.c_char)]
r_anal_esil_dfg_new = _libr_anal.r_anal_esil_dfg_new
r_anal_esil_dfg_new.restype = ctypes.POINTER(struct_r_anal_esil_dfg_t)
r_anal_esil_dfg_new.argtypes = [ctypes.POINTER(struct_r_reg_t)]
r_anal_esil_dfg_free = _libr_anal.r_anal_esil_dfg_free
r_anal_esil_dfg_free.restype = None
r_anal_esil_dfg_free.argtypes = [ctypes.POINTER(struct_r_anal_esil_dfg_t)]
r_anal_esil_dfg_expr = _libr_anal.r_anal_esil_dfg_expr
r_anal_esil_dfg_expr.restype = ctypes.POINTER(struct_r_anal_esil_dfg_t)
r_anal_esil_dfg_expr.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_esil_dfg_t), ctypes.POINTER(ctypes.c_char)]
r_anal_esil_dfg_fold_const = _libr_anal.r_anal_esil_dfg_fold_const
r_anal_esil_dfg_fold_const.restype = None
r_anal_esil_dfg_fold_const.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_esil_dfg_t)]
r_anal_esil_dfg_filter = _libr_anal.r_anal_esil_dfg_filter
r_anal_esil_dfg_filter.restype = ctypes.POINTER(struct_c__SA_RStrBuf)
r_anal_esil_dfg_filter.argtypes = [ctypes.POINTER(struct_r_anal_esil_dfg_t), ctypes.POINTER(ctypes.c_char)]
r_anal_esil_dfg_filter_expr = _libr_anal.r_anal_esil_dfg_filter_expr
r_anal_esil_dfg_filter_expr.restype = ctypes.POINTER(struct_c__SA_RStrBuf)
r_anal_esil_dfg_filter_expr.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_anal_types_from_fcn = _libr_anal.r_anal_types_from_fcn
r_anal_types_from_fcn.restype = ctypes.POINTER(struct_r_list_t)
r_anal_types_from_fcn.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_function_t)]
r_anal_get_base_type = _libr_anal.r_anal_get_base_type
r_anal_get_base_type.restype = ctypes.POINTER(struct_r_anal_base_type_t)
r_anal_get_base_type.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(ctypes.c_char)]
class struct_r_pdb_t(Structure):
    pass

class struct_R_PDB7_ROOT_STREAM(Structure):
    pass

struct_r_pdb_t._pack_ = 1 # source:False
struct_r_pdb_t._fields_ = [
    ('pdb_parse', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_pdb_t))),
    ('finish_pdb_parse', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_pdb_t))),
    ('print_types', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_pdb_t), ctypes.POINTER(struct_pj_t), ctypes.c_int32)),
    ('cb_printf', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_char))),
    ('root_stream', ctypes.POINTER(struct_R_PDB7_ROOT_STREAM)),
    ('stream_map', ctypes.POINTER(None)),
    ('pdb_streams', ctypes.POINTER(struct_r_list_t)),
    ('pdb_streams2', ctypes.POINTER(struct_r_list_t)),
    ('buf', ctypes.POINTER(struct_r_buf_t)),
    ('print_gvars', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_pdb_t), ctypes.c_uint64, ctypes.POINTER(struct_pj_t), ctypes.c_int32)),
]

r_parse_pdb_types = _libr_anal.r_parse_pdb_types
r_parse_pdb_types.restype = None
r_parse_pdb_types.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_pdb_t)]
r_anal_save_base_type = _libr_anal.r_anal_save_base_type
r_anal_save_base_type.restype = None
r_anal_save_base_type.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_base_type_t)]
r_anal_base_type_free = _libr_anal.r_anal_base_type_free
r_anal_base_type_free.restype = None
r_anal_base_type_free.argtypes = [ctypes.POINTER(struct_r_anal_base_type_t)]
r_anal_base_type_new = _libr_anal.r_anal_base_type_new
r_anal_base_type_new.restype = ctypes.POINTER(struct_r_anal_base_type_t)
r_anal_base_type_new.argtypes = [RAnalBaseTypeKind]
r_anal_dwarf_process_info = _libr_anal.r_anal_dwarf_process_info
r_anal_dwarf_process_info.restype = None
r_anal_dwarf_process_info.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_anal_dwarf_context)]
r_anal_dwarf_integrate_functions = _libr_anal.r_anal_dwarf_integrate_functions
r_anal_dwarf_integrate_functions.restype = None
r_anal_dwarf_integrate_functions.argtypes = [ctypes.POINTER(struct_r_anal_t), ctypes.POINTER(struct_r_flag_t), ctypes.POINTER(struct_sdb_t)]
r_anal_plugin_null = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_6502 = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_6502_cs = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_8051 = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_amd29k = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_arc = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_arm_cs = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_arm_gnu = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_avr = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_bf = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_chip8 = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_cr16 = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_cris = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_dalvik = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_ebc = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_gb = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_h8300 = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_hexagon = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_i4004 = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_i8080 = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_java = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_m68k_cs = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_m680x_cs = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_malbolge = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_mcore = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_mips_cs = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_mips_gnu = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_msp430 = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_nios2 = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_or1k = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_pic = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_ppc_cs = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_ppc_gnu = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_propeller = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_riscv = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_riscv_cs = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_rsp = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_sh = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_snes = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_sparc_cs = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_sparc_gnu = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_sysz = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_tms320 = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_tms320c64x = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_tricore = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_v810 = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_v850 = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_vax = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_wasm = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_ws = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_x86 = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_x86_cs = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_x86_im = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_x86_simple = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_x86_udis = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_xap = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_xcore_cs = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_xtensa = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_z80 = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_anal_plugin_pyc = struct_r_anal_plugin_t # Variable struct_r_anal_plugin_t
r_esil_plugin_dummy = struct_r_anal_esil_plugin_t # Variable struct_r_anal_esil_plugin_t
__all__ = \
    ['ARG_CONST', 'ARG_ESIL_INTERNAL', 'ARG_NONE', 'ARG_REG',
    'ARG_TEMP', 'DW_AT_KIND_ADDRESS', 'DW_AT_KIND_BLOCK',
    'DW_AT_KIND_CONSTANT', 'DW_AT_KIND_EXPRLOC', 'DW_AT_KIND_FLAG',
    'DW_AT_KIND_LINEPTR', 'DW_AT_KIND_LOCLISTPTR',
    'DW_AT_KIND_MACPTR', 'DW_AT_KIND_RANGELISTPTR',
    'DW_AT_KIND_REFERENCE', 'DW_AT_KIND_STRING', 'PJEncodingNum',
    'PJEncodingStr', 'PJ_ENCODING_NUM_DEFAULT', 'PJ_ENCODING_NUM_HEX',
    'PJ_ENCODING_NUM_STR', 'PJ_ENCODING_STR_ARRAY',
    'PJ_ENCODING_STR_BASE64', 'PJ_ENCODING_STR_DEFAULT',
    'PJ_ENCODING_STR_HEX', 'PJ_ENCODING_STR_STRIP', 'RAnal',
    'RAnalAddrCb', 'RAnalAddrHintRecord', 'RAnalAddrHintRecordsCb',
    'RAnalAddrHintType', 'RAnalAddrHintType__enumvalues',
    'RAnalArchHintCb', 'RAnalAttr', 'RAnalBaseClass', 'RAnalBaseType',
    'RAnalBaseTypeEnum', 'RAnalBaseTypeKind',
    'RAnalBaseTypeKind__enumvalues', 'RAnalBaseTypeStruct',
    'RAnalBaseTypeUnion', 'RAnalBind', 'RAnalBitsHintCb',
    'RAnalBlock', 'RAnalBlockCb', 'RAnalCPPABI',
    'RAnalCPPABI__enumvalues', 'RAnalCallbacks', 'RAnalCaseOp',
    'RAnalClassErr', 'RAnalClassErr__enumvalues', 'RAnalCmdExt',
    'RAnalCond', 'RAnalCycleFrame', 'RAnalCycleHook', 'RAnalData',
    'RAnalDataType', 'RAnalDataType__enumvalues', 'RAnalDiff',
    'RAnalDiffBBCallback', 'RAnalDiffEvalCallback',
    'RAnalDiffFcnCallback', 'RAnalDwarfContext', 'RAnalEnumCase',
    'RAnalEsil', 'RAnalEsilActivePlugin', 'RAnalEsilBB',
    'RAnalEsilBlockEnterType', 'RAnalEsilBlockEnterType__enumvalues',
    'RAnalEsilCB', 'RAnalEsilCFG', 'RAnalEsilCallbacks',
    'RAnalEsilDFG', 'RAnalEsilDFGNode', 'RAnalEsilEOffset',
    'RAnalEsilHandler', 'RAnalEsilHandlerCB',
    'RAnalEsilHookRegWriteCB', 'RAnalEsilLoopCB',
    'RAnalEsilMemChange', 'RAnalEsilOp', 'RAnalEsilOpCb',
    'RAnalEsilPlugin', 'RAnalEsilRegChange', 'RAnalEsilTrace',
    'RAnalEsilTrapCB', 'RAnalEsilWord', 'RAnalFPBBCallback',
    'RAnalFPFcnCallback', 'RAnalFcnMeta', 'RAnalFcnVarsCache',
    'RAnalFuncArg', 'RAnalFunction', 'RAnalGetFcnIn', 'RAnalGetHint',
    'RAnalHint', 'RAnalLabelAt', 'RAnalMetaItem', 'RAnalMetaType',
    'RAnalMetaType__enumvalues', 'RAnalMetaUserItem', 'RAnalMethod',
    'RAnalOp', 'RAnalOpCallback', 'RAnalOpDirection',
    'RAnalOpDirection__enumvalues', 'RAnalOpFamily',
    'RAnalOpFamily__enumvalues', 'RAnalOpMask',
    'RAnalOpMask__enumvalues', 'RAnalOpPrefix',
    'RAnalOpPrefix__enumvalues', 'RAnalOptions', 'RAnalPlugin',
    'RAnalRange', 'RAnalRef', 'RAnalRefCmp', 'RAnalRefStr',
    'RAnalRefType', 'RAnalRefType__enumvalues', 'RAnalRefline',
    'RAnalRegProfCallback', 'RAnalRegProfGetCallback', 'RAnalReil',
    'RAnalReilArg', 'RAnalReilArgType',
    'RAnalReilArgType__enumvalues', 'RAnalReilInst',
    'RAnalReilOpcode', 'RAnalReilOpcode__enumvalues', 'RAnalStackOp',
    'RAnalStackOp__enumvalues', 'RAnalStructMember', 'RAnalSwitchOp',
    'RAnalType', 'RAnalTypeAlloca', 'RAnalTypeArray', 'RAnalTypePtr',
    'RAnalTypeStruct', 'RAnalTypeUnion', 'RAnalTypeVar',
    'RAnalUnionMember', 'RAnalVTable', 'RAnalValue',
    'RAnalValueAccess', 'RAnalValueAccess__enumvalues',
    'RAnalValueType', 'RAnalValueType__enumvalues', 'RAnalVar',
    'RAnalVarAccess', 'RAnalVarAccessType',
    'RAnalVarAccessType__enumvalues', 'RAnalVarConstraint',
    'RAnalVarField', 'RAnalVarKind', 'RAnalVarKind__enumvalues',
    'REIL_ADD', 'REIL_AND', 'REIL_DIV', 'REIL_EQ', 'REIL_JCC',
    'REIL_LDM', 'REIL_LT', 'REIL_MOD', 'REIL_MUL', 'REIL_NEG',
    'REIL_NOP', 'REIL_NOT', 'REIL_OR', 'REIL_SDIV', 'REIL_SHL',
    'REIL_SHR', 'REIL_SMOD', 'REIL_SMUL', 'REIL_STM', 'REIL_STR',
    'REIL_SUB', 'REIL_UNK', 'REIL_XOR', 'RHintCb', 'RNCAND',
    'RNCASSIGN', 'RNCDEC', 'RNCDIV', 'RNCEND', 'RNCINC', 'RNCLEFTP',
    'RNCMINUS', 'RNCMOD', 'RNCMUL', 'RNCNAME', 'RNCNEG', 'RNCNUMBER',
    'RNCOR', 'RNCPLUS', 'RNCPRINT', 'RNCRIGHTP', 'RNCROL', 'RNCROR',
    'RNCSHL', 'RNCSHR', 'RNCXOR', 'RVTableContext', 'RVTableInfo',
    'RVTableMethodInfo', 'R_ANAL_ACC_R', 'R_ANAL_ACC_UNKNOWN',
    'R_ANAL_ACC_W', 'R_ANAL_ADDR_HINT_TYPE_ESIL',
    'R_ANAL_ADDR_HINT_TYPE_FAIL', 'R_ANAL_ADDR_HINT_TYPE_HIGH',
    'R_ANAL_ADDR_HINT_TYPE_IMMBASE', 'R_ANAL_ADDR_HINT_TYPE_JUMP',
    'R_ANAL_ADDR_HINT_TYPE_NEW_BITS', 'R_ANAL_ADDR_HINT_TYPE_NWORD',
    'R_ANAL_ADDR_HINT_TYPE_OPCODE', 'R_ANAL_ADDR_HINT_TYPE_OPTYPE',
    'R_ANAL_ADDR_HINT_TYPE_PTR', 'R_ANAL_ADDR_HINT_TYPE_RET',
    'R_ANAL_ADDR_HINT_TYPE_SIZE', 'R_ANAL_ADDR_HINT_TYPE_STACKFRAME',
    'R_ANAL_ADDR_HINT_TYPE_SYNTAX',
    'R_ANAL_ADDR_HINT_TYPE_TYPE_OFFSET', 'R_ANAL_ADDR_HINT_TYPE_VAL',
    'R_ANAL_BASE_TYPE_KIND_ATOMIC', 'R_ANAL_BASE_TYPE_KIND_ENUM',
    'R_ANAL_BASE_TYPE_KIND_STRUCT', 'R_ANAL_BASE_TYPE_KIND_TYPEDEF',
    'R_ANAL_BASE_TYPE_KIND_UNION', 'R_ANAL_CLASS_ERR_CLASH',
    'R_ANAL_CLASS_ERR_NONEXISTENT_ATTR',
    'R_ANAL_CLASS_ERR_NONEXISTENT_CLASS', 'R_ANAL_CLASS_ERR_OTHER',
    'R_ANAL_CLASS_ERR_SUCCESS', 'R_ANAL_COND_AL', 'R_ANAL_COND_EQ',
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
    'R_ANAL_DATATYPE_STRING', 'R_ANAL_DATA_TYPE_HEADER',
    'R_ANAL_DATA_TYPE_INVALID', 'R_ANAL_DATA_TYPE_NULL',
    'R_ANAL_DATA_TYPE_NUMBER', 'R_ANAL_DATA_TYPE_PATTERN',
    'R_ANAL_DATA_TYPE_POINTER', 'R_ANAL_DATA_TYPE_SEQUENCE',
    'R_ANAL_DATA_TYPE_STRING', 'R_ANAL_DATA_TYPE_UNKNOWN',
    'R_ANAL_DATA_TYPE_WIDE_STRING', 'R_ANAL_DIFF_TYPE_MATCH',
    'R_ANAL_DIFF_TYPE_NULL', 'R_ANAL_DIFF_TYPE_UNMATCH',
    'R_ANAL_ESIL_BLOCK_ENTER_FALSE', 'R_ANAL_ESIL_BLOCK_ENTER_GLUE',
    'R_ANAL_ESIL_BLOCK_ENTER_NORMAL', 'R_ANAL_ESIL_BLOCK_ENTER_TRUE',
    'R_ANAL_ESIL_DFG_BLOCK_CONST', 'R_ANAL_ESIL_DFG_BLOCK_GENERATIVE',
    'R_ANAL_ESIL_DFG_BLOCK_PTR', 'R_ANAL_ESIL_DFG_BLOCK_RESULT',
    'R_ANAL_ESIL_DFG_BLOCK_VAR', 'R_ANAL_ESIL_FLAG_CARRY',
    'R_ANAL_ESIL_FLAG_OVERFLOW', 'R_ANAL_ESIL_FLAG_PARITY',
    'R_ANAL_ESIL_FLAG_SIGN', 'R_ANAL_ESIL_FLAG_ZERO',
    'R_ANAL_ESIL_OP_TYPE_CONTROL_FLOW', 'R_ANAL_ESIL_OP_TYPE_CUSTOM',
    'R_ANAL_ESIL_OP_TYPE_MATH', 'R_ANAL_ESIL_OP_TYPE_MEM_READ',
    'R_ANAL_ESIL_OP_TYPE_MEM_WRITE', 'R_ANAL_ESIL_OP_TYPE_REG_WRITE',
    'R_ANAL_ESIL_OP_TYPE_UNKNOWN', 'R_ANAL_ESIL_PARM_INVALID',
    'R_ANAL_ESIL_PARM_NUM', 'R_ANAL_ESIL_PARM_REG',
    'R_ANAL_FCN_TYPE_ANY', 'R_ANAL_FCN_TYPE_FCN',
    'R_ANAL_FCN_TYPE_IMP', 'R_ANAL_FCN_TYPE_INT',
    'R_ANAL_FCN_TYPE_LOC', 'R_ANAL_FCN_TYPE_NULL',
    'R_ANAL_FCN_TYPE_ROOT', 'R_ANAL_FCN_TYPE_SYM',
    'R_ANAL_FQUALIFIER_INLINE', 'R_ANAL_FQUALIFIER_NAKED',
    'R_ANAL_FQUALIFIER_NONE', 'R_ANAL_FQUALIFIER_STATIC',
    'R_ANAL_FQUALIFIER_VIRTUAL', 'R_ANAL_FQUALIFIER_VOLATILE',
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
    'R_ANAL_OP_TYPE_ABS', 'R_ANAL_OP_TYPE_ACMP', 'R_ANAL_OP_TYPE_ADD',
    'R_ANAL_OP_TYPE_AND', 'R_ANAL_OP_TYPE_CALL',
    'R_ANAL_OP_TYPE_CASE', 'R_ANAL_OP_TYPE_CAST',
    'R_ANAL_OP_TYPE_CCALL', 'R_ANAL_OP_TYPE_CJMP',
    'R_ANAL_OP_TYPE_CMOV', 'R_ANAL_OP_TYPE_CMP',
    'R_ANAL_OP_TYPE_COND', 'R_ANAL_OP_TYPE_CPL',
    'R_ANAL_OP_TYPE_CRET', 'R_ANAL_OP_TYPE_CRYPTO',
    'R_ANAL_OP_TYPE_CSWI', 'R_ANAL_OP_TYPE_DIV',
    'R_ANAL_OP_TYPE_ICALL', 'R_ANAL_OP_TYPE_IJMP',
    'R_ANAL_OP_TYPE_ILL', 'R_ANAL_OP_TYPE_IND', 'R_ANAL_OP_TYPE_IO',
    'R_ANAL_OP_TYPE_IRCALL', 'R_ANAL_OP_TYPE_IRJMP',
    'R_ANAL_OP_TYPE_JMP', 'R_ANAL_OP_TYPE_LEA',
    'R_ANAL_OP_TYPE_LEAVE', 'R_ANAL_OP_TYPE_LENGTH',
    'R_ANAL_OP_TYPE_LOAD', 'R_ANAL_OP_TYPE_MCJMP',
    'R_ANAL_OP_TYPE_MEM', 'R_ANAL_OP_TYPE_MJMP', 'R_ANAL_OP_TYPE_MOD',
    'R_ANAL_OP_TYPE_MOV', 'R_ANAL_OP_TYPE_MUL', 'R_ANAL_OP_TYPE_NEW',
    'R_ANAL_OP_TYPE_NOP', 'R_ANAL_OP_TYPE_NOR', 'R_ANAL_OP_TYPE_NOT',
    'R_ANAL_OP_TYPE_NULL', 'R_ANAL_OP_TYPE_OR', 'R_ANAL_OP_TYPE_POP',
    'R_ANAL_OP_TYPE_PUSH', 'R_ANAL_OP_TYPE_RCALL',
    'R_ANAL_OP_TYPE_RCJMP', 'R_ANAL_OP_TYPE_REG',
    'R_ANAL_OP_TYPE_REP', 'R_ANAL_OP_TYPE_RET', 'R_ANAL_OP_TYPE_RJMP',
    'R_ANAL_OP_TYPE_ROL', 'R_ANAL_OP_TYPE_ROR',
    'R_ANAL_OP_TYPE_RPUSH', 'R_ANAL_OP_TYPE_SAL',
    'R_ANAL_OP_TYPE_SAR', 'R_ANAL_OP_TYPE_SHL', 'R_ANAL_OP_TYPE_SHR',
    'R_ANAL_OP_TYPE_STORE', 'R_ANAL_OP_TYPE_SUB',
    'R_ANAL_OP_TYPE_SWI', 'R_ANAL_OP_TYPE_SWITCH',
    'R_ANAL_OP_TYPE_SYNC', 'R_ANAL_OP_TYPE_TRAP',
    'R_ANAL_OP_TYPE_UCALL', 'R_ANAL_OP_TYPE_UCCALL',
    'R_ANAL_OP_TYPE_UCJMP', 'R_ANAL_OP_TYPE_UJMP',
    'R_ANAL_OP_TYPE_UNK', 'R_ANAL_OP_TYPE_UPUSH',
    'R_ANAL_OP_TYPE_XCHG', 'R_ANAL_OP_TYPE_XOR',
    'R_ANAL_REFLINE_TYPE_MIDDLE_AFTER',
    'R_ANAL_REFLINE_TYPE_MIDDLE_BEFORE', 'R_ANAL_REFLINE_TYPE_UTF8',
    'R_ANAL_REFLINE_TYPE_WIDE', 'R_ANAL_REF_TYPE_CALL',
    'R_ANAL_REF_TYPE_CODE', 'R_ANAL_REF_TYPE_DATA',
    'R_ANAL_REF_TYPE_NULL', 'R_ANAL_REF_TYPE_STRING',
    'R_ANAL_RET_DUP', 'R_ANAL_RET_END', 'R_ANAL_RET_ERROR',
    'R_ANAL_RET_NEW', 'R_ANAL_RET_NOP', 'R_ANAL_STACK_ALIGN',
    'R_ANAL_STACK_GET', 'R_ANAL_STACK_INC', 'R_ANAL_STACK_NOP',
    'R_ANAL_STACK_NULL', 'R_ANAL_STACK_RESET', 'R_ANAL_STACK_SET',
    'R_ANAL_TRAP_BREAKPOINT', 'R_ANAL_TRAP_DIVBYZERO',
    'R_ANAL_TRAP_EXEC_ERR', 'R_ANAL_TRAP_HALT', 'R_ANAL_TRAP_INVALID',
    'R_ANAL_TRAP_NONE', 'R_ANAL_TRAP_READ_ERR', 'R_ANAL_TRAP_TODO',
    'R_ANAL_TRAP_UNALIGNED', 'R_ANAL_TRAP_UNHANDLED',
    'R_ANAL_TRAP_WRITE_ERR', 'R_ANAL_VAL_IMM', 'R_ANAL_VAL_MEM',
    'R_ANAL_VAL_REG', 'R_ANAL_VAR_ACCESS_TYPE_PTR',
    'R_ANAL_VAR_ACCESS_TYPE_READ', 'R_ANAL_VAR_ACCESS_TYPE_WRITE',
    'R_ANAL_VAR_KIND_BPV', 'R_ANAL_VAR_KIND_REG',
    'R_ANAL_VAR_KIND_SPV', 'R_ANAL_VAR_SCOPE_LOCAL',
    'R_META_TYPE_ANY', 'R_META_TYPE_CODE', 'R_META_TYPE_COMMENT',
    'R_META_TYPE_DATA', 'R_META_TYPE_FORMAT', 'R_META_TYPE_HIDE',
    'R_META_TYPE_HIGHLIGHT', 'R_META_TYPE_MAGIC', 'R_META_TYPE_RUN',
    'R_META_TYPE_STRING', 'R_META_TYPE_VARTYPE', 'SdbForeachCallback',
    '_RAnalCond', '_RAnalCond__enumvalues', '_RAnalOpType',
    '_RAnalOpType__enumvalues', '_RAnalVarScope',
    '_RAnalVarScope__enumvalues', 'c__EA_RAnalBaseTypeKind',
    'c__EA_RAnalCPPABI', 'c__EA_RAnalClassErr',
    'c__EA_RAnalEsilBlockEnterType', 'c__EA_RAnalMetaType',
    'c__EA_RAnalOpDirection', 'c__EA_RAnalOpFamily',
    'c__EA_RAnalOpMask', 'c__EA_RAnalOpPrefix', 'c__EA_RAnalRefType',
    'c__EA_RAnalReilArgType', 'c__EA_RAnalReilOpcode',
    'c__EA_RAnalStackOp', 'c__EA_RAnalValueAccess',
    'c__EA_RAnalValueType', 'c__EA_RAnalVarAccessType',
    'c__EA_RAnalVarKind', 'c__EA_RBinDwarfAttrKind',
    'c__EA_RNumCalcToken', 'c__EA__RAnalCond', 'c__EA__RAnalOpType',
    'c__EA__RAnalVarScope', 'c__Ea_R_ANAL_DATA_TYPE_NULL',
    'c__Ea_R_ANAL_DIFF_TYPE_NULL',
    'c__Ea_R_ANAL_ESIL_DFG_BLOCK_CONST',
    'c__Ea_R_ANAL_ESIL_FLAG_ZERO',
    'c__Ea_R_ANAL_ESIL_OP_TYPE_UNKNOWN',
    'c__Ea_R_ANAL_ESIL_PARM_INVALID', 'c__Ea_R_ANAL_FCN_TYPE_NULL',
    'c__Ea_R_ANAL_FQUALIFIER_NONE', 'c__Ea_R_ANAL_REFLINE_TYPE_UTF8',
    'c__Ea_R_ANAL_RET_NOP', 'c__Ea_R_ANAL_TRAP_NONE', 'r_anal_add',
    'r_anal_add_function', 'r_anal_add_import',
    'r_anal_addr_hint_type_t', 'r_anal_addr_hints_at',
    'r_anal_addr_hints_foreach', 'r_anal_arch_hints_foreach',
    'r_anal_archinfo', 'r_anal_base_type_free',
    'r_anal_base_type_new', 'r_anal_bb_from_offset',
    'r_anal_bb_offset_inst', 'r_anal_bb_opaddr_at',
    'r_anal_bb_opaddr_i', 'r_anal_bb_set_offset', 'r_anal_bb_size_i',
    'r_anal_bind', 'r_anal_bits_hints_foreach',
    'r_anal_block_add_switch_case', 'r_anal_block_automerge',
    'r_anal_block_chop_noreturn', 'r_anal_block_contains',
    'r_anal_block_is_contiguous', 'r_anal_block_merge',
    'r_anal_block_op_starts_at', 'r_anal_block_recurse',
    'r_anal_block_recurse_depth_first',
    'r_anal_block_recurse_followthrough', 'r_anal_block_recurse_list',
    'r_anal_block_ref', 'r_anal_block_relocate',
    'r_anal_block_set_size', 'r_anal_block_shortest_path',
    'r_anal_block_split', 'r_anal_block_successor_addrs_foreach',
    'r_anal_block_unref', 'r_anal_block_update_hash',
    'r_anal_block_was_modified', 'r_anal_blocks_foreach_in',
    'r_anal_blocks_foreach_intersect', 'r_anal_cc_arg',
    'r_anal_cc_default', 'r_anal_cc_del', 'r_anal_cc_error',
    'r_anal_cc_exist', 'r_anal_cc_func', 'r_anal_cc_get',
    'r_anal_cc_get_json', 'r_anal_cc_max_arg', 'r_anal_cc_once',
    'r_anal_cc_ret', 'r_anal_cc_self', 'r_anal_cc_set',
    'r_anal_cc_set_error', 'r_anal_cc_set_self', 'r_anal_check_fcn',
    'r_anal_class_base_delete', 'r_anal_class_base_fini',
    'r_anal_class_base_get', 'r_anal_class_base_get_all',
    'r_anal_class_base_set', 'r_anal_class_create',
    'r_anal_class_delete', 'r_anal_class_exists',
    'r_anal_class_foreach', 'r_anal_class_get_all',
    'r_anal_class_get_inheritance_graph', 'r_anal_class_json',
    'r_anal_class_list', 'r_anal_class_list_bases',
    'r_anal_class_list_vtable_offset_functions',
    'r_anal_class_list_vtables', 'r_anal_class_method_delete',
    'r_anal_class_method_fini', 'r_anal_class_method_get',
    'r_anal_class_method_get_all', 'r_anal_class_method_rename',
    'r_anal_class_method_set', 'r_anal_class_print',
    'r_anal_class_rename', 'r_anal_class_vtable_delete',
    'r_anal_class_vtable_fini', 'r_anal_class_vtable_get',
    'r_anal_class_vtable_get_all', 'r_anal_class_vtable_set',
    'r_anal_compare', 'r_anal_cond_eval', 'r_anal_cond_fini',
    'r_anal_cond_free', 'r_anal_cond_new', 'r_anal_cond_new_from_op',
    'r_anal_cond_new_from_string', 'r_anal_cond_to_string',
    'r_anal_cond_tostring', 'r_anal_create_block',
    'r_anal_create_function', 'r_anal_cycle_frame_free',
    'r_anal_cycle_frame_new', 'r_anal_data', 'r_anal_data_free',
    'r_anal_data_kind', 'r_anal_data_new', 'r_anal_data_new_string',
    'r_anal_data_to_string', 'r_anal_data_type_t',
    'r_anal_datatype_to_string', 'r_anal_del_jmprefs',
    'r_anal_delete_block', 'r_anal_diff_bb', 'r_anal_diff_eval',
    'r_anal_diff_fcn', 'r_anal_diff_fingerprint_bb',
    'r_anal_diff_fingerprint_fcn', 'r_anal_diff_free',
    'r_anal_diff_new', 'r_anal_diff_setup', 'r_anal_diff_setup_i',
    'r_anal_dwarf_integrate_functions', 'r_anal_dwarf_process_info',
    'r_anal_esil_cfg_expr', 'r_anal_esil_cfg_free',
    'r_anal_esil_cfg_merge_blocks', 'r_anal_esil_cfg_op',
    'r_anal_esil_condition', 'r_anal_esil_del_interrupt',
    'r_anal_esil_del_op', 'r_anal_esil_del_syscall',
    'r_anal_esil_dfg_expr', 'r_anal_esil_dfg_filter',
    'r_anal_esil_dfg_filter_expr', 'r_anal_esil_dfg_fold_const',
    'r_anal_esil_dfg_free', 'r_anal_esil_dfg_new',
    'r_anal_esil_dfg_node_new', 'r_anal_esil_do_syscall',
    'r_anal_esil_dumpstack', 'r_anal_esil_fire_interrupt',
    'r_anal_esil_free', 'r_anal_esil_get_interrupt',
    'r_anal_esil_get_op', 'r_anal_esil_get_parm',
    'r_anal_esil_get_parm_type', 'r_anal_esil_get_syscall',
    'r_anal_esil_handlers_fini', 'r_anal_esil_handlers_init',
    'r_anal_esil_mem_read', 'r_anal_esil_mem_ro',
    'r_anal_esil_mem_write', 'r_anal_esil_new', 'r_anal_esil_parse',
    'r_anal_esil_plugin_activate', 'r_anal_esil_plugin_add',
    'r_anal_esil_plugin_deactivate', 'r_anal_esil_plugins_fini',
    'r_anal_esil_plugins_init', 'r_anal_esil_pop', 'r_anal_esil_push',
    'r_anal_esil_pushnum', 'r_anal_esil_reg_read',
    'r_anal_esil_reg_write', 'r_anal_esil_runword',
    'r_anal_esil_set_interrupt', 'r_anal_esil_set_op',
    'r_anal_esil_set_pc', 'r_anal_esil_set_syscall',
    'r_anal_esil_setup', 'r_anal_esil_stack_free',
    'r_anal_esil_stats', 'r_anal_esil_to_reil_setup',
    'r_anal_esil_trace_free', 'r_anal_esil_trace_list',
    'r_anal_esil_trace_new', 'r_anal_esil_trace_op',
    'r_anal_esil_trace_restore', 'r_anal_esil_trace_show',
    'r_anal_esil_use', 'r_anal_extract_rarg', 'r_anal_extract_vars',
    'r_anal_fcn', 'r_anal_fcn_add_bb', 'r_anal_fcn_bb',
    'r_anal_fcn_bbadd', 'r_anal_fcn_bbget_at', 'r_anal_fcn_bbget_in',
    'r_anal_fcn_count', 'r_anal_fcn_del', 'r_anal_fcn_del_locs',
    'r_anal_fcn_format_sig', 'r_anal_fcn_invalidate_read_ahead_cache',
    'r_anal_fcn_next', 'r_anal_fcn_var_del_byindex',
    'r_anal_fcn_vars_cache_fini', 'r_anal_fcn_vars_cache_init',
    'r_anal_fcntype_tostring', 'r_anal_free',
    'r_anal_function_add_block', 'r_anal_function_autoname_var',
    'r_anal_function_check_bp_use', 'r_anal_function_complexity',
    'r_anal_function_contains', 'r_anal_function_cost',
    'r_anal_function_count_edges', 'r_anal_function_delete',
    'r_anal_function_delete_all_vars', 'r_anal_function_delete_label',
    'r_anal_function_delete_label_at',
    'r_anal_function_delete_unused_vars',
    'r_anal_function_delete_var',
    'r_anal_function_delete_vars_by_kind', 'r_anal_function_free',
    'r_anal_function_get_json', 'r_anal_function_get_label',
    'r_anal_function_get_label_at', 'r_anal_function_get_refs',
    'r_anal_function_get_signature', 'r_anal_function_get_var',
    'r_anal_function_get_var_byname',
    'r_anal_function_get_var_fields',
    'r_anal_function_get_var_reg_at',
    'r_anal_function_get_var_stackptr_at',
    'r_anal_function_get_vars_used_at', 'r_anal_function_get_xrefs',
    'r_anal_function_linear_size', 'r_anal_function_loops',
    'r_anal_function_max_addr', 'r_anal_function_min_addr',
    'r_anal_function_new', 'r_anal_function_purity',
    'r_anal_function_realsize', 'r_anal_function_rebase_vars',
    'r_anal_function_relocate', 'r_anal_function_remove_block',
    'r_anal_function_rename', 'r_anal_function_resize',
    'r_anal_function_set_label', 'r_anal_function_set_var',
    'r_anal_function_size_from_entry',
    'r_anal_function_update_analysis', 'r_anal_function_was_modified',
    'r_anal_get_base_type', 'r_anal_get_bbaddr',
    'r_anal_get_block_at', 'r_anal_get_blocks_in',
    'r_anal_get_blocks_intersect', 'r_anal_get_fcn_in',
    'r_anal_get_fcn_in_bounds', 'r_anal_get_fcns',
    'r_anal_get_function_at', 'r_anal_get_function_byname',
    'r_anal_get_functions_in', 'r_anal_get_reg_profile',
    'r_anal_get_used_function_var', 'r_anal_hint_arch_at',
    'r_anal_hint_bits_at', 'r_anal_hint_clear', 'r_anal_hint_del',
    'r_anal_hint_free', 'r_anal_hint_get', 'r_anal_hint_set_arch',
    'r_anal_hint_set_bits', 'r_anal_hint_set_esil',
    'r_anal_hint_set_fail', 'r_anal_hint_set_high',
    'r_anal_hint_set_immbase', 'r_anal_hint_set_jump',
    'r_anal_hint_set_newbits', 'r_anal_hint_set_nword',
    'r_anal_hint_set_offset', 'r_anal_hint_set_opcode',
    'r_anal_hint_set_pointer', 'r_anal_hint_set_ret',
    'r_anal_hint_set_size', 'r_anal_hint_set_stackframe',
    'r_anal_hint_set_syntax', 'r_anal_hint_set_type',
    'r_anal_hint_set_val', 'r_anal_hint_unset_arch',
    'r_anal_hint_unset_bits', 'r_anal_hint_unset_esil',
    'r_anal_hint_unset_fail', 'r_anal_hint_unset_high',
    'r_anal_hint_unset_immbase', 'r_anal_hint_unset_jump',
    'r_anal_hint_unset_newbits', 'r_anal_hint_unset_nword',
    'r_anal_hint_unset_offset', 'r_anal_hint_unset_opcode',
    'r_anal_hint_unset_pointer', 'r_anal_hint_unset_ret',
    'r_anal_hint_unset_size', 'r_anal_hint_unset_stackframe',
    'r_anal_hint_unset_syntax', 'r_anal_hint_unset_type',
    'r_anal_hint_unset_val', 'r_anal_is_prelude', 'r_anal_jmptbl',
    'r_anal_list_vtables', 'r_anal_mask', 'r_anal_new',
    'r_anal_noreturn_add', 'r_anal_noreturn_at',
    'r_anal_noreturn_at_addr', 'r_anal_noreturn_drop',
    'r_anal_noreturn_list', 'r_anal_op',
    'r_anal_op_family_from_string', 'r_anal_op_family_to_string',
    'r_anal_op_fini', 'r_anal_op_free', 'r_anal_op_hexstr',
    'r_anal_op_hint', 'r_anal_op_init', 'r_anal_op_is_eob',
    'r_anal_op_ismemref', 'r_anal_op_list_new', 'r_anal_op_new',
    'r_anal_op_nonlinear', 'r_anal_op_reg_delta',
    'r_anal_op_to_string', 'r_anal_optype_from_string',
    'r_anal_optype_to_string', 'r_anal_pin', 'r_anal_pin_call',
    'r_anal_pin_fini', 'r_anal_pin_init', 'r_anal_pin_list',
    'r_anal_pin_unset', 'r_anal_plugin_6502', 'r_anal_plugin_6502_cs',
    'r_anal_plugin_8051', 'r_anal_plugin_amd29k', 'r_anal_plugin_arc',
    'r_anal_plugin_arm_cs', 'r_anal_plugin_arm_gnu',
    'r_anal_plugin_avr', 'r_anal_plugin_bf', 'r_anal_plugin_chip8',
    'r_anal_plugin_cr16', 'r_anal_plugin_cris',
    'r_anal_plugin_dalvik', 'r_anal_plugin_ebc', 'r_anal_plugin_free',
    'r_anal_plugin_gb', 'r_anal_plugin_h8300',
    'r_anal_plugin_hexagon', 'r_anal_plugin_i4004',
    'r_anal_plugin_i8080', 'r_anal_plugin_java',
    'r_anal_plugin_m680x_cs', 'r_anal_plugin_m68k_cs',
    'r_anal_plugin_malbolge', 'r_anal_plugin_mcore',
    'r_anal_plugin_mips_cs', 'r_anal_plugin_mips_gnu',
    'r_anal_plugin_msp430', 'r_anal_plugin_nios2',
    'r_anal_plugin_null', 'r_anal_plugin_or1k', 'r_anal_plugin_pic',
    'r_anal_plugin_ppc_cs', 'r_anal_plugin_ppc_gnu',
    'r_anal_plugin_propeller', 'r_anal_plugin_pyc',
    'r_anal_plugin_riscv', 'r_anal_plugin_riscv_cs',
    'r_anal_plugin_rsp', 'r_anal_plugin_sh', 'r_anal_plugin_snes',
    'r_anal_plugin_sparc_cs', 'r_anal_plugin_sparc_gnu',
    'r_anal_plugin_sysz', 'r_anal_plugin_tms320',
    'r_anal_plugin_tms320c64x', 'r_anal_plugin_tricore',
    'r_anal_plugin_v810', 'r_anal_plugin_v850', 'r_anal_plugin_vax',
    'r_anal_plugin_wasm', 'r_anal_plugin_ws', 'r_anal_plugin_x86',
    'r_anal_plugin_x86_cs', 'r_anal_plugin_x86_im',
    'r_anal_plugin_x86_simple', 'r_anal_plugin_x86_udis',
    'r_anal_plugin_xap', 'r_anal_plugin_xcore_cs',
    'r_anal_plugin_xtensa', 'r_anal_plugin_z80', 'r_anal_preludes',
    'r_anal_purge', 'r_anal_purge_imports', 'r_anal_ref_list_new',
    'r_anal_ref_type_tostring', 'r_anal_reflines_get',
    'r_anal_reflines_middle', 'r_anal_reflines_str',
    'r_anal_reflines_str_free', 'r_anal_refs_get',
    'r_anal_remove_import', 'r_anal_remove_parsed_type',
    'r_anal_rtti_demangle_class_name',
    'r_anal_rtti_itanium_demangle_class_name',
    'r_anal_rtti_itanium_print_at_vtable',
    'r_anal_rtti_itanium_print_class_type_info',
    'r_anal_rtti_itanium_print_si_class_type_info',
    'r_anal_rtti_itanium_print_vmi_class_type_info',
    'r_anal_rtti_itanium_recover_all',
    'r_anal_rtti_msvc_demangle_class_name',
    'r_anal_rtti_msvc_print_at_vtable',
    'r_anal_rtti_msvc_print_base_class_descriptor',
    'r_anal_rtti_msvc_print_class_hierarchy_descriptor',
    'r_anal_rtti_msvc_print_complete_object_locator',
    'r_anal_rtti_msvc_print_type_descriptor',
    'r_anal_rtti_msvc_recover_all', 'r_anal_rtti_print_all',
    'r_anal_rtti_print_at_vtable', 'r_anal_rtti_recover_all',
    'r_anal_save_base_type', 'r_anal_save_parsed_type',
    'r_anal_set_big_endian', 'r_anal_set_bits',
    'r_anal_set_cc_default', 'r_anal_set_cpu', 'r_anal_set_limits',
    'r_anal_set_os', 'r_anal_set_reg_profile',
    'r_anal_set_syscc_default', 'r_anal_set_triplet',
    'r_anal_set_user_ptr', 'r_anal_stackop_tostring',
    'r_anal_str_to_fcn', 'r_anal_str_to_type',
    'r_anal_switch_op_add_case', 'r_anal_switch_op_free',
    'r_anal_switch_op_new', 'r_anal_syscc_default', 'r_anal_trace_bb',
    'r_anal_trim_jmprefs', 'r_anal_type_add', 'r_anal_type_find',
    'r_anal_type_free', 'r_anal_type_list', 'r_anal_type_loadfile',
    'r_anal_type_new', 'r_anal_types_from_fcn', 'r_anal_unset_limits',
    'r_anal_update_analysis_range', 'r_anal_use', 'r_anal_value_copy',
    'r_anal_value_eval', 'r_anal_value_free', 'r_anal_value_new',
    'r_anal_value_new_from_string', 'r_anal_value_set_ut64',
    'r_anal_value_to_string', 'r_anal_value_to_ut64',
    'r_anal_var_add_constraint', 'r_anal_var_addr',
    'r_anal_var_all_list', 'r_anal_var_clear_accesses',
    'r_anal_var_count', 'r_anal_var_delete', 'r_anal_var_display',
    'r_anal_var_get_access_at', 'r_anal_var_get_argnum',
    'r_anal_var_get_constraints_readable', 'r_anal_var_get_dst_var',
    'r_anal_var_list', 'r_anal_var_list_show',
    'r_anal_var_remove_access_at', 'r_anal_var_rename',
    'r_anal_var_set_access', 'r_anal_var_set_type', 'r_anal_version',
    'r_anal_vtable_begin', 'r_anal_vtable_info_free',
    'r_anal_vtable_info_get_size', 'r_anal_vtable_parse_at',
    'r_anal_vtable_search', 'r_anal_xref_del', 'r_anal_xrefs_count',
    'r_anal_xrefs_deln', 'r_anal_xrefs_from', 'r_anal_xrefs_get',
    'r_anal_xrefs_get_from', 'r_anal_xrefs_init', 'r_anal_xrefs_list',
    'r_anal_xrefs_set', 'r_anal_xrefs_type',
    'r_anal_xrefs_type_tostring', 'r_esil_plugin_dummy',
    'r_listrange_add', 'r_listrange_del', 'r_listrange_find_in_range',
    'r_listrange_find_root', 'r_listrange_free', 'r_listrange_new',
    'r_listrange_resize', 'r_meta_del', 'r_meta_get_all_at',
    'r_meta_get_all_in', 'r_meta_get_all_intersect', 'r_meta_get_at',
    'r_meta_get_in', 'r_meta_get_size', 'r_meta_get_string',
    'r_meta_item_size', 'r_meta_node_size', 'r_meta_print',
    'r_meta_print_list_all', 'r_meta_print_list_at',
    'r_meta_print_list_in_function', 'r_meta_rebase', 'r_meta_set',
    'r_meta_set_data_at', 'r_meta_set_string',
    'r_meta_set_with_subtype', 'r_meta_space_count_for',
    'r_meta_space_unset_for', 'r_meta_type_to_string',
    'r_parse_pdb_types', 'r_sign_space_count_for',
    'r_sign_space_rename_for', 'r_sign_space_unset_for', 'size_t',
    'struct_R_PDB7_ROOT_STREAM', 'struct__IO_FILE',
    'struct__IO_codecvt', 'struct__IO_marker', 'struct__IO_wide_data',
    'struct_buffer', 'struct_c__SA_RAnalMetaUserItem',
    'struct_c__SA_RBinDwarfBlock', 'struct_c__SA_RBinDwarfCompUnit',
    'struct_c__SA_RBinDwarfCompUnitHdr',
    'struct_c__SA_RBinDwarfDebugInfo', 'struct_c__SA_RBinDwarfDie',
    'struct_c__SA_RNumCalcValue', 'struct_c__SA_RStrBuf',
    'struct_c__SA_RVTableContext', 'struct_c__SA_dict', 'struct_cdb',
    'struct_cdb_hp', 'struct_cdb_hplist', 'struct_cdb_make',
    'struct_dwarf_attr_kind', 'struct_dwarf_attr_kind_0_0',
    'struct_ht_pp_bucket_t', 'struct_ht_pp_kv',
    'struct_ht_pp_options_t', 'struct_ht_pp_t',
    'struct_ht_up_bucket_t', 'struct_ht_up_kv',
    'struct_ht_up_options_t', 'struct_ht_up_t', 'struct_ls_iter_t',
    'struct_ls_t', 'struct_pj_t', 'struct_r_anal_addr_hint_record_t',
    'struct_r_anal_attr_t', 'struct_r_anal_base_class_t',
    'struct_r_anal_base_type_enum_t',
    'struct_r_anal_base_type_struct_t', 'struct_r_anal_base_type_t',
    'struct_r_anal_base_type_union_t', 'struct_r_anal_bb_t',
    'struct_r_anal_bind_t', 'struct_r_anal_callbacks_t',
    'struct_r_anal_case_obj_t', 'struct_r_anal_cond_t',
    'struct_r_anal_cycle_frame_t', 'struct_r_anal_cycle_hook_t',
    'struct_r_anal_data_t', 'struct_r_anal_diff_t',
    'struct_r_anal_dwarf_context', 'struct_r_anal_enum_case_t',
    'struct_r_anal_esil_active_plugin_t',
    'struct_r_anal_esil_basic_block_t',
    'struct_r_anal_esil_callbacks_t', 'struct_r_anal_esil_cfg_t',
    'struct_r_anal_esil_change_mem_t',
    'struct_r_anal_esil_change_reg_t',
    'struct_r_anal_esil_dfg_node_t', 'struct_r_anal_esil_dfg_t',
    'struct_r_anal_esil_expr_offset_t',
    'struct_r_anal_esil_handler_t', 'struct_r_anal_esil_operation_t',
    'struct_r_anal_esil_plugin_t', 'struct_r_anal_esil_t',
    'struct_r_anal_esil_trace_t', 'struct_r_anal_esil_word_t',
    'struct_r_anal_fcn_meta_t', 'struct_r_anal_fcn_vars_cache',
    'struct_r_anal_func_arg_t', 'struct_r_anal_function_t',
    'struct_r_anal_hint_cb_t', 'struct_r_anal_hint_t',
    'struct_r_anal_meta_item_t', 'struct_r_anal_method_t',
    'struct_r_anal_op_t', 'struct_r_anal_options_t',
    'struct_r_anal_plugin_t', 'struct_r_anal_range_t',
    'struct_r_anal_ref_char', 'struct_r_anal_ref_t',
    'struct_r_anal_refline_t', 'struct_r_anal_reil',
    'struct_r_anal_reil_arg', 'struct_r_anal_reil_inst',
    'struct_r_anal_struct_member_t', 'struct_r_anal_switch_obj_t',
    'struct_r_anal_t', 'struct_r_anal_type_alloca_t',
    'struct_r_anal_type_array_t', 'struct_r_anal_type_ptr_t',
    'struct_r_anal_type_struct_t', 'struct_r_anal_type_t',
    'struct_r_anal_type_union_t', 'struct_r_anal_type_var_t',
    'struct_r_anal_union_member_t', 'struct_r_anal_value_t',
    'struct_r_anal_var_access_t', 'struct_r_anal_var_constraint_t',
    'struct_r_anal_var_field_t', 'struct_r_anal_var_t',
    'struct_r_anal_vtable_t', 'struct_r_bin_addr_t',
    'struct_r_bin_arch_options_t', 'struct_r_bin_bind_t',
    'struct_r_bin_dbginfo_t', 'struct_r_bin_file_t',
    'struct_r_bin_hash_t', 'struct_r_bin_info_t',
    'struct_r_bin_object_t', 'struct_r_bin_plugin_t',
    'struct_r_bin_section_t', 'struct_r_bin_t',
    'struct_r_bin_write_t', 'struct_r_bin_xtr_extract_t',
    'struct_r_bin_xtr_metadata_t', 'struct_r_bin_xtr_plugin_t',
    'struct_r_buf_t', 'struct_r_buffer_methods_t', 'struct_r_cache_t',
    'struct_r_cons_bind_t', 'struct_r_cons_printable_palette_t',
    'struct_r_containing_rb_node_t', 'struct_r_containing_rb_tree_t',
    'struct_r_core_bind_t', 'struct_r_event_t',
    'struct_r_flag_bind_t', 'struct_r_flag_item_t', 'struct_r_flag_t',
    'struct_r_graph_node_t', 'struct_r_graph_t', 'struct_r_id_pool_t',
    'struct_r_id_storage_t', 'struct_r_interval_node_t',
    'struct_r_interval_t', 'struct_r_interval_tree_t',
    'struct_r_io_bind_t', 'struct_r_io_desc_t', 'struct_r_io_map_t',
    'struct_r_io_plugin_t', 'struct_r_io_t', 'struct_r_io_undo_t',
    'struct_r_io_undos_t', 'struct_r_list_iter_t',
    'struct_r_list_range_t', 'struct_r_list_t', 'struct_r_num_calc_t',
    'struct_r_num_t', 'struct_r_pdb_t', 'struct_r_pvector_t',
    'struct_r_queue_t', 'struct_r_rb_node_t', 'struct_r_reg_arena_t',
    'struct_r_reg_item_t', 'struct_r_reg_set_t', 'struct_r_reg_t',
    'struct_r_skiplist_node_t', 'struct_r_skiplist_t',
    'struct_r_skyline_t', 'struct_r_space_t', 'struct_r_spaces_t',
    'struct_r_str_constpool_t', 'struct_r_syscall_item_t',
    'struct_r_syscall_port_t', 'struct_r_syscall_t',
    'struct_r_vector_t', 'struct_rcolor_t', 'struct_sdb_gperf_t',
    'struct_sdb_kv', 'struct_sdb_t', 'struct_vtable_info_t',
    'struct_vtable_method_info_t', 'try_get_delta_jmptbl_info',
    'try_get_jmptbl_info', 'try_walkthrough_casetbl',
    'try_walkthrough_jmptbl', 'union_dwarf_attr_kind_0',
    'union_r_anal_addr_hint_record_t_0', 'union_r_anal_base_type_t_0',
    'union_r_anal_type_array_t_0', 'union_r_anal_type_ptr_t_0',
    'union_r_anal_type_var_t_0', 'walkthrough_arm_jmptbl_style']
