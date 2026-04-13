# -*- coding: utf-8 -*-
#
# WORD_SIZE is: 8
# POINTER_SIZE is: 8
# LONGDOUBLE_SIZE is: 16
#
import ctypes
from .r_libs import r_anal as _libr_anal
from .r_libs import r_arch as _libr_arch
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
                type_ = type_._type_
                if hasattr(type_, 'as_dict'):
                    value = [type_.as_dict(v) for v in value]
                else:
                    value = [i for i in value]
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


__u_char = ctypes.c_ubyte
__u_short = ctypes.c_uint16
__u_int = ctypes.c_uint32
__u_long = ctypes.c_uint64
__int8_t = ctypes.c_byte
__uint8_t = ctypes.c_ubyte
__int16_t = ctypes.c_int16
__uint16_t = ctypes.c_uint16
__int32_t = ctypes.c_int32
__uint32_t = ctypes.c_uint32
__int64_t = ctypes.c_int64
__uint64_t = ctypes.c_uint64
__int_least8_t = ctypes.c_byte
__uint_least8_t = ctypes.c_ubyte
__int_least16_t = ctypes.c_int16
__uint_least16_t = ctypes.c_uint16
__int_least32_t = ctypes.c_int32
__uint_least32_t = ctypes.c_uint32
__int_least64_t = ctypes.c_int64
__uint_least64_t = ctypes.c_uint64
__quad_t = ctypes.c_int64
__u_quad_t = ctypes.c_uint64
__intmax_t = ctypes.c_int64
__uintmax_t = ctypes.c_uint64
__dev_t = ctypes.c_uint64
__uid_t = ctypes.c_uint32
__gid_t = ctypes.c_uint32
__ino_t = ctypes.c_uint64
__ino64_t = ctypes.c_uint64
__mode_t = ctypes.c_uint32
__nlink_t = ctypes.c_uint64
__off_t = ctypes.c_int64
__off64_t = ctypes.c_int64
__pid_t = ctypes.c_int32
class struct___fsid_t(Structure):
    pass

struct___fsid_t._pack_ = 1 # source:False
struct___fsid_t._fields_ = [
    ('__val', ctypes.c_int32 * 2),
]

__fsid_t = struct___fsid_t
__clock_t = ctypes.c_int64
__rlim_t = ctypes.c_uint64
__rlim64_t = ctypes.c_uint64
__id_t = ctypes.c_uint32
__time_t = ctypes.c_int64
__useconds_t = ctypes.c_uint32
__suseconds_t = ctypes.c_int64
__suseconds64_t = ctypes.c_int64
__daddr_t = ctypes.c_int32
__key_t = ctypes.c_int32
__clockid_t = ctypes.c_int32
__timer_t = ctypes.POINTER(None)
__blksize_t = ctypes.c_int64
__blkcnt_t = ctypes.c_int64
__blkcnt64_t = ctypes.c_int64
__fsblkcnt_t = ctypes.c_uint64
__fsblkcnt64_t = ctypes.c_uint64
__fsfilcnt_t = ctypes.c_uint64
__fsfilcnt64_t = ctypes.c_uint64
__fsword_t = ctypes.c_int64
__ssize_t = ctypes.c_int64
__syscall_slong_t = ctypes.c_int64
__syscall_ulong_t = ctypes.c_uint64
__loff_t = ctypes.c_int64
__caddr_t = ctypes.POINTER(ctypes.c_char)
__intptr_t = ctypes.c_int64
__socklen_t = ctypes.c_uint32
__sig_atomic_t = ctypes.c_int32

# values for enumeration 'c__Ea__ISupper'
c__Ea__ISupper__enumvalues = {
    256: '_ISupper',
    512: '_ISlower',
    1024: '_ISalpha',
    2048: '_ISdigit',
    4096: '_ISxdigit',
    8192: '_ISspace',
    16384: '_ISprint',
    32768: '_ISgraph',
    1: '_ISblank',
    2: '_IScntrl',
    4: '_ISpunct',
    8: '_ISalnum',
}
_ISupper = 256
_ISlower = 512
_ISalpha = 1024
_ISdigit = 2048
_ISxdigit = 4096
_ISspace = 8192
_ISprint = 16384
_ISgraph = 32768
_ISblank = 1
_IScntrl = 2
_ISpunct = 4
_ISalnum = 8
c__Ea__ISupper = ctypes.c_uint32 # enum
try:
    __ctype_b_loc = _libraries['FIXME_STUB'].__ctype_b_loc
    __ctype_b_loc.restype = ctypes.POINTER(ctypes.POINTER(ctypes.c_uint16))
    __ctype_b_loc.argtypes = []
except AttributeError:
    pass
try:
    __ctype_tolower_loc = _libraries['FIXME_STUB'].__ctype_tolower_loc
    __ctype_tolower_loc.restype = ctypes.POINTER(ctypes.POINTER(ctypes.c_int32))
    __ctype_tolower_loc.argtypes = []
except AttributeError:
    pass
try:
    __ctype_toupper_loc = _libraries['FIXME_STUB'].__ctype_toupper_loc
    __ctype_toupper_loc.restype = ctypes.POINTER(ctypes.POINTER(ctypes.c_int32))
    __ctype_toupper_loc.argtypes = []
except AttributeError:
    pass
try:
    isalnum = _libraries['FIXME_STUB'].isalnum
    isalnum.restype = ctypes.c_int32
    isalnum.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    isalpha = _libraries['FIXME_STUB'].isalpha
    isalpha.restype = ctypes.c_int32
    isalpha.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    iscntrl = _libraries['FIXME_STUB'].iscntrl
    iscntrl.restype = ctypes.c_int32
    iscntrl.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    isdigit = _libraries['FIXME_STUB'].isdigit
    isdigit.restype = ctypes.c_int32
    isdigit.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    islower = _libraries['FIXME_STUB'].islower
    islower.restype = ctypes.c_int32
    islower.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    isgraph = _libraries['FIXME_STUB'].isgraph
    isgraph.restype = ctypes.c_int32
    isgraph.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    isprint = _libraries['FIXME_STUB'].isprint
    isprint.restype = ctypes.c_int32
    isprint.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    ispunct = _libraries['FIXME_STUB'].ispunct
    ispunct.restype = ctypes.c_int32
    ispunct.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    isspace = _libraries['FIXME_STUB'].isspace
    isspace.restype = ctypes.c_int32
    isspace.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    isupper = _libraries['FIXME_STUB'].isupper
    isupper.restype = ctypes.c_int32
    isupper.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    isxdigit = _libraries['FIXME_STUB'].isxdigit
    isxdigit.restype = ctypes.c_int32
    isxdigit.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    tolower = _libraries['FIXME_STUB'].tolower
    tolower.restype = ctypes.c_int32
    tolower.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    toupper = _libraries['FIXME_STUB'].toupper
    toupper.restype = ctypes.c_int32
    toupper.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    isblank = _libraries['FIXME_STUB'].isblank
    isblank.restype = ctypes.c_int32
    isblank.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    isascii = _libraries['FIXME_STUB'].isascii
    isascii.restype = ctypes.c_int32
    isascii.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    toascii = _libraries['FIXME_STUB'].toascii
    toascii.restype = ctypes.c_int32
    toascii.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    _toupper = _libraries['FIXME_STUB']._toupper
    _toupper.restype = ctypes.c_int32
    _toupper.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    _tolower = _libraries['FIXME_STUB']._tolower
    _tolower.restype = ctypes.c_int32
    _tolower.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
class struct___locale_struct(Structure):
    pass

class struct___locale_data(Structure):
    pass

struct___locale_struct._pack_ = 1 # source:False
struct___locale_struct._fields_ = [
    ('__locales', ctypes.POINTER(struct___locale_data) * 13),
    ('__ctype_b', ctypes.POINTER(ctypes.c_uint16)),
    ('__ctype_tolower', ctypes.POINTER(ctypes.c_int32)),
    ('__ctype_toupper', ctypes.POINTER(ctypes.c_int32)),
    ('__names', ctypes.POINTER(ctypes.c_char) * 13),
]

__locale_t = ctypes.POINTER(struct___locale_struct)
locale_t = ctypes.POINTER(struct___locale_struct)
try:
    isalnum_l = _libraries['FIXME_STUB'].isalnum_l
    isalnum_l.restype = ctypes.c_int32
    isalnum_l.argtypes = [ctypes.c_int32, locale_t]
except AttributeError:
    pass
try:
    isalpha_l = _libraries['FIXME_STUB'].isalpha_l
    isalpha_l.restype = ctypes.c_int32
    isalpha_l.argtypes = [ctypes.c_int32, locale_t]
except AttributeError:
    pass
try:
    iscntrl_l = _libraries['FIXME_STUB'].iscntrl_l
    iscntrl_l.restype = ctypes.c_int32
    iscntrl_l.argtypes = [ctypes.c_int32, locale_t]
except AttributeError:
    pass
try:
    isdigit_l = _libraries['FIXME_STUB'].isdigit_l
    isdigit_l.restype = ctypes.c_int32
    isdigit_l.argtypes = [ctypes.c_int32, locale_t]
except AttributeError:
    pass
try:
    islower_l = _libraries['FIXME_STUB'].islower_l
    islower_l.restype = ctypes.c_int32
    islower_l.argtypes = [ctypes.c_int32, locale_t]
except AttributeError:
    pass
try:
    isgraph_l = _libraries['FIXME_STUB'].isgraph_l
    isgraph_l.restype = ctypes.c_int32
    isgraph_l.argtypes = [ctypes.c_int32, locale_t]
except AttributeError:
    pass
try:
    isprint_l = _libraries['FIXME_STUB'].isprint_l
    isprint_l.restype = ctypes.c_int32
    isprint_l.argtypes = [ctypes.c_int32, locale_t]
except AttributeError:
    pass
try:
    ispunct_l = _libraries['FIXME_STUB'].ispunct_l
    ispunct_l.restype = ctypes.c_int32
    ispunct_l.argtypes = [ctypes.c_int32, locale_t]
except AttributeError:
    pass
try:
    isspace_l = _libraries['FIXME_STUB'].isspace_l
    isspace_l.restype = ctypes.c_int32
    isspace_l.argtypes = [ctypes.c_int32, locale_t]
except AttributeError:
    pass
try:
    isupper_l = _libraries['FIXME_STUB'].isupper_l
    isupper_l.restype = ctypes.c_int32
    isupper_l.argtypes = [ctypes.c_int32, locale_t]
except AttributeError:
    pass
try:
    isxdigit_l = _libraries['FIXME_STUB'].isxdigit_l
    isxdigit_l.restype = ctypes.c_int32
    isxdigit_l.argtypes = [ctypes.c_int32, locale_t]
except AttributeError:
    pass
try:
    isblank_l = _libraries['FIXME_STUB'].isblank_l
    isblank_l.restype = ctypes.c_int32
    isblank_l.argtypes = [ctypes.c_int32, locale_t]
except AttributeError:
    pass
try:
    __tolower_l = _libraries['FIXME_STUB'].__tolower_l
    __tolower_l.restype = ctypes.c_int32
    __tolower_l.argtypes = [ctypes.c_int32, locale_t]
except AttributeError:
    pass
try:
    tolower_l = _libraries['FIXME_STUB'].tolower_l
    tolower_l.restype = ctypes.c_int32
    tolower_l.argtypes = [ctypes.c_int32, locale_t]
except AttributeError:
    pass
try:
    __toupper_l = _libraries['FIXME_STUB'].__toupper_l
    __toupper_l.restype = ctypes.c_int32
    __toupper_l.argtypes = [ctypes.c_int32, locale_t]
except AttributeError:
    pass
try:
    toupper_l = _libraries['FIXME_STUB'].toupper_l
    toupper_l.restype = ctypes.c_int32
    toupper_l.argtypes = [ctypes.c_int32, locale_t]
except AttributeError:
    pass
u_char = ctypes.c_ubyte
u_short = ctypes.c_uint16
u_int = ctypes.c_uint32
u_long = ctypes.c_uint64
quad_t = ctypes.c_int64
u_quad_t = ctypes.c_uint64
fsid_t = struct___fsid_t
loff_t = ctypes.c_int64
ino_t = ctypes.c_uint64
dev_t = ctypes.c_uint64
gid_t = ctypes.c_uint32
mode_t = ctypes.c_uint32
nlink_t = ctypes.c_uint64
uid_t = ctypes.c_uint32
off_t = ctypes.c_int64
pid_t = ctypes.c_int32
id_t = ctypes.c_uint32
ssize_t = ctypes.c_int64
daddr_t = ctypes.c_int32
caddr_t = ctypes.POINTER(ctypes.c_char)
key_t = ctypes.c_int32
clock_t = ctypes.c_int64
clockid_t = ctypes.c_int32
time_t = ctypes.c_int64
timer_t = ctypes.POINTER(None)
size_t = ctypes.c_uint64
ulong = ctypes.c_uint64
ushort = ctypes.c_uint16
uint = ctypes.c_uint32
int8_t = ctypes.c_int8
int16_t = ctypes.c_int16
int32_t = ctypes.c_int32
int64_t = ctypes.c_int64
u_int8_t = ctypes.c_ubyte
u_int16_t = ctypes.c_uint16
u_int32_t = ctypes.c_uint32
u_int64_t = ctypes.c_uint64
register_t = ctypes.c_int64
try:
    __bswap_16 = _libraries['FIXME_STUB'].__bswap_16
    __bswap_16.restype = __uint16_t
    __bswap_16.argtypes = [__uint16_t]
except AttributeError:
    pass
try:
    __bswap_32 = _libraries['FIXME_STUB'].__bswap_32
    __bswap_32.restype = __uint32_t
    __bswap_32.argtypes = [__uint32_t]
except AttributeError:
    pass
try:
    __bswap_64 = _libraries['FIXME_STUB'].__bswap_64
    __bswap_64.restype = __uint64_t
    __bswap_64.argtypes = [__uint64_t]
except AttributeError:
    pass
try:
    __uint16_identity = _libraries['FIXME_STUB'].__uint16_identity
    __uint16_identity.restype = __uint16_t
    __uint16_identity.argtypes = [__uint16_t]
except AttributeError:
    pass
try:
    __uint32_identity = _libraries['FIXME_STUB'].__uint32_identity
    __uint32_identity.restype = __uint32_t
    __uint32_identity.argtypes = [__uint32_t]
except AttributeError:
    pass
try:
    __uint64_identity = _libraries['FIXME_STUB'].__uint64_identity
    __uint64_identity.restype = __uint64_t
    __uint64_identity.argtypes = [__uint64_t]
except AttributeError:
    pass
class struct___sigset_t(Structure):
    pass

struct___sigset_t._pack_ = 1 # source:False
struct___sigset_t._fields_ = [
    ('__val', ctypes.c_uint64 * 16),
]

__sigset_t = struct___sigset_t
sigset_t = struct___sigset_t
class struct_timeval(Structure):
    pass

struct_timeval._pack_ = 1 # source:False
struct_timeval._fields_ = [
    ('tv_sec', ctypes.c_int64),
    ('tv_usec', ctypes.c_int64),
]

class struct_timespec(Structure):
    pass

struct_timespec._pack_ = 1 # source:False
struct_timespec._fields_ = [
    ('tv_sec', ctypes.c_int64),
    ('tv_nsec', ctypes.c_int64),
]

suseconds_t = ctypes.c_int64
__fd_mask = ctypes.c_int64
class struct_fd_set(Structure):
    pass

struct_fd_set._pack_ = 1 # source:False
struct_fd_set._fields_ = [
    ('__fds_bits', ctypes.c_int64 * 16),
]

fd_set = struct_fd_set
fd_mask = ctypes.c_int64
try:
    select = _libraries['FIXME_STUB'].select
    select.restype = ctypes.c_int32
    select.argtypes = [ctypes.c_int32, ctypes.POINTER(struct_fd_set), ctypes.POINTER(struct_fd_set), ctypes.POINTER(struct_fd_set), ctypes.POINTER(struct_timeval)]
except AttributeError:
    pass
try:
    pselect = _libraries['FIXME_STUB'].pselect
    pselect.restype = ctypes.c_int32
    pselect.argtypes = [ctypes.c_int32, ctypes.POINTER(struct_fd_set), ctypes.POINTER(struct_fd_set), ctypes.POINTER(struct_fd_set), ctypes.POINTER(struct_timespec), ctypes.POINTER(struct___sigset_t)]
except AttributeError:
    pass
blksize_t = ctypes.c_int64
blkcnt_t = ctypes.c_int64
fsblkcnt_t = ctypes.c_uint64
fsfilcnt_t = ctypes.c_uint64
class union___atomic_wide_counter(Union):
    pass

class struct___atomic_wide_counter___value32(Structure):
    pass

struct___atomic_wide_counter___value32._pack_ = 1 # source:False
struct___atomic_wide_counter___value32._fields_ = [
    ('__low', ctypes.c_uint32),
    ('__high', ctypes.c_uint32),
]

union___atomic_wide_counter._pack_ = 1 # source:False
union___atomic_wide_counter._fields_ = [
    ('__value64', ctypes.c_uint64),
    ('__value32', struct___atomic_wide_counter___value32),
]

__atomic_wide_counter = union___atomic_wide_counter
class struct___pthread_internal_list(Structure):
    pass

struct___pthread_internal_list._pack_ = 1 # source:False
struct___pthread_internal_list._fields_ = [
    ('__prev', ctypes.POINTER(struct___pthread_internal_list)),
    ('__next', ctypes.POINTER(struct___pthread_internal_list)),
]

__pthread_list_t = struct___pthread_internal_list
class struct___pthread_internal_slist(Structure):
    pass

struct___pthread_internal_slist._pack_ = 1 # source:False
struct___pthread_internal_slist._fields_ = [
    ('__next', ctypes.POINTER(struct___pthread_internal_slist)),
]

__pthread_slist_t = struct___pthread_internal_slist
class struct___pthread_mutex_s(Structure):
    pass

struct___pthread_mutex_s._pack_ = 1 # source:False
struct___pthread_mutex_s._fields_ = [
    ('__lock', ctypes.c_int32),
    ('__count', ctypes.c_uint32),
    ('__owner', ctypes.c_int32),
    ('__nusers', ctypes.c_uint32),
    ('__kind', ctypes.c_int32),
    ('__spins', ctypes.c_int16),
    ('__elision', ctypes.c_int16),
    ('__list', globals()['__pthread_list_t']),
]

class struct___pthread_rwlock_arch_t(Structure):
    pass

struct___pthread_rwlock_arch_t._pack_ = 1 # source:False
struct___pthread_rwlock_arch_t._fields_ = [
    ('__readers', ctypes.c_uint32),
    ('__writers', ctypes.c_uint32),
    ('__wrphase_futex', ctypes.c_uint32),
    ('__writers_futex', ctypes.c_uint32),
    ('__pad3', ctypes.c_uint32),
    ('__pad4', ctypes.c_uint32),
    ('__cur_writer', ctypes.c_int32),
    ('__shared', ctypes.c_int32),
    ('__rwelision', ctypes.c_byte),
    ('__pad1', ctypes.c_ubyte * 7),
    ('__pad2', ctypes.c_uint64),
    ('__flags', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

class struct___pthread_cond_s(Structure):
    pass

struct___pthread_cond_s._pack_ = 1 # source:False
struct___pthread_cond_s._fields_ = [
    ('__wseq', globals()['__atomic_wide_counter']),
    ('__g1_start', globals()['__atomic_wide_counter']),
    ('__g_refs', ctypes.c_uint32 * 2),
    ('__g_size', ctypes.c_uint32 * 2),
    ('__g1_orig_size', ctypes.c_uint32),
    ('__wrefs', ctypes.c_uint32),
    ('__g_signals', ctypes.c_uint32 * 2),
]

__tss_t = ctypes.c_uint32
__thrd_t = ctypes.c_uint64
class struct___once_flag(Structure):
    pass

struct___once_flag._pack_ = 1 # source:False
struct___once_flag._fields_ = [
    ('__data', ctypes.c_int32),
]

__once_flag = struct___once_flag
pthread_t = ctypes.c_uint64
class union_pthread_mutexattr_t(Union):
    pass

union_pthread_mutexattr_t._pack_ = 1 # source:False
union_pthread_mutexattr_t._fields_ = [
    ('__size', ctypes.c_char * 4),
    ('__align', ctypes.c_int32),
]

pthread_mutexattr_t = union_pthread_mutexattr_t
class union_pthread_condattr_t(Union):
    pass

union_pthread_condattr_t._pack_ = 1 # source:False
union_pthread_condattr_t._fields_ = [
    ('__size', ctypes.c_char * 4),
    ('__align', ctypes.c_int32),
]

pthread_condattr_t = union_pthread_condattr_t
pthread_key_t = ctypes.c_uint32
pthread_once_t = ctypes.c_int32
class union_pthread_attr_t(Union):
    pass

union_pthread_attr_t._pack_ = 1 # source:False
union_pthread_attr_t._fields_ = [
    ('__size', ctypes.c_char * 56),
    ('__align', ctypes.c_int64),
    ('PADDING_0', ctypes.c_ubyte * 48),
]

pthread_attr_t = union_pthread_attr_t
class union_pthread_mutex_t(Union):
    pass

union_pthread_mutex_t._pack_ = 1 # source:False
union_pthread_mutex_t._fields_ = [
    ('__data', struct___pthread_mutex_s),
    ('__size', ctypes.c_char * 40),
    ('__align', ctypes.c_int64),
    ('PADDING_0', ctypes.c_ubyte * 32),
]

pthread_mutex_t = union_pthread_mutex_t
class union_pthread_cond_t(Union):
    pass

union_pthread_cond_t._pack_ = 1 # source:False
union_pthread_cond_t._fields_ = [
    ('__data', struct___pthread_cond_s),
    ('__size', ctypes.c_char * 48),
    ('__align', ctypes.c_int64),
    ('PADDING_0', ctypes.c_ubyte * 40),
]

pthread_cond_t = union_pthread_cond_t
class union_pthread_rwlock_t(Union):
    pass

union_pthread_rwlock_t._pack_ = 1 # source:False
union_pthread_rwlock_t._fields_ = [
    ('__data', struct___pthread_rwlock_arch_t),
    ('__size', ctypes.c_char * 56),
    ('__align', ctypes.c_int64),
    ('PADDING_0', ctypes.c_ubyte * 48),
]

pthread_rwlock_t = union_pthread_rwlock_t
class union_pthread_rwlockattr_t(Union):
    pass

union_pthread_rwlockattr_t._pack_ = 1 # source:False
union_pthread_rwlockattr_t._fields_ = [
    ('__size', ctypes.c_char * 8),
    ('__align', ctypes.c_int64),
]

pthread_rwlockattr_t = union_pthread_rwlockattr_t
pthread_spinlock_t = ctypes.c_int32
class union_pthread_barrier_t(Union):
    pass

union_pthread_barrier_t._pack_ = 1 # source:False
union_pthread_barrier_t._fields_ = [
    ('__size', ctypes.c_char * 32),
    ('__align', ctypes.c_int64),
    ('PADDING_0', ctypes.c_ubyte * 24),
]

pthread_barrier_t = union_pthread_barrier_t
class union_pthread_barrierattr_t(Union):
    pass

union_pthread_barrierattr_t._pack_ = 1 # source:False
union_pthread_barrierattr_t._fields_ = [
    ('__size', ctypes.c_char * 4),
    ('__align', ctypes.c_int32),
]

pthread_barrierattr_t = union_pthread_barrierattr_t
uint8_t = ctypes.c_uint8
uint16_t = ctypes.c_uint16
uint32_t = ctypes.c_uint32
uint64_t = ctypes.c_uint64
int_least8_t = ctypes.c_byte
int_least16_t = ctypes.c_int16
int_least32_t = ctypes.c_int32
int_least64_t = ctypes.c_int64
uint_least8_t = ctypes.c_ubyte
uint_least16_t = ctypes.c_uint16
uint_least32_t = ctypes.c_uint32
uint_least64_t = ctypes.c_uint64
int_fast8_t = ctypes.c_byte
int_fast16_t = ctypes.c_int64
int_fast32_t = ctypes.c_int64
int_fast64_t = ctypes.c_int64
uint_fast8_t = ctypes.c_ubyte
uint_fast16_t = ctypes.c_uint64
uint_fast32_t = ctypes.c_uint64
uint_fast64_t = ctypes.c_uint64
intptr_t = ctypes.c_int64
uintptr_t = ctypes.c_uint64
intmax_t = ctypes.c_int64
uintmax_t = ctypes.c_uint64
_Float32 = ctypes.c_float
_Float64 = ctypes.c_double
_Float32x = ctypes.c_double
_Float64x = c_long_double_t
float_t = ctypes.c_float
double_t = ctypes.c_double
try:
    __fpclassify = _libraries['FIXME_STUB'].__fpclassify
    __fpclassify.restype = ctypes.c_int32
    __fpclassify.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __signbit = _libraries['FIXME_STUB'].__signbit
    __signbit.restype = ctypes.c_int32
    __signbit.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __isinf = _libraries['FIXME_STUB'].__isinf
    __isinf.restype = ctypes.c_int32
    __isinf.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __finite = _libraries['FIXME_STUB'].__finite
    __finite.restype = ctypes.c_int32
    __finite.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __isnan = _libraries['FIXME_STUB'].__isnan
    __isnan.restype = ctypes.c_int32
    __isnan.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __iseqsig = _libraries['FIXME_STUB'].__iseqsig
    __iseqsig.restype = ctypes.c_int32
    __iseqsig.argtypes = [ctypes.c_double, ctypes.c_double]
except AttributeError:
    pass
try:
    __issignaling = _libraries['FIXME_STUB'].__issignaling
    __issignaling.restype = ctypes.c_int32
    __issignaling.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    acos = _libraries['FIXME_STUB'].acos
    acos.restype = ctypes.c_double
    acos.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __acos = _libraries['FIXME_STUB'].__acos
    __acos.restype = ctypes.c_double
    __acos.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    asin = _libraries['FIXME_STUB'].asin
    asin.restype = ctypes.c_double
    asin.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __asin = _libraries['FIXME_STUB'].__asin
    __asin.restype = ctypes.c_double
    __asin.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    atan = _libraries['FIXME_STUB'].atan
    atan.restype = ctypes.c_double
    atan.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __atan = _libraries['FIXME_STUB'].__atan
    __atan.restype = ctypes.c_double
    __atan.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    atan2 = _libraries['FIXME_STUB'].atan2
    atan2.restype = ctypes.c_double
    atan2.argtypes = [ctypes.c_double, ctypes.c_double]
except AttributeError:
    pass
try:
    __atan2 = _libraries['FIXME_STUB'].__atan2
    __atan2.restype = ctypes.c_double
    __atan2.argtypes = [ctypes.c_double, ctypes.c_double]
except AttributeError:
    pass
try:
    cos = _libraries['FIXME_STUB'].cos
    cos.restype = ctypes.c_double
    cos.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __cos = _libraries['FIXME_STUB'].__cos
    __cos.restype = ctypes.c_double
    __cos.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    sin = _libraries['FIXME_STUB'].sin
    sin.restype = ctypes.c_double
    sin.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __sin = _libraries['FIXME_STUB'].__sin
    __sin.restype = ctypes.c_double
    __sin.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    tan = _libraries['FIXME_STUB'].tan
    tan.restype = ctypes.c_double
    tan.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __tan = _libraries['FIXME_STUB'].__tan
    __tan.restype = ctypes.c_double
    __tan.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    cosh = _libraries['FIXME_STUB'].cosh
    cosh.restype = ctypes.c_double
    cosh.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __cosh = _libraries['FIXME_STUB'].__cosh
    __cosh.restype = ctypes.c_double
    __cosh.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    sinh = _libraries['FIXME_STUB'].sinh
    sinh.restype = ctypes.c_double
    sinh.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __sinh = _libraries['FIXME_STUB'].__sinh
    __sinh.restype = ctypes.c_double
    __sinh.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    tanh = _libraries['FIXME_STUB'].tanh
    tanh.restype = ctypes.c_double
    tanh.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __tanh = _libraries['FIXME_STUB'].__tanh
    __tanh.restype = ctypes.c_double
    __tanh.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    acosh = _libraries['FIXME_STUB'].acosh
    acosh.restype = ctypes.c_double
    acosh.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __acosh = _libraries['FIXME_STUB'].__acosh
    __acosh.restype = ctypes.c_double
    __acosh.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    asinh = _libraries['FIXME_STUB'].asinh
    asinh.restype = ctypes.c_double
    asinh.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __asinh = _libraries['FIXME_STUB'].__asinh
    __asinh.restype = ctypes.c_double
    __asinh.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    atanh = _libraries['FIXME_STUB'].atanh
    atanh.restype = ctypes.c_double
    atanh.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __atanh = _libraries['FIXME_STUB'].__atanh
    __atanh.restype = ctypes.c_double
    __atanh.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    exp = _libraries['FIXME_STUB'].exp
    exp.restype = ctypes.c_double
    exp.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __exp = _libraries['FIXME_STUB'].__exp
    __exp.restype = ctypes.c_double
    __exp.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    frexp = _libraries['FIXME_STUB'].frexp
    frexp.restype = ctypes.c_double
    frexp.argtypes = [ctypes.c_double, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    __frexp = _libraries['FIXME_STUB'].__frexp
    __frexp.restype = ctypes.c_double
    __frexp.argtypes = [ctypes.c_double, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    ldexp = _libraries['FIXME_STUB'].ldexp
    ldexp.restype = ctypes.c_double
    ldexp.argtypes = [ctypes.c_double, ctypes.c_int32]
except AttributeError:
    pass
try:
    __ldexp = _libraries['FIXME_STUB'].__ldexp
    __ldexp.restype = ctypes.c_double
    __ldexp.argtypes = [ctypes.c_double, ctypes.c_int32]
except AttributeError:
    pass
try:
    log = _libraries['FIXME_STUB'].log
    log.restype = ctypes.c_double
    log.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __log = _libraries['FIXME_STUB'].__log
    __log.restype = ctypes.c_double
    __log.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    log10 = _libraries['FIXME_STUB'].log10
    log10.restype = ctypes.c_double
    log10.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __log10 = _libraries['FIXME_STUB'].__log10
    __log10.restype = ctypes.c_double
    __log10.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    modf = _libraries['FIXME_STUB'].modf
    modf.restype = ctypes.c_double
    modf.argtypes = [ctypes.c_double, ctypes.POINTER(ctypes.c_double)]
except AttributeError:
    pass
try:
    __modf = _libraries['FIXME_STUB'].__modf
    __modf.restype = ctypes.c_double
    __modf.argtypes = [ctypes.c_double, ctypes.POINTER(ctypes.c_double)]
except AttributeError:
    pass
try:
    expm1 = _libraries['FIXME_STUB'].expm1
    expm1.restype = ctypes.c_double
    expm1.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __expm1 = _libraries['FIXME_STUB'].__expm1
    __expm1.restype = ctypes.c_double
    __expm1.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    log1p = _libraries['FIXME_STUB'].log1p
    log1p.restype = ctypes.c_double
    log1p.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __log1p = _libraries['FIXME_STUB'].__log1p
    __log1p.restype = ctypes.c_double
    __log1p.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    logb = _libraries['FIXME_STUB'].logb
    logb.restype = ctypes.c_double
    logb.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __logb = _libraries['FIXME_STUB'].__logb
    __logb.restype = ctypes.c_double
    __logb.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    exp2 = _libraries['FIXME_STUB'].exp2
    exp2.restype = ctypes.c_double
    exp2.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __exp2 = _libraries['FIXME_STUB'].__exp2
    __exp2.restype = ctypes.c_double
    __exp2.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    log2 = _libraries['FIXME_STUB'].log2
    log2.restype = ctypes.c_double
    log2.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __log2 = _libraries['FIXME_STUB'].__log2
    __log2.restype = ctypes.c_double
    __log2.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    pow = _libraries['FIXME_STUB'].pow
    pow.restype = ctypes.c_double
    pow.argtypes = [ctypes.c_double, ctypes.c_double]
except AttributeError:
    pass
try:
    __pow = _libraries['FIXME_STUB'].__pow
    __pow.restype = ctypes.c_double
    __pow.argtypes = [ctypes.c_double, ctypes.c_double]
except AttributeError:
    pass
try:
    sqrt = _libraries['FIXME_STUB'].sqrt
    sqrt.restype = ctypes.c_double
    sqrt.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __sqrt = _libraries['FIXME_STUB'].__sqrt
    __sqrt.restype = ctypes.c_double
    __sqrt.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    hypot = _libraries['FIXME_STUB'].hypot
    hypot.restype = ctypes.c_double
    hypot.argtypes = [ctypes.c_double, ctypes.c_double]
except AttributeError:
    pass
try:
    __hypot = _libraries['FIXME_STUB'].__hypot
    __hypot.restype = ctypes.c_double
    __hypot.argtypes = [ctypes.c_double, ctypes.c_double]
except AttributeError:
    pass
try:
    cbrt = _libraries['FIXME_STUB'].cbrt
    cbrt.restype = ctypes.c_double
    cbrt.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __cbrt = _libraries['FIXME_STUB'].__cbrt
    __cbrt.restype = ctypes.c_double
    __cbrt.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    ceil = _libraries['FIXME_STUB'].ceil
    ceil.restype = ctypes.c_double
    ceil.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __ceil = _libraries['FIXME_STUB'].__ceil
    __ceil.restype = ctypes.c_double
    __ceil.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    fabs = _libraries['FIXME_STUB'].fabs
    fabs.restype = ctypes.c_double
    fabs.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __fabs = _libraries['FIXME_STUB'].__fabs
    __fabs.restype = ctypes.c_double
    __fabs.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    floor = _libraries['FIXME_STUB'].floor
    floor.restype = ctypes.c_double
    floor.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __floor = _libraries['FIXME_STUB'].__floor
    __floor.restype = ctypes.c_double
    __floor.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    fmod = _libraries['FIXME_STUB'].fmod
    fmod.restype = ctypes.c_double
    fmod.argtypes = [ctypes.c_double, ctypes.c_double]
except AttributeError:
    pass
try:
    __fmod = _libraries['FIXME_STUB'].__fmod
    __fmod.restype = ctypes.c_double
    __fmod.argtypes = [ctypes.c_double, ctypes.c_double]
except AttributeError:
    pass
try:
    isinf = _libraries['FIXME_STUB'].isinf
    isinf.restype = ctypes.c_int32
    isinf.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    finite = _libraries['FIXME_STUB'].finite
    finite.restype = ctypes.c_int32
    finite.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    drem = _libraries['FIXME_STUB'].drem
    drem.restype = ctypes.c_double
    drem.argtypes = [ctypes.c_double, ctypes.c_double]
except AttributeError:
    pass
try:
    __drem = _libraries['FIXME_STUB'].__drem
    __drem.restype = ctypes.c_double
    __drem.argtypes = [ctypes.c_double, ctypes.c_double]
except AttributeError:
    pass
try:
    significand = _libraries['FIXME_STUB'].significand
    significand.restype = ctypes.c_double
    significand.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __significand = _libraries['FIXME_STUB'].__significand
    __significand.restype = ctypes.c_double
    __significand.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    copysign = _libraries['FIXME_STUB'].copysign
    copysign.restype = ctypes.c_double
    copysign.argtypes = [ctypes.c_double, ctypes.c_double]
except AttributeError:
    pass
try:
    __copysign = _libraries['FIXME_STUB'].__copysign
    __copysign.restype = ctypes.c_double
    __copysign.argtypes = [ctypes.c_double, ctypes.c_double]
except AttributeError:
    pass
try:
    nan = _libraries['FIXME_STUB'].nan
    nan.restype = ctypes.c_double
    nan.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    __nan = _libraries['FIXME_STUB'].__nan
    __nan.restype = ctypes.c_double
    __nan.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    isnan = _libraries['FIXME_STUB'].isnan
    isnan.restype = ctypes.c_int32
    isnan.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    j0 = _libraries['FIXME_STUB'].j0
    j0.restype = ctypes.c_double
    j0.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __j0 = _libraries['FIXME_STUB'].__j0
    __j0.restype = ctypes.c_double
    __j0.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    j1 = _libraries['FIXME_STUB'].j1
    j1.restype = ctypes.c_double
    j1.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __j1 = _libraries['FIXME_STUB'].__j1
    __j1.restype = ctypes.c_double
    __j1.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    jn = _libraries['FIXME_STUB'].jn
    jn.restype = ctypes.c_double
    jn.argtypes = [ctypes.c_int32, ctypes.c_double]
except AttributeError:
    pass
try:
    __jn = _libraries['FIXME_STUB'].__jn
    __jn.restype = ctypes.c_double
    __jn.argtypes = [ctypes.c_int32, ctypes.c_double]
except AttributeError:
    pass
try:
    y0 = _libraries['FIXME_STUB'].y0
    y0.restype = ctypes.c_double
    y0.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __y0 = _libraries['FIXME_STUB'].__y0
    __y0.restype = ctypes.c_double
    __y0.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    y1 = _libraries['FIXME_STUB'].y1
    y1.restype = ctypes.c_double
    y1.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __y1 = _libraries['FIXME_STUB'].__y1
    __y1.restype = ctypes.c_double
    __y1.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    yn = _libraries['FIXME_STUB'].yn
    yn.restype = ctypes.c_double
    yn.argtypes = [ctypes.c_int32, ctypes.c_double]
except AttributeError:
    pass
try:
    __yn = _libraries['FIXME_STUB'].__yn
    __yn.restype = ctypes.c_double
    __yn.argtypes = [ctypes.c_int32, ctypes.c_double]
except AttributeError:
    pass
try:
    erf = _libraries['FIXME_STUB'].erf
    erf.restype = ctypes.c_double
    erf.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __erf = _libraries['FIXME_STUB'].__erf
    __erf.restype = ctypes.c_double
    __erf.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    erfc = _libraries['FIXME_STUB'].erfc
    erfc.restype = ctypes.c_double
    erfc.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __erfc = _libraries['FIXME_STUB'].__erfc
    __erfc.restype = ctypes.c_double
    __erfc.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    lgamma = _libraries['FIXME_STUB'].lgamma
    lgamma.restype = ctypes.c_double
    lgamma.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __lgamma = _libraries['FIXME_STUB'].__lgamma
    __lgamma.restype = ctypes.c_double
    __lgamma.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    tgamma = _libraries['FIXME_STUB'].tgamma
    tgamma.restype = ctypes.c_double
    tgamma.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __tgamma = _libraries['FIXME_STUB'].__tgamma
    __tgamma.restype = ctypes.c_double
    __tgamma.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    gamma = _libraries['FIXME_STUB'].gamma
    gamma.restype = ctypes.c_double
    gamma.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __gamma = _libraries['FIXME_STUB'].__gamma
    __gamma.restype = ctypes.c_double
    __gamma.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    lgamma_r = _libraries['FIXME_STUB'].lgamma_r
    lgamma_r.restype = ctypes.c_double
    lgamma_r.argtypes = [ctypes.c_double, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    __lgamma_r = _libraries['FIXME_STUB'].__lgamma_r
    __lgamma_r.restype = ctypes.c_double
    __lgamma_r.argtypes = [ctypes.c_double, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    rint = _libraries['FIXME_STUB'].rint
    rint.restype = ctypes.c_double
    rint.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __rint = _libraries['FIXME_STUB'].__rint
    __rint.restype = ctypes.c_double
    __rint.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    nextafter = _libraries['FIXME_STUB'].nextafter
    nextafter.restype = ctypes.c_double
    nextafter.argtypes = [ctypes.c_double, ctypes.c_double]
except AttributeError:
    pass
try:
    __nextafter = _libraries['FIXME_STUB'].__nextafter
    __nextafter.restype = ctypes.c_double
    __nextafter.argtypes = [ctypes.c_double, ctypes.c_double]
except AttributeError:
    pass
try:
    nexttoward = _libraries['FIXME_STUB'].nexttoward
    nexttoward.restype = ctypes.c_double
    nexttoward.argtypes = [ctypes.c_double, c_long_double_t]
except AttributeError:
    pass
try:
    __nexttoward = _libraries['FIXME_STUB'].__nexttoward
    __nexttoward.restype = ctypes.c_double
    __nexttoward.argtypes = [ctypes.c_double, c_long_double_t]
except AttributeError:
    pass
try:
    remainder = _libraries['FIXME_STUB'].remainder
    remainder.restype = ctypes.c_double
    remainder.argtypes = [ctypes.c_double, ctypes.c_double]
except AttributeError:
    pass
try:
    __remainder = _libraries['FIXME_STUB'].__remainder
    __remainder.restype = ctypes.c_double
    __remainder.argtypes = [ctypes.c_double, ctypes.c_double]
except AttributeError:
    pass
try:
    scalbn = _libraries['FIXME_STUB'].scalbn
    scalbn.restype = ctypes.c_double
    scalbn.argtypes = [ctypes.c_double, ctypes.c_int32]
except AttributeError:
    pass
try:
    __scalbn = _libraries['FIXME_STUB'].__scalbn
    __scalbn.restype = ctypes.c_double
    __scalbn.argtypes = [ctypes.c_double, ctypes.c_int32]
except AttributeError:
    pass
try:
    ilogb = _libraries['FIXME_STUB'].ilogb
    ilogb.restype = ctypes.c_int32
    ilogb.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __ilogb = _libraries['FIXME_STUB'].__ilogb
    __ilogb.restype = ctypes.c_int32
    __ilogb.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    scalbln = _libraries['FIXME_STUB'].scalbln
    scalbln.restype = ctypes.c_double
    scalbln.argtypes = [ctypes.c_double, ctypes.c_int64]
except AttributeError:
    pass
try:
    __scalbln = _libraries['FIXME_STUB'].__scalbln
    __scalbln.restype = ctypes.c_double
    __scalbln.argtypes = [ctypes.c_double, ctypes.c_int64]
except AttributeError:
    pass
try:
    nearbyint = _libraries['FIXME_STUB'].nearbyint
    nearbyint.restype = ctypes.c_double
    nearbyint.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __nearbyint = _libraries['FIXME_STUB'].__nearbyint
    __nearbyint.restype = ctypes.c_double
    __nearbyint.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    round = _libraries['FIXME_STUB'].round
    round.restype = ctypes.c_double
    round.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __round = _libraries['FIXME_STUB'].__round
    __round.restype = ctypes.c_double
    __round.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    trunc = _libraries['FIXME_STUB'].trunc
    trunc.restype = ctypes.c_double
    trunc.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __trunc = _libraries['FIXME_STUB'].__trunc
    __trunc.restype = ctypes.c_double
    __trunc.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    remquo = _libraries['FIXME_STUB'].remquo
    remquo.restype = ctypes.c_double
    remquo.argtypes = [ctypes.c_double, ctypes.c_double, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    __remquo = _libraries['FIXME_STUB'].__remquo
    __remquo.restype = ctypes.c_double
    __remquo.argtypes = [ctypes.c_double, ctypes.c_double, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    lrint = _libraries['FIXME_STUB'].lrint
    lrint.restype = ctypes.c_int64
    lrint.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __lrint = _libraries['FIXME_STUB'].__lrint
    __lrint.restype = ctypes.c_int64
    __lrint.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    llrint = _libraries['FIXME_STUB'].llrint
    llrint.restype = ctypes.c_int64
    llrint.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __llrint = _libraries['FIXME_STUB'].__llrint
    __llrint.restype = ctypes.c_int64
    __llrint.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    lround = _libraries['FIXME_STUB'].lround
    lround.restype = ctypes.c_int64
    lround.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __lround = _libraries['FIXME_STUB'].__lround
    __lround.restype = ctypes.c_int64
    __lround.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    llround = _libraries['FIXME_STUB'].llround
    llround.restype = ctypes.c_int64
    llround.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    __llround = _libraries['FIXME_STUB'].__llround
    __llround.restype = ctypes.c_int64
    __llround.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    fdim = _libraries['FIXME_STUB'].fdim
    fdim.restype = ctypes.c_double
    fdim.argtypes = [ctypes.c_double, ctypes.c_double]
except AttributeError:
    pass
try:
    __fdim = _libraries['FIXME_STUB'].__fdim
    __fdim.restype = ctypes.c_double
    __fdim.argtypes = [ctypes.c_double, ctypes.c_double]
except AttributeError:
    pass
try:
    fmax = _libraries['FIXME_STUB'].fmax
    fmax.restype = ctypes.c_double
    fmax.argtypes = [ctypes.c_double, ctypes.c_double]
except AttributeError:
    pass
try:
    __fmax = _libraries['FIXME_STUB'].__fmax
    __fmax.restype = ctypes.c_double
    __fmax.argtypes = [ctypes.c_double, ctypes.c_double]
except AttributeError:
    pass
try:
    fmin = _libraries['FIXME_STUB'].fmin
    fmin.restype = ctypes.c_double
    fmin.argtypes = [ctypes.c_double, ctypes.c_double]
except AttributeError:
    pass
try:
    __fmin = _libraries['FIXME_STUB'].__fmin
    __fmin.restype = ctypes.c_double
    __fmin.argtypes = [ctypes.c_double, ctypes.c_double]
except AttributeError:
    pass
try:
    fma = _libraries['FIXME_STUB'].fma
    fma.restype = ctypes.c_double
    fma.argtypes = [ctypes.c_double, ctypes.c_double, ctypes.c_double]
except AttributeError:
    pass
try:
    __fma = _libraries['FIXME_STUB'].__fma
    __fma.restype = ctypes.c_double
    __fma.argtypes = [ctypes.c_double, ctypes.c_double, ctypes.c_double]
except AttributeError:
    pass
try:
    scalb = _libraries['FIXME_STUB'].scalb
    scalb.restype = ctypes.c_double
    scalb.argtypes = [ctypes.c_double, ctypes.c_double]
except AttributeError:
    pass
try:
    __scalb = _libraries['FIXME_STUB'].__scalb
    __scalb.restype = ctypes.c_double
    __scalb.argtypes = [ctypes.c_double, ctypes.c_double]
except AttributeError:
    pass
try:
    __fpclassifyf = _libraries['FIXME_STUB'].__fpclassifyf
    __fpclassifyf.restype = ctypes.c_int32
    __fpclassifyf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __signbitf = _libraries['FIXME_STUB'].__signbitf
    __signbitf.restype = ctypes.c_int32
    __signbitf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __isinff = _libraries['FIXME_STUB'].__isinff
    __isinff.restype = ctypes.c_int32
    __isinff.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __finitef = _libraries['FIXME_STUB'].__finitef
    __finitef.restype = ctypes.c_int32
    __finitef.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __isnanf = _libraries['FIXME_STUB'].__isnanf
    __isnanf.restype = ctypes.c_int32
    __isnanf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __iseqsigf = _libraries['FIXME_STUB'].__iseqsigf
    __iseqsigf.restype = ctypes.c_int32
    __iseqsigf.argtypes = [ctypes.c_float, ctypes.c_float]
except AttributeError:
    pass
try:
    __issignalingf = _libraries['FIXME_STUB'].__issignalingf
    __issignalingf.restype = ctypes.c_int32
    __issignalingf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    acosf = _libraries['FIXME_STUB'].acosf
    acosf.restype = ctypes.c_float
    acosf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __acosf = _libraries['FIXME_STUB'].__acosf
    __acosf.restype = ctypes.c_float
    __acosf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    asinf = _libraries['FIXME_STUB'].asinf
    asinf.restype = ctypes.c_float
    asinf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __asinf = _libraries['FIXME_STUB'].__asinf
    __asinf.restype = ctypes.c_float
    __asinf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    atanf = _libraries['FIXME_STUB'].atanf
    atanf.restype = ctypes.c_float
    atanf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __atanf = _libraries['FIXME_STUB'].__atanf
    __atanf.restype = ctypes.c_float
    __atanf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    atan2f = _libraries['FIXME_STUB'].atan2f
    atan2f.restype = ctypes.c_float
    atan2f.argtypes = [ctypes.c_float, ctypes.c_float]
except AttributeError:
    pass
try:
    __atan2f = _libraries['FIXME_STUB'].__atan2f
    __atan2f.restype = ctypes.c_float
    __atan2f.argtypes = [ctypes.c_float, ctypes.c_float]
except AttributeError:
    pass
try:
    cosf = _libraries['FIXME_STUB'].cosf
    cosf.restype = ctypes.c_float
    cosf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __cosf = _libraries['FIXME_STUB'].__cosf
    __cosf.restype = ctypes.c_float
    __cosf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    sinf = _libraries['FIXME_STUB'].sinf
    sinf.restype = ctypes.c_float
    sinf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __sinf = _libraries['FIXME_STUB'].__sinf
    __sinf.restype = ctypes.c_float
    __sinf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    tanf = _libraries['FIXME_STUB'].tanf
    tanf.restype = ctypes.c_float
    tanf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __tanf = _libraries['FIXME_STUB'].__tanf
    __tanf.restype = ctypes.c_float
    __tanf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    coshf = _libraries['FIXME_STUB'].coshf
    coshf.restype = ctypes.c_float
    coshf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __coshf = _libraries['FIXME_STUB'].__coshf
    __coshf.restype = ctypes.c_float
    __coshf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    sinhf = _libraries['FIXME_STUB'].sinhf
    sinhf.restype = ctypes.c_float
    sinhf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __sinhf = _libraries['FIXME_STUB'].__sinhf
    __sinhf.restype = ctypes.c_float
    __sinhf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    tanhf = _libraries['FIXME_STUB'].tanhf
    tanhf.restype = ctypes.c_float
    tanhf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __tanhf = _libraries['FIXME_STUB'].__tanhf
    __tanhf.restype = ctypes.c_float
    __tanhf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    acoshf = _libraries['FIXME_STUB'].acoshf
    acoshf.restype = ctypes.c_float
    acoshf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __acoshf = _libraries['FIXME_STUB'].__acoshf
    __acoshf.restype = ctypes.c_float
    __acoshf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    asinhf = _libraries['FIXME_STUB'].asinhf
    asinhf.restype = ctypes.c_float
    asinhf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __asinhf = _libraries['FIXME_STUB'].__asinhf
    __asinhf.restype = ctypes.c_float
    __asinhf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    atanhf = _libraries['FIXME_STUB'].atanhf
    atanhf.restype = ctypes.c_float
    atanhf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __atanhf = _libraries['FIXME_STUB'].__atanhf
    __atanhf.restype = ctypes.c_float
    __atanhf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    expf = _libraries['FIXME_STUB'].expf
    expf.restype = ctypes.c_float
    expf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __expf = _libraries['FIXME_STUB'].__expf
    __expf.restype = ctypes.c_float
    __expf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    frexpf = _libraries['FIXME_STUB'].frexpf
    frexpf.restype = ctypes.c_float
    frexpf.argtypes = [ctypes.c_float, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    __frexpf = _libraries['FIXME_STUB'].__frexpf
    __frexpf.restype = ctypes.c_float
    __frexpf.argtypes = [ctypes.c_float, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    ldexpf = _libraries['FIXME_STUB'].ldexpf
    ldexpf.restype = ctypes.c_float
    ldexpf.argtypes = [ctypes.c_float, ctypes.c_int32]
except AttributeError:
    pass
try:
    __ldexpf = _libraries['FIXME_STUB'].__ldexpf
    __ldexpf.restype = ctypes.c_float
    __ldexpf.argtypes = [ctypes.c_float, ctypes.c_int32]
except AttributeError:
    pass
try:
    logf = _libraries['FIXME_STUB'].logf
    logf.restype = ctypes.c_float
    logf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __logf = _libraries['FIXME_STUB'].__logf
    __logf.restype = ctypes.c_float
    __logf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    log10f = _libraries['FIXME_STUB'].log10f
    log10f.restype = ctypes.c_float
    log10f.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __log10f = _libraries['FIXME_STUB'].__log10f
    __log10f.restype = ctypes.c_float
    __log10f.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    modff = _libraries['FIXME_STUB'].modff
    modff.restype = ctypes.c_float
    modff.argtypes = [ctypes.c_float, ctypes.POINTER(ctypes.c_float)]
except AttributeError:
    pass
try:
    __modff = _libraries['FIXME_STUB'].__modff
    __modff.restype = ctypes.c_float
    __modff.argtypes = [ctypes.c_float, ctypes.POINTER(ctypes.c_float)]
except AttributeError:
    pass
try:
    expm1f = _libraries['FIXME_STUB'].expm1f
    expm1f.restype = ctypes.c_float
    expm1f.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __expm1f = _libraries['FIXME_STUB'].__expm1f
    __expm1f.restype = ctypes.c_float
    __expm1f.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    log1pf = _libraries['FIXME_STUB'].log1pf
    log1pf.restype = ctypes.c_float
    log1pf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __log1pf = _libraries['FIXME_STUB'].__log1pf
    __log1pf.restype = ctypes.c_float
    __log1pf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    logbf = _libraries['FIXME_STUB'].logbf
    logbf.restype = ctypes.c_float
    logbf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __logbf = _libraries['FIXME_STUB'].__logbf
    __logbf.restype = ctypes.c_float
    __logbf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    exp2f = _libraries['FIXME_STUB'].exp2f
    exp2f.restype = ctypes.c_float
    exp2f.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __exp2f = _libraries['FIXME_STUB'].__exp2f
    __exp2f.restype = ctypes.c_float
    __exp2f.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    log2f = _libraries['FIXME_STUB'].log2f
    log2f.restype = ctypes.c_float
    log2f.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __log2f = _libraries['FIXME_STUB'].__log2f
    __log2f.restype = ctypes.c_float
    __log2f.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    powf = _libraries['FIXME_STUB'].powf
    powf.restype = ctypes.c_float
    powf.argtypes = [ctypes.c_float, ctypes.c_float]
except AttributeError:
    pass
try:
    __powf = _libraries['FIXME_STUB'].__powf
    __powf.restype = ctypes.c_float
    __powf.argtypes = [ctypes.c_float, ctypes.c_float]
except AttributeError:
    pass
try:
    sqrtf = _libraries['FIXME_STUB'].sqrtf
    sqrtf.restype = ctypes.c_float
    sqrtf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __sqrtf = _libraries['FIXME_STUB'].__sqrtf
    __sqrtf.restype = ctypes.c_float
    __sqrtf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    hypotf = _libraries['FIXME_STUB'].hypotf
    hypotf.restype = ctypes.c_float
    hypotf.argtypes = [ctypes.c_float, ctypes.c_float]
except AttributeError:
    pass
try:
    __hypotf = _libraries['FIXME_STUB'].__hypotf
    __hypotf.restype = ctypes.c_float
    __hypotf.argtypes = [ctypes.c_float, ctypes.c_float]
except AttributeError:
    pass
try:
    cbrtf = _libraries['FIXME_STUB'].cbrtf
    cbrtf.restype = ctypes.c_float
    cbrtf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __cbrtf = _libraries['FIXME_STUB'].__cbrtf
    __cbrtf.restype = ctypes.c_float
    __cbrtf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    ceilf = _libraries['FIXME_STUB'].ceilf
    ceilf.restype = ctypes.c_float
    ceilf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __ceilf = _libraries['FIXME_STUB'].__ceilf
    __ceilf.restype = ctypes.c_float
    __ceilf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    fabsf = _libraries['FIXME_STUB'].fabsf
    fabsf.restype = ctypes.c_float
    fabsf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __fabsf = _libraries['FIXME_STUB'].__fabsf
    __fabsf.restype = ctypes.c_float
    __fabsf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    floorf = _libraries['FIXME_STUB'].floorf
    floorf.restype = ctypes.c_float
    floorf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __floorf = _libraries['FIXME_STUB'].__floorf
    __floorf.restype = ctypes.c_float
    __floorf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    fmodf = _libraries['FIXME_STUB'].fmodf
    fmodf.restype = ctypes.c_float
    fmodf.argtypes = [ctypes.c_float, ctypes.c_float]
except AttributeError:
    pass
try:
    __fmodf = _libraries['FIXME_STUB'].__fmodf
    __fmodf.restype = ctypes.c_float
    __fmodf.argtypes = [ctypes.c_float, ctypes.c_float]
except AttributeError:
    pass
try:
    isinff = _libraries['FIXME_STUB'].isinff
    isinff.restype = ctypes.c_int32
    isinff.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    finitef = _libraries['FIXME_STUB'].finitef
    finitef.restype = ctypes.c_int32
    finitef.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    dremf = _libraries['FIXME_STUB'].dremf
    dremf.restype = ctypes.c_float
    dremf.argtypes = [ctypes.c_float, ctypes.c_float]
except AttributeError:
    pass
try:
    __dremf = _libraries['FIXME_STUB'].__dremf
    __dremf.restype = ctypes.c_float
    __dremf.argtypes = [ctypes.c_float, ctypes.c_float]
except AttributeError:
    pass
try:
    significandf = _libraries['FIXME_STUB'].significandf
    significandf.restype = ctypes.c_float
    significandf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __significandf = _libraries['FIXME_STUB'].__significandf
    __significandf.restype = ctypes.c_float
    __significandf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    copysignf = _libraries['FIXME_STUB'].copysignf
    copysignf.restype = ctypes.c_float
    copysignf.argtypes = [ctypes.c_float, ctypes.c_float]
except AttributeError:
    pass
try:
    __copysignf = _libraries['FIXME_STUB'].__copysignf
    __copysignf.restype = ctypes.c_float
    __copysignf.argtypes = [ctypes.c_float, ctypes.c_float]
except AttributeError:
    pass
try:
    nanf = _libraries['FIXME_STUB'].nanf
    nanf.restype = ctypes.c_float
    nanf.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    __nanf = _libraries['FIXME_STUB'].__nanf
    __nanf.restype = ctypes.c_float
    __nanf.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    isnanf = _libraries['FIXME_STUB'].isnanf
    isnanf.restype = ctypes.c_int32
    isnanf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    j0f = _libraries['FIXME_STUB'].j0f
    j0f.restype = ctypes.c_float
    j0f.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __j0f = _libraries['FIXME_STUB'].__j0f
    __j0f.restype = ctypes.c_float
    __j0f.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    j1f = _libraries['FIXME_STUB'].j1f
    j1f.restype = ctypes.c_float
    j1f.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __j1f = _libraries['FIXME_STUB'].__j1f
    __j1f.restype = ctypes.c_float
    __j1f.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    jnf = _libraries['FIXME_STUB'].jnf
    jnf.restype = ctypes.c_float
    jnf.argtypes = [ctypes.c_int32, ctypes.c_float]
except AttributeError:
    pass
try:
    __jnf = _libraries['FIXME_STUB'].__jnf
    __jnf.restype = ctypes.c_float
    __jnf.argtypes = [ctypes.c_int32, ctypes.c_float]
except AttributeError:
    pass
try:
    y0f = _libraries['FIXME_STUB'].y0f
    y0f.restype = ctypes.c_float
    y0f.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __y0f = _libraries['FIXME_STUB'].__y0f
    __y0f.restype = ctypes.c_float
    __y0f.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    y1f = _libraries['FIXME_STUB'].y1f
    y1f.restype = ctypes.c_float
    y1f.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __y1f = _libraries['FIXME_STUB'].__y1f
    __y1f.restype = ctypes.c_float
    __y1f.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    ynf = _libraries['FIXME_STUB'].ynf
    ynf.restype = ctypes.c_float
    ynf.argtypes = [ctypes.c_int32, ctypes.c_float]
except AttributeError:
    pass
try:
    __ynf = _libraries['FIXME_STUB'].__ynf
    __ynf.restype = ctypes.c_float
    __ynf.argtypes = [ctypes.c_int32, ctypes.c_float]
except AttributeError:
    pass
try:
    erff = _libraries['FIXME_STUB'].erff
    erff.restype = ctypes.c_float
    erff.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __erff = _libraries['FIXME_STUB'].__erff
    __erff.restype = ctypes.c_float
    __erff.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    erfcf = _libraries['FIXME_STUB'].erfcf
    erfcf.restype = ctypes.c_float
    erfcf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __erfcf = _libraries['FIXME_STUB'].__erfcf
    __erfcf.restype = ctypes.c_float
    __erfcf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    lgammaf = _libraries['FIXME_STUB'].lgammaf
    lgammaf.restype = ctypes.c_float
    lgammaf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __lgammaf = _libraries['FIXME_STUB'].__lgammaf
    __lgammaf.restype = ctypes.c_float
    __lgammaf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    tgammaf = _libraries['FIXME_STUB'].tgammaf
    tgammaf.restype = ctypes.c_float
    tgammaf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __tgammaf = _libraries['FIXME_STUB'].__tgammaf
    __tgammaf.restype = ctypes.c_float
    __tgammaf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    gammaf = _libraries['FIXME_STUB'].gammaf
    gammaf.restype = ctypes.c_float
    gammaf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __gammaf = _libraries['FIXME_STUB'].__gammaf
    __gammaf.restype = ctypes.c_float
    __gammaf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    lgammaf_r = _libraries['FIXME_STUB'].lgammaf_r
    lgammaf_r.restype = ctypes.c_float
    lgammaf_r.argtypes = [ctypes.c_float, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    __lgammaf_r = _libraries['FIXME_STUB'].__lgammaf_r
    __lgammaf_r.restype = ctypes.c_float
    __lgammaf_r.argtypes = [ctypes.c_float, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    rintf = _libraries['FIXME_STUB'].rintf
    rintf.restype = ctypes.c_float
    rintf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __rintf = _libraries['FIXME_STUB'].__rintf
    __rintf.restype = ctypes.c_float
    __rintf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    nextafterf = _libraries['FIXME_STUB'].nextafterf
    nextafterf.restype = ctypes.c_float
    nextafterf.argtypes = [ctypes.c_float, ctypes.c_float]
except AttributeError:
    pass
try:
    __nextafterf = _libraries['FIXME_STUB'].__nextafterf
    __nextafterf.restype = ctypes.c_float
    __nextafterf.argtypes = [ctypes.c_float, ctypes.c_float]
except AttributeError:
    pass
try:
    nexttowardf = _libraries['FIXME_STUB'].nexttowardf
    nexttowardf.restype = ctypes.c_float
    nexttowardf.argtypes = [ctypes.c_float, c_long_double_t]
except AttributeError:
    pass
try:
    __nexttowardf = _libraries['FIXME_STUB'].__nexttowardf
    __nexttowardf.restype = ctypes.c_float
    __nexttowardf.argtypes = [ctypes.c_float, c_long_double_t]
except AttributeError:
    pass
try:
    remainderf = _libraries['FIXME_STUB'].remainderf
    remainderf.restype = ctypes.c_float
    remainderf.argtypes = [ctypes.c_float, ctypes.c_float]
except AttributeError:
    pass
try:
    __remainderf = _libraries['FIXME_STUB'].__remainderf
    __remainderf.restype = ctypes.c_float
    __remainderf.argtypes = [ctypes.c_float, ctypes.c_float]
except AttributeError:
    pass
try:
    scalbnf = _libraries['FIXME_STUB'].scalbnf
    scalbnf.restype = ctypes.c_float
    scalbnf.argtypes = [ctypes.c_float, ctypes.c_int32]
except AttributeError:
    pass
try:
    __scalbnf = _libraries['FIXME_STUB'].__scalbnf
    __scalbnf.restype = ctypes.c_float
    __scalbnf.argtypes = [ctypes.c_float, ctypes.c_int32]
except AttributeError:
    pass
try:
    ilogbf = _libraries['FIXME_STUB'].ilogbf
    ilogbf.restype = ctypes.c_int32
    ilogbf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __ilogbf = _libraries['FIXME_STUB'].__ilogbf
    __ilogbf.restype = ctypes.c_int32
    __ilogbf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    scalblnf = _libraries['FIXME_STUB'].scalblnf
    scalblnf.restype = ctypes.c_float
    scalblnf.argtypes = [ctypes.c_float, ctypes.c_int64]
except AttributeError:
    pass
try:
    __scalblnf = _libraries['FIXME_STUB'].__scalblnf
    __scalblnf.restype = ctypes.c_float
    __scalblnf.argtypes = [ctypes.c_float, ctypes.c_int64]
except AttributeError:
    pass
try:
    nearbyintf = _libraries['FIXME_STUB'].nearbyintf
    nearbyintf.restype = ctypes.c_float
    nearbyintf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __nearbyintf = _libraries['FIXME_STUB'].__nearbyintf
    __nearbyintf.restype = ctypes.c_float
    __nearbyintf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    roundf = _libraries['FIXME_STUB'].roundf
    roundf.restype = ctypes.c_float
    roundf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __roundf = _libraries['FIXME_STUB'].__roundf
    __roundf.restype = ctypes.c_float
    __roundf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    truncf = _libraries['FIXME_STUB'].truncf
    truncf.restype = ctypes.c_float
    truncf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __truncf = _libraries['FIXME_STUB'].__truncf
    __truncf.restype = ctypes.c_float
    __truncf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    remquof = _libraries['FIXME_STUB'].remquof
    remquof.restype = ctypes.c_float
    remquof.argtypes = [ctypes.c_float, ctypes.c_float, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    __remquof = _libraries['FIXME_STUB'].__remquof
    __remquof.restype = ctypes.c_float
    __remquof.argtypes = [ctypes.c_float, ctypes.c_float, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    lrintf = _libraries['FIXME_STUB'].lrintf
    lrintf.restype = ctypes.c_int64
    lrintf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __lrintf = _libraries['FIXME_STUB'].__lrintf
    __lrintf.restype = ctypes.c_int64
    __lrintf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    llrintf = _libraries['FIXME_STUB'].llrintf
    llrintf.restype = ctypes.c_int64
    llrintf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __llrintf = _libraries['FIXME_STUB'].__llrintf
    __llrintf.restype = ctypes.c_int64
    __llrintf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    lroundf = _libraries['FIXME_STUB'].lroundf
    lroundf.restype = ctypes.c_int64
    lroundf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __lroundf = _libraries['FIXME_STUB'].__lroundf
    __lroundf.restype = ctypes.c_int64
    __lroundf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    llroundf = _libraries['FIXME_STUB'].llroundf
    llroundf.restype = ctypes.c_int64
    llroundf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    __llroundf = _libraries['FIXME_STUB'].__llroundf
    __llroundf.restype = ctypes.c_int64
    __llroundf.argtypes = [ctypes.c_float]
except AttributeError:
    pass
try:
    fdimf = _libraries['FIXME_STUB'].fdimf
    fdimf.restype = ctypes.c_float
    fdimf.argtypes = [ctypes.c_float, ctypes.c_float]
except AttributeError:
    pass
try:
    __fdimf = _libraries['FIXME_STUB'].__fdimf
    __fdimf.restype = ctypes.c_float
    __fdimf.argtypes = [ctypes.c_float, ctypes.c_float]
except AttributeError:
    pass
try:
    fmaxf = _libraries['FIXME_STUB'].fmaxf
    fmaxf.restype = ctypes.c_float
    fmaxf.argtypes = [ctypes.c_float, ctypes.c_float]
except AttributeError:
    pass
try:
    __fmaxf = _libraries['FIXME_STUB'].__fmaxf
    __fmaxf.restype = ctypes.c_float
    __fmaxf.argtypes = [ctypes.c_float, ctypes.c_float]
except AttributeError:
    pass
try:
    fminf = _libraries['FIXME_STUB'].fminf
    fminf.restype = ctypes.c_float
    fminf.argtypes = [ctypes.c_float, ctypes.c_float]
except AttributeError:
    pass
try:
    __fminf = _libraries['FIXME_STUB'].__fminf
    __fminf.restype = ctypes.c_float
    __fminf.argtypes = [ctypes.c_float, ctypes.c_float]
except AttributeError:
    pass
try:
    fmaf = _libraries['FIXME_STUB'].fmaf
    fmaf.restype = ctypes.c_float
    fmaf.argtypes = [ctypes.c_float, ctypes.c_float, ctypes.c_float]
except AttributeError:
    pass
try:
    __fmaf = _libraries['FIXME_STUB'].__fmaf
    __fmaf.restype = ctypes.c_float
    __fmaf.argtypes = [ctypes.c_float, ctypes.c_float, ctypes.c_float]
except AttributeError:
    pass
try:
    scalbf = _libraries['FIXME_STUB'].scalbf
    scalbf.restype = ctypes.c_float
    scalbf.argtypes = [ctypes.c_float, ctypes.c_float]
except AttributeError:
    pass
try:
    __scalbf = _libraries['FIXME_STUB'].__scalbf
    __scalbf.restype = ctypes.c_float
    __scalbf.argtypes = [ctypes.c_float, ctypes.c_float]
except AttributeError:
    pass
try:
    __fpclassifyl = _libraries['FIXME_STUB'].__fpclassifyl
    __fpclassifyl.restype = ctypes.c_int32
    __fpclassifyl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __signbitl = _libraries['FIXME_STUB'].__signbitl
    __signbitl.restype = ctypes.c_int32
    __signbitl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __isinfl = _libraries['FIXME_STUB'].__isinfl
    __isinfl.restype = ctypes.c_int32
    __isinfl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __finitel = _libraries['FIXME_STUB'].__finitel
    __finitel.restype = ctypes.c_int32
    __finitel.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __isnanl = _libraries['FIXME_STUB'].__isnanl
    __isnanl.restype = ctypes.c_int32
    __isnanl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __iseqsigl = _libraries['FIXME_STUB'].__iseqsigl
    __iseqsigl.restype = ctypes.c_int32
    __iseqsigl.argtypes = [c_long_double_t, c_long_double_t]
except AttributeError:
    pass
try:
    __issignalingl = _libraries['FIXME_STUB'].__issignalingl
    __issignalingl.restype = ctypes.c_int32
    __issignalingl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    acosl = _libraries['FIXME_STUB'].acosl
    acosl.restype = c_long_double_t
    acosl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __acosl = _libraries['FIXME_STUB'].__acosl
    __acosl.restype = c_long_double_t
    __acosl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    asinl = _libraries['FIXME_STUB'].asinl
    asinl.restype = c_long_double_t
    asinl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __asinl = _libraries['FIXME_STUB'].__asinl
    __asinl.restype = c_long_double_t
    __asinl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    atanl = _libraries['FIXME_STUB'].atanl
    atanl.restype = c_long_double_t
    atanl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __atanl = _libraries['FIXME_STUB'].__atanl
    __atanl.restype = c_long_double_t
    __atanl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    atan2l = _libraries['FIXME_STUB'].atan2l
    atan2l.restype = c_long_double_t
    atan2l.argtypes = [c_long_double_t, c_long_double_t]
except AttributeError:
    pass
try:
    __atan2l = _libraries['FIXME_STUB'].__atan2l
    __atan2l.restype = c_long_double_t
    __atan2l.argtypes = [c_long_double_t, c_long_double_t]
except AttributeError:
    pass
try:
    cosl = _libraries['FIXME_STUB'].cosl
    cosl.restype = c_long_double_t
    cosl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __cosl = _libraries['FIXME_STUB'].__cosl
    __cosl.restype = c_long_double_t
    __cosl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    sinl = _libraries['FIXME_STUB'].sinl
    sinl.restype = c_long_double_t
    sinl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __sinl = _libraries['FIXME_STUB'].__sinl
    __sinl.restype = c_long_double_t
    __sinl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    tanl = _libraries['FIXME_STUB'].tanl
    tanl.restype = c_long_double_t
    tanl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __tanl = _libraries['FIXME_STUB'].__tanl
    __tanl.restype = c_long_double_t
    __tanl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    coshl = _libraries['FIXME_STUB'].coshl
    coshl.restype = c_long_double_t
    coshl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __coshl = _libraries['FIXME_STUB'].__coshl
    __coshl.restype = c_long_double_t
    __coshl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    sinhl = _libraries['FIXME_STUB'].sinhl
    sinhl.restype = c_long_double_t
    sinhl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __sinhl = _libraries['FIXME_STUB'].__sinhl
    __sinhl.restype = c_long_double_t
    __sinhl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    tanhl = _libraries['FIXME_STUB'].tanhl
    tanhl.restype = c_long_double_t
    tanhl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __tanhl = _libraries['FIXME_STUB'].__tanhl
    __tanhl.restype = c_long_double_t
    __tanhl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    acoshl = _libraries['FIXME_STUB'].acoshl
    acoshl.restype = c_long_double_t
    acoshl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __acoshl = _libraries['FIXME_STUB'].__acoshl
    __acoshl.restype = c_long_double_t
    __acoshl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    asinhl = _libraries['FIXME_STUB'].asinhl
    asinhl.restype = c_long_double_t
    asinhl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __asinhl = _libraries['FIXME_STUB'].__asinhl
    __asinhl.restype = c_long_double_t
    __asinhl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    atanhl = _libraries['FIXME_STUB'].atanhl
    atanhl.restype = c_long_double_t
    atanhl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __atanhl = _libraries['FIXME_STUB'].__atanhl
    __atanhl.restype = c_long_double_t
    __atanhl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    expl = _libraries['FIXME_STUB'].expl
    expl.restype = c_long_double_t
    expl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __expl = _libraries['FIXME_STUB'].__expl
    __expl.restype = c_long_double_t
    __expl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    frexpl = _libraries['FIXME_STUB'].frexpl
    frexpl.restype = c_long_double_t
    frexpl.argtypes = [c_long_double_t, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    __frexpl = _libraries['FIXME_STUB'].__frexpl
    __frexpl.restype = c_long_double_t
    __frexpl.argtypes = [c_long_double_t, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    ldexpl = _libraries['FIXME_STUB'].ldexpl
    ldexpl.restype = c_long_double_t
    ldexpl.argtypes = [c_long_double_t, ctypes.c_int32]
except AttributeError:
    pass
try:
    __ldexpl = _libraries['FIXME_STUB'].__ldexpl
    __ldexpl.restype = c_long_double_t
    __ldexpl.argtypes = [c_long_double_t, ctypes.c_int32]
except AttributeError:
    pass
try:
    logl = _libraries['FIXME_STUB'].logl
    logl.restype = c_long_double_t
    logl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __logl = _libraries['FIXME_STUB'].__logl
    __logl.restype = c_long_double_t
    __logl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    log10l = _libraries['FIXME_STUB'].log10l
    log10l.restype = c_long_double_t
    log10l.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __log10l = _libraries['FIXME_STUB'].__log10l
    __log10l.restype = c_long_double_t
    __log10l.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    modfl = _libraries['FIXME_STUB'].modfl
    modfl.restype = c_long_double_t
    modfl.argtypes = [c_long_double_t, ctypes.POINTER(c_long_double_t)]
except AttributeError:
    pass
try:
    __modfl = _libraries['FIXME_STUB'].__modfl
    __modfl.restype = c_long_double_t
    __modfl.argtypes = [c_long_double_t, ctypes.POINTER(c_long_double_t)]
except AttributeError:
    pass
try:
    expm1l = _libraries['FIXME_STUB'].expm1l
    expm1l.restype = c_long_double_t
    expm1l.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __expm1l = _libraries['FIXME_STUB'].__expm1l
    __expm1l.restype = c_long_double_t
    __expm1l.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    log1pl = _libraries['FIXME_STUB'].log1pl
    log1pl.restype = c_long_double_t
    log1pl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __log1pl = _libraries['FIXME_STUB'].__log1pl
    __log1pl.restype = c_long_double_t
    __log1pl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    logbl = _libraries['FIXME_STUB'].logbl
    logbl.restype = c_long_double_t
    logbl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __logbl = _libraries['FIXME_STUB'].__logbl
    __logbl.restype = c_long_double_t
    __logbl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    exp2l = _libraries['FIXME_STUB'].exp2l
    exp2l.restype = c_long_double_t
    exp2l.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __exp2l = _libraries['FIXME_STUB'].__exp2l
    __exp2l.restype = c_long_double_t
    __exp2l.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    log2l = _libraries['FIXME_STUB'].log2l
    log2l.restype = c_long_double_t
    log2l.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __log2l = _libraries['FIXME_STUB'].__log2l
    __log2l.restype = c_long_double_t
    __log2l.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    powl = _libraries['FIXME_STUB'].powl
    powl.restype = c_long_double_t
    powl.argtypes = [c_long_double_t, c_long_double_t]
except AttributeError:
    pass
try:
    __powl = _libraries['FIXME_STUB'].__powl
    __powl.restype = c_long_double_t
    __powl.argtypes = [c_long_double_t, c_long_double_t]
except AttributeError:
    pass
try:
    sqrtl = _libraries['FIXME_STUB'].sqrtl
    sqrtl.restype = c_long_double_t
    sqrtl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __sqrtl = _libraries['FIXME_STUB'].__sqrtl
    __sqrtl.restype = c_long_double_t
    __sqrtl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    hypotl = _libraries['FIXME_STUB'].hypotl
    hypotl.restype = c_long_double_t
    hypotl.argtypes = [c_long_double_t, c_long_double_t]
except AttributeError:
    pass
try:
    __hypotl = _libraries['FIXME_STUB'].__hypotl
    __hypotl.restype = c_long_double_t
    __hypotl.argtypes = [c_long_double_t, c_long_double_t]
except AttributeError:
    pass
try:
    cbrtl = _libraries['FIXME_STUB'].cbrtl
    cbrtl.restype = c_long_double_t
    cbrtl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __cbrtl = _libraries['FIXME_STUB'].__cbrtl
    __cbrtl.restype = c_long_double_t
    __cbrtl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    ceill = _libraries['FIXME_STUB'].ceill
    ceill.restype = c_long_double_t
    ceill.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __ceill = _libraries['FIXME_STUB'].__ceill
    __ceill.restype = c_long_double_t
    __ceill.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    fabsl = _libraries['FIXME_STUB'].fabsl
    fabsl.restype = c_long_double_t
    fabsl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __fabsl = _libraries['FIXME_STUB'].__fabsl
    __fabsl.restype = c_long_double_t
    __fabsl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    floorl = _libraries['FIXME_STUB'].floorl
    floorl.restype = c_long_double_t
    floorl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __floorl = _libraries['FIXME_STUB'].__floorl
    __floorl.restype = c_long_double_t
    __floorl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    fmodl = _libraries['FIXME_STUB'].fmodl
    fmodl.restype = c_long_double_t
    fmodl.argtypes = [c_long_double_t, c_long_double_t]
except AttributeError:
    pass
try:
    __fmodl = _libraries['FIXME_STUB'].__fmodl
    __fmodl.restype = c_long_double_t
    __fmodl.argtypes = [c_long_double_t, c_long_double_t]
except AttributeError:
    pass
try:
    isinfl = _libraries['FIXME_STUB'].isinfl
    isinfl.restype = ctypes.c_int32
    isinfl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    finitel = _libraries['FIXME_STUB'].finitel
    finitel.restype = ctypes.c_int32
    finitel.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    dreml = _libraries['FIXME_STUB'].dreml
    dreml.restype = c_long_double_t
    dreml.argtypes = [c_long_double_t, c_long_double_t]
except AttributeError:
    pass
try:
    __dreml = _libraries['FIXME_STUB'].__dreml
    __dreml.restype = c_long_double_t
    __dreml.argtypes = [c_long_double_t, c_long_double_t]
except AttributeError:
    pass
try:
    significandl = _libraries['FIXME_STUB'].significandl
    significandl.restype = c_long_double_t
    significandl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __significandl = _libraries['FIXME_STUB'].__significandl
    __significandl.restype = c_long_double_t
    __significandl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    copysignl = _libraries['FIXME_STUB'].copysignl
    copysignl.restype = c_long_double_t
    copysignl.argtypes = [c_long_double_t, c_long_double_t]
except AttributeError:
    pass
try:
    __copysignl = _libraries['FIXME_STUB'].__copysignl
    __copysignl.restype = c_long_double_t
    __copysignl.argtypes = [c_long_double_t, c_long_double_t]
except AttributeError:
    pass
try:
    nanl = _libraries['FIXME_STUB'].nanl
    nanl.restype = c_long_double_t
    nanl.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    __nanl = _libraries['FIXME_STUB'].__nanl
    __nanl.restype = c_long_double_t
    __nanl.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    isnanl = _libraries['FIXME_STUB'].isnanl
    isnanl.restype = ctypes.c_int32
    isnanl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    j0l = _libraries['FIXME_STUB'].j0l
    j0l.restype = c_long_double_t
    j0l.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __j0l = _libraries['FIXME_STUB'].__j0l
    __j0l.restype = c_long_double_t
    __j0l.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    j1l = _libraries['FIXME_STUB'].j1l
    j1l.restype = c_long_double_t
    j1l.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __j1l = _libraries['FIXME_STUB'].__j1l
    __j1l.restype = c_long_double_t
    __j1l.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    jnl = _libraries['FIXME_STUB'].jnl
    jnl.restype = c_long_double_t
    jnl.argtypes = [ctypes.c_int32, c_long_double_t]
except AttributeError:
    pass
try:
    __jnl = _libraries['FIXME_STUB'].__jnl
    __jnl.restype = c_long_double_t
    __jnl.argtypes = [ctypes.c_int32, c_long_double_t]
except AttributeError:
    pass
try:
    y0l = _libraries['FIXME_STUB'].y0l
    y0l.restype = c_long_double_t
    y0l.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __y0l = _libraries['FIXME_STUB'].__y0l
    __y0l.restype = c_long_double_t
    __y0l.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    y1l = _libraries['FIXME_STUB'].y1l
    y1l.restype = c_long_double_t
    y1l.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __y1l = _libraries['FIXME_STUB'].__y1l
    __y1l.restype = c_long_double_t
    __y1l.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    ynl = _libraries['FIXME_STUB'].ynl
    ynl.restype = c_long_double_t
    ynl.argtypes = [ctypes.c_int32, c_long_double_t]
except AttributeError:
    pass
try:
    __ynl = _libraries['FIXME_STUB'].__ynl
    __ynl.restype = c_long_double_t
    __ynl.argtypes = [ctypes.c_int32, c_long_double_t]
except AttributeError:
    pass
try:
    erfl = _libraries['FIXME_STUB'].erfl
    erfl.restype = c_long_double_t
    erfl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __erfl = _libraries['FIXME_STUB'].__erfl
    __erfl.restype = c_long_double_t
    __erfl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    erfcl = _libraries['FIXME_STUB'].erfcl
    erfcl.restype = c_long_double_t
    erfcl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __erfcl = _libraries['FIXME_STUB'].__erfcl
    __erfcl.restype = c_long_double_t
    __erfcl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    lgammal = _libraries['FIXME_STUB'].lgammal
    lgammal.restype = c_long_double_t
    lgammal.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __lgammal = _libraries['FIXME_STUB'].__lgammal
    __lgammal.restype = c_long_double_t
    __lgammal.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    tgammal = _libraries['FIXME_STUB'].tgammal
    tgammal.restype = c_long_double_t
    tgammal.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __tgammal = _libraries['FIXME_STUB'].__tgammal
    __tgammal.restype = c_long_double_t
    __tgammal.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    gammal = _libraries['FIXME_STUB'].gammal
    gammal.restype = c_long_double_t
    gammal.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __gammal = _libraries['FIXME_STUB'].__gammal
    __gammal.restype = c_long_double_t
    __gammal.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    lgammal_r = _libraries['FIXME_STUB'].lgammal_r
    lgammal_r.restype = c_long_double_t
    lgammal_r.argtypes = [c_long_double_t, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    __lgammal_r = _libraries['FIXME_STUB'].__lgammal_r
    __lgammal_r.restype = c_long_double_t
    __lgammal_r.argtypes = [c_long_double_t, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    rintl = _libraries['FIXME_STUB'].rintl
    rintl.restype = c_long_double_t
    rintl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __rintl = _libraries['FIXME_STUB'].__rintl
    __rintl.restype = c_long_double_t
    __rintl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    nextafterl = _libraries['FIXME_STUB'].nextafterl
    nextafterl.restype = c_long_double_t
    nextafterl.argtypes = [c_long_double_t, c_long_double_t]
except AttributeError:
    pass
try:
    __nextafterl = _libraries['FIXME_STUB'].__nextafterl
    __nextafterl.restype = c_long_double_t
    __nextafterl.argtypes = [c_long_double_t, c_long_double_t]
except AttributeError:
    pass
try:
    nexttowardl = _libraries['FIXME_STUB'].nexttowardl
    nexttowardl.restype = c_long_double_t
    nexttowardl.argtypes = [c_long_double_t, c_long_double_t]
except AttributeError:
    pass
try:
    __nexttowardl = _libraries['FIXME_STUB'].__nexttowardl
    __nexttowardl.restype = c_long_double_t
    __nexttowardl.argtypes = [c_long_double_t, c_long_double_t]
except AttributeError:
    pass
try:
    remainderl = _libraries['FIXME_STUB'].remainderl
    remainderl.restype = c_long_double_t
    remainderl.argtypes = [c_long_double_t, c_long_double_t]
except AttributeError:
    pass
try:
    __remainderl = _libraries['FIXME_STUB'].__remainderl
    __remainderl.restype = c_long_double_t
    __remainderl.argtypes = [c_long_double_t, c_long_double_t]
except AttributeError:
    pass
try:
    scalbnl = _libraries['FIXME_STUB'].scalbnl
    scalbnl.restype = c_long_double_t
    scalbnl.argtypes = [c_long_double_t, ctypes.c_int32]
except AttributeError:
    pass
try:
    __scalbnl = _libraries['FIXME_STUB'].__scalbnl
    __scalbnl.restype = c_long_double_t
    __scalbnl.argtypes = [c_long_double_t, ctypes.c_int32]
except AttributeError:
    pass
try:
    ilogbl = _libraries['FIXME_STUB'].ilogbl
    ilogbl.restype = ctypes.c_int32
    ilogbl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __ilogbl = _libraries['FIXME_STUB'].__ilogbl
    __ilogbl.restype = ctypes.c_int32
    __ilogbl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    scalblnl = _libraries['FIXME_STUB'].scalblnl
    scalblnl.restype = c_long_double_t
    scalblnl.argtypes = [c_long_double_t, ctypes.c_int64]
except AttributeError:
    pass
try:
    __scalblnl = _libraries['FIXME_STUB'].__scalblnl
    __scalblnl.restype = c_long_double_t
    __scalblnl.argtypes = [c_long_double_t, ctypes.c_int64]
except AttributeError:
    pass
try:
    nearbyintl = _libraries['FIXME_STUB'].nearbyintl
    nearbyintl.restype = c_long_double_t
    nearbyintl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __nearbyintl = _libraries['FIXME_STUB'].__nearbyintl
    __nearbyintl.restype = c_long_double_t
    __nearbyintl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    roundl = _libraries['FIXME_STUB'].roundl
    roundl.restype = c_long_double_t
    roundl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __roundl = _libraries['FIXME_STUB'].__roundl
    __roundl.restype = c_long_double_t
    __roundl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    truncl = _libraries['FIXME_STUB'].truncl
    truncl.restype = c_long_double_t
    truncl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __truncl = _libraries['FIXME_STUB'].__truncl
    __truncl.restype = c_long_double_t
    __truncl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    remquol = _libraries['FIXME_STUB'].remquol
    remquol.restype = c_long_double_t
    remquol.argtypes = [c_long_double_t, c_long_double_t, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    __remquol = _libraries['FIXME_STUB'].__remquol
    __remquol.restype = c_long_double_t
    __remquol.argtypes = [c_long_double_t, c_long_double_t, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    lrintl = _libraries['FIXME_STUB'].lrintl
    lrintl.restype = ctypes.c_int64
    lrintl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __lrintl = _libraries['FIXME_STUB'].__lrintl
    __lrintl.restype = ctypes.c_int64
    __lrintl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    llrintl = _libraries['FIXME_STUB'].llrintl
    llrintl.restype = ctypes.c_int64
    llrintl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __llrintl = _libraries['FIXME_STUB'].__llrintl
    __llrintl.restype = ctypes.c_int64
    __llrintl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    lroundl = _libraries['FIXME_STUB'].lroundl
    lroundl.restype = ctypes.c_int64
    lroundl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __lroundl = _libraries['FIXME_STUB'].__lroundl
    __lroundl.restype = ctypes.c_int64
    __lroundl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    llroundl = _libraries['FIXME_STUB'].llroundl
    llroundl.restype = ctypes.c_int64
    llroundl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    __llroundl = _libraries['FIXME_STUB'].__llroundl
    __llroundl.restype = ctypes.c_int64
    __llroundl.argtypes = [c_long_double_t]
except AttributeError:
    pass
try:
    fdiml = _libraries['FIXME_STUB'].fdiml
    fdiml.restype = c_long_double_t
    fdiml.argtypes = [c_long_double_t, c_long_double_t]
except AttributeError:
    pass
try:
    __fdiml = _libraries['FIXME_STUB'].__fdiml
    __fdiml.restype = c_long_double_t
    __fdiml.argtypes = [c_long_double_t, c_long_double_t]
except AttributeError:
    pass
try:
    fmaxl = _libraries['FIXME_STUB'].fmaxl
    fmaxl.restype = c_long_double_t
    fmaxl.argtypes = [c_long_double_t, c_long_double_t]
except AttributeError:
    pass
try:
    __fmaxl = _libraries['FIXME_STUB'].__fmaxl
    __fmaxl.restype = c_long_double_t
    __fmaxl.argtypes = [c_long_double_t, c_long_double_t]
except AttributeError:
    pass
try:
    fminl = _libraries['FIXME_STUB'].fminl
    fminl.restype = c_long_double_t
    fminl.argtypes = [c_long_double_t, c_long_double_t]
except AttributeError:
    pass
try:
    __fminl = _libraries['FIXME_STUB'].__fminl
    __fminl.restype = c_long_double_t
    __fminl.argtypes = [c_long_double_t, c_long_double_t]
except AttributeError:
    pass
try:
    fmal = _libraries['FIXME_STUB'].fmal
    fmal.restype = c_long_double_t
    fmal.argtypes = [c_long_double_t, c_long_double_t, c_long_double_t]
except AttributeError:
    pass
try:
    __fmal = _libraries['FIXME_STUB'].__fmal
    __fmal.restype = c_long_double_t
    __fmal.argtypes = [c_long_double_t, c_long_double_t, c_long_double_t]
except AttributeError:
    pass
try:
    scalbl = _libraries['FIXME_STUB'].scalbl
    scalbl.restype = c_long_double_t
    scalbl.argtypes = [c_long_double_t, c_long_double_t]
except AttributeError:
    pass
try:
    __scalbl = _libraries['FIXME_STUB'].__scalbl
    __scalbl.restype = c_long_double_t
    __scalbl.argtypes = [c_long_double_t, c_long_double_t]
except AttributeError:
    pass
signgam = 0 # Variable ctypes.c_int32

# values for enumeration 'c__Ea_FP_NAN'
c__Ea_FP_NAN__enumvalues = {
    0: 'FP_NAN',
    1: 'FP_INFINITE',
    2: 'FP_ZERO',
    3: 'FP_SUBNORMAL',
    4: 'FP_NORMAL',
}
FP_NAN = 0
FP_INFINITE = 1
FP_ZERO = 2
FP_SUBNORMAL = 3
FP_NORMAL = 4
c__Ea_FP_NAN = ctypes.c_uint32 # enum
uut16 = ctypes.c_uint16
uut32 = ctypes.c_uint32
uut64 = ctypes.c_uint64
ust16 = ctypes.c_int16
ust32 = ctypes.c_int32
ust64 = ctypes.c_int64
class union_utAny(Union):
    pass

union_utAny._pack_ = 1 # source:False
union_utAny._fields_ = [
    ('v8', ctypes.c_ubyte),
    ('v16', ctypes.c_uint16),
    ('v32', ctypes.c_uint32),
    ('v64', ctypes.c_uint64),
]

utAny = union_utAny
class struct__ut80(Structure):
    pass

struct__ut80._pack_ = 1 # source:False
struct__ut80._fields_ = [
    ('Low', ctypes.c_uint64),
    ('High', ctypes.c_uint16),
    ('PADDING_0', ctypes.c_ubyte * 6),
]

ut80 = struct__ut80
class struct__ut96(Structure):
    pass

struct__ut96._pack_ = 1 # source:False
struct__ut96._fields_ = [
    ('Low', ctypes.c_uint64),
    ('High', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

ut96 = struct__ut96
class struct__ut128(Structure):
    pass

struct__ut128._pack_ = 1 # source:False
struct__ut128._fields_ = [
    ('Low', ctypes.c_uint64),
    ('High', ctypes.c_int64),
]

ut128 = struct__ut128
class struct__ut256(Structure):
    _pack_ = 1 # source:False
    _fields_ = [
    ('Low', ut128),
    ('High', ut128),
     ]

ut256 = struct__ut256
class struct__utX(Structure):
    _pack_ = 1 # source:False
    _fields_ = [
    ('v80', ut80),
    ('v96', ut96),
    ('v128', ut128),
    ('v256', ut256),
     ]

utX = struct__utX
try:
    ST8_DIV_OVFCHK = _libraries['FIXME_STUB'].ST8_DIV_OVFCHK
    ST8_DIV_OVFCHK.restype = ctypes.c_bool
    ST8_DIV_OVFCHK.argtypes = [uint8_t, uint8_t]
except AttributeError:
    pass
try:
    ST16_DIV_OVFCHK = _libraries['FIXME_STUB'].ST16_DIV_OVFCHK
    ST16_DIV_OVFCHK.restype = ctypes.c_bool
    ST16_DIV_OVFCHK.argtypes = [uint16_t, uint16_t]
except AttributeError:
    pass
try:
    ST32_DIV_OVFCHK = _libraries['FIXME_STUB'].ST32_DIV_OVFCHK
    ST32_DIV_OVFCHK.restype = ctypes.c_bool
    ST32_DIV_OVFCHK.argtypes = [uint32_t, uint32_t]
except AttributeError:
    pass
try:
    ST64_DIV_OVFCHK = _libraries['FIXME_STUB'].ST64_DIV_OVFCHK
    ST64_DIV_OVFCHK.restype = ctypes.c_bool
    ST64_DIV_OVFCHK.argtypes = [uint64_t, uint64_t]
except AttributeError:
    pass
try:
    UT8_DIV_OVFCHK = _libraries['FIXME_STUB'].UT8_DIV_OVFCHK
    UT8_DIV_OVFCHK.restype = ctypes.c_bool
    UT8_DIV_OVFCHK.argtypes = [uint8_t, uint8_t]
except AttributeError:
    pass
try:
    UT16_DIV_OVFCHK = _libraries['FIXME_STUB'].UT16_DIV_OVFCHK
    UT16_DIV_OVFCHK.restype = ctypes.c_bool
    UT16_DIV_OVFCHK.argtypes = [uint16_t, uint16_t]
except AttributeError:
    pass
try:
    UT32_DIV_OVFCHK = _libraries['FIXME_STUB'].UT32_DIV_OVFCHK
    UT32_DIV_OVFCHK.restype = ctypes.c_bool
    UT32_DIV_OVFCHK.argtypes = [uint32_t, uint32_t]
except AttributeError:
    pass
try:
    UT64_DIV_OVFCHK = _libraries['FIXME_STUB'].UT64_DIV_OVFCHK
    UT64_DIV_OVFCHK.restype = ctypes.c_bool
    UT64_DIV_OVFCHK.argtypes = [uint64_t, uint64_t]
except AttributeError:
    pass
try:
    ST8_MUL_OVFCHK = _libraries['FIXME_STUB'].ST8_MUL_OVFCHK
    ST8_MUL_OVFCHK.restype = ctypes.c_bool
    ST8_MUL_OVFCHK.argtypes = [int8_t, int8_t]
except AttributeError:
    pass
try:
    ST16_MUL_OVFCHK = _libraries['FIXME_STUB'].ST16_MUL_OVFCHK
    ST16_MUL_OVFCHK.restype = ctypes.c_bool
    ST16_MUL_OVFCHK.argtypes = [int16_t, int16_t]
except AttributeError:
    pass
try:
    ST32_MUL_OVFCHK = _libraries['FIXME_STUB'].ST32_MUL_OVFCHK
    ST32_MUL_OVFCHK.restype = ctypes.c_bool
    ST32_MUL_OVFCHK.argtypes = [int32_t, int32_t]
except AttributeError:
    pass
try:
    ST64_MUL_OVFCHK = _libraries['FIXME_STUB'].ST64_MUL_OVFCHK
    ST64_MUL_OVFCHK.restype = ctypes.c_bool
    ST64_MUL_OVFCHK.argtypes = [int64_t, int64_t]
except AttributeError:
    pass
try:
    SZT_MUL_OVFCHK = _libraries['FIXME_STUB'].SZT_MUL_OVFCHK
    SZT_MUL_OVFCHK.restype = ctypes.c_bool
    SZT_MUL_OVFCHK.argtypes = [size_t, size_t]
except AttributeError:
    pass
try:
    UT8_MUL_OVFCHK = _libraries['FIXME_STUB'].UT8_MUL_OVFCHK
    UT8_MUL_OVFCHK.restype = ctypes.c_bool
    UT8_MUL_OVFCHK.argtypes = [uint8_t, uint8_t]
except AttributeError:
    pass
try:
    UT16_MUL_OVFCHK = _libraries['FIXME_STUB'].UT16_MUL_OVFCHK
    UT16_MUL_OVFCHK.restype = ctypes.c_bool
    UT16_MUL_OVFCHK.argtypes = [uint16_t, uint16_t]
except AttributeError:
    pass
try:
    UT32_MUL_OVFCHK = _libraries['FIXME_STUB'].UT32_MUL_OVFCHK
    UT32_MUL_OVFCHK.restype = ctypes.c_bool
    UT32_MUL_OVFCHK.argtypes = [uint32_t, uint32_t]
except AttributeError:
    pass
try:
    UT64_MUL_OVFCHK = _libraries['FIXME_STUB'].UT64_MUL_OVFCHK
    UT64_MUL_OVFCHK.restype = ctypes.c_bool
    UT64_MUL_OVFCHK.argtypes = [uint64_t, uint64_t]
except AttributeError:
    pass
ptrdiff_t = ctypes.c_int64
wchar_t = ctypes.c_int32
class struct_max_align_t(Structure):
    pass

struct_max_align_t._pack_ = 1 # source:False
struct_max_align_t._fields_ = [
    ('__clang_max_align_nonce1', ctypes.c_int64),
    ('PADDING_0', ctypes.c_ubyte * 8),
    ('__clang_max_align_nonce2', c_long_double_t),
]

max_align_t = struct_max_align_t
class struct_div_t(Structure):
    pass

struct_div_t._pack_ = 1 # source:False
struct_div_t._fields_ = [
    ('quot', ctypes.c_int32),
    ('rem', ctypes.c_int32),
]

div_t = struct_div_t
class struct_ldiv_t(Structure):
    pass

struct_ldiv_t._pack_ = 1 # source:False
struct_ldiv_t._fields_ = [
    ('quot', ctypes.c_int64),
    ('rem', ctypes.c_int64),
]

ldiv_t = struct_ldiv_t
class struct_lldiv_t(Structure):
    pass

struct_lldiv_t._pack_ = 1 # source:False
struct_lldiv_t._fields_ = [
    ('quot', ctypes.c_int64),
    ('rem', ctypes.c_int64),
]

lldiv_t = struct_lldiv_t
try:
    __ctype_get_mb_cur_max = _libraries['FIXME_STUB'].__ctype_get_mb_cur_max
    __ctype_get_mb_cur_max.restype = size_t
    __ctype_get_mb_cur_max.argtypes = []
except AttributeError:
    pass
try:
    atof = _libraries['FIXME_STUB'].atof
    atof.restype = ctypes.c_double
    atof.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    atoi = _libraries['FIXME_STUB'].atoi
    atoi.restype = ctypes.c_int32
    atoi.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    atol = _libraries['FIXME_STUB'].atol
    atol.restype = ctypes.c_int64
    atol.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    atoll = _libraries['FIXME_STUB'].atoll
    atoll.restype = ctypes.c_int64
    atoll.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    strtod = _libraries['FIXME_STUB'].strtod
    strtod.restype = ctypes.c_double
    strtod.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
except AttributeError:
    pass
try:
    strtof = _libraries['FIXME_STUB'].strtof
    strtof.restype = ctypes.c_float
    strtof.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
except AttributeError:
    pass
try:
    strtold = _libraries['FIXME_STUB'].strtold
    strtold.restype = c_long_double_t
    strtold.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
except AttributeError:
    pass
try:
    strtol = _libraries['FIXME_STUB'].strtol
    strtol.restype = ctypes.c_int64
    strtol.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.c_int32]
except AttributeError:
    pass
try:
    strtoul = _libraries['FIXME_STUB'].strtoul
    strtoul.restype = ctypes.c_uint64
    strtoul.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.c_int32]
except AttributeError:
    pass
try:
    strtoq = _libraries['FIXME_STUB'].strtoq
    strtoq.restype = ctypes.c_int64
    strtoq.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.c_int32]
except AttributeError:
    pass
try:
    strtouq = _libraries['FIXME_STUB'].strtouq
    strtouq.restype = ctypes.c_uint64
    strtouq.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.c_int32]
except AttributeError:
    pass
try:
    strtoll = _libraries['FIXME_STUB'].strtoll
    strtoll.restype = ctypes.c_int64
    strtoll.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.c_int32]
except AttributeError:
    pass
try:
    strtoull = _libraries['FIXME_STUB'].strtoull
    strtoull.restype = ctypes.c_uint64
    strtoull.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.c_int32]
except AttributeError:
    pass
try:
    l64a = _libraries['FIXME_STUB'].l64a
    l64a.restype = ctypes.POINTER(ctypes.c_char)
    l64a.argtypes = [ctypes.c_int64]
except AttributeError:
    pass
try:
    a64l = _libraries['FIXME_STUB'].a64l
    a64l.restype = ctypes.c_int64
    a64l.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    random = _libraries['FIXME_STUB'].random
    random.restype = ctypes.c_int64
    random.argtypes = []
except AttributeError:
    pass
try:
    srandom = _libraries['FIXME_STUB'].srandom
    srandom.restype = None
    srandom.argtypes = [ctypes.c_uint32]
except AttributeError:
    pass
try:
    initstate = _libraries['FIXME_STUB'].initstate
    initstate.restype = ctypes.POINTER(ctypes.c_char)
    initstate.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    setstate = _libraries['FIXME_STUB'].setstate
    setstate.restype = ctypes.POINTER(ctypes.c_char)
    setstate.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
class struct_random_data(Structure):
    pass

struct_random_data._pack_ = 1 # source:False
struct_random_data._fields_ = [
    ('fptr', ctypes.POINTER(ctypes.c_int32)),
    ('rptr', ctypes.POINTER(ctypes.c_int32)),
    ('state', ctypes.POINTER(ctypes.c_int32)),
    ('rand_type', ctypes.c_int32),
    ('rand_deg', ctypes.c_int32),
    ('rand_sep', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('end_ptr', ctypes.POINTER(ctypes.c_int32)),
]

try:
    random_r = _libraries['FIXME_STUB'].random_r
    random_r.restype = ctypes.c_int32
    random_r.argtypes = [ctypes.POINTER(struct_random_data), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    srandom_r = _libraries['FIXME_STUB'].srandom_r
    srandom_r.restype = ctypes.c_int32
    srandom_r.argtypes = [ctypes.c_uint32, ctypes.POINTER(struct_random_data)]
except AttributeError:
    pass
try:
    initstate_r = _libraries['FIXME_STUB'].initstate_r
    initstate_r.restype = ctypes.c_int32
    initstate_r.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(struct_random_data)]
except AttributeError:
    pass
try:
    setstate_r = _libraries['FIXME_STUB'].setstate_r
    setstate_r.restype = ctypes.c_int32
    setstate_r.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_random_data)]
except AttributeError:
    pass
try:
    rand = _libraries['FIXME_STUB'].rand
    rand.restype = ctypes.c_int32
    rand.argtypes = []
except AttributeError:
    pass
try:
    srand = _libraries['FIXME_STUB'].srand
    srand.restype = None
    srand.argtypes = [ctypes.c_uint32]
except AttributeError:
    pass
try:
    rand_r = _libraries['FIXME_STUB'].rand_r
    rand_r.restype = ctypes.c_int32
    rand_r.argtypes = [ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    drand48 = _libraries['FIXME_STUB'].drand48
    drand48.restype = ctypes.c_double
    drand48.argtypes = []
except AttributeError:
    pass
try:
    erand48 = _libraries['FIXME_STUB'].erand48
    erand48.restype = ctypes.c_double
    erand48.argtypes = [ctypes.c_uint16 * 3]
except AttributeError:
    pass
try:
    lrand48 = _libraries['FIXME_STUB'].lrand48
    lrand48.restype = ctypes.c_int64
    lrand48.argtypes = []
except AttributeError:
    pass
try:
    nrand48 = _libraries['FIXME_STUB'].nrand48
    nrand48.restype = ctypes.c_int64
    nrand48.argtypes = [ctypes.c_uint16 * 3]
except AttributeError:
    pass
try:
    mrand48 = _libraries['FIXME_STUB'].mrand48
    mrand48.restype = ctypes.c_int64
    mrand48.argtypes = []
except AttributeError:
    pass
try:
    jrand48 = _libraries['FIXME_STUB'].jrand48
    jrand48.restype = ctypes.c_int64
    jrand48.argtypes = [ctypes.c_uint16 * 3]
except AttributeError:
    pass
try:
    srand48 = _libraries['FIXME_STUB'].srand48
    srand48.restype = None
    srand48.argtypes = [ctypes.c_int64]
except AttributeError:
    pass
try:
    seed48 = _libraries['FIXME_STUB'].seed48
    seed48.restype = ctypes.POINTER(ctypes.c_uint16)
    seed48.argtypes = [ctypes.c_uint16 * 3]
except AttributeError:
    pass
try:
    lcong48 = _libraries['FIXME_STUB'].lcong48
    lcong48.restype = None
    lcong48.argtypes = [ctypes.c_uint16 * 7]
except AttributeError:
    pass
class struct_drand48_data(Structure):
    pass

struct_drand48_data._pack_ = 1 # source:False
struct_drand48_data._fields_ = [
    ('__x', ctypes.c_uint16 * 3),
    ('__old_x', ctypes.c_uint16 * 3),
    ('__c', ctypes.c_uint16),
    ('__init', ctypes.c_uint16),
    ('__a', ctypes.c_uint64),
]

try:
    drand48_r = _libraries['FIXME_STUB'].drand48_r
    drand48_r.restype = ctypes.c_int32
    drand48_r.argtypes = [ctypes.POINTER(struct_drand48_data), ctypes.POINTER(ctypes.c_double)]
except AttributeError:
    pass
try:
    erand48_r = _libraries['FIXME_STUB'].erand48_r
    erand48_r.restype = ctypes.c_int32
    erand48_r.argtypes = [ctypes.c_uint16 * 3, ctypes.POINTER(struct_drand48_data), ctypes.POINTER(ctypes.c_double)]
except AttributeError:
    pass
try:
    lrand48_r = _libraries['FIXME_STUB'].lrand48_r
    lrand48_r.restype = ctypes.c_int32
    lrand48_r.argtypes = [ctypes.POINTER(struct_drand48_data), ctypes.POINTER(ctypes.c_int64)]
except AttributeError:
    pass
try:
    nrand48_r = _libraries['FIXME_STUB'].nrand48_r
    nrand48_r.restype = ctypes.c_int32
    nrand48_r.argtypes = [ctypes.c_uint16 * 3, ctypes.POINTER(struct_drand48_data), ctypes.POINTER(ctypes.c_int64)]
except AttributeError:
    pass
try:
    mrand48_r = _libraries['FIXME_STUB'].mrand48_r
    mrand48_r.restype = ctypes.c_int32
    mrand48_r.argtypes = [ctypes.POINTER(struct_drand48_data), ctypes.POINTER(ctypes.c_int64)]
except AttributeError:
    pass
try:
    jrand48_r = _libraries['FIXME_STUB'].jrand48_r
    jrand48_r.restype = ctypes.c_int32
    jrand48_r.argtypes = [ctypes.c_uint16 * 3, ctypes.POINTER(struct_drand48_data), ctypes.POINTER(ctypes.c_int64)]
except AttributeError:
    pass
try:
    srand48_r = _libraries['FIXME_STUB'].srand48_r
    srand48_r.restype = ctypes.c_int32
    srand48_r.argtypes = [ctypes.c_int64, ctypes.POINTER(struct_drand48_data)]
except AttributeError:
    pass
try:
    seed48_r = _libraries['FIXME_STUB'].seed48_r
    seed48_r.restype = ctypes.c_int32
    seed48_r.argtypes = [ctypes.c_uint16 * 3, ctypes.POINTER(struct_drand48_data)]
except AttributeError:
    pass
try:
    lcong48_r = _libraries['FIXME_STUB'].lcong48_r
    lcong48_r.restype = ctypes.c_int32
    lcong48_r.argtypes = [ctypes.c_uint16 * 7, ctypes.POINTER(struct_drand48_data)]
except AttributeError:
    pass
try:
    arc4random = _libraries['FIXME_STUB'].arc4random
    arc4random.restype = __uint32_t
    arc4random.argtypes = []
except AttributeError:
    pass
try:
    arc4random_buf = _libraries['FIXME_STUB'].arc4random_buf
    arc4random_buf.restype = None
    arc4random_buf.argtypes = [ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    arc4random_uniform = _libraries['FIXME_STUB'].arc4random_uniform
    arc4random_uniform.restype = __uint32_t
    arc4random_uniform.argtypes = [__uint32_t]
except AttributeError:
    pass
try:
    malloc = _libraries['FIXME_STUB'].malloc
    malloc.restype = ctypes.POINTER(None)
    malloc.argtypes = [size_t]
except AttributeError:
    pass
try:
    calloc = _libraries['FIXME_STUB'].calloc
    calloc.restype = ctypes.POINTER(None)
    calloc.argtypes = [size_t, size_t]
except AttributeError:
    pass
try:
    realloc = _libraries['FIXME_STUB'].realloc
    realloc.restype = ctypes.POINTER(None)
    realloc.argtypes = [ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    free = _libraries['FIXME_STUB'].free
    free.restype = None
    free.argtypes = [ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    reallocarray = _libraries['FIXME_STUB'].reallocarray
    reallocarray.restype = ctypes.POINTER(None)
    reallocarray.argtypes = [ctypes.POINTER(None), size_t, size_t]
except AttributeError:
    pass
try:
    alloca = _libraries['FIXME_STUB'].alloca
    alloca.restype = ctypes.POINTER(None)
    alloca.argtypes = [size_t]
except AttributeError:
    pass
try:
    valloc = _libraries['FIXME_STUB'].valloc
    valloc.restype = ctypes.POINTER(None)
    valloc.argtypes = [size_t]
except AttributeError:
    pass
try:
    posix_memalign = _libraries['FIXME_STUB'].posix_memalign
    posix_memalign.restype = ctypes.c_int32
    posix_memalign.argtypes = [ctypes.POINTER(ctypes.POINTER(None)), size_t, size_t]
except AttributeError:
    pass
try:
    aligned_alloc = _libraries['FIXME_STUB'].aligned_alloc
    aligned_alloc.restype = ctypes.POINTER(None)
    aligned_alloc.argtypes = [size_t, size_t]
except AttributeError:
    pass
try:
    abort = _libraries['FIXME_STUB'].abort
    abort.restype = None
    abort.argtypes = []
except AttributeError:
    pass
try:
    atexit = _libraries['FIXME_STUB'].atexit
    atexit.restype = ctypes.c_int32
    atexit.argtypes = [ctypes.CFUNCTYPE(None)]
except AttributeError:
    pass
try:
    at_quick_exit = _libraries['FIXME_STUB'].at_quick_exit
    at_quick_exit.restype = ctypes.c_int32
    at_quick_exit.argtypes = [ctypes.CFUNCTYPE(None)]
except AttributeError:
    pass
try:
    on_exit = _libraries['FIXME_STUB'].on_exit
    on_exit.restype = ctypes.c_int32
    on_exit.argtypes = [ctypes.CFUNCTYPE(None, ctypes.c_int32, ctypes.POINTER(None)), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    exit = _libraries['FIXME_STUB'].exit
    exit.restype = None
    exit.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    quick_exit = _libraries['FIXME_STUB'].quick_exit
    quick_exit.restype = None
    quick_exit.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    _Exit = _libraries['FIXME_STUB']._Exit
    _Exit.restype = None
    _Exit.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    getenv = _libraries['FIXME_STUB'].getenv
    getenv.restype = ctypes.POINTER(ctypes.c_char)
    getenv.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    putenv = _libraries['FIXME_STUB'].putenv
    putenv.restype = ctypes.c_int32
    putenv.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    setenv = _libraries['FIXME_STUB'].setenv
    setenv.restype = ctypes.c_int32
    setenv.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    unsetenv = _libraries['FIXME_STUB'].unsetenv
    unsetenv.restype = ctypes.c_int32
    unsetenv.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    clearenv = _libraries['FIXME_STUB'].clearenv
    clearenv.restype = ctypes.c_int32
    clearenv.argtypes = []
except AttributeError:
    pass
try:
    mktemp = _libraries['FIXME_STUB'].mktemp
    mktemp.restype = ctypes.POINTER(ctypes.c_char)
    mktemp.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    mkstemp = _libraries['FIXME_STUB'].mkstemp
    mkstemp.restype = ctypes.c_int32
    mkstemp.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    mkstemps = _libraries['FIXME_STUB'].mkstemps
    mkstemps.restype = ctypes.c_int32
    mkstemps.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    mkdtemp = _libraries['FIXME_STUB'].mkdtemp
    mkdtemp.restype = ctypes.POINTER(ctypes.c_char)
    mkdtemp.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    system = _libraries['FIXME_STUB'].system
    system.restype = ctypes.c_int32
    system.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    realpath = _libraries['FIXME_STUB'].realpath
    realpath.restype = ctypes.POINTER(ctypes.c_char)
    realpath.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
__compar_fn_t = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(None))
try:
    bsearch = _libraries['FIXME_STUB'].bsearch
    bsearch.restype = ctypes.POINTER(None)
    bsearch.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None), size_t, size_t, __compar_fn_t]
except AttributeError:
    pass
try:
    qsort = _libraries['FIXME_STUB'].qsort
    qsort.restype = None
    qsort.argtypes = [ctypes.POINTER(None), size_t, size_t, __compar_fn_t]
except AttributeError:
    pass
try:
    abs = _libraries['FIXME_STUB'].abs
    abs.restype = ctypes.c_int32
    abs.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    labs = _libraries['FIXME_STUB'].labs
    labs.restype = ctypes.c_int64
    labs.argtypes = [ctypes.c_int64]
except AttributeError:
    pass
try:
    llabs = _libraries['FIXME_STUB'].llabs
    llabs.restype = ctypes.c_int64
    llabs.argtypes = [ctypes.c_int64]
except AttributeError:
    pass
try:
    div = _libraries['FIXME_STUB'].div
    div.restype = div_t
    div.argtypes = [ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    ldiv = _libraries['FIXME_STUB'].ldiv
    ldiv.restype = ldiv_t
    ldiv.argtypes = [ctypes.c_int64, ctypes.c_int64]
except AttributeError:
    pass
try:
    lldiv = _libraries['FIXME_STUB'].lldiv
    lldiv.restype = lldiv_t
    lldiv.argtypes = [ctypes.c_int64, ctypes.c_int64]
except AttributeError:
    pass
try:
    ecvt = _libraries['FIXME_STUB'].ecvt
    ecvt.restype = ctypes.POINTER(ctypes.c_char)
    ecvt.argtypes = [ctypes.c_double, ctypes.c_int32, ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    fcvt = _libraries['FIXME_STUB'].fcvt
    fcvt.restype = ctypes.POINTER(ctypes.c_char)
    fcvt.argtypes = [ctypes.c_double, ctypes.c_int32, ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    gcvt = _libraries['FIXME_STUB'].gcvt
    gcvt.restype = ctypes.POINTER(ctypes.c_char)
    gcvt.argtypes = [ctypes.c_double, ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    qecvt = _libraries['FIXME_STUB'].qecvt
    qecvt.restype = ctypes.POINTER(ctypes.c_char)
    qecvt.argtypes = [c_long_double_t, ctypes.c_int32, ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    qfcvt = _libraries['FIXME_STUB'].qfcvt
    qfcvt.restype = ctypes.POINTER(ctypes.c_char)
    qfcvt.argtypes = [c_long_double_t, ctypes.c_int32, ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    qgcvt = _libraries['FIXME_STUB'].qgcvt
    qgcvt.restype = ctypes.POINTER(ctypes.c_char)
    qgcvt.argtypes = [c_long_double_t, ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    ecvt_r = _libraries['FIXME_STUB'].ecvt_r
    ecvt_r.restype = ctypes.c_int32
    ecvt_r.argtypes = [ctypes.c_double, ctypes.c_int32, ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    fcvt_r = _libraries['FIXME_STUB'].fcvt_r
    fcvt_r.restype = ctypes.c_int32
    fcvt_r.argtypes = [ctypes.c_double, ctypes.c_int32, ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    qecvt_r = _libraries['FIXME_STUB'].qecvt_r
    qecvt_r.restype = ctypes.c_int32
    qecvt_r.argtypes = [c_long_double_t, ctypes.c_int32, ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    qfcvt_r = _libraries['FIXME_STUB'].qfcvt_r
    qfcvt_r.restype = ctypes.c_int32
    qfcvt_r.argtypes = [c_long_double_t, ctypes.c_int32, ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    mblen = _libraries['FIXME_STUB'].mblen
    mblen.restype = ctypes.c_int32
    mblen.argtypes = [ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    mbtowc = _libraries['FIXME_STUB'].mbtowc
    mbtowc.restype = ctypes.c_int32
    mbtowc.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    wctomb = _libraries['FIXME_STUB'].wctomb
    wctomb.restype = ctypes.c_int32
    wctomb.argtypes = [ctypes.POINTER(ctypes.c_char), wchar_t]
except AttributeError:
    pass
try:
    mbstowcs = _libraries['FIXME_STUB'].mbstowcs
    mbstowcs.restype = size_t
    mbstowcs.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    wcstombs = _libraries['FIXME_STUB'].wcstombs
    wcstombs.restype = size_t
    wcstombs.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_int32), size_t]
except AttributeError:
    pass
try:
    rpmatch = _libraries['FIXME_STUB'].rpmatch
    rpmatch.restype = ctypes.c_int32
    rpmatch.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    getsubopt = _libraries['FIXME_STUB'].getsubopt
    getsubopt.restype = ctypes.c_int32
    getsubopt.argtypes = [ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
except AttributeError:
    pass
try:
    getloadavg = _libraries['FIXME_STUB'].getloadavg
    getloadavg.restype = ctypes.c_int32
    getloadavg.argtypes = [ctypes.c_double * 0, ctypes.c_int32]
except AttributeError:
    pass
try:
    __assert_fail = _libraries['FIXME_STUB'].__assert_fail
    __assert_fail.restype = None
    __assert_fail.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_uint32, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    __assert_perror_fail = _libraries['FIXME_STUB'].__assert_perror_fail
    __assert_perror_fail.restype = None
    __assert_perror_fail.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.c_uint32, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    __assert = _libraries['FIXME_STUB'].__assert
    __assert.restype = None
    __assert.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
__gwchar_t = ctypes.c_int32
class struct_imaxdiv_t(Structure):
    pass

struct_imaxdiv_t._pack_ = 1 # source:False
struct_imaxdiv_t._fields_ = [
    ('quot', ctypes.c_int64),
    ('rem', ctypes.c_int64),
]

imaxdiv_t = struct_imaxdiv_t
try:
    imaxabs = _libraries['FIXME_STUB'].imaxabs
    imaxabs.restype = intmax_t
    imaxabs.argtypes = [intmax_t]
except AttributeError:
    pass
try:
    imaxdiv = _libraries['FIXME_STUB'].imaxdiv
    imaxdiv.restype = imaxdiv_t
    imaxdiv.argtypes = [intmax_t, intmax_t]
except AttributeError:
    pass
try:
    strtoimax = _libraries['FIXME_STUB'].strtoimax
    strtoimax.restype = intmax_t
    strtoimax.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.c_int32]
except AttributeError:
    pass
try:
    strtoumax = _libraries['FIXME_STUB'].strtoumax
    strtoumax.restype = uintmax_t
    strtoumax.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.c_int32]
except AttributeError:
    pass
try:
    wcstoimax = _libraries['FIXME_STUB'].wcstoimax
    wcstoimax.restype = intmax_t
    wcstoimax.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.POINTER(ctypes.c_int32)), ctypes.c_int32]
except AttributeError:
    pass
try:
    wcstoumax = _libraries['FIXME_STUB'].wcstoumax
    wcstoumax.restype = uintmax_t
    wcstoumax.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.POINTER(ctypes.c_int32)), ctypes.c_int32]
except AttributeError:
    pass
class struct___va_list_tag(Structure):
    pass

struct___va_list_tag._pack_ = 1 # source:False
struct___va_list_tag._fields_ = [
    ('gp_offset', ctypes.c_uint32),
    ('fp_offset', ctypes.c_uint32),
    ('overflow_arg_area', ctypes.POINTER(None)),
    ('reg_save_area', ctypes.POINTER(None)),
]

__gnuc_va_list = struct___va_list_tag * 1
class struct___mbstate_t(Structure):
    pass

class union___mbstate_t___value(Union):
    pass

union___mbstate_t___value._pack_ = 1 # source:False
union___mbstate_t___value._fields_ = [
    ('__wch', ctypes.c_uint32),
    ('__wchb', ctypes.c_char * 4),
]

struct___mbstate_t._pack_ = 1 # source:False
struct___mbstate_t._fields_ = [
    ('__count', ctypes.c_int32),
    ('__value', union___mbstate_t___value),
]

__mbstate_t = struct___mbstate_t
class struct__G_fpos_t(Structure):
    pass

struct__G_fpos_t._pack_ = 1 # source:False
struct__G_fpos_t._fields_ = [
    ('__pos', ctypes.c_int64),
    ('__state', globals()['__mbstate_t']),
]

__fpos_t = struct__G_fpos_t
class struct__G_fpos64_t(Structure):
    pass

struct__G_fpos64_t._pack_ = 1 # source:False
struct__G_fpos64_t._fields_ = [
    ('__pos', ctypes.c_int64),
    ('__state', globals()['__mbstate_t']),
]

__fpos64_t = struct__G_fpos64_t
class struct__IO_FILE(Structure):
    pass

class struct__IO_marker(Structure):
    pass

class struct__IO_codecvt(Structure):
    pass

class struct__IO_wide_data(Structure):
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

__FILE = struct__IO_FILE
FILE = struct__IO_FILE
_IO_lock_t = None
cookie_read_function_t = ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64)
cookie_write_function_t = ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64)
cookie_seek_function_t = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_int64), ctypes.c_int32)
cookie_close_function_t = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None))
class struct__IO_cookie_io_functions_t(Structure):
    pass

struct__IO_cookie_io_functions_t._pack_ = 1 # source:False
struct__IO_cookie_io_functions_t._fields_ = [
    ('read', ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64)),
    ('write', ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64)),
    ('seek', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_int64), ctypes.c_int32)),
    ('close', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None))),
]

cookie_io_functions_t = struct__IO_cookie_io_functions_t
va_list = struct___va_list_tag * 1
fpos_t = struct__G_fpos64_t
stdin = ctypes.POINTER(struct__IO_FILE)() # Variable ctypes.POINTER(struct__IO_FILE)
stdout = ctypes.POINTER(struct__IO_FILE)() # Variable ctypes.POINTER(struct__IO_FILE)
stderr = ctypes.POINTER(struct__IO_FILE)() # Variable ctypes.POINTER(struct__IO_FILE)
try:
    remove = _libraries['FIXME_STUB'].remove
    remove.restype = ctypes.c_int32
    remove.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    rename = _libraries['FIXME_STUB'].rename
    rename.restype = ctypes.c_int32
    rename.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    renameat = _libraries['FIXME_STUB'].renameat
    renameat.restype = ctypes.c_int32
    renameat.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    fclose = _libraries['FIXME_STUB'].fclose
    fclose.restype = ctypes.c_int32
    fclose.argtypes = [ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    tmpfile = _libraries['FIXME_STUB'].tmpfile
    tmpfile.restype = ctypes.POINTER(struct__IO_FILE)
    tmpfile.argtypes = []
except AttributeError:
    pass
try:
    tmpnam = _libraries['FIXME_STUB'].tmpnam
    tmpnam.restype = ctypes.POINTER(ctypes.c_char)
    tmpnam.argtypes = [ctypes.c_char * 20]
except AttributeError:
    pass
try:
    tmpnam_r = _libraries['FIXME_STUB'].tmpnam_r
    tmpnam_r.restype = ctypes.POINTER(ctypes.c_char)
    tmpnam_r.argtypes = [ctypes.c_char * 20]
except AttributeError:
    pass
try:
    tempnam = _libraries['FIXME_STUB'].tempnam
    tempnam.restype = ctypes.POINTER(ctypes.c_char)
    tempnam.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    fflush = _libraries['FIXME_STUB'].fflush
    fflush.restype = ctypes.c_int32
    fflush.argtypes = [ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    fflush_unlocked = _libraries['FIXME_STUB'].fflush_unlocked
    fflush_unlocked.restype = ctypes.c_int32
    fflush_unlocked.argtypes = [ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    fopen = _libraries['FIXME_STUB'].fopen
    fopen.restype = ctypes.POINTER(struct__IO_FILE)
    fopen.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    freopen = _libraries['FIXME_STUB'].freopen
    freopen.restype = ctypes.POINTER(struct__IO_FILE)
    freopen.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    fdopen = _libraries['FIXME_STUB'].fdopen
    fdopen.restype = ctypes.POINTER(struct__IO_FILE)
    fdopen.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    fopencookie = _libraries['FIXME_STUB'].fopencookie
    fopencookie.restype = ctypes.POINTER(struct__IO_FILE)
    fopencookie.argtypes = [ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char), cookie_io_functions_t]
except AttributeError:
    pass
try:
    fmemopen = _libraries['FIXME_STUB'].fmemopen
    fmemopen.restype = ctypes.POINTER(struct__IO_FILE)
    fmemopen.argtypes = [ctypes.POINTER(None), size_t, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    open_memstream = _libraries['FIXME_STUB'].open_memstream
    open_memstream.restype = ctypes.POINTER(struct__IO_FILE)
    open_memstream.argtypes = [ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.POINTER(ctypes.c_uint64)]
except AttributeError:
    pass
try:
    setbuf = _libraries['FIXME_STUB'].setbuf
    setbuf.restype = None
    setbuf.argtypes = [ctypes.POINTER(struct__IO_FILE), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    setvbuf = _libraries['FIXME_STUB'].setvbuf
    setvbuf.restype = ctypes.c_int32
    setvbuf.argtypes = [ctypes.POINTER(struct__IO_FILE), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, size_t]
except AttributeError:
    pass
try:
    setbuffer = _libraries['FIXME_STUB'].setbuffer
    setbuffer.restype = None
    setbuffer.argtypes = [ctypes.POINTER(struct__IO_FILE), ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    setlinebuf = _libraries['FIXME_STUB'].setlinebuf
    setlinebuf.restype = None
    setlinebuf.argtypes = [ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    fprintf = _libraries['FIXME_STUB'].fprintf
    fprintf.restype = ctypes.c_int32
    fprintf.argtypes = [ctypes.POINTER(struct__IO_FILE), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    printf = _libraries['FIXME_STUB'].printf
    printf.restype = ctypes.c_int32
    printf.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sprintf = _libraries['FIXME_STUB'].sprintf
    sprintf.restype = ctypes.c_int32
    sprintf.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    vfprintf = _libraries['FIXME_STUB'].vfprintf
    vfprintf.restype = ctypes.c_int32
    vfprintf.argtypes = [ctypes.POINTER(struct__IO_FILE), ctypes.POINTER(ctypes.c_char), __gnuc_va_list]
except AttributeError:
    pass
try:
    vprintf = _libraries['FIXME_STUB'].vprintf
    vprintf.restype = ctypes.c_int32
    vprintf.argtypes = [ctypes.POINTER(ctypes.c_char), __gnuc_va_list]
except AttributeError:
    pass
try:
    vsprintf = _libraries['FIXME_STUB'].vsprintf
    vsprintf.restype = ctypes.c_int32
    vsprintf.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), __gnuc_va_list]
except AttributeError:
    pass
try:
    snprintf = _libraries['FIXME_STUB'].snprintf
    snprintf.restype = ctypes.c_int32
    snprintf.argtypes = [ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    vsnprintf = _libraries['FIXME_STUB'].vsnprintf
    vsnprintf.restype = ctypes.c_int32
    vsnprintf.argtypes = [ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(ctypes.c_char), __gnuc_va_list]
except AttributeError:
    pass
try:
    vasprintf = _libraries['FIXME_STUB'].vasprintf
    vasprintf.restype = ctypes.c_int32
    vasprintf.argtypes = [ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.POINTER(ctypes.c_char), __gnuc_va_list]
except AttributeError:
    pass
try:
    __asprintf = _libraries['FIXME_STUB'].__asprintf
    __asprintf.restype = ctypes.c_int32
    __asprintf.argtypes = [ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    asprintf = _libraries['FIXME_STUB'].asprintf
    asprintf.restype = ctypes.c_int32
    asprintf.argtypes = [ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    vdprintf = _libraries['FIXME_STUB'].vdprintf
    vdprintf.restype = ctypes.c_int32
    vdprintf.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char), __gnuc_va_list]
except AttributeError:
    pass
try:
    dprintf = _libraries['FIXME_STUB'].dprintf
    dprintf.restype = ctypes.c_int32
    dprintf.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    fscanf = _libraries['FIXME_STUB'].fscanf
    fscanf.restype = ctypes.c_int32
    fscanf.argtypes = [ctypes.POINTER(struct__IO_FILE), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    scanf = _libraries['FIXME_STUB'].scanf
    scanf.restype = ctypes.c_int32
    scanf.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sscanf = _libraries['FIXME_STUB'].sscanf
    sscanf.restype = ctypes.c_int32
    sscanf.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    vfscanf = _libraries['FIXME_STUB'].vfscanf
    vfscanf.restype = ctypes.c_int32
    vfscanf.argtypes = [ctypes.POINTER(struct__IO_FILE), ctypes.POINTER(ctypes.c_char), __gnuc_va_list]
except AttributeError:
    pass
try:
    vscanf = _libraries['FIXME_STUB'].vscanf
    vscanf.restype = ctypes.c_int32
    vscanf.argtypes = [ctypes.POINTER(ctypes.c_char), __gnuc_va_list]
except AttributeError:
    pass
try:
    vsscanf = _libraries['FIXME_STUB'].vsscanf
    vsscanf.restype = ctypes.c_int32
    vsscanf.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), __gnuc_va_list]
except AttributeError:
    pass
try:
    fgetc = _libraries['FIXME_STUB'].fgetc
    fgetc.restype = ctypes.c_int32
    fgetc.argtypes = [ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    getc = _libraries['FIXME_STUB'].getc
    getc.restype = ctypes.c_int32
    getc.argtypes = [ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    getchar = _libraries['FIXME_STUB'].getchar
    getchar.restype = ctypes.c_int32
    getchar.argtypes = []
except AttributeError:
    pass
try:
    getc_unlocked = _libraries['FIXME_STUB'].getc_unlocked
    getc_unlocked.restype = ctypes.c_int32
    getc_unlocked.argtypes = [ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    getchar_unlocked = _libraries['FIXME_STUB'].getchar_unlocked
    getchar_unlocked.restype = ctypes.c_int32
    getchar_unlocked.argtypes = []
except AttributeError:
    pass
try:
    fgetc_unlocked = _libraries['FIXME_STUB'].fgetc_unlocked
    fgetc_unlocked.restype = ctypes.c_int32
    fgetc_unlocked.argtypes = [ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    fputc = _libraries['FIXME_STUB'].fputc
    fputc.restype = ctypes.c_int32
    fputc.argtypes = [ctypes.c_int32, ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    putc = _libraries['FIXME_STUB'].putc
    putc.restype = ctypes.c_int32
    putc.argtypes = [ctypes.c_int32, ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    putchar = _libraries['FIXME_STUB'].putchar
    putchar.restype = ctypes.c_int32
    putchar.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    fputc_unlocked = _libraries['FIXME_STUB'].fputc_unlocked
    fputc_unlocked.restype = ctypes.c_int32
    fputc_unlocked.argtypes = [ctypes.c_int32, ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    putc_unlocked = _libraries['FIXME_STUB'].putc_unlocked
    putc_unlocked.restype = ctypes.c_int32
    putc_unlocked.argtypes = [ctypes.c_int32, ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    putchar_unlocked = _libraries['FIXME_STUB'].putchar_unlocked
    putchar_unlocked.restype = ctypes.c_int32
    putchar_unlocked.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    getw = _libraries['FIXME_STUB'].getw
    getw.restype = ctypes.c_int32
    getw.argtypes = [ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    putw = _libraries['FIXME_STUB'].putw
    putw.restype = ctypes.c_int32
    putw.argtypes = [ctypes.c_int32, ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    fgets = _libraries['FIXME_STUB'].fgets
    fgets.restype = ctypes.POINTER(ctypes.c_char)
    fgets.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    __getdelim = _libraries['FIXME_STUB'].__getdelim
    __getdelim.restype = __ssize_t
    __getdelim.argtypes = [ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.POINTER(ctypes.c_uint64), ctypes.c_int32, ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    getdelim = _libraries['FIXME_STUB'].getdelim
    getdelim.restype = __ssize_t
    getdelim.argtypes = [ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.POINTER(ctypes.c_uint64), ctypes.c_int32, ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    getline = _libraries['FIXME_STUB'].getline
    getline.restype = __ssize_t
    getline.argtypes = [ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    fputs = _libraries['FIXME_STUB'].fputs
    fputs.restype = ctypes.c_int32
    fputs.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    puts = _libraries['FIXME_STUB'].puts
    puts.restype = ctypes.c_int32
    puts.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    ungetc = _libraries['FIXME_STUB'].ungetc
    ungetc.restype = ctypes.c_int32
    ungetc.argtypes = [ctypes.c_int32, ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    fread = _libraries['FIXME_STUB'].fread
    fread.restype = ctypes.c_uint64
    fread.argtypes = [ctypes.POINTER(None), size_t, size_t, ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    fwrite = _libraries['FIXME_STUB'].fwrite
    fwrite.restype = ctypes.c_uint64
    fwrite.argtypes = [ctypes.POINTER(None), size_t, size_t, ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    fread_unlocked = _libraries['FIXME_STUB'].fread_unlocked
    fread_unlocked.restype = size_t
    fread_unlocked.argtypes = [ctypes.POINTER(None), size_t, size_t, ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    fwrite_unlocked = _libraries['FIXME_STUB'].fwrite_unlocked
    fwrite_unlocked.restype = size_t
    fwrite_unlocked.argtypes = [ctypes.POINTER(None), size_t, size_t, ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    fseek = _libraries['FIXME_STUB'].fseek
    fseek.restype = ctypes.c_int32
    fseek.argtypes = [ctypes.POINTER(struct__IO_FILE), ctypes.c_int64, ctypes.c_int32]
except AttributeError:
    pass
try:
    ftell = _libraries['FIXME_STUB'].ftell
    ftell.restype = ctypes.c_int64
    ftell.argtypes = [ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    rewind = _libraries['FIXME_STUB'].rewind
    rewind.restype = None
    rewind.argtypes = [ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    fseeko = _libraries['FIXME_STUB'].fseeko
    fseeko.restype = ctypes.c_int32
    fseeko.argtypes = [ctypes.POINTER(struct__IO_FILE), __off64_t, ctypes.c_int32]
except AttributeError:
    pass
try:
    ftello = _libraries['FIXME_STUB'].ftello
    ftello.restype = __off64_t
    ftello.argtypes = [ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    fgetpos = _libraries['FIXME_STUB'].fgetpos
    fgetpos.restype = ctypes.c_int32
    fgetpos.argtypes = [ctypes.POINTER(struct__IO_FILE), ctypes.POINTER(struct__G_fpos64_t)]
except AttributeError:
    pass
try:
    fsetpos = _libraries['FIXME_STUB'].fsetpos
    fsetpos.restype = ctypes.c_int32
    fsetpos.argtypes = [ctypes.POINTER(struct__IO_FILE), ctypes.POINTER(struct__G_fpos64_t)]
except AttributeError:
    pass
try:
    clearerr = _libraries['FIXME_STUB'].clearerr
    clearerr.restype = None
    clearerr.argtypes = [ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    feof = _libraries['FIXME_STUB'].feof
    feof.restype = ctypes.c_int32
    feof.argtypes = [ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    ferror = _libraries['FIXME_STUB'].ferror
    ferror.restype = ctypes.c_int32
    ferror.argtypes = [ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    clearerr_unlocked = _libraries['FIXME_STUB'].clearerr_unlocked
    clearerr_unlocked.restype = None
    clearerr_unlocked.argtypes = [ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    feof_unlocked = _libraries['FIXME_STUB'].feof_unlocked
    feof_unlocked.restype = ctypes.c_int32
    feof_unlocked.argtypes = [ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    ferror_unlocked = _libraries['FIXME_STUB'].ferror_unlocked
    ferror_unlocked.restype = ctypes.c_int32
    ferror_unlocked.argtypes = [ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    perror = _libraries['FIXME_STUB'].perror
    perror.restype = None
    perror.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    fileno = _libraries['FIXME_STUB'].fileno
    fileno.restype = ctypes.c_int32
    fileno.argtypes = [ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    fileno_unlocked = _libraries['FIXME_STUB'].fileno_unlocked
    fileno_unlocked.restype = ctypes.c_int32
    fileno_unlocked.argtypes = [ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    pclose = _libraries['FIXME_STUB'].pclose
    pclose.restype = ctypes.c_int32
    pclose.argtypes = [ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    popen = _libraries['FIXME_STUB'].popen
    popen.restype = ctypes.POINTER(struct__IO_FILE)
    popen.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    ctermid = _libraries['FIXME_STUB'].ctermid
    ctermid.restype = ctypes.POINTER(ctypes.c_char)
    ctermid.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    flockfile = _libraries['FIXME_STUB'].flockfile
    flockfile.restype = None
    flockfile.argtypes = [ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    ftrylockfile = _libraries['FIXME_STUB'].ftrylockfile
    ftrylockfile.restype = ctypes.c_int32
    ftrylockfile.argtypes = [ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    funlockfile = _libraries['FIXME_STUB'].funlockfile
    funlockfile.restype = None
    funlockfile.argtypes = [ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    __uflow = _libraries['FIXME_STUB'].__uflow
    __uflow.restype = ctypes.c_int32
    __uflow.argtypes = [ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    __overflow = _libraries['FIXME_STUB'].__overflow
    __overflow.restype = ctypes.c_int32
    __overflow.argtypes = [ctypes.POINTER(struct__IO_FILE), ctypes.c_int32]
except AttributeError:
    pass
try:
    memcpy = _libraries['FIXME_STUB'].memcpy
    memcpy.restype = ctypes.POINTER(None)
    memcpy.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    memmove = _libraries['FIXME_STUB'].memmove
    memmove.restype = ctypes.POINTER(None)
    memmove.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    memccpy = _libraries['FIXME_STUB'].memccpy
    memccpy.restype = ctypes.POINTER(None)
    memccpy.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None), ctypes.c_int32, size_t]
except AttributeError:
    pass
try:
    memset = _libraries['FIXME_STUB'].memset
    memset.restype = ctypes.POINTER(None)
    memset.argtypes = [ctypes.POINTER(None), ctypes.c_int32, size_t]
except AttributeError:
    pass
try:
    memcmp = _libraries['FIXME_STUB'].memcmp
    memcmp.restype = ctypes.c_int32
    memcmp.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    __memcmpeq = _libraries['FIXME_STUB'].__memcmpeq
    __memcmpeq.restype = ctypes.c_int32
    __memcmpeq.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    memchr = _libraries['FIXME_STUB'].memchr
    memchr.restype = ctypes.POINTER(None)
    memchr.argtypes = [ctypes.POINTER(None), ctypes.c_int32, size_t]
except AttributeError:
    pass
try:
    strcpy = _libraries['FIXME_STUB'].strcpy
    strcpy.restype = ctypes.POINTER(ctypes.c_char)
    strcpy.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    strncpy = _libraries['FIXME_STUB'].strncpy
    strncpy.restype = ctypes.POINTER(ctypes.c_char)
    strncpy.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    strcat = _libraries['FIXME_STUB'].strcat
    strcat.restype = ctypes.POINTER(ctypes.c_char)
    strcat.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    strncat = _libraries['FIXME_STUB'].strncat
    strncat.restype = ctypes.POINTER(ctypes.c_char)
    strncat.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    strcmp = _libraries['FIXME_STUB'].strcmp
    strcmp.restype = ctypes.c_int32
    strcmp.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    strncmp = _libraries['FIXME_STUB'].strncmp
    strncmp.restype = ctypes.c_int32
    strncmp.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    strcoll = _libraries['FIXME_STUB'].strcoll
    strcoll.restype = ctypes.c_int32
    strcoll.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    strxfrm = _libraries['FIXME_STUB'].strxfrm
    strxfrm.restype = ctypes.c_uint64
    strxfrm.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    strcoll_l = _libraries['FIXME_STUB'].strcoll_l
    strcoll_l.restype = ctypes.c_int32
    strcoll_l.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), locale_t]
except AttributeError:
    pass
try:
    strxfrm_l = _libraries['FIXME_STUB'].strxfrm_l
    strxfrm_l.restype = size_t
    strxfrm_l.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), size_t, locale_t]
except AttributeError:
    pass
try:
    strdup = _libraries['FIXME_STUB'].strdup
    strdup.restype = ctypes.POINTER(ctypes.c_char)
    strdup.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    strndup = _libraries['FIXME_STUB'].strndup
    strndup.restype = ctypes.POINTER(ctypes.c_char)
    strndup.argtypes = [ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    strchr = _libraries['FIXME_STUB'].strchr
    strchr.restype = ctypes.POINTER(ctypes.c_char)
    strchr.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    strrchr = _libraries['FIXME_STUB'].strrchr
    strrchr.restype = ctypes.POINTER(ctypes.c_char)
    strrchr.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    strchrnul = _libraries['FIXME_STUB'].strchrnul
    strchrnul.restype = ctypes.POINTER(ctypes.c_char)
    strchrnul.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    strcspn = _libraries['FIXME_STUB'].strcspn
    strcspn.restype = ctypes.c_uint64
    strcspn.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    strspn = _libraries['FIXME_STUB'].strspn
    strspn.restype = ctypes.c_uint64
    strspn.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    strpbrk = _libraries['FIXME_STUB'].strpbrk
    strpbrk.restype = ctypes.POINTER(ctypes.c_char)
    strpbrk.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    strstr = _libraries['FIXME_STUB'].strstr
    strstr.restype = ctypes.POINTER(ctypes.c_char)
    strstr.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    strtok = _libraries['FIXME_STUB'].strtok
    strtok.restype = ctypes.POINTER(ctypes.c_char)
    strtok.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    __strtok_r = _libraries['FIXME_STUB'].__strtok_r
    __strtok_r.restype = ctypes.POINTER(ctypes.c_char)
    __strtok_r.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
except AttributeError:
    pass
try:
    strtok_r = _libraries['FIXME_STUB'].strtok_r
    strtok_r.restype = ctypes.POINTER(ctypes.c_char)
    strtok_r.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
except AttributeError:
    pass
try:
    strcasestr = _libraries['FIXME_STUB'].strcasestr
    strcasestr.restype = ctypes.POINTER(ctypes.c_char)
    strcasestr.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    memmem = _libraries['FIXME_STUB'].memmem
    memmem.restype = ctypes.POINTER(None)
    memmem.argtypes = [ctypes.POINTER(None), size_t, ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    __mempcpy = _libraries['FIXME_STUB'].__mempcpy
    __mempcpy.restype = ctypes.POINTER(None)
    __mempcpy.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    mempcpy = _libraries['FIXME_STUB'].mempcpy
    mempcpy.restype = ctypes.POINTER(None)
    mempcpy.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    strlen = _libraries['FIXME_STUB'].strlen
    strlen.restype = ctypes.c_uint64
    strlen.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    strnlen = _libraries['FIXME_STUB'].strnlen
    strnlen.restype = size_t
    strnlen.argtypes = [ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    strerror = _libraries['FIXME_STUB'].strerror
    strerror.restype = ctypes.POINTER(ctypes.c_char)
    strerror.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    strerror_r = _libraries['FIXME_STUB'].strerror_r
    strerror_r.restype = ctypes.c_int32
    strerror_r.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    strerror_l = _libraries['FIXME_STUB'].strerror_l
    strerror_l.restype = ctypes.POINTER(ctypes.c_char)
    strerror_l.argtypes = [ctypes.c_int32, locale_t]
except AttributeError:
    pass
try:
    bcmp = _libraries['FIXME_STUB'].bcmp
    bcmp.restype = ctypes.c_int32
    bcmp.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    bcopy = _libraries['FIXME_STUB'].bcopy
    bcopy.restype = None
    bcopy.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    bzero = _libraries['FIXME_STUB'].bzero
    bzero.restype = None
    bzero.argtypes = [ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    index = _libraries['FIXME_STUB'].index
    index.restype = ctypes.POINTER(ctypes.c_char)
    index.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    rindex = _libraries['FIXME_STUB'].rindex
    rindex.restype = ctypes.POINTER(ctypes.c_char)
    rindex.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    ffs = _libraries['FIXME_STUB'].ffs
    ffs.restype = ctypes.c_int32
    ffs.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    ffsl = _libraries['FIXME_STUB'].ffsl
    ffsl.restype = ctypes.c_int32
    ffsl.argtypes = [ctypes.c_int64]
except AttributeError:
    pass
try:
    ffsll = _libraries['FIXME_STUB'].ffsll
    ffsll.restype = ctypes.c_int32
    ffsll.argtypes = [ctypes.c_int64]
except AttributeError:
    pass
try:
    strcasecmp = _libraries['FIXME_STUB'].strcasecmp
    strcasecmp.restype = ctypes.c_int32
    strcasecmp.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    strncasecmp = _libraries['FIXME_STUB'].strncasecmp
    strncasecmp.restype = ctypes.c_int32
    strncasecmp.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    strcasecmp_l = _libraries['FIXME_STUB'].strcasecmp_l
    strcasecmp_l.restype = ctypes.c_int32
    strcasecmp_l.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), locale_t]
except AttributeError:
    pass
try:
    strncasecmp_l = _libraries['FIXME_STUB'].strncasecmp_l
    strncasecmp_l.restype = ctypes.c_int32
    strncasecmp_l.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), size_t, locale_t]
except AttributeError:
    pass
try:
    explicit_bzero = _libraries['FIXME_STUB'].explicit_bzero
    explicit_bzero.restype = None
    explicit_bzero.argtypes = [ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    strsep = _libraries['FIXME_STUB'].strsep
    strsep.restype = ctypes.POINTER(ctypes.c_char)
    strsep.argtypes = [ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    strsignal = _libraries['FIXME_STUB'].strsignal
    strsignal.restype = ctypes.POINTER(ctypes.c_char)
    strsignal.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    __stpcpy = _libraries['FIXME_STUB'].__stpcpy
    __stpcpy.restype = ctypes.POINTER(ctypes.c_char)
    __stpcpy.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    stpcpy = _libraries['FIXME_STUB'].stpcpy
    stpcpy.restype = ctypes.POINTER(ctypes.c_char)
    stpcpy.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    __stpncpy = _libraries['FIXME_STUB'].__stpncpy
    __stpncpy.restype = ctypes.POINTER(ctypes.c_char)
    __stpncpy.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    stpncpy = _libraries['FIXME_STUB'].stpncpy
    stpncpy.restype = ctypes.POINTER(ctypes.c_char)
    stpncpy.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    strlcpy = _libraries['FIXME_STUB'].strlcpy
    strlcpy.restype = size_t
    strlcpy.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    strlcat = _libraries['FIXME_STUB'].strlcat
    strlcat.restype = size_t
    strlcat.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
class struct_flock(Structure):
    pass

struct_flock._pack_ = 1 # source:False
struct_flock._fields_ = [
    ('l_type', ctypes.c_int16),
    ('l_whence', ctypes.c_int16),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('l_start', ctypes.c_int64),
    ('l_len', ctypes.c_int64),
    ('l_pid', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
]

class struct_stat(Structure):
    pass

struct_stat._pack_ = 1 # source:False
struct_stat._fields_ = [
    ('st_dev', ctypes.c_uint64),
    ('st_ino', ctypes.c_uint64),
    ('st_nlink', ctypes.c_uint64),
    ('st_mode', ctypes.c_uint32),
    ('st_uid', ctypes.c_uint32),
    ('st_gid', ctypes.c_uint32),
    ('__pad0', ctypes.c_int32),
    ('st_rdev', ctypes.c_uint64),
    ('st_size', ctypes.c_int64),
    ('st_blksize', ctypes.c_int64),
    ('st_blocks', ctypes.c_int64),
    ('st_atim', struct_timespec),
    ('st_mtim', struct_timespec),
    ('st_ctim', struct_timespec),
    ('__glibc_reserved', ctypes.c_int64 * 3),
]

try:
    fcntl = _libraries['FIXME_STUB'].fcntl
    fcntl.restype = ctypes.c_int32
    fcntl.argtypes = [ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    open = _libraries['FIXME_STUB'].open
    open.restype = ctypes.c_int32
    open.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    openat = _libraries['FIXME_STUB'].openat
    openat.restype = ctypes.c_int32
    openat.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    creat = _libraries['FIXME_STUB'].creat
    creat.restype = ctypes.c_int32
    creat.argtypes = [ctypes.POINTER(ctypes.c_char), mode_t]
except AttributeError:
    pass
try:
    lockf = _libraries['FIXME_STUB'].lockf
    lockf.restype = ctypes.c_int32
    lockf.argtypes = [ctypes.c_int32, ctypes.c_int32, __off64_t]
except AttributeError:
    pass
try:
    posix_fadvise = _libraries['FIXME_STUB'].posix_fadvise
    posix_fadvise.restype = ctypes.c_int32
    posix_fadvise.argtypes = [ctypes.c_int32, __off64_t, __off64_t, ctypes.c_int32]
except AttributeError:
    pass
try:
    posix_fallocate = _libraries['FIXME_STUB'].posix_fallocate
    posix_fallocate.restype = ctypes.c_int32
    posix_fallocate.argtypes = [ctypes.c_int32, __off64_t, __off64_t]
except AttributeError:
    pass
try:
    r_read_ble8 = _libraries['FIXME_STUB'].r_read_ble8
    r_read_ble8.restype = uint8_t
    r_read_ble8.argtypes = [ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_read_at_ble8 = _libraries['FIXME_STUB'].r_read_at_ble8
    r_read_at_ble8.restype = uint8_t
    r_read_at_ble8.argtypes = [ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    r_write_ble8 = _libraries['FIXME_STUB'].r_write_ble8
    r_write_ble8.restype = None
    r_write_ble8.argtypes = [ctypes.POINTER(None), uint8_t]
except AttributeError:
    pass
try:
    r_write_at_ble8 = _libraries['FIXME_STUB'].r_write_at_ble8
    r_write_at_ble8.restype = None
    r_write_at_ble8.argtypes = [ctypes.POINTER(None), uint8_t, size_t]
except AttributeError:
    pass
try:
    r_read_be8 = _libraries['FIXME_STUB'].r_read_be8
    r_read_be8.restype = uint8_t
    r_read_be8.argtypes = [ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_read_at_be8 = _libraries['FIXME_STUB'].r_read_at_be8
    r_read_at_be8.restype = uint8_t
    r_read_at_be8.argtypes = [ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    r_write_be8 = _libraries['FIXME_STUB'].r_write_be8
    r_write_be8.restype = None
    r_write_be8.argtypes = [ctypes.POINTER(None), uint8_t]
except AttributeError:
    pass
try:
    r_write_at_be8 = _libraries['FIXME_STUB'].r_write_at_be8
    r_write_at_be8.restype = None
    r_write_at_be8.argtypes = [ctypes.POINTER(None), uint8_t, size_t]
except AttributeError:
    pass
try:
    r_read_be16 = _libraries['FIXME_STUB'].r_read_be16
    r_read_be16.restype = uint16_t
    r_read_be16.argtypes = [ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_read_at_be16 = _libraries['FIXME_STUB'].r_read_at_be16
    r_read_at_be16.restype = uint16_t
    r_read_at_be16.argtypes = [ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    r_write_be16 = _libraries['FIXME_STUB'].r_write_be16
    r_write_be16.restype = None
    r_write_be16.argtypes = [ctypes.POINTER(None), uint16_t]
except AttributeError:
    pass
try:
    r_write_at_be16 = _libraries['FIXME_STUB'].r_write_at_be16
    r_write_at_be16.restype = None
    r_write_at_be16.argtypes = [ctypes.POINTER(None), uint16_t, size_t]
except AttributeError:
    pass
try:
    r_read_be32 = _libraries['FIXME_STUB'].r_read_be32
    r_read_be32.restype = uint32_t
    r_read_be32.argtypes = [ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_read_at_be32 = _libraries['FIXME_STUB'].r_read_at_be32
    r_read_at_be32.restype = uint32_t
    r_read_at_be32.argtypes = [ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    r_write_be32 = _libraries['FIXME_STUB'].r_write_be32
    r_write_be32.restype = None
    r_write_be32.argtypes = [ctypes.POINTER(None), uint32_t]
except AttributeError:
    pass
try:
    r_write_be24 = _libraries['FIXME_STUB'].r_write_be24
    r_write_be24.restype = None
    r_write_be24.argtypes = [ctypes.POINTER(None), uint32_t]
except AttributeError:
    pass
try:
    r_write_at_be32 = _libraries['FIXME_STUB'].r_write_at_be32
    r_write_at_be32.restype = None
    r_write_at_be32.argtypes = [ctypes.POINTER(None), uint32_t, size_t]
except AttributeError:
    pass
try:
    r_read_be64 = _libraries['FIXME_STUB'].r_read_be64
    r_read_be64.restype = uint64_t
    r_read_be64.argtypes = [ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_read_at_be64 = _libraries['FIXME_STUB'].r_read_at_be64
    r_read_at_be64.restype = uint64_t
    r_read_at_be64.argtypes = [ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    r_write_be64 = _libraries['FIXME_STUB'].r_write_be64
    r_write_be64.restype = None
    r_write_be64.argtypes = [ctypes.POINTER(None), uint64_t]
except AttributeError:
    pass
try:
    r_write_at_be64 = _libraries['FIXME_STUB'].r_write_at_be64
    r_write_at_be64.restype = None
    r_write_at_be64.argtypes = [ctypes.POINTER(None), uint64_t, size_t]
except AttributeError:
    pass
try:
    r_read_le8 = _libraries['FIXME_STUB'].r_read_le8
    r_read_le8.restype = uint8_t
    r_read_le8.argtypes = [ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_read_at_le8 = _libraries['FIXME_STUB'].r_read_at_le8
    r_read_at_le8.restype = uint8_t
    r_read_at_le8.argtypes = [ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    r_write_le8 = _libraries['FIXME_STUB'].r_write_le8
    r_write_le8.restype = None
    r_write_le8.argtypes = [ctypes.POINTER(None), uint8_t]
except AttributeError:
    pass
try:
    r_write_at_le8 = _libraries['FIXME_STUB'].r_write_at_le8
    r_write_at_le8.restype = None
    r_write_at_le8.argtypes = [ctypes.POINTER(None), uint8_t, size_t]
except AttributeError:
    pass
try:
    r_read_le16 = _libraries['FIXME_STUB'].r_read_le16
    r_read_le16.restype = uint16_t
    r_read_le16.argtypes = [ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_read_at_le16 = _libraries['FIXME_STUB'].r_read_at_le16
    r_read_at_le16.restype = uint16_t
    r_read_at_le16.argtypes = [ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    r_write_le16 = _libraries['FIXME_STUB'].r_write_le16
    r_write_le16.restype = None
    r_write_le16.argtypes = [ctypes.POINTER(None), uint16_t]
except AttributeError:
    pass
try:
    r_write_at_le16 = _libraries['FIXME_STUB'].r_write_at_le16
    r_write_at_le16.restype = None
    r_write_at_le16.argtypes = [ctypes.POINTER(None), uint16_t, size_t]
except AttributeError:
    pass
try:
    r_write_le24 = _libraries['FIXME_STUB'].r_write_le24
    r_write_le24.restype = None
    r_write_le24.argtypes = [ctypes.POINTER(None), uint32_t]
except AttributeError:
    pass
try:
    r_read_le32 = _libraries['FIXME_STUB'].r_read_le32
    r_read_le32.restype = uint32_t
    r_read_le32.argtypes = [ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_read_at_le32 = _libraries['FIXME_STUB'].r_read_at_le32
    r_read_at_le32.restype = uint32_t
    r_read_at_le32.argtypes = [ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    r_write_le32 = _libraries['FIXME_STUB'].r_write_le32
    r_write_le32.restype = None
    r_write_le32.argtypes = [ctypes.POINTER(None), uint32_t]
except AttributeError:
    pass
try:
    r_write_at_le32 = _libraries['FIXME_STUB'].r_write_at_le32
    r_write_at_le32.restype = None
    r_write_at_le32.argtypes = [ctypes.POINTER(None), uint32_t, size_t]
except AttributeError:
    pass
try:
    r_read_le64 = _libraries['FIXME_STUB'].r_read_le64
    r_read_le64.restype = uint64_t
    r_read_le64.argtypes = [ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_read_at_le64 = _libraries['FIXME_STUB'].r_read_at_le64
    r_read_at_le64.restype = uint64_t
    r_read_at_le64.argtypes = [ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    r_write_le64 = _libraries['FIXME_STUB'].r_write_le64
    r_write_le64.restype = None
    r_write_le64.argtypes = [ctypes.POINTER(None), uint64_t]
except AttributeError:
    pass
try:
    r_write_at_le64 = _libraries['FIXME_STUB'].r_write_at_le64
    r_write_at_le64.restype = None
    r_write_at_le64.argtypes = [ctypes.POINTER(None), uint64_t, size_t]
except AttributeError:
    pass
try:
    r_read_me8 = _libraries['FIXME_STUB'].r_read_me8
    r_read_me8.restype = uint8_t
    r_read_me8.argtypes = [ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_read_at_me8 = _libraries['FIXME_STUB'].r_read_at_me8
    r_read_at_me8.restype = uint8_t
    r_read_at_me8.argtypes = [ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    r_write_me8 = _libraries['FIXME_STUB'].r_write_me8
    r_write_me8.restype = None
    r_write_me8.argtypes = [ctypes.POINTER(None), uint8_t]
except AttributeError:
    pass
try:
    r_write_at_me8 = _libraries['FIXME_STUB'].r_write_at_me8
    r_write_at_me8.restype = None
    r_write_at_me8.argtypes = [ctypes.POINTER(None), uint8_t, size_t]
except AttributeError:
    pass
try:
    r_read_me16 = _libraries['FIXME_STUB'].r_read_me16
    r_read_me16.restype = uint16_t
    r_read_me16.argtypes = [ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_read_at_me16 = _libraries['FIXME_STUB'].r_read_at_me16
    r_read_at_me16.restype = uint16_t
    r_read_at_me16.argtypes = [ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    r_write_me16 = _libraries['FIXME_STUB'].r_write_me16
    r_write_me16.restype = None
    r_write_me16.argtypes = [ctypes.POINTER(None), uint16_t]
except AttributeError:
    pass
try:
    r_write_at_me16 = _libraries['FIXME_STUB'].r_write_at_me16
    r_write_at_me16.restype = None
    r_write_at_me16.argtypes = [ctypes.POINTER(None), uint16_t, size_t]
except AttributeError:
    pass
try:
    r_read_me32 = _libraries['FIXME_STUB'].r_read_me32
    r_read_me32.restype = uint32_t
    r_read_me32.argtypes = [ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_read_at_me32 = _libraries['FIXME_STUB'].r_read_at_me32
    r_read_at_me32.restype = uint32_t
    r_read_at_me32.argtypes = [ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    r_write_me32 = _libraries['FIXME_STUB'].r_write_me32
    r_write_me32.restype = None
    r_write_me32.argtypes = [ctypes.POINTER(None), uint32_t]
except AttributeError:
    pass
try:
    r_write_at_me32 = _libraries['FIXME_STUB'].r_write_at_me32
    r_write_at_me32.restype = None
    r_write_at_me32.argtypes = [ctypes.POINTER(None), uint32_t, size_t]
except AttributeError:
    pass
try:
    r_read_me64 = _libraries['FIXME_STUB'].r_read_me64
    r_read_me64.restype = uint64_t
    r_read_me64.argtypes = [ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_read_at_me64 = _libraries['FIXME_STUB'].r_read_at_me64
    r_read_at_me64.restype = uint64_t
    r_read_at_me64.argtypes = [ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    r_write_me64 = _libraries['FIXME_STUB'].r_write_me64
    r_write_me64.restype = None
    r_write_me64.argtypes = [ctypes.POINTER(None), uint64_t]
except AttributeError:
    pass
try:
    r_write_at_me64 = _libraries['FIXME_STUB'].r_write_at_me64
    r_write_at_me64.restype = None
    r_write_at_me64.argtypes = [ctypes.POINTER(None), uint64_t, size_t]
except AttributeError:
    pass
try:
    r_read_ble16 = _libraries['FIXME_STUB'].r_read_ble16
    r_read_ble16.restype = uint16_t
    r_read_ble16.argtypes = [ctypes.POINTER(None), ctypes.c_bool]
except AttributeError:
    pass
try:
    r_read_ble32 = _libraries['FIXME_STUB'].r_read_ble32
    r_read_ble32.restype = uint32_t
    r_read_ble32.argtypes = [ctypes.POINTER(None), ctypes.c_bool]
except AttributeError:
    pass
try:
    r_read_ble64 = _libraries['FIXME_STUB'].r_read_ble64
    r_read_ble64.restype = uint64_t
    r_read_ble64.argtypes = [ctypes.POINTER(None), ctypes.c_bool]
except AttributeError:
    pass
try:
    r_read_at_ble16 = _libraries['FIXME_STUB'].r_read_at_ble16
    r_read_at_ble16.restype = uint16_t
    r_read_at_ble16.argtypes = [ctypes.POINTER(None), size_t, ctypes.c_bool]
except AttributeError:
    pass
try:
    r_read_at_ble32 = _libraries['FIXME_STUB'].r_read_at_ble32
    r_read_at_ble32.restype = uint32_t
    r_read_at_ble32.argtypes = [ctypes.POINTER(None), size_t, ctypes.c_bool]
except AttributeError:
    pass
try:
    r_read_at_ble64 = _libraries['FIXME_STUB'].r_read_at_ble64
    r_read_at_ble64.restype = uint64_t
    r_read_at_ble64.argtypes = [ctypes.POINTER(None), size_t, ctypes.c_bool]
except AttributeError:
    pass
try:
    r_read_ble = _libraries['FIXME_STUB'].r_read_ble
    r_read_ble.restype = uint64_t
    r_read_ble.argtypes = [ctypes.POINTER(None), ctypes.c_bool, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_write_ble16 = _libraries['FIXME_STUB'].r_write_ble16
    r_write_ble16.restype = None
    r_write_ble16.argtypes = [ctypes.POINTER(None), uint16_t, ctypes.c_bool]
except AttributeError:
    pass
try:
    r_write_ble24 = _libraries['FIXME_STUB'].r_write_ble24
    r_write_ble24.restype = None
    r_write_ble24.argtypes = [ctypes.POINTER(None), uint32_t, ctypes.c_bool]
except AttributeError:
    pass
try:
    r_write_ble32 = _libraries['FIXME_STUB'].r_write_ble32
    r_write_ble32.restype = None
    r_write_ble32.argtypes = [ctypes.POINTER(None), uint32_t, ctypes.c_bool]
except AttributeError:
    pass
try:
    r_write_ble64 = _libraries['FIXME_STUB'].r_write_ble64
    r_write_ble64.restype = None
    r_write_ble64.argtypes = [ctypes.POINTER(None), uint64_t, ctypes.c_bool]
except AttributeError:
    pass
try:
    r_write_ble = _libraries['FIXME_STUB'].r_write_ble
    r_write_ble.restype = None
    r_write_ble.argtypes = [ctypes.POINTER(None), uint64_t, ctypes.c_bool, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_swap_ut16 = _libraries['FIXME_STUB'].r_swap_ut16
    r_swap_ut16.restype = uint16_t
    r_swap_ut16.argtypes = [uint16_t]
except AttributeError:
    pass
try:
    r_swap_st16 = _libraries['FIXME_STUB'].r_swap_st16
    r_swap_st16.restype = int16_t
    r_swap_st16.argtypes = [int16_t]
except AttributeError:
    pass
try:
    r_swap_ut32 = _libraries['FIXME_STUB'].r_swap_ut32
    r_swap_ut32.restype = uint32_t
    r_swap_ut32.argtypes = [uint32_t]
except AttributeError:
    pass
try:
    r_swap_st32 = _libraries['FIXME_STUB'].r_swap_st32
    r_swap_st32.restype = int32_t
    r_swap_st32.argtypes = [int32_t]
except AttributeError:
    pass
try:
    r_swap_ut64 = _libraries['FIXME_STUB'].r_swap_ut64
    r_swap_ut64.restype = uint64_t
    r_swap_ut64.argtypes = [uint64_t]
except AttributeError:
    pass
try:
    r_swap_st64 = _libraries['FIXME_STUB'].r_swap_st64
    r_swap_st64.restype = int64_t
    r_swap_st64.argtypes = [int64_t]
except AttributeError:
    pass
try:
    UT64_ADD = _libraries['FIXME_STUB'].UT64_ADD
    UT64_ADD.restype = ctypes.c_int32
    UT64_ADD.argtypes = [ctypes.POINTER(ctypes.c_uint64), uint64_t, uint64_t]
except AttributeError:
    pass
try:
    UT64_MUL = _libraries['FIXME_STUB'].UT64_MUL
    UT64_MUL.restype = ctypes.c_int32
    UT64_MUL.argtypes = [ctypes.POINTER(ctypes.c_uint64), uint64_t, uint64_t]
except AttributeError:
    pass
try:
    UT64_SUB = _libraries['FIXME_STUB'].UT64_SUB
    UT64_SUB.restype = ctypes.c_int32
    UT64_SUB.argtypes = [ctypes.POINTER(ctypes.c_uint64), uint64_t, uint64_t]
except AttributeError:
    pass
try:
    UT32_ADD = _libraries['FIXME_STUB'].UT32_ADD
    UT32_ADD.restype = ctypes.c_int32
    UT32_ADD.argtypes = [ctypes.POINTER(ctypes.c_uint32), uint32_t, uint32_t]
except AttributeError:
    pass
try:
    UT32_MUL = _libraries['FIXME_STUB'].UT32_MUL
    UT32_MUL.restype = ctypes.c_int32
    UT32_MUL.argtypes = [ctypes.POINTER(ctypes.c_uint32), uint32_t, uint32_t]
except AttributeError:
    pass
try:
    UT32_SUB = _libraries['FIXME_STUB'].UT32_SUB
    UT32_SUB.restype = ctypes.c_int32
    UT32_SUB.argtypes = [ctypes.POINTER(ctypes.c_uint32), uint32_t, uint32_t]
except AttributeError:
    pass
try:
    UT16_ADD = _libraries['FIXME_STUB'].UT16_ADD
    UT16_ADD.restype = ctypes.c_int32
    UT16_ADD.argtypes = [ctypes.POINTER(ctypes.c_uint16), uint16_t, uint16_t]
except AttributeError:
    pass
try:
    UT16_MUL = _libraries['FIXME_STUB'].UT16_MUL
    UT16_MUL.restype = ctypes.c_int32
    UT16_MUL.argtypes = [ctypes.POINTER(ctypes.c_uint16), uint16_t, uint16_t]
except AttributeError:
    pass
try:
    UT16_SUB = _libraries['FIXME_STUB'].UT16_SUB
    UT16_SUB.restype = ctypes.c_int32
    UT16_SUB.argtypes = [ctypes.POINTER(ctypes.c_uint16), uint16_t, uint16_t]
except AttributeError:
    pass
try:
    UT8_ADD = _libraries['FIXME_STUB'].UT8_ADD
    UT8_ADD.restype = ctypes.c_int32
    UT8_ADD.argtypes = [ctypes.POINTER(ctypes.c_ubyte), uint8_t, uint8_t]
except AttributeError:
    pass
try:
    UT8_MUL = _libraries['FIXME_STUB'].UT8_MUL
    UT8_MUL.restype = ctypes.c_int32
    UT8_MUL.argtypes = [ctypes.POINTER(ctypes.c_ubyte), uint8_t, uint8_t]
except AttributeError:
    pass
try:
    UT8_SUB = _libraries['FIXME_STUB'].UT8_SUB
    UT8_SUB.restype = ctypes.c_int32
    UT8_SUB.argtypes = [ctypes.POINTER(ctypes.c_ubyte), uint8_t, uint8_t]
except AttributeError:
    pass
PrintfCallback = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_char))
try:
    r_new_copy = _libraries['FIXME_STUB'].r_new_copy
    r_new_copy.restype = ctypes.POINTER(None)
    r_new_copy.argtypes = [ctypes.c_int32, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    stat = _libraries['FIXME_STUB'].stat
    stat.restype = ctypes.c_int32
    stat.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_stat)]
except AttributeError:
    pass
try:
    fstat = _libraries['FIXME_STUB'].fstat
    fstat.restype = ctypes.c_int32
    fstat.argtypes = [ctypes.c_int32, ctypes.POINTER(struct_stat)]
except AttributeError:
    pass
try:
    fstatat = _libraries['FIXME_STUB'].fstatat
    fstatat.restype = ctypes.c_int32
    fstatat.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_stat), ctypes.c_int32]
except AttributeError:
    pass
try:
    lstat = _libraries['FIXME_STUB'].lstat
    lstat.restype = ctypes.c_int32
    lstat.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_stat)]
except AttributeError:
    pass
try:
    chmod = _libraries['FIXME_STUB'].chmod
    chmod.restype = ctypes.c_int32
    chmod.argtypes = [ctypes.POINTER(ctypes.c_char), __mode_t]
except AttributeError:
    pass
try:
    lchmod = _libraries['FIXME_STUB'].lchmod
    lchmod.restype = ctypes.c_int32
    lchmod.argtypes = [ctypes.POINTER(ctypes.c_char), __mode_t]
except AttributeError:
    pass
try:
    fchmod = _libraries['FIXME_STUB'].fchmod
    fchmod.restype = ctypes.c_int32
    fchmod.argtypes = [ctypes.c_int32, __mode_t]
except AttributeError:
    pass
try:
    fchmodat = _libraries['FIXME_STUB'].fchmodat
    fchmodat.restype = ctypes.c_int32
    fchmodat.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char), __mode_t, ctypes.c_int32]
except AttributeError:
    pass
try:
    umask = _libraries['FIXME_STUB'].umask
    umask.restype = __mode_t
    umask.argtypes = [__mode_t]
except AttributeError:
    pass
try:
    mkdir = _libraries['FIXME_STUB'].mkdir
    mkdir.restype = ctypes.c_int32
    mkdir.argtypes = [ctypes.POINTER(ctypes.c_char), __mode_t]
except AttributeError:
    pass
try:
    mkdirat = _libraries['FIXME_STUB'].mkdirat
    mkdirat.restype = ctypes.c_int32
    mkdirat.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char), __mode_t]
except AttributeError:
    pass
try:
    mknod = _libraries['FIXME_STUB'].mknod
    mknod.restype = ctypes.c_int32
    mknod.argtypes = [ctypes.POINTER(ctypes.c_char), __mode_t, __dev_t]
except AttributeError:
    pass
try:
    mknodat = _libraries['FIXME_STUB'].mknodat
    mknodat.restype = ctypes.c_int32
    mknodat.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char), __mode_t, __dev_t]
except AttributeError:
    pass
try:
    mkfifo = _libraries['FIXME_STUB'].mkfifo
    mkfifo.restype = ctypes.c_int32
    mkfifo.argtypes = [ctypes.POINTER(ctypes.c_char), __mode_t]
except AttributeError:
    pass
try:
    mkfifoat = _libraries['FIXME_STUB'].mkfifoat
    mkfifoat.restype = ctypes.c_int32
    mkfifoat.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char), __mode_t]
except AttributeError:
    pass
try:
    utimensat = _libraries['FIXME_STUB'].utimensat
    utimensat.restype = ctypes.c_int32
    utimensat.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char), struct_timespec * 2, ctypes.c_int32]
except AttributeError:
    pass
try:
    futimens = _libraries['FIXME_STUB'].futimens
    futimens.restype = ctypes.c_int32
    futimens.argtypes = [ctypes.c_int32, struct_timespec * 2]
except AttributeError:
    pass
class struct_dirent(Structure):
    pass

struct_dirent._pack_ = 1 # source:False
struct_dirent._fields_ = [
    ('d_ino', ctypes.c_uint64),
    ('d_off', ctypes.c_int64),
    ('d_reclen', ctypes.c_uint16),
    ('d_type', ctypes.c_ubyte),
    ('d_name', ctypes.c_char * 256),
    ('PADDING_0', ctypes.c_ubyte * 5),
]


# values for enumeration 'c__Ea_DT_UNKNOWN'
c__Ea_DT_UNKNOWN__enumvalues = {
    0: 'DT_UNKNOWN',
    1: 'DT_FIFO',
    2: 'DT_CHR',
    4: 'DT_DIR',
    6: 'DT_BLK',
    8: 'DT_REG',
    10: 'DT_LNK',
    12: 'DT_SOCK',
    14: 'DT_WHT',
}
DT_UNKNOWN = 0
DT_FIFO = 1
DT_CHR = 2
DT_DIR = 4
DT_BLK = 6
DT_REG = 8
DT_LNK = 10
DT_SOCK = 12
DT_WHT = 14
c__Ea_DT_UNKNOWN = ctypes.c_uint32 # enum
class struct___dirstream(Structure):
    pass

DIR = struct___dirstream
try:
    closedir = _libraries['FIXME_STUB'].closedir
    closedir.restype = ctypes.c_int32
    closedir.argtypes = [ctypes.POINTER(struct___dirstream)]
except AttributeError:
    pass
try:
    opendir = _libraries['FIXME_STUB'].opendir
    opendir.restype = ctypes.POINTER(struct___dirstream)
    opendir.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    fdopendir = _libraries['FIXME_STUB'].fdopendir
    fdopendir.restype = ctypes.POINTER(struct___dirstream)
    fdopendir.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    readdir = _libraries['FIXME_STUB'].readdir
    readdir.restype = ctypes.POINTER(struct_dirent)
    readdir.argtypes = [ctypes.POINTER(struct___dirstream)]
except AttributeError:
    pass
try:
    readdir_r = _libraries['FIXME_STUB'].readdir_r
    readdir_r.restype = ctypes.c_int32
    readdir_r.argtypes = [ctypes.POINTER(struct___dirstream), ctypes.POINTER(struct_dirent), ctypes.POINTER(ctypes.POINTER(struct_dirent))]
except AttributeError:
    pass
try:
    rewinddir = _libraries['FIXME_STUB'].rewinddir
    rewinddir.restype = None
    rewinddir.argtypes = [ctypes.POINTER(struct___dirstream)]
except AttributeError:
    pass
try:
    seekdir = _libraries['FIXME_STUB'].seekdir
    seekdir.restype = None
    seekdir.argtypes = [ctypes.POINTER(struct___dirstream), ctypes.c_int64]
except AttributeError:
    pass
try:
    telldir = _libraries['FIXME_STUB'].telldir
    telldir.restype = ctypes.c_int64
    telldir.argtypes = [ctypes.POINTER(struct___dirstream)]
except AttributeError:
    pass
try:
    dirfd = _libraries['FIXME_STUB'].dirfd
    dirfd.restype = ctypes.c_int32
    dirfd.argtypes = [ctypes.POINTER(struct___dirstream)]
except AttributeError:
    pass
try:
    scandir = _libraries['FIXME_STUB'].scandir
    scandir.restype = ctypes.c_int32
    scandir.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.POINTER(ctypes.POINTER(struct_dirent))), ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_dirent)), ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(struct_dirent)), ctypes.POINTER(ctypes.POINTER(struct_dirent)))]
except AttributeError:
    pass
try:
    alphasort = _libraries['FIXME_STUB'].alphasort
    alphasort.restype = ctypes.c_int32
    alphasort.argtypes = [ctypes.POINTER(ctypes.POINTER(struct_dirent)), ctypes.POINTER(ctypes.POINTER(struct_dirent))]
except AttributeError:
    pass
try:
    getdirentries = _libraries['FIXME_STUB'].getdirentries
    getdirentries.restype = __ssize_t
    getdirentries.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(ctypes.c_int64)]
except AttributeError:
    pass
useconds_t = ctypes.c_uint32
socklen_t = ctypes.c_uint32
try:
    access = _libraries['FIXME_STUB'].access
    access.restype = ctypes.c_int32
    access.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    faccessat = _libraries['FIXME_STUB'].faccessat
    faccessat.restype = ctypes.c_int32
    faccessat.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    lseek = _libraries['FIXME_STUB'].lseek
    lseek.restype = __off64_t
    lseek.argtypes = [ctypes.c_int32, __off64_t, ctypes.c_int32]
except AttributeError:
    pass
try:
    close = _libraries['FIXME_STUB'].close
    close.restype = ctypes.c_int32
    close.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    closefrom = _libraries['FIXME_STUB'].closefrom
    closefrom.restype = None
    closefrom.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    read = _libraries['FIXME_STUB'].read
    read.restype = ssize_t
    read.argtypes = [ctypes.c_int32, ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    write = _libraries['FIXME_STUB'].write
    write.restype = ssize_t
    write.argtypes = [ctypes.c_int32, ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    pread = _libraries['FIXME_STUB'].pread
    pread.restype = ssize_t
    pread.argtypes = [ctypes.c_int32, ctypes.POINTER(None), size_t, __off64_t]
except AttributeError:
    pass
try:
    pwrite = _libraries['FIXME_STUB'].pwrite
    pwrite.restype = ssize_t
    pwrite.argtypes = [ctypes.c_int32, ctypes.POINTER(None), size_t, __off64_t]
except AttributeError:
    pass
try:
    pipe = _libraries['FIXME_STUB'].pipe
    pipe.restype = ctypes.c_int32
    pipe.argtypes = [ctypes.c_int32 * 2]
except AttributeError:
    pass
try:
    alarm = _libraries['FIXME_STUB'].alarm
    alarm.restype = ctypes.c_uint32
    alarm.argtypes = [ctypes.c_uint32]
except AttributeError:
    pass
try:
    sleep = _libraries['FIXME_STUB'].sleep
    sleep.restype = ctypes.c_uint32
    sleep.argtypes = [ctypes.c_uint32]
except AttributeError:
    pass
try:
    ualarm = _libraries['FIXME_STUB'].ualarm
    ualarm.restype = __useconds_t
    ualarm.argtypes = [__useconds_t, __useconds_t]
except AttributeError:
    pass
try:
    usleep = _libraries['FIXME_STUB'].usleep
    usleep.restype = ctypes.c_int32
    usleep.argtypes = [__useconds_t]
except AttributeError:
    pass
try:
    pause = _libraries['FIXME_STUB'].pause
    pause.restype = ctypes.c_int32
    pause.argtypes = []
except AttributeError:
    pass
try:
    chown = _libraries['FIXME_STUB'].chown
    chown.restype = ctypes.c_int32
    chown.argtypes = [ctypes.POINTER(ctypes.c_char), __uid_t, __gid_t]
except AttributeError:
    pass
try:
    fchown = _libraries['FIXME_STUB'].fchown
    fchown.restype = ctypes.c_int32
    fchown.argtypes = [ctypes.c_int32, __uid_t, __gid_t]
except AttributeError:
    pass
try:
    lchown = _libraries['FIXME_STUB'].lchown
    lchown.restype = ctypes.c_int32
    lchown.argtypes = [ctypes.POINTER(ctypes.c_char), __uid_t, __gid_t]
except AttributeError:
    pass
try:
    fchownat = _libraries['FIXME_STUB'].fchownat
    fchownat.restype = ctypes.c_int32
    fchownat.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char), __uid_t, __gid_t, ctypes.c_int32]
except AttributeError:
    pass
try:
    chdir = _libraries['FIXME_STUB'].chdir
    chdir.restype = ctypes.c_int32
    chdir.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    fchdir = _libraries['FIXME_STUB'].fchdir
    fchdir.restype = ctypes.c_int32
    fchdir.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    getcwd = _libraries['FIXME_STUB'].getcwd
    getcwd.restype = ctypes.POINTER(ctypes.c_char)
    getcwd.argtypes = [ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    getwd = _libraries['FIXME_STUB'].getwd
    getwd.restype = ctypes.POINTER(ctypes.c_char)
    getwd.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    dup = _libraries['FIXME_STUB'].dup
    dup.restype = ctypes.c_int32
    dup.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    dup2 = _libraries['FIXME_STUB'].dup2
    dup2.restype = ctypes.c_int32
    dup2.argtypes = [ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
__environ = ctypes.POINTER(ctypes.POINTER(ctypes.c_char))() # Variable ctypes.POINTER(ctypes.POINTER(ctypes.c_char))
try:
    execve = _libraries['FIXME_STUB'].execve
    execve.restype = ctypes.c_int32
    execve.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char) * 0, ctypes.POINTER(ctypes.c_char) * 0]
except AttributeError:
    pass
try:
    fexecve = _libraries['FIXME_STUB'].fexecve
    fexecve.restype = ctypes.c_int32
    fexecve.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char) * 0, ctypes.POINTER(ctypes.c_char) * 0]
except AttributeError:
    pass
try:
    execv = _libraries['FIXME_STUB'].execv
    execv.restype = ctypes.c_int32
    execv.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char) * 0]
except AttributeError:
    pass
try:
    execle = _libraries['FIXME_STUB'].execle
    execle.restype = ctypes.c_int32
    execle.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    execl = _libraries['FIXME_STUB'].execl
    execl.restype = ctypes.c_int32
    execl.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    execvp = _libraries['FIXME_STUB'].execvp
    execvp.restype = ctypes.c_int32
    execvp.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char) * 0]
except AttributeError:
    pass
try:
    execlp = _libraries['FIXME_STUB'].execlp
    execlp.restype = ctypes.c_int32
    execlp.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    nice = _libraries['FIXME_STUB'].nice
    nice.restype = ctypes.c_int32
    nice.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    _exit = _libraries['FIXME_STUB']._exit
    _exit.restype = None
    _exit.argtypes = [ctypes.c_int32]
except AttributeError:
    pass

# values for enumeration 'c__Ea__PC_LINK_MAX'
c__Ea__PC_LINK_MAX__enumvalues = {
    0: '_PC_LINK_MAX',
    1: '_PC_MAX_CANON',
    2: '_PC_MAX_INPUT',
    3: '_PC_NAME_MAX',
    4: '_PC_PATH_MAX',
    5: '_PC_PIPE_BUF',
    6: '_PC_CHOWN_RESTRICTED',
    7: '_PC_NO_TRUNC',
    8: '_PC_VDISABLE',
    9: '_PC_SYNC_IO',
    10: '_PC_ASYNC_IO',
    11: '_PC_PRIO_IO',
    12: '_PC_SOCK_MAXBUF',
    13: '_PC_FILESIZEBITS',
    14: '_PC_REC_INCR_XFER_SIZE',
    15: '_PC_REC_MAX_XFER_SIZE',
    16: '_PC_REC_MIN_XFER_SIZE',
    17: '_PC_REC_XFER_ALIGN',
    18: '_PC_ALLOC_SIZE_MIN',
    19: '_PC_SYMLINK_MAX',
    20: '_PC_2_SYMLINKS',
}
_PC_LINK_MAX = 0
_PC_MAX_CANON = 1
_PC_MAX_INPUT = 2
_PC_NAME_MAX = 3
_PC_PATH_MAX = 4
_PC_PIPE_BUF = 5
_PC_CHOWN_RESTRICTED = 6
_PC_NO_TRUNC = 7
_PC_VDISABLE = 8
_PC_SYNC_IO = 9
_PC_ASYNC_IO = 10
_PC_PRIO_IO = 11
_PC_SOCK_MAXBUF = 12
_PC_FILESIZEBITS = 13
_PC_REC_INCR_XFER_SIZE = 14
_PC_REC_MAX_XFER_SIZE = 15
_PC_REC_MIN_XFER_SIZE = 16
_PC_REC_XFER_ALIGN = 17
_PC_ALLOC_SIZE_MIN = 18
_PC_SYMLINK_MAX = 19
_PC_2_SYMLINKS = 20
c__Ea__PC_LINK_MAX = ctypes.c_uint32 # enum

# values for enumeration 'c__Ea__SC_ARG_MAX'
c__Ea__SC_ARG_MAX__enumvalues = {
    0: '_SC_ARG_MAX',
    1: '_SC_CHILD_MAX',
    2: '_SC_CLK_TCK',
    3: '_SC_NGROUPS_MAX',
    4: '_SC_OPEN_MAX',
    5: '_SC_STREAM_MAX',
    6: '_SC_TZNAME_MAX',
    7: '_SC_JOB_CONTROL',
    8: '_SC_SAVED_IDS',
    9: '_SC_REALTIME_SIGNALS',
    10: '_SC_PRIORITY_SCHEDULING',
    11: '_SC_TIMERS',
    12: '_SC_ASYNCHRONOUS_IO',
    13: '_SC_PRIORITIZED_IO',
    14: '_SC_SYNCHRONIZED_IO',
    15: '_SC_FSYNC',
    16: '_SC_MAPPED_FILES',
    17: '_SC_MEMLOCK',
    18: '_SC_MEMLOCK_RANGE',
    19: '_SC_MEMORY_PROTECTION',
    20: '_SC_MESSAGE_PASSING',
    21: '_SC_SEMAPHORES',
    22: '_SC_SHARED_MEMORY_OBJECTS',
    23: '_SC_AIO_LISTIO_MAX',
    24: '_SC_AIO_MAX',
    25: '_SC_AIO_PRIO_DELTA_MAX',
    26: '_SC_DELAYTIMER_MAX',
    27: '_SC_MQ_OPEN_MAX',
    28: '_SC_MQ_PRIO_MAX',
    29: '_SC_VERSION',
    30: '_SC_PAGESIZE',
    31: '_SC_RTSIG_MAX',
    32: '_SC_SEM_NSEMS_MAX',
    33: '_SC_SEM_VALUE_MAX',
    34: '_SC_SIGQUEUE_MAX',
    35: '_SC_TIMER_MAX',
    36: '_SC_BC_BASE_MAX',
    37: '_SC_BC_DIM_MAX',
    38: '_SC_BC_SCALE_MAX',
    39: '_SC_BC_STRING_MAX',
    40: '_SC_COLL_WEIGHTS_MAX',
    41: '_SC_EQUIV_CLASS_MAX',
    42: '_SC_EXPR_NEST_MAX',
    43: '_SC_LINE_MAX',
    44: '_SC_RE_DUP_MAX',
    45: '_SC_CHARCLASS_NAME_MAX',
    46: '_SC_2_VERSION',
    47: '_SC_2_C_BIND',
    48: '_SC_2_C_DEV',
    49: '_SC_2_FORT_DEV',
    50: '_SC_2_FORT_RUN',
    51: '_SC_2_SW_DEV',
    52: '_SC_2_LOCALEDEF',
    53: '_SC_PII',
    54: '_SC_PII_XTI',
    55: '_SC_PII_SOCKET',
    56: '_SC_PII_INTERNET',
    57: '_SC_PII_OSI',
    58: '_SC_POLL',
    59: '_SC_SELECT',
    60: '_SC_UIO_MAXIOV',
    60: '_SC_IOV_MAX',
    61: '_SC_PII_INTERNET_STREAM',
    62: '_SC_PII_INTERNET_DGRAM',
    63: '_SC_PII_OSI_COTS',
    64: '_SC_PII_OSI_CLTS',
    65: '_SC_PII_OSI_M',
    66: '_SC_T_IOV_MAX',
    67: '_SC_THREADS',
    68: '_SC_THREAD_SAFE_FUNCTIONS',
    69: '_SC_GETGR_R_SIZE_MAX',
    70: '_SC_GETPW_R_SIZE_MAX',
    71: '_SC_LOGIN_NAME_MAX',
    72: '_SC_TTY_NAME_MAX',
    73: '_SC_THREAD_DESTRUCTOR_ITERATIONS',
    74: '_SC_THREAD_KEYS_MAX',
    75: '_SC_THREAD_STACK_MIN',
    76: '_SC_THREAD_THREADS_MAX',
    77: '_SC_THREAD_ATTR_STACKADDR',
    78: '_SC_THREAD_ATTR_STACKSIZE',
    79: '_SC_THREAD_PRIORITY_SCHEDULING',
    80: '_SC_THREAD_PRIO_INHERIT',
    81: '_SC_THREAD_PRIO_PROTECT',
    82: '_SC_THREAD_PROCESS_SHARED',
    83: '_SC_NPROCESSORS_CONF',
    84: '_SC_NPROCESSORS_ONLN',
    85: '_SC_PHYS_PAGES',
    86: '_SC_AVPHYS_PAGES',
    87: '_SC_ATEXIT_MAX',
    88: '_SC_PASS_MAX',
    89: '_SC_XOPEN_VERSION',
    90: '_SC_XOPEN_XCU_VERSION',
    91: '_SC_XOPEN_UNIX',
    92: '_SC_XOPEN_CRYPT',
    93: '_SC_XOPEN_ENH_I18N',
    94: '_SC_XOPEN_SHM',
    95: '_SC_2_CHAR_TERM',
    96: '_SC_2_C_VERSION',
    97: '_SC_2_UPE',
    98: '_SC_XOPEN_XPG2',
    99: '_SC_XOPEN_XPG3',
    100: '_SC_XOPEN_XPG4',
    101: '_SC_CHAR_BIT',
    102: '_SC_CHAR_MAX',
    103: '_SC_CHAR_MIN',
    104: '_SC_INT_MAX',
    105: '_SC_INT_MIN',
    106: '_SC_LONG_BIT',
    107: '_SC_WORD_BIT',
    108: '_SC_MB_LEN_MAX',
    109: '_SC_NZERO',
    110: '_SC_SSIZE_MAX',
    111: '_SC_SCHAR_MAX',
    112: '_SC_SCHAR_MIN',
    113: '_SC_SHRT_MAX',
    114: '_SC_SHRT_MIN',
    115: '_SC_UCHAR_MAX',
    116: '_SC_UINT_MAX',
    117: '_SC_ULONG_MAX',
    118: '_SC_USHRT_MAX',
    119: '_SC_NL_ARGMAX',
    120: '_SC_NL_LANGMAX',
    121: '_SC_NL_MSGMAX',
    122: '_SC_NL_NMAX',
    123: '_SC_NL_SETMAX',
    124: '_SC_NL_TEXTMAX',
    125: '_SC_XBS5_ILP32_OFF32',
    126: '_SC_XBS5_ILP32_OFFBIG',
    127: '_SC_XBS5_LP64_OFF64',
    128: '_SC_XBS5_LPBIG_OFFBIG',
    129: '_SC_XOPEN_LEGACY',
    130: '_SC_XOPEN_REALTIME',
    131: '_SC_XOPEN_REALTIME_THREADS',
    132: '_SC_ADVISORY_INFO',
    133: '_SC_BARRIERS',
    134: '_SC_BASE',
    135: '_SC_C_LANG_SUPPORT',
    136: '_SC_C_LANG_SUPPORT_R',
    137: '_SC_CLOCK_SELECTION',
    138: '_SC_CPUTIME',
    139: '_SC_THREAD_CPUTIME',
    140: '_SC_DEVICE_IO',
    141: '_SC_DEVICE_SPECIFIC',
    142: '_SC_DEVICE_SPECIFIC_R',
    143: '_SC_FD_MGMT',
    144: '_SC_FIFO',
    145: '_SC_PIPE',
    146: '_SC_FILE_ATTRIBUTES',
    147: '_SC_FILE_LOCKING',
    148: '_SC_FILE_SYSTEM',
    149: '_SC_MONOTONIC_CLOCK',
    150: '_SC_MULTI_PROCESS',
    151: '_SC_SINGLE_PROCESS',
    152: '_SC_NETWORKING',
    153: '_SC_READER_WRITER_LOCKS',
    154: '_SC_SPIN_LOCKS',
    155: '_SC_REGEXP',
    156: '_SC_REGEX_VERSION',
    157: '_SC_SHELL',
    158: '_SC_SIGNALS',
    159: '_SC_SPAWN',
    160: '_SC_SPORADIC_SERVER',
    161: '_SC_THREAD_SPORADIC_SERVER',
    162: '_SC_SYSTEM_DATABASE',
    163: '_SC_SYSTEM_DATABASE_R',
    164: '_SC_TIMEOUTS',
    165: '_SC_TYPED_MEMORY_OBJECTS',
    166: '_SC_USER_GROUPS',
    167: '_SC_USER_GROUPS_R',
    168: '_SC_2_PBS',
    169: '_SC_2_PBS_ACCOUNTING',
    170: '_SC_2_PBS_LOCATE',
    171: '_SC_2_PBS_MESSAGE',
    172: '_SC_2_PBS_TRACK',
    173: '_SC_SYMLOOP_MAX',
    174: '_SC_STREAMS',
    175: '_SC_2_PBS_CHECKPOINT',
    176: '_SC_V6_ILP32_OFF32',
    177: '_SC_V6_ILP32_OFFBIG',
    178: '_SC_V6_LP64_OFF64',
    179: '_SC_V6_LPBIG_OFFBIG',
    180: '_SC_HOST_NAME_MAX',
    181: '_SC_TRACE',
    182: '_SC_TRACE_EVENT_FILTER',
    183: '_SC_TRACE_INHERIT',
    184: '_SC_TRACE_LOG',
    185: '_SC_LEVEL1_ICACHE_SIZE',
    186: '_SC_LEVEL1_ICACHE_ASSOC',
    187: '_SC_LEVEL1_ICACHE_LINESIZE',
    188: '_SC_LEVEL1_DCACHE_SIZE',
    189: '_SC_LEVEL1_DCACHE_ASSOC',
    190: '_SC_LEVEL1_DCACHE_LINESIZE',
    191: '_SC_LEVEL2_CACHE_SIZE',
    192: '_SC_LEVEL2_CACHE_ASSOC',
    193: '_SC_LEVEL2_CACHE_LINESIZE',
    194: '_SC_LEVEL3_CACHE_SIZE',
    195: '_SC_LEVEL3_CACHE_ASSOC',
    196: '_SC_LEVEL3_CACHE_LINESIZE',
    197: '_SC_LEVEL4_CACHE_SIZE',
    198: '_SC_LEVEL4_CACHE_ASSOC',
    199: '_SC_LEVEL4_CACHE_LINESIZE',
    235: '_SC_IPV6',
    236: '_SC_RAW_SOCKETS',
    237: '_SC_V7_ILP32_OFF32',
    238: '_SC_V7_ILP32_OFFBIG',
    239: '_SC_V7_LP64_OFF64',
    240: '_SC_V7_LPBIG_OFFBIG',
    241: '_SC_SS_REPL_MAX',
    242: '_SC_TRACE_EVENT_NAME_MAX',
    243: '_SC_TRACE_NAME_MAX',
    244: '_SC_TRACE_SYS_MAX',
    245: '_SC_TRACE_USER_EVENT_MAX',
    246: '_SC_XOPEN_STREAMS',
    247: '_SC_THREAD_ROBUST_PRIO_INHERIT',
    248: '_SC_THREAD_ROBUST_PRIO_PROTECT',
    249: '_SC_MINSIGSTKSZ',
    250: '_SC_SIGSTKSZ',
}
_SC_ARG_MAX = 0
_SC_CHILD_MAX = 1
_SC_CLK_TCK = 2
_SC_NGROUPS_MAX = 3
_SC_OPEN_MAX = 4
_SC_STREAM_MAX = 5
_SC_TZNAME_MAX = 6
_SC_JOB_CONTROL = 7
_SC_SAVED_IDS = 8
_SC_REALTIME_SIGNALS = 9
_SC_PRIORITY_SCHEDULING = 10
_SC_TIMERS = 11
_SC_ASYNCHRONOUS_IO = 12
_SC_PRIORITIZED_IO = 13
_SC_SYNCHRONIZED_IO = 14
_SC_FSYNC = 15
_SC_MAPPED_FILES = 16
_SC_MEMLOCK = 17
_SC_MEMLOCK_RANGE = 18
_SC_MEMORY_PROTECTION = 19
_SC_MESSAGE_PASSING = 20
_SC_SEMAPHORES = 21
_SC_SHARED_MEMORY_OBJECTS = 22
_SC_AIO_LISTIO_MAX = 23
_SC_AIO_MAX = 24
_SC_AIO_PRIO_DELTA_MAX = 25
_SC_DELAYTIMER_MAX = 26
_SC_MQ_OPEN_MAX = 27
_SC_MQ_PRIO_MAX = 28
_SC_VERSION = 29
_SC_PAGESIZE = 30
_SC_RTSIG_MAX = 31
_SC_SEM_NSEMS_MAX = 32
_SC_SEM_VALUE_MAX = 33
_SC_SIGQUEUE_MAX = 34
_SC_TIMER_MAX = 35
_SC_BC_BASE_MAX = 36
_SC_BC_DIM_MAX = 37
_SC_BC_SCALE_MAX = 38
_SC_BC_STRING_MAX = 39
_SC_COLL_WEIGHTS_MAX = 40
_SC_EQUIV_CLASS_MAX = 41
_SC_EXPR_NEST_MAX = 42
_SC_LINE_MAX = 43
_SC_RE_DUP_MAX = 44
_SC_CHARCLASS_NAME_MAX = 45
_SC_2_VERSION = 46
_SC_2_C_BIND = 47
_SC_2_C_DEV = 48
_SC_2_FORT_DEV = 49
_SC_2_FORT_RUN = 50
_SC_2_SW_DEV = 51
_SC_2_LOCALEDEF = 52
_SC_PII = 53
_SC_PII_XTI = 54
_SC_PII_SOCKET = 55
_SC_PII_INTERNET = 56
_SC_PII_OSI = 57
_SC_POLL = 58
_SC_SELECT = 59
_SC_UIO_MAXIOV = 60
_SC_IOV_MAX = 60
_SC_PII_INTERNET_STREAM = 61
_SC_PII_INTERNET_DGRAM = 62
_SC_PII_OSI_COTS = 63
_SC_PII_OSI_CLTS = 64
_SC_PII_OSI_M = 65
_SC_T_IOV_MAX = 66
_SC_THREADS = 67
_SC_THREAD_SAFE_FUNCTIONS = 68
_SC_GETGR_R_SIZE_MAX = 69
_SC_GETPW_R_SIZE_MAX = 70
_SC_LOGIN_NAME_MAX = 71
_SC_TTY_NAME_MAX = 72
_SC_THREAD_DESTRUCTOR_ITERATIONS = 73
_SC_THREAD_KEYS_MAX = 74
_SC_THREAD_STACK_MIN = 75
_SC_THREAD_THREADS_MAX = 76
_SC_THREAD_ATTR_STACKADDR = 77
_SC_THREAD_ATTR_STACKSIZE = 78
_SC_THREAD_PRIORITY_SCHEDULING = 79
_SC_THREAD_PRIO_INHERIT = 80
_SC_THREAD_PRIO_PROTECT = 81
_SC_THREAD_PROCESS_SHARED = 82
_SC_NPROCESSORS_CONF = 83
_SC_NPROCESSORS_ONLN = 84
_SC_PHYS_PAGES = 85
_SC_AVPHYS_PAGES = 86
_SC_ATEXIT_MAX = 87
_SC_PASS_MAX = 88
_SC_XOPEN_VERSION = 89
_SC_XOPEN_XCU_VERSION = 90
_SC_XOPEN_UNIX = 91
_SC_XOPEN_CRYPT = 92
_SC_XOPEN_ENH_I18N = 93
_SC_XOPEN_SHM = 94
_SC_2_CHAR_TERM = 95
_SC_2_C_VERSION = 96
_SC_2_UPE = 97
_SC_XOPEN_XPG2 = 98
_SC_XOPEN_XPG3 = 99
_SC_XOPEN_XPG4 = 100
_SC_CHAR_BIT = 101
_SC_CHAR_MAX = 102
_SC_CHAR_MIN = 103
_SC_INT_MAX = 104
_SC_INT_MIN = 105
_SC_LONG_BIT = 106
_SC_WORD_BIT = 107
_SC_MB_LEN_MAX = 108
_SC_NZERO = 109
_SC_SSIZE_MAX = 110
_SC_SCHAR_MAX = 111
_SC_SCHAR_MIN = 112
_SC_SHRT_MAX = 113
_SC_SHRT_MIN = 114
_SC_UCHAR_MAX = 115
_SC_UINT_MAX = 116
_SC_ULONG_MAX = 117
_SC_USHRT_MAX = 118
_SC_NL_ARGMAX = 119
_SC_NL_LANGMAX = 120
_SC_NL_MSGMAX = 121
_SC_NL_NMAX = 122
_SC_NL_SETMAX = 123
_SC_NL_TEXTMAX = 124
_SC_XBS5_ILP32_OFF32 = 125
_SC_XBS5_ILP32_OFFBIG = 126
_SC_XBS5_LP64_OFF64 = 127
_SC_XBS5_LPBIG_OFFBIG = 128
_SC_XOPEN_LEGACY = 129
_SC_XOPEN_REALTIME = 130
_SC_XOPEN_REALTIME_THREADS = 131
_SC_ADVISORY_INFO = 132
_SC_BARRIERS = 133
_SC_BASE = 134
_SC_C_LANG_SUPPORT = 135
_SC_C_LANG_SUPPORT_R = 136
_SC_CLOCK_SELECTION = 137
_SC_CPUTIME = 138
_SC_THREAD_CPUTIME = 139
_SC_DEVICE_IO = 140
_SC_DEVICE_SPECIFIC = 141
_SC_DEVICE_SPECIFIC_R = 142
_SC_FD_MGMT = 143
_SC_FIFO = 144
_SC_PIPE = 145
_SC_FILE_ATTRIBUTES = 146
_SC_FILE_LOCKING = 147
_SC_FILE_SYSTEM = 148
_SC_MONOTONIC_CLOCK = 149
_SC_MULTI_PROCESS = 150
_SC_SINGLE_PROCESS = 151
_SC_NETWORKING = 152
_SC_READER_WRITER_LOCKS = 153
_SC_SPIN_LOCKS = 154
_SC_REGEXP = 155
_SC_REGEX_VERSION = 156
_SC_SHELL = 157
_SC_SIGNALS = 158
_SC_SPAWN = 159
_SC_SPORADIC_SERVER = 160
_SC_THREAD_SPORADIC_SERVER = 161
_SC_SYSTEM_DATABASE = 162
_SC_SYSTEM_DATABASE_R = 163
_SC_TIMEOUTS = 164
_SC_TYPED_MEMORY_OBJECTS = 165
_SC_USER_GROUPS = 166
_SC_USER_GROUPS_R = 167
_SC_2_PBS = 168
_SC_2_PBS_ACCOUNTING = 169
_SC_2_PBS_LOCATE = 170
_SC_2_PBS_MESSAGE = 171
_SC_2_PBS_TRACK = 172
_SC_SYMLOOP_MAX = 173
_SC_STREAMS = 174
_SC_2_PBS_CHECKPOINT = 175
_SC_V6_ILP32_OFF32 = 176
_SC_V6_ILP32_OFFBIG = 177
_SC_V6_LP64_OFF64 = 178
_SC_V6_LPBIG_OFFBIG = 179
_SC_HOST_NAME_MAX = 180
_SC_TRACE = 181
_SC_TRACE_EVENT_FILTER = 182
_SC_TRACE_INHERIT = 183
_SC_TRACE_LOG = 184
_SC_LEVEL1_ICACHE_SIZE = 185
_SC_LEVEL1_ICACHE_ASSOC = 186
_SC_LEVEL1_ICACHE_LINESIZE = 187
_SC_LEVEL1_DCACHE_SIZE = 188
_SC_LEVEL1_DCACHE_ASSOC = 189
_SC_LEVEL1_DCACHE_LINESIZE = 190
_SC_LEVEL2_CACHE_SIZE = 191
_SC_LEVEL2_CACHE_ASSOC = 192
_SC_LEVEL2_CACHE_LINESIZE = 193
_SC_LEVEL3_CACHE_SIZE = 194
_SC_LEVEL3_CACHE_ASSOC = 195
_SC_LEVEL3_CACHE_LINESIZE = 196
_SC_LEVEL4_CACHE_SIZE = 197
_SC_LEVEL4_CACHE_ASSOC = 198
_SC_LEVEL4_CACHE_LINESIZE = 199
_SC_IPV6 = 235
_SC_RAW_SOCKETS = 236
_SC_V7_ILP32_OFF32 = 237
_SC_V7_ILP32_OFFBIG = 238
_SC_V7_LP64_OFF64 = 239
_SC_V7_LPBIG_OFFBIG = 240
_SC_SS_REPL_MAX = 241
_SC_TRACE_EVENT_NAME_MAX = 242
_SC_TRACE_NAME_MAX = 243
_SC_TRACE_SYS_MAX = 244
_SC_TRACE_USER_EVENT_MAX = 245
_SC_XOPEN_STREAMS = 246
_SC_THREAD_ROBUST_PRIO_INHERIT = 247
_SC_THREAD_ROBUST_PRIO_PROTECT = 248
_SC_MINSIGSTKSZ = 249
_SC_SIGSTKSZ = 250
c__Ea__SC_ARG_MAX = ctypes.c_uint32 # enum

# values for enumeration 'c__Ea__CS_PATH'
c__Ea__CS_PATH__enumvalues = {
    0: '_CS_PATH',
    1: '_CS_V6_WIDTH_RESTRICTED_ENVS',
    2: '_CS_GNU_LIBC_VERSION',
    3: '_CS_GNU_LIBPTHREAD_VERSION',
    4: '_CS_V5_WIDTH_RESTRICTED_ENVS',
    5: '_CS_V7_WIDTH_RESTRICTED_ENVS',
    1000: '_CS_LFS_CFLAGS',
    1001: '_CS_LFS_LDFLAGS',
    1002: '_CS_LFS_LIBS',
    1003: '_CS_LFS_LINTFLAGS',
    1004: '_CS_LFS64_CFLAGS',
    1005: '_CS_LFS64_LDFLAGS',
    1006: '_CS_LFS64_LIBS',
    1007: '_CS_LFS64_LINTFLAGS',
    1100: '_CS_XBS5_ILP32_OFF32_CFLAGS',
    1101: '_CS_XBS5_ILP32_OFF32_LDFLAGS',
    1102: '_CS_XBS5_ILP32_OFF32_LIBS',
    1103: '_CS_XBS5_ILP32_OFF32_LINTFLAGS',
    1104: '_CS_XBS5_ILP32_OFFBIG_CFLAGS',
    1105: '_CS_XBS5_ILP32_OFFBIG_LDFLAGS',
    1106: '_CS_XBS5_ILP32_OFFBIG_LIBS',
    1107: '_CS_XBS5_ILP32_OFFBIG_LINTFLAGS',
    1108: '_CS_XBS5_LP64_OFF64_CFLAGS',
    1109: '_CS_XBS5_LP64_OFF64_LDFLAGS',
    1110: '_CS_XBS5_LP64_OFF64_LIBS',
    1111: '_CS_XBS5_LP64_OFF64_LINTFLAGS',
    1112: '_CS_XBS5_LPBIG_OFFBIG_CFLAGS',
    1113: '_CS_XBS5_LPBIG_OFFBIG_LDFLAGS',
    1114: '_CS_XBS5_LPBIG_OFFBIG_LIBS',
    1115: '_CS_XBS5_LPBIG_OFFBIG_LINTFLAGS',
    1116: '_CS_POSIX_V6_ILP32_OFF32_CFLAGS',
    1117: '_CS_POSIX_V6_ILP32_OFF32_LDFLAGS',
    1118: '_CS_POSIX_V6_ILP32_OFF32_LIBS',
    1119: '_CS_POSIX_V6_ILP32_OFF32_LINTFLAGS',
    1120: '_CS_POSIX_V6_ILP32_OFFBIG_CFLAGS',
    1121: '_CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS',
    1122: '_CS_POSIX_V6_ILP32_OFFBIG_LIBS',
    1123: '_CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS',
    1124: '_CS_POSIX_V6_LP64_OFF64_CFLAGS',
    1125: '_CS_POSIX_V6_LP64_OFF64_LDFLAGS',
    1126: '_CS_POSIX_V6_LP64_OFF64_LIBS',
    1127: '_CS_POSIX_V6_LP64_OFF64_LINTFLAGS',
    1128: '_CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS',
    1129: '_CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS',
    1130: '_CS_POSIX_V6_LPBIG_OFFBIG_LIBS',
    1131: '_CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS',
    1132: '_CS_POSIX_V7_ILP32_OFF32_CFLAGS',
    1133: '_CS_POSIX_V7_ILP32_OFF32_LDFLAGS',
    1134: '_CS_POSIX_V7_ILP32_OFF32_LIBS',
    1135: '_CS_POSIX_V7_ILP32_OFF32_LINTFLAGS',
    1136: '_CS_POSIX_V7_ILP32_OFFBIG_CFLAGS',
    1137: '_CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS',
    1138: '_CS_POSIX_V7_ILP32_OFFBIG_LIBS',
    1139: '_CS_POSIX_V7_ILP32_OFFBIG_LINTFLAGS',
    1140: '_CS_POSIX_V7_LP64_OFF64_CFLAGS',
    1141: '_CS_POSIX_V7_LP64_OFF64_LDFLAGS',
    1142: '_CS_POSIX_V7_LP64_OFF64_LIBS',
    1143: '_CS_POSIX_V7_LP64_OFF64_LINTFLAGS',
    1144: '_CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS',
    1145: '_CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS',
    1146: '_CS_POSIX_V7_LPBIG_OFFBIG_LIBS',
    1147: '_CS_POSIX_V7_LPBIG_OFFBIG_LINTFLAGS',
    1148: '_CS_V6_ENV',
    1149: '_CS_V7_ENV',
}
_CS_PATH = 0
_CS_V6_WIDTH_RESTRICTED_ENVS = 1
_CS_GNU_LIBC_VERSION = 2
_CS_GNU_LIBPTHREAD_VERSION = 3
_CS_V5_WIDTH_RESTRICTED_ENVS = 4
_CS_V7_WIDTH_RESTRICTED_ENVS = 5
_CS_LFS_CFLAGS = 1000
_CS_LFS_LDFLAGS = 1001
_CS_LFS_LIBS = 1002
_CS_LFS_LINTFLAGS = 1003
_CS_LFS64_CFLAGS = 1004
_CS_LFS64_LDFLAGS = 1005
_CS_LFS64_LIBS = 1006
_CS_LFS64_LINTFLAGS = 1007
_CS_XBS5_ILP32_OFF32_CFLAGS = 1100
_CS_XBS5_ILP32_OFF32_LDFLAGS = 1101
_CS_XBS5_ILP32_OFF32_LIBS = 1102
_CS_XBS5_ILP32_OFF32_LINTFLAGS = 1103
_CS_XBS5_ILP32_OFFBIG_CFLAGS = 1104
_CS_XBS5_ILP32_OFFBIG_LDFLAGS = 1105
_CS_XBS5_ILP32_OFFBIG_LIBS = 1106
_CS_XBS5_ILP32_OFFBIG_LINTFLAGS = 1107
_CS_XBS5_LP64_OFF64_CFLAGS = 1108
_CS_XBS5_LP64_OFF64_LDFLAGS = 1109
_CS_XBS5_LP64_OFF64_LIBS = 1110
_CS_XBS5_LP64_OFF64_LINTFLAGS = 1111
_CS_XBS5_LPBIG_OFFBIG_CFLAGS = 1112
_CS_XBS5_LPBIG_OFFBIG_LDFLAGS = 1113
_CS_XBS5_LPBIG_OFFBIG_LIBS = 1114
_CS_XBS5_LPBIG_OFFBIG_LINTFLAGS = 1115
_CS_POSIX_V6_ILP32_OFF32_CFLAGS = 1116
_CS_POSIX_V6_ILP32_OFF32_LDFLAGS = 1117
_CS_POSIX_V6_ILP32_OFF32_LIBS = 1118
_CS_POSIX_V6_ILP32_OFF32_LINTFLAGS = 1119
_CS_POSIX_V6_ILP32_OFFBIG_CFLAGS = 1120
_CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS = 1121
_CS_POSIX_V6_ILP32_OFFBIG_LIBS = 1122
_CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS = 1123
_CS_POSIX_V6_LP64_OFF64_CFLAGS = 1124
_CS_POSIX_V6_LP64_OFF64_LDFLAGS = 1125
_CS_POSIX_V6_LP64_OFF64_LIBS = 1126
_CS_POSIX_V6_LP64_OFF64_LINTFLAGS = 1127
_CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS = 1128
_CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS = 1129
_CS_POSIX_V6_LPBIG_OFFBIG_LIBS = 1130
_CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS = 1131
_CS_POSIX_V7_ILP32_OFF32_CFLAGS = 1132
_CS_POSIX_V7_ILP32_OFF32_LDFLAGS = 1133
_CS_POSIX_V7_ILP32_OFF32_LIBS = 1134
_CS_POSIX_V7_ILP32_OFF32_LINTFLAGS = 1135
_CS_POSIX_V7_ILP32_OFFBIG_CFLAGS = 1136
_CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS = 1137
_CS_POSIX_V7_ILP32_OFFBIG_LIBS = 1138
_CS_POSIX_V7_ILP32_OFFBIG_LINTFLAGS = 1139
_CS_POSIX_V7_LP64_OFF64_CFLAGS = 1140
_CS_POSIX_V7_LP64_OFF64_LDFLAGS = 1141
_CS_POSIX_V7_LP64_OFF64_LIBS = 1142
_CS_POSIX_V7_LP64_OFF64_LINTFLAGS = 1143
_CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS = 1144
_CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS = 1145
_CS_POSIX_V7_LPBIG_OFFBIG_LIBS = 1146
_CS_POSIX_V7_LPBIG_OFFBIG_LINTFLAGS = 1147
_CS_V6_ENV = 1148
_CS_V7_ENV = 1149
c__Ea__CS_PATH = ctypes.c_uint32 # enum
try:
    pathconf = _libraries['FIXME_STUB'].pathconf
    pathconf.restype = ctypes.c_int64
    pathconf.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    fpathconf = _libraries['FIXME_STUB'].fpathconf
    fpathconf.restype = ctypes.c_int64
    fpathconf.argtypes = [ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    sysconf = _libraries['FIXME_STUB'].sysconf
    sysconf.restype = ctypes.c_int64
    sysconf.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    confstr = _libraries['FIXME_STUB'].confstr
    confstr.restype = size_t
    confstr.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    getpid = _libraries['FIXME_STUB'].getpid
    getpid.restype = __pid_t
    getpid.argtypes = []
except AttributeError:
    pass
try:
    getppid = _libraries['FIXME_STUB'].getppid
    getppid.restype = __pid_t
    getppid.argtypes = []
except AttributeError:
    pass
try:
    getpgrp = _libraries['FIXME_STUB'].getpgrp
    getpgrp.restype = __pid_t
    getpgrp.argtypes = []
except AttributeError:
    pass
try:
    __getpgid = _libraries['FIXME_STUB'].__getpgid
    __getpgid.restype = __pid_t
    __getpgid.argtypes = [__pid_t]
except AttributeError:
    pass
try:
    getpgid = _libraries['FIXME_STUB'].getpgid
    getpgid.restype = __pid_t
    getpgid.argtypes = [__pid_t]
except AttributeError:
    pass
try:
    setpgid = _libraries['FIXME_STUB'].setpgid
    setpgid.restype = ctypes.c_int32
    setpgid.argtypes = [__pid_t, __pid_t]
except AttributeError:
    pass
try:
    setpgrp = _libraries['FIXME_STUB'].setpgrp
    setpgrp.restype = ctypes.c_int32
    setpgrp.argtypes = []
except AttributeError:
    pass
try:
    setsid = _libraries['FIXME_STUB'].setsid
    setsid.restype = __pid_t
    setsid.argtypes = []
except AttributeError:
    pass
try:
    getsid = _libraries['FIXME_STUB'].getsid
    getsid.restype = __pid_t
    getsid.argtypes = [__pid_t]
except AttributeError:
    pass
try:
    getuid = _libraries['FIXME_STUB'].getuid
    getuid.restype = __uid_t
    getuid.argtypes = []
except AttributeError:
    pass
try:
    geteuid = _libraries['FIXME_STUB'].geteuid
    geteuid.restype = __uid_t
    geteuid.argtypes = []
except AttributeError:
    pass
try:
    getgid = _libraries['FIXME_STUB'].getgid
    getgid.restype = __gid_t
    getgid.argtypes = []
except AttributeError:
    pass
try:
    getegid = _libraries['FIXME_STUB'].getegid
    getegid.restype = __gid_t
    getegid.argtypes = []
except AttributeError:
    pass
try:
    getgroups = _libraries['FIXME_STUB'].getgroups
    getgroups.restype = ctypes.c_int32
    getgroups.argtypes = [ctypes.c_int32, ctypes.c_uint32 * 0]
except AttributeError:
    pass
try:
    setuid = _libraries['FIXME_STUB'].setuid
    setuid.restype = ctypes.c_int32
    setuid.argtypes = [__uid_t]
except AttributeError:
    pass
try:
    setreuid = _libraries['FIXME_STUB'].setreuid
    setreuid.restype = ctypes.c_int32
    setreuid.argtypes = [__uid_t, __uid_t]
except AttributeError:
    pass
try:
    seteuid = _libraries['FIXME_STUB'].seteuid
    seteuid.restype = ctypes.c_int32
    seteuid.argtypes = [__uid_t]
except AttributeError:
    pass
try:
    setgid = _libraries['FIXME_STUB'].setgid
    setgid.restype = ctypes.c_int32
    setgid.argtypes = [__gid_t]
except AttributeError:
    pass
try:
    setregid = _libraries['FIXME_STUB'].setregid
    setregid.restype = ctypes.c_int32
    setregid.argtypes = [__gid_t, __gid_t]
except AttributeError:
    pass
try:
    setegid = _libraries['FIXME_STUB'].setegid
    setegid.restype = ctypes.c_int32
    setegid.argtypes = [__gid_t]
except AttributeError:
    pass
try:
    fork = _libraries['FIXME_STUB'].fork
    fork.restype = __pid_t
    fork.argtypes = []
except AttributeError:
    pass
try:
    vfork = _libraries['FIXME_STUB'].vfork
    vfork.restype = ctypes.c_int32
    vfork.argtypes = []
except AttributeError:
    pass
try:
    ttyname = _libraries['FIXME_STUB'].ttyname
    ttyname.restype = ctypes.POINTER(ctypes.c_char)
    ttyname.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    ttyname_r = _libraries['FIXME_STUB'].ttyname_r
    ttyname_r.restype = ctypes.c_int32
    ttyname_r.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    isatty = _libraries['FIXME_STUB'].isatty
    isatty.restype = ctypes.c_int32
    isatty.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    ttyslot = _libraries['FIXME_STUB'].ttyslot
    ttyslot.restype = ctypes.c_int32
    ttyslot.argtypes = []
except AttributeError:
    pass
try:
    link = _libraries['FIXME_STUB'].link
    link.restype = ctypes.c_int32
    link.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    linkat = _libraries['FIXME_STUB'].linkat
    linkat.restype = ctypes.c_int32
    linkat.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    symlink = _libraries['FIXME_STUB'].symlink
    symlink.restype = ctypes.c_int32
    symlink.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    readlink = _libraries['FIXME_STUB'].readlink
    readlink.restype = ssize_t
    readlink.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    symlinkat = _libraries['FIXME_STUB'].symlinkat
    symlinkat.restype = ctypes.c_int32
    symlinkat.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    readlinkat = _libraries['FIXME_STUB'].readlinkat
    readlinkat.restype = ssize_t
    readlinkat.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    unlink = _libraries['FIXME_STUB'].unlink
    unlink.restype = ctypes.c_int32
    unlink.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    unlinkat = _libraries['FIXME_STUB'].unlinkat
    unlinkat.restype = ctypes.c_int32
    unlinkat.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    rmdir = _libraries['FIXME_STUB'].rmdir
    rmdir.restype = ctypes.c_int32
    rmdir.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    tcgetpgrp = _libraries['FIXME_STUB'].tcgetpgrp
    tcgetpgrp.restype = __pid_t
    tcgetpgrp.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    tcsetpgrp = _libraries['FIXME_STUB'].tcsetpgrp
    tcsetpgrp.restype = ctypes.c_int32
    tcsetpgrp.argtypes = [ctypes.c_int32, __pid_t]
except AttributeError:
    pass
try:
    getlogin = _libraries['FIXME_STUB'].getlogin
    getlogin.restype = ctypes.POINTER(ctypes.c_char)
    getlogin.argtypes = []
except AttributeError:
    pass
try:
    getlogin_r = _libraries['FIXME_STUB'].getlogin_r
    getlogin_r.restype = ctypes.c_int32
    getlogin_r.argtypes = [ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    setlogin = _libraries['FIXME_STUB'].setlogin
    setlogin.restype = ctypes.c_int32
    setlogin.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
optarg = None # Variable ctypes.POINTER(ctypes.c_char)
optind = 0 # Variable ctypes.c_int32
opterr = 0 # Variable ctypes.c_int32
optopt = 0 # Variable ctypes.c_int32
try:
    getopt = _libraries['FIXME_STUB'].getopt
    getopt.restype = ctypes.c_int32
    getopt.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    gethostname = _libraries['FIXME_STUB'].gethostname
    gethostname.restype = ctypes.c_int32
    gethostname.argtypes = [ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    sethostname = _libraries['FIXME_STUB'].sethostname
    sethostname.restype = ctypes.c_int32
    sethostname.argtypes = [ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    sethostid = _libraries['FIXME_STUB'].sethostid
    sethostid.restype = ctypes.c_int32
    sethostid.argtypes = [ctypes.c_int64]
except AttributeError:
    pass
try:
    getdomainname = _libraries['FIXME_STUB'].getdomainname
    getdomainname.restype = ctypes.c_int32
    getdomainname.argtypes = [ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    setdomainname = _libraries['FIXME_STUB'].setdomainname
    setdomainname.restype = ctypes.c_int32
    setdomainname.argtypes = [ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    vhangup = _libraries['FIXME_STUB'].vhangup
    vhangup.restype = ctypes.c_int32
    vhangup.argtypes = []
except AttributeError:
    pass
try:
    revoke = _libraries['FIXME_STUB'].revoke
    revoke.restype = ctypes.c_int32
    revoke.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    profil = _libraries['FIXME_STUB'].profil
    profil.restype = ctypes.c_int32
    profil.argtypes = [ctypes.POINTER(ctypes.c_uint16), size_t, size_t, ctypes.c_uint32]
except AttributeError:
    pass
try:
    acct = _libraries['FIXME_STUB'].acct
    acct.restype = ctypes.c_int32
    acct.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    getusershell = _libraries['FIXME_STUB'].getusershell
    getusershell.restype = ctypes.POINTER(ctypes.c_char)
    getusershell.argtypes = []
except AttributeError:
    pass
try:
    endusershell = _libraries['FIXME_STUB'].endusershell
    endusershell.restype = None
    endusershell.argtypes = []
except AttributeError:
    pass
try:
    setusershell = _libraries['FIXME_STUB'].setusershell
    setusershell.restype = None
    setusershell.argtypes = []
except AttributeError:
    pass
try:
    daemon = _libraries['FIXME_STUB'].daemon
    daemon.restype = ctypes.c_int32
    daemon.argtypes = [ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    chroot = _libraries['FIXME_STUB'].chroot
    chroot.restype = ctypes.c_int32
    chroot.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    getpass = _libraries['FIXME_STUB'].getpass
    getpass.restype = ctypes.POINTER(ctypes.c_char)
    getpass.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    fsync = _libraries['FIXME_STUB'].fsync
    fsync.restype = ctypes.c_int32
    fsync.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    gethostid = _libraries['FIXME_STUB'].gethostid
    gethostid.restype = ctypes.c_int64
    gethostid.argtypes = []
except AttributeError:
    pass
try:
    sync = _libraries['FIXME_STUB'].sync
    sync.restype = None
    sync.argtypes = []
except AttributeError:
    pass
try:
    getpagesize = _libraries['FIXME_STUB'].getpagesize
    getpagesize.restype = ctypes.c_int32
    getpagesize.argtypes = []
except AttributeError:
    pass
try:
    getdtablesize = _libraries['FIXME_STUB'].getdtablesize
    getdtablesize.restype = ctypes.c_int32
    getdtablesize.argtypes = []
except AttributeError:
    pass
try:
    truncate = _libraries['FIXME_STUB'].truncate
    truncate.restype = ctypes.c_int32
    truncate.argtypes = [ctypes.POINTER(ctypes.c_char), __off64_t]
except AttributeError:
    pass
try:
    ftruncate = _libraries['FIXME_STUB'].ftruncate
    ftruncate.restype = ctypes.c_int32
    ftruncate.argtypes = [ctypes.c_int32, __off64_t]
except AttributeError:
    pass
try:
    brk = _libraries['FIXME_STUB'].brk
    brk.restype = ctypes.c_int32
    brk.argtypes = [ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    sbrk = _libraries['FIXME_STUB'].sbrk
    sbrk.restype = ctypes.POINTER(None)
    sbrk.argtypes = [intptr_t]
except AttributeError:
    pass
try:
    syscall = _libraries['FIXME_STUB'].syscall
    syscall.restype = ctypes.c_int64
    syscall.argtypes = [ctypes.c_int64]
except AttributeError:
    pass
try:
    fdatasync = _libraries['FIXME_STUB'].fdatasync
    fdatasync.restype = ctypes.c_int32
    fdatasync.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    crypt = _libraries['FIXME_STUB'].crypt
    crypt.restype = ctypes.POINTER(ctypes.c_char)
    crypt.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    getentropy = _libraries['FIXME_STUB'].getentropy
    getentropy.restype = ctypes.c_int32
    getentropy.argtypes = [ctypes.POINTER(None), size_t]
except AttributeError:
    pass
class struct_timezone(Structure):
    pass

struct_timezone._pack_ = 1 # source:False
struct_timezone._fields_ = [
    ('tz_minuteswest', ctypes.c_int32),
    ('tz_dsttime', ctypes.c_int32),
]

try:
    gettimeofday = _libraries['FIXME_STUB'].gettimeofday
    gettimeofday.restype = ctypes.c_int32
    gettimeofday.argtypes = [ctypes.POINTER(struct_timeval), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    settimeofday = _libraries['FIXME_STUB'].settimeofday
    settimeofday.restype = ctypes.c_int32
    settimeofday.argtypes = [ctypes.POINTER(struct_timeval), ctypes.POINTER(struct_timezone)]
except AttributeError:
    pass
try:
    adjtime = _libraries['FIXME_STUB'].adjtime
    adjtime.restype = ctypes.c_int32
    adjtime.argtypes = [ctypes.POINTER(struct_timeval), ctypes.POINTER(struct_timeval)]
except AttributeError:
    pass

# values for enumeration '__itimer_which'
__itimer_which__enumvalues = {
    0: 'ITIMER_REAL',
    1: 'ITIMER_VIRTUAL',
    2: 'ITIMER_PROF',
}
ITIMER_REAL = 0
ITIMER_VIRTUAL = 1
ITIMER_PROF = 2
__itimer_which = ctypes.c_uint32 # enum
class struct_itimerval(Structure):
    _pack_ = 1 # source:False
    _fields_ = [
    ('it_interval', struct_timeval),
    ('it_value', struct_timeval),
     ]

__itimer_which_t = ctypes.c_int32
try:
    getitimer = _libraries['FIXME_STUB'].getitimer
    getitimer.restype = ctypes.c_int32
    getitimer.argtypes = [__itimer_which_t, ctypes.POINTER(struct_itimerval)]
except AttributeError:
    pass
try:
    setitimer = _libraries['FIXME_STUB'].setitimer
    setitimer.restype = ctypes.c_int32
    setitimer.argtypes = [__itimer_which_t, ctypes.POINTER(struct_itimerval), ctypes.POINTER(struct_itimerval)]
except AttributeError:
    pass
try:
    utimes = _libraries['FIXME_STUB'].utimes
    utimes.restype = ctypes.c_int32
    utimes.argtypes = [ctypes.POINTER(ctypes.c_char), struct_timeval * 2]
except AttributeError:
    pass
try:
    lutimes = _libraries['FIXME_STUB'].lutimes
    lutimes.restype = ctypes.c_int32
    lutimes.argtypes = [ctypes.POINTER(ctypes.c_char), struct_timeval * 2]
except AttributeError:
    pass
try:
    futimes = _libraries['FIXME_STUB'].futimes
    futimes.restype = ctypes.c_int32
    futimes.argtypes = [ctypes.c_int32, struct_timeval * 2]
except AttributeError:
    pass

# values for enumeration 'RSysArch'
RSysArch__enumvalues = {
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
    25: 'R_SYS_ARCH_S390',
    26: 'R_SYS_ARCH_XCORE',
    27: 'R_SYS_ARCH_PROPELLER',
    28: 'R_SYS_ARCH_MSP430',
    29: 'R_SYS_ARCH_CRIS',
    30: 'R_SYS_ARCH_HPPA',
    31: 'R_SYS_ARCH_V810',
    32: 'R_SYS_ARCH_LM32',
    33: 'R_SYS_ARCH_RISCV',
    34: 'R_SYS_ARCH_ESIL',
    35: 'R_SYS_ARCH_BPF',
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
R_SYS_ARCH_S390 = 25
R_SYS_ARCH_XCORE = 26
R_SYS_ARCH_PROPELLER = 27
R_SYS_ARCH_MSP430 = 28
R_SYS_ARCH_CRIS = 29
R_SYS_ARCH_HPPA = 30
R_SYS_ARCH_V810 = 31
R_SYS_ARCH_LM32 = 32
R_SYS_ARCH_RISCV = 33
R_SYS_ARCH_ESIL = 34
R_SYS_ARCH_BPF = 35
RSysArch = ctypes.c_uint32 # enum
try:
    r_run_call1 = _libraries['FIXME_STUB'].r_run_call1
    r_run_call1.restype = None
    r_run_call1.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_run_call2 = _libraries['FIXME_STUB'].r_run_call2
    r_run_call2.restype = None
    r_run_call2.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_run_call3 = _libraries['FIXME_STUB'].r_run_call3
    r_run_call3.restype = None
    r_run_call3.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_run_call4 = _libraries['FIXME_STUB'].r_run_call4
    r_run_call4.restype = None
    r_run_call4.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_run_call5 = _libraries['FIXME_STUB'].r_run_call5
    r_run_call5.restype = None
    r_run_call5.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_run_call6 = _libraries['FIXME_STUB'].r_run_call6
    r_run_call6.restype = None
    r_run_call6.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_run_call7 = _libraries['FIXME_STUB'].r_run_call7
    r_run_call7.restype = None
    r_run_call7.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_run_call8 = _libraries['FIXME_STUB'].r_run_call8
    r_run_call8.restype = None
    r_run_call8.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_run_call9 = _libraries['FIXME_STUB'].r_run_call9
    r_run_call9.restype = None
    r_run_call9.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_run_call10 = _libraries['FIXME_STUB'].r_run_call10
    r_run_call10.restype = None
    r_run_call10.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    seek_set = _libraries['FIXME_STUB'].seek_set
    seek_set.restype = ctypes.c_int32
    seek_set.argtypes = [ctypes.c_int32, off_t]
except AttributeError:
    pass
try:
    ut32_pack = _libraries['FIXME_STUB'].ut32_pack
    ut32_pack.restype = None
    ut32_pack.argtypes = [ctypes.c_char * 4, uint32_t]
except AttributeError:
    pass
try:
    ut32_pack_big = _libraries['FIXME_STUB'].ut32_pack_big
    ut32_pack_big.restype = None
    ut32_pack_big.argtypes = [ctypes.c_char * 4, uint32_t]
except AttributeError:
    pass
try:
    ut32_unpack = _libraries['FIXME_STUB'].ut32_unpack
    ut32_unpack.restype = None
    ut32_unpack.argtypes = [ctypes.c_char * 4, ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
SdbListFree = ctypes.CFUNCTYPE(None, ctypes.POINTER(None))
SdbListComparator = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(None))
class struct_ls_iter_t(Structure):
    pass

struct_ls_iter_t._pack_ = 1 # source:False
struct_ls_iter_t._fields_ = [
    ('data', ctypes.POINTER(None)),
    ('n', ctypes.POINTER(struct_ls_iter_t)),
    ('p', ctypes.POINTER(struct_ls_iter_t)),
]

SdbListIter = struct_ls_iter_t
class struct_ls_t(Structure):
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

SdbList = struct_ls_t
try:
    ls_new = _libr_anal.ls_new
    ls_new.restype = ctypes.POINTER(struct_ls_t)
    ls_new.argtypes = []
except AttributeError:
    pass
try:
    ls_newf = _libr_anal.ls_newf
    ls_newf.restype = ctypes.POINTER(struct_ls_t)
    ls_newf.argtypes = [SdbListFree]
except AttributeError:
    pass
try:
    ls_append = _libr_anal.ls_append
    ls_append.restype = ctypes.POINTER(struct_ls_iter_t)
    ls_append.argtypes = [ctypes.POINTER(struct_ls_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    ls_prepend = _libr_anal.ls_prepend
    ls_prepend.restype = ctypes.POINTER(struct_ls_iter_t)
    ls_prepend.argtypes = [ctypes.POINTER(struct_ls_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    ls_sort = _libr_anal.ls_sort
    ls_sort.restype = ctypes.c_bool
    ls_sort.argtypes = [ctypes.POINTER(struct_ls_t), SdbListComparator]
except AttributeError:
    pass
try:
    ls_merge_sort = _libr_anal.ls_merge_sort
    ls_merge_sort.restype = ctypes.c_bool
    ls_merge_sort.argtypes = [ctypes.POINTER(struct_ls_t), SdbListComparator]
except AttributeError:
    pass
try:
    ls_delete = _libr_anal.ls_delete
    ls_delete.restype = None
    ls_delete.argtypes = [ctypes.POINTER(struct_ls_t), ctypes.POINTER(struct_ls_iter_t)]
except AttributeError:
    pass
try:
    ls_delete_data = _libr_anal.ls_delete_data
    ls_delete_data.restype = ctypes.c_bool
    ls_delete_data.argtypes = [ctypes.POINTER(struct_ls_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    ls_iter_init = _libraries['FIXME_STUB'].ls_iter_init
    ls_iter_init.restype = None
    ls_iter_init.argtypes = [ctypes.POINTER(struct_ls_iter_t), ctypes.POINTER(struct_ls_t)]
except AttributeError:
    pass
try:
    ls_destroy = _libr_anal.ls_destroy
    ls_destroy.restype = None
    ls_destroy.argtypes = [ctypes.POINTER(struct_ls_t)]
except AttributeError:
    pass
try:
    ls_free = _libr_anal.ls_free
    ls_free.restype = None
    ls_free.argtypes = [ctypes.POINTER(struct_ls_t)]
except AttributeError:
    pass
try:
    ls_item_new = _libraries['FIXME_STUB'].ls_item_new
    ls_item_new.restype = ctypes.POINTER(struct_ls_iter_t)
    ls_item_new.argtypes = [ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    ls_unlink = _libraries['FIXME_STUB'].ls_unlink
    ls_unlink.restype = None
    ls_unlink.argtypes = [ctypes.POINTER(struct_ls_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    ls_split = _libraries['FIXME_STUB'].ls_split
    ls_split.restype = None
    ls_split.argtypes = [ctypes.POINTER(struct_ls_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    ls_split_iter = _libr_anal.ls_split_iter
    ls_split_iter.restype = None
    ls_split_iter.argtypes = [ctypes.POINTER(struct_ls_t), ctypes.POINTER(struct_ls_iter_t)]
except AttributeError:
    pass
try:
    ls_get_n = _libraries['FIXME_STUB'].ls_get_n
    ls_get_n.restype = ctypes.POINTER(None)
    ls_get_n.argtypes = [ctypes.POINTER(struct_ls_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    ls_get_top = _libraries['FIXME_STUB'].ls_get_top
    ls_get_top.restype = ctypes.POINTER(None)
    ls_get_top.argtypes = [ctypes.POINTER(struct_ls_t)]
except AttributeError:
    pass
try:
    ls_pop = _libr_anal.ls_pop
    ls_pop.restype = ctypes.POINTER(None)
    ls_pop.argtypes = [ctypes.POINTER(struct_ls_t)]
except AttributeError:
    pass
try:
    ls_reverse = _libraries['FIXME_STUB'].ls_reverse
    ls_reverse.restype = None
    ls_reverse.argtypes = [ctypes.POINTER(struct_ls_t)]
except AttributeError:
    pass
try:
    ls_clone = _libr_anal.ls_clone
    ls_clone.restype = ctypes.POINTER(struct_ls_t)
    ls_clone.argtypes = [ctypes.POINTER(struct_ls_t)]
except AttributeError:
    pass
try:
    ls_join = _libr_anal.ls_join
    ls_join.restype = ctypes.c_int32
    ls_join.argtypes = [ctypes.POINTER(struct_ls_t), ctypes.POINTER(struct_ls_t)]
except AttributeError:
    pass
try:
    ls_del_n = _libr_anal.ls_del_n
    ls_del_n.restype = ctypes.c_int32
    ls_del_n.argtypes = [ctypes.POINTER(struct_ls_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    ls_insert = _libr_anal.ls_insert
    ls_insert.restype = ctypes.POINTER(struct_ls_iter_t)
    ls_insert.argtypes = [ctypes.POINTER(struct_ls_t), ctypes.c_int32, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    ls_pop_head = _libr_anal.ls_pop_head
    ls_pop_head.restype = ctypes.POINTER(None)
    ls_pop_head.argtypes = [ctypes.POINTER(struct_ls_t)]
except AttributeError:
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

HtPPKv = struct_ht_pp_kv
HtPPKvFreeFunc = ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_ht_pp_kv))
HtPPDupKey = ctypes.CFUNCTYPE(ctypes.POINTER(None), ctypes.POINTER(None))
HtPPDupValue = ctypes.CFUNCTYPE(ctypes.POINTER(None), ctypes.POINTER(None))
HtPPCalcSizeK = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.POINTER(None))
HtPPCalcSizeV = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.POINTER(None))
HtPPHashFunction = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.POINTER(None))
HtPPListComparator = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(None))
HtPPForeachCallback = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None))
class struct_ht_pp_bucket_t(Structure):
    pass

struct_ht_pp_bucket_t._pack_ = 1 # source:False
struct_ht_pp_bucket_t._fields_ = [
    ('arr', ctypes.POINTER(struct_ht_pp_kv)),
    ('count', ctypes.c_uint32),
    ('size', ctypes.c_uint32),
]

HtPPBucket = struct_ht_pp_bucket_t
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

HtPPOptions = struct_ht_pp_options_t
class struct_ht_pp_t(Structure):
    pass

struct_ht_pp_t._pack_ = 1 # source:False
struct_ht_pp_t._fields_ = [
    ('size', ctypes.c_uint32),
    ('count', ctypes.c_uint32),
    ('table', ctypes.POINTER(struct_ht_pp_bucket_t)),
    ('prime_idx', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('opt', HtPPOptions),
]

HtPP = struct_ht_pp_t
try:
    ht_pp_new_opt = _libr_anal.ht_pp_new_opt
    ht_pp_new_opt.restype = ctypes.POINTER(struct_ht_pp_t)
    ht_pp_new_opt.argtypes = [ctypes.POINTER(struct_ht_pp_options_t)]
except AttributeError:
    pass
try:
    ht_pp_free = _libr_anal.ht_pp_free
    ht_pp_free.restype = None
    ht_pp_free.argtypes = [ctypes.POINTER(struct_ht_pp_t)]
except AttributeError:
    pass
try:
    ht_pp_insert = _libr_anal.ht_pp_insert
    ht_pp_insert.restype = ctypes.c_bool
    ht_pp_insert.argtypes = [ctypes.POINTER(struct_ht_pp_t), ctypes.POINTER(None), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    ht_pp_update = _libr_anal.ht_pp_update
    ht_pp_update.restype = ctypes.c_bool
    ht_pp_update.argtypes = [ctypes.POINTER(struct_ht_pp_t), ctypes.POINTER(None), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    ht_pp_update_key = _libr_anal.ht_pp_update_key
    ht_pp_update_key.restype = ctypes.c_bool
    ht_pp_update_key.argtypes = [ctypes.POINTER(struct_ht_pp_t), ctypes.POINTER(None), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    ht_pp_delete = _libr_anal.ht_pp_delete
    ht_pp_delete.restype = ctypes.c_bool
    ht_pp_delete.argtypes = [ctypes.POINTER(struct_ht_pp_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    ht_pp_find = _libr_anal.ht_pp_find
    ht_pp_find.restype = ctypes.POINTER(None)
    ht_pp_find.argtypes = [ctypes.POINTER(struct_ht_pp_t), ctypes.POINTER(None), ctypes.POINTER(ctypes.c_bool)]
except AttributeError:
    pass
try:
    ht_pp_foreach = _libr_anal.ht_pp_foreach
    ht_pp_foreach.restype = None
    ht_pp_foreach.argtypes = [ctypes.POINTER(struct_ht_pp_t), HtPPForeachCallback, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    ht_pp_find_kv = _libr_anal.ht_pp_find_kv
    ht_pp_find_kv.restype = ctypes.POINTER(struct_ht_pp_kv)
    ht_pp_find_kv.argtypes = [ctypes.POINTER(struct_ht_pp_t), ctypes.POINTER(None), ctypes.POINTER(ctypes.c_bool)]
except AttributeError:
    pass
try:
    ht_pp_insert_kv = _libr_anal.ht_pp_insert_kv
    ht_pp_insert_kv.restype = ctypes.c_bool
    ht_pp_insert_kv.argtypes = [ctypes.POINTER(struct_ht_pp_t), ctypes.POINTER(struct_ht_pp_kv), ctypes.c_bool]
except AttributeError:
    pass
try:
    ht_pp_new0 = _libr_anal.ht_pp_new0
    ht_pp_new0.restype = ctypes.POINTER(struct_ht_pp_t)
    ht_pp_new0.argtypes = []
except AttributeError:
    pass
try:
    ht_pp_new = _libr_anal.ht_pp_new
    ht_pp_new.restype = ctypes.POINTER(struct_ht_pp_t)
    ht_pp_new.argtypes = [HtPPDupValue, HtPPKvFreeFunc, HtPPCalcSizeV]
except AttributeError:
    pass
try:
    ht_pp_new_size = _libr_anal.ht_pp_new_size
    ht_pp_new_size.restype = ctypes.POINTER(struct_ht_pp_t)
    ht_pp_new_size.argtypes = [uint32_t, HtPPDupValue, HtPPKvFreeFunc, HtPPCalcSizeV]
except AttributeError:
    pass
class struct_sdb_kv(Structure):
    pass

struct_sdb_kv._pack_ = 1 # source:False
struct_sdb_kv._fields_ = [
    ('base', HtPPKv),
    ('cas', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('expire', ctypes.c_uint64),
]

SdbKv = struct_sdb_kv
try:
    sdbkv_key = _libraries['FIXME_STUB'].sdbkv_key
    sdbkv_key.restype = ctypes.POINTER(ctypes.c_char)
    sdbkv_key.argtypes = [ctypes.POINTER(struct_sdb_kv)]
except AttributeError:
    pass
try:
    sdbkv_value = _libraries['FIXME_STUB'].sdbkv_value
    sdbkv_value.restype = ctypes.POINTER(ctypes.c_char)
    sdbkv_value.argtypes = [ctypes.POINTER(struct_sdb_kv)]
except AttributeError:
    pass
try:
    sdbkv_key_len = _libraries['FIXME_STUB'].sdbkv_key_len
    sdbkv_key_len.restype = uint32_t
    sdbkv_key_len.argtypes = [ctypes.POINTER(struct_sdb_kv)]
except AttributeError:
    pass
try:
    sdbkv_value_len = _libraries['FIXME_STUB'].sdbkv_value_len
    sdbkv_value_len.restype = uint32_t
    sdbkv_value_len.argtypes = [ctypes.POINTER(struct_sdb_kv)]
except AttributeError:
    pass
try:
    sdbkv_new2 = _libr_anal.sdbkv_new2
    sdbkv_new2.restype = ctypes.POINTER(struct_sdb_kv)
    sdbkv_new2.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    sdbkv_new = _libr_anal.sdbkv_new
    sdbkv_new.restype = ctypes.POINTER(struct_sdb_kv)
    sdbkv_new.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdbkv_free = _libr_anal.sdbkv_free
    sdbkv_free.restype = None
    sdbkv_free.argtypes = [ctypes.POINTER(struct_sdb_kv)]
except AttributeError:
    pass
try:
    sdb_hash = _libr_anal.sdb_hash
    sdb_hash.restype = uint32_t
    sdb_hash.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_ht_new = _libr_anal.sdb_ht_new
    sdb_ht_new.restype = ctypes.POINTER(struct_ht_pp_t)
    sdb_ht_new.argtypes = []
except AttributeError:
    pass
try:
    sdb_ht_free = _libr_anal.sdb_ht_free
    sdb_ht_free.restype = None
    sdb_ht_free.argtypes = [ctypes.POINTER(struct_ht_pp_t)]
except AttributeError:
    pass
try:
    sdb_ht_insert = _libr_anal.sdb_ht_insert
    sdb_ht_insert.restype = ctypes.c_bool
    sdb_ht_insert.argtypes = [ctypes.POINTER(struct_ht_pp_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_ht_insert_kvp = _libr_anal.sdb_ht_insert_kvp
    sdb_ht_insert_kvp.restype = ctypes.c_bool
    sdb_ht_insert_kvp.argtypes = [ctypes.POINTER(struct_ht_pp_t), ctypes.POINTER(struct_sdb_kv), ctypes.c_bool]
except AttributeError:
    pass
try:
    sdb_ht_update = _libr_anal.sdb_ht_update
    sdb_ht_update.restype = ctypes.c_bool
    sdb_ht_update.argtypes = [ctypes.POINTER(struct_ht_pp_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_ht_delete = _libr_anal.sdb_ht_delete
    sdb_ht_delete.restype = ctypes.c_bool
    sdb_ht_delete.argtypes = [ctypes.POINTER(struct_ht_pp_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_ht_find = _libr_anal.sdb_ht_find
    sdb_ht_find.restype = ctypes.POINTER(ctypes.c_char)
    sdb_ht_find.argtypes = [ctypes.POINTER(struct_ht_pp_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_bool)]
except AttributeError:
    pass
try:
    sdb_ht_find_kvp = _libr_anal.sdb_ht_find_kvp
    sdb_ht_find_kvp.restype = ctypes.POINTER(struct_sdb_kv)
    sdb_ht_find_kvp.argtypes = [ctypes.POINTER(struct_ht_pp_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_bool)]
except AttributeError:
    pass
dicti = ctypes.c_uint64
class struct_dictkv(Structure):
    pass

struct_dictkv._pack_ = 1 # source:False
struct_dictkv._fields_ = [
    ('k', ctypes.c_uint64),
    ('v', ctypes.c_uint64),
    ('u', ctypes.POINTER(None)),
]

dictkv = struct_dictkv
dict_freecb = ctypes.CFUNCTYPE(None, ctypes.POINTER(None))
dictkv_cb = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_dictkv), ctypes.POINTER(None))
class struct_dict(Structure):
    pass

struct_dict._pack_ = 1 # source:False
struct_dict._fields_ = [
    ('table', ctypes.POINTER(ctypes.POINTER(None))),
    ('f', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
    ('size', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

dict = struct_dict
SdbMini = struct_dict
try:
    dict_new = _libr_anal.dict_new
    dict_new.restype = ctypes.POINTER(struct_dict)
    dict_new.argtypes = [uint32_t, dict_freecb]
except AttributeError:
    pass
try:
    dict_free = _libr_anal.dict_free
    dict_free.restype = None
    dict_free.argtypes = [ctypes.POINTER(struct_dict)]
except AttributeError:
    pass
try:
    dict_init = _libr_anal.dict_init
    dict_init.restype = ctypes.c_bool
    dict_init.argtypes = [ctypes.POINTER(struct_dict), uint32_t, dict_freecb]
except AttributeError:
    pass
try:
    dict_fini = _libr_anal.dict_fini
    dict_fini.restype = None
    dict_fini.argtypes = [ctypes.POINTER(struct_dict)]
except AttributeError:
    pass
try:
    dict_stats = _libr_anal.dict_stats
    dict_stats.restype = uint32_t
    dict_stats.argtypes = [ctypes.POINTER(struct_dict), uint32_t]
except AttributeError:
    pass
try:
    dict_hash = _libr_anal.dict_hash
    dict_hash.restype = dicti
    dict_hash.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    dict_set = _libr_anal.dict_set
    dict_set.restype = ctypes.c_bool
    dict_set.argtypes = [ctypes.POINTER(struct_dict), dicti, dicti, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    dict_getr = _libr_anal.dict_getr
    dict_getr.restype = ctypes.POINTER(struct_dictkv)
    dict_getr.argtypes = [ctypes.POINTER(struct_dict), dicti]
except AttributeError:
    pass
try:
    dict_get = _libr_anal.dict_get
    dict_get.restype = dicti
    dict_get.argtypes = [ctypes.POINTER(struct_dict), dicti]
except AttributeError:
    pass
try:
    dict_getu = _libr_anal.dict_getu
    dict_getu.restype = ctypes.POINTER(None)
    dict_getu.argtypes = [ctypes.POINTER(struct_dict), dicti]
except AttributeError:
    pass
try:
    dict_add = _libr_anal.dict_add
    dict_add.restype = ctypes.c_bool
    dict_add.argtypes = [ctypes.POINTER(struct_dict), dicti, dicti, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    dict_del = _libr_anal.dict_del
    dict_del.restype = ctypes.c_bool
    dict_del.argtypes = [ctypes.POINTER(struct_dict), dicti]
except AttributeError:
    pass
try:
    dict_foreach = _libr_anal.dict_foreach
    dict_foreach.restype = None
    dict_foreach.argtypes = [ctypes.POINTER(struct_dict), dictkv_cb, ctypes.POINTER(None)]
except AttributeError:
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

try:
    cdb_getkvlen = _libraries['FIXME_STUB'].cdb_getkvlen
    cdb_getkvlen.restype = ctypes.c_bool
    cdb_getkvlen.argtypes = [ctypes.POINTER(struct_cdb), ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32), uint32_t]
except AttributeError:
    pass
try:
    cdb_free = _libraries['FIXME_STUB'].cdb_free
    cdb_free.restype = None
    cdb_free.argtypes = [ctypes.POINTER(struct_cdb)]
except AttributeError:
    pass
try:
    cdb_init = _libraries['FIXME_STUB'].cdb_init
    cdb_init.restype = ctypes.c_bool
    cdb_init.argtypes = [ctypes.POINTER(struct_cdb), ctypes.c_int32]
except AttributeError:
    pass
try:
    cdb_findstart = _libraries['FIXME_STUB'].cdb_findstart
    cdb_findstart.restype = None
    cdb_findstart.argtypes = [ctypes.POINTER(struct_cdb)]
except AttributeError:
    pass
try:
    cdb_read = _libraries['FIXME_STUB'].cdb_read
    cdb_read.restype = ctypes.c_bool
    cdb_read.argtypes = [ctypes.POINTER(struct_cdb), ctypes.POINTER(ctypes.c_char), ctypes.c_uint32, uint32_t]
except AttributeError:
    pass
try:
    cdb_findnext = _libraries['FIXME_STUB'].cdb_findnext
    cdb_findnext.restype = ctypes.c_int32
    cdb_findnext.argtypes = [ctypes.POINTER(struct_cdb), uint32_t, ctypes.POINTER(ctypes.c_char), uint32_t]
except AttributeError:
    pass
BufferOp = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.c_int32)
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

buffer = struct_buffer
try:
    buffer_init = _libraries['FIXME_STUB'].buffer_init
    buffer_init.restype = None
    buffer_init.argtypes = [ctypes.POINTER(struct_buffer), BufferOp, ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.c_uint32]
except AttributeError:
    pass
try:
    buffer_flush = _libraries['FIXME_STUB'].buffer_flush
    buffer_flush.restype = ctypes.c_int32
    buffer_flush.argtypes = [ctypes.POINTER(struct_buffer)]
except AttributeError:
    pass
try:
    buffer_put = _libraries['FIXME_STUB'].buffer_put
    buffer_put.restype = ctypes.c_int32
    buffer_put.argtypes = [ctypes.POINTER(struct_buffer), ctypes.POINTER(ctypes.c_char), ctypes.c_uint32]
except AttributeError:
    pass
try:
    buffer_putalign = _libraries['FIXME_STUB'].buffer_putalign
    buffer_putalign.restype = ctypes.c_int32
    buffer_putalign.argtypes = [ctypes.POINTER(struct_buffer), ctypes.POINTER(ctypes.c_char), ctypes.c_uint32]
except AttributeError:
    pass
try:
    buffer_putflush = _libraries['FIXME_STUB'].buffer_putflush
    buffer_putflush.restype = ctypes.c_int32
    buffer_putflush.argtypes = [ctypes.POINTER(struct_buffer), ctypes.POINTER(ctypes.c_char), ctypes.c_uint32]
except AttributeError:
    pass
try:
    buffer_get = _libraries['FIXME_STUB'].buffer_get
    buffer_get.restype = ctypes.c_int32
    buffer_get.argtypes = [ctypes.POINTER(struct_buffer), ctypes.POINTER(ctypes.c_char), ctypes.c_uint32]
except AttributeError:
    pass
try:
    buffer_bget = _libraries['FIXME_STUB'].buffer_bget
    buffer_bget.restype = ctypes.c_int32
    buffer_bget.argtypes = [ctypes.POINTER(struct_buffer), ctypes.POINTER(ctypes.c_char), ctypes.c_uint32]
except AttributeError:
    pass
try:
    buffer_feed = _libraries['FIXME_STUB'].buffer_feed
    buffer_feed.restype = ctypes.c_int32
    buffer_feed.argtypes = [ctypes.POINTER(struct_buffer)]
except AttributeError:
    pass
try:
    buffer_peek = _libraries['FIXME_STUB'].buffer_peek
    buffer_peek.restype = ctypes.POINTER(ctypes.c_char)
    buffer_peek.argtypes = [ctypes.POINTER(struct_buffer)]
except AttributeError:
    pass
try:
    buffer_seek = _libraries['FIXME_STUB'].buffer_seek
    buffer_seek.restype = None
    buffer_seek.argtypes = [ctypes.POINTER(struct_buffer), ctypes.c_uint32]
except AttributeError:
    pass
try:
    buffer_copy = _libraries['FIXME_STUB'].buffer_copy
    buffer_copy.restype = ctypes.c_int32
    buffer_copy.argtypes = [ctypes.POINTER(struct_buffer), ctypes.POINTER(struct_buffer)]
except AttributeError:
    pass
class struct_cdb_hp(Structure):
    pass

struct_cdb_hp._pack_ = 1 # source:False
struct_cdb_hp._fields_ = [
    ('h', ctypes.c_uint32),
    ('p', ctypes.c_uint32),
]

class struct_cdb_hplist(Structure):
    pass

struct_cdb_hplist._pack_ = 1 # source:False
struct_cdb_hplist._fields_ = [
    ('hp', struct_cdb_hp * 1000),
    ('next', ctypes.POINTER(struct_cdb_hplist)),
    ('num', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

class struct_cdb_make(Structure):
    pass

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
    ('b', buffer),
    ('pos', ctypes.c_uint32),
    ('fd', ctypes.c_int32),
]

try:
    cdb_make_start = _libraries['FIXME_STUB'].cdb_make_start
    cdb_make_start.restype = ctypes.c_int32
    cdb_make_start.argtypes = [ctypes.POINTER(struct_cdb_make), ctypes.c_int32]
except AttributeError:
    pass
try:
    cdb_make_addbegin = _libraries['FIXME_STUB'].cdb_make_addbegin
    cdb_make_addbegin.restype = ctypes.c_int32
    cdb_make_addbegin.argtypes = [ctypes.POINTER(struct_cdb_make), ctypes.c_uint32, ctypes.c_uint32]
except AttributeError:
    pass
try:
    cdb_make_addend = _libraries['FIXME_STUB'].cdb_make_addend
    cdb_make_addend.restype = ctypes.c_int32
    cdb_make_addend.argtypes = [ctypes.POINTER(struct_cdb_make), ctypes.c_uint32, ctypes.c_uint32, uint32_t]
except AttributeError:
    pass
try:
    cdb_make_add = _libraries['FIXME_STUB'].cdb_make_add
    cdb_make_add.restype = ctypes.c_int32
    cdb_make_add.argtypes = [ctypes.POINTER(struct_cdb_make), ctypes.POINTER(ctypes.c_char), ctypes.c_uint32, ctypes.POINTER(ctypes.c_char), ctypes.c_uint32]
except AttributeError:
    pass
try:
    cdb_make_finish = _libraries['FIXME_STUB'].cdb_make_finish
    cdb_make_finish.restype = ctypes.c_int32
    cdb_make_finish.argtypes = [ctypes.POINTER(struct_cdb_make)]
except AttributeError:
    pass
GperfForeachCallback = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char))
class struct_sdb_gperf_t(Structure):
    pass

struct_sdb_gperf_t._pack_ = 1 # source:False
struct_sdb_gperf_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('get', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char))),
    ('hash', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_char))),
    ('foreach', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)), ctypes.POINTER(None))),
]

SdbGperf = struct_sdb_gperf_t
class struct_sdb_t(Structure):
    pass

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
    ('tmpkv', SdbKv),
    ('depth', ctypes.c_uint32),
    ('timestamped', ctypes.c_bool),
    ('PADDING_1', ctypes.c_ubyte * 3),
    ('mht', SdbMini),
]

Sdb = struct_sdb_t
class struct_sdb_ns_t(Structure):
    pass

struct_sdb_ns_t._pack_ = 1 # source:False
struct_sdb_ns_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('hash', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('sdb', ctypes.POINTER(struct_sdb_t)),
]

SdbNs = struct_sdb_ns_t
try:
    sdb_new0 = _libr_anal.sdb_new0
    sdb_new0.restype = ctypes.POINTER(struct_sdb_t)
    sdb_new0.argtypes = []
except AttributeError:
    pass
try:
    sdb_new = _libr_anal.sdb_new
    sdb_new.restype = ctypes.POINTER(struct_sdb_t)
    sdb_new.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    sdb_open = _libr_anal.sdb_open
    sdb_open.restype = ctypes.c_int32
    sdb_open.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_open_gperf = _libr_anal.sdb_open_gperf
    sdb_open_gperf.restype = ctypes.c_int32
    sdb_open_gperf.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(struct_sdb_gperf_t)]
except AttributeError:
    pass
try:
    sdb_close = _libr_anal.sdb_close
    sdb_close.restype = None
    sdb_close.argtypes = [ctypes.POINTER(struct_sdb_t)]
except AttributeError:
    pass
try:
    sdb_config = _libr_anal.sdb_config
    sdb_config.restype = None
    sdb_config.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    sdb_free = _libr_anal.sdb_free
    sdb_free.restype = ctypes.c_bool
    sdb_free.argtypes = [ctypes.POINTER(struct_sdb_t)]
except AttributeError:
    pass
try:
    sdb_file = _libr_anal.sdb_file
    sdb_file.restype = None
    sdb_file.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_merge = _libr_anal.sdb_merge
    sdb_merge.restype = ctypes.c_bool
    sdb_merge.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(struct_sdb_t)]
except AttributeError:
    pass
try:
    sdb_count = _libr_anal.sdb_count
    sdb_count.restype = ctypes.c_int32
    sdb_count.argtypes = [ctypes.POINTER(struct_sdb_t)]
except AttributeError:
    pass
try:
    sdb_reset = _libr_anal.sdb_reset
    sdb_reset.restype = None
    sdb_reset.argtypes = [ctypes.POINTER(struct_sdb_t)]
except AttributeError:
    pass
try:
    sdb_setup = _libraries['FIXME_STUB'].sdb_setup
    sdb_setup.restype = None
    sdb_setup.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    sdb_drain = _libr_anal.sdb_drain
    sdb_drain.restype = None
    sdb_drain.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(struct_sdb_t)]
except AttributeError:
    pass
try:
    sdb_copy = _libr_anal.sdb_copy
    sdb_copy.restype = None
    sdb_copy.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(struct_sdb_t)]
except AttributeError:
    pass
try:
    sdb_stats = _libr_anal.sdb_stats
    sdb_stats.restype = ctypes.c_bool
    sdb_stats.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    sdb_dump_hasnext = _libr_anal.sdb_dump_hasnext
    sdb_dump_hasnext.restype = ctypes.c_bool
    sdb_dump_hasnext.argtypes = [ctypes.POINTER(struct_sdb_t)]
except AttributeError:
    pass
SdbForeachCallback = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char))
try:
    sdb_foreach = _libr_anal.sdb_foreach
    sdb_foreach.restype = ctypes.c_bool
    sdb_foreach.argtypes = [ctypes.POINTER(struct_sdb_t), SdbForeachCallback, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    sdb_foreach_list = _libr_anal.sdb_foreach_list
    sdb_foreach_list.restype = ctypes.POINTER(struct_ls_t)
    sdb_foreach_list.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.c_bool]
except AttributeError:
    pass
try:
    sdb_foreach_list_filter = _libr_anal.sdb_foreach_list_filter
    sdb_foreach_list_filter.restype = ctypes.POINTER(struct_ls_t)
    sdb_foreach_list_filter.argtypes = [ctypes.POINTER(struct_sdb_t), SdbForeachCallback, ctypes.c_bool]
except AttributeError:
    pass
try:
    sdb_foreach_match = _libr_anal.sdb_foreach_match
    sdb_foreach_match.restype = ctypes.POINTER(struct_ls_t)
    sdb_foreach_match.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.c_bool]
except AttributeError:
    pass
try:
    sdb_query = _libr_anal.sdb_query
    sdb_query.restype = ctypes.c_bool
    sdb_query.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_queryf = _libr_anal.sdb_queryf
    sdb_queryf.restype = ctypes.c_int32
    sdb_queryf.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_query_lines = _libr_anal.sdb_query_lines
    sdb_query_lines.restype = ctypes.c_int32
    sdb_query_lines.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_querys = _libr_anal.sdb_querys
    sdb_querys.restype = ctypes.POINTER(ctypes.c_char)
    sdb_querys.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_querysf = _libr_anal.sdb_querysf
    sdb_querysf.restype = ctypes.POINTER(ctypes.c_char)
    sdb_querysf.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_query_file = _libr_anal.sdb_query_file
    sdb_query_file.restype = ctypes.c_int32
    sdb_query_file.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_exists = _libr_anal.sdb_exists
    sdb_exists.restype = ctypes.c_bool
    sdb_exists.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_remove = _libr_anal.sdb_remove
    sdb_remove.restype = ctypes.c_bool
    sdb_remove.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), uint32_t]
except AttributeError:
    pass
try:
    sdb_unset = _libr_anal.sdb_unset
    sdb_unset.restype = ctypes.c_int32
    sdb_unset.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), uint32_t]
except AttributeError:
    pass
try:
    sdb_nunset = _libr_anal.sdb_nunset
    sdb_nunset.restype = ctypes.c_int32
    sdb_nunset.argtypes = [ctypes.POINTER(struct_sdb_t), uint64_t, uint32_t]
except AttributeError:
    pass
try:
    sdb_unset_like = _libr_anal.sdb_unset_like
    sdb_unset_like.restype = ctypes.c_int32
    sdb_unset_like.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_like = _libr_anal.sdb_like
    sdb_like.restype = ctypes.POINTER(ctypes.POINTER(ctypes.c_char))
    sdb_like.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), SdbForeachCallback]
except AttributeError:
    pass
class struct_sdb_diff_t(Structure):
    pass

struct_sdb_diff_t._pack_ = 1 # source:False
struct_sdb_diff_t._fields_ = [
    ('path', ctypes.POINTER(struct_ls_t)),
    ('k', ctypes.POINTER(ctypes.c_char)),
    ('v', ctypes.POINTER(ctypes.c_char)),
    ('add', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
]

SdbDiff = struct_sdb_diff_t
try:
    sdb_diff_format = _libr_anal.sdb_diff_format
    sdb_diff_format.restype = ctypes.c_int32
    sdb_diff_format.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(struct_sdb_diff_t)]
except AttributeError:
    pass
SdbDiffCallback = ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_sdb_diff_t), ctypes.POINTER(None))
try:
    sdb_diff = _libr_anal.sdb_diff
    sdb_diff.restype = ctypes.c_bool
    sdb_diff.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(struct_sdb_t), SdbDiffCallback, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    sdb_get = _libr_anal.sdb_get
    sdb_get.restype = ctypes.POINTER(ctypes.c_char)
    sdb_get.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    sdb_nget = _libr_anal.sdb_nget
    sdb_nget.restype = ctypes.POINTER(ctypes.c_char)
    sdb_nget.argtypes = [ctypes.POINTER(struct_sdb_t), uint64_t, ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    sdb_get_len = _libr_anal.sdb_get_len
    sdb_get_len.restype = ctypes.POINTER(ctypes.c_char)
    sdb_get_len.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    sdb_const_get = _libr_anal.sdb_const_get
    sdb_const_get.restype = ctypes.POINTER(ctypes.c_char)
    sdb_const_get.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    sdb_const_get_len = _libr_anal.sdb_const_get_len
    sdb_const_get_len.restype = ctypes.POINTER(ctypes.c_char)
    sdb_const_get_len.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    sdb_set = _libr_anal.sdb_set
    sdb_set.restype = ctypes.c_int32
    sdb_set.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), uint32_t]
except AttributeError:
    pass
try:
    sdb_nset = _libr_anal.sdb_nset
    sdb_nset.restype = ctypes.c_int32
    sdb_nset.argtypes = [ctypes.POINTER(struct_sdb_t), uint64_t, ctypes.POINTER(ctypes.c_char), uint32_t]
except AttributeError:
    pass
try:
    sdb_num_nget = _libr_anal.sdb_num_nget
    sdb_num_nget.restype = uint64_t
    sdb_num_nget.argtypes = [ctypes.POINTER(struct_sdb_t), uint64_t, ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    sdb_num_nset = _libr_anal.sdb_num_nset
    sdb_num_nset.restype = ctypes.c_int32
    sdb_num_nset.argtypes = [ctypes.POINTER(struct_sdb_t), uint64_t, uint64_t, uint32_t]
except AttributeError:
    pass
try:
    sdb_set_owned = _libr_anal.sdb_set_owned
    sdb_set_owned.restype = ctypes.c_int32
    sdb_set_owned.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), uint32_t]
except AttributeError:
    pass
try:
    sdb_concat = _libr_anal.sdb_concat
    sdb_concat.restype = ctypes.c_int32
    sdb_concat.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), uint32_t]
except AttributeError:
    pass
try:
    sdb_uncat = _libr_anal.sdb_uncat
    sdb_uncat.restype = ctypes.c_int32
    sdb_uncat.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), uint32_t]
except AttributeError:
    pass
try:
    sdb_add = _libr_anal.sdb_add
    sdb_add.restype = ctypes.c_int32
    sdb_add.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), uint32_t]
except AttributeError:
    pass
try:
    sdb_nadd = _libr_anal.sdb_nadd
    sdb_nadd.restype = ctypes.c_int32
    sdb_nadd.argtypes = [ctypes.POINTER(struct_sdb_t), uint64_t, ctypes.POINTER(ctypes.c_char), uint32_t]
except AttributeError:
    pass
try:
    sdb_sync = _libr_anal.sdb_sync
    sdb_sync.restype = ctypes.c_bool
    sdb_sync.argtypes = [ctypes.POINTER(struct_sdb_t)]
except AttributeError:
    pass
try:
    sdb_num_exists = _libr_anal.sdb_num_exists
    sdb_num_exists.restype = ctypes.c_bool
    sdb_num_exists.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_num_base = _libr_anal.sdb_num_base
    sdb_num_base.restype = ctypes.c_int32
    sdb_num_base.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_num_get = _libr_anal.sdb_num_get
    sdb_num_get.restype = uint64_t
    sdb_num_get.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    sdb_num_set = _libr_anal.sdb_num_set
    sdb_num_set.restype = ctypes.c_int32
    sdb_num_set.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), uint64_t, uint32_t]
except AttributeError:
    pass
try:
    sdb_num_add = _libr_anal.sdb_num_add
    sdb_num_add.restype = ctypes.c_int32
    sdb_num_add.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), uint64_t, uint32_t]
except AttributeError:
    pass
try:
    sdb_num_inc = _libr_anal.sdb_num_inc
    sdb_num_inc.restype = uint64_t
    sdb_num_inc.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), uint64_t, uint32_t]
except AttributeError:
    pass
try:
    sdb_num_dec = _libr_anal.sdb_num_dec
    sdb_num_dec.restype = uint64_t
    sdb_num_dec.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), uint64_t, uint32_t]
except AttributeError:
    pass
try:
    sdb_num_min = _libr_anal.sdb_num_min
    sdb_num_min.restype = ctypes.c_int32
    sdb_num_min.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), uint64_t, uint32_t]
except AttributeError:
    pass
try:
    sdb_num_max = _libr_anal.sdb_num_max
    sdb_num_max.restype = ctypes.c_int32
    sdb_num_max.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), uint64_t, uint32_t]
except AttributeError:
    pass
try:
    sdb_ptr_set = _libr_anal.sdb_ptr_set
    sdb_ptr_set.restype = ctypes.c_int32
    sdb_ptr_set.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), uint32_t]
except AttributeError:
    pass
try:
    sdb_ptr_get = _libr_anal.sdb_ptr_get
    sdb_ptr_get.restype = ctypes.POINTER(None)
    sdb_ptr_get.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    sdb_disk_create = _libr_anal.sdb_disk_create
    sdb_disk_create.restype = ctypes.c_bool
    sdb_disk_create.argtypes = [ctypes.POINTER(struct_sdb_t)]
except AttributeError:
    pass
try:
    sdb_disk_insert = _libr_anal.sdb_disk_insert
    sdb_disk_insert.restype = ctypes.c_bool
    sdb_disk_insert.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_disk_finish = _libr_anal.sdb_disk_finish
    sdb_disk_finish.restype = ctypes.c_bool
    sdb_disk_finish.argtypes = [ctypes.POINTER(struct_sdb_t)]
except AttributeError:
    pass
try:
    sdb_disk_unlink = _libr_anal.sdb_disk_unlink
    sdb_disk_unlink.restype = ctypes.c_bool
    sdb_disk_unlink.argtypes = [ctypes.POINTER(struct_sdb_t)]
except AttributeError:
    pass
try:
    sdb_text_save_fd = _libr_anal.sdb_text_save_fd
    sdb_text_save_fd.restype = ctypes.c_bool
    sdb_text_save_fd.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.c_int32, ctypes.c_bool]
except AttributeError:
    pass
try:
    sdb_text_save = _libr_anal.sdb_text_save
    sdb_text_save.restype = ctypes.c_bool
    sdb_text_save.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.c_bool]
except AttributeError:
    pass
try:
    sdb_text_load_buf = _libr_anal.sdb_text_load_buf
    sdb_text_load_buf.restype = ctypes.c_bool
    sdb_text_load_buf.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    sdb_text_load = _libr_anal.sdb_text_load
    sdb_text_load.restype = ctypes.c_bool
    sdb_text_load.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_text_check = _libr_anal.sdb_text_check
    sdb_text_check.restype = ctypes.c_bool
    sdb_text_check.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_dump_begin = _libr_anal.sdb_dump_begin
    sdb_dump_begin.restype = None
    sdb_dump_begin.argtypes = [ctypes.POINTER(struct_sdb_t)]
except AttributeError:
    pass
try:
    sdb_dump_next = _libr_anal.sdb_dump_next
    sdb_dump_next.restype = ctypes.POINTER(struct_sdb_kv)
    sdb_dump_next.argtypes = [ctypes.POINTER(struct_sdb_t)]
except AttributeError:
    pass
try:
    sdb_dump_dupnext = _libr_anal.sdb_dump_dupnext
    sdb_dump_dupnext.restype = ctypes.c_bool
    sdb_dump_dupnext.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    sdb_journal_close = _libr_anal.sdb_journal_close
    sdb_journal_close.restype = ctypes.c_bool
    sdb_journal_close.argtypes = [ctypes.POINTER(struct_sdb_t)]
except AttributeError:
    pass
try:
    sdb_journal_open = _libr_anal.sdb_journal_open
    sdb_journal_open.restype = ctypes.c_bool
    sdb_journal_open.argtypes = [ctypes.POINTER(struct_sdb_t)]
except AttributeError:
    pass
try:
    sdb_journal_load = _libr_anal.sdb_journal_load
    sdb_journal_load.restype = ctypes.c_int32
    sdb_journal_load.argtypes = [ctypes.POINTER(struct_sdb_t)]
except AttributeError:
    pass
try:
    sdb_journal_log = _libr_anal.sdb_journal_log
    sdb_journal_log.restype = ctypes.c_bool
    sdb_journal_log.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_journal_clear = _libr_anal.sdb_journal_clear
    sdb_journal_clear.restype = ctypes.c_bool
    sdb_journal_clear.argtypes = [ctypes.POINTER(struct_sdb_t)]
except AttributeError:
    pass
try:
    sdb_journal_unlink = _libr_anal.sdb_journal_unlink
    sdb_journal_unlink.restype = ctypes.c_bool
    sdb_journal_unlink.argtypes = [ctypes.POINTER(struct_sdb_t)]
except AttributeError:
    pass
try:
    sdb_itoa = _libr_anal.sdb_itoa
    sdb_itoa.restype = ctypes.POINTER(ctypes.c_char)
    sdb_itoa.argtypes = [uint64_t, ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    sdb_itoas = _libr_anal.sdb_itoas
    sdb_itoas.restype = ctypes.POINTER(ctypes.c_char)
    sdb_itoas.argtypes = [uint64_t, ctypes.c_int32]
except AttributeError:
    pass
try:
    sdb_atoi = _libr_anal.sdb_atoi
    sdb_atoi.restype = uint64_t
    sdb_atoi.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_lock = _libr_anal.sdb_lock
    sdb_lock.restype = ctypes.c_bool
    sdb_lock.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_lock_file = _libr_anal.sdb_lock_file
    sdb_lock_file.restype = ctypes.c_bool
    sdb_lock_file.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    sdb_unlock = _libr_anal.sdb_unlock
    sdb_unlock.restype = None
    sdb_unlock.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_unlink = _libr_anal.sdb_unlink
    sdb_unlink.restype = ctypes.c_bool
    sdb_unlink.argtypes = [ctypes.POINTER(struct_sdb_t)]
except AttributeError:
    pass
try:
    sdb_lock_wait = _libr_anal.sdb_lock_wait
    sdb_lock_wait.restype = ctypes.c_int32
    sdb_lock_wait.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_expire_set = _libr_anal.sdb_expire_set
    sdb_expire_set.restype = ctypes.c_bool
    sdb_expire_set.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), uint64_t, uint32_t]
except AttributeError:
    pass
try:
    sdb_expire_get = _libr_anal.sdb_expire_get
    sdb_expire_get.restype = uint64_t
    sdb_expire_get.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    sdb_now = _libr_anal.sdb_now
    sdb_now.restype = uint64_t
    sdb_now.argtypes = []
except AttributeError:
    pass
try:
    sdb_unow = _libr_anal.sdb_unow
    sdb_unow.restype = uint64_t
    sdb_unow.argtypes = []
except AttributeError:
    pass
try:
    sdb_hash_len = _libr_anal.sdb_hash_len
    sdb_hash_len.restype = uint32_t
    sdb_hash_len.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    sdb_hash_byte = _libr_anal.sdb_hash_byte
    sdb_hash_byte.restype = uint8_t
    sdb_hash_byte.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_isjson = _libr_anal.sdb_isjson
    sdb_isjson.restype = ctypes.c_bool
    sdb_isjson.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_json_get_str = _libr_anal.sdb_json_get_str
    sdb_json_get_str.restype = ctypes.POINTER(ctypes.c_char)
    sdb_json_get_str.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_json_get_bool = _libr_anal.sdb_json_get_bool
    sdb_json_get_bool.restype = ctypes.c_bool
    sdb_json_get_bool.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_json_get = _libr_anal.sdb_json_get
    sdb_json_get.restype = ctypes.POINTER(ctypes.c_char)
    sdb_json_get.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    sdb_json_set = _libr_anal.sdb_json_set
    sdb_json_set.restype = ctypes.c_bool
    sdb_json_set.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), uint32_t]
except AttributeError:
    pass
try:
    sdb_json_num_get = _libr_anal.sdb_json_num_get
    sdb_json_num_get.restype = ctypes.c_int32
    sdb_json_num_get.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    sdb_json_num_set = _libr_anal.sdb_json_num_set
    sdb_json_num_set.restype = ctypes.c_int32
    sdb_json_num_set.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, uint32_t]
except AttributeError:
    pass
try:
    sdb_json_num_dec = _libr_anal.sdb_json_num_dec
    sdb_json_num_dec.restype = ctypes.c_int32
    sdb_json_num_dec.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, uint32_t]
except AttributeError:
    pass
try:
    sdb_json_num_inc = _libr_anal.sdb_json_num_inc
    sdb_json_num_inc.restype = ctypes.c_int32
    sdb_json_num_inc.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, uint32_t]
except AttributeError:
    pass
try:
    sdb_json_indent = _libr_anal.sdb_json_indent
    sdb_json_indent.restype = ctypes.POINTER(ctypes.c_char)
    sdb_json_indent.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_json_unindent = _libr_anal.sdb_json_unindent
    sdb_json_unindent.restype = ctypes.POINTER(ctypes.c_char)
    sdb_json_unindent.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
class struct_SdbJsonString(Structure):
    pass

struct_SdbJsonString._pack_ = 1 # source:False
struct_SdbJsonString._fields_ = [
    ('buf', ctypes.POINTER(ctypes.c_char)),
    ('blen', ctypes.c_uint64),
    ('len', ctypes.c_uint64),
]

SdbJsonString = struct_SdbJsonString
try:
    sdb_json_format = _libr_anal.sdb_json_format
    sdb_json_format.restype = ctypes.POINTER(ctypes.c_char)
    sdb_json_format.argtypes = [ctypes.POINTER(struct_SdbJsonString), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_ns = _libr_anal.sdb_ns
    sdb_ns.restype = ctypes.POINTER(struct_sdb_t)
    sdb_ns.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    sdb_ns_path = _libr_anal.sdb_ns_path
    sdb_ns_path.restype = ctypes.POINTER(struct_sdb_t)
    sdb_ns_path.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    sdb_ns_init = _libraries['FIXME_STUB'].sdb_ns_init
    sdb_ns_init.restype = None
    sdb_ns_init.argtypes = [ctypes.POINTER(struct_sdb_t)]
except AttributeError:
    pass
try:
    sdb_ns_free = _libr_anal.sdb_ns_free
    sdb_ns_free.restype = None
    sdb_ns_free.argtypes = [ctypes.POINTER(struct_sdb_t)]
except AttributeError:
    pass
try:
    sdb_ns_lock = _libr_anal.sdb_ns_lock
    sdb_ns_lock.restype = None
    sdb_ns_lock.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    sdb_ns_sync = _libr_anal.sdb_ns_sync
    sdb_ns_sync.restype = None
    sdb_ns_sync.argtypes = [ctypes.POINTER(struct_sdb_t)]
except AttributeError:
    pass
try:
    sdb_ns_set = _libr_anal.sdb_ns_set
    sdb_ns_set.restype = ctypes.c_int32
    sdb_ns_set.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_sdb_t)]
except AttributeError:
    pass
try:
    sdb_ns_unset = _libr_anal.sdb_ns_unset
    sdb_ns_unset.restype = ctypes.c_bool
    sdb_ns_unset.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_sdb_t)]
except AttributeError:
    pass
try:
    sdb_array_contains = _libr_anal.sdb_array_contains
    sdb_array_contains.restype = ctypes.c_bool
    sdb_array_contains.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    sdb_array_contains_num = _libr_anal.sdb_array_contains_num
    sdb_array_contains_num.restype = ctypes.c_bool
    sdb_array_contains_num.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), uint64_t, ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    sdb_array_indexof = _libr_anal.sdb_array_indexof
    sdb_array_indexof.restype = ctypes.c_int32
    sdb_array_indexof.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), uint32_t]
except AttributeError:
    pass
try:
    sdb_array_set = _libr_anal.sdb_array_set
    sdb_array_set.restype = ctypes.c_int32
    sdb_array_set.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(ctypes.c_char), uint32_t]
except AttributeError:
    pass
try:
    sdb_array_set_num = _libr_anal.sdb_array_set_num
    sdb_array_set_num.restype = ctypes.c_int32
    sdb_array_set_num.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, uint64_t, uint32_t]
except AttributeError:
    pass
try:
    sdb_array_append = _libr_anal.sdb_array_append
    sdb_array_append.restype = ctypes.c_bool
    sdb_array_append.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), uint32_t]
except AttributeError:
    pass
try:
    sdb_array_append_num = _libr_anal.sdb_array_append_num
    sdb_array_append_num.restype = ctypes.c_bool
    sdb_array_append_num.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), uint64_t, uint32_t]
except AttributeError:
    pass
try:
    sdb_array_prepend = _libr_anal.sdb_array_prepend
    sdb_array_prepend.restype = ctypes.c_bool
    sdb_array_prepend.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), uint32_t]
except AttributeError:
    pass
try:
    sdb_array_prepend_num = _libr_anal.sdb_array_prepend_num
    sdb_array_prepend_num.restype = ctypes.c_bool
    sdb_array_prepend_num.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), uint64_t, uint32_t]
except AttributeError:
    pass
try:
    sdb_array_get = _libr_anal.sdb_array_get
    sdb_array_get.restype = ctypes.POINTER(ctypes.c_char)
    sdb_array_get.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    sdb_array_get_num = _libr_anal.sdb_array_get_num
    sdb_array_get_num.restype = uint64_t
    sdb_array_get_num.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    sdb_array_get_idx = _libraries['FIXME_STUB'].sdb_array_get_idx
    sdb_array_get_idx.restype = ctypes.c_int32
    sdb_array_get_idx.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), uint32_t]
except AttributeError:
    pass
try:
    sdb_array_insert = _libr_anal.sdb_array_insert
    sdb_array_insert.restype = ctypes.c_int32
    sdb_array_insert.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(ctypes.c_char), uint32_t]
except AttributeError:
    pass
try:
    sdb_array_insert_num = _libr_anal.sdb_array_insert_num
    sdb_array_insert_num.restype = ctypes.c_int32
    sdb_array_insert_num.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, uint64_t, uint32_t]
except AttributeError:
    pass
try:
    sdb_array_unset = _libr_anal.sdb_array_unset
    sdb_array_unset.restype = ctypes.c_int32
    sdb_array_unset.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, uint32_t]
except AttributeError:
    pass
try:
    sdb_array_delete = _libr_anal.sdb_array_delete
    sdb_array_delete.restype = ctypes.c_int32
    sdb_array_delete.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, uint32_t]
except AttributeError:
    pass
try:
    sdb_array_sort = _libr_anal.sdb_array_sort
    sdb_array_sort.restype = None
    sdb_array_sort.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), uint32_t]
except AttributeError:
    pass
try:
    sdb_array_sort_num = _libr_anal.sdb_array_sort_num
    sdb_array_sort_num.restype = None
    sdb_array_sort_num.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), uint32_t]
except AttributeError:
    pass
try:
    sdb_array_add = _libr_anal.sdb_array_add
    sdb_array_add.restype = ctypes.c_int32
    sdb_array_add.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), uint32_t]
except AttributeError:
    pass
try:
    sdb_array_add_num = _libr_anal.sdb_array_add_num
    sdb_array_add_num.restype = ctypes.c_int32
    sdb_array_add_num.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), uint64_t, uint32_t]
except AttributeError:
    pass
try:
    sdb_array_add_sorted = _libr_anal.sdb_array_add_sorted
    sdb_array_add_sorted.restype = ctypes.c_int32
    sdb_array_add_sorted.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), uint32_t]
except AttributeError:
    pass
try:
    sdb_array_add_sorted_num = _libr_anal.sdb_array_add_sorted_num
    sdb_array_add_sorted_num.restype = ctypes.c_int32
    sdb_array_add_sorted_num.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), uint64_t, uint32_t]
except AttributeError:
    pass
try:
    sdb_array_remove = _libr_anal.sdb_array_remove
    sdb_array_remove.restype = ctypes.c_int32
    sdb_array_remove.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), uint32_t]
except AttributeError:
    pass
try:
    sdb_array_remove_num = _libr_anal.sdb_array_remove_num
    sdb_array_remove_num.restype = ctypes.c_int32
    sdb_array_remove_num.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), uint64_t, uint32_t]
except AttributeError:
    pass
try:
    sdb_anext = _libr_anal.sdb_anext
    sdb_anext.restype = ctypes.POINTER(ctypes.c_char)
    sdb_anext.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
except AttributeError:
    pass
try:
    sdb_const_anext = _libr_anal.sdb_const_anext
    sdb_const_anext.restype = ctypes.POINTER(ctypes.c_char)
    sdb_const_anext.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_alen = _libr_anal.sdb_alen
    sdb_alen.restype = ctypes.c_int32
    sdb_alen.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_alen_ignore_empty = _libr_anal.sdb_alen_ignore_empty
    sdb_alen_ignore_empty.restype = ctypes.c_int32
    sdb_alen_ignore_empty.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_array_size = _libr_anal.sdb_array_size
    sdb_array_size.restype = ctypes.c_int32
    sdb_array_size.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_array_length = _libr_anal.sdb_array_length
    sdb_array_length.restype = ctypes.c_int32
    sdb_array_length.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_array_list = _libraries['FIXME_STUB'].sdb_array_list
    sdb_array_list.restype = ctypes.c_int32
    sdb_array_list.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_array_push = _libr_anal.sdb_array_push
    sdb_array_push.restype = ctypes.c_bool
    sdb_array_push.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), uint32_t]
except AttributeError:
    pass
try:
    sdb_array_pop = _libr_anal.sdb_array_pop
    sdb_array_pop.restype = ctypes.POINTER(ctypes.c_char)
    sdb_array_pop.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    sdb_array_push_num = _libr_anal.sdb_array_push_num
    sdb_array_push_num.restype = ctypes.c_int32
    sdb_array_push_num.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), uint64_t, uint32_t]
except AttributeError:
    pass
try:
    sdb_array_pop_num = _libr_anal.sdb_array_pop_num
    sdb_array_pop_num.restype = uint64_t
    sdb_array_pop_num.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    sdb_array_pop_head = _libr_anal.sdb_array_pop_head
    sdb_array_pop_head.restype = ctypes.POINTER(ctypes.c_char)
    sdb_array_pop_head.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    sdb_array_pop_tail = _libr_anal.sdb_array_pop_tail
    sdb_array_pop_tail.restype = ctypes.POINTER(ctypes.c_char)
    sdb_array_pop_tail.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
SdbHook = ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_sdb_t), ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char))
try:
    sdb_hook = _libr_anal.sdb_hook
    sdb_hook.restype = ctypes.c_bool
    sdb_hook.argtypes = [ctypes.POINTER(struct_sdb_t), SdbHook, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    sdb_unhook = _libr_anal.sdb_unhook
    sdb_unhook.restype = ctypes.c_bool
    sdb_unhook.argtypes = [ctypes.POINTER(struct_sdb_t), SdbHook]
except AttributeError:
    pass
try:
    sdb_hook_call = _libr_anal.sdb_hook_call
    sdb_hook_call.restype = ctypes.c_int32
    sdb_hook_call.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_hook_free = _libr_anal.sdb_hook_free
    sdb_hook_free.restype = None
    sdb_hook_free.argtypes = [ctypes.POINTER(struct_sdb_t)]
except AttributeError:
    pass
try:
    sdb_isnum = _libr_anal.sdb_isnum
    sdb_isnum.restype = ctypes.c_int32
    sdb_isnum.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_isempty = _libr_anal.sdb_isempty
    sdb_isempty.restype = ctypes.c_bool
    sdb_isempty.argtypes = [ctypes.POINTER(struct_sdb_t)]
except AttributeError:
    pass
try:
    sdb_type = _libr_anal.sdb_type
    sdb_type.restype = ctypes.POINTER(ctypes.c_char)
    sdb_type.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_match = _libr_anal.sdb_match
    sdb_match.restype = ctypes.c_bool
    sdb_match.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_bool_set = _libr_anal.sdb_bool_set
    sdb_bool_set.restype = ctypes.c_int32
    sdb_bool_set.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.c_bool, uint32_t]
except AttributeError:
    pass
try:
    sdb_bool_get = _libr_anal.sdb_bool_get
    sdb_bool_get.restype = ctypes.c_bool
    sdb_bool_get.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    sdb_decode = _libr_anal.sdb_decode
    sdb_decode.restype = ctypes.POINTER(ctypes.c_ubyte)
    sdb_decode.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    sdb_encode = _libr_anal.sdb_encode
    sdb_encode.restype = ctypes.POINTER(ctypes.c_char)
    sdb_encode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    sdb_encode_raw = _libr_anal.sdb_encode_raw
    sdb_encode_raw.restype = None
    sdb_encode_raw.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    sdb_decode_raw = _libr_anal.sdb_decode_raw
    sdb_decode_raw.restype = ctypes.c_int32
    sdb_decode_raw.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    sdb_fmt_init = _libr_anal.sdb_fmt_init
    sdb_fmt_init.restype = ctypes.c_int32
    sdb_fmt_init.argtypes = [ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_fmt_free = _libr_anal.sdb_fmt_free
    sdb_fmt_free.restype = None
    sdb_fmt_free.argtypes = [ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_fmt_tobin = _libr_anal.sdb_fmt_tobin
    sdb_fmt_tobin.restype = ctypes.c_int32
    sdb_fmt_tobin.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    sdb_fmt_tostr = _libr_anal.sdb_fmt_tostr
    sdb_fmt_tostr.restype = ctypes.POINTER(ctypes.c_char)
    sdb_fmt_tostr.argtypes = [ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_fmt_array = _libr_anal.sdb_fmt_array
    sdb_fmt_array.restype = ctypes.POINTER(ctypes.POINTER(ctypes.c_char))
    sdb_fmt_array.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_fmt_array_num = _libr_anal.sdb_fmt_array_num
    sdb_fmt_array_num.restype = ctypes.POINTER(ctypes.c_uint64)
    sdb_fmt_array_num.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_array_compact = _libr_anal.sdb_array_compact
    sdb_array_compact.restype = ctypes.POINTER(ctypes.c_char)
    sdb_array_compact.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sdb_aslice = _libr_anal.sdb_aslice
    sdb_aslice.restype = ctypes.POINTER(ctypes.c_char)
    sdb_aslice.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
RListFree = ctypes.CFUNCTYPE(None, ctypes.POINTER(None))
class struct_r_list_iter_t(Structure):
    pass

struct_r_list_iter_t._pack_ = 1 # source:False
struct_r_list_iter_t._fields_ = [
    ('data', ctypes.POINTER(None)),
    ('n', ctypes.POINTER(struct_r_list_iter_t)),
    ('p', ctypes.POINTER(struct_r_list_iter_t)),
]

RListIter = struct_r_list_iter_t
class struct_r_list_t(Structure):
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

RList = struct_r_list_t
class struct_r_list_range_t(Structure):
    pass

struct_r_list_range_t._pack_ = 1 # source:False
struct_r_list_range_t._fields_ = [
    ('h', ctypes.POINTER(struct_ht_pp_t)),
    ('l', ctypes.POINTER(struct_r_list_t)),
]

RListRange = struct_r_list_range_t
RListComparator = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(None))
RListComparatorItem = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(None))
try:
    r_list_new = _libr_util.r_list_new
    r_list_new.restype = ctypes.POINTER(struct_r_list_t)
    r_list_new.argtypes = []
except AttributeError:
    pass
try:
    r_list_newf = _libr_util.r_list_newf
    r_list_newf.restype = ctypes.POINTER(struct_r_list_t)
    r_list_newf.argtypes = [RListFree]
except AttributeError:
    pass
try:
    r_list_iter_get_next = _libr_util.r_list_iter_get_next
    r_list_iter_get_next.restype = ctypes.POINTER(struct_r_list_iter_t)
    r_list_iter_get_next.argtypes = [ctypes.POINTER(struct_r_list_iter_t)]
except AttributeError:
    pass
try:
    r_list_iter_get_prev = _libr_util.r_list_iter_get_prev
    r_list_iter_get_prev.restype = ctypes.POINTER(struct_r_list_iter_t)
    r_list_iter_get_prev.argtypes = [ctypes.POINTER(struct_r_list_iter_t)]
except AttributeError:
    pass
try:
    r_list_set_n = _libr_util.r_list_set_n
    r_list_set_n.restype = ctypes.c_int32
    r_list_set_n.argtypes = [ctypes.POINTER(struct_r_list_t), ctypes.c_int32, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_list_iter_get_data = _libr_util.r_list_iter_get_data
    r_list_iter_get_data.restype = ctypes.POINTER(None)
    r_list_iter_get_data.argtypes = [ctypes.POINTER(struct_r_list_iter_t)]
except AttributeError:
    pass
try:
    r_list_append = _libr_util.r_list_append
    r_list_append.restype = ctypes.POINTER(struct_r_list_iter_t)
    r_list_append.argtypes = [ctypes.POINTER(struct_r_list_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_list_prepend = _libr_util.r_list_prepend
    r_list_prepend.restype = ctypes.POINTER(struct_r_list_iter_t)
    r_list_prepend.argtypes = [ctypes.POINTER(struct_r_list_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_list_insert = _libr_util.r_list_insert
    r_list_insert.restype = ctypes.POINTER(struct_r_list_iter_t)
    r_list_insert.argtypes = [ctypes.POINTER(struct_r_list_t), uint32_t, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_list_length = _libr_util.r_list_length
    r_list_length.restype = ctypes.c_int32
    r_list_length.argtypes = [ctypes.POINTER(struct_r_list_t)]
except AttributeError:
    pass
try:
    r_list_iter_length = _libr_util.r_list_iter_length
    r_list_iter_length.restype = size_t
    r_list_iter_length.argtypes = [ctypes.POINTER(struct_r_list_iter_t)]
except AttributeError:
    pass
try:
    r_list_first = _libr_util.r_list_first
    r_list_first.restype = ctypes.POINTER(None)
    r_list_first.argtypes = [ctypes.POINTER(struct_r_list_t)]
except AttributeError:
    pass
try:
    r_list_last = _libr_util.r_list_last
    r_list_last.restype = ctypes.POINTER(None)
    r_list_last.argtypes = [ctypes.POINTER(struct_r_list_t)]
except AttributeError:
    pass
try:
    r_list_add_sorted = _libr_util.r_list_add_sorted
    r_list_add_sorted.restype = ctypes.POINTER(struct_r_list_iter_t)
    r_list_add_sorted.argtypes = [ctypes.POINTER(struct_r_list_t), ctypes.POINTER(None), RListComparator]
except AttributeError:
    pass
try:
    r_list_sort = _libr_util.r_list_sort
    r_list_sort.restype = None
    r_list_sort.argtypes = [ctypes.POINTER(struct_r_list_t), RListComparator]
except AttributeError:
    pass
try:
    r_list_merge_sort = _libr_util.r_list_merge_sort
    r_list_merge_sort.restype = None
    r_list_merge_sort.argtypes = [ctypes.POINTER(struct_r_list_t), RListComparator]
except AttributeError:
    pass
try:
    r_list_insertion_sort = _libr_util.r_list_insertion_sort
    r_list_insertion_sort.restype = None
    r_list_insertion_sort.argtypes = [ctypes.POINTER(struct_r_list_t), RListComparator]
except AttributeError:
    pass
try:
    r_list_uniq = _libr_util.r_list_uniq
    r_list_uniq.restype = ctypes.POINTER(struct_r_list_t)
    r_list_uniq.argtypes = [ctypes.POINTER(struct_r_list_t), RListComparatorItem]
except AttributeError:
    pass
try:
    r_list_uniq_inplace = _libr_util.r_list_uniq_inplace
    r_list_uniq_inplace.restype = ctypes.c_int32
    r_list_uniq_inplace.argtypes = [ctypes.POINTER(struct_r_list_t), RListComparatorItem]
except AttributeError:
    pass
try:
    r_list_init = _libr_util.r_list_init
    r_list_init.restype = None
    r_list_init.argtypes = [ctypes.POINTER(struct_r_list_t)]
except AttributeError:
    pass
try:
    r_list_delete = _libr_util.r_list_delete
    r_list_delete.restype = None
    r_list_delete.argtypes = [ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_list_iter_t)]
except AttributeError:
    pass
try:
    r_list_delete_data = _libr_util.r_list_delete_data
    r_list_delete_data.restype = ctypes.c_bool
    r_list_delete_data.argtypes = [ctypes.POINTER(struct_r_list_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_list_iter_init = _libraries['FIXME_STUB'].r_list_iter_init
    r_list_iter_init.restype = None
    r_list_iter_init.argtypes = [ctypes.POINTER(struct_r_list_iter_t), ctypes.POINTER(struct_r_list_t)]
except AttributeError:
    pass
try:
    r_list_purge = _libr_util.r_list_purge
    r_list_purge.restype = None
    r_list_purge.argtypes = [ctypes.POINTER(struct_r_list_t)]
except AttributeError:
    pass
try:
    r_list_free = _libr_util.r_list_free
    r_list_free.restype = None
    r_list_free.argtypes = [ctypes.POINTER(struct_r_list_t)]
except AttributeError:
    pass
try:
    r_list_item_new = _libr_util.r_list_item_new
    r_list_item_new.restype = ctypes.POINTER(struct_r_list_iter_t)
    r_list_item_new.argtypes = [ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_list_split = _libr_util.r_list_split
    r_list_split.restype = None
    r_list_split.argtypes = [ctypes.POINTER(struct_r_list_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_list_split_iter = _libr_util.r_list_split_iter
    r_list_split_iter.restype = None
    r_list_split_iter.argtypes = [ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_list_iter_t)]
except AttributeError:
    pass
try:
    r_list_join = _libr_util.r_list_join
    r_list_join.restype = ctypes.c_int32
    r_list_join.argtypes = [ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_list_t)]
except AttributeError:
    pass
try:
    r_list_get_n = _libr_util.r_list_get_n
    r_list_get_n.restype = ctypes.POINTER(None)
    r_list_get_n.argtypes = [ctypes.POINTER(struct_r_list_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_list_del_n = _libr_util.r_list_del_n
    r_list_del_n.restype = ctypes.c_int32
    r_list_del_n.argtypes = [ctypes.POINTER(struct_r_list_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_list_get_top = _libr_util.r_list_get_top
    r_list_get_top.restype = ctypes.POINTER(None)
    r_list_get_top.argtypes = [ctypes.POINTER(struct_r_list_t)]
except AttributeError:
    pass
try:
    r_list_get_bottom = _libr_util.r_list_get_bottom
    r_list_get_bottom.restype = ctypes.POINTER(None)
    r_list_get_bottom.argtypes = [ctypes.POINTER(struct_r_list_t)]
except AttributeError:
    pass
try:
    r_list_iter_to_top = _libr_util.r_list_iter_to_top
    r_list_iter_to_top.restype = None
    r_list_iter_to_top.argtypes = [ctypes.POINTER(struct_r_list_t), ctypes.POINTER(struct_r_list_iter_t)]
except AttributeError:
    pass
try:
    r_list_pop = _libr_util.r_list_pop
    r_list_pop.restype = ctypes.POINTER(None)
    r_list_pop.argtypes = [ctypes.POINTER(struct_r_list_t)]
except AttributeError:
    pass
try:
    r_list_pop_head = _libr_util.r_list_pop_head
    r_list_pop_head.restype = ctypes.POINTER(None)
    r_list_pop_head.argtypes = [ctypes.POINTER(struct_r_list_t)]
except AttributeError:
    pass
try:
    r_list_reverse = _libr_util.r_list_reverse
    r_list_reverse.restype = None
    r_list_reverse.argtypes = [ctypes.POINTER(struct_r_list_t)]
except AttributeError:
    pass
try:
    r_list_clone = _libr_util.r_list_clone
    r_list_clone.restype = ctypes.POINTER(struct_r_list_t)
    r_list_clone.argtypes = [ctypes.POINTER(struct_r_list_t)]
except AttributeError:
    pass
try:
    r_list_to_str = _libr_util.r_list_to_str
    r_list_to_str.restype = ctypes.POINTER(ctypes.c_char)
    r_list_to_str.argtypes = [ctypes.POINTER(struct_r_list_t), ctypes.c_char]
except AttributeError:
    pass
try:
    r_list_contains = _libr_util.r_list_contains
    r_list_contains.restype = ctypes.POINTER(struct_r_list_iter_t)
    r_list_contains.argtypes = [ctypes.POINTER(struct_r_list_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_list_find = _libr_util.r_list_find
    r_list_find.restype = ctypes.POINTER(struct_r_list_iter_t)
    r_list_find.argtypes = [ctypes.POINTER(struct_r_list_t), ctypes.POINTER(None), RListComparator]
except AttributeError:
    pass
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
try:
    r_regex_run = _libraries['FIXME_STUB'].r_regex_run
    r_regex_run.restype = ctypes.c_int32
    r_regex_run.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_regex_match = _libr_util.r_regex_match
    r_regex_match.restype = ctypes.c_bool
    r_regex_match.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_regex_flags = _libr_util.r_regex_flags
    r_regex_flags.restype = ctypes.c_int32
    r_regex_flags.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_regex_new = _libr_util.r_regex_new
    r_regex_new.restype = ctypes.POINTER(struct_r_regex_t)
    r_regex_new.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_regex_free = _libr_util.r_regex_free
    r_regex_free.restype = None
    r_regex_free.argtypes = [ctypes.POINTER(struct_r_regex_t)]
except AttributeError:
    pass
try:
    r_regex_init = _libr_util.r_regex_init
    r_regex_init.restype = ctypes.c_int32
    r_regex_init.argtypes = [ctypes.POINTER(struct_r_regex_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_regex_fini = _libr_util.r_regex_fini
    r_regex_fini.restype = None
    r_regex_fini.argtypes = [ctypes.POINTER(struct_r_regex_t)]
except AttributeError:
    pass
try:
    r_regex_check = _libr_util.r_regex_check
    r_regex_check.restype = ctypes.c_bool
    r_regex_check.argtypes = [ctypes.POINTER(struct_r_regex_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_regex_exec = _libr_util.r_regex_exec
    r_regex_exec.restype = ctypes.c_int32
    r_regex_exec.argtypes = [ctypes.POINTER(struct_r_regex_t), ctypes.POINTER(ctypes.c_char), size_t, struct_r_regmatch_t * 0, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_regex_match_list = _libr_util.r_regex_match_list
    r_regex_match_list.restype = ctypes.POINTER(struct_r_list_t)
    r_regex_match_list.argtypes = [ctypes.POINTER(struct_r_regex_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_regex_error = _libr_util.r_regex_error
    r_regex_error.restype = ctypes.POINTER(ctypes.c_char)
    r_regex_error.argtypes = [ctypes.POINTER(struct_r_regex_t), ctypes.c_int32]
except AttributeError:
    pass
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
try:
    r_getopt_init = _libr_util.r_getopt_init
    r_getopt_init.restype = None
    r_getopt_init.argtypes = [ctypes.POINTER(struct_r_getopt_t), ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_getopt_next = _libr_util.r_getopt_next
    r_getopt_next.restype = ctypes.c_int32
    r_getopt_next.argtypes = [ctypes.POINTER(struct_r_getopt_t)]
except AttributeError:
    pass
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
try:
    r_skiplist_new = _libr_util.r_skiplist_new
    r_skiplist_new.restype = ctypes.POINTER(struct_r_skiplist_t)
    r_skiplist_new.argtypes = [RListFree, RListComparator]
except AttributeError:
    pass
try:
    r_skiplist_free = _libr_util.r_skiplist_free
    r_skiplist_free.restype = None
    r_skiplist_free.argtypes = [ctypes.POINTER(struct_r_skiplist_t)]
except AttributeError:
    pass
try:
    r_skiplist_purge = _libr_util.r_skiplist_purge
    r_skiplist_purge.restype = None
    r_skiplist_purge.argtypes = [ctypes.POINTER(struct_r_skiplist_t)]
except AttributeError:
    pass
try:
    r_skiplist_insert = _libr_util.r_skiplist_insert
    r_skiplist_insert.restype = ctypes.POINTER(struct_r_skiplist_node_t)
    r_skiplist_insert.argtypes = [ctypes.POINTER(struct_r_skiplist_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_skiplist_insert_autofree = _libr_util.r_skiplist_insert_autofree
    r_skiplist_insert_autofree.restype = ctypes.c_bool
    r_skiplist_insert_autofree.argtypes = [ctypes.POINTER(struct_r_skiplist_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_skiplist_delete = _libr_util.r_skiplist_delete
    r_skiplist_delete.restype = ctypes.c_bool
    r_skiplist_delete.argtypes = [ctypes.POINTER(struct_r_skiplist_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_skiplist_delete_node = _libr_util.r_skiplist_delete_node
    r_skiplist_delete_node.restype = ctypes.c_bool
    r_skiplist_delete_node.argtypes = [ctypes.POINTER(struct_r_skiplist_t), ctypes.POINTER(struct_r_skiplist_node_t)]
except AttributeError:
    pass
try:
    r_skiplist_find = _libr_util.r_skiplist_find
    r_skiplist_find.restype = ctypes.POINTER(struct_r_skiplist_node_t)
    r_skiplist_find.argtypes = [ctypes.POINTER(struct_r_skiplist_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_skiplist_find_geq = _libr_util.r_skiplist_find_geq
    r_skiplist_find_geq.restype = ctypes.POINTER(struct_r_skiplist_node_t)
    r_skiplist_find_geq.argtypes = [ctypes.POINTER(struct_r_skiplist_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_skiplist_find_leq = _libr_util.r_skiplist_find_leq
    r_skiplist_find_leq.restype = ctypes.POINTER(struct_r_skiplist_node_t)
    r_skiplist_find_leq.argtypes = [ctypes.POINTER(struct_r_skiplist_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_skiplist_join = _libr_util.r_skiplist_join
    r_skiplist_join.restype = None
    r_skiplist_join.argtypes = [ctypes.POINTER(struct_r_skiplist_t), ctypes.POINTER(struct_r_skiplist_t)]
except AttributeError:
    pass
try:
    r_skiplist_get_first = _libr_util.r_skiplist_get_first
    r_skiplist_get_first.restype = ctypes.POINTER(None)
    r_skiplist_get_first.argtypes = [ctypes.POINTER(struct_r_skiplist_t)]
except AttributeError:
    pass
try:
    r_skiplist_get_n = _libr_util.r_skiplist_get_n
    r_skiplist_get_n.restype = ctypes.POINTER(None)
    r_skiplist_get_n.argtypes = [ctypes.POINTER(struct_r_skiplist_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_skiplist_get_geq = _libr_util.r_skiplist_get_geq
    r_skiplist_get_geq.restype = ctypes.POINTER(None)
    r_skiplist_get_geq.argtypes = [ctypes.POINTER(struct_r_skiplist_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_skiplist_get_leq = _libr_util.r_skiplist_get_leq
    r_skiplist_get_leq.restype = ctypes.POINTER(None)
    r_skiplist_get_leq.argtypes = [ctypes.POINTER(struct_r_skiplist_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_skiplist_empty = _libr_util.r_skiplist_empty
    r_skiplist_empty.restype = ctypes.c_bool
    r_skiplist_empty.argtypes = [ctypes.POINTER(struct_r_skiplist_t)]
except AttributeError:
    pass
try:
    r_skiplist_to_list = _libr_util.r_skiplist_to_list
    r_skiplist_to_list.restype = ctypes.POINTER(struct_r_list_t)
    r_skiplist_to_list.argtypes = [ctypes.POINTER(struct_r_skiplist_t)]
except AttributeError:
    pass
class union_sem_t(Union):
    pass

union_sem_t._pack_ = 1 # source:False
union_sem_t._fields_ = [
    ('__size', ctypes.c_char * 32),
    ('__align', ctypes.c_int64),
    ('PADDING_0', ctypes.c_ubyte * 24),
]

sem_t = union_sem_t
try:
    sem_init = _libraries['FIXME_STUB'].sem_init
    sem_init.restype = ctypes.c_int32
    sem_init.argtypes = [ctypes.POINTER(union_sem_t), ctypes.c_int32, ctypes.c_uint32]
except AttributeError:
    pass
try:
    sem_destroy = _libraries['FIXME_STUB'].sem_destroy
    sem_destroy.restype = ctypes.c_int32
    sem_destroy.argtypes = [ctypes.POINTER(union_sem_t)]
except AttributeError:
    pass
try:
    sem_open = _libraries['FIXME_STUB'].sem_open
    sem_open.restype = ctypes.POINTER(union_sem_t)
    sem_open.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    sem_close = _libraries['FIXME_STUB'].sem_close
    sem_close.restype = ctypes.c_int32
    sem_close.argtypes = [ctypes.POINTER(union_sem_t)]
except AttributeError:
    pass
try:
    sem_unlink = _libraries['FIXME_STUB'].sem_unlink
    sem_unlink.restype = ctypes.c_int32
    sem_unlink.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sem_wait = _libraries['FIXME_STUB'].sem_wait
    sem_wait.restype = ctypes.c_int32
    sem_wait.argtypes = [ctypes.POINTER(union_sem_t)]
except AttributeError:
    pass
try:
    sem_timedwait = _libraries['FIXME_STUB'].sem_timedwait
    sem_timedwait.restype = ctypes.c_int32
    sem_timedwait.argtypes = [ctypes.POINTER(union_sem_t), ctypes.POINTER(struct_timespec)]
except AttributeError:
    pass
try:
    sem_trywait = _libraries['FIXME_STUB'].sem_trywait
    sem_trywait.restype = ctypes.c_int32
    sem_trywait.argtypes = [ctypes.POINTER(union_sem_t)]
except AttributeError:
    pass
try:
    sem_post = _libraries['FIXME_STUB'].sem_post
    sem_post.restype = ctypes.c_int32
    sem_post.argtypes = [ctypes.POINTER(union_sem_t)]
except AttributeError:
    pass
try:
    sem_getvalue = _libraries['FIXME_STUB'].sem_getvalue
    sem_getvalue.restype = ctypes.c_int32
    sem_getvalue.argtypes = [ctypes.POINTER(union_sem_t), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
class struct_sched_param(Structure):
    pass

struct_sched_param._pack_ = 1 # source:False
struct_sched_param._fields_ = [
    ('sched_priority', ctypes.c_int32),
]

__cpu_mask = ctypes.c_uint64
class struct_cpu_set_t(Structure):
    pass

struct_cpu_set_t._pack_ = 1 # source:False
struct_cpu_set_t._fields_ = [
    ('__bits', ctypes.c_uint64 * 16),
]

cpu_set_t = struct_cpu_set_t
try:
    __sched_cpucount = _libraries['FIXME_STUB'].__sched_cpucount
    __sched_cpucount.restype = ctypes.c_int32
    __sched_cpucount.argtypes = [size_t, ctypes.POINTER(struct_cpu_set_t)]
except AttributeError:
    pass
try:
    __sched_cpualloc = _libraries['FIXME_STUB'].__sched_cpualloc
    __sched_cpualloc.restype = ctypes.POINTER(struct_cpu_set_t)
    __sched_cpualloc.argtypes = [size_t]
except AttributeError:
    pass
try:
    __sched_cpufree = _libraries['FIXME_STUB'].__sched_cpufree
    __sched_cpufree.restype = None
    __sched_cpufree.argtypes = [ctypes.POINTER(struct_cpu_set_t)]
except AttributeError:
    pass
try:
    sched_setparam = _libraries['FIXME_STUB'].sched_setparam
    sched_setparam.restype = ctypes.c_int32
    sched_setparam.argtypes = [__pid_t, ctypes.POINTER(struct_sched_param)]
except AttributeError:
    pass
try:
    sched_getparam = _libraries['FIXME_STUB'].sched_getparam
    sched_getparam.restype = ctypes.c_int32
    sched_getparam.argtypes = [__pid_t, ctypes.POINTER(struct_sched_param)]
except AttributeError:
    pass
try:
    sched_setscheduler = _libraries['FIXME_STUB'].sched_setscheduler
    sched_setscheduler.restype = ctypes.c_int32
    sched_setscheduler.argtypes = [__pid_t, ctypes.c_int32, ctypes.POINTER(struct_sched_param)]
except AttributeError:
    pass
try:
    sched_getscheduler = _libraries['FIXME_STUB'].sched_getscheduler
    sched_getscheduler.restype = ctypes.c_int32
    sched_getscheduler.argtypes = [__pid_t]
except AttributeError:
    pass
try:
    sched_yield = _libraries['FIXME_STUB'].sched_yield
    sched_yield.restype = ctypes.c_int32
    sched_yield.argtypes = []
except AttributeError:
    pass
try:
    sched_get_priority_max = _libraries['FIXME_STUB'].sched_get_priority_max
    sched_get_priority_max.restype = ctypes.c_int32
    sched_get_priority_max.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    sched_get_priority_min = _libraries['FIXME_STUB'].sched_get_priority_min
    sched_get_priority_min.restype = ctypes.c_int32
    sched_get_priority_min.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    sched_rr_get_interval = _libraries['FIXME_STUB'].sched_rr_get_interval
    sched_rr_get_interval.restype = ctypes.c_int32
    sched_rr_get_interval.argtypes = [__pid_t, ctypes.POINTER(struct_timespec)]
except AttributeError:
    pass
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

class struct_itimerspec(Structure):
    _pack_ = 1 # source:False
    _fields_ = [
    ('it_interval', struct_timespec),
    ('it_value', struct_timespec),
     ]

try:
    clock = _libraries['FIXME_STUB'].clock
    clock.restype = clock_t
    clock.argtypes = []
except AttributeError:
    pass
try:
    time = _libraries['FIXME_STUB'].time
    time.restype = time_t
    time.argtypes = [ctypes.POINTER(ctypes.c_int64)]
except AttributeError:
    pass
try:
    difftime = _libraries['FIXME_STUB'].difftime
    difftime.restype = ctypes.c_double
    difftime.argtypes = [time_t, time_t]
except AttributeError:
    pass
try:
    mktime = _libraries['FIXME_STUB'].mktime
    mktime.restype = time_t
    mktime.argtypes = [ctypes.POINTER(struct_tm)]
except AttributeError:
    pass
try:
    strftime = _libraries['FIXME_STUB'].strftime
    strftime.restype = size_t
    strftime.argtypes = [ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_tm)]
except AttributeError:
    pass
try:
    strftime_l = _libraries['FIXME_STUB'].strftime_l
    strftime_l.restype = size_t
    strftime_l.argtypes = [ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_tm), locale_t]
except AttributeError:
    pass
try:
    gmtime = _libraries['FIXME_STUB'].gmtime
    gmtime.restype = ctypes.POINTER(struct_tm)
    gmtime.argtypes = [ctypes.POINTER(ctypes.c_int64)]
except AttributeError:
    pass
try:
    localtime = _libraries['FIXME_STUB'].localtime
    localtime.restype = ctypes.POINTER(struct_tm)
    localtime.argtypes = [ctypes.POINTER(ctypes.c_int64)]
except AttributeError:
    pass
try:
    gmtime_r = _libraries['FIXME_STUB'].gmtime_r
    gmtime_r.restype = ctypes.POINTER(struct_tm)
    gmtime_r.argtypes = [ctypes.POINTER(ctypes.c_int64), ctypes.POINTER(struct_tm)]
except AttributeError:
    pass
try:
    localtime_r = _libraries['FIXME_STUB'].localtime_r
    localtime_r.restype = ctypes.POINTER(struct_tm)
    localtime_r.argtypes = [ctypes.POINTER(ctypes.c_int64), ctypes.POINTER(struct_tm)]
except AttributeError:
    pass
try:
    asctime = _libraries['FIXME_STUB'].asctime
    asctime.restype = ctypes.POINTER(ctypes.c_char)
    asctime.argtypes = [ctypes.POINTER(struct_tm)]
except AttributeError:
    pass
try:
    ctime = _libraries['FIXME_STUB'].ctime
    ctime.restype = ctypes.POINTER(ctypes.c_char)
    ctime.argtypes = [ctypes.POINTER(ctypes.c_int64)]
except AttributeError:
    pass
try:
    asctime_r = _libraries['FIXME_STUB'].asctime_r
    asctime_r.restype = ctypes.POINTER(ctypes.c_char)
    asctime_r.argtypes = [ctypes.POINTER(struct_tm), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    ctime_r = _libraries['FIXME_STUB'].ctime_r
    ctime_r.restype = ctypes.POINTER(ctypes.c_char)
    ctime_r.argtypes = [ctypes.POINTER(ctypes.c_int64), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
__tzname = [] # Variable ctypes.POINTER(ctypes.c_char) * 2
__daylight = 0 # Variable ctypes.c_int32
__timezone = 0 # Variable ctypes.c_int64
tzname = [] # Variable ctypes.POINTER(ctypes.c_char) * 2
try:
    tzset = _libraries['FIXME_STUB'].tzset
    tzset.restype = None
    tzset.argtypes = []
except AttributeError:
    pass
daylight = 0 # Variable ctypes.c_int32
timezone = 0 # Variable ctypes.c_int64
try:
    timegm = _libraries['FIXME_STUB'].timegm
    timegm.restype = time_t
    timegm.argtypes = [ctypes.POINTER(struct_tm)]
except AttributeError:
    pass
try:
    timelocal = _libraries['FIXME_STUB'].timelocal
    timelocal.restype = time_t
    timelocal.argtypes = [ctypes.POINTER(struct_tm)]
except AttributeError:
    pass
try:
    dysize = _libraries['FIXME_STUB'].dysize
    dysize.restype = ctypes.c_int32
    dysize.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    nanosleep = _libraries['FIXME_STUB'].nanosleep
    nanosleep.restype = ctypes.c_int32
    nanosleep.argtypes = [ctypes.POINTER(struct_timespec), ctypes.POINTER(struct_timespec)]
except AttributeError:
    pass
try:
    clock_getres = _libraries['FIXME_STUB'].clock_getres
    clock_getres.restype = ctypes.c_int32
    clock_getres.argtypes = [clockid_t, ctypes.POINTER(struct_timespec)]
except AttributeError:
    pass
try:
    clock_gettime = _libraries['FIXME_STUB'].clock_gettime
    clock_gettime.restype = ctypes.c_int32
    clock_gettime.argtypes = [clockid_t, ctypes.POINTER(struct_timespec)]
except AttributeError:
    pass
try:
    clock_settime = _libraries['FIXME_STUB'].clock_settime
    clock_settime.restype = ctypes.c_int32
    clock_settime.argtypes = [clockid_t, ctypes.POINTER(struct_timespec)]
except AttributeError:
    pass
try:
    clock_nanosleep = _libraries['FIXME_STUB'].clock_nanosleep
    clock_nanosleep.restype = ctypes.c_int32
    clock_nanosleep.argtypes = [clockid_t, ctypes.c_int32, ctypes.POINTER(struct_timespec), ctypes.POINTER(struct_timespec)]
except AttributeError:
    pass
try:
    clock_getcpuclockid = _libraries['FIXME_STUB'].clock_getcpuclockid
    clock_getcpuclockid.restype = ctypes.c_int32
    clock_getcpuclockid.argtypes = [pid_t, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
class struct_sigevent(Structure):
    pass

try:
    timer_create = _libraries['FIXME_STUB'].timer_create
    timer_create.restype = ctypes.c_int32
    timer_create.argtypes = [clockid_t, ctypes.POINTER(struct_sigevent), ctypes.POINTER(ctypes.POINTER(None))]
except AttributeError:
    pass
try:
    timer_delete = _libraries['FIXME_STUB'].timer_delete
    timer_delete.restype = ctypes.c_int32
    timer_delete.argtypes = [timer_t]
except AttributeError:
    pass
try:
    timer_settime = _libraries['FIXME_STUB'].timer_settime
    timer_settime.restype = ctypes.c_int32
    timer_settime.argtypes = [timer_t, ctypes.c_int32, ctypes.POINTER(struct_itimerspec), ctypes.POINTER(struct_itimerspec)]
except AttributeError:
    pass
try:
    timer_gettime = _libraries['FIXME_STUB'].timer_gettime
    timer_gettime.restype = ctypes.c_int32
    timer_gettime.argtypes = [timer_t, ctypes.POINTER(struct_itimerspec)]
except AttributeError:
    pass
try:
    timer_getoverrun = _libraries['FIXME_STUB'].timer_getoverrun
    timer_getoverrun.restype = ctypes.c_int32
    timer_getoverrun.argtypes = [timer_t]
except AttributeError:
    pass
try:
    timespec_get = _libraries['FIXME_STUB'].timespec_get
    timespec_get.restype = ctypes.c_int32
    timespec_get.argtypes = [ctypes.POINTER(struct_timespec), ctypes.c_int32]
except AttributeError:
    pass
__jmp_buf = ctypes.c_int64 * 8
class struct___jmp_buf_tag(Structure):
    pass

struct___jmp_buf_tag._pack_ = 1 # source:False
struct___jmp_buf_tag._fields_ = [
    ('__jmpbuf', ctypes.c_int64 * 8),
    ('__mask_was_saved', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('__saved_mask', globals()['__sigset_t']),
]


# values for enumeration 'c__Ea_PTHREAD_CREATE_JOINABLE'
c__Ea_PTHREAD_CREATE_JOINABLE__enumvalues = {
    0: 'PTHREAD_CREATE_JOINABLE',
    1: 'PTHREAD_CREATE_DETACHED',
}
PTHREAD_CREATE_JOINABLE = 0
PTHREAD_CREATE_DETACHED = 1
c__Ea_PTHREAD_CREATE_JOINABLE = ctypes.c_uint32 # enum

# values for enumeration 'c__Ea_PTHREAD_MUTEX_TIMED_NP'
c__Ea_PTHREAD_MUTEX_TIMED_NP__enumvalues = {
    0: 'PTHREAD_MUTEX_TIMED_NP',
    1: 'PTHREAD_MUTEX_RECURSIVE_NP',
    2: 'PTHREAD_MUTEX_ERRORCHECK_NP',
    3: 'PTHREAD_MUTEX_ADAPTIVE_NP',
    0: 'PTHREAD_MUTEX_NORMAL',
    1: 'PTHREAD_MUTEX_RECURSIVE',
    2: 'PTHREAD_MUTEX_ERRORCHECK',
    0: 'PTHREAD_MUTEX_DEFAULT',
}
PTHREAD_MUTEX_TIMED_NP = 0
PTHREAD_MUTEX_RECURSIVE_NP = 1
PTHREAD_MUTEX_ERRORCHECK_NP = 2
PTHREAD_MUTEX_ADAPTIVE_NP = 3
PTHREAD_MUTEX_NORMAL = 0
PTHREAD_MUTEX_RECURSIVE = 1
PTHREAD_MUTEX_ERRORCHECK = 2
PTHREAD_MUTEX_DEFAULT = 0
c__Ea_PTHREAD_MUTEX_TIMED_NP = ctypes.c_uint32 # enum

# values for enumeration 'c__Ea_PTHREAD_MUTEX_STALLED'
c__Ea_PTHREAD_MUTEX_STALLED__enumvalues = {
    0: 'PTHREAD_MUTEX_STALLED',
    0: 'PTHREAD_MUTEX_STALLED_NP',
    1: 'PTHREAD_MUTEX_ROBUST',
    1: 'PTHREAD_MUTEX_ROBUST_NP',
}
PTHREAD_MUTEX_STALLED = 0
PTHREAD_MUTEX_STALLED_NP = 0
PTHREAD_MUTEX_ROBUST = 1
PTHREAD_MUTEX_ROBUST_NP = 1
c__Ea_PTHREAD_MUTEX_STALLED = ctypes.c_uint32 # enum

# values for enumeration 'c__Ea_PTHREAD_PRIO_NONE'
c__Ea_PTHREAD_PRIO_NONE__enumvalues = {
    0: 'PTHREAD_PRIO_NONE',
    1: 'PTHREAD_PRIO_INHERIT',
    2: 'PTHREAD_PRIO_PROTECT',
}
PTHREAD_PRIO_NONE = 0
PTHREAD_PRIO_INHERIT = 1
PTHREAD_PRIO_PROTECT = 2
c__Ea_PTHREAD_PRIO_NONE = ctypes.c_uint32 # enum

# values for enumeration 'c__Ea_PTHREAD_RWLOCK_PREFER_READER_NP'
c__Ea_PTHREAD_RWLOCK_PREFER_READER_NP__enumvalues = {
    0: 'PTHREAD_RWLOCK_PREFER_READER_NP',
    1: 'PTHREAD_RWLOCK_PREFER_WRITER_NP',
    2: 'PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP',
    0: 'PTHREAD_RWLOCK_DEFAULT_NP',
}
PTHREAD_RWLOCK_PREFER_READER_NP = 0
PTHREAD_RWLOCK_PREFER_WRITER_NP = 1
PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP = 2
PTHREAD_RWLOCK_DEFAULT_NP = 0
c__Ea_PTHREAD_RWLOCK_PREFER_READER_NP = ctypes.c_uint32 # enum

# values for enumeration 'c__Ea_PTHREAD_INHERIT_SCHED'
c__Ea_PTHREAD_INHERIT_SCHED__enumvalues = {
    0: 'PTHREAD_INHERIT_SCHED',
    1: 'PTHREAD_EXPLICIT_SCHED',
}
PTHREAD_INHERIT_SCHED = 0
PTHREAD_EXPLICIT_SCHED = 1
c__Ea_PTHREAD_INHERIT_SCHED = ctypes.c_uint32 # enum

# values for enumeration 'c__Ea_PTHREAD_SCOPE_SYSTEM'
c__Ea_PTHREAD_SCOPE_SYSTEM__enumvalues = {
    0: 'PTHREAD_SCOPE_SYSTEM',
    1: 'PTHREAD_SCOPE_PROCESS',
}
PTHREAD_SCOPE_SYSTEM = 0
PTHREAD_SCOPE_PROCESS = 1
c__Ea_PTHREAD_SCOPE_SYSTEM = ctypes.c_uint32 # enum

# values for enumeration 'c__Ea_PTHREAD_PROCESS_PRIVATE'
c__Ea_PTHREAD_PROCESS_PRIVATE__enumvalues = {
    0: 'PTHREAD_PROCESS_PRIVATE',
    1: 'PTHREAD_PROCESS_SHARED',
}
PTHREAD_PROCESS_PRIVATE = 0
PTHREAD_PROCESS_SHARED = 1
c__Ea_PTHREAD_PROCESS_PRIVATE = ctypes.c_uint32 # enum
class struct__pthread_cleanup_buffer(Structure):
    pass

struct__pthread_cleanup_buffer._pack_ = 1 # source:False
struct__pthread_cleanup_buffer._fields_ = [
    ('__routine', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
    ('__arg', ctypes.POINTER(None)),
    ('__canceltype', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('__prev', ctypes.POINTER(struct__pthread_cleanup_buffer)),
]


# values for enumeration 'c__Ea_PTHREAD_CANCEL_ENABLE'
c__Ea_PTHREAD_CANCEL_ENABLE__enumvalues = {
    0: 'PTHREAD_CANCEL_ENABLE',
    1: 'PTHREAD_CANCEL_DISABLE',
}
PTHREAD_CANCEL_ENABLE = 0
PTHREAD_CANCEL_DISABLE = 1
c__Ea_PTHREAD_CANCEL_ENABLE = ctypes.c_uint32 # enum

# values for enumeration 'c__Ea_PTHREAD_CANCEL_DEFERRED'
c__Ea_PTHREAD_CANCEL_DEFERRED__enumvalues = {
    0: 'PTHREAD_CANCEL_DEFERRED',
    1: 'PTHREAD_CANCEL_ASYNCHRONOUS',
}
PTHREAD_CANCEL_DEFERRED = 0
PTHREAD_CANCEL_ASYNCHRONOUS = 1
c__Ea_PTHREAD_CANCEL_DEFERRED = ctypes.c_uint32 # enum
try:
    pthread_create = _libraries['FIXME_STUB'].pthread_create
    pthread_create.restype = ctypes.c_int32
    pthread_create.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(union_pthread_attr_t), ctypes.CFUNCTYPE(ctypes.POINTER(None), ctypes.POINTER(None)), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    pthread_exit = _libraries['FIXME_STUB'].pthread_exit
    pthread_exit.restype = None
    pthread_exit.argtypes = [ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    pthread_join = _libraries['FIXME_STUB'].pthread_join
    pthread_join.restype = ctypes.c_int32
    pthread_join.argtypes = [pthread_t, ctypes.POINTER(ctypes.POINTER(None))]
except AttributeError:
    pass
try:
    pthread_detach = _libraries['FIXME_STUB'].pthread_detach
    pthread_detach.restype = ctypes.c_int32
    pthread_detach.argtypes = [pthread_t]
except AttributeError:
    pass
try:
    pthread_self = _libraries['FIXME_STUB'].pthread_self
    pthread_self.restype = pthread_t
    pthread_self.argtypes = []
except AttributeError:
    pass
try:
    pthread_equal = _libraries['FIXME_STUB'].pthread_equal
    pthread_equal.restype = ctypes.c_int32
    pthread_equal.argtypes = [pthread_t, pthread_t]
except AttributeError:
    pass
try:
    pthread_attr_init = _libraries['FIXME_STUB'].pthread_attr_init
    pthread_attr_init.restype = ctypes.c_int32
    pthread_attr_init.argtypes = [ctypes.POINTER(union_pthread_attr_t)]
except AttributeError:
    pass
try:
    pthread_attr_destroy = _libraries['FIXME_STUB'].pthread_attr_destroy
    pthread_attr_destroy.restype = ctypes.c_int32
    pthread_attr_destroy.argtypes = [ctypes.POINTER(union_pthread_attr_t)]
except AttributeError:
    pass
try:
    pthread_attr_getdetachstate = _libraries['FIXME_STUB'].pthread_attr_getdetachstate
    pthread_attr_getdetachstate.restype = ctypes.c_int32
    pthread_attr_getdetachstate.argtypes = [ctypes.POINTER(union_pthread_attr_t), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    pthread_attr_setdetachstate = _libraries['FIXME_STUB'].pthread_attr_setdetachstate
    pthread_attr_setdetachstate.restype = ctypes.c_int32
    pthread_attr_setdetachstate.argtypes = [ctypes.POINTER(union_pthread_attr_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    pthread_attr_getguardsize = _libraries['FIXME_STUB'].pthread_attr_getguardsize
    pthread_attr_getguardsize.restype = ctypes.c_int32
    pthread_attr_getguardsize.argtypes = [ctypes.POINTER(union_pthread_attr_t), ctypes.POINTER(ctypes.c_uint64)]
except AttributeError:
    pass
try:
    pthread_attr_setguardsize = _libraries['FIXME_STUB'].pthread_attr_setguardsize
    pthread_attr_setguardsize.restype = ctypes.c_int32
    pthread_attr_setguardsize.argtypes = [ctypes.POINTER(union_pthread_attr_t), size_t]
except AttributeError:
    pass
try:
    pthread_attr_getschedparam = _libraries['FIXME_STUB'].pthread_attr_getschedparam
    pthread_attr_getschedparam.restype = ctypes.c_int32
    pthread_attr_getschedparam.argtypes = [ctypes.POINTER(union_pthread_attr_t), ctypes.POINTER(struct_sched_param)]
except AttributeError:
    pass
try:
    pthread_attr_setschedparam = _libraries['FIXME_STUB'].pthread_attr_setschedparam
    pthread_attr_setschedparam.restype = ctypes.c_int32
    pthread_attr_setschedparam.argtypes = [ctypes.POINTER(union_pthread_attr_t), ctypes.POINTER(struct_sched_param)]
except AttributeError:
    pass
try:
    pthread_attr_getschedpolicy = _libraries['FIXME_STUB'].pthread_attr_getschedpolicy
    pthread_attr_getschedpolicy.restype = ctypes.c_int32
    pthread_attr_getschedpolicy.argtypes = [ctypes.POINTER(union_pthread_attr_t), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    pthread_attr_setschedpolicy = _libraries['FIXME_STUB'].pthread_attr_setschedpolicy
    pthread_attr_setschedpolicy.restype = ctypes.c_int32
    pthread_attr_setschedpolicy.argtypes = [ctypes.POINTER(union_pthread_attr_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    pthread_attr_getinheritsched = _libraries['FIXME_STUB'].pthread_attr_getinheritsched
    pthread_attr_getinheritsched.restype = ctypes.c_int32
    pthread_attr_getinheritsched.argtypes = [ctypes.POINTER(union_pthread_attr_t), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    pthread_attr_setinheritsched = _libraries['FIXME_STUB'].pthread_attr_setinheritsched
    pthread_attr_setinheritsched.restype = ctypes.c_int32
    pthread_attr_setinheritsched.argtypes = [ctypes.POINTER(union_pthread_attr_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    pthread_attr_getscope = _libraries['FIXME_STUB'].pthread_attr_getscope
    pthread_attr_getscope.restype = ctypes.c_int32
    pthread_attr_getscope.argtypes = [ctypes.POINTER(union_pthread_attr_t), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    pthread_attr_setscope = _libraries['FIXME_STUB'].pthread_attr_setscope
    pthread_attr_setscope.restype = ctypes.c_int32
    pthread_attr_setscope.argtypes = [ctypes.POINTER(union_pthread_attr_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    pthread_attr_getstackaddr = _libraries['FIXME_STUB'].pthread_attr_getstackaddr
    pthread_attr_getstackaddr.restype = ctypes.c_int32
    pthread_attr_getstackaddr.argtypes = [ctypes.POINTER(union_pthread_attr_t), ctypes.POINTER(ctypes.POINTER(None))]
except AttributeError:
    pass
try:
    pthread_attr_setstackaddr = _libraries['FIXME_STUB'].pthread_attr_setstackaddr
    pthread_attr_setstackaddr.restype = ctypes.c_int32
    pthread_attr_setstackaddr.argtypes = [ctypes.POINTER(union_pthread_attr_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    pthread_attr_getstacksize = _libraries['FIXME_STUB'].pthread_attr_getstacksize
    pthread_attr_getstacksize.restype = ctypes.c_int32
    pthread_attr_getstacksize.argtypes = [ctypes.POINTER(union_pthread_attr_t), ctypes.POINTER(ctypes.c_uint64)]
except AttributeError:
    pass
try:
    pthread_attr_setstacksize = _libraries['FIXME_STUB'].pthread_attr_setstacksize
    pthread_attr_setstacksize.restype = ctypes.c_int32
    pthread_attr_setstacksize.argtypes = [ctypes.POINTER(union_pthread_attr_t), size_t]
except AttributeError:
    pass
try:
    pthread_attr_getstack = _libraries['FIXME_STUB'].pthread_attr_getstack
    pthread_attr_getstack.restype = ctypes.c_int32
    pthread_attr_getstack.argtypes = [ctypes.POINTER(union_pthread_attr_t), ctypes.POINTER(ctypes.POINTER(None)), ctypes.POINTER(ctypes.c_uint64)]
except AttributeError:
    pass
try:
    pthread_attr_setstack = _libraries['FIXME_STUB'].pthread_attr_setstack
    pthread_attr_setstack.restype = ctypes.c_int32
    pthread_attr_setstack.argtypes = [ctypes.POINTER(union_pthread_attr_t), ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    pthread_setschedparam = _libraries['FIXME_STUB'].pthread_setschedparam
    pthread_setschedparam.restype = ctypes.c_int32
    pthread_setschedparam.argtypes = [pthread_t, ctypes.c_int32, ctypes.POINTER(struct_sched_param)]
except AttributeError:
    pass
try:
    pthread_getschedparam = _libraries['FIXME_STUB'].pthread_getschedparam
    pthread_getschedparam.restype = ctypes.c_int32
    pthread_getschedparam.argtypes = [pthread_t, ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(struct_sched_param)]
except AttributeError:
    pass
try:
    pthread_setschedprio = _libraries['FIXME_STUB'].pthread_setschedprio
    pthread_setschedprio.restype = ctypes.c_int32
    pthread_setschedprio.argtypes = [pthread_t, ctypes.c_int32]
except AttributeError:
    pass
try:
    pthread_once = _libraries['FIXME_STUB'].pthread_once
    pthread_once.restype = ctypes.c_int32
    pthread_once.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.CFUNCTYPE(None)]
except AttributeError:
    pass
try:
    pthread_setcancelstate = _libraries['FIXME_STUB'].pthread_setcancelstate
    pthread_setcancelstate.restype = ctypes.c_int32
    pthread_setcancelstate.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    pthread_setcanceltype = _libraries['FIXME_STUB'].pthread_setcanceltype
    pthread_setcanceltype.restype = ctypes.c_int32
    pthread_setcanceltype.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    pthread_cancel = _libraries['FIXME_STUB'].pthread_cancel
    pthread_cancel.restype = ctypes.c_int32
    pthread_cancel.argtypes = [pthread_t]
except AttributeError:
    pass
try:
    pthread_testcancel = _libraries['FIXME_STUB'].pthread_testcancel
    pthread_testcancel.restype = None
    pthread_testcancel.argtypes = []
except AttributeError:
    pass
class struct___cancel_jmp_buf_tag(Structure):
    pass

struct___cancel_jmp_buf_tag._pack_ = 1 # source:False
struct___cancel_jmp_buf_tag._fields_ = [
    ('__cancel_jmp_buf', ctypes.c_int64 * 8),
    ('__mask_was_saved', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

class struct___pthread_unwind_buf_t(Structure):
    pass

struct___pthread_unwind_buf_t._pack_ = 1 # source:False
struct___pthread_unwind_buf_t._fields_ = [
    ('__cancel_jmp_buf', struct___cancel_jmp_buf_tag * 1),
    ('__pad', ctypes.POINTER(None) * 4),
]

__pthread_unwind_buf_t = struct___pthread_unwind_buf_t
class struct___pthread_cleanup_frame(Structure):
    pass

struct___pthread_cleanup_frame._pack_ = 1 # source:False
struct___pthread_cleanup_frame._fields_ = [
    ('__cancel_routine', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
    ('__cancel_arg', ctypes.POINTER(None)),
    ('__do_it', ctypes.c_int32),
    ('__cancel_type', ctypes.c_int32),
]

try:
    __pthread_register_cancel = _libraries['FIXME_STUB'].__pthread_register_cancel
    __pthread_register_cancel.restype = None
    __pthread_register_cancel.argtypes = [ctypes.POINTER(struct___pthread_unwind_buf_t)]
except AttributeError:
    pass
try:
    __pthread_unregister_cancel = _libraries['FIXME_STUB'].__pthread_unregister_cancel
    __pthread_unregister_cancel.restype = None
    __pthread_unregister_cancel.argtypes = [ctypes.POINTER(struct___pthread_unwind_buf_t)]
except AttributeError:
    pass
try:
    __pthread_unwind_next = _libraries['FIXME_STUB'].__pthread_unwind_next
    __pthread_unwind_next.restype = None
    __pthread_unwind_next.argtypes = [ctypes.POINTER(struct___pthread_unwind_buf_t)]
except AttributeError:
    pass
try:
    __sigsetjmp = _libraries['FIXME_STUB'].__sigsetjmp
    __sigsetjmp.restype = ctypes.c_int32
    __sigsetjmp.argtypes = [struct___jmp_buf_tag * 1, ctypes.c_int32]
except AttributeError:
    pass
try:
    pthread_mutex_init = _libraries['FIXME_STUB'].pthread_mutex_init
    pthread_mutex_init.restype = ctypes.c_int32
    pthread_mutex_init.argtypes = [ctypes.POINTER(union_pthread_mutex_t), ctypes.POINTER(union_pthread_mutexattr_t)]
except AttributeError:
    pass
try:
    pthread_mutex_destroy = _libraries['FIXME_STUB'].pthread_mutex_destroy
    pthread_mutex_destroy.restype = ctypes.c_int32
    pthread_mutex_destroy.argtypes = [ctypes.POINTER(union_pthread_mutex_t)]
except AttributeError:
    pass
try:
    pthread_mutex_trylock = _libraries['FIXME_STUB'].pthread_mutex_trylock
    pthread_mutex_trylock.restype = ctypes.c_int32
    pthread_mutex_trylock.argtypes = [ctypes.POINTER(union_pthread_mutex_t)]
except AttributeError:
    pass
try:
    pthread_mutex_lock = _libraries['FIXME_STUB'].pthread_mutex_lock
    pthread_mutex_lock.restype = ctypes.c_int32
    pthread_mutex_lock.argtypes = [ctypes.POINTER(union_pthread_mutex_t)]
except AttributeError:
    pass
try:
    pthread_mutex_timedlock = _libraries['FIXME_STUB'].pthread_mutex_timedlock
    pthread_mutex_timedlock.restype = ctypes.c_int32
    pthread_mutex_timedlock.argtypes = [ctypes.POINTER(union_pthread_mutex_t), ctypes.POINTER(struct_timespec)]
except AttributeError:
    pass
try:
    pthread_mutex_unlock = _libraries['FIXME_STUB'].pthread_mutex_unlock
    pthread_mutex_unlock.restype = ctypes.c_int32
    pthread_mutex_unlock.argtypes = [ctypes.POINTER(union_pthread_mutex_t)]
except AttributeError:
    pass
try:
    pthread_mutex_getprioceiling = _libraries['FIXME_STUB'].pthread_mutex_getprioceiling
    pthread_mutex_getprioceiling.restype = ctypes.c_int32
    pthread_mutex_getprioceiling.argtypes = [ctypes.POINTER(union_pthread_mutex_t), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    pthread_mutex_setprioceiling = _libraries['FIXME_STUB'].pthread_mutex_setprioceiling
    pthread_mutex_setprioceiling.restype = ctypes.c_int32
    pthread_mutex_setprioceiling.argtypes = [ctypes.POINTER(union_pthread_mutex_t), ctypes.c_int32, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    pthread_mutex_consistent = _libraries['FIXME_STUB'].pthread_mutex_consistent
    pthread_mutex_consistent.restype = ctypes.c_int32
    pthread_mutex_consistent.argtypes = [ctypes.POINTER(union_pthread_mutex_t)]
except AttributeError:
    pass
try:
    pthread_mutexattr_init = _libraries['FIXME_STUB'].pthread_mutexattr_init
    pthread_mutexattr_init.restype = ctypes.c_int32
    pthread_mutexattr_init.argtypes = [ctypes.POINTER(union_pthread_mutexattr_t)]
except AttributeError:
    pass
try:
    pthread_mutexattr_destroy = _libraries['FIXME_STUB'].pthread_mutexattr_destroy
    pthread_mutexattr_destroy.restype = ctypes.c_int32
    pthread_mutexattr_destroy.argtypes = [ctypes.POINTER(union_pthread_mutexattr_t)]
except AttributeError:
    pass
try:
    pthread_mutexattr_getpshared = _libraries['FIXME_STUB'].pthread_mutexattr_getpshared
    pthread_mutexattr_getpshared.restype = ctypes.c_int32
    pthread_mutexattr_getpshared.argtypes = [ctypes.POINTER(union_pthread_mutexattr_t), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    pthread_mutexattr_setpshared = _libraries['FIXME_STUB'].pthread_mutexattr_setpshared
    pthread_mutexattr_setpshared.restype = ctypes.c_int32
    pthread_mutexattr_setpshared.argtypes = [ctypes.POINTER(union_pthread_mutexattr_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    pthread_mutexattr_gettype = _libraries['FIXME_STUB'].pthread_mutexattr_gettype
    pthread_mutexattr_gettype.restype = ctypes.c_int32
    pthread_mutexattr_gettype.argtypes = [ctypes.POINTER(union_pthread_mutexattr_t), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    pthread_mutexattr_settype = _libraries['FIXME_STUB'].pthread_mutexattr_settype
    pthread_mutexattr_settype.restype = ctypes.c_int32
    pthread_mutexattr_settype.argtypes = [ctypes.POINTER(union_pthread_mutexattr_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    pthread_mutexattr_getprotocol = _libraries['FIXME_STUB'].pthread_mutexattr_getprotocol
    pthread_mutexattr_getprotocol.restype = ctypes.c_int32
    pthread_mutexattr_getprotocol.argtypes = [ctypes.POINTER(union_pthread_mutexattr_t), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    pthread_mutexattr_setprotocol = _libraries['FIXME_STUB'].pthread_mutexattr_setprotocol
    pthread_mutexattr_setprotocol.restype = ctypes.c_int32
    pthread_mutexattr_setprotocol.argtypes = [ctypes.POINTER(union_pthread_mutexattr_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    pthread_mutexattr_getprioceiling = _libraries['FIXME_STUB'].pthread_mutexattr_getprioceiling
    pthread_mutexattr_getprioceiling.restype = ctypes.c_int32
    pthread_mutexattr_getprioceiling.argtypes = [ctypes.POINTER(union_pthread_mutexattr_t), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    pthread_mutexattr_setprioceiling = _libraries['FIXME_STUB'].pthread_mutexattr_setprioceiling
    pthread_mutexattr_setprioceiling.restype = ctypes.c_int32
    pthread_mutexattr_setprioceiling.argtypes = [ctypes.POINTER(union_pthread_mutexattr_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    pthread_mutexattr_getrobust = _libraries['FIXME_STUB'].pthread_mutexattr_getrobust
    pthread_mutexattr_getrobust.restype = ctypes.c_int32
    pthread_mutexattr_getrobust.argtypes = [ctypes.POINTER(union_pthread_mutexattr_t), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    pthread_mutexattr_setrobust = _libraries['FIXME_STUB'].pthread_mutexattr_setrobust
    pthread_mutexattr_setrobust.restype = ctypes.c_int32
    pthread_mutexattr_setrobust.argtypes = [ctypes.POINTER(union_pthread_mutexattr_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    pthread_rwlock_init = _libraries['FIXME_STUB'].pthread_rwlock_init
    pthread_rwlock_init.restype = ctypes.c_int32
    pthread_rwlock_init.argtypes = [ctypes.POINTER(union_pthread_rwlock_t), ctypes.POINTER(union_pthread_rwlockattr_t)]
except AttributeError:
    pass
try:
    pthread_rwlock_destroy = _libraries['FIXME_STUB'].pthread_rwlock_destroy
    pthread_rwlock_destroy.restype = ctypes.c_int32
    pthread_rwlock_destroy.argtypes = [ctypes.POINTER(union_pthread_rwlock_t)]
except AttributeError:
    pass
try:
    pthread_rwlock_rdlock = _libraries['FIXME_STUB'].pthread_rwlock_rdlock
    pthread_rwlock_rdlock.restype = ctypes.c_int32
    pthread_rwlock_rdlock.argtypes = [ctypes.POINTER(union_pthread_rwlock_t)]
except AttributeError:
    pass
try:
    pthread_rwlock_tryrdlock = _libraries['FIXME_STUB'].pthread_rwlock_tryrdlock
    pthread_rwlock_tryrdlock.restype = ctypes.c_int32
    pthread_rwlock_tryrdlock.argtypes = [ctypes.POINTER(union_pthread_rwlock_t)]
except AttributeError:
    pass
try:
    pthread_rwlock_timedrdlock = _libraries['FIXME_STUB'].pthread_rwlock_timedrdlock
    pthread_rwlock_timedrdlock.restype = ctypes.c_int32
    pthread_rwlock_timedrdlock.argtypes = [ctypes.POINTER(union_pthread_rwlock_t), ctypes.POINTER(struct_timespec)]
except AttributeError:
    pass
try:
    pthread_rwlock_wrlock = _libraries['FIXME_STUB'].pthread_rwlock_wrlock
    pthread_rwlock_wrlock.restype = ctypes.c_int32
    pthread_rwlock_wrlock.argtypes = [ctypes.POINTER(union_pthread_rwlock_t)]
except AttributeError:
    pass
try:
    pthread_rwlock_trywrlock = _libraries['FIXME_STUB'].pthread_rwlock_trywrlock
    pthread_rwlock_trywrlock.restype = ctypes.c_int32
    pthread_rwlock_trywrlock.argtypes = [ctypes.POINTER(union_pthread_rwlock_t)]
except AttributeError:
    pass
try:
    pthread_rwlock_timedwrlock = _libraries['FIXME_STUB'].pthread_rwlock_timedwrlock
    pthread_rwlock_timedwrlock.restype = ctypes.c_int32
    pthread_rwlock_timedwrlock.argtypes = [ctypes.POINTER(union_pthread_rwlock_t), ctypes.POINTER(struct_timespec)]
except AttributeError:
    pass
try:
    pthread_rwlock_unlock = _libraries['FIXME_STUB'].pthread_rwlock_unlock
    pthread_rwlock_unlock.restype = ctypes.c_int32
    pthread_rwlock_unlock.argtypes = [ctypes.POINTER(union_pthread_rwlock_t)]
except AttributeError:
    pass
try:
    pthread_rwlockattr_init = _libraries['FIXME_STUB'].pthread_rwlockattr_init
    pthread_rwlockattr_init.restype = ctypes.c_int32
    pthread_rwlockattr_init.argtypes = [ctypes.POINTER(union_pthread_rwlockattr_t)]
except AttributeError:
    pass
try:
    pthread_rwlockattr_destroy = _libraries['FIXME_STUB'].pthread_rwlockattr_destroy
    pthread_rwlockattr_destroy.restype = ctypes.c_int32
    pthread_rwlockattr_destroy.argtypes = [ctypes.POINTER(union_pthread_rwlockattr_t)]
except AttributeError:
    pass
try:
    pthread_rwlockattr_getpshared = _libraries['FIXME_STUB'].pthread_rwlockattr_getpshared
    pthread_rwlockattr_getpshared.restype = ctypes.c_int32
    pthread_rwlockattr_getpshared.argtypes = [ctypes.POINTER(union_pthread_rwlockattr_t), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    pthread_rwlockattr_setpshared = _libraries['FIXME_STUB'].pthread_rwlockattr_setpshared
    pthread_rwlockattr_setpshared.restype = ctypes.c_int32
    pthread_rwlockattr_setpshared.argtypes = [ctypes.POINTER(union_pthread_rwlockattr_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    pthread_rwlockattr_getkind_np = _libraries['FIXME_STUB'].pthread_rwlockattr_getkind_np
    pthread_rwlockattr_getkind_np.restype = ctypes.c_int32
    pthread_rwlockattr_getkind_np.argtypes = [ctypes.POINTER(union_pthread_rwlockattr_t), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    pthread_rwlockattr_setkind_np = _libraries['FIXME_STUB'].pthread_rwlockattr_setkind_np
    pthread_rwlockattr_setkind_np.restype = ctypes.c_int32
    pthread_rwlockattr_setkind_np.argtypes = [ctypes.POINTER(union_pthread_rwlockattr_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    pthread_cond_init = _libraries['FIXME_STUB'].pthread_cond_init
    pthread_cond_init.restype = ctypes.c_int32
    pthread_cond_init.argtypes = [ctypes.POINTER(union_pthread_cond_t), ctypes.POINTER(union_pthread_condattr_t)]
except AttributeError:
    pass
try:
    pthread_cond_destroy = _libraries['FIXME_STUB'].pthread_cond_destroy
    pthread_cond_destroy.restype = ctypes.c_int32
    pthread_cond_destroy.argtypes = [ctypes.POINTER(union_pthread_cond_t)]
except AttributeError:
    pass
try:
    pthread_cond_signal = _libraries['FIXME_STUB'].pthread_cond_signal
    pthread_cond_signal.restype = ctypes.c_int32
    pthread_cond_signal.argtypes = [ctypes.POINTER(union_pthread_cond_t)]
except AttributeError:
    pass
try:
    pthread_cond_broadcast = _libraries['FIXME_STUB'].pthread_cond_broadcast
    pthread_cond_broadcast.restype = ctypes.c_int32
    pthread_cond_broadcast.argtypes = [ctypes.POINTER(union_pthread_cond_t)]
except AttributeError:
    pass
try:
    pthread_cond_wait = _libraries['FIXME_STUB'].pthread_cond_wait
    pthread_cond_wait.restype = ctypes.c_int32
    pthread_cond_wait.argtypes = [ctypes.POINTER(union_pthread_cond_t), ctypes.POINTER(union_pthread_mutex_t)]
except AttributeError:
    pass
try:
    pthread_cond_timedwait = _libraries['FIXME_STUB'].pthread_cond_timedwait
    pthread_cond_timedwait.restype = ctypes.c_int32
    pthread_cond_timedwait.argtypes = [ctypes.POINTER(union_pthread_cond_t), ctypes.POINTER(union_pthread_mutex_t), ctypes.POINTER(struct_timespec)]
except AttributeError:
    pass
try:
    pthread_condattr_init = _libraries['FIXME_STUB'].pthread_condattr_init
    pthread_condattr_init.restype = ctypes.c_int32
    pthread_condattr_init.argtypes = [ctypes.POINTER(union_pthread_condattr_t)]
except AttributeError:
    pass
try:
    pthread_condattr_destroy = _libraries['FIXME_STUB'].pthread_condattr_destroy
    pthread_condattr_destroy.restype = ctypes.c_int32
    pthread_condattr_destroy.argtypes = [ctypes.POINTER(union_pthread_condattr_t)]
except AttributeError:
    pass
try:
    pthread_condattr_getpshared = _libraries['FIXME_STUB'].pthread_condattr_getpshared
    pthread_condattr_getpshared.restype = ctypes.c_int32
    pthread_condattr_getpshared.argtypes = [ctypes.POINTER(union_pthread_condattr_t), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    pthread_condattr_setpshared = _libraries['FIXME_STUB'].pthread_condattr_setpshared
    pthread_condattr_setpshared.restype = ctypes.c_int32
    pthread_condattr_setpshared.argtypes = [ctypes.POINTER(union_pthread_condattr_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    pthread_condattr_getclock = _libraries['FIXME_STUB'].pthread_condattr_getclock
    pthread_condattr_getclock.restype = ctypes.c_int32
    pthread_condattr_getclock.argtypes = [ctypes.POINTER(union_pthread_condattr_t), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    pthread_condattr_setclock = _libraries['FIXME_STUB'].pthread_condattr_setclock
    pthread_condattr_setclock.restype = ctypes.c_int32
    pthread_condattr_setclock.argtypes = [ctypes.POINTER(union_pthread_condattr_t), __clockid_t]
except AttributeError:
    pass
try:
    pthread_spin_init = _libraries['FIXME_STUB'].pthread_spin_init
    pthread_spin_init.restype = ctypes.c_int32
    pthread_spin_init.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.c_int32]
except AttributeError:
    pass
try:
    pthread_spin_destroy = _libraries['FIXME_STUB'].pthread_spin_destroy
    pthread_spin_destroy.restype = ctypes.c_int32
    pthread_spin_destroy.argtypes = [ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    pthread_spin_lock = _libraries['FIXME_STUB'].pthread_spin_lock
    pthread_spin_lock.restype = ctypes.c_int32
    pthread_spin_lock.argtypes = [ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    pthread_spin_trylock = _libraries['FIXME_STUB'].pthread_spin_trylock
    pthread_spin_trylock.restype = ctypes.c_int32
    pthread_spin_trylock.argtypes = [ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    pthread_spin_unlock = _libraries['FIXME_STUB'].pthread_spin_unlock
    pthread_spin_unlock.restype = ctypes.c_int32
    pthread_spin_unlock.argtypes = [ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    pthread_barrier_init = _libraries['FIXME_STUB'].pthread_barrier_init
    pthread_barrier_init.restype = ctypes.c_int32
    pthread_barrier_init.argtypes = [ctypes.POINTER(union_pthread_barrier_t), ctypes.POINTER(union_pthread_barrierattr_t), ctypes.c_uint32]
except AttributeError:
    pass
try:
    pthread_barrier_destroy = _libraries['FIXME_STUB'].pthread_barrier_destroy
    pthread_barrier_destroy.restype = ctypes.c_int32
    pthread_barrier_destroy.argtypes = [ctypes.POINTER(union_pthread_barrier_t)]
except AttributeError:
    pass
try:
    pthread_barrier_wait = _libraries['FIXME_STUB'].pthread_barrier_wait
    pthread_barrier_wait.restype = ctypes.c_int32
    pthread_barrier_wait.argtypes = [ctypes.POINTER(union_pthread_barrier_t)]
except AttributeError:
    pass
try:
    pthread_barrierattr_init = _libraries['FIXME_STUB'].pthread_barrierattr_init
    pthread_barrierattr_init.restype = ctypes.c_int32
    pthread_barrierattr_init.argtypes = [ctypes.POINTER(union_pthread_barrierattr_t)]
except AttributeError:
    pass
try:
    pthread_barrierattr_destroy = _libraries['FIXME_STUB'].pthread_barrierattr_destroy
    pthread_barrierattr_destroy.restype = ctypes.c_int32
    pthread_barrierattr_destroy.argtypes = [ctypes.POINTER(union_pthread_barrierattr_t)]
except AttributeError:
    pass
try:
    pthread_barrierattr_getpshared = _libraries['FIXME_STUB'].pthread_barrierattr_getpshared
    pthread_barrierattr_getpshared.restype = ctypes.c_int32
    pthread_barrierattr_getpshared.argtypes = [ctypes.POINTER(union_pthread_barrierattr_t), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    pthread_barrierattr_setpshared = _libraries['FIXME_STUB'].pthread_barrierattr_setpshared
    pthread_barrierattr_setpshared.restype = ctypes.c_int32
    pthread_barrierattr_setpshared.argtypes = [ctypes.POINTER(union_pthread_barrierattr_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    pthread_key_create = _libraries['FIXME_STUB'].pthread_key_create
    pthread_key_create.restype = ctypes.c_int32
    pthread_key_create.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.CFUNCTYPE(None, ctypes.POINTER(None))]
except AttributeError:
    pass
try:
    pthread_key_delete = _libraries['FIXME_STUB'].pthread_key_delete
    pthread_key_delete.restype = ctypes.c_int32
    pthread_key_delete.argtypes = [pthread_key_t]
except AttributeError:
    pass
try:
    pthread_getspecific = _libraries['FIXME_STUB'].pthread_getspecific
    pthread_getspecific.restype = ctypes.POINTER(None)
    pthread_getspecific.argtypes = [pthread_key_t]
except AttributeError:
    pass
try:
    pthread_setspecific = _libraries['FIXME_STUB'].pthread_setspecific
    pthread_setspecific.restype = ctypes.c_int32
    pthread_setspecific.argtypes = [pthread_key_t, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    pthread_getcpuclockid = _libraries['FIXME_STUB'].pthread_getcpuclockid
    pthread_getcpuclockid.restype = ctypes.c_int32
    pthread_getcpuclockid.argtypes = [pthread_t, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    pthread_atfork = _libraries['FIXME_STUB'].pthread_atfork
    pthread_atfork.restype = ctypes.c_int32
    pthread_atfork.argtypes = [ctypes.CFUNCTYPE(None), ctypes.CFUNCTYPE(None), ctypes.CFUNCTYPE(None)]
except AttributeError:
    pass

# values for enumeration 'RThreadFunctionRet'
RThreadFunctionRet__enumvalues = {
    -1: 'R_TH_FREED',
    0: 'R_TH_STOP',
    1: 'R_TH_REPEAT',
}
R_TH_FREED = -1
R_TH_STOP = 0
R_TH_REPEAT = 1
RThreadFunctionRet = ctypes.c_int32 # enum
class struct_r_th_t(Structure):
    pass

RThreadFunction = ctypes.CFUNCTYPE(RThreadFunctionRet, ctypes.POINTER(struct_r_th_t))
class struct_r_th_sem_t(Structure):
    pass

struct_r_th_sem_t._pack_ = 1 # source:False
struct_r_th_sem_t._fields_ = [
    ('sem', ctypes.POINTER(union_sem_t)),
]

RThreadSemaphore = struct_r_th_sem_t

# values for enumeration 'r_th_lock_type_t'
r_th_lock_type_t__enumvalues = {
    0: 'R_TH_LOCK_TYPE_STATIC',
    1: 'R_TH_LOCK_TYPE_HEAP',
}
R_TH_LOCK_TYPE_STATIC = 0
R_TH_LOCK_TYPE_HEAP = 1
r_th_lock_type_t = ctypes.c_uint32 # enum
c_bool = r_th_lock_type_t
c_bool__enumvalues = r_th_lock_type_t__enumvalues
class struct_r_th_lock_t(Structure):
    pass

class struct_r_th_lock_t_0(Structure):
    pass

struct_r_th_lock_t_0._pack_ = 1 # source:False
struct_r_th_lock_t_0._fields_ = [
    ('active', ctypes.c_bool, 1),
    ('type', c_bool, 7),
    ('PADDING_0', ctypes.c_uint32, 24),
]

struct_r_th_lock_t._pack_ = 1 # source:False
struct_r_th_lock_t._anonymous_ = ('_0',)
struct_r_th_lock_t._fields_ = [
    ('activating', ctypes.c_int32),
    ('_0', struct_r_th_lock_t_0),
    ('lock', pthread_mutex_t),
]

RThreadLock = struct_r_th_lock_t
class struct_r_th_cond_t(Structure):
    _pack_ = 1 # source:False
    _fields_ = [
    ('cond', pthread_cond_t),
     ]

RThreadCond = struct_r_th_cond_t
struct_r_th_t._pack_ = 1 # source:False
struct_r_th_t._fields_ = [
    ('tid', ctypes.c_uint64),
    ('lock', ctypes.POINTER(struct_r_th_lock_t)),
    ('fun', ctypes.CFUNCTYPE(RThreadFunctionRet, ctypes.POINTER(struct_r_th_t))),
    ('user', ctypes.POINTER(None)),
    ('running', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 3),
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
class struct_RThreadChannel(Structure):
    pass

struct_RThreadChannel._pack_ = 1 # source:False
struct_RThreadChannel._fields_ = [
    ('nextid', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('lock', ctypes.POINTER(struct_r_th_lock_t)),
    ('sem', ctypes.POINTER(struct_r_th_sem_t)),
    ('stack', ctypes.POINTER(struct_r_list_t)),
    ('responses', ctypes.POINTER(struct_r_list_t)),
    ('consumer', ctypes.POINTER(struct_r_th_t)),
]

RThreadChannel = struct_RThreadChannel
class struct_RThreadChannelMessage(Structure):
    pass

struct_RThreadChannelMessage._pack_ = 1 # source:False
struct_RThreadChannelMessage._fields_ = [
    ('id', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('msg', ctypes.POINTER(ctypes.c_ubyte)),
    ('len', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
    ('lock', ctypes.POINTER(struct_r_th_lock_t)),
    ('sem', ctypes.POINTER(struct_r_th_sem_t)),
]

RThreadChannelMessage = struct_RThreadChannelMessage
class struct_RThreadChannelPromise(Structure):
    pass

struct_RThreadChannelPromise._pack_ = 1 # source:False
struct_RThreadChannelPromise._fields_ = [
    ('id', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('message', ctypes.POINTER(struct_RThreadChannelMessage)),
    ('tc', ctypes.POINTER(struct_RThreadChannel)),
]

RThreadChannelPromise = struct_RThreadChannelPromise
try:
    r_th_channel_read = _libr_util.r_th_channel_read
    r_th_channel_read.restype = ctypes.POINTER(struct_RThreadChannelMessage)
    r_th_channel_read.argtypes = [ctypes.POINTER(struct_RThreadChannel)]
except AttributeError:
    pass
try:
    r_th_channel_message_free = _libr_util.r_th_channel_message_free
    r_th_channel_message_free.restype = None
    r_th_channel_message_free.argtypes = [ctypes.POINTER(struct_RThreadChannelMessage)]
except AttributeError:
    pass
try:
    r_th_channel_write = _libr_util.r_th_channel_write
    r_th_channel_write.restype = ctypes.POINTER(struct_RThreadChannelMessage)
    r_th_channel_write.argtypes = [ctypes.POINTER(struct_RThreadChannel), ctypes.POINTER(struct_RThreadChannelMessage)]
except AttributeError:
    pass
try:
    r_th_channel_message_read = _libr_util.r_th_channel_message_read
    r_th_channel_message_read.restype = ctypes.POINTER(struct_RThreadChannelMessage)
    r_th_channel_message_read.argtypes = [ctypes.POINTER(struct_RThreadChannel), ctypes.POINTER(struct_RThreadChannelMessage)]
except AttributeError:
    pass
try:
    r_th_channel_message_new = _libr_util.r_th_channel_message_new
    r_th_channel_message_new.restype = ctypes.POINTER(struct_RThreadChannelMessage)
    r_th_channel_message_new.argtypes = [ctypes.POINTER(struct_RThreadChannel), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_th_channel_new = _libr_util.r_th_channel_new
    r_th_channel_new.restype = ctypes.POINTER(struct_RThreadChannel)
    r_th_channel_new.argtypes = [RThreadFunction, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_th_channel_free = _libr_util.r_th_channel_free
    r_th_channel_free.restype = None
    r_th_channel_free.argtypes = [ctypes.POINTER(struct_RThreadChannel)]
except AttributeError:
    pass
try:
    r_th_channel_query = _libr_util.r_th_channel_query
    r_th_channel_query.restype = ctypes.POINTER(struct_RThreadChannelPromise)
    r_th_channel_query.argtypes = [ctypes.POINTER(struct_RThreadChannel), ctypes.POINTER(struct_RThreadChannelMessage)]
except AttributeError:
    pass
try:
    r_th_channel_post = _libr_util.r_th_channel_post
    r_th_channel_post.restype = None
    r_th_channel_post.argtypes = [ctypes.POINTER(struct_RThreadChannel), ctypes.POINTER(struct_RThreadChannelMessage)]
except AttributeError:
    pass
try:
    r_th_channel_promise_new = _libr_util.r_th_channel_promise_new
    r_th_channel_promise_new.restype = ctypes.POINTER(struct_RThreadChannelPromise)
    r_th_channel_promise_new.argtypes = [ctypes.POINTER(struct_RThreadChannel)]
except AttributeError:
    pass
try:
    r_th_channel_promise_wait = _libr_util.r_th_channel_promise_wait
    r_th_channel_promise_wait.restype = ctypes.POINTER(struct_RThreadChannelMessage)
    r_th_channel_promise_wait.argtypes = [ctypes.POINTER(struct_RThreadChannelPromise)]
except AttributeError:
    pass
try:
    r_th_channel_promise_free = _libr_util.r_th_channel_promise_free
    r_th_channel_promise_free.restype = None
    r_th_channel_promise_free.argtypes = [ctypes.POINTER(struct_RThreadChannelPromise)]
except AttributeError:
    pass
try:
    r_th_new = _libr_util.r_th_new
    r_th_new.restype = ctypes.POINTER(struct_r_th_t)
    r_th_new.argtypes = [RThreadFunction, ctypes.POINTER(None), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_th_start = _libr_util.r_th_start
    r_th_start.restype = ctypes.c_bool
    r_th_start.argtypes = [ctypes.POINTER(struct_r_th_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_th_wait = _libr_util.r_th_wait
    r_th_wait.restype = ctypes.c_int32
    r_th_wait.argtypes = [ctypes.POINTER(struct_r_th_t)]
except AttributeError:
    pass
try:
    r_th_wait_async = _libr_util.r_th_wait_async
    r_th_wait_async.restype = ctypes.c_int32
    r_th_wait_async.argtypes = [ctypes.POINTER(struct_r_th_t)]
except AttributeError:
    pass
try:
    r_th_break = _libr_util.r_th_break
    r_th_break.restype = None
    r_th_break.argtypes = [ctypes.POINTER(struct_r_th_t)]
except AttributeError:
    pass
try:
    r_th_free = _libr_util.r_th_free
    r_th_free.restype = ctypes.POINTER(None)
    r_th_free.argtypes = [ctypes.POINTER(struct_r_th_t)]
except AttributeError:
    pass
try:
    r_th_set_running = _libr_util.r_th_set_running
    r_th_set_running.restype = None
    r_th_set_running.argtypes = [ctypes.POINTER(struct_r_th_t), ctypes.c_bool]
except AttributeError:
    pass
try:
    r_th_is_running = _libr_util.r_th_is_running
    r_th_is_running.restype = ctypes.c_bool
    r_th_is_running.argtypes = [ctypes.POINTER(struct_r_th_t)]
except AttributeError:
    pass
try:
    r_th_kill_free = _libr_util.r_th_kill_free
    r_th_kill_free.restype = ctypes.POINTER(None)
    r_th_kill_free.argtypes = [ctypes.POINTER(struct_r_th_t)]
except AttributeError:
    pass
try:
    r_th_kill = _libr_util.r_th_kill
    r_th_kill.restype = ctypes.c_bool
    r_th_kill.argtypes = [ctypes.POINTER(struct_r_th_t), ctypes.c_bool]
except AttributeError:
    pass
try:
    r_th_self = _libr_util.r_th_self
    r_th_self.restype = pthread_t
    r_th_self.argtypes = []
except AttributeError:
    pass
try:
    r_th_setname = _libr_util.r_th_setname
    r_th_setname.restype = ctypes.c_bool
    r_th_setname.argtypes = [ctypes.POINTER(struct_r_th_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_th_getname = _libr_util.r_th_getname
    r_th_getname.restype = ctypes.c_bool
    r_th_getname.argtypes = [ctypes.POINTER(struct_r_th_t), ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    r_th_setaffinity = _libr_util.r_th_setaffinity
    r_th_setaffinity.restype = ctypes.c_bool
    r_th_setaffinity.argtypes = [ctypes.POINTER(struct_r_th_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_th_sem_new = _libr_util.r_th_sem_new
    r_th_sem_new.restype = ctypes.POINTER(struct_r_th_sem_t)
    r_th_sem_new.argtypes = [ctypes.c_uint32]
except AttributeError:
    pass
try:
    r_th_sem_free = _libr_util.r_th_sem_free
    r_th_sem_free.restype = None
    r_th_sem_free.argtypes = [ctypes.POINTER(struct_r_th_sem_t)]
except AttributeError:
    pass
try:
    r_th_sem_post = _libr_util.r_th_sem_post
    r_th_sem_post.restype = None
    r_th_sem_post.argtypes = [ctypes.POINTER(struct_r_th_sem_t)]
except AttributeError:
    pass
try:
    r_th_sem_wait = _libr_util.r_th_sem_wait
    r_th_sem_wait.restype = None
    r_th_sem_wait.argtypes = [ctypes.POINTER(struct_r_th_sem_t)]
except AttributeError:
    pass
try:
    r_th_lock_new = _libr_util.r_th_lock_new
    r_th_lock_new.restype = ctypes.POINTER(struct_r_th_lock_t)
    r_th_lock_new.argtypes = [ctypes.c_bool]
except AttributeError:
    pass
try:
    r_th_lock_wait = _libr_util.r_th_lock_wait
    r_th_lock_wait.restype = ctypes.c_bool
    r_th_lock_wait.argtypes = [ctypes.POINTER(struct_r_th_lock_t)]
except AttributeError:
    pass
try:
    r_th_lock_tryenter = _libr_util.r_th_lock_tryenter
    r_th_lock_tryenter.restype = ctypes.c_bool
    r_th_lock_tryenter.argtypes = [ctypes.POINTER(struct_r_th_lock_t)]
except AttributeError:
    pass
try:
    r_th_lock_enter = _libr_util.r_th_lock_enter
    r_th_lock_enter.restype = ctypes.c_bool
    r_th_lock_enter.argtypes = [ctypes.POINTER(struct_r_th_lock_t)]
except AttributeError:
    pass
try:
    r_th_lock_leave = _libr_util.r_th_lock_leave
    r_th_lock_leave.restype = ctypes.c_bool
    r_th_lock_leave.argtypes = [ctypes.POINTER(struct_r_th_lock_t)]
except AttributeError:
    pass
try:
    r_th_lock_free = _libr_util.r_th_lock_free
    r_th_lock_free.restype = ctypes.POINTER(None)
    r_th_lock_free.argtypes = [ctypes.POINTER(struct_r_th_lock_t)]
except AttributeError:
    pass
try:
    r_th_cond_new = _libr_util.r_th_cond_new
    r_th_cond_new.restype = ctypes.POINTER(struct_r_th_cond_t)
    r_th_cond_new.argtypes = []
except AttributeError:
    pass
try:
    r_th_cond_signal = _libr_util.r_th_cond_signal
    r_th_cond_signal.restype = None
    r_th_cond_signal.argtypes = [ctypes.POINTER(struct_r_th_cond_t)]
except AttributeError:
    pass
try:
    r_th_cond_signal_all = _libr_util.r_th_cond_signal_all
    r_th_cond_signal_all.restype = None
    r_th_cond_signal_all.argtypes = [ctypes.POINTER(struct_r_th_cond_t)]
except AttributeError:
    pass
try:
    r_th_cond_wait = _libr_util.r_th_cond_wait
    r_th_cond_wait.restype = None
    r_th_cond_wait.argtypes = [ctypes.POINTER(struct_r_th_cond_t), ctypes.POINTER(struct_r_th_lock_t)]
except AttributeError:
    pass
try:
    r_th_cond_free = _libr_util.r_th_cond_free
    r_th_cond_free.restype = None
    r_th_cond_free.argtypes = [ctypes.POINTER(struct_r_th_cond_t)]
except AttributeError:
    pass
try:
    r_atomic_store = _libr_util.r_atomic_store
    r_atomic_store.restype = None
    r_atomic_store.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.c_bool]
except AttributeError:
    pass
try:
    r_atomic_exchange = _libr_util.r_atomic_exchange
    r_atomic_exchange.restype = ctypes.c_bool
    r_atomic_exchange.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.c_bool]
except AttributeError:
    pass
sig_atomic_t = ctypes.c_int32
class union_sigval(Union):
    pass

union_sigval._pack_ = 1 # source:False
union_sigval._fields_ = [
    ('sival_int', ctypes.c_int32),
    ('sival_ptr', ctypes.POINTER(None)),
]

__sigval_t = union_sigval
class struct_siginfo_t(Structure):
    pass

class union_siginfo_t__sifields(Union):
    pass

class struct_siginfo_t_0__kill(Structure):
    pass

struct_siginfo_t_0__kill._pack_ = 1 # source:False
struct_siginfo_t_0__kill._fields_ = [
    ('si_pid', ctypes.c_int32),
    ('si_uid', ctypes.c_uint32),
]

class struct_siginfo_t_0__timer(Structure):
    pass

struct_siginfo_t_0__timer._pack_ = 1 # source:False
struct_siginfo_t_0__timer._fields_ = [
    ('si_tid', ctypes.c_int32),
    ('si_overrun', ctypes.c_int32),
    ('si_sigval', globals()['__sigval_t']),
]

class struct_siginfo_t_0__rt(Structure):
    pass

struct_siginfo_t_0__rt._pack_ = 1 # source:False
struct_siginfo_t_0__rt._fields_ = [
    ('si_pid', ctypes.c_int32),
    ('si_uid', ctypes.c_uint32),
    ('si_sigval', globals()['__sigval_t']),
]

class struct_siginfo_t_0__sigchld(Structure):
    pass

struct_siginfo_t_0__sigchld._pack_ = 1 # source:False
struct_siginfo_t_0__sigchld._fields_ = [
    ('si_pid', ctypes.c_int32),
    ('si_uid', ctypes.c_uint32),
    ('si_status', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('si_utime', ctypes.c_int64),
    ('si_stime', ctypes.c_int64),
]

class struct_siginfo_t_0__sigfault(Structure):
    pass

class union_siginfo_t_0_4__bounds(Union):
    pass

class struct_siginfo_t_0_4_0__addr_bnd(Structure):
    pass

struct_siginfo_t_0_4_0__addr_bnd._pack_ = 1 # source:False
struct_siginfo_t_0_4_0__addr_bnd._fields_ = [
    ('_lower', ctypes.POINTER(None)),
    ('_upper', ctypes.POINTER(None)),
]

union_siginfo_t_0_4__bounds._pack_ = 1 # source:False
union_siginfo_t_0_4__bounds._fields_ = [
    ('_addr_bnd', struct_siginfo_t_0_4_0__addr_bnd),
    ('_pkey', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 12),
]

struct_siginfo_t_0__sigfault._pack_ = 1 # source:False
struct_siginfo_t_0__sigfault._fields_ = [
    ('si_addr', ctypes.POINTER(None)),
    ('si_addr_lsb', ctypes.c_int16),
    ('PADDING_0', ctypes.c_ubyte * 6),
    ('_bounds', union_siginfo_t_0_4__bounds),
]

class struct_siginfo_t_0__sigpoll(Structure):
    pass

struct_siginfo_t_0__sigpoll._pack_ = 1 # source:False
struct_siginfo_t_0__sigpoll._fields_ = [
    ('si_band', ctypes.c_int64),
    ('si_fd', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

class struct_siginfo_t_0__sigsys(Structure):
    pass

struct_siginfo_t_0__sigsys._pack_ = 1 # source:False
struct_siginfo_t_0__sigsys._fields_ = [
    ('_call_addr', ctypes.POINTER(None)),
    ('_syscall', ctypes.c_int32),
    ('_arch', ctypes.c_uint32),
]

union_siginfo_t__sifields._pack_ = 1 # source:False
union_siginfo_t__sifields._fields_ = [
    ('_pad', ctypes.c_int32 * 28),
    ('_kill', struct_siginfo_t_0__kill),
    ('_timer', struct_siginfo_t_0__timer),
    ('_rt', struct_siginfo_t_0__rt),
    ('_sigchld', struct_siginfo_t_0__sigchld),
    ('_sigfault', struct_siginfo_t_0__sigfault),
    ('_sigpoll', struct_siginfo_t_0__sigpoll),
    ('_sigsys', struct_siginfo_t_0__sigsys),
    ('PADDING_0', ctypes.c_ubyte * 96),
]

struct_siginfo_t._pack_ = 1 # source:False
struct_siginfo_t._fields_ = [
    ('si_signo', ctypes.c_int32),
    ('si_errno', ctypes.c_int32),
    ('si_code', ctypes.c_int32),
    ('__pad0', ctypes.c_int32),
    ('_sifields', union_siginfo_t__sifields),
]

siginfo_t = struct_siginfo_t

# values for enumeration 'c__Ea_SI_ASYNCNL'
c__Ea_SI_ASYNCNL__enumvalues = {
    -60: 'SI_ASYNCNL',
    -7: 'SI_DETHREAD',
    -6: 'SI_TKILL',
    -5: 'SI_SIGIO',
    -4: 'SI_ASYNCIO',
    -3: 'SI_MESGQ',
    -2: 'SI_TIMER',
    -1: 'SI_QUEUE',
    0: 'SI_USER',
    128: 'SI_KERNEL',
}
SI_ASYNCNL = -60
SI_DETHREAD = -7
SI_TKILL = -6
SI_SIGIO = -5
SI_ASYNCIO = -4
SI_MESGQ = -3
SI_TIMER = -2
SI_QUEUE = -1
SI_USER = 0
SI_KERNEL = 128
c__Ea_SI_ASYNCNL = ctypes.c_int32 # enum

# values for enumeration 'c__Ea_ILL_ILLOPC'
c__Ea_ILL_ILLOPC__enumvalues = {
    1: 'ILL_ILLOPC',
    2: 'ILL_ILLOPN',
    3: 'ILL_ILLADR',
    4: 'ILL_ILLTRP',
    5: 'ILL_PRVOPC',
    6: 'ILL_PRVREG',
    7: 'ILL_COPROC',
    8: 'ILL_BADSTK',
    9: 'ILL_BADIADDR',
}
ILL_ILLOPC = 1
ILL_ILLOPN = 2
ILL_ILLADR = 3
ILL_ILLTRP = 4
ILL_PRVOPC = 5
ILL_PRVREG = 6
ILL_COPROC = 7
ILL_BADSTK = 8
ILL_BADIADDR = 9
c__Ea_ILL_ILLOPC = ctypes.c_uint32 # enum

# values for enumeration 'c__Ea_FPE_INTDIV'
c__Ea_FPE_INTDIV__enumvalues = {
    1: 'FPE_INTDIV',
    2: 'FPE_INTOVF',
    3: 'FPE_FLTDIV',
    4: 'FPE_FLTOVF',
    5: 'FPE_FLTUND',
    6: 'FPE_FLTRES',
    7: 'FPE_FLTINV',
    8: 'FPE_FLTSUB',
    14: 'FPE_FLTUNK',
    15: 'FPE_CONDTRAP',
}
FPE_INTDIV = 1
FPE_INTOVF = 2
FPE_FLTDIV = 3
FPE_FLTOVF = 4
FPE_FLTUND = 5
FPE_FLTRES = 6
FPE_FLTINV = 7
FPE_FLTSUB = 8
FPE_FLTUNK = 14
FPE_CONDTRAP = 15
c__Ea_FPE_INTDIV = ctypes.c_uint32 # enum

# values for enumeration 'c__Ea_SEGV_MAPERR'
c__Ea_SEGV_MAPERR__enumvalues = {
    1: 'SEGV_MAPERR',
    2: 'SEGV_ACCERR',
    3: 'SEGV_BNDERR',
    4: 'SEGV_PKUERR',
    5: 'SEGV_ACCADI',
    6: 'SEGV_ADIDERR',
    7: 'SEGV_ADIPERR',
    8: 'SEGV_MTEAERR',
    9: 'SEGV_MTESERR',
    10: 'SEGV_CPERR',
}
SEGV_MAPERR = 1
SEGV_ACCERR = 2
SEGV_BNDERR = 3
SEGV_PKUERR = 4
SEGV_ACCADI = 5
SEGV_ADIDERR = 6
SEGV_ADIPERR = 7
SEGV_MTEAERR = 8
SEGV_MTESERR = 9
SEGV_CPERR = 10
c__Ea_SEGV_MAPERR = ctypes.c_uint32 # enum

# values for enumeration 'c__Ea_BUS_ADRALN'
c__Ea_BUS_ADRALN__enumvalues = {
    1: 'BUS_ADRALN',
    2: 'BUS_ADRERR',
    3: 'BUS_OBJERR',
    4: 'BUS_MCEERR_AR',
    5: 'BUS_MCEERR_AO',
}
BUS_ADRALN = 1
BUS_ADRERR = 2
BUS_OBJERR = 3
BUS_MCEERR_AR = 4
BUS_MCEERR_AO = 5
c__Ea_BUS_ADRALN = ctypes.c_uint32 # enum

# values for enumeration 'c__Ea_CLD_EXITED'
c__Ea_CLD_EXITED__enumvalues = {
    1: 'CLD_EXITED',
    2: 'CLD_KILLED',
    3: 'CLD_DUMPED',
    4: 'CLD_TRAPPED',
    5: 'CLD_STOPPED',
    6: 'CLD_CONTINUED',
}
CLD_EXITED = 1
CLD_KILLED = 2
CLD_DUMPED = 3
CLD_TRAPPED = 4
CLD_STOPPED = 5
CLD_CONTINUED = 6
c__Ea_CLD_EXITED = ctypes.c_uint32 # enum

# values for enumeration 'c__Ea_POLL_IN'
c__Ea_POLL_IN__enumvalues = {
    1: 'POLL_IN',
    2: 'POLL_OUT',
    3: 'POLL_MSG',
    4: 'POLL_ERR',
    5: 'POLL_PRI',
    6: 'POLL_HUP',
}
POLL_IN = 1
POLL_OUT = 2
POLL_MSG = 3
POLL_ERR = 4
POLL_PRI = 5
POLL_HUP = 6
c__Ea_POLL_IN = ctypes.c_uint32 # enum
sigval_t = union_sigval
class struct_sigevent_0__sigev_thread(Structure):
    pass

struct_sigevent_0__sigev_thread._pack_ = 1 # source:False
struct_sigevent_0__sigev_thread._fields_ = [
    ('_function', ctypes.CFUNCTYPE(None, union_sigval)),
    ('_attribute', ctypes.POINTER(union_pthread_attr_t)),
]

class union_sigevent__sigev_un(Union):
    pass

union_sigevent__sigev_un._pack_ = 1 # source:False
union_sigevent__sigev_un._fields_ = [
    ('_pad', ctypes.c_int32 * 12),
    ('_tid', ctypes.c_int32),
    ('_sigev_thread', struct_sigevent_0__sigev_thread),
    ('PADDING_0', ctypes.c_ubyte * 32),
]

struct_sigevent._pack_ = 1 # source:False
struct_sigevent._fields_ = [
    ('sigev_value', globals()['__sigval_t']),
    ('sigev_signo', ctypes.c_int32),
    ('sigev_notify', ctypes.c_int32),
    ('_sigev_un', union_sigevent__sigev_un),
]

sigevent_t = struct_sigevent

# values for enumeration 'c__Ea_SIGEV_SIGNAL'
c__Ea_SIGEV_SIGNAL__enumvalues = {
    0: 'SIGEV_SIGNAL',
    1: 'SIGEV_NONE',
    2: 'SIGEV_THREAD',
    4: 'SIGEV_THREAD_ID',
}
SIGEV_SIGNAL = 0
SIGEV_NONE = 1
SIGEV_THREAD = 2
SIGEV_THREAD_ID = 4
c__Ea_SIGEV_SIGNAL = ctypes.c_uint32 # enum
__sighandler_t = ctypes.CFUNCTYPE(None, ctypes.c_int32)
try:
    __sysv_signal = _libraries['FIXME_STUB'].__sysv_signal
    __sysv_signal.restype = __sighandler_t
    __sysv_signal.argtypes = [ctypes.c_int32, __sighandler_t]
except AttributeError:
    pass
try:
    signal = _libraries['FIXME_STUB'].signal
    signal.restype = __sighandler_t
    signal.argtypes = [ctypes.c_int32, __sighandler_t]
except AttributeError:
    pass
try:
    kill = _libraries['FIXME_STUB'].kill
    kill.restype = ctypes.c_int32
    kill.argtypes = [__pid_t, ctypes.c_int32]
except AttributeError:
    pass
try:
    killpg = _libraries['FIXME_STUB'].killpg
    killpg.restype = ctypes.c_int32
    killpg.argtypes = [__pid_t, ctypes.c_int32]
except AttributeError:
    pass
try:
    raise_ = _libraries['FIXME_STUB'].raise_
    raise_.restype = ctypes.c_int32
    raise_.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    ssignal = _libraries['FIXME_STUB'].ssignal
    ssignal.restype = __sighandler_t
    ssignal.argtypes = [ctypes.c_int32, __sighandler_t]
except AttributeError:
    pass
try:
    gsignal = _libraries['FIXME_STUB'].gsignal
    gsignal.restype = ctypes.c_int32
    gsignal.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    psignal = _libraries['FIXME_STUB'].psignal
    psignal.restype = None
    psignal.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    psiginfo = _libraries['FIXME_STUB'].psiginfo
    psiginfo.restype = None
    psiginfo.argtypes = [ctypes.POINTER(struct_siginfo_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    sigblock = _libraries['FIXME_STUB'].sigblock
    sigblock.restype = ctypes.c_int32
    sigblock.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    sigsetmask = _libraries['FIXME_STUB'].sigsetmask
    sigsetmask.restype = ctypes.c_int32
    sigsetmask.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    siggetmask = _libraries['FIXME_STUB'].siggetmask
    siggetmask.restype = ctypes.c_int32
    siggetmask.argtypes = []
except AttributeError:
    pass
sig_t = ctypes.CFUNCTYPE(None, ctypes.c_int32)
try:
    sigemptyset = _libraries['FIXME_STUB'].sigemptyset
    sigemptyset.restype = ctypes.c_int32
    sigemptyset.argtypes = [ctypes.POINTER(struct___sigset_t)]
except AttributeError:
    pass
try:
    sigfillset = _libraries['FIXME_STUB'].sigfillset
    sigfillset.restype = ctypes.c_int32
    sigfillset.argtypes = [ctypes.POINTER(struct___sigset_t)]
except AttributeError:
    pass
try:
    sigaddset = _libraries['FIXME_STUB'].sigaddset
    sigaddset.restype = ctypes.c_int32
    sigaddset.argtypes = [ctypes.POINTER(struct___sigset_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    sigdelset = _libraries['FIXME_STUB'].sigdelset
    sigdelset.restype = ctypes.c_int32
    sigdelset.argtypes = [ctypes.POINTER(struct___sigset_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    sigismember = _libraries['FIXME_STUB'].sigismember
    sigismember.restype = ctypes.c_int32
    sigismember.argtypes = [ctypes.POINTER(struct___sigset_t), ctypes.c_int32]
except AttributeError:
    pass
class struct_sigaction(Structure):
    pass

class union_sigaction___sigaction_handler(Union):
    pass

union_sigaction___sigaction_handler._pack_ = 1 # source:False
union_sigaction___sigaction_handler._fields_ = [
    ('sa_handler', ctypes.CFUNCTYPE(None, ctypes.c_int32)),
    ('sa_sigaction', ctypes.CFUNCTYPE(None, ctypes.c_int32, ctypes.POINTER(struct_siginfo_t), ctypes.POINTER(None))),
]

struct_sigaction._pack_ = 1 # source:False
struct_sigaction._fields_ = [
    ('__sigaction_handler', union_sigaction___sigaction_handler),
    ('sa_mask', globals()['__sigset_t']),
    ('sa_flags', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('sa_restorer', ctypes.CFUNCTYPE(None)),
]

try:
    sigprocmask = _libraries['FIXME_STUB'].sigprocmask
    sigprocmask.restype = ctypes.c_int32
    sigprocmask.argtypes = [ctypes.c_int32, ctypes.POINTER(struct___sigset_t), ctypes.POINTER(struct___sigset_t)]
except AttributeError:
    pass
try:
    sigsuspend = _libraries['FIXME_STUB'].sigsuspend
    sigsuspend.restype = ctypes.c_int32
    sigsuspend.argtypes = [ctypes.POINTER(struct___sigset_t)]
except AttributeError:
    pass
try:
    sigaction = _libraries['FIXME_STUB'].sigaction
    sigaction.restype = ctypes.c_int32
    sigaction.argtypes = [ctypes.c_int32, ctypes.POINTER(struct_sigaction), ctypes.POINTER(struct_sigaction)]
except AttributeError:
    pass
try:
    sigpending = _libraries['FIXME_STUB'].sigpending
    sigpending.restype = ctypes.c_int32
    sigpending.argtypes = [ctypes.POINTER(struct___sigset_t)]
except AttributeError:
    pass
try:
    sigwait = _libraries['FIXME_STUB'].sigwait
    sigwait.restype = ctypes.c_int32
    sigwait.argtypes = [ctypes.POINTER(struct___sigset_t), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    sigwaitinfo = _libraries['FIXME_STUB'].sigwaitinfo
    sigwaitinfo.restype = ctypes.c_int32
    sigwaitinfo.argtypes = [ctypes.POINTER(struct___sigset_t), ctypes.POINTER(struct_siginfo_t)]
except AttributeError:
    pass
try:
    sigtimedwait = _libraries['FIXME_STUB'].sigtimedwait
    sigtimedwait.restype = ctypes.c_int32
    sigtimedwait.argtypes = [ctypes.POINTER(struct___sigset_t), ctypes.POINTER(struct_siginfo_t), ctypes.POINTER(struct_timespec)]
except AttributeError:
    pass
try:
    sigqueue = _libraries['FIXME_STUB'].sigqueue
    sigqueue.restype = ctypes.c_int32
    sigqueue.argtypes = [__pid_t, ctypes.c_int32, union_sigval]
except AttributeError:
    pass
class struct__fpx_sw_bytes(Structure):
    pass

struct__fpx_sw_bytes._pack_ = 1 # source:False
struct__fpx_sw_bytes._fields_ = [
    ('magic1', ctypes.c_uint32),
    ('extended_size', ctypes.c_uint32),
    ('xstate_bv', ctypes.c_uint64),
    ('xstate_size', ctypes.c_uint32),
    ('__glibc_reserved1', ctypes.c_uint32 * 7),
]

class struct__fpreg(Structure):
    pass

struct__fpreg._pack_ = 1 # source:False
struct__fpreg._fields_ = [
    ('significand', ctypes.c_uint16 * 4),
    ('exponent', ctypes.c_uint16),
]

class struct__fpxreg(Structure):
    pass

struct__fpxreg._pack_ = 1 # source:False
struct__fpxreg._fields_ = [
    ('significand', ctypes.c_uint16 * 4),
    ('exponent', ctypes.c_uint16),
    ('__glibc_reserved1', ctypes.c_uint16 * 3),
]

class struct__xmmreg(Structure):
    pass

struct__xmmreg._pack_ = 1 # source:False
struct__xmmreg._fields_ = [
    ('element', ctypes.c_uint32 * 4),
]

class struct__fpstate(Structure):
    pass

struct__fpstate._pack_ = 1 # source:False
struct__fpstate._fields_ = [
    ('cwd', ctypes.c_uint16),
    ('swd', ctypes.c_uint16),
    ('ftw', ctypes.c_uint16),
    ('fop', ctypes.c_uint16),
    ('rip', ctypes.c_uint64),
    ('rdp', ctypes.c_uint64),
    ('mxcsr', ctypes.c_uint32),
    ('mxcr_mask', ctypes.c_uint32),
    ('_st', struct__fpxreg * 8),
    ('_xmm', struct__xmmreg * 16),
    ('__glibc_reserved1', ctypes.c_uint32 * 24),
]

class struct_sigcontext(Structure):
    pass

class union_sigcontext_0(Union):
    pass

union_sigcontext_0._pack_ = 1 # source:False
union_sigcontext_0._fields_ = [
    ('fpstate', ctypes.POINTER(struct__fpstate)),
    ('__fpstate_word', ctypes.c_uint64),
]

struct_sigcontext._pack_ = 1 # source:False
struct_sigcontext._anonymous_ = ('_0',)
struct_sigcontext._fields_ = [
    ('r8', ctypes.c_uint64),
    ('r9', ctypes.c_uint64),
    ('r10', ctypes.c_uint64),
    ('r11', ctypes.c_uint64),
    ('r12', ctypes.c_uint64),
    ('r13', ctypes.c_uint64),
    ('r14', ctypes.c_uint64),
    ('r15', ctypes.c_uint64),
    ('rdi', ctypes.c_uint64),
    ('rsi', ctypes.c_uint64),
    ('rbp', ctypes.c_uint64),
    ('rbx', ctypes.c_uint64),
    ('rdx', ctypes.c_uint64),
    ('rax', ctypes.c_uint64),
    ('rcx', ctypes.c_uint64),
    ('rsp', ctypes.c_uint64),
    ('rip', ctypes.c_uint64),
    ('eflags', ctypes.c_uint64),
    ('cs', ctypes.c_uint16),
    ('gs', ctypes.c_uint16),
    ('fs', ctypes.c_uint16),
    ('__pad0', ctypes.c_uint16),
    ('err', ctypes.c_uint64),
    ('trapno', ctypes.c_uint64),
    ('oldmask', ctypes.c_uint64),
    ('cr2', ctypes.c_uint64),
    ('_0', union_sigcontext_0),
    ('__reserved1', ctypes.c_uint64 * 8),
]

class struct__xsave_hdr(Structure):
    pass

struct__xsave_hdr._pack_ = 1 # source:False
struct__xsave_hdr._fields_ = [
    ('xstate_bv', ctypes.c_uint64),
    ('__glibc_reserved1', ctypes.c_uint64 * 2),
    ('__glibc_reserved2', ctypes.c_uint64 * 5),
]

class struct__ymmh_state(Structure):
    pass

struct__ymmh_state._pack_ = 1 # source:False
struct__ymmh_state._fields_ = [
    ('ymmh_space', ctypes.c_uint32 * 64),
]

class struct__xstate(Structure):
    _pack_ = 1 # source:False
    _fields_ = [
    ('fpstate', struct__fpstate),
    ('xstate_hdr', struct__xsave_hdr),
    ('ymmh', struct__ymmh_state),
     ]

try:
    sigreturn = _libraries['FIXME_STUB'].sigreturn
    sigreturn.restype = ctypes.c_int32
    sigreturn.argtypes = [ctypes.POINTER(struct_sigcontext)]
except AttributeError:
    pass
class struct_stack_t(Structure):
    pass

struct_stack_t._pack_ = 1 # source:False
struct_stack_t._fields_ = [
    ('ss_sp', ctypes.POINTER(None)),
    ('ss_flags', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('ss_size', ctypes.c_uint64),
]

stack_t = struct_stack_t
greg_t = ctypes.c_int64
gregset_t = ctypes.c_int64 * 23
class struct__libc_fpxreg(Structure):
    pass

struct__libc_fpxreg._pack_ = 1 # source:False
struct__libc_fpxreg._fields_ = [
    ('significand', ctypes.c_uint16 * 4),
    ('exponent', ctypes.c_uint16),
    ('__glibc_reserved1', ctypes.c_uint16 * 3),
]

class struct__libc_xmmreg(Structure):
    pass

struct__libc_xmmreg._pack_ = 1 # source:False
struct__libc_xmmreg._fields_ = [
    ('element', ctypes.c_uint32 * 4),
]

class struct__libc_fpstate(Structure):
    pass

struct__libc_fpstate._pack_ = 1 # source:False
struct__libc_fpstate._fields_ = [
    ('cwd', ctypes.c_uint16),
    ('swd', ctypes.c_uint16),
    ('ftw', ctypes.c_uint16),
    ('fop', ctypes.c_uint16),
    ('rip', ctypes.c_uint64),
    ('rdp', ctypes.c_uint64),
    ('mxcsr', ctypes.c_uint32),
    ('mxcr_mask', ctypes.c_uint32),
    ('_st', struct__libc_fpxreg * 8),
    ('_xmm', struct__libc_xmmreg * 16),
    ('__glibc_reserved1', ctypes.c_uint32 * 24),
]

fpregset_t = ctypes.POINTER(struct__libc_fpstate)
class struct_mcontext_t(Structure):
    pass

struct_mcontext_t._pack_ = 1 # source:False
struct_mcontext_t._fields_ = [
    ('gregs', ctypes.c_int64 * 23),
    ('fpregs', ctypes.POINTER(struct__libc_fpstate)),
    ('__reserved1', ctypes.c_uint64 * 8),
]

mcontext_t = struct_mcontext_t
class struct_ucontext_t(Structure):
    pass

struct_ucontext_t._pack_ = 1 # source:False
struct_ucontext_t._fields_ = [
    ('uc_flags', ctypes.c_uint64),
    ('uc_link', ctypes.POINTER(struct_ucontext_t)),
    ('uc_stack', stack_t),
    ('uc_mcontext', mcontext_t),
    ('uc_sigmask', sigset_t),
    ('__fpregs_mem', struct__libc_fpstate),
    ('__ssp', ctypes.c_uint64 * 4),
]

ucontext_t = struct_ucontext_t
try:
    siginterrupt = _libraries['FIXME_STUB'].siginterrupt
    siginterrupt.restype = ctypes.c_int32
    siginterrupt.argtypes = [ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass

# values for enumeration 'c__Ea_SS_ONSTACK'
c__Ea_SS_ONSTACK__enumvalues = {
    1: 'SS_ONSTACK',
    2: 'SS_DISABLE',
}
SS_ONSTACK = 1
SS_DISABLE = 2
c__Ea_SS_ONSTACK = ctypes.c_uint32 # enum
try:
    sigaltstack = _libraries['FIXME_STUB'].sigaltstack
    sigaltstack.restype = ctypes.c_int32
    sigaltstack.argtypes = [ctypes.POINTER(struct_stack_t), ctypes.POINTER(struct_stack_t)]
except AttributeError:
    pass
class struct_sigstack(Structure):
    pass

struct_sigstack._pack_ = 1 # source:False
struct_sigstack._fields_ = [
    ('ss_sp', ctypes.POINTER(None)),
    ('ss_onstack', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

try:
    sigstack = _libraries['FIXME_STUB'].sigstack
    sigstack.restype = ctypes.c_int32
    sigstack.argtypes = [ctypes.POINTER(struct_sigstack), ctypes.POINTER(struct_sigstack)]
except AttributeError:
    pass
try:
    pthread_sigmask = _libraries['FIXME_STUB'].pthread_sigmask
    pthread_sigmask.restype = ctypes.c_int32
    pthread_sigmask.argtypes = [ctypes.c_int32, ctypes.POINTER(struct___sigset_t), ctypes.POINTER(struct___sigset_t)]
except AttributeError:
    pass
try:
    pthread_kill = _libraries['FIXME_STUB'].pthread_kill
    pthread_kill.restype = ctypes.c_int32
    pthread_kill.argtypes = [pthread_t, ctypes.c_int32]
except AttributeError:
    pass
try:
    __libc_current_sigrtmin = _libraries['FIXME_STUB'].__libc_current_sigrtmin
    __libc_current_sigrtmin.restype = ctypes.c_int32
    __libc_current_sigrtmin.argtypes = []
except AttributeError:
    pass
try:
    __libc_current_sigrtmax = _libraries['FIXME_STUB'].__libc_current_sigrtmax
    __libc_current_sigrtmax.restype = ctypes.c_int32
    __libc_current_sigrtmax.argtypes = []
except AttributeError:
    pass
class struct_ht_up_kv(Structure):
    pass

struct_ht_up_kv._pack_ = 1 # source:False
struct_ht_up_kv._fields_ = [
    ('key', ctypes.c_uint64),
    ('value', ctypes.POINTER(None)),
    ('key_len', ctypes.c_uint32),
    ('value_len', ctypes.c_uint32),
]

HtUPKv = struct_ht_up_kv
HtUPKvFreeFunc = ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_ht_up_kv))
HtUPDupKey = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64)
HtUPDupValue = ctypes.CFUNCTYPE(ctypes.POINTER(None), ctypes.POINTER(None))
HtUPCalcSizeK = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_uint64)
HtUPCalcSizeV = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.POINTER(None))
HtUPHashFunction = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_uint64)
HtUPListComparator = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_uint64, ctypes.c_uint64)
HtUPForeachCallback = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(None), ctypes.c_uint64, ctypes.POINTER(None))
class struct_ht_up_bucket_t(Structure):
    pass

struct_ht_up_bucket_t._pack_ = 1 # source:False
struct_ht_up_bucket_t._fields_ = [
    ('arr', ctypes.POINTER(struct_ht_up_kv)),
    ('count', ctypes.c_uint32),
    ('size', ctypes.c_uint32),
]

HtUPBucket = struct_ht_up_bucket_t
class struct_ht_up_options_t(Structure):
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

HtUPOptions = struct_ht_up_options_t
class struct_ht_up_t(Structure):
    pass

struct_ht_up_t._pack_ = 1 # source:False
struct_ht_up_t._fields_ = [
    ('size', ctypes.c_uint32),
    ('count', ctypes.c_uint32),
    ('table', ctypes.POINTER(struct_ht_up_bucket_t)),
    ('prime_idx', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('opt', HtUPOptions),
]

HtUP = struct_ht_up_t
try:
    ht_up_new_opt = _libr_anal.ht_up_new_opt
    ht_up_new_opt.restype = ctypes.POINTER(struct_ht_up_t)
    ht_up_new_opt.argtypes = [ctypes.POINTER(struct_ht_up_options_t)]
except AttributeError:
    pass
try:
    ht_up_free = _libr_anal.ht_up_free
    ht_up_free.restype = None
    ht_up_free.argtypes = [ctypes.POINTER(struct_ht_up_t)]
except AttributeError:
    pass
try:
    ht_up_insert = _libr_anal.ht_up_insert
    ht_up_insert.restype = ctypes.c_bool
    ht_up_insert.argtypes = [ctypes.POINTER(struct_ht_up_t), uint64_t, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    ht_up_update = _libr_anal.ht_up_update
    ht_up_update.restype = ctypes.c_bool
    ht_up_update.argtypes = [ctypes.POINTER(struct_ht_up_t), uint64_t, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    ht_up_update_key = _libr_anal.ht_up_update_key
    ht_up_update_key.restype = ctypes.c_bool
    ht_up_update_key.argtypes = [ctypes.POINTER(struct_ht_up_t), uint64_t, uint64_t]
except AttributeError:
    pass
try:
    ht_up_delete = _libr_anal.ht_up_delete
    ht_up_delete.restype = ctypes.c_bool
    ht_up_delete.argtypes = [ctypes.POINTER(struct_ht_up_t), uint64_t]
except AttributeError:
    pass
try:
    ht_up_find = _libr_anal.ht_up_find
    ht_up_find.restype = ctypes.POINTER(None)
    ht_up_find.argtypes = [ctypes.POINTER(struct_ht_up_t), uint64_t, ctypes.POINTER(ctypes.c_bool)]
except AttributeError:
    pass
try:
    ht_up_foreach = _libr_anal.ht_up_foreach
    ht_up_foreach.restype = None
    ht_up_foreach.argtypes = [ctypes.POINTER(struct_ht_up_t), HtUPForeachCallback, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    ht_up_find_kv = _libr_anal.ht_up_find_kv
    ht_up_find_kv.restype = ctypes.POINTER(struct_ht_up_kv)
    ht_up_find_kv.argtypes = [ctypes.POINTER(struct_ht_up_t), uint64_t, ctypes.POINTER(ctypes.c_bool)]
except AttributeError:
    pass
try:
    ht_up_insert_kv = _libr_anal.ht_up_insert_kv
    ht_up_insert_kv.restype = ctypes.c_bool
    ht_up_insert_kv.argtypes = [ctypes.POINTER(struct_ht_up_t), ctypes.POINTER(struct_ht_up_kv), ctypes.c_bool]
except AttributeError:
    pass
try:
    ht_up_new0 = _libr_anal.ht_up_new0
    ht_up_new0.restype = ctypes.POINTER(struct_ht_up_t)
    ht_up_new0.argtypes = []
except AttributeError:
    pass
try:
    ht_up_new = _libr_anal.ht_up_new
    ht_up_new.restype = ctypes.POINTER(struct_ht_up_t)
    ht_up_new.argtypes = [HtUPDupValue, HtUPKvFreeFunc, HtUPCalcSizeV]
except AttributeError:
    pass
try:
    ht_up_new_size = _libr_anal.ht_up_new_size
    ht_up_new_size.restype = ctypes.POINTER(struct_ht_up_t)
    ht_up_new_size.argtypes = [uint32_t, HtUPDupValue, HtUPKvFreeFunc, HtUPCalcSizeV]
except AttributeError:
    pass

# values for enumeration 'r_log_level'
r_log_level__enumvalues = {
    0: 'R_LOGLVL_FATAL',
    1: 'R_LOGLVL_ERROR',
    2: 'R_LOGLVL_INFO',
    3: 'R_LOGLVL_WARN',
    4: 'R_LOGLVL_TODO',
    5: 'R_LOGLVL_DEBUG',
    6: 'R_LOGLVL_LAST',
}
R_LOGLVL_FATAL = 0
R_LOGLVL_ERROR = 1
R_LOGLVL_INFO = 2
R_LOGLVL_WARN = 3
R_LOGLVL_TODO = 4
R_LOGLVL_DEBUG = 5
R_LOGLVL_LAST = 6
r_log_level = ctypes.c_uint32 # enum
RLogLevel = r_log_level
RLogLevel__enumvalues = r_log_level__enumvalues
RLogCallback = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(None), ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char))
class struct_r_log_t(Structure):
    pass

struct_r_log_t._pack_ = 1 # source:False
struct_r_log_t._fields_ = [
    ('level', ctypes.c_int32),
    ('traplevel', ctypes.c_int32),
    ('user', ctypes.POINTER(None)),
    ('file', ctypes.POINTER(ctypes.c_char)),
    ('filter', ctypes.POINTER(ctypes.c_char)),
    ('color', ctypes.c_bool),
    ('quiet', ctypes.c_bool),
    ('show_origin', ctypes.c_bool),
    ('show_source', ctypes.c_bool),
    ('show_ts', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 3),
    ('cbs', ctypes.POINTER(struct_r_list_t)),
]

RLog = struct_r_log_t
class struct_r_log_source_t(Structure):
    pass

struct_r_log_source_t._pack_ = 1 # source:False
struct_r_log_source_t._fields_ = [
    ('file', ctypes.POINTER(ctypes.c_char)),
    ('lineno', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('source', ctypes.POINTER(ctypes.c_char)),
]

RLogSource = struct_r_log_source_t
try:
    r_log_init = _libr_util.r_log_init
    r_log_init.restype = None
    r_log_init.argtypes = []
except AttributeError:
    pass
try:
    r_log_fini = _libr_util.r_log_fini
    r_log_fini.restype = None
    r_log_fini.argtypes = []
except AttributeError:
    pass
try:
    r_log_match = _libr_util.r_log_match
    r_log_match.restype = ctypes.c_bool
    r_log_match.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_log_message = _libr_util.r_log_message
    r_log_message.restype = None
    r_log_message.argtypes = [RLogLevel, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_log_vmessage = _libr_util.r_log_vmessage
    r_log_vmessage.restype = None
    r_log_vmessage.argtypes = [RLogLevel, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(ctypes.c_char), va_list]
except AttributeError:
    pass
try:
    r_log_add_callback = _libr_util.r_log_add_callback
    r_log_add_callback.restype = None
    r_log_add_callback.argtypes = [RLogCallback, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_log_del_callback = _libr_util.r_log_del_callback
    r_log_del_callback.restype = None
    r_log_del_callback.argtypes = [RLogCallback]
except AttributeError:
    pass
try:
    r_log_set_file = _libr_util.r_log_set_file
    r_log_set_file.restype = None
    r_log_set_file.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_log_set_filter = _libr_util.r_log_set_filter
    r_log_set_filter.restype = None
    r_log_set_filter.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_log_set_colors = _libr_util.r_log_set_colors
    r_log_set_colors.restype = None
    r_log_set_colors.argtypes = [ctypes.c_bool]
except AttributeError:
    pass
try:
    r_log_show_origin = _libr_util.r_log_show_origin
    r_log_show_origin.restype = None
    r_log_show_origin.argtypes = [ctypes.c_bool]
except AttributeError:
    pass
try:
    r_log_show_source = _libr_util.r_log_show_source
    r_log_show_source.restype = None
    r_log_show_source.argtypes = [ctypes.c_bool]
except AttributeError:
    pass
try:
    r_log_set_quiet = _libr_util.r_log_set_quiet
    r_log_set_quiet.restype = None
    r_log_set_quiet.argtypes = [ctypes.c_bool]
except AttributeError:
    pass
try:
    r_log_set_level = _libr_util.r_log_set_level
    r_log_set_level.restype = None
    r_log_set_level.argtypes = [RLogLevel]
except AttributeError:
    pass
try:
    r_log_show_ts = _libr_util.r_log_show_ts
    r_log_show_ts.restype = None
    r_log_show_ts.argtypes = [ctypes.c_bool]
except AttributeError:
    pass
try:
    r_log_get_level = _libr_util.r_log_get_level
    r_log_get_level.restype = RLogLevel
    r_log_get_level.argtypes = []
except AttributeError:
    pass
try:
    r_log_get_traplevel = _libr_util.r_log_get_traplevel
    r_log_get_traplevel.restype = RLogLevel
    r_log_get_traplevel.argtypes = []
except AttributeError:
    pass
try:
    r_log_set_traplevel = _libr_util.r_log_set_traplevel
    r_log_set_traplevel.restype = None
    r_log_set_traplevel.argtypes = [RLogLevel]
except AttributeError:
    pass
try:
    r_log_set_callback = _libraries['FIXME_STUB'].r_log_set_callback
    r_log_set_callback.restype = None
    r_log_set_callback.argtypes = [RLogCallback]
except AttributeError:
    pass
try:
    r_log = _libr_util.r_log
    r_log.restype = None
    r_log.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), uint32_t, RLogLevel, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_vlog = _libraries['FIXME_STUB'].r_vlog
    r_vlog.restype = None
    r_vlog.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), uint32_t, RLogLevel, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), va_list]
except AttributeError:
    pass
try:
    r_assert_log = _libr_util.r_assert_log
    r_assert_log.restype = None
    r_assert_log.argtypes = [RLogLevel, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
RPVectorComparator = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(None))
RVectorFree = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(None))
RPVectorFree = ctypes.CFUNCTYPE(None, ctypes.POINTER(None))
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

RVector = struct_r_vector_t
class struct_r_pvector_t(Structure):
    _pack_ = 1 # source:False
    _fields_ = [
    ('v', RVector),
     ]

RPVector = struct_r_pvector_t
try:
    r_vector_init = _libr_util.r_vector_init
    r_vector_init.restype = None
    r_vector_init.argtypes = [ctypes.POINTER(struct_r_vector_t), size_t, RVectorFree, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_vector_new = _libr_util.r_vector_new
    r_vector_new.restype = ctypes.POINTER(struct_r_vector_t)
    r_vector_new.argtypes = [size_t, RVectorFree, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_vector_fini = _libr_util.r_vector_fini
    r_vector_fini.restype = None
    r_vector_fini.argtypes = [ctypes.POINTER(struct_r_vector_t)]
except AttributeError:
    pass
try:
    r_vector_free = _libr_util.r_vector_free
    r_vector_free.restype = None
    r_vector_free.argtypes = [ctypes.POINTER(struct_r_vector_t)]
except AttributeError:
    pass
try:
    r_vector_clone = _libr_util.r_vector_clone
    r_vector_clone.restype = ctypes.POINTER(struct_r_vector_t)
    r_vector_clone.argtypes = [ctypes.POINTER(struct_r_vector_t)]
except AttributeError:
    pass
try:
    r_vector_empty = _libraries['FIXME_STUB'].r_vector_empty
    r_vector_empty.restype = ctypes.c_bool
    r_vector_empty.argtypes = [ctypes.POINTER(struct_r_vector_t)]
except AttributeError:
    pass
try:
    r_vector_clear = _libr_util.r_vector_clear
    r_vector_clear.restype = None
    r_vector_clear.argtypes = [ctypes.POINTER(struct_r_vector_t)]
except AttributeError:
    pass
try:
    r_vector_len = _libraries['FIXME_STUB'].r_vector_len
    r_vector_len.restype = size_t
    r_vector_len.argtypes = [ctypes.POINTER(struct_r_vector_t)]
except AttributeError:
    pass
try:
    r_vector_index_ptr = _libraries['FIXME_STUB'].r_vector_index_ptr
    r_vector_index_ptr.restype = ctypes.POINTER(None)
    r_vector_index_ptr.argtypes = [ctypes.POINTER(struct_r_vector_t), size_t]
except AttributeError:
    pass
try:
    r_vector_assign = _libr_util.r_vector_assign
    r_vector_assign.restype = None
    r_vector_assign.argtypes = [ctypes.POINTER(struct_r_vector_t), ctypes.POINTER(None), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_vector_assign_at = _libr_util.r_vector_assign_at
    r_vector_assign_at.restype = ctypes.POINTER(None)
    r_vector_assign_at.argtypes = [ctypes.POINTER(struct_r_vector_t), size_t, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_vector_remove_at = _libr_util.r_vector_remove_at
    r_vector_remove_at.restype = None
    r_vector_remove_at.argtypes = [ctypes.POINTER(struct_r_vector_t), size_t, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_vector_insert = _libr_util.r_vector_insert
    r_vector_insert.restype = ctypes.POINTER(None)
    r_vector_insert.argtypes = [ctypes.POINTER(struct_r_vector_t), size_t, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_vector_insert_range = _libr_util.r_vector_insert_range
    r_vector_insert_range.restype = ctypes.POINTER(None)
    r_vector_insert_range.argtypes = [ctypes.POINTER(struct_r_vector_t), size_t, ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    r_vector_pop = _libr_util.r_vector_pop
    r_vector_pop.restype = None
    r_vector_pop.argtypes = [ctypes.POINTER(struct_r_vector_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_vector_pop_front = _libr_util.r_vector_pop_front
    r_vector_pop_front.restype = None
    r_vector_pop_front.argtypes = [ctypes.POINTER(struct_r_vector_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_vector_push = _libr_util.r_vector_push
    r_vector_push.restype = ctypes.POINTER(None)
    r_vector_push.argtypes = [ctypes.POINTER(struct_r_vector_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_vector_push_front = _libr_util.r_vector_push_front
    r_vector_push_front.restype = ctypes.POINTER(None)
    r_vector_push_front.argtypes = [ctypes.POINTER(struct_r_vector_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_vector_reserve = _libr_util.r_vector_reserve
    r_vector_reserve.restype = ctypes.POINTER(None)
    r_vector_reserve.argtypes = [ctypes.POINTER(struct_r_vector_t), size_t]
except AttributeError:
    pass
try:
    r_vector_shrink = _libr_util.r_vector_shrink
    r_vector_shrink.restype = ctypes.POINTER(None)
    r_vector_shrink.argtypes = [ctypes.POINTER(struct_r_vector_t)]
except AttributeError:
    pass
try:
    r_vector_flush = _libr_util.r_vector_flush
    r_vector_flush.restype = ctypes.POINTER(None)
    r_vector_flush.argtypes = [ctypes.POINTER(struct_r_vector_t)]
except AttributeError:
    pass
try:
    r_pvector_init = _libr_util.r_pvector_init
    r_pvector_init.restype = None
    r_pvector_init.argtypes = [ctypes.POINTER(struct_r_pvector_t), RPVectorFree]
except AttributeError:
    pass
try:
    r_pvector_fini = _libr_util.r_pvector_fini
    r_pvector_fini.restype = None
    r_pvector_fini.argtypes = [ctypes.POINTER(struct_r_pvector_t)]
except AttributeError:
    pass
try:
    r_pvector_new = _libr_util.r_pvector_new
    r_pvector_new.restype = ctypes.POINTER(struct_r_pvector_t)
    r_pvector_new.argtypes = [RPVectorFree]
except AttributeError:
    pass
try:
    r_pvector_new_with_len = _libr_util.r_pvector_new_with_len
    r_pvector_new_with_len.restype = ctypes.POINTER(struct_r_pvector_t)
    r_pvector_new_with_len.argtypes = [RPVectorFree, size_t]
except AttributeError:
    pass
try:
    r_pvector_clear = _libr_util.r_pvector_clear
    r_pvector_clear.restype = None
    r_pvector_clear.argtypes = [ctypes.POINTER(struct_r_pvector_t)]
except AttributeError:
    pass
try:
    r_pvector_free = _libr_util.r_pvector_free
    r_pvector_free.restype = None
    r_pvector_free.argtypes = [ctypes.POINTER(struct_r_pvector_t)]
except AttributeError:
    pass
try:
    r_pvector_len = _libraries['FIXME_STUB'].r_pvector_len
    r_pvector_len.restype = size_t
    r_pvector_len.argtypes = [ctypes.POINTER(struct_r_pvector_t)]
except AttributeError:
    pass
try:
    r_pvector_at = _libraries['FIXME_STUB'].r_pvector_at
    r_pvector_at.restype = ctypes.POINTER(None)
    r_pvector_at.argtypes = [ctypes.POINTER(struct_r_pvector_t), size_t]
except AttributeError:
    pass
try:
    r_pvector_set = _libraries['FIXME_STUB'].r_pvector_set
    r_pvector_set.restype = None
    r_pvector_set.argtypes = [ctypes.POINTER(struct_r_pvector_t), size_t, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_pvector_empty = _libraries['FIXME_STUB'].r_pvector_empty
    r_pvector_empty.restype = ctypes.c_bool
    r_pvector_empty.argtypes = [ctypes.POINTER(struct_r_pvector_t)]
except AttributeError:
    pass
try:
    r_pvector_index_ptr = _libraries['FIXME_STUB'].r_pvector_index_ptr
    r_pvector_index_ptr.restype = ctypes.POINTER(ctypes.POINTER(None))
    r_pvector_index_ptr.argtypes = [ctypes.POINTER(struct_r_pvector_t), size_t]
except AttributeError:
    pass
try:
    r_pvector_data = _libraries['FIXME_STUB'].r_pvector_data
    r_pvector_data.restype = ctypes.POINTER(ctypes.POINTER(None))
    r_pvector_data.argtypes = [ctypes.POINTER(struct_r_pvector_t)]
except AttributeError:
    pass
try:
    r_pvector_contains = _libr_util.r_pvector_contains
    r_pvector_contains.restype = ctypes.POINTER(ctypes.POINTER(None))
    r_pvector_contains.argtypes = [ctypes.POINTER(struct_r_pvector_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_pvector_remove_at = _libr_util.r_pvector_remove_at
    r_pvector_remove_at.restype = ctypes.POINTER(None)
    r_pvector_remove_at.argtypes = [ctypes.POINTER(struct_r_pvector_t), size_t]
except AttributeError:
    pass
try:
    r_pvector_remove_data = _libr_util.r_pvector_remove_data
    r_pvector_remove_data.restype = None
    r_pvector_remove_data.argtypes = [ctypes.POINTER(struct_r_pvector_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_pvector_insert = _libraries['FIXME_STUB'].r_pvector_insert
    r_pvector_insert.restype = ctypes.POINTER(ctypes.POINTER(None))
    r_pvector_insert.argtypes = [ctypes.POINTER(struct_r_pvector_t), size_t, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_pvector_insert_range = _libraries['FIXME_STUB'].r_pvector_insert_range
    r_pvector_insert_range.restype = ctypes.POINTER(ctypes.POINTER(None))
    r_pvector_insert_range.argtypes = [ctypes.POINTER(struct_r_pvector_t), size_t, ctypes.POINTER(ctypes.POINTER(None)), size_t]
except AttributeError:
    pass
try:
    r_pvector_pop = _libr_util.r_pvector_pop
    r_pvector_pop.restype = ctypes.POINTER(None)
    r_pvector_pop.argtypes = [ctypes.POINTER(struct_r_pvector_t)]
except AttributeError:
    pass
try:
    r_pvector_pop_front = _libr_util.r_pvector_pop_front
    r_pvector_pop_front.restype = ctypes.POINTER(None)
    r_pvector_pop_front.argtypes = [ctypes.POINTER(struct_r_pvector_t)]
except AttributeError:
    pass
try:
    r_pvector_push = _libraries['FIXME_STUB'].r_pvector_push
    r_pvector_push.restype = ctypes.POINTER(ctypes.POINTER(None))
    r_pvector_push.argtypes = [ctypes.POINTER(struct_r_pvector_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_pvector_push_front = _libraries['FIXME_STUB'].r_pvector_push_front
    r_pvector_push_front.restype = ctypes.POINTER(ctypes.POINTER(None))
    r_pvector_push_front.argtypes = [ctypes.POINTER(struct_r_pvector_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_pvector_sort = _libr_util.r_pvector_sort
    r_pvector_sort.restype = None
    r_pvector_sort.argtypes = [ctypes.POINTER(struct_r_pvector_t), RPVectorComparator]
except AttributeError:
    pass
try:
    r_pvector_bsearch = _libr_util.r_pvector_bsearch
    r_pvector_bsearch.restype = ctypes.c_int32
    r_pvector_bsearch.argtypes = [ctypes.POINTER(struct_r_pvector_t), ctypes.POINTER(None), RPVectorComparator]
except AttributeError:
    pass
try:
    r_pvector_reserve = _libraries['FIXME_STUB'].r_pvector_reserve
    r_pvector_reserve.restype = ctypes.POINTER(ctypes.POINTER(None))
    r_pvector_reserve.argtypes = [ctypes.POINTER(struct_r_pvector_t), size_t]
except AttributeError:
    pass
try:
    r_pvector_shrink = _libraries['FIXME_STUB'].r_pvector_shrink
    r_pvector_shrink.restype = ctypes.POINTER(ctypes.POINTER(None))
    r_pvector_shrink.argtypes = [ctypes.POINTER(struct_r_pvector_t)]
except AttributeError:
    pass
try:
    r_pvector_flush = _libraries['FIXME_STUB'].r_pvector_flush
    r_pvector_flush.restype = ctypes.POINTER(ctypes.POINTER(None))
    r_pvector_flush.argtypes = [ctypes.POINTER(struct_r_pvector_t)]
except AttributeError:
    pass
class struct_r_event_t(Structure):
    pass

struct_r_event_t._pack_ = 1 # source:False
struct_r_event_t._fields_ = [
    ('user', ctypes.POINTER(None)),
    ('incall', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
    ('callbacks', ctypes.POINTER(struct_ht_up_t)),
    ('all_callbacks', RVector),
    ('next_handle', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
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

# values for enumeration 'REventType'
REventType__enumvalues = {
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
REventType = ctypes.c_uint32 # enum
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
try:
    r_event_new = _libr_util.r_event_new
    r_event_new.restype = ctypes.POINTER(struct_r_event_t)
    r_event_new.argtypes = [ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_event_free = _libr_util.r_event_free
    r_event_free.restype = None
    r_event_free.argtypes = [ctypes.POINTER(struct_r_event_t)]
except AttributeError:
    pass
try:
    r_event_hook = _libr_util.r_event_hook
    r_event_hook.restype = REventCallbackHandle
    r_event_hook.argtypes = [ctypes.POINTER(struct_r_event_t), ctypes.c_int32, REventCallback, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_event_unhook = _libr_util.r_event_unhook
    r_event_unhook.restype = None
    r_event_unhook.argtypes = [ctypes.POINTER(struct_r_event_t), REventCallbackHandle]
except AttributeError:
    pass
try:
    r_event_send = _libr_util.r_event_send
    r_event_send.restype = None
    r_event_send.argtypes = [ctypes.POINTER(struct_r_event_t), ctypes.c_int32, ctypes.POINTER(None)]
except AttributeError:
    pass
class struct_r_interval_t(Structure):
    pass

struct_r_interval_t._pack_ = 1 # source:False
struct_r_interval_t._fields_ = [
    ('addr', ctypes.c_uint64),
    ('size', ctypes.c_uint64),
]

RInterval = struct_r_interval_t
r_itv_t = struct_r_interval_t
try:
    r_itv_new = _libraries['FIXME_STUB'].r_itv_new
    r_itv_new.restype = ctypes.POINTER(struct_r_interval_t)
    r_itv_new.argtypes = [uint64_t, uint64_t]
except AttributeError:
    pass
try:
    r_itv_free = _libraries['FIXME_STUB'].r_itv_free
    r_itv_free.restype = None
    r_itv_free.argtypes = [ctypes.POINTER(struct_r_interval_t)]
except AttributeError:
    pass
try:
    r_itv_begin = _libraries['FIXME_STUB'].r_itv_begin
    r_itv_begin.restype = uint64_t
    r_itv_begin.argtypes = [RInterval]
except AttributeError:
    pass
try:
    r_itv_size = _libraries['FIXME_STUB'].r_itv_size
    r_itv_size.restype = uint64_t
    r_itv_size.argtypes = [RInterval]
except AttributeError:
    pass
try:
    r_itv_end = _libraries['FIXME_STUB'].r_itv_end
    r_itv_end.restype = uint64_t
    r_itv_end.argtypes = [RInterval]
except AttributeError:
    pass
try:
    r_itv_eq = _libraries['FIXME_STUB'].r_itv_eq
    r_itv_eq.restype = ctypes.c_bool
    r_itv_eq.argtypes = [RInterval, RInterval]
except AttributeError:
    pass
try:
    r_itv_contain = _libraries['FIXME_STUB'].r_itv_contain
    r_itv_contain.restype = ctypes.c_bool
    r_itv_contain.argtypes = [RInterval, uint64_t]
except AttributeError:
    pass
try:
    r_itv_include = _libraries['FIXME_STUB'].r_itv_include
    r_itv_include.restype = ctypes.c_bool
    r_itv_include.argtypes = [RInterval, RInterval]
except AttributeError:
    pass
try:
    r_itv_overlap = _libraries['FIXME_STUB'].r_itv_overlap
    r_itv_overlap.restype = ctypes.c_bool
    r_itv_overlap.argtypes = [RInterval, RInterval]
except AttributeError:
    pass
try:
    r_itv_overlap2 = _libraries['FIXME_STUB'].r_itv_overlap2
    r_itv_overlap2.restype = ctypes.c_bool
    r_itv_overlap2.argtypes = [RInterval, uint64_t, uint64_t]
except AttributeError:
    pass
try:
    r_itv_intersect = _libraries['FIXME_STUB'].r_itv_intersect
    r_itv_intersect.restype = RInterval
    r_itv_intersect.argtypes = [RInterval, RInterval]
except AttributeError:
    pass
try:
    r_signal_from_string = _libr_util.r_signal_from_string
    r_signal_from_string.restype = ctypes.c_int32
    r_signal_from_string.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_signal_to_string = _libr_util.r_signal_to_string
    r_signal_to_string.restype = ctypes.POINTER(ctypes.c_char)
    r_signal_to_string.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_signal_to_human = _libr_util.r_signal_to_human
    r_signal_to_human.restype = ctypes.POINTER(ctypes.c_char)
    r_signal_to_human.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_signal_sigmask = _libr_util.r_signal_sigmask
    r_signal_sigmask.restype = None
    r_signal_sigmask.argtypes = [ctypes.c_int32, ctypes.POINTER(struct___sigset_t), ctypes.POINTER(struct___sigset_t)]
except AttributeError:
    pass
RMalloc = ctypes.CFUNCTYPE(ctypes.POINTER(None), ctypes.c_uint64)
RCalloc = ctypes.CFUNCTYPE(ctypes.POINTER(None), ctypes.c_uint64, ctypes.c_uint64)
RRealloc = ctypes.CFUNCTYPE(ctypes.POINTER(None), ctypes.POINTER(None), ctypes.c_uint64)
RFree = ctypes.CFUNCTYPE(None, ctypes.POINTER(None))
try:
    r_malloc_aligned = _libr_util.r_malloc_aligned
    r_malloc_aligned.restype = ctypes.POINTER(None)
    r_malloc_aligned.argtypes = [size_t, size_t]
except AttributeError:
    pass
try:
    r_free_aligned = _libr_util.r_free_aligned
    r_free_aligned.restype = None
    r_free_aligned.argtypes = [ctypes.POINTER(None)]
except AttributeError:
    pass
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
try:
    r_rbtree_aug_delete = _libr_util.r_rbtree_aug_delete
    r_rbtree_aug_delete.restype = ctypes.c_bool
    r_rbtree_aug_delete.argtypes = [ctypes.POINTER(ctypes.POINTER(struct_r_rb_node_t)), ctypes.POINTER(None), RBComparator, ctypes.POINTER(None), RBNodeFree, ctypes.POINTER(None), RBNodeSum]
except AttributeError:
    pass
try:
    r_rbtree_aug_insert = _libr_util.r_rbtree_aug_insert
    r_rbtree_aug_insert.restype = ctypes.c_bool
    r_rbtree_aug_insert.argtypes = [ctypes.POINTER(ctypes.POINTER(struct_r_rb_node_t)), ctypes.POINTER(None), ctypes.POINTER(struct_r_rb_node_t), RBComparator, ctypes.POINTER(None), RBNodeSum]
except AttributeError:
    pass
try:
    r_rbtree_aug_update_sum = _libr_util.r_rbtree_aug_update_sum
    r_rbtree_aug_update_sum.restype = ctypes.c_bool
    r_rbtree_aug_update_sum.argtypes = [ctypes.POINTER(struct_r_rb_node_t), ctypes.POINTER(None), ctypes.POINTER(struct_r_rb_node_t), RBComparator, ctypes.POINTER(None), RBNodeSum]
except AttributeError:
    pass
try:
    r_rbtree_delete = _libr_util.r_rbtree_delete
    r_rbtree_delete.restype = ctypes.c_bool
    r_rbtree_delete.argtypes = [ctypes.POINTER(ctypes.POINTER(struct_r_rb_node_t)), ctypes.POINTER(None), RBComparator, ctypes.POINTER(None), RBNodeFree, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_rbtree_find = _libr_util.r_rbtree_find
    r_rbtree_find.restype = ctypes.POINTER(struct_r_rb_node_t)
    r_rbtree_find.argtypes = [ctypes.POINTER(struct_r_rb_node_t), ctypes.POINTER(None), RBComparator, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_rbtree_free = _libr_util.r_rbtree_free
    r_rbtree_free.restype = None
    r_rbtree_free.argtypes = [ctypes.POINTER(struct_r_rb_node_t), RBNodeFree, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_rbtree_insert = _libr_util.r_rbtree_insert
    r_rbtree_insert.restype = None
    r_rbtree_insert.argtypes = [ctypes.POINTER(ctypes.POINTER(struct_r_rb_node_t)), ctypes.POINTER(None), ctypes.POINTER(struct_r_rb_node_t), RBComparator, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_rbtree_lower_bound = _libr_util.r_rbtree_lower_bound
    r_rbtree_lower_bound.restype = ctypes.POINTER(struct_r_rb_node_t)
    r_rbtree_lower_bound.argtypes = [ctypes.POINTER(struct_r_rb_node_t), ctypes.POINTER(None), RBComparator, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_rbtree_upper_bound = _libr_util.r_rbtree_upper_bound
    r_rbtree_upper_bound.restype = ctypes.POINTER(struct_r_rb_node_t)
    r_rbtree_upper_bound.argtypes = [ctypes.POINTER(struct_r_rb_node_t), ctypes.POINTER(None), RBComparator, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_rbtree_first = _libr_util.r_rbtree_first
    r_rbtree_first.restype = RBIter
    r_rbtree_first.argtypes = [ctypes.POINTER(struct_r_rb_node_t)]
except AttributeError:
    pass
try:
    r_rbtree_last = _libr_util.r_rbtree_last
    r_rbtree_last.restype = RBIter
    r_rbtree_last.argtypes = [ctypes.POINTER(struct_r_rb_node_t)]
except AttributeError:
    pass
try:
    r_rbtree_lower_bound_forward = _libr_util.r_rbtree_lower_bound_forward
    r_rbtree_lower_bound_forward.restype = RBIter
    r_rbtree_lower_bound_forward.argtypes = [ctypes.POINTER(struct_r_rb_node_t), ctypes.POINTER(None), RBComparator, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_rbtree_upper_bound_backward = _libr_util.r_rbtree_upper_bound_backward
    r_rbtree_upper_bound_backward.restype = RBIter
    r_rbtree_upper_bound_backward.argtypes = [ctypes.POINTER(struct_r_rb_node_t), ctypes.POINTER(None), RBComparator, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_rbtree_iter_next = _libr_util.r_rbtree_iter_next
    r_rbtree_iter_next.restype = None
    r_rbtree_iter_next.argtypes = [ctypes.POINTER(struct_r_rb_iter_t)]
except AttributeError:
    pass
try:
    r_rbtree_iter_prev = _libr_util.r_rbtree_iter_prev
    r_rbtree_iter_prev.restype = None
    r_rbtree_iter_prev.argtypes = [ctypes.POINTER(struct_r_rb_iter_t)]
except AttributeError:
    pass
class struct_r_crbtree_node(Structure):
    pass

struct_r_crbtree_node._pack_ = 1 # source:False
struct_r_crbtree_node._fields_ = [
    ('link', ctypes.POINTER(struct_r_crbtree_node) * 2),
    ('parent', ctypes.POINTER(struct_r_crbtree_node)),
    ('red', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('data', ctypes.POINTER(None)),
]

RRBNode = struct_r_crbtree_node
RRBComparator = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None))
RRBFree = ctypes.CFUNCTYPE(None, ctypes.POINTER(None))
class struct_r_crbtree_t(Structure):
    pass

struct_r_crbtree_t._pack_ = 1 # source:False
struct_r_crbtree_t._fields_ = [
    ('root', ctypes.POINTER(struct_r_crbtree_node)),
    ('size', ctypes.c_uint64),
    ('free', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
]

RRBTree = struct_r_crbtree_t
try:
    r_crbtree_new = _libr_util.r_crbtree_new
    r_crbtree_new.restype = ctypes.POINTER(struct_r_crbtree_t)
    r_crbtree_new.argtypes = [RRBFree]
except AttributeError:
    pass
try:
    r_crbtree_clear = _libr_util.r_crbtree_clear
    r_crbtree_clear.restype = None
    r_crbtree_clear.argtypes = [ctypes.POINTER(struct_r_crbtree_t)]
except AttributeError:
    pass
try:
    r_crbtree_free = _libr_util.r_crbtree_free
    r_crbtree_free.restype = None
    r_crbtree_free.argtypes = [ctypes.POINTER(struct_r_crbtree_t)]
except AttributeError:
    pass
try:
    r_crbtree_find_node = _libr_util.r_crbtree_find_node
    r_crbtree_find_node.restype = ctypes.POINTER(struct_r_crbtree_node)
    r_crbtree_find_node.argtypes = [ctypes.POINTER(struct_r_crbtree_t), ctypes.POINTER(None), RRBComparator, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_crbtree_find = _libr_util.r_crbtree_find
    r_crbtree_find.restype = ctypes.POINTER(None)
    r_crbtree_find.argtypes = [ctypes.POINTER(struct_r_crbtree_t), ctypes.POINTER(None), RRBComparator, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_crbtree_insert = _libr_util.r_crbtree_insert
    r_crbtree_insert.restype = ctypes.c_bool
    r_crbtree_insert.argtypes = [ctypes.POINTER(struct_r_crbtree_t), ctypes.POINTER(None), RRBComparator, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_crbtree_take = _libr_util.r_crbtree_take
    r_crbtree_take.restype = ctypes.POINTER(None)
    r_crbtree_take.argtypes = [ctypes.POINTER(struct_r_crbtree_t), ctypes.POINTER(None), RRBComparator, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_crbtree_delete = _libr_util.r_crbtree_delete
    r_crbtree_delete.restype = ctypes.c_bool
    r_crbtree_delete.argtypes = [ctypes.POINTER(struct_r_crbtree_t), ctypes.POINTER(None), RRBComparator, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_crbtree_first_node = _libr_util.r_crbtree_first_node
    r_crbtree_first_node.restype = ctypes.POINTER(struct_r_crbtree_node)
    r_crbtree_first_node.argtypes = [ctypes.POINTER(struct_r_crbtree_t)]
except AttributeError:
    pass
try:
    r_crbtree_last_node = _libr_util.r_crbtree_last_node
    r_crbtree_last_node.restype = ctypes.POINTER(struct_r_crbtree_node)
    r_crbtree_last_node.argtypes = [ctypes.POINTER(struct_r_crbtree_t)]
except AttributeError:
    pass
try:
    r_rbnode_next = _libr_util.r_rbnode_next
    r_rbnode_next.restype = ctypes.POINTER(struct_r_crbtree_node)
    r_rbnode_next.argtypes = [ctypes.POINTER(struct_r_crbtree_node)]
except AttributeError:
    pass
try:
    r_rbnode_prev = _libr_util.r_rbnode_prev
    r_rbnode_prev.restype = ctypes.POINTER(struct_r_crbtree_node)
    r_rbnode_prev.argtypes = [ctypes.POINTER(struct_r_crbtree_node)]
except AttributeError:
    pass
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
try:
    r_interval_tree_init = _libr_util.r_interval_tree_init
    r_interval_tree_init.restype = None
    r_interval_tree_init.argtypes = [ctypes.POINTER(struct_r_interval_tree_t), RIntervalNodeFree]
except AttributeError:
    pass
try:
    r_interval_tree_fini = _libr_util.r_interval_tree_fini
    r_interval_tree_fini.restype = None
    r_interval_tree_fini.argtypes = [ctypes.POINTER(struct_r_interval_tree_t)]
except AttributeError:
    pass
try:
    r_interval_tree_insert = _libr_util.r_interval_tree_insert
    r_interval_tree_insert.restype = ctypes.c_bool
    r_interval_tree_insert.argtypes = [ctypes.POINTER(struct_r_interval_tree_t), uint64_t, uint64_t, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_interval_tree_delete = _libr_util.r_interval_tree_delete
    r_interval_tree_delete.restype = ctypes.c_bool
    r_interval_tree_delete.argtypes = [ctypes.POINTER(struct_r_interval_tree_t), ctypes.POINTER(struct_r_interval_node_t), ctypes.c_bool]
except AttributeError:
    pass
try:
    r_interval_tree_resize = _libr_util.r_interval_tree_resize
    r_interval_tree_resize.restype = ctypes.c_bool
    r_interval_tree_resize.argtypes = [ctypes.POINTER(struct_r_interval_tree_t), ctypes.POINTER(struct_r_interval_node_t), uint64_t, uint64_t]
except AttributeError:
    pass
try:
    r_interval_tree_first_at = _libr_util.r_interval_tree_first_at
    r_interval_tree_first_at.restype = RBIter
    r_interval_tree_first_at.argtypes = [ctypes.POINTER(struct_r_interval_tree_t), uint64_t]
except AttributeError:
    pass
try:
    r_interval_tree_node_at = _libr_util.r_interval_tree_node_at
    r_interval_tree_node_at.restype = ctypes.POINTER(struct_r_interval_node_t)
    r_interval_tree_node_at.argtypes = [ctypes.POINTER(struct_r_interval_tree_t), uint64_t]
except AttributeError:
    pass
try:
    r_interval_tree_node_at_data = _libr_util.r_interval_tree_node_at_data
    r_interval_tree_node_at_data.restype = ctypes.POINTER(struct_r_interval_node_t)
    r_interval_tree_node_at_data.argtypes = [ctypes.POINTER(struct_r_interval_tree_t), uint64_t, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_interval_tree_at = _libraries['FIXME_STUB'].r_interval_tree_at
    r_interval_tree_at.restype = ctypes.POINTER(None)
    r_interval_tree_at.argtypes = [ctypes.POINTER(struct_r_interval_tree_t), uint64_t]
except AttributeError:
    pass
RIntervalIterCb = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(struct_r_interval_node_t), ctypes.POINTER(None))
try:
    r_interval_tree_all_at = _libr_util.r_interval_tree_all_at
    r_interval_tree_all_at.restype = ctypes.c_bool
    r_interval_tree_all_at.argtypes = [ctypes.POINTER(struct_r_interval_tree_t), uint64_t, RIntervalIterCb, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_interval_tree_all_in = _libr_util.r_interval_tree_all_in
    r_interval_tree_all_in.restype = ctypes.c_bool
    r_interval_tree_all_in.argtypes = [ctypes.POINTER(struct_r_interval_tree_t), uint64_t, ctypes.c_bool, RIntervalIterCb, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_interval_tree_all_intersect = _libr_util.r_interval_tree_all_intersect
    r_interval_tree_all_intersect.restype = ctypes.c_bool
    r_interval_tree_all_intersect.argtypes = [ctypes.POINTER(struct_r_interval_tree_t), uint64_t, uint64_t, ctypes.c_bool, RIntervalIterCb, ctypes.POINTER(None)]
except AttributeError:
    pass
RIntervalTreeIter = struct_r_rb_iter_t
try:
    r_interval_tree_iter_get = _libraries['FIXME_STUB'].r_interval_tree_iter_get
    r_interval_tree_iter_get.restype = ctypes.POINTER(struct_r_interval_node_t)
    r_interval_tree_iter_get.argtypes = [ctypes.POINTER(struct_r_rb_iter_t)]
except AttributeError:
    pass
class struct_r_num_big_t(Structure):
    pass

struct_r_num_big_t._pack_ = 1 # source:False
struct_r_num_big_t._fields_ = [
    ('array', ctypes.c_uint32 * 128),
    ('sign', ctypes.c_int32),
]

RNumBig = struct_r_num_big_t
try:
    r_big_new = _libr_util.r_big_new
    r_big_new.restype = ctypes.POINTER(struct_r_num_big_t)
    r_big_new.argtypes = []
except AttributeError:
    pass
try:
    r_big_free = _libr_util.r_big_free
    r_big_free.restype = None
    r_big_free.argtypes = [ctypes.POINTER(struct_r_num_big_t)]
except AttributeError:
    pass
try:
    r_big_init = _libr_util.r_big_init
    r_big_init.restype = None
    r_big_init.argtypes = [ctypes.POINTER(struct_r_num_big_t)]
except AttributeError:
    pass
try:
    r_big_fini = _libr_util.r_big_fini
    r_big_fini.restype = None
    r_big_fini.argtypes = [ctypes.POINTER(struct_r_num_big_t)]
except AttributeError:
    pass
try:
    r_big_from_int = _libr_util.r_big_from_int
    r_big_from_int.restype = None
    r_big_from_int.argtypes = [ctypes.POINTER(struct_r_num_big_t), int64_t]
except AttributeError:
    pass
try:
    r_big_to_int = _libr_util.r_big_to_int
    r_big_to_int.restype = int64_t
    r_big_to_int.argtypes = [ctypes.POINTER(struct_r_num_big_t)]
except AttributeError:
    pass
try:
    r_big_from_hexstr = _libr_util.r_big_from_hexstr
    r_big_from_hexstr.restype = None
    r_big_from_hexstr.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_big_to_hexstr = _libr_util.r_big_to_hexstr
    r_big_to_hexstr.restype = ctypes.POINTER(ctypes.c_char)
    r_big_to_hexstr.argtypes = [ctypes.POINTER(struct_r_num_big_t)]
except AttributeError:
    pass
try:
    r_big_assign = _libr_util.r_big_assign
    r_big_assign.restype = None
    r_big_assign.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t)]
except AttributeError:
    pass
try:
    r_big_add = _libr_util.r_big_add
    r_big_add.restype = None
    r_big_add.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t)]
except AttributeError:
    pass
try:
    r_big_sub = _libr_util.r_big_sub
    r_big_sub.restype = None
    r_big_sub.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t)]
except AttributeError:
    pass
try:
    r_big_mul = _libr_util.r_big_mul
    r_big_mul.restype = None
    r_big_mul.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t)]
except AttributeError:
    pass
try:
    r_big_div = _libr_util.r_big_div
    r_big_div.restype = None
    r_big_div.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t)]
except AttributeError:
    pass
try:
    r_big_mod = _libr_util.r_big_mod
    r_big_mod.restype = None
    r_big_mod.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t)]
except AttributeError:
    pass
try:
    r_big_divmod = _libr_util.r_big_divmod
    r_big_divmod.restype = None
    r_big_divmod.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t)]
except AttributeError:
    pass
try:
    r_big_and = _libr_util.r_big_and
    r_big_and.restype = None
    r_big_and.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t)]
except AttributeError:
    pass
try:
    r_big_or = _libr_util.r_big_or
    r_big_or.restype = None
    r_big_or.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t)]
except AttributeError:
    pass
try:
    r_big_xor = _libr_util.r_big_xor
    r_big_xor.restype = None
    r_big_xor.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t)]
except AttributeError:
    pass
try:
    r_big_lshift = _libr_util.r_big_lshift
    r_big_lshift.restype = None
    r_big_lshift.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t), size_t]
except AttributeError:
    pass
try:
    r_big_rshift = _libr_util.r_big_rshift
    r_big_rshift.restype = None
    r_big_rshift.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t), size_t]
except AttributeError:
    pass
try:
    r_big_cmp = _libr_util.r_big_cmp
    r_big_cmp.restype = ctypes.c_int32
    r_big_cmp.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t)]
except AttributeError:
    pass
try:
    r_big_is_zero = _libr_util.r_big_is_zero
    r_big_is_zero.restype = ctypes.c_int32
    r_big_is_zero.argtypes = [ctypes.POINTER(struct_r_num_big_t)]
except AttributeError:
    pass
try:
    r_big_inc = _libr_util.r_big_inc
    r_big_inc.restype = None
    r_big_inc.argtypes = [ctypes.POINTER(struct_r_num_big_t)]
except AttributeError:
    pass
try:
    r_big_dec = _libr_util.r_big_dec
    r_big_dec.restype = None
    r_big_dec.argtypes = [ctypes.POINTER(struct_r_num_big_t)]
except AttributeError:
    pass
try:
    r_big_powm = _libr_util.r_big_powm
    r_big_powm.restype = None
    r_big_powm.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t)]
except AttributeError:
    pass
try:
    r_big_isqrt = _libr_util.r_big_isqrt
    r_big_isqrt.restype = None
    r_big_isqrt.argtypes = [ctypes.POINTER(struct_r_num_big_t), ctypes.POINTER(struct_r_num_big_t)]
except AttributeError:
    pass
try:
    r_base64_encode = _libr_util.r_base64_encode
    r_base64_encode.restype = ctypes.c_int32
    r_base64_encode.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_base64_decode = _libr_util.r_base64_decode
    r_base64_decode.restype = ctypes.c_int32
    r_base64_decode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_base64_decode_dyn = _libr_util.r_base64_decode_dyn
    r_base64_decode_dyn.restype = ctypes.POINTER(ctypes.c_ubyte)
    r_base64_decode_dyn.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_base64_encode_dyn = _libr_util.r_base64_encode_dyn
    r_base64_encode_dyn.restype = ctypes.POINTER(ctypes.c_char)
    r_base64_encode_dyn.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_base91_encode = _libr_util.r_base91_encode
    r_base91_encode.restype = ctypes.c_int32
    r_base91_encode.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_base91_decode = _libr_util.r_base91_decode
    r_base91_decode.restype = ctypes.c_int32
    r_base91_decode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
class struct_r_mmap_t(Structure):
    pass

struct_r_mmap_t._pack_ = 1 # source:False
struct_r_mmap_t._fields_ = [
    ('buf', ctypes.POINTER(ctypes.c_ubyte)),
    ('base', ctypes.c_uint64),
    ('len', ctypes.c_int32),
    ('fd', ctypes.c_int32),
    ('rw', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('filename', ctypes.POINTER(ctypes.c_char)),
]

RMmap = struct_r_mmap_t
class struct_r_mem_pool_t(Structure):
    pass

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

RMemoryPool = struct_r_mem_pool_t
try:
    r_mem_get_num = _libr_util.r_mem_get_num
    r_mem_get_num.restype = uint64_t
    r_mem_get_num.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_mem_pool_deinit = _libraries['FIXME_STUB'].r_mem_pool_deinit
    r_mem_pool_deinit.restype = ctypes.POINTER(struct_r_mem_pool_t)
    r_mem_pool_deinit.argtypes = [ctypes.POINTER(struct_r_mem_pool_t)]
except AttributeError:
    pass
try:
    r_mem_pool_new = _libraries['FIXME_STUB'].r_mem_pool_new
    r_mem_pool_new.restype = ctypes.POINTER(struct_r_mem_pool_t)
    r_mem_pool_new.argtypes = [ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_mem_pool_free = _libraries['FIXME_STUB'].r_mem_pool_free
    r_mem_pool_free.restype = ctypes.POINTER(struct_r_mem_pool_t)
    r_mem_pool_free.argtypes = [ctypes.POINTER(struct_r_mem_pool_t)]
except AttributeError:
    pass
try:
    r_mem_pool_alloc = _libraries['FIXME_STUB'].r_mem_pool_alloc
    r_mem_pool_alloc.restype = ctypes.POINTER(None)
    r_mem_pool_alloc.argtypes = [ctypes.POINTER(struct_r_mem_pool_t)]
except AttributeError:
    pass
try:
    r_mem_dup = _libr_util.r_mem_dup
    r_mem_dup.restype = ctypes.POINTER(None)
    r_mem_dup.argtypes = [ctypes.POINTER(None), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_mem_alloc = _libr_util.r_mem_alloc
    r_mem_alloc.restype = ctypes.POINTER(None)
    r_mem_alloc.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_mem_free = _libr_util.r_mem_free
    r_mem_free.restype = None
    r_mem_free.argtypes = [ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_mem_memzero = _libr_util.r_mem_memzero
    r_mem_memzero.restype = None
    r_mem_memzero.argtypes = [ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    r_mem_reverse = _libr_util.r_mem_reverse
    r_mem_reverse.restype = None
    r_mem_reverse.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_mem_protect = _libr_util.r_mem_protect
    r_mem_protect.restype = ctypes.c_bool
    r_mem_protect.argtypes = [ctypes.POINTER(None), ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_mem_set_num = _libr_util.r_mem_set_num
    r_mem_set_num.restype = ctypes.c_int32
    r_mem_set_num.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, uint64_t]
except AttributeError:
    pass
try:
    r_mem_eq = _libr_util.r_mem_eq
    r_mem_eq.restype = ctypes.c_int32
    r_mem_eq.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_mem_copybits = _libr_util.r_mem_copybits
    r_mem_copybits.restype = None
    r_mem_copybits.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_mem_copybits_delta = _libr_util.r_mem_copybits_delta
    r_mem_copybits_delta.restype = None
    r_mem_copybits_delta.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_mem_copyloop = _libr_util.r_mem_copyloop
    r_mem_copyloop.restype = None
    r_mem_copyloop.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_mem_swaporcopy = _libr_util.r_mem_swaporcopy
    r_mem_swaporcopy.restype = None
    r_mem_swaporcopy.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.c_bool]
except AttributeError:
    pass
try:
    r_mem_swapendian = _libr_util.r_mem_swapendian
    r_mem_swapendian.restype = None
    r_mem_swapendian.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_mem_swap = _libr_util.r_mem_swap
    r_mem_swap.restype = None
    r_mem_swap.argtypes = [ctypes.POINTER(ctypes.c_ubyte), size_t]
except AttributeError:
    pass
try:
    r_mem_cmp_mask = _libr_util.r_mem_cmp_mask
    r_mem_cmp_mask.restype = ctypes.c_int32
    r_mem_cmp_mask.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_mem_mem = _libr_util.r_mem_mem
    r_mem_mem.restype = ctypes.POINTER(ctypes.c_ubyte)
    r_mem_mem.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_mem_mem_aligned = _libr_util.r_mem_mem_aligned
    r_mem_mem_aligned.restype = ctypes.POINTER(ctypes.c_ubyte)
    r_mem_mem_aligned.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_mem_count = _libr_util.r_mem_count
    r_mem_count.restype = ctypes.c_int32
    r_mem_count.argtypes = [ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))]
except AttributeError:
    pass
try:
    r_mem_is_printable = _libr_util.r_mem_is_printable
    r_mem_is_printable.restype = ctypes.c_bool
    r_mem_is_printable.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_mem_is_zero = _libr_util.r_mem_is_zero
    r_mem_is_zero.restype = ctypes.c_bool
    r_mem_is_zero.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_mem_mmap_resize = _libr_util.r_mem_mmap_resize
    r_mem_mmap_resize.restype = ctypes.POINTER(None)
    r_mem_mmap_resize.argtypes = [ctypes.POINTER(struct_r_mmap_t), uint64_t]
except AttributeError:
    pass
ut27 = ctypes.c_uint32
try:
    r_read_me27 = _libraries['FIXME_STUB'].r_read_me27
    r_read_me27.restype = ut27
    r_read_me27.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
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
    ('from_', ctypes.c_uint64),
    ('to', ctypes.c_uint64),
    ('size', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('data', ctypes.POINTER(ctypes.c_ubyte)),
    ('written', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
]

RBufferSparse = struct_r_buf_cache_t
try:
    r_buf_new = _libr_util.r_buf_new
    r_buf_new.restype = ctypes.POINTER(struct_r_buf_t)
    r_buf_new.argtypes = []
except AttributeError:
    pass
try:
    r_buf_new_with_io = _libr_util.r_buf_new_with_io
    r_buf_new_with_io.restype = ctypes.POINTER(struct_r_buf_t)
    r_buf_new_with_io.argtypes = [ctypes.POINTER(None), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_buf_new_with_bytes = _libr_util.r_buf_new_with_bytes
    r_buf_new_with_bytes.restype = ctypes.POINTER(struct_r_buf_t)
    r_buf_new_with_bytes.argtypes = [ctypes.POINTER(ctypes.c_ubyte), uint64_t]
except AttributeError:
    pass
try:
    r_buf_new_with_string = _libr_util.r_buf_new_with_string
    r_buf_new_with_string.restype = ctypes.POINTER(struct_r_buf_t)
    r_buf_new_with_string.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_buf_new_with_pointers = _libr_util.r_buf_new_with_pointers
    r_buf_new_with_pointers.restype = ctypes.POINTER(struct_r_buf_t)
    r_buf_new_with_pointers.argtypes = [ctypes.POINTER(ctypes.c_ubyte), uint64_t, ctypes.c_bool]
except AttributeError:
    pass
try:
    r_buf_new_file = _libr_util.r_buf_new_file
    r_buf_new_file.restype = ctypes.POINTER(struct_r_buf_t)
    r_buf_new_file.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_buf_new_with_buf = _libr_util.r_buf_new_with_buf
    r_buf_new_with_buf.restype = ctypes.POINTER(struct_r_buf_t)
    r_buf_new_with_buf.argtypes = [ctypes.POINTER(struct_r_buf_t)]
except AttributeError:
    pass
try:
    r_buf_new_slurp = _libr_util.r_buf_new_slurp
    r_buf_new_slurp.restype = ctypes.POINTER(struct_r_buf_t)
    r_buf_new_slurp.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_buf_new_slice = _libr_util.r_buf_new_slice
    r_buf_new_slice.restype = ctypes.POINTER(struct_r_buf_t)
    r_buf_new_slice.argtypes = [ctypes.POINTER(struct_r_buf_t), uint64_t, uint64_t]
except AttributeError:
    pass
try:
    r_buf_new_empty = _libr_util.r_buf_new_empty
    r_buf_new_empty.restype = ctypes.POINTER(struct_r_buf_t)
    r_buf_new_empty.argtypes = [uint64_t]
except AttributeError:
    pass
try:
    r_buf_new_mmap = _libr_util.r_buf_new_mmap
    r_buf_new_mmap.restype = ctypes.POINTER(struct_r_buf_t)
    r_buf_new_mmap.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_buf_new_sparse = _libr_util.r_buf_new_sparse
    r_buf_new_sparse.restype = ctypes.POINTER(struct_r_buf_t)
    r_buf_new_sparse.argtypes = [uint8_t]
except AttributeError:
    pass
try:
    r_buf_dump = _libr_util.r_buf_dump
    r_buf_dump.restype = ctypes.c_bool
    r_buf_dump.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_buf_set_bytes = _libr_util.r_buf_set_bytes
    r_buf_set_bytes.restype = ctypes.c_bool
    r_buf_set_bytes.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_ubyte), uint64_t]
except AttributeError:
    pass
try:
    r_buf_append_string = _libr_util.r_buf_append_string
    r_buf_append_string.restype = int64_t
    r_buf_append_string.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_buf_append_buf = _libr_util.r_buf_append_buf
    r_buf_append_buf.restype = ctypes.c_bool
    r_buf_append_buf.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(struct_r_buf_t)]
except AttributeError:
    pass
try:
    r_buf_append_bytes = _libr_util.r_buf_append_bytes
    r_buf_append_bytes.restype = ctypes.c_bool
    r_buf_append_bytes.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_ubyte), uint64_t]
except AttributeError:
    pass
try:
    r_buf_append_nbytes = _libr_util.r_buf_append_nbytes
    r_buf_append_nbytes.restype = ctypes.c_bool
    r_buf_append_nbytes.argtypes = [ctypes.POINTER(struct_r_buf_t), uint64_t]
except AttributeError:
    pass
try:
    r_buf_append_ut8 = _libr_util.r_buf_append_ut8
    r_buf_append_ut8.restype = ctypes.c_bool
    r_buf_append_ut8.argtypes = [ctypes.POINTER(struct_r_buf_t), uint8_t]
except AttributeError:
    pass
try:
    r_buf_append_ut16 = _libr_util.r_buf_append_ut16
    r_buf_append_ut16.restype = ctypes.c_bool
    r_buf_append_ut16.argtypes = [ctypes.POINTER(struct_r_buf_t), uint16_t]
except AttributeError:
    pass
try:
    r_buf_append_buf_slice = _libr_util.r_buf_append_buf_slice
    r_buf_append_buf_slice.restype = ctypes.c_bool
    r_buf_append_buf_slice.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(struct_r_buf_t), uint64_t, uint64_t]
except AttributeError:
    pass
try:
    r_buf_append_ut32 = _libr_util.r_buf_append_ut32
    r_buf_append_ut32.restype = ctypes.c_bool
    r_buf_append_ut32.argtypes = [ctypes.POINTER(struct_r_buf_t), uint32_t]
except AttributeError:
    pass
try:
    r_buf_append_ut64 = _libr_util.r_buf_append_ut64
    r_buf_append_ut64.restype = ctypes.c_bool
    r_buf_append_ut64.argtypes = [ctypes.POINTER(struct_r_buf_t), uint64_t]
except AttributeError:
    pass
try:
    r_buf_prepend_bytes = _libr_util.r_buf_prepend_bytes
    r_buf_prepend_bytes.restype = ctypes.c_bool
    r_buf_prepend_bytes.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_ubyte), uint64_t]
except AttributeError:
    pass
try:
    r_buf_insert_bytes = _libr_util.r_buf_insert_bytes
    r_buf_insert_bytes.restype = int64_t
    r_buf_insert_bytes.argtypes = [ctypes.POINTER(struct_r_buf_t), uint64_t, ctypes.POINTER(ctypes.c_ubyte), uint64_t]
except AttributeError:
    pass
try:
    r_buf_to_string = _libr_util.r_buf_to_string
    r_buf_to_string.restype = ctypes.POINTER(ctypes.c_char)
    r_buf_to_string.argtypes = [ctypes.POINTER(struct_r_buf_t)]
except AttributeError:
    pass
try:
    r_buf_get_string = _libr_util.r_buf_get_string
    r_buf_get_string.restype = ctypes.POINTER(ctypes.c_char)
    r_buf_get_string.argtypes = [ctypes.POINTER(struct_r_buf_t), uint64_t]
except AttributeError:
    pass
try:
    r_buf_read = _libr_util.r_buf_read
    r_buf_read.restype = int64_t
    r_buf_read.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_ubyte), uint64_t]
except AttributeError:
    pass
try:
    r_buf_read_all = _libr_util.r_buf_read_all
    r_buf_read_all.restype = ctypes.POINTER(ctypes.c_ubyte)
    r_buf_read_all.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_buf_read8 = _libr_util.r_buf_read8
    r_buf_read8.restype = uint8_t
    r_buf_read8.argtypes = [ctypes.POINTER(struct_r_buf_t)]
except AttributeError:
    pass
try:
    r_buf_fread = _libr_util.r_buf_fread
    r_buf_fread.restype = int64_t
    r_buf_fread.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_buf_read_at = _libr_util.r_buf_read_at
    r_buf_read_at.restype = int64_t
    r_buf_read_at.argtypes = [ctypes.POINTER(struct_r_buf_t), uint64_t, ctypes.POINTER(ctypes.c_ubyte), uint64_t]
except AttributeError:
    pass
try:
    r_buf_read8_at = _libr_util.r_buf_read8_at
    r_buf_read8_at.restype = uint8_t
    r_buf_read8_at.argtypes = [ctypes.POINTER(struct_r_buf_t), uint64_t]
except AttributeError:
    pass
try:
    r_buf_tell = _libr_util.r_buf_tell
    r_buf_tell.restype = uint64_t
    r_buf_tell.argtypes = [ctypes.POINTER(struct_r_buf_t)]
except AttributeError:
    pass
try:
    r_buf_seek = _libr_util.r_buf_seek
    r_buf_seek.restype = int64_t
    r_buf_seek.argtypes = [ctypes.POINTER(struct_r_buf_t), int64_t, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_buf_fread_at = _libr_util.r_buf_fread_at
    r_buf_fread_at.restype = int64_t
    r_buf_fread_at.argtypes = [ctypes.POINTER(struct_r_buf_t), uint64_t, ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_buf_write = _libr_util.r_buf_write
    r_buf_write.restype = int64_t
    r_buf_write.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_ubyte), uint64_t]
except AttributeError:
    pass
try:
    r_buf_fwrite = _libr_util.r_buf_fwrite
    r_buf_fwrite.restype = int64_t
    r_buf_fwrite.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_buf_write_at = _libr_util.r_buf_write_at
    r_buf_write_at.restype = int64_t
    r_buf_write_at.argtypes = [ctypes.POINTER(struct_r_buf_t), uint64_t, ctypes.POINTER(ctypes.c_ubyte), uint64_t]
except AttributeError:
    pass
try:
    r_buf_fwrite_at = _libr_util.r_buf_fwrite_at
    r_buf_fwrite_at.restype = int64_t
    r_buf_fwrite_at.argtypes = [ctypes.POINTER(struct_r_buf_t), uint64_t, ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_buf_data = _libr_util.r_buf_data
    r_buf_data.restype = ctypes.POINTER(ctypes.c_ubyte)
    r_buf_data.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_uint64)]
except AttributeError:
    pass
try:
    r_buf_size = _libr_util.r_buf_size
    r_buf_size.restype = uint64_t
    r_buf_size.argtypes = [ctypes.POINTER(struct_r_buf_t)]
except AttributeError:
    pass
try:
    r_buf_resize = _libr_util.r_buf_resize
    r_buf_resize.restype = ctypes.c_bool
    r_buf_resize.argtypes = [ctypes.POINTER(struct_r_buf_t), uint64_t]
except AttributeError:
    pass
try:
    r_buf_ref = _libr_util.r_buf_ref
    r_buf_ref.restype = ctypes.POINTER(struct_r_buf_t)
    r_buf_ref.argtypes = [ctypes.POINTER(struct_r_buf_t)]
except AttributeError:
    pass
try:
    r_buf_free = _libr_util.r_buf_free
    r_buf_free.restype = None
    r_buf_free.argtypes = [ctypes.POINTER(struct_r_buf_t)]
except AttributeError:
    pass
try:
    r_buf_fini = _libr_util.r_buf_fini
    r_buf_fini.restype = None
    r_buf_fini.argtypes = [ctypes.POINTER(struct_r_buf_t)]
except AttributeError:
    pass
try:
    r_buf_nonempty_list = _libr_util.r_buf_nonempty_list
    r_buf_nonempty_list.restype = ctypes.POINTER(struct_r_list_t)
    r_buf_nonempty_list.argtypes = [ctypes.POINTER(struct_r_buf_t)]
except AttributeError:
    pass
try:
    r_buf_read_be16 = _libraries['FIXME_STUB'].r_buf_read_be16
    r_buf_read_be16.restype = uint16_t
    r_buf_read_be16.argtypes = [ctypes.POINTER(struct_r_buf_t)]
except AttributeError:
    pass
try:
    r_buf_read_be16_at = _libraries['FIXME_STUB'].r_buf_read_be16_at
    r_buf_read_be16_at.restype = uint16_t
    r_buf_read_be16_at.argtypes = [ctypes.POINTER(struct_r_buf_t), uint64_t]
except AttributeError:
    pass
try:
    r_buf_read_be32 = _libraries['FIXME_STUB'].r_buf_read_be32
    r_buf_read_be32.restype = uint32_t
    r_buf_read_be32.argtypes = [ctypes.POINTER(struct_r_buf_t)]
except AttributeError:
    pass
try:
    r_buf_read_be32_at = _libraries['FIXME_STUB'].r_buf_read_be32_at
    r_buf_read_be32_at.restype = uint32_t
    r_buf_read_be32_at.argtypes = [ctypes.POINTER(struct_r_buf_t), uint64_t]
except AttributeError:
    pass
try:
    r_buf_read_be64 = _libraries['FIXME_STUB'].r_buf_read_be64
    r_buf_read_be64.restype = uint64_t
    r_buf_read_be64.argtypes = [ctypes.POINTER(struct_r_buf_t)]
except AttributeError:
    pass
try:
    r_buf_read_be64_at = _libraries['FIXME_STUB'].r_buf_read_be64_at
    r_buf_read_be64_at.restype = uint64_t
    r_buf_read_be64_at.argtypes = [ctypes.POINTER(struct_r_buf_t), uint64_t]
except AttributeError:
    pass
try:
    r_buf_read_le16 = _libraries['FIXME_STUB'].r_buf_read_le16
    r_buf_read_le16.restype = uint16_t
    r_buf_read_le16.argtypes = [ctypes.POINTER(struct_r_buf_t)]
except AttributeError:
    pass
try:
    r_buf_read_le16_at = _libraries['FIXME_STUB'].r_buf_read_le16_at
    r_buf_read_le16_at.restype = uint16_t
    r_buf_read_le16_at.argtypes = [ctypes.POINTER(struct_r_buf_t), uint64_t]
except AttributeError:
    pass
try:
    r_buf_read_le32 = _libraries['FIXME_STUB'].r_buf_read_le32
    r_buf_read_le32.restype = uint32_t
    r_buf_read_le32.argtypes = [ctypes.POINTER(struct_r_buf_t)]
except AttributeError:
    pass
try:
    r_buf_read_le32_at = _libraries['FIXME_STUB'].r_buf_read_le32_at
    r_buf_read_le32_at.restype = uint32_t
    r_buf_read_le32_at.argtypes = [ctypes.POINTER(struct_r_buf_t), uint64_t]
except AttributeError:
    pass
try:
    r_buf_read_le64 = _libraries['FIXME_STUB'].r_buf_read_le64
    r_buf_read_le64.restype = uint64_t
    r_buf_read_le64.argtypes = [ctypes.POINTER(struct_r_buf_t)]
except AttributeError:
    pass
try:
    r_buf_read_le64_at = _libraries['FIXME_STUB'].r_buf_read_le64_at
    r_buf_read_le64_at.restype = uint64_t
    r_buf_read_le64_at.argtypes = [ctypes.POINTER(struct_r_buf_t), uint64_t]
except AttributeError:
    pass
try:
    r_buf_read_ble16_at = _libraries['FIXME_STUB'].r_buf_read_ble16_at
    r_buf_read_ble16_at.restype = uint16_t
    r_buf_read_ble16_at.argtypes = [ctypes.POINTER(struct_r_buf_t), uint64_t, ctypes.c_bool]
except AttributeError:
    pass
try:
    r_buf_read_ble32_at = _libraries['FIXME_STUB'].r_buf_read_ble32_at
    r_buf_read_ble32_at.restype = uint32_t
    r_buf_read_ble32_at.argtypes = [ctypes.POINTER(struct_r_buf_t), uint64_t, ctypes.c_bool]
except AttributeError:
    pass
try:
    r_buf_read_ble64_at = _libraries['FIXME_STUB'].r_buf_read_ble64_at
    r_buf_read_ble64_at.restype = uint64_t
    r_buf_read_ble64_at.argtypes = [ctypes.POINTER(struct_r_buf_t), uint64_t, ctypes.c_bool]
except AttributeError:
    pass
try:
    r_buf_uleb128 = _libr_util.r_buf_uleb128
    r_buf_uleb128.restype = int64_t
    r_buf_uleb128.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_uint64)]
except AttributeError:
    pass
try:
    r_buf_sleb128 = _libr_util.r_buf_sleb128
    r_buf_sleb128.restype = int64_t
    r_buf_sleb128.argtypes = [ctypes.POINTER(struct_r_buf_t), ctypes.POINTER(ctypes.c_int64)]
except AttributeError:
    pass
try:
    r_buf_uleb128_at = _libraries['FIXME_STUB'].r_buf_uleb128_at
    r_buf_uleb128_at.restype = int64_t
    r_buf_uleb128_at.argtypes = [ctypes.POINTER(struct_r_buf_t), uint64_t, ctypes.POINTER(ctypes.c_uint64)]
except AttributeError:
    pass
try:
    r_buf_sleb128_at = _libraries['FIXME_STUB'].r_buf_sleb128_at
    r_buf_sleb128_at.restype = int64_t
    r_buf_sleb128_at.argtypes = [ctypes.POINTER(struct_r_buf_t), uint64_t, ctypes.POINTER(ctypes.c_int64)]
except AttributeError:
    pass
class struct_r_bitmap_t(Structure):
    pass

struct_r_bitmap_t._pack_ = 1 # source:False
struct_r_bitmap_t._fields_ = [
    ('length', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('bitmap', ctypes.POINTER(ctypes.c_uint64)),
]

RBitmap = struct_r_bitmap_t
try:
    r_bitmap_new = _libr_util.r_bitmap_new
    r_bitmap_new.restype = ctypes.POINTER(struct_r_bitmap_t)
    r_bitmap_new.argtypes = [size_t]
except AttributeError:
    pass
try:
    r_bitmap_set_bytes = _libr_util.r_bitmap_set_bytes
    r_bitmap_set_bytes.restype = None
    r_bitmap_set_bytes.argtypes = [ctypes.POINTER(struct_r_bitmap_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_bitmap_free = _libr_util.r_bitmap_free
    r_bitmap_free.restype = None
    r_bitmap_free.argtypes = [ctypes.POINTER(struct_r_bitmap_t)]
except AttributeError:
    pass
try:
    r_bitmap_set = _libr_util.r_bitmap_set
    r_bitmap_set.restype = None
    r_bitmap_set.argtypes = [ctypes.POINTER(struct_r_bitmap_t), size_t]
except AttributeError:
    pass
try:
    r_bitmap_unset = _libr_util.r_bitmap_unset
    r_bitmap_unset.restype = None
    r_bitmap_unset.argtypes = [ctypes.POINTER(struct_r_bitmap_t), size_t]
except AttributeError:
    pass
try:
    r_bitmap_test = _libr_util.r_bitmap_test
    r_bitmap_test.restype = ctypes.c_int32
    r_bitmap_test.argtypes = [ctypes.POINTER(struct_r_bitmap_t), size_t]
except AttributeError:
    pass
try:
    r_time_now = _libr_util.r_time_now
    r_time_now.restype = uint64_t
    r_time_now.argtypes = []
except AttributeError:
    pass
try:
    r_time_now_mono = _libr_util.r_time_now_mono
    r_time_now_mono.restype = uint64_t
    r_time_now_mono.argtypes = []
except AttributeError:
    pass
try:
    r_time_stamp_to_str = _libr_util.r_time_stamp_to_str
    r_time_stamp_to_str.restype = ctypes.POINTER(ctypes.c_char)
    r_time_stamp_to_str.argtypes = [time_t]
except AttributeError:
    pass
try:
    r_time_dos_time_stamp_to_posix = _libr_util.r_time_dos_time_stamp_to_posix
    r_time_dos_time_stamp_to_posix.restype = uint32_t
    r_time_dos_time_stamp_to_posix.argtypes = [uint32_t]
except AttributeError:
    pass
try:
    r_time_stamp_is_dos_format = _libr_util.r_time_stamp_is_dos_format
    r_time_stamp_is_dos_format.restype = ctypes.c_bool
    r_time_stamp_is_dos_format.argtypes = [uint32_t, uint32_t]
except AttributeError:
    pass
try:
    r_time_to_string = _libr_util.r_time_to_string
    r_time_to_string.restype = ctypes.POINTER(ctypes.c_char)
    r_time_to_string.argtypes = [uint64_t]
except AttributeError:
    pass
try:
    r_asctime_r = _libr_util.r_asctime_r
    r_asctime_r.restype = ctypes.POINTER(ctypes.c_char)
    r_asctime_r.argtypes = [ctypes.POINTER(struct_tm), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_ctime_r = _libr_util.r_ctime_r
    r_ctime_r.restype = ctypes.POINTER(ctypes.c_char)
    r_ctime_r.argtypes = [ctypes.POINTER(ctypes.c_int64), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_debruijn_pattern = _libr_util.r_debruijn_pattern
    r_debruijn_pattern.restype = ctypes.POINTER(ctypes.c_char)
    r_debruijn_pattern.argtypes = [ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_debruijn_offset = _libr_util.r_debruijn_offset
    r_debruijn_offset.restype = ctypes.c_int32
    r_debruijn_offset.argtypes = [uint64_t, ctypes.c_bool]
except AttributeError:
    pass
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

struct_r_prof_t._pack_ = 1 # source:False
struct_r_prof_t._fields_ = [
    ('when', struct_timeval),
    ('result', ctypes.c_double),
]

RProfile = struct_r_prof_t
try:
    r_cache_new = _libr_util.r_cache_new
    r_cache_new.restype = ctypes.POINTER(struct_r_cache_t)
    r_cache_new.argtypes = []
except AttributeError:
    pass
try:
    r_cache_free = _libr_util.r_cache_free
    r_cache_free.restype = None
    r_cache_free.argtypes = [ctypes.POINTER(struct_r_cache_t)]
except AttributeError:
    pass
try:
    r_cache_get = _libr_util.r_cache_get
    r_cache_get.restype = ctypes.POINTER(ctypes.c_ubyte)
    r_cache_get.argtypes = [ctypes.POINTER(struct_r_cache_t), uint64_t, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_cache_set = _libr_util.r_cache_set
    r_cache_set.restype = ctypes.c_int32
    r_cache_set.argtypes = [ctypes.POINTER(struct_r_cache_t), uint64_t, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cache_flush = _libr_util.r_cache_flush
    r_cache_flush.restype = None
    r_cache_flush.argtypes = [ctypes.POINTER(struct_r_cache_t)]
except AttributeError:
    pass
try:
    r_prof_start = _libr_util.r_prof_start
    r_prof_start.restype = None
    r_prof_start.argtypes = [ctypes.POINTER(struct_r_prof_t)]
except AttributeError:
    pass
try:
    r_prof_end = _libr_util.r_prof_end
    r_prof_end.restype = ctypes.c_double
    r_prof_end.argtypes = [ctypes.POINTER(struct_r_prof_t)]
except AttributeError:
    pass
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
try:
    r_type_set = _libr_util.r_type_set
    r_type_set.restype = ctypes.c_bool
    r_type_set.argtypes = [ctypes.POINTER(struct_sdb_t), uint64_t, ctypes.POINTER(ctypes.c_char), uint64_t]
except AttributeError:
    pass
try:
    r_type_del = _libr_util.r_type_del
    r_type_del.restype = None
    r_type_del.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_type_kind = _libr_util.r_type_kind
    r_type_kind.restype = RTypeKind
    r_type_kind.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_type_enum_member = _libr_util.r_type_enum_member
    r_type_enum_member.restype = ctypes.POINTER(ctypes.c_char)
    r_type_enum_member.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), uint64_t]
except AttributeError:
    pass
try:
    r_type_enum_getbitfield = _libr_util.r_type_enum_getbitfield
    r_type_enum_getbitfield.restype = ctypes.POINTER(ctypes.c_char)
    r_type_enum_getbitfield.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), uint64_t]
except AttributeError:
    pass
try:
    r_type_get_enum = _libr_util.r_type_get_enum
    r_type_get_enum.restype = ctypes.POINTER(struct_r_list_t)
    r_type_get_enum.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_type_get_bitsize = _libr_util.r_type_get_bitsize
    r_type_get_bitsize.restype = uint64_t
    r_type_get_bitsize.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_type_get_by_offset = _libr_util.r_type_get_by_offset
    r_type_get_by_offset.restype = ctypes.POINTER(struct_r_list_t)
    r_type_get_by_offset.argtypes = [ctypes.POINTER(struct_sdb_t), uint64_t]
except AttributeError:
    pass
try:
    r_type_get_struct_memb = _libr_util.r_type_get_struct_memb
    r_type_get_struct_memb.restype = ctypes.POINTER(ctypes.c_char)
    r_type_get_struct_memb.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_type_link_at = _libr_util.r_type_link_at
    r_type_link_at.restype = ctypes.POINTER(ctypes.c_char)
    r_type_link_at.argtypes = [ctypes.POINTER(struct_sdb_t), uint64_t]
except AttributeError:
    pass
try:
    r_type_set_link = _libr_util.r_type_set_link
    r_type_set_link.restype = ctypes.c_int32
    r_type_set_link.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), uint64_t]
except AttributeError:
    pass
try:
    r_type_unlink = _libr_util.r_type_unlink
    r_type_unlink.restype = ctypes.c_int32
    r_type_unlink.argtypes = [ctypes.POINTER(struct_sdb_t), uint64_t]
except AttributeError:
    pass
try:
    r_type_link_offset = _libr_util.r_type_link_offset
    r_type_link_offset.restype = ctypes.c_int32
    r_type_link_offset.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), uint64_t]
except AttributeError:
    pass
try:
    r_type_format = _libr_util.r_type_format
    r_type_format.restype = ctypes.POINTER(ctypes.c_char)
    r_type_format.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_type_func_exist = _libr_util.r_type_func_exist
    r_type_func_exist.restype = ctypes.c_int32
    r_type_func_exist.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_type_func_cc = _libraries['FIXME_STUB'].r_type_func_cc
    r_type_func_cc.restype = ctypes.POINTER(ctypes.c_char)
    r_type_func_cc.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_type_func_ret = _libr_util.r_type_func_ret
    r_type_func_ret.restype = ctypes.POINTER(ctypes.c_char)
    r_type_func_ret.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_type_func_args_count = _libr_util.r_type_func_args_count
    r_type_func_args_count.restype = ctypes.c_int32
    r_type_func_args_count.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_type_func_args_type = _libr_util.r_type_func_args_type
    r_type_func_args_type.restype = ctypes.POINTER(ctypes.c_char)
    r_type_func_args_type.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_type_func_args_name = _libr_util.r_type_func_args_name
    r_type_func_args_name.restype = ctypes.POINTER(ctypes.c_char)
    r_type_func_args_name.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_type_func_guess = _libr_util.r_type_func_guess
    r_type_func_guess.restype = ctypes.POINTER(ctypes.c_char)
    r_type_func_guess.argtypes = [ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_file_is_abspath = _libr_util.r_file_is_abspath
    r_file_is_abspath.restype = ctypes.c_bool
    r_file_is_abspath.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_file_is_c = _libr_util.r_file_is_c
    r_file_is_c.restype = ctypes.c_bool
    r_file_is_c.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_file_is_directory = _libr_util.r_file_is_directory
    r_file_is_directory.restype = ctypes.c_bool
    r_file_is_directory.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_file_is_regular = _libr_util.r_file_is_regular
    r_file_is_regular.restype = ctypes.c_bool
    r_file_is_regular.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_file_is_executable = _libr_util.r_file_is_executable
    r_file_is_executable.restype = ctypes.c_bool
    r_file_is_executable.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_file_truncate = _libr_util.r_file_truncate
    r_file_truncate.restype = ctypes.c_bool
    r_file_truncate.argtypes = [ctypes.POINTER(ctypes.c_char), uint64_t]
except AttributeError:
    pass
try:
    r_file_new = _libr_util.r_file_new
    r_file_new.restype = ctypes.POINTER(ctypes.c_char)
    r_file_new.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_file_size = _libr_util.r_file_size
    r_file_size.restype = uint64_t
    r_file_size.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_file_root = _libr_util.r_file_root
    r_file_root.restype = ctypes.POINTER(ctypes.c_char)
    r_file_root.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_file_mmap = _libr_util.r_file_mmap
    r_file_mmap.restype = ctypes.POINTER(struct_r_mmap_t)
    r_file_mmap.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_bool, uint64_t]
except AttributeError:
    pass
try:
    r_file_mmap_read = _libr_util.r_file_mmap_read
    r_file_mmap_read.restype = ctypes.c_int32
    r_file_mmap_read.argtypes = [ctypes.POINTER(ctypes.c_char), uint64_t, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_file_mmap_write = _libr_util.r_file_mmap_write
    r_file_mmap_write.restype = ctypes.c_int32
    r_file_mmap_write.argtypes = [ctypes.POINTER(ctypes.c_char), uint64_t, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_file_mmap_free = _libr_util.r_file_mmap_free
    r_file_mmap_free.restype = None
    r_file_mmap_free.argtypes = [ctypes.POINTER(struct_r_mmap_t)]
except AttributeError:
    pass
try:
    r_file_chmod = _libr_util.r_file_chmod
    r_file_chmod.restype = ctypes.c_bool
    r_file_chmod.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_file_temp = _libr_util.r_file_temp
    r_file_temp.restype = ctypes.POINTER(ctypes.c_char)
    r_file_temp.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_file_path = _libr_util.r_file_path
    r_file_path.restype = ctypes.POINTER(ctypes.c_char)
    r_file_path.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_file_binsh = _libr_util.r_file_binsh
    r_file_binsh.restype = ctypes.POINTER(ctypes.c_char)
    r_file_binsh.argtypes = []
except AttributeError:
    pass
try:
    r_file_basename = _libr_util.r_file_basename
    r_file_basename.restype = ctypes.POINTER(ctypes.c_char)
    r_file_basename.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_file_dirname = _libr_util.r_file_dirname
    r_file_dirname.restype = ctypes.POINTER(ctypes.c_char)
    r_file_dirname.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_file_abspath_rel = _libr_util.r_file_abspath_rel
    r_file_abspath_rel.restype = ctypes.POINTER(ctypes.c_char)
    r_file_abspath_rel.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_file_abspath = _libr_util.r_file_abspath
    r_file_abspath.restype = ctypes.POINTER(ctypes.c_char)
    r_file_abspath.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_inflate = _libr_util.r_inflate
    r_inflate.restype = ctypes.POINTER(ctypes.c_ubyte)
    r_inflate.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_inflate_raw = _libr_util.r_inflate_raw
    r_inflate_raw.restype = ctypes.POINTER(ctypes.c_ubyte)
    r_inflate_raw.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_inflate_lz4 = _libr_util.r_inflate_lz4
    r_inflate_lz4.restype = ctypes.POINTER(ctypes.c_ubyte)
    r_inflate_lz4.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_file_gzslurp = _libr_util.r_file_gzslurp
    r_file_gzslurp.restype = ctypes.POINTER(ctypes.c_ubyte)
    r_file_gzslurp.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_int32), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_stdin_slurp = _libr_util.r_stdin_slurp
    r_stdin_slurp.restype = ctypes.POINTER(ctypes.c_char)
    r_stdin_slurp.argtypes = [ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_file_slurp = _libr_util.r_file_slurp
    r_file_slurp.restype = ctypes.POINTER(ctypes.c_char)
    r_file_slurp.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_uint64)]
except AttributeError:
    pass
try:
    r_file_slurp_range = _libr_util.r_file_slurp_range
    r_file_slurp_range.restype = ctypes.POINTER(ctypes.c_char)
    r_file_slurp_range.argtypes = [ctypes.POINTER(ctypes.c_char), uint64_t, ctypes.c_int32, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_file_slurp_random_line = _libr_util.r_file_slurp_random_line
    r_file_slurp_random_line.restype = ctypes.POINTER(ctypes.c_char)
    r_file_slurp_random_line.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_file_slurp_random_line_count = _libr_util.r_file_slurp_random_line_count
    r_file_slurp_random_line_count.restype = ctypes.POINTER(ctypes.c_char)
    r_file_slurp_random_line_count.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_file_slurp_hexpairs = _libr_util.r_file_slurp_hexpairs
    r_file_slurp_hexpairs.restype = ctypes.POINTER(ctypes.c_ubyte)
    r_file_slurp_hexpairs.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_file_dump = _libr_util.r_file_dump
    r_file_dump.restype = ctypes.c_bool
    r_file_dump.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.c_bool]
except AttributeError:
    pass
try:
    r_file_touch = _libr_util.r_file_touch
    r_file_touch.restype = ctypes.c_bool
    r_file_touch.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_file_hexdump = _libr_util.r_file_hexdump
    r_file_hexdump.restype = ctypes.c_bool
    r_file_hexdump.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_file_rm = _libr_util.r_file_rm
    r_file_rm.restype = ctypes.c_bool
    r_file_rm.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_file_exists = _libr_util.r_file_exists
    r_file_exists.restype = ctypes.c_bool
    r_file_exists.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_file_extension = _libr_util.r_file_extension
    r_file_extension.restype = ctypes.POINTER(ctypes.c_char)
    r_file_extension.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_file_fexists = _libr_util.r_file_fexists
    r_file_fexists.restype = ctypes.c_bool
    r_file_fexists.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_file_slurp_line = _libr_util.r_file_slurp_line
    r_file_slurp_line.restype = ctypes.POINTER(ctypes.c_char)
    r_file_slurp_line.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_file_slurp_lines = _libr_util.r_file_slurp_lines
    r_file_slurp_lines.restype = ctypes.POINTER(ctypes.c_char)
    r_file_slurp_lines.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_file_slurp_lines_from_bottom = _libr_util.r_file_slurp_lines_from_bottom
    r_file_slurp_lines_from_bottom.restype = ctypes.POINTER(ctypes.c_char)
    r_file_slurp_lines_from_bottom.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_file_temp_ex = _libr_util.r_file_temp_ex
    r_file_temp_ex.restype = ctypes.POINTER(ctypes.c_char)
    r_file_temp_ex.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_file_mkstemp = _libr_util.r_file_mkstemp
    r_file_mkstemp.restype = ctypes.c_int32
    r_file_mkstemp.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
except AttributeError:
    pass
try:
    r_file_tmpdir = _libr_util.r_file_tmpdir
    r_file_tmpdir.restype = ctypes.POINTER(ctypes.c_char)
    r_file_tmpdir.argtypes = []
except AttributeError:
    pass
try:
    r_file_readlink = _libr_util.r_file_readlink
    r_file_readlink.restype = ctypes.POINTER(ctypes.c_char)
    r_file_readlink.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_file_copy = _libr_util.r_file_copy
    r_file_copy.restype = ctypes.c_bool
    r_file_copy.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_file_move = _libr_util.r_file_move
    r_file_move.restype = ctypes.c_bool
    r_file_move.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_file_glob = _libr_util.r_file_glob
    r_file_glob.restype = ctypes.POINTER(struct_r_list_t)
    r_file_glob.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_file_mmap_arch = _libr_util.r_file_mmap_arch
    r_file_mmap_arch.restype = ctypes.POINTER(struct_r_mmap_t)
    r_file_mmap_arch.argtypes = [ctypes.POINTER(struct_r_mmap_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_file_lsrf = _libr_util.r_file_lsrf
    r_file_lsrf.restype = ctypes.POINTER(struct_r_list_t)
    r_file_lsrf.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_file_rm_rf = _libr_util.r_file_rm_rf
    r_file_rm_rf.restype = ctypes.c_bool
    r_file_rm_rf.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_xdg_configdir = _libr_util.r_xdg_configdir
    r_xdg_configdir.restype = ctypes.POINTER(ctypes.c_char)
    r_xdg_configdir.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_xdg_datadir = _libr_util.r_xdg_datadir
    r_xdg_datadir.restype = ctypes.POINTER(ctypes.c_char)
    r_xdg_datadir.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_xdg_cachedir = _libr_util.r_xdg_cachedir
    r_xdg_cachedir.restype = ctypes.POINTER(ctypes.c_char)
    r_xdg_cachedir.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_hex_pair2bin = _libr_util.r_hex_pair2bin
    r_hex_pair2bin.restype = ctypes.c_int32
    r_hex_pair2bin.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_hex_str2bin_until_new = _libr_util.r_hex_str2bin_until_new
    r_hex_str2bin_until_new.restype = ctypes.c_int32
    r_hex_str2bin_until_new.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))]
except AttributeError:
    pass
try:
    r_hex_str2binmask = _libr_util.r_hex_str2binmask
    r_hex_str2binmask.restype = ctypes.c_int32
    r_hex_str2binmask.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
except AttributeError:
    pass
try:
    r_hex_str2bin = _libr_util.r_hex_str2bin
    r_hex_str2bin.restype = ctypes.c_int32
    r_hex_str2bin.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_ubyte)]
except AttributeError:
    pass
try:
    r_hex_bin2str = _libr_util.r_hex_bin2str
    r_hex_bin2str.restype = ctypes.c_int32
    r_hex_bin2str.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_hex_bin2strdup = _libr_util.r_hex_bin2strdup
    r_hex_bin2strdup.restype = ctypes.POINTER(ctypes.c_char)
    r_hex_bin2strdup.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_hex_to_byte = _libr_util.r_hex_to_byte
    r_hex_to_byte.restype = ctypes.c_bool
    r_hex_to_byte.argtypes = [ctypes.POINTER(ctypes.c_ubyte), uint8_t]
except AttributeError:
    pass
try:
    r_hex_str_is_valid = _libr_util.r_hex_str_is_valid
    r_hex_str_is_valid.restype = ctypes.c_int32
    r_hex_str_is_valid.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_hex_bin_truncate = _libr_util.r_hex_bin_truncate
    r_hex_bin_truncate.restype = int64_t
    r_hex_bin_truncate.argtypes = [uint64_t, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_hex_from_c = _libr_util.r_hex_from_c
    r_hex_from_c.restype = ctypes.POINTER(ctypes.c_char)
    r_hex_from_c.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_hex_from_py = _libr_util.r_hex_from_py
    r_hex_from_py.restype = ctypes.POINTER(ctypes.c_char)
    r_hex_from_py.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_hex_from_code = _libr_util.r_hex_from_code
    r_hex_from_code.restype = ctypes.POINTER(ctypes.c_char)
    r_hex_from_code.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_hex_no_code = _libr_util.r_hex_no_code
    r_hex_no_code.restype = ctypes.POINTER(ctypes.c_char)
    r_hex_no_code.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_hex_from_py_str = _libr_util.r_hex_from_py_str
    r_hex_from_py_str.restype = ctypes.POINTER(ctypes.c_char)
    r_hex_from_py_str.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_hex_from_py_array = _libr_util.r_hex_from_py_array
    r_hex_from_py_array.restype = ctypes.POINTER(ctypes.c_char)
    r_hex_from_py_array.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_hex_from_c_str = _libr_util.r_hex_from_c_str
    r_hex_from_c_str.restype = ctypes.POINTER(ctypes.c_char)
    r_hex_from_c_str.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
except AttributeError:
    pass
try:
    r_hex_from_c_array = _libr_util.r_hex_from_c_array
    r_hex_from_c_array.restype = ctypes.POINTER(ctypes.c_char)
    r_hex_from_c_array.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_name_validate_print = _libr_util.r_name_validate_print
    r_name_validate_print.restype = ctypes.c_bool
    r_name_validate_print.argtypes = [ctypes.c_char]
except AttributeError:
    pass
try:
    r_name_validate_char = _libr_util.r_name_validate_char
    r_name_validate_char.restype = ctypes.c_bool
    r_name_validate_char.argtypes = [ctypes.c_char]
except AttributeError:
    pass
try:
    r_name_validate_first = _libr_util.r_name_validate_first
    r_name_validate_first.restype = ctypes.c_bool
    r_name_validate_first.argtypes = [ctypes.c_char]
except AttributeError:
    pass
try:
    r_name_check = _libr_util.r_name_check
    r_name_check.restype = ctypes.c_bool
    r_name_check.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_name_filter_ro = _libr_util.r_name_filter_ro
    r_name_filter_ro.restype = ctypes.POINTER(ctypes.c_char)
    r_name_filter_ro.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_name_filter_flag = _libraries['FIXME_STUB'].r_name_filter_flag
    r_name_filter_flag.restype = ctypes.c_bool
    r_name_filter_flag.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_name_filter_print = _libr_util.r_name_filter_print
    r_name_filter_print.restype = ctypes.c_bool
    r_name_filter_print.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_name_filter = _libr_util.r_name_filter
    r_name_filter.restype = ctypes.c_bool
    r_name_filter.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_name_filter_dup = _libr_util.r_name_filter_dup
    r_name_filter_dup.restype = ctypes.POINTER(ctypes.c_char)
    r_name_filter_dup.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
class struct_RNumCalcValue(Structure):
    pass

struct_RNumCalcValue._pack_ = 1 # source:False
struct_RNumCalcValue._fields_ = [
    ('d', ctypes.c_double),
    ('n', ctypes.c_uint64),
]

RNumCalcValue = struct_RNumCalcValue
class union_RNumFloat(Union):
    pass

union_RNumFloat._pack_ = 1 # source:False
union_RNumFloat._fields_ = [
    ('u16', ctypes.c_uint16),
    ('u32', ctypes.c_uint32),
    ('u64', ctypes.c_uint64),
    ('s16', ctypes.c_int16),
    ('s32', ctypes.c_int32),
    ('s64', ctypes.c_int64),
    ('f32', ctypes.c_float),
    ('f64', ctypes.c_double),
]

RNumFloat = union_RNumFloat

# values for enumeration 'RNumCalcToken'
RNumCalcToken__enumvalues = {
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
RNumCalcToken = ctypes.c_uint32 # enum
class struct_r_num_calc_t(Structure):
    pass

struct_r_num_calc_t._pack_ = 1 # source:False
struct_r_num_calc_t._fields_ = [
    ('curr_tok', RNumCalcToken),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('number_value', RNumCalcValue),
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

RNumCalc = struct_r_num_calc_t
class struct_r_num_t(Structure):
    pass

struct_r_num_t._pack_ = 1 # source:False
struct_r_num_t._fields_ = [
    ('callback', ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(struct_r_num_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_int32))),
    ('cb_from_value', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_num_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_int32))),
    ('value', ctypes.c_uint64),
    ('fvalue', ctypes.c_double),
    ('userptr', ctypes.POINTER(None)),
    ('dbz', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('nc', RNumCalc),
]

RNum = struct_r_num_t
RNumCallback = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(struct_r_num_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_int32))
RNumCallback2 = ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_num_t), ctypes.c_uint64, ctypes.POINTER(ctypes.c_int32))
try:
    r_num_new = _libr_util.r_num_new
    r_num_new.restype = ctypes.POINTER(struct_r_num_t)
    r_num_new.argtypes = [RNumCallback, RNumCallback2, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_num_free = _libr_util.r_num_free
    r_num_free.restype = None
    r_num_free.argtypes = [ctypes.POINTER(struct_r_num_t)]
except AttributeError:
    pass
try:
    r_num_units = _libr_util.r_num_units
    r_num_units.restype = ctypes.POINTER(ctypes.c_char)
    r_num_units.argtypes = [ctypes.POINTER(ctypes.c_char), size_t, uint64_t]
except AttributeError:
    pass
try:
    r_num_conditional = _libr_util.r_num_conditional
    r_num_conditional.restype = ctypes.c_int32
    r_num_conditional.argtypes = [ctypes.POINTER(struct_r_num_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_num_calc = _libr_util.r_num_calc
    r_num_calc.restype = uint64_t
    r_num_calc.argtypes = [ctypes.POINTER(struct_r_num_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
except AttributeError:
    pass
try:
    r_num_calc_index = _libr_util.r_num_calc_index
    r_num_calc_index.restype = ctypes.POINTER(ctypes.c_char)
    r_num_calc_index.argtypes = [ctypes.POINTER(struct_r_num_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_num_chs = _libr_util.r_num_chs
    r_num_chs.restype = uint64_t
    r_num_chs.argtypes = [ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_num_is_valid_input = _libr_util.r_num_is_valid_input
    r_num_is_valid_input.restype = ctypes.c_int32
    r_num_is_valid_input.argtypes = [ctypes.POINTER(struct_r_num_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_num_get_input_value = _libr_util.r_num_get_input_value
    r_num_get_input_value.restype = uint64_t
    r_num_get_input_value.argtypes = [ctypes.POINTER(struct_r_num_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_num_get_name = _libr_util.r_num_get_name
    r_num_get_name.restype = ctypes.POINTER(ctypes.c_char)
    r_num_get_name.argtypes = [ctypes.POINTER(struct_r_num_t), uint64_t]
except AttributeError:
    pass
try:
    r_num_as_string = _libr_util.r_num_as_string
    r_num_as_string.restype = ctypes.POINTER(ctypes.c_char)
    r_num_as_string.argtypes = [ctypes.POINTER(struct_r_num_t), uint64_t, ctypes.c_bool]
except AttributeError:
    pass
try:
    r_num_tail = _libr_util.r_num_tail
    r_num_tail.restype = uint64_t
    r_num_tail.argtypes = [ctypes.POINTER(struct_r_num_t), uint64_t, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_num_tail_base = _libr_util.r_num_tail_base
    r_num_tail_base.restype = uint64_t
    r_num_tail_base.argtypes = [ctypes.POINTER(struct_r_num_t), uint64_t, uint64_t]
except AttributeError:
    pass
try:
    r_num_segaddr = _libr_util.r_num_segaddr
    r_num_segaddr.restype = ctypes.c_bool
    r_num_segaddr.argtypes = [uint64_t, uint64_t, ctypes.c_int32, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    r_num_minmax_swap = _libr_util.r_num_minmax_swap
    r_num_minmax_swap.restype = None
    r_num_minmax_swap.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint64)]
except AttributeError:
    pass
try:
    r_num_minmax_swap_i = _libr_util.r_num_minmax_swap_i
    r_num_minmax_swap_i.restype = None
    r_num_minmax_swap_i.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_num_math = _libr_util.r_num_math
    r_num_math.restype = uint64_t
    r_num_math.argtypes = [ctypes.POINTER(struct_r_num_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_num_get = _libr_util.r_num_get
    r_num_get.restype = uint64_t
    r_num_get.argtypes = [ctypes.POINTER(struct_r_num_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_num_to_bits = _libr_util.r_num_to_bits
    r_num_to_bits.restype = ctypes.c_int32
    r_num_to_bits.argtypes = [ctypes.POINTER(ctypes.c_char), uint64_t]
except AttributeError:
    pass
try:
    r_num_to_ternary = _libr_util.r_num_to_ternary
    r_num_to_ternary.restype = ctypes.c_int32
    r_num_to_ternary.argtypes = [ctypes.POINTER(ctypes.c_char), uint64_t]
except AttributeError:
    pass
try:
    r_num_rand = _libr_util.r_num_rand
    r_num_rand.restype = ctypes.c_int32
    r_num_rand.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_num_irand = _libr_util.r_num_irand
    r_num_irand.restype = None
    r_num_irand.argtypes = []
except AttributeError:
    pass
try:
    r_get_input_num_value = _libr_util.r_get_input_num_value
    r_get_input_num_value.restype = uint64_t
    r_get_input_num_value.argtypes = [ctypes.POINTER(struct_r_num_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_is_valid_input_num_value = _libr_util.r_is_valid_input_num_value
    r_is_valid_input_num_value.restype = ctypes.c_bool
    r_is_valid_input_num_value.argtypes = [ctypes.POINTER(struct_r_num_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_num_between = _libr_util.r_num_between
    r_num_between.restype = ctypes.c_int32
    r_num_between.argtypes = [ctypes.POINTER(struct_r_num_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_num_is_op = _libr_util.r_num_is_op
    r_num_is_op.restype = ctypes.c_bool
    r_num_is_op.argtypes = [ctypes.c_char]
except AttributeError:
    pass
try:
    r_num_str_len = _libr_util.r_num_str_len
    r_num_str_len.restype = ctypes.c_int32
    r_num_str_len.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_num_str_split = _libr_util.r_num_str_split
    r_num_str_split.restype = ctypes.c_int32
    r_num_str_split.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_num_str_split_list = _libr_util.r_num_str_split_list
    r_num_str_split_list.restype = ctypes.POINTER(struct_r_list_t)
    r_num_str_split_list.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_num_dup = _libr_util.r_num_dup
    r_num_dup.restype = ctypes.POINTER(None)
    r_num_dup.argtypes = [uint64_t]
except AttributeError:
    pass
try:
    r_num_cos = _libr_util.r_num_cos
    r_num_cos.restype = ctypes.c_double
    r_num_cos.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    r_num_sin = _libr_util.r_num_sin
    r_num_sin.restype = ctypes.c_double
    r_num_sin.argtypes = [ctypes.c_double]
except AttributeError:
    pass
try:
    r_num_bit_count = _libr_util.r_num_bit_count
    r_num_bit_count.restype = size_t
    r_num_bit_count.argtypes = [uint32_t]
except AttributeError:
    pass
try:
    r_num_get_float = _libr_util.r_num_get_float
    r_num_get_float.restype = ctypes.c_double
    r_num_get_float.argtypes = [ctypes.POINTER(struct_r_num_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_num_abs = _libraries['FIXME_STUB'].r_num_abs
    r_num_abs.restype = int64_t
    r_num_abs.argtypes = [int64_t]
except AttributeError:
    pass
class struct_RTableColumnType(Structure):
    pass

struct_RTableColumnType._pack_ = 1 # source:False
struct_RTableColumnType._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('cmp', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(None))),
]

RTableColumnType = struct_RTableColumnType
class struct_RTableColumn(Structure):
    pass

struct_RTableColumn._pack_ = 1 # source:False
struct_RTableColumn._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('type', ctypes.POINTER(struct_RTableColumnType)),
    ('align', ctypes.c_int32),
    ('width', ctypes.c_int32),
    ('maxWidth', ctypes.c_int32),
    ('forceUppercase', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 3),
    ('total', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
]

RTableColumn = struct_RTableColumn
class struct_RListInfo(Structure):
    pass

struct_RListInfo._pack_ = 1 # source:False
struct_RListInfo._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('pitv', RInterval),
    ('vitv', RInterval),
    ('perm', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('extra', ctypes.POINTER(ctypes.c_char)),
]

RListInfo = struct_RListInfo

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
class struct_RTableRow(Structure):
    pass

struct_RTableRow._pack_ = 1 # source:False
struct_RTableRow._fields_ = [
    ('items', ctypes.POINTER(struct_r_list_t)),
]

RTableRow = struct_RTableRow
class struct_RTable(Structure):
    pass

struct_RTable._pack_ = 1 # source:False
struct_RTable._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
    ('rows', ctypes.POINTER(struct_r_list_t)),
    ('cols', ctypes.POINTER(struct_r_list_t)),
    ('totalCols', ctypes.c_int32),
    ('showHeader', ctypes.c_bool),
    ('showFancy', ctypes.c_bool),
    ('showSQL', ctypes.c_bool),
    ('showJSON', ctypes.c_bool),
    ('showCSV', ctypes.c_bool),
    ('showTSV', ctypes.c_bool),
    ('showHTML', ctypes.c_bool),
    ('showR2', ctypes.c_bool),
    ('showSum', ctypes.c_bool),
    ('adjustedCols', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 2),
    ('cons', ctypes.POINTER(None)),
]

RTable = struct_RTable
RTableSelector = ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_RTableRow), ctypes.POINTER(struct_RTableRow), ctypes.c_int32)
try:
    r_table_row_free = _libr_util.r_table_row_free
    r_table_row_free.restype = None
    r_table_row_free.argtypes = [ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_table_column_free = _libr_util.r_table_column_free
    r_table_column_free.restype = None
    r_table_column_free.argtypes = [ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_table_column_clone = _libr_util.r_table_column_clone
    r_table_column_clone.restype = ctypes.POINTER(struct_RTableColumn)
    r_table_column_clone.argtypes = [ctypes.POINTER(struct_RTableColumn)]
except AttributeError:
    pass
try:
    r_table_type = _libr_util.r_table_type
    r_table_type.restype = ctypes.POINTER(struct_RTableColumnType)
    r_table_type.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_table_new = _libr_util.r_table_new
    r_table_new.restype = ctypes.POINTER(struct_RTable)
    r_table_new.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_table_clone = _libr_util.r_table_clone
    r_table_clone.restype = ctypes.POINTER(struct_RTable)
    r_table_clone.argtypes = [ctypes.POINTER(struct_RTable)]
except AttributeError:
    pass
try:
    r_table_free = _libr_util.r_table_free
    r_table_free.restype = None
    r_table_free.argtypes = [ctypes.POINTER(struct_RTable)]
except AttributeError:
    pass
try:
    r_table_column_nth = _libr_util.r_table_column_nth
    r_table_column_nth.restype = ctypes.c_int32
    r_table_column_nth.argtypes = [ctypes.POINTER(struct_RTable), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_table_add_column = _libr_util.r_table_add_column
    r_table_add_column.restype = None
    r_table_add_column.argtypes = [ctypes.POINTER(struct_RTable), ctypes.POINTER(struct_RTableColumnType), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_table_set_columnsf = _libr_util.r_table_set_columnsf
    r_table_set_columnsf.restype = None
    r_table_set_columnsf.argtypes = [ctypes.POINTER(struct_RTable), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_table_row_new = _libr_util.r_table_row_new
    r_table_row_new.restype = ctypes.POINTER(struct_RTableRow)
    r_table_row_new.argtypes = [ctypes.POINTER(struct_r_list_t)]
except AttributeError:
    pass
try:
    r_table_add_row = _libr_util.r_table_add_row
    r_table_add_row.restype = None
    r_table_add_row.argtypes = [ctypes.POINTER(struct_RTable), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_table_add_rowf = _libr_util.r_table_add_rowf
    r_table_add_rowf.restype = None
    r_table_add_rowf.argtypes = [ctypes.POINTER(struct_RTable), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_table_add_row_list = _libr_util.r_table_add_row_list
    r_table_add_row_list.restype = None
    r_table_add_row_list.argtypes = [ctypes.POINTER(struct_RTable), ctypes.POINTER(struct_r_list_t)]
except AttributeError:
    pass
try:
    r_table_tofancystring = _libr_util.r_table_tofancystring
    r_table_tofancystring.restype = ctypes.POINTER(ctypes.c_char)
    r_table_tofancystring.argtypes = [ctypes.POINTER(struct_RTable)]
except AttributeError:
    pass
try:
    r_table_tosimplestring = _libr_util.r_table_tosimplestring
    r_table_tosimplestring.restype = ctypes.POINTER(ctypes.c_char)
    r_table_tosimplestring.argtypes = [ctypes.POINTER(struct_RTable)]
except AttributeError:
    pass
try:
    r_table_tostring = _libr_util.r_table_tostring
    r_table_tostring.restype = ctypes.POINTER(ctypes.c_char)
    r_table_tostring.argtypes = [ctypes.POINTER(struct_RTable)]
except AttributeError:
    pass
try:
    r_table_tosql = _libr_util.r_table_tosql
    r_table_tosql.restype = ctypes.POINTER(ctypes.c_char)
    r_table_tosql.argtypes = [ctypes.POINTER(struct_RTable)]
except AttributeError:
    pass
try:
    r_table_tocsv = _libr_util.r_table_tocsv
    r_table_tocsv.restype = ctypes.POINTER(ctypes.c_char)
    r_table_tocsv.argtypes = [ctypes.POINTER(struct_RTable)]
except AttributeError:
    pass
try:
    r_table_tohtml = _libr_util.r_table_tohtml
    r_table_tohtml.restype = ctypes.POINTER(ctypes.c_char)
    r_table_tohtml.argtypes = [ctypes.POINTER(struct_RTable)]
except AttributeError:
    pass
try:
    r_table_totsv = _libr_util.r_table_totsv
    r_table_totsv.restype = ctypes.POINTER(ctypes.c_char)
    r_table_totsv.argtypes = [ctypes.POINTER(struct_RTable)]
except AttributeError:
    pass
try:
    r_table_tor2cmds = _libr_util.r_table_tor2cmds
    r_table_tor2cmds.restype = ctypes.POINTER(ctypes.c_char)
    r_table_tor2cmds.argtypes = [ctypes.POINTER(struct_RTable)]
except AttributeError:
    pass
try:
    r_table_tojson = _libr_util.r_table_tojson
    r_table_tojson.restype = ctypes.POINTER(ctypes.c_char)
    r_table_tojson.argtypes = [ctypes.POINTER(struct_RTable)]
except AttributeError:
    pass
try:
    r_table_help = _libr_util.r_table_help
    r_table_help.restype = ctypes.POINTER(ctypes.c_char)
    r_table_help.argtypes = []
except AttributeError:
    pass
try:
    r_table_filter = _libr_util.r_table_filter
    r_table_filter.restype = None
    r_table_filter.argtypes = [ctypes.POINTER(struct_RTable), ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_table_sort = _libr_util.r_table_sort
    r_table_sort.restype = None
    r_table_sort.argtypes = [ctypes.POINTER(struct_RTable), ctypes.c_int32, ctypes.c_bool]
except AttributeError:
    pass
try:
    r_table_uniq = _libr_util.r_table_uniq
    r_table_uniq.restype = None
    r_table_uniq.argtypes = [ctypes.POINTER(struct_RTable)]
except AttributeError:
    pass
try:
    r_table_group = _libr_util.r_table_group
    r_table_group.restype = None
    r_table_group.argtypes = [ctypes.POINTER(struct_RTable), ctypes.c_int32, RTableSelector]
except AttributeError:
    pass
try:
    r_table_query = _libr_util.r_table_query
    r_table_query.restype = ctypes.c_bool
    r_table_query.argtypes = [ctypes.POINTER(struct_RTable), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_table_hide_header = _libr_util.r_table_hide_header
    r_table_hide_header.restype = None
    r_table_hide_header.argtypes = [ctypes.POINTER(struct_RTable)]
except AttributeError:
    pass
try:
    r_table_align = _libr_util.r_table_align
    r_table_align.restype = ctypes.c_bool
    r_table_align.argtypes = [ctypes.POINTER(struct_RTable), ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_table_visual_list = _libr_util.r_table_visual_list
    r_table_visual_list.restype = None
    r_table_visual_list.argtypes = [ctypes.POINTER(struct_RTable), ctypes.POINTER(struct_r_list_t), uint64_t, uint64_t, ctypes.c_int32, ctypes.c_bool]
except AttributeError:
    pass
try:
    r_table_push = _libraries['FIXME_STUB'].r_table_push
    r_table_push.restype = ctypes.POINTER(struct_RTable)
    r_table_push.argtypes = [ctypes.POINTER(struct_RTable)]
except AttributeError:
    pass
try:
    r_table_pop = _libraries['FIXME_STUB'].r_table_pop
    r_table_pop.restype = ctypes.POINTER(struct_RTable)
    r_table_pop.argtypes = [ctypes.POINTER(struct_RTable)]
except AttributeError:
    pass
try:
    r_table_columns = _libr_util.r_table_columns
    r_table_columns.restype = None
    r_table_columns.argtypes = [ctypes.POINTER(struct_RTable), ctypes.POINTER(struct_r_list_t)]
except AttributeError:
    pass
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

RGraphNode = struct_r_graph_node_t
class struct_r_graph_edge_t(Structure):
    pass

struct_r_graph_edge_t._pack_ = 1 # source:False
struct_r_graph_edge_t._fields_ = [
    ('from_', ctypes.POINTER(struct_r_graph_node_t)),
    ('to', ctypes.POINTER(struct_r_graph_node_t)),
    ('nth', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

RGraphEdge = struct_r_graph_edge_t
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

RGraph = struct_r_graph_t
class struct_r_graph_visitor_t(Structure):
    pass

struct_r_graph_visitor_t._pack_ = 1 # source:False
struct_r_graph_visitor_t._fields_ = [
    ('discover_node', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_graph_node_t), ctypes.POINTER(struct_r_graph_visitor_t))),
    ('finish_node', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_graph_node_t), ctypes.POINTER(struct_r_graph_visitor_t))),
    ('tree_edge', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_graph_edge_t), ctypes.POINTER(struct_r_graph_visitor_t))),
    ('back_edge', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_graph_edge_t), ctypes.POINTER(struct_r_graph_visitor_t))),
    ('fcross_edge', ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_graph_edge_t), ctypes.POINTER(struct_r_graph_visitor_t))),
    ('data', ctypes.POINTER(None)),
]

RGraphVisitor = struct_r_graph_visitor_t
RGraphNodeCallback = ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_graph_node_t), ctypes.POINTER(struct_r_graph_visitor_t))
RGraphEdgeCallback = ctypes.CFUNCTYPE(None, ctypes.POINTER(struct_r_graph_edge_t), ctypes.POINTER(struct_r_graph_visitor_t))
try:
    r_graph_new = _libr_util.r_graph_new
    r_graph_new.restype = ctypes.POINTER(struct_r_graph_t)
    r_graph_new.argtypes = []
except AttributeError:
    pass
try:
    r_graph_free = _libr_util.r_graph_free
    r_graph_free.restype = None
    r_graph_free.argtypes = [ctypes.POINTER(struct_r_graph_t)]
except AttributeError:
    pass
try:
    r_graph_get_node = _libr_util.r_graph_get_node
    r_graph_get_node.restype = ctypes.POINTER(struct_r_graph_node_t)
    r_graph_get_node.argtypes = [ctypes.POINTER(struct_r_graph_t), ctypes.c_uint32]
except AttributeError:
    pass
try:
    r_graph_node_iter = _libr_util.r_graph_node_iter
    r_graph_node_iter.restype = ctypes.POINTER(struct_r_list_iter_t)
    r_graph_node_iter.argtypes = [ctypes.POINTER(struct_r_graph_t), ctypes.c_uint32]
except AttributeError:
    pass
try:
    r_graph_reset = _libr_util.r_graph_reset
    r_graph_reset.restype = None
    r_graph_reset.argtypes = [ctypes.POINTER(struct_r_graph_t)]
except AttributeError:
    pass
try:
    r_graph_add_node = _libr_util.r_graph_add_node
    r_graph_add_node.restype = ctypes.POINTER(struct_r_graph_node_t)
    r_graph_add_node.argtypes = [ctypes.POINTER(struct_r_graph_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_graph_add_nodef = _libr_util.r_graph_add_nodef
    r_graph_add_nodef.restype = ctypes.POINTER(struct_r_graph_node_t)
    r_graph_add_nodef.argtypes = [ctypes.POINTER(struct_r_graph_t), ctypes.POINTER(None), RListFree]
except AttributeError:
    pass
try:
    r_graph_del_node = _libr_util.r_graph_del_node
    r_graph_del_node.restype = None
    r_graph_del_node.argtypes = [ctypes.POINTER(struct_r_graph_t), ctypes.POINTER(struct_r_graph_node_t)]
except AttributeError:
    pass
try:
    r_graph_add_edge = _libr_util.r_graph_add_edge
    r_graph_add_edge.restype = None
    r_graph_add_edge.argtypes = [ctypes.POINTER(struct_r_graph_t), ctypes.POINTER(struct_r_graph_node_t), ctypes.POINTER(struct_r_graph_node_t)]
except AttributeError:
    pass
try:
    r_graph_add_edge_at = _libr_util.r_graph_add_edge_at
    r_graph_add_edge_at.restype = None
    r_graph_add_edge_at.argtypes = [ctypes.POINTER(struct_r_graph_t), ctypes.POINTER(struct_r_graph_node_t), ctypes.POINTER(struct_r_graph_node_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_graph_node_split_forward = _libr_util.r_graph_node_split_forward
    r_graph_node_split_forward.restype = ctypes.POINTER(struct_r_graph_node_t)
    r_graph_node_split_forward.argtypes = [ctypes.POINTER(struct_r_graph_t), ctypes.POINTER(struct_r_graph_node_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_graph_del_edge = _libr_util.r_graph_del_edge
    r_graph_del_edge.restype = None
    r_graph_del_edge.argtypes = [ctypes.POINTER(struct_r_graph_t), ctypes.POINTER(struct_r_graph_node_t), ctypes.POINTER(struct_r_graph_node_t)]
except AttributeError:
    pass
try:
    r_graph_get_neighbours = _libr_util.r_graph_get_neighbours
    r_graph_get_neighbours.restype = ctypes.POINTER(struct_r_list_t)
    r_graph_get_neighbours.argtypes = [ctypes.POINTER(struct_r_graph_t), ctypes.POINTER(struct_r_graph_node_t)]
except AttributeError:
    pass
try:
    r_graph_nth_neighbour = _libr_util.r_graph_nth_neighbour
    r_graph_nth_neighbour.restype = ctypes.POINTER(struct_r_graph_node_t)
    r_graph_nth_neighbour.argtypes = [ctypes.POINTER(struct_r_graph_t), ctypes.POINTER(struct_r_graph_node_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_graph_innodes = _libr_util.r_graph_innodes
    r_graph_innodes.restype = ctypes.POINTER(struct_r_list_t)
    r_graph_innodes.argtypes = [ctypes.POINTER(struct_r_graph_t), ctypes.POINTER(struct_r_graph_node_t)]
except AttributeError:
    pass
try:
    r_graph_all_neighbours = _libr_util.r_graph_all_neighbours
    r_graph_all_neighbours.restype = ctypes.POINTER(struct_r_list_t)
    r_graph_all_neighbours.argtypes = [ctypes.POINTER(struct_r_graph_t), ctypes.POINTER(struct_r_graph_node_t)]
except AttributeError:
    pass
try:
    r_graph_get_nodes = _libr_util.r_graph_get_nodes
    r_graph_get_nodes.restype = ctypes.POINTER(struct_r_list_t)
    r_graph_get_nodes.argtypes = [ctypes.POINTER(struct_r_graph_t)]
except AttributeError:
    pass
try:
    r_graph_adjacent = _libr_util.r_graph_adjacent
    r_graph_adjacent.restype = ctypes.c_bool
    r_graph_adjacent.argtypes = [ctypes.POINTER(struct_r_graph_t), ctypes.POINTER(struct_r_graph_node_t), ctypes.POINTER(struct_r_graph_node_t)]
except AttributeError:
    pass
try:
    r_graph_dfs_node = _libr_util.r_graph_dfs_node
    r_graph_dfs_node.restype = None
    r_graph_dfs_node.argtypes = [ctypes.POINTER(struct_r_graph_t), ctypes.POINTER(struct_r_graph_node_t), ctypes.POINTER(struct_r_graph_visitor_t)]
except AttributeError:
    pass
try:
    r_graph_dfs_node_reverse = _libr_util.r_graph_dfs_node_reverse
    r_graph_dfs_node_reverse.restype = None
    r_graph_dfs_node_reverse.argtypes = [ctypes.POINTER(struct_r_graph_t), ctypes.POINTER(struct_r_graph_node_t), ctypes.POINTER(struct_r_graph_visitor_t)]
except AttributeError:
    pass
try:
    r_graph_dfs = _libr_util.r_graph_dfs
    r_graph_dfs.restype = None
    r_graph_dfs.argtypes = [ctypes.POINTER(struct_r_graph_t), ctypes.POINTER(struct_r_graph_visitor_t)]
except AttributeError:
    pass

# values for enumeration 'RPanelLayout'
RPanelLayout__enumvalues = {
    0: 'PANEL_LAYOUT_VERTICAL',
    1: 'PANEL_LAYOUT_HORIZONTAL',
    2: 'PANEL_LAYOUT_NONE',
}
PANEL_LAYOUT_VERTICAL = 0
PANEL_LAYOUT_HORIZONTAL = 1
PANEL_LAYOUT_NONE = 2
RPanelLayout = ctypes.c_uint32 # enum

# values for enumeration 'RPanelType'
RPanelType__enumvalues = {
    0: 'PANEL_TYPE_DEFAULT',
    1: 'PANEL_TYPE_MENU',
}
PANEL_TYPE_DEFAULT = 0
PANEL_TYPE_MENU = 1
RPanelType = ctypes.c_uint32 # enum

# values for enumeration 'RPanelEdge'
RPanelEdge__enumvalues = {
    0: 'PANEL_EDGE_NONE',
    1: 'PANEL_EDGE_BOTTOM',
    2: 'PANEL_EDGE_RIGHT',
}
PANEL_EDGE_NONE = 0
PANEL_EDGE_BOTTOM = 1
PANEL_EDGE_RIGHT = 2
RPanelEdge = ctypes.c_uint32 # enum
RPanelMenuUpdateCallback = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))
RPanelDirectionCallback = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.c_int32)
RPanelRotateCallback = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.c_bool)
RPanelPrintCallback = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(None))
class struct_r_panel_pos_t(Structure):
    pass

struct_r_panel_pos_t._pack_ = 1 # source:False
struct_r_panel_pos_t._fields_ = [
    ('x', ctypes.c_int32),
    ('y', ctypes.c_int32),
    ('w', ctypes.c_int32),
    ('h', ctypes.c_int32),
]

RPanelPos = struct_r_panel_pos_t
class struct_r_panel_model_t(Structure):
    pass

struct_r_panel_model_t._pack_ = 1 # source:False
struct_r_panel_model_t._fields_ = [
    ('directionCb', ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.c_int32)),
    ('rotateCb', ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.c_bool)),
    ('print_cb', ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(None))),
    ('type', RPanelType),
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

RPanelModel = struct_r_panel_model_t
class struct_r_panel_view_t(Structure):
    pass

struct_r_panel_view_t._pack_ = 1 # source:False
struct_r_panel_view_t._fields_ = [
    ('pos', RPanelPos),
    ('prevPos', RPanelPos),
    ('sx', ctypes.c_int32),
    ('sy', ctypes.c_int32),
    ('curpos', ctypes.c_int32),
    ('refresh', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 3),
    ('edge', ctypes.c_int32),
]

RPanelView = struct_r_panel_view_t
class struct_r_panel_t(Structure):
    pass

struct_r_panel_t._pack_ = 1 # source:False
struct_r_panel_t._fields_ = [
    ('model', ctypes.POINTER(struct_r_panel_model_t)),
    ('view', ctypes.POINTER(struct_r_panel_view_t)),
]

RPanel = struct_r_panel_t
RPanelAlmightyCallback = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(struct_r_panel_t), RPanelLayout, ctypes.POINTER(ctypes.c_char))
class struct_r_mem_pool_factory_t(Structure):
    pass

struct_r_mem_pool_factory_t._pack_ = 1 # source:False
struct_r_mem_pool_factory_t._fields_ = [
    ('limit', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('pools', ctypes.POINTER(ctypes.POINTER(struct_r_mem_pool_t))),
]

RPoolFactory = struct_r_mem_pool_factory_t
try:
    r_poolfactory_instance = _libraries['FIXME_STUB'].r_poolfactory_instance
    r_poolfactory_instance.restype = ctypes.POINTER(struct_r_mem_pool_factory_t)
    r_poolfactory_instance.argtypes = []
except AttributeError:
    pass
try:
    r_poolfactory_init = _libraries['FIXME_STUB'].r_poolfactory_init
    r_poolfactory_init.restype = None
    r_poolfactory_init.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_poolfactory_new = _libraries['FIXME_STUB'].r_poolfactory_new
    r_poolfactory_new.restype = ctypes.POINTER(struct_r_mem_pool_factory_t)
    r_poolfactory_new.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_poolfactory_alloc = _libraries['FIXME_STUB'].r_poolfactory_alloc
    r_poolfactory_alloc.restype = ctypes.POINTER(None)
    r_poolfactory_alloc.argtypes = [ctypes.POINTER(struct_r_mem_pool_factory_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_poolfactory_stats = _libraries['FIXME_STUB'].r_poolfactory_stats
    r_poolfactory_stats.restype = None
    r_poolfactory_stats.argtypes = [ctypes.POINTER(struct_r_mem_pool_factory_t)]
except AttributeError:
    pass
try:
    r_poolfactory_free = _libraries['FIXME_STUB'].r_poolfactory_free
    r_poolfactory_free.restype = None
    r_poolfactory_free.argtypes = [ctypes.POINTER(struct_r_mem_pool_factory_t)]
except AttributeError:
    pass
class struct_RStrBuf(Structure):
    pass

struct_RStrBuf._pack_ = 1 # source:False
struct_RStrBuf._fields_ = [
    ('buf', ctypes.c_char * 32),
    ('len', ctypes.c_uint64),
    ('ptr', ctypes.POINTER(ctypes.c_char)),
    ('ptrlen', ctypes.c_uint64),
    ('weakref', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
]

RStrBuf = struct_RStrBuf
try:
    r_strbuf_new = _libr_util.r_strbuf_new
    r_strbuf_new.restype = ctypes.POINTER(struct_RStrBuf)
    r_strbuf_new.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_strbuf_set = _libr_util.r_strbuf_set
    r_strbuf_set.restype = ctypes.POINTER(ctypes.c_char)
    r_strbuf_set.argtypes = [ctypes.POINTER(struct_RStrBuf), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_strbuf_slice = _libr_util.r_strbuf_slice
    r_strbuf_slice.restype = ctypes.c_bool
    r_strbuf_slice.argtypes = [ctypes.POINTER(struct_RStrBuf), ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_strbuf_setbin = _libr_util.r_strbuf_setbin
    r_strbuf_setbin.restype = ctypes.c_bool
    r_strbuf_setbin.argtypes = [ctypes.POINTER(struct_RStrBuf), ctypes.POINTER(ctypes.c_ubyte), size_t]
except AttributeError:
    pass
try:
    r_strbuf_getbin = _libr_util.r_strbuf_getbin
    r_strbuf_getbin.restype = ctypes.POINTER(ctypes.c_ubyte)
    r_strbuf_getbin.argtypes = [ctypes.POINTER(struct_RStrBuf), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_strbuf_setf = _libr_util.r_strbuf_setf
    r_strbuf_setf.restype = ctypes.POINTER(ctypes.c_char)
    r_strbuf_setf.argtypes = [ctypes.POINTER(struct_RStrBuf), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_strbuf_vsetf = _libr_util.r_strbuf_vsetf
    r_strbuf_vsetf.restype = ctypes.POINTER(ctypes.c_char)
    r_strbuf_vsetf.argtypes = [ctypes.POINTER(struct_RStrBuf), ctypes.POINTER(ctypes.c_char), va_list]
except AttributeError:
    pass
try:
    r_strbuf_append = _libr_util.r_strbuf_append
    r_strbuf_append.restype = ctypes.c_bool
    r_strbuf_append.argtypes = [ctypes.POINTER(struct_RStrBuf), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_strbuf_append_n = _libr_util.r_strbuf_append_n
    r_strbuf_append_n.restype = ctypes.c_bool
    r_strbuf_append_n.argtypes = [ctypes.POINTER(struct_RStrBuf), ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    r_strbuf_prepend = _libr_util.r_strbuf_prepend
    r_strbuf_prepend.restype = ctypes.c_bool
    r_strbuf_prepend.argtypes = [ctypes.POINTER(struct_RStrBuf), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_strbuf_appendf = _libr_util.r_strbuf_appendf
    r_strbuf_appendf.restype = ctypes.c_bool
    r_strbuf_appendf.argtypes = [ctypes.POINTER(struct_RStrBuf), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_strbuf_vappendf = _libr_util.r_strbuf_vappendf
    r_strbuf_vappendf.restype = ctypes.c_bool
    r_strbuf_vappendf.argtypes = [ctypes.POINTER(struct_RStrBuf), ctypes.POINTER(ctypes.c_char), va_list]
except AttributeError:
    pass
try:
    r_strbuf_get = _libr_util.r_strbuf_get
    r_strbuf_get.restype = ctypes.POINTER(ctypes.c_char)
    r_strbuf_get.argtypes = [ctypes.POINTER(struct_RStrBuf)]
except AttributeError:
    pass
try:
    r_strbuf_drain = _libr_util.r_strbuf_drain
    r_strbuf_drain.restype = ctypes.POINTER(ctypes.c_char)
    r_strbuf_drain.argtypes = [ctypes.POINTER(struct_RStrBuf)]
except AttributeError:
    pass
try:
    r_strbuf_drain_nofree = _libr_util.r_strbuf_drain_nofree
    r_strbuf_drain_nofree.restype = ctypes.POINTER(ctypes.c_char)
    r_strbuf_drain_nofree.argtypes = [ctypes.POINTER(struct_RStrBuf)]
except AttributeError:
    pass
try:
    r_strbuf_replace = _libr_util.r_strbuf_replace
    r_strbuf_replace.restype = ctypes.c_bool
    r_strbuf_replace.argtypes = [ctypes.POINTER(struct_RStrBuf), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_strbuf_replacef = _libr_util.r_strbuf_replacef
    r_strbuf_replacef.restype = ctypes.c_bool
    r_strbuf_replacef.argtypes = [ctypes.POINTER(struct_RStrBuf), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_strbuf_length = _libr_util.r_strbuf_length
    r_strbuf_length.restype = ctypes.c_int32
    r_strbuf_length.argtypes = [ctypes.POINTER(struct_RStrBuf)]
except AttributeError:
    pass
try:
    r_strbuf_size = _libraries['FIXME_STUB'].r_strbuf_size
    r_strbuf_size.restype = ctypes.c_int32
    r_strbuf_size.argtypes = [ctypes.POINTER(struct_RStrBuf)]
except AttributeError:
    pass
try:
    r_strbuf_free = _libr_util.r_strbuf_free
    r_strbuf_free.restype = None
    r_strbuf_free.argtypes = [ctypes.POINTER(struct_RStrBuf)]
except AttributeError:
    pass
try:
    r_strbuf_fini = _libr_util.r_strbuf_fini
    r_strbuf_fini.restype = None
    r_strbuf_fini.argtypes = [ctypes.POINTER(struct_RStrBuf)]
except AttributeError:
    pass
try:
    r_strbuf_init = _libr_util.r_strbuf_init
    r_strbuf_init.restype = None
    r_strbuf_init.argtypes = [ctypes.POINTER(struct_RStrBuf)]
except AttributeError:
    pass
try:
    r_strbuf_initf = _libr_util.r_strbuf_initf
    r_strbuf_initf.restype = ctypes.POINTER(ctypes.c_char)
    r_strbuf_initf.argtypes = [ctypes.POINTER(struct_RStrBuf), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_strbuf_copy = _libr_util.r_strbuf_copy
    r_strbuf_copy.restype = ctypes.c_bool
    r_strbuf_copy.argtypes = [ctypes.POINTER(struct_RStrBuf), ctypes.POINTER(struct_RStrBuf)]
except AttributeError:
    pass
try:
    r_strbuf_equals = _libr_util.r_strbuf_equals
    r_strbuf_equals.restype = ctypes.c_bool
    r_strbuf_equals.argtypes = [ctypes.POINTER(struct_RStrBuf), ctypes.POINTER(struct_RStrBuf)]
except AttributeError:
    pass
try:
    r_strbuf_reserve = _libr_util.r_strbuf_reserve
    r_strbuf_reserve.restype = ctypes.c_bool
    r_strbuf_reserve.argtypes = [ctypes.POINTER(struct_RStrBuf), size_t]
except AttributeError:
    pass
try:
    r_strbuf_is_empty = _libr_util.r_strbuf_is_empty
    r_strbuf_is_empty.restype = ctypes.c_bool
    r_strbuf_is_empty.argtypes = [ctypes.POINTER(struct_RStrBuf)]
except AttributeError:
    pass
try:
    r_strbuf_setptr = _libr_util.r_strbuf_setptr
    r_strbuf_setptr.restype = ctypes.c_bool
    r_strbuf_setptr.argtypes = [ctypes.POINTER(struct_RStrBuf), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
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
class struct_pj_t(Structure):
    pass

struct_pj_t._pack_ = 1 # source:False
struct_pj_t._fields_ = [
    ('sb', RStrBuf),
    ('is_first', ctypes.c_bool),
    ('is_key', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 6),
    ('comma', ctypes.POINTER(ctypes.c_char)),
    ('braces', ctypes.c_char * 128),
    ('level', ctypes.c_int32),
    ('str_encoding', PJEncodingStr),
    ('num_encoding', PJEncodingNum),
    ('PADDING_1', ctypes.c_ubyte * 4),
]

PJ = struct_pj_t
try:
    pj_new = _libr_util.pj_new
    pj_new.restype = ctypes.POINTER(struct_pj_t)
    pj_new.argtypes = []
except AttributeError:
    pass
try:
    pj_new_with_encoding = _libr_util.pj_new_with_encoding
    pj_new_with_encoding.restype = ctypes.POINTER(struct_pj_t)
    pj_new_with_encoding.argtypes = [PJEncodingStr, PJEncodingNum]
except AttributeError:
    pass
try:
    pj_free = _libr_util.pj_free
    pj_free.restype = None
    pj_free.argtypes = [ctypes.POINTER(struct_pj_t)]
except AttributeError:
    pass
try:
    pj_reset = _libr_util.pj_reset
    pj_reset.restype = None
    pj_reset.argtypes = [ctypes.POINTER(struct_pj_t)]
except AttributeError:
    pass
try:
    pj_drain = _libr_util.pj_drain
    pj_drain.restype = ctypes.POINTER(ctypes.c_char)
    pj_drain.argtypes = [ctypes.POINTER(struct_pj_t)]
except AttributeError:
    pass
try:
    pj_string = _libr_util.pj_string
    pj_string.restype = ctypes.POINTER(ctypes.c_char)
    pj_string.argtypes = [ctypes.POINTER(struct_pj_t)]
except AttributeError:
    pass
try:
    pj_end = _libr_util.pj_end
    pj_end.restype = ctypes.POINTER(struct_pj_t)
    pj_end.argtypes = [ctypes.POINTER(struct_pj_t)]
except AttributeError:
    pass
try:
    pj_raw = _libr_util.pj_raw
    pj_raw.restype = None
    pj_raw.argtypes = [ctypes.POINTER(struct_pj_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    pj_kraw = _libr_util.pj_kraw
    pj_kraw.restype = None
    pj_kraw.argtypes = [ctypes.POINTER(struct_pj_t)]
except AttributeError:
    pass
try:
    pj_o = _libr_util.pj_o
    pj_o.restype = ctypes.POINTER(struct_pj_t)
    pj_o.argtypes = [ctypes.POINTER(struct_pj_t)]
except AttributeError:
    pass
try:
    pj_a = _libr_util.pj_a
    pj_a.restype = ctypes.POINTER(struct_pj_t)
    pj_a.argtypes = [ctypes.POINTER(struct_pj_t)]
except AttributeError:
    pass
try:
    pj_k = _libr_util.pj_k
    pj_k.restype = ctypes.POINTER(struct_pj_t)
    pj_k.argtypes = [ctypes.POINTER(struct_pj_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    pj_knull = _libr_util.pj_knull
    pj_knull.restype = ctypes.POINTER(struct_pj_t)
    pj_knull.argtypes = [ctypes.POINTER(struct_pj_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    pj_kn = _libr_util.pj_kn
    pj_kn.restype = ctypes.POINTER(struct_pj_t)
    pj_kn.argtypes = [ctypes.POINTER(struct_pj_t), ctypes.POINTER(ctypes.c_char), uint64_t]
except AttributeError:
    pass
try:
    pj_kN = _libr_util.pj_kN
    pj_kN.restype = ctypes.POINTER(struct_pj_t)
    pj_kN.argtypes = [ctypes.POINTER(struct_pj_t), ctypes.POINTER(ctypes.c_char), int64_t]
except AttributeError:
    pass
try:
    pj_ks = _libr_util.pj_ks
    pj_ks.restype = ctypes.POINTER(struct_pj_t)
    pj_ks.argtypes = [ctypes.POINTER(struct_pj_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    pj_ka = _libr_util.pj_ka
    pj_ka.restype = ctypes.POINTER(struct_pj_t)
    pj_ka.argtypes = [ctypes.POINTER(struct_pj_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    pj_ko = _libr_util.pj_ko
    pj_ko.restype = ctypes.POINTER(struct_pj_t)
    pj_ko.argtypes = [ctypes.POINTER(struct_pj_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    pj_ki = _libr_util.pj_ki
    pj_ki.restype = ctypes.POINTER(struct_pj_t)
    pj_ki.argtypes = [ctypes.POINTER(struct_pj_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    pj_kd = _libr_util.pj_kd
    pj_kd.restype = ctypes.POINTER(struct_pj_t)
    pj_kd.argtypes = [ctypes.POINTER(struct_pj_t), ctypes.POINTER(ctypes.c_char), ctypes.c_double]
except AttributeError:
    pass
try:
    pj_kf = _libr_util.pj_kf
    pj_kf.restype = ctypes.POINTER(struct_pj_t)
    pj_kf.argtypes = [ctypes.POINTER(struct_pj_t), ctypes.POINTER(ctypes.c_char), ctypes.c_float]
except AttributeError:
    pass
try:
    pj_kb = _libr_util.pj_kb
    pj_kb.restype = ctypes.POINTER(struct_pj_t)
    pj_kb.argtypes = [ctypes.POINTER(struct_pj_t), ctypes.POINTER(ctypes.c_char), ctypes.c_bool]
except AttributeError:
    pass
try:
    pj_null = _libr_util.pj_null
    pj_null.restype = ctypes.POINTER(struct_pj_t)
    pj_null.argtypes = [ctypes.POINTER(struct_pj_t)]
except AttributeError:
    pass
try:
    pj_r = _libr_util.pj_r
    pj_r.restype = ctypes.POINTER(struct_pj_t)
    pj_r.argtypes = [ctypes.POINTER(struct_pj_t), ctypes.POINTER(ctypes.c_ubyte), size_t]
except AttributeError:
    pass
try:
    pj_kr = _libr_util.pj_kr
    pj_kr.restype = ctypes.POINTER(struct_pj_t)
    pj_kr.argtypes = [ctypes.POINTER(struct_pj_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_ubyte), size_t]
except AttributeError:
    pass
try:
    pj_s = _libr_util.pj_s
    pj_s.restype = ctypes.POINTER(struct_pj_t)
    pj_s.argtypes = [ctypes.POINTER(struct_pj_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    pj_j = _libr_util.pj_j
    pj_j.restype = ctypes.POINTER(struct_pj_t)
    pj_j.argtypes = [ctypes.POINTER(struct_pj_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    pj_se = _libr_util.pj_se
    pj_se.restype = ctypes.POINTER(struct_pj_t)
    pj_se.argtypes = [ctypes.POINTER(struct_pj_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    pj_ne = _libr_util.pj_ne
    pj_ne.restype = ctypes.POINTER(struct_pj_t)
    pj_ne.argtypes = [ctypes.POINTER(struct_pj_t), uint64_t]
except AttributeError:
    pass
try:
    pj_n = _libr_util.pj_n
    pj_n.restype = ctypes.POINTER(struct_pj_t)
    pj_n.argtypes = [ctypes.POINTER(struct_pj_t), uint64_t]
except AttributeError:
    pass
try:
    pj_N = _libr_util.pj_N
    pj_N.restype = ctypes.POINTER(struct_pj_t)
    pj_N.argtypes = [ctypes.POINTER(struct_pj_t), int64_t]
except AttributeError:
    pass
try:
    pj_i = _libr_util.pj_i
    pj_i.restype = ctypes.POINTER(struct_pj_t)
    pj_i.argtypes = [ctypes.POINTER(struct_pj_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    pj_d = _libr_util.pj_d
    pj_d.restype = ctypes.POINTER(struct_pj_t)
    pj_d.argtypes = [ctypes.POINTER(struct_pj_t), ctypes.c_double]
except AttributeError:
    pass
try:
    pj_f = _libr_util.pj_f
    pj_f.restype = ctypes.POINTER(struct_pj_t)
    pj_f.argtypes = [ctypes.POINTER(struct_pj_t), ctypes.c_float]
except AttributeError:
    pass
try:
    pj_b = _libr_util.pj_b
    pj_b.restype = ctypes.POINTER(struct_pj_t)
    pj_b.argtypes = [ctypes.POINTER(struct_pj_t), ctypes.c_bool]
except AttributeError:
    pass
try:
    r_sandbox_opendir = _libr_util.r_sandbox_opendir
    r_sandbox_opendir.restype = ctypes.POINTER(struct___dirstream)
    r_sandbox_opendir.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_sandbox_truncate = _libr_util.r_sandbox_truncate
    r_sandbox_truncate.restype = ctypes.c_int32
    r_sandbox_truncate.argtypes = [ctypes.c_int32, uint64_t]
except AttributeError:
    pass
try:
    r_sandbox_lseek = _libr_util.r_sandbox_lseek
    r_sandbox_lseek.restype = ctypes.c_int32
    r_sandbox_lseek.argtypes = [ctypes.c_int32, uint64_t, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_sandbox_close = _libr_util.r_sandbox_close
    r_sandbox_close.restype = ctypes.c_int32
    r_sandbox_close.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_sandbox_read = _libr_util.r_sandbox_read
    r_sandbox_read.restype = ctypes.c_int32
    r_sandbox_read.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_sandbox_write = _libr_util.r_sandbox_write
    r_sandbox_write.restype = ctypes.c_int32
    r_sandbox_write.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_sandbox_system = _libr_util.r_sandbox_system
    r_sandbox_system.restype = ctypes.c_int32
    r_sandbox_system.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_sandbox_creat = _libr_util.r_sandbox_creat
    r_sandbox_creat.restype = ctypes.c_bool
    r_sandbox_creat.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_sandbox_open = _libr_util.r_sandbox_open
    r_sandbox_open.restype = ctypes.c_int32
    r_sandbox_open.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_sandbox_fopen = _libr_util.r_sandbox_fopen
    r_sandbox_fopen.restype = ctypes.POINTER(struct__IO_FILE)
    r_sandbox_fopen.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_sandbox_chdir = _libr_util.r_sandbox_chdir
    r_sandbox_chdir.restype = ctypes.c_int32
    r_sandbox_chdir.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_sandbox_check_path = _libr_util.r_sandbox_check_path
    r_sandbox_check_path.restype = ctypes.c_bool
    r_sandbox_check_path.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_sandbox_kill = _libr_util.r_sandbox_kill
    r_sandbox_kill.restype = ctypes.c_int32
    r_sandbox_kill.argtypes = [ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_sandbox_enable = _libr_util.r_sandbox_enable
    r_sandbox_enable.restype = ctypes.c_bool
    r_sandbox_enable.argtypes = [ctypes.c_bool]
except AttributeError:
    pass
try:
    r_sandbox_disable = _libr_util.r_sandbox_disable
    r_sandbox_disable.restype = ctypes.c_bool
    r_sandbox_disable.argtypes = [ctypes.c_bool]
except AttributeError:
    pass
try:
    r_sandbox_grain = _libr_util.r_sandbox_grain
    r_sandbox_grain.restype = ctypes.c_int32
    r_sandbox_grain.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_sandbox_check = _libr_util.r_sandbox_check
    r_sandbox_check.restype = ctypes.c_bool
    r_sandbox_check.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
RStackFree = ctypes.CFUNCTYPE(None, ctypes.POINTER(None))
class struct_r_stack_t(Structure):
    pass

struct_r_stack_t._pack_ = 1 # source:False
struct_r_stack_t._fields_ = [
    ('elems', ctypes.POINTER(ctypes.POINTER(None))),
    ('n_elems', ctypes.c_int32),
    ('top', ctypes.c_int32),
    ('free', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
]

RStack = struct_r_stack_t
try:
    r_stack_new = _libr_util.r_stack_new
    r_stack_new.restype = ctypes.POINTER(struct_r_stack_t)
    r_stack_new.argtypes = [uint32_t]
except AttributeError:
    pass
try:
    r_stack_free = _libr_util.r_stack_free
    r_stack_free.restype = None
    r_stack_free.argtypes = [ctypes.POINTER(struct_r_stack_t)]
except AttributeError:
    pass
try:
    r_stack_is_empty = _libr_util.r_stack_is_empty
    r_stack_is_empty.restype = ctypes.c_bool
    r_stack_is_empty.argtypes = [ctypes.POINTER(struct_r_stack_t)]
except AttributeError:
    pass
try:
    r_stack_newf = _libr_util.r_stack_newf
    r_stack_newf.restype = ctypes.POINTER(struct_r_stack_t)
    r_stack_newf.argtypes = [uint32_t, RStackFree]
except AttributeError:
    pass
try:
    r_stack_push = _libr_util.r_stack_push
    r_stack_push.restype = ctypes.c_bool
    r_stack_push.argtypes = [ctypes.POINTER(struct_r_stack_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_stack_pop = _libr_util.r_stack_pop
    r_stack_pop.restype = ctypes.POINTER(None)
    r_stack_pop.argtypes = [ctypes.POINTER(struct_r_stack_t)]
except AttributeError:
    pass
try:
    r_stack_size = _libr_util.r_stack_size
    r_stack_size.restype = size_t
    r_stack_size.argtypes = [ctypes.POINTER(struct_r_stack_t)]
except AttributeError:
    pass
try:
    r_stack_peek = _libr_util.r_stack_peek
    r_stack_peek.restype = ctypes.POINTER(None)
    r_stack_peek.argtypes = [ctypes.POINTER(struct_r_stack_t)]
except AttributeError:
    pass
wint_t = ctypes.c_uint32
mbstate_t = struct___mbstate_t
try:
    wcscpy = _libraries['FIXME_STUB'].wcscpy
    wcscpy.restype = ctypes.POINTER(ctypes.c_int32)
    wcscpy.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    wcsncpy = _libraries['FIXME_STUB'].wcsncpy
    wcsncpy.restype = ctypes.POINTER(ctypes.c_int32)
    wcsncpy.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32), size_t]
except AttributeError:
    pass
try:
    wcslcpy = _libraries['FIXME_STUB'].wcslcpy
    wcslcpy.restype = size_t
    wcslcpy.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32), size_t]
except AttributeError:
    pass
try:
    wcslcat = _libraries['FIXME_STUB'].wcslcat
    wcslcat.restype = size_t
    wcslcat.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32), size_t]
except AttributeError:
    pass
try:
    wcscat = _libraries['FIXME_STUB'].wcscat
    wcscat.restype = ctypes.POINTER(ctypes.c_int32)
    wcscat.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    wcsncat = _libraries['FIXME_STUB'].wcsncat
    wcsncat.restype = ctypes.POINTER(ctypes.c_int32)
    wcsncat.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32), size_t]
except AttributeError:
    pass
try:
    wcscmp = _libraries['FIXME_STUB'].wcscmp
    wcscmp.restype = ctypes.c_int32
    wcscmp.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    wcsncmp = _libraries['FIXME_STUB'].wcsncmp
    wcsncmp.restype = ctypes.c_int32
    wcsncmp.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32), size_t]
except AttributeError:
    pass
try:
    wcscasecmp = _libraries['FIXME_STUB'].wcscasecmp
    wcscasecmp.restype = ctypes.c_int32
    wcscasecmp.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    wcsncasecmp = _libraries['FIXME_STUB'].wcsncasecmp
    wcsncasecmp.restype = ctypes.c_int32
    wcsncasecmp.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32), size_t]
except AttributeError:
    pass
try:
    wcscasecmp_l = _libraries['FIXME_STUB'].wcscasecmp_l
    wcscasecmp_l.restype = ctypes.c_int32
    wcscasecmp_l.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32), locale_t]
except AttributeError:
    pass
try:
    wcsncasecmp_l = _libraries['FIXME_STUB'].wcsncasecmp_l
    wcsncasecmp_l.restype = ctypes.c_int32
    wcsncasecmp_l.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32), size_t, locale_t]
except AttributeError:
    pass
try:
    wcscoll = _libraries['FIXME_STUB'].wcscoll
    wcscoll.restype = ctypes.c_int32
    wcscoll.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    wcsxfrm = _libraries['FIXME_STUB'].wcsxfrm
    wcsxfrm.restype = size_t
    wcsxfrm.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32), size_t]
except AttributeError:
    pass
try:
    wcscoll_l = _libraries['FIXME_STUB'].wcscoll_l
    wcscoll_l.restype = ctypes.c_int32
    wcscoll_l.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32), locale_t]
except AttributeError:
    pass
try:
    wcsxfrm_l = _libraries['FIXME_STUB'].wcsxfrm_l
    wcsxfrm_l.restype = size_t
    wcsxfrm_l.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32), size_t, locale_t]
except AttributeError:
    pass
try:
    wcsdup = _libraries['FIXME_STUB'].wcsdup
    wcsdup.restype = ctypes.POINTER(ctypes.c_int32)
    wcsdup.argtypes = [ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    wcschr = _libraries['FIXME_STUB'].wcschr
    wcschr.restype = ctypes.POINTER(ctypes.c_int32)
    wcschr.argtypes = [ctypes.POINTER(ctypes.c_int32), wchar_t]
except AttributeError:
    pass
try:
    wcsrchr = _libraries['FIXME_STUB'].wcsrchr
    wcsrchr.restype = ctypes.POINTER(ctypes.c_int32)
    wcsrchr.argtypes = [ctypes.POINTER(ctypes.c_int32), wchar_t]
except AttributeError:
    pass
try:
    wcscspn = _libraries['FIXME_STUB'].wcscspn
    wcscspn.restype = size_t
    wcscspn.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    wcsspn = _libraries['FIXME_STUB'].wcsspn
    wcsspn.restype = size_t
    wcsspn.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    wcspbrk = _libraries['FIXME_STUB'].wcspbrk
    wcspbrk.restype = ctypes.POINTER(ctypes.c_int32)
    wcspbrk.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    wcsstr = _libraries['FIXME_STUB'].wcsstr
    wcsstr.restype = ctypes.POINTER(ctypes.c_int32)
    wcsstr.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    wcstok = _libraries['FIXME_STUB'].wcstok
    wcstok.restype = ctypes.POINTER(ctypes.c_int32)
    wcstok.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.POINTER(ctypes.c_int32))]
except AttributeError:
    pass
try:
    wcslen = _libraries['FIXME_STUB'].wcslen
    wcslen.restype = ctypes.c_uint64
    wcslen.argtypes = [ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    wcsnlen = _libraries['FIXME_STUB'].wcsnlen
    wcsnlen.restype = size_t
    wcsnlen.argtypes = [ctypes.POINTER(ctypes.c_int32), size_t]
except AttributeError:
    pass
try:
    wmemchr = _libraries['FIXME_STUB'].wmemchr
    wmemchr.restype = ctypes.POINTER(ctypes.c_int32)
    wmemchr.argtypes = [ctypes.POINTER(ctypes.c_int32), wchar_t, size_t]
except AttributeError:
    pass
try:
    wmemcmp = _libraries['FIXME_STUB'].wmemcmp
    wmemcmp.restype = ctypes.c_int32
    wmemcmp.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32), size_t]
except AttributeError:
    pass
try:
    wmemcpy = _libraries['FIXME_STUB'].wmemcpy
    wmemcpy.restype = ctypes.POINTER(ctypes.c_int32)
    wmemcpy.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32), size_t]
except AttributeError:
    pass
try:
    wmemmove = _libraries['FIXME_STUB'].wmemmove
    wmemmove.restype = ctypes.POINTER(ctypes.c_int32)
    wmemmove.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32), size_t]
except AttributeError:
    pass
try:
    wmemset = _libraries['FIXME_STUB'].wmemset
    wmemset.restype = ctypes.POINTER(ctypes.c_int32)
    wmemset.argtypes = [ctypes.POINTER(ctypes.c_int32), wchar_t, size_t]
except AttributeError:
    pass
try:
    btowc = _libraries['FIXME_STUB'].btowc
    btowc.restype = wint_t
    btowc.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    wctob = _libraries['FIXME_STUB'].wctob
    wctob.restype = ctypes.c_int32
    wctob.argtypes = [wint_t]
except AttributeError:
    pass
try:
    mbsinit = _libraries['FIXME_STUB'].mbsinit
    mbsinit.restype = ctypes.c_int32
    mbsinit.argtypes = [ctypes.POINTER(struct___mbstate_t)]
except AttributeError:
    pass
try:
    mbrtowc = _libraries['FIXME_STUB'].mbrtowc
    mbrtowc.restype = size_t
    mbrtowc.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(struct___mbstate_t)]
except AttributeError:
    pass
try:
    wcrtomb = _libraries['FIXME_STUB'].wcrtomb
    wcrtomb.restype = size_t
    wcrtomb.argtypes = [ctypes.POINTER(ctypes.c_char), wchar_t, ctypes.POINTER(struct___mbstate_t)]
except AttributeError:
    pass
try:
    __mbrlen = _libraries['FIXME_STUB'].__mbrlen
    __mbrlen.restype = size_t
    __mbrlen.argtypes = [ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(struct___mbstate_t)]
except AttributeError:
    pass
try:
    mbrlen = _libraries['FIXME_STUB'].mbrlen
    mbrlen.restype = size_t
    mbrlen.argtypes = [ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(struct___mbstate_t)]
except AttributeError:
    pass
try:
    mbsrtowcs = _libraries['FIXME_STUB'].mbsrtowcs
    mbsrtowcs.restype = size_t
    mbsrtowcs.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), size_t, ctypes.POINTER(struct___mbstate_t)]
except AttributeError:
    pass
try:
    wcsrtombs = _libraries['FIXME_STUB'].wcsrtombs
    wcsrtombs.restype = size_t
    wcsrtombs.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.POINTER(ctypes.c_int32)), size_t, ctypes.POINTER(struct___mbstate_t)]
except AttributeError:
    pass
try:
    mbsnrtowcs = _libraries['FIXME_STUB'].mbsnrtowcs
    mbsnrtowcs.restype = size_t
    mbsnrtowcs.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), size_t, size_t, ctypes.POINTER(struct___mbstate_t)]
except AttributeError:
    pass
try:
    wcsnrtombs = _libraries['FIXME_STUB'].wcsnrtombs
    wcsnrtombs.restype = size_t
    wcsnrtombs.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.POINTER(ctypes.c_int32)), size_t, size_t, ctypes.POINTER(struct___mbstate_t)]
except AttributeError:
    pass
try:
    wcstod = _libraries['FIXME_STUB'].wcstod
    wcstod.restype = ctypes.c_double
    wcstod.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.POINTER(ctypes.c_int32))]
except AttributeError:
    pass
try:
    wcstof = _libraries['FIXME_STUB'].wcstof
    wcstof.restype = ctypes.c_float
    wcstof.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.POINTER(ctypes.c_int32))]
except AttributeError:
    pass
try:
    wcstold = _libraries['FIXME_STUB'].wcstold
    wcstold.restype = c_long_double_t
    wcstold.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.POINTER(ctypes.c_int32))]
except AttributeError:
    pass
try:
    wcstol = _libraries['FIXME_STUB'].wcstol
    wcstol.restype = ctypes.c_int64
    wcstol.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.POINTER(ctypes.c_int32)), ctypes.c_int32]
except AttributeError:
    pass
try:
    wcstoul = _libraries['FIXME_STUB'].wcstoul
    wcstoul.restype = ctypes.c_uint64
    wcstoul.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.POINTER(ctypes.c_int32)), ctypes.c_int32]
except AttributeError:
    pass
try:
    wcstoll = _libraries['FIXME_STUB'].wcstoll
    wcstoll.restype = ctypes.c_int64
    wcstoll.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.POINTER(ctypes.c_int32)), ctypes.c_int32]
except AttributeError:
    pass
try:
    wcstoull = _libraries['FIXME_STUB'].wcstoull
    wcstoull.restype = ctypes.c_uint64
    wcstoull.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.POINTER(ctypes.c_int32)), ctypes.c_int32]
except AttributeError:
    pass
try:
    wcpcpy = _libraries['FIXME_STUB'].wcpcpy
    wcpcpy.restype = ctypes.POINTER(ctypes.c_int32)
    wcpcpy.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    wcpncpy = _libraries['FIXME_STUB'].wcpncpy
    wcpncpy.restype = ctypes.POINTER(ctypes.c_int32)
    wcpncpy.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32), size_t]
except AttributeError:
    pass
try:
    open_wmemstream = _libraries['FIXME_STUB'].open_wmemstream
    open_wmemstream.restype = ctypes.POINTER(struct__IO_FILE)
    open_wmemstream.argtypes = [ctypes.POINTER(ctypes.POINTER(ctypes.c_int32)), ctypes.POINTER(ctypes.c_uint64)]
except AttributeError:
    pass
try:
    fwide = _libraries['FIXME_STUB'].fwide
    fwide.restype = ctypes.c_int32
    fwide.argtypes = [ctypes.POINTER(struct__IO_FILE), ctypes.c_int32]
except AttributeError:
    pass
try:
    fwprintf = _libraries['FIXME_STUB'].fwprintf
    fwprintf.restype = ctypes.c_int32
    fwprintf.argtypes = [ctypes.POINTER(struct__IO_FILE), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    wprintf = _libraries['FIXME_STUB'].wprintf
    wprintf.restype = ctypes.c_int32
    wprintf.argtypes = [ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    swprintf = _libraries['FIXME_STUB'].swprintf
    swprintf.restype = ctypes.c_int32
    swprintf.argtypes = [ctypes.POINTER(ctypes.c_int32), size_t, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    vfwprintf = _libraries['FIXME_STUB'].vfwprintf
    vfwprintf.restype = ctypes.c_int32
    vfwprintf.argtypes = [ctypes.POINTER(struct__IO_FILE), ctypes.POINTER(ctypes.c_int32), __gnuc_va_list]
except AttributeError:
    pass
try:
    vwprintf = _libraries['FIXME_STUB'].vwprintf
    vwprintf.restype = ctypes.c_int32
    vwprintf.argtypes = [ctypes.POINTER(ctypes.c_int32), __gnuc_va_list]
except AttributeError:
    pass
try:
    vswprintf = _libraries['FIXME_STUB'].vswprintf
    vswprintf.restype = ctypes.c_int32
    vswprintf.argtypes = [ctypes.POINTER(ctypes.c_int32), size_t, ctypes.POINTER(ctypes.c_int32), __gnuc_va_list]
except AttributeError:
    pass
try:
    fwscanf = _libraries['FIXME_STUB'].fwscanf
    fwscanf.restype = ctypes.c_int32
    fwscanf.argtypes = [ctypes.POINTER(struct__IO_FILE), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    wscanf = _libraries['FIXME_STUB'].wscanf
    wscanf.restype = ctypes.c_int32
    wscanf.argtypes = [ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    swscanf = _libraries['FIXME_STUB'].swscanf
    swscanf.restype = ctypes.c_int32
    swscanf.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    vfwscanf = _libraries['FIXME_STUB'].vfwscanf
    vfwscanf.restype = ctypes.c_int32
    vfwscanf.argtypes = [ctypes.POINTER(struct__IO_FILE), ctypes.POINTER(ctypes.c_int32), __gnuc_va_list]
except AttributeError:
    pass
try:
    vwscanf = _libraries['FIXME_STUB'].vwscanf
    vwscanf.restype = ctypes.c_int32
    vwscanf.argtypes = [ctypes.POINTER(ctypes.c_int32), __gnuc_va_list]
except AttributeError:
    pass
try:
    vswscanf = _libraries['FIXME_STUB'].vswscanf
    vswscanf.restype = ctypes.c_int32
    vswscanf.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32), __gnuc_va_list]
except AttributeError:
    pass
try:
    fgetwc = _libraries['FIXME_STUB'].fgetwc
    fgetwc.restype = wint_t
    fgetwc.argtypes = [ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    getwc = _libraries['FIXME_STUB'].getwc
    getwc.restype = wint_t
    getwc.argtypes = [ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    getwchar = _libraries['FIXME_STUB'].getwchar
    getwchar.restype = wint_t
    getwchar.argtypes = []
except AttributeError:
    pass
try:
    fputwc = _libraries['FIXME_STUB'].fputwc
    fputwc.restype = wint_t
    fputwc.argtypes = [wchar_t, ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    putwc = _libraries['FIXME_STUB'].putwc
    putwc.restype = wint_t
    putwc.argtypes = [wchar_t, ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    putwchar = _libraries['FIXME_STUB'].putwchar
    putwchar.restype = wint_t
    putwchar.argtypes = [wchar_t]
except AttributeError:
    pass
try:
    fgetws = _libraries['FIXME_STUB'].fgetws
    fgetws.restype = ctypes.POINTER(ctypes.c_int32)
    fgetws.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.c_int32, ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    fputws = _libraries['FIXME_STUB'].fputws
    fputws.restype = ctypes.c_int32
    fputws.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    ungetwc = _libraries['FIXME_STUB'].ungetwc
    ungetwc.restype = wint_t
    ungetwc.argtypes = [wint_t, ctypes.POINTER(struct__IO_FILE)]
except AttributeError:
    pass
try:
    wcsftime = _libraries['FIXME_STUB'].wcsftime
    wcsftime.restype = size_t
    wcsftime.argtypes = [ctypes.POINTER(ctypes.c_int32), size_t, ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(struct_tm)]
except AttributeError:
    pass

# values for enumeration 'RStrEnc'
RStrEnc__enumvalues = {
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
RStrEnc = ctypes.c_uint32 # enum
class struct_RString(Structure):
    pass

struct_RString._pack_ = 1 # source:False
struct_RString._fields_ = [
    ('str', ctypes.POINTER(ctypes.c_char)),
    ('buf', ctypes.c_char * 64),
    ('len', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('ptr', ctypes.POINTER(ctypes.c_char)),
    ('weak', ctypes.c_bool),
    ('PADDING_1', ctypes.c_ubyte * 7),
]

RString = struct_RString
RStrRangeCallback = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.c_int32)
class struct_r_charset_rune_t(Structure):
    pass

struct_r_charset_rune_t._pack_ = 1 # source:False
struct_r_charset_rune_t._fields_ = [
    ('ch', ctypes.POINTER(ctypes.c_ubyte)),
    ('hx', ctypes.POINTER(ctypes.c_ubyte)),
    ('left', ctypes.POINTER(struct_r_charset_rune_t)),
    ('right', ctypes.POINTER(struct_r_charset_rune_t)),
]

RCharsetRune = struct_r_charset_rune_t
class struct_r_charset_t(Structure):
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

RCharset = struct_r_charset_t
try:
    r_charset_new = _libr_util.r_charset_new
    r_charset_new.restype = ctypes.POINTER(struct_r_charset_t)
    r_charset_new.argtypes = []
except AttributeError:
    pass
try:
    r_charset_free = _libr_util.r_charset_free
    r_charset_free.restype = None
    r_charset_free.argtypes = [ctypes.POINTER(struct_r_charset_t)]
except AttributeError:
    pass
try:
    r_charset_rune_new = _libr_util.r_charset_rune_new
    r_charset_rune_new.restype = ctypes.POINTER(struct_r_charset_rune_t)
    r_charset_rune_new.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
except AttributeError:
    pass
try:
    r_charset_rune_free = _libr_util.r_charset_rune_free
    r_charset_rune_free.restype = None
    r_charset_rune_free.argtypes = [ctypes.POINTER(struct_r_charset_rune_t)]
except AttributeError:
    pass
try:
    r_charset_encode_str = _libr_util.r_charset_encode_str
    r_charset_encode_str.restype = size_t
    r_charset_encode_str.argtypes = [ctypes.POINTER(struct_r_charset_t), ctypes.POINTER(ctypes.c_ubyte), size_t, ctypes.POINTER(ctypes.c_ubyte), size_t]
except AttributeError:
    pass
try:
    r_charset_decode_str = _libr_util.r_charset_decode_str
    r_charset_decode_str.restype = size_t
    r_charset_decode_str.argtypes = [ctypes.POINTER(struct_r_charset_t), ctypes.POINTER(ctypes.c_ubyte), size_t, ctypes.POINTER(ctypes.c_ubyte), size_t]
except AttributeError:
    pass
try:
    r_charset_open = _libr_util.r_charset_open
    r_charset_open.restype = ctypes.c_bool
    r_charset_open.argtypes = [ctypes.POINTER(struct_r_charset_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_charset_use = _libr_util.r_charset_use
    r_charset_use.restype = ctypes.c_bool
    r_charset_use.argtypes = [ctypes.POINTER(struct_r_charset_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_charset_list = _libr_util.r_charset_list
    r_charset_list.restype = ctypes.POINTER(struct_r_list_t)
    r_charset_list.argtypes = [ctypes.POINTER(struct_r_charset_t)]
except AttributeError:
    pass
try:
    r_charset_close = _libr_util.r_charset_close
    r_charset_close.restype = None
    r_charset_close.argtypes = [ctypes.POINTER(struct_r_charset_t)]
except AttributeError:
    pass
try:
    add_rune = _libraries['FIXME_STUB'].add_rune
    add_rune.restype = ctypes.POINTER(struct_r_charset_rune_t)
    add_rune.argtypes = [ctypes.POINTER(struct_r_charset_rune_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
except AttributeError:
    pass
try:
    search_from_hex = _libraries['FIXME_STUB'].search_from_hex
    search_from_hex.restype = ctypes.POINTER(struct_r_charset_rune_t)
    search_from_hex.argtypes = [ctypes.POINTER(struct_r_charset_rune_t), ctypes.POINTER(ctypes.c_ubyte)]
except AttributeError:
    pass
try:
    search_from_char = _libraries['FIXME_STUB'].search_from_char
    search_from_char.restype = ctypes.POINTER(struct_r_charset_rune_t)
    search_from_char.argtypes = [ctypes.POINTER(struct_r_charset_rune_t), ctypes.POINTER(ctypes.c_ubyte)]
except AttributeError:
    pass
try:
    r_str_repeat = _libr_util.r_str_repeat
    r_str_repeat.restype = ctypes.POINTER(ctypes.c_char)
    r_str_repeat.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_pad = _libr_util.r_str_pad
    r_str_pad.restype = ctypes.POINTER(ctypes.c_char)
    r_str_pad.argtypes = [ctypes.c_char, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_rstr = _libr_util.r_str_rstr
    r_str_rstr.restype = ctypes.POINTER(ctypes.c_char)
    r_str_rstr.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_strstr_ansi = _libr_util.r_strstr_ansi
    r_strstr_ansi.restype = ctypes.POINTER(ctypes.c_char)
    r_strstr_ansi.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_rchr = _libr_util.r_str_rchr
    r_str_rchr.restype = ctypes.POINTER(ctypes.c_char)
    r_str_rchr.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_closer_chr = _libr_util.r_str_closer_chr
    r_str_closer_chr.restype = ctypes.POINTER(ctypes.c_char)
    r_str_closer_chr.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_bounds = _libr_util.r_str_bounds
    r_str_bounds.restype = ctypes.c_int32
    r_str_bounds.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_str_eq = _libr_util.r_str_eq
    r_str_eq.restype = ctypes.c_bool
    r_str_eq.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_eqi = _libr_util.r_str_eqi
    r_str_eqi.restype = ctypes.c_bool
    r_str_eqi.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_crop = _libr_util.r_str_crop
    r_str_crop.restype = ctypes.POINTER(ctypes.c_char)
    r_str_crop.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
except AttributeError:
    pass
try:
    r_str_scale = _libr_util.r_str_scale
    r_str_scale.restype = ctypes.POINTER(ctypes.c_char)
    r_str_scale.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_range_in = _libr_util.r_str_range_in
    r_str_range_in.restype = ctypes.c_bool
    r_str_range_in.argtypes = [ctypes.POINTER(ctypes.c_char), uint64_t]
except AttributeError:
    pass
try:
    r_str_size = _libr_util.r_str_size
    r_str_size.restype = ctypes.c_int32
    r_str_size.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_str_len_utf8 = _libr_util.r_str_len_utf8
    r_str_len_utf8.restype = size_t
    r_str_len_utf8.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_len_utf8_ansi = _libr_util.r_str_len_utf8_ansi
    r_str_len_utf8_ansi.restype = size_t
    r_str_len_utf8_ansi.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_len_utf8char = _libr_util.r_str_len_utf8char
    r_str_len_utf8char.restype = size_t
    r_str_len_utf8char.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_utf8_charsize = _libr_util.r_str_utf8_charsize
    r_str_utf8_charsize.restype = size_t
    r_str_utf8_charsize.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_utf8_charsize_prev = _libr_util.r_str_utf8_charsize_prev
    r_str_utf8_charsize_prev.restype = size_t
    r_str_utf8_charsize_prev.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_utf8_charsize_last = _libr_util.r_str_utf8_charsize_last
    r_str_utf8_charsize_last.restype = size_t
    r_str_utf8_charsize_last.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_filter_zeroline = _libr_util.r_str_filter_zeroline
    r_str_filter_zeroline.restype = None
    r_str_filter_zeroline.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_utf8_codepoint = _libr_util.r_str_utf8_codepoint
    r_str_utf8_codepoint.restype = size_t
    r_str_utf8_codepoint.argtypes = [ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    r_str_char_fullwidth = _libr_util.r_str_char_fullwidth
    r_str_char_fullwidth.restype = ctypes.c_bool
    r_str_char_fullwidth.argtypes = [ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    r_str_write = _libr_util.r_str_write
    r_str_write.restype = ctypes.c_int32
    r_str_write.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_ncpy = _libr_util.r_str_ncpy
    r_str_ncpy.restype = size_t
    r_str_ncpy.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    r_str_sanitize = _libr_util.r_str_sanitize
    r_str_sanitize.restype = None
    r_str_sanitize.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_sanitize_sdb_key = _libr_util.r_str_sanitize_sdb_key
    r_str_sanitize_sdb_key.restype = ctypes.POINTER(ctypes.c_char)
    r_str_sanitize_sdb_key.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_casestr = _libr_util.r_str_casestr
    r_str_casestr.restype = ctypes.POINTER(ctypes.c_char)
    r_str_casestr.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_firstbut = _libr_util.r_str_firstbut
    r_str_firstbut.restype = ctypes.POINTER(ctypes.c_char)
    r_str_firstbut.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_char, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_firstbut_escape = _libr_util.r_str_firstbut_escape
    r_str_firstbut_escape.restype = ctypes.POINTER(ctypes.c_char)
    r_str_firstbut_escape.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_char, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_lastbut = _libr_util.r_str_lastbut
    r_str_lastbut.restype = ctypes.POINTER(ctypes.c_char)
    r_str_lastbut.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_char, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_split = _libr_util.r_str_split
    r_str_split.restype = ctypes.c_int32
    r_str_split.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_char]
except AttributeError:
    pass
try:
    r_str_split_list = _libr_util.r_str_split_list
    r_str_split_list.restype = ctypes.POINTER(struct_r_list_t)
    r_str_split_list.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_split_duplist = _libr_util.r_str_split_duplist
    r_str_split_duplist.restype = ctypes.POINTER(struct_r_list_t)
    r_str_split_duplist.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_bool]
except AttributeError:
    pass
try:
    r_str_split_lines = _libr_util.r_str_split_lines
    r_str_split_lines.restype = ctypes.POINTER(ctypes.c_uint64)
    r_str_split_lines.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_uint64)]
except AttributeError:
    pass
try:
    r_str_replace = _libr_util.r_str_replace
    r_str_replace.restype = ctypes.POINTER(ctypes.c_char)
    r_str_replace.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_replace_all = _libr_util.r_str_replace_all
    r_str_replace_all.restype = ctypes.POINTER(ctypes.c_char)
    r_str_replace_all.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_replace_icase = _libr_util.r_str_replace_icase
    r_str_replace_icase.restype = ctypes.POINTER(ctypes.c_char)
    r_str_replace_icase.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_replace_in = _libr_util.r_str_replace_in
    r_str_replace_in.restype = ctypes.POINTER(ctypes.c_char)
    r_str_replace_in.argtypes = [ctypes.POINTER(ctypes.c_char), uint32_t, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_replace_thunked = _libr_util.r_str_replace_thunked
    r_str_replace_thunked.restype = ctypes.POINTER(ctypes.c_char)
    r_str_replace_thunked.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_int32), ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_bits = _libr_util.r_str_bits
    r_str_bits.restype = ctypes.c_int32
    r_str_bits.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_bits64 = _libr_util.r_str_bits64
    r_str_bits64.restype = ctypes.c_int32
    r_str_bits64.argtypes = [ctypes.POINTER(ctypes.c_char), uint64_t]
except AttributeError:
    pass
try:
    r_str_bits_from_string = _libr_util.r_str_bits_from_string
    r_str_bits_from_string.restype = uint64_t
    r_str_bits_from_string.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_rwx = _libr_util.r_str_rwx
    r_str_rwx.restype = ctypes.c_int32
    r_str_rwx.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_replace_ch = _libr_util.r_str_replace_ch
    r_str_replace_ch.restype = ctypes.c_int32
    r_str_replace_ch.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_char, ctypes.c_char, ctypes.c_bool]
except AttributeError:
    pass
try:
    r_str_replace_char = _libr_util.r_str_replace_char
    r_str_replace_char.restype = ctypes.c_int32
    r_str_replace_char.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_replace_char_once = _libr_util.r_str_replace_char_once
    r_str_replace_char_once.restype = ctypes.c_int32
    r_str_replace_char_once.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_remove_char = _libr_util.r_str_remove_char
    r_str_remove_char.restype = None
    r_str_remove_char.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_char]
except AttributeError:
    pass
try:
    r_str_rwx_i = _libr_util.r_str_rwx_i
    r_str_rwx_i.restype = ctypes.POINTER(ctypes.c_char)
    r_str_rwx_i.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_fmtargs = _libr_util.r_str_fmtargs
    r_str_fmtargs.restype = ctypes.c_int32
    r_str_fmtargs.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_arg_escape = _libr_util.r_str_arg_escape
    r_str_arg_escape.restype = ctypes.POINTER(ctypes.c_char)
    r_str_arg_escape.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_arg_unescape = _libr_util.r_str_arg_unescape
    r_str_arg_unescape.restype = ctypes.c_int32
    r_str_arg_unescape.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_argv = _libr_util.r_str_argv
    r_str_argv.restype = ctypes.POINTER(ctypes.POINTER(ctypes.c_char))
    r_str_argv.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_str_argv_free = _libr_util.r_str_argv_free
    r_str_argv_free.restype = None
    r_str_argv_free.argtypes = [ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
except AttributeError:
    pass
try:
    r_str_new = _libr_util.r_str_new
    r_str_new.restype = ctypes.POINTER(ctypes.c_char)
    r_str_new.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_fixspaces = _libr_util.r_str_fixspaces
    r_str_fixspaces.restype = None
    r_str_fixspaces.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_snprintf = _libr_util.r_snprintf
    r_snprintf.restype = ctypes.c_int32
    r_snprintf.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_is_ascii = _libr_util.r_str_is_ascii
    r_str_is_ascii.restype = ctypes.c_bool
    r_str_is_ascii.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_nextword = _libr_util.r_str_nextword
    r_str_nextword.restype = ctypes.POINTER(ctypes.c_char)
    r_str_nextword.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_char]
except AttributeError:
    pass
try:
    r_str_is_printable = _libr_util.r_str_is_printable
    r_str_is_printable.restype = ctypes.c_bool
    r_str_is_printable.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_is_printable_limited = _libr_util.r_str_is_printable_limited
    r_str_is_printable_limited.restype = ctypes.c_bool
    r_str_is_printable_limited.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_is_printable_incl_newlines = _libr_util.r_str_is_printable_incl_newlines
    r_str_is_printable_incl_newlines.restype = ctypes.c_bool
    r_str_is_printable_incl_newlines.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_appendlen = _libr_util.r_str_appendlen
    r_str_appendlen.restype = ctypes.POINTER(ctypes.c_char)
    r_str_appendlen.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_newf = _libr_util.r_str_newf
    r_str_newf.restype = ctypes.POINTER(ctypes.c_char)
    r_str_newf.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_newvf = _libr_util.r_str_newvf
    r_str_newvf.restype = ctypes.POINTER(ctypes.c_char)
    r_str_newvf.argtypes = [ctypes.POINTER(ctypes.c_char), va_list]
except AttributeError:
    pass
try:
    r_str_distance = _libr_util.r_str_distance
    r_str_distance.restype = ctypes.c_int32
    r_str_distance.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_newlen = _libr_util.r_str_newlen
    r_str_newlen.restype = ctypes.POINTER(ctypes.c_char)
    r_str_newlen.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_sysbits = _libr_util.r_str_sysbits
    r_str_sysbits.restype = ctypes.POINTER(ctypes.c_char)
    r_str_sysbits.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_trunc_ellipsis = _libr_util.r_str_trunc_ellipsis
    r_str_trunc_ellipsis.restype = ctypes.POINTER(ctypes.c_char)
    r_str_trunc_ellipsis.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_bool = _libr_util.r_str_bool
    r_str_bool.restype = ctypes.POINTER(ctypes.c_char)
    r_str_bool.argtypes = [ctypes.c_bool]
except AttributeError:
    pass
try:
    r_str_is_true = _libr_util.r_str_is_true
    r_str_is_true.restype = ctypes.c_bool
    r_str_is_true.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_is_false = _libr_util.r_str_is_false
    r_str_is_false.restype = ctypes.c_bool
    r_str_is_false.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_is_bool = _libr_util.r_str_is_bool
    r_str_is_bool.restype = ctypes.c_bool
    r_str_is_bool.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_ansi_chrn = _libr_util.r_str_ansi_chrn
    r_str_ansi_chrn.restype = ctypes.POINTER(ctypes.c_char)
    r_str_ansi_chrn.argtypes = [ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    r_str_ansi_strip = _libr_util.r_str_ansi_strip
    r_str_ansi_strip.restype = size_t
    r_str_ansi_strip.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_ansi_len = _libr_util.r_str_ansi_len
    r_str_ansi_len.restype = size_t
    r_str_ansi_len.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_ansi_nlen = _libr_util.r_str_ansi_nlen
    r_str_ansi_nlen.restype = size_t
    r_str_ansi_nlen.argtypes = [ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    r_str_ansi_trim = _libr_util.r_str_ansi_trim
    r_str_ansi_trim.restype = ctypes.c_int32
    r_str_ansi_trim.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_ansi_filter = _libr_util.r_str_ansi_filter
    r_str_ansi_filter.restype = ctypes.c_int32
    r_str_ansi_filter.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.POINTER(ctypes.POINTER(ctypes.c_int32)), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_ansi_crop = _libr_util.r_str_ansi_crop
    r_str_ansi_crop.restype = ctypes.POINTER(ctypes.c_char)
    r_str_ansi_crop.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
except AttributeError:
    pass
try:
    r_str_word_count = _libr_util.r_str_word_count
    r_str_word_count.restype = ctypes.c_int32
    r_str_word_count.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_char_count = _libr_util.r_str_char_count
    r_str_char_count.restype = size_t
    r_str_char_count.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_char]
except AttributeError:
    pass
try:
    r_str_word_get0set = _libr_util.r_str_word_get0set
    r_str_word_get0set.restype = ctypes.POINTER(ctypes.c_char)
    r_str_word_get0set.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_str_insert = _libr_util.r_str_insert
    r_str_insert.restype = ctypes.POINTER(ctypes.c_char)
    r_str_insert.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_word_set0 = _libr_util.r_str_word_set0
    r_str_word_set0.restype = ctypes.c_int32
    r_str_word_set0.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_word_set0_stack = _libr_util.r_str_word_set0_stack
    r_str_word_set0_stack.restype = ctypes.c_int32
    r_str_word_set0_stack.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_word_get0 = _libr_util.r_str_word_get0
    r_str_word_get0.restype = ctypes.POINTER(ctypes.c_char)
    r_str_word_get0.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_word_get_first = _libr_util.r_str_word_get_first
    r_str_word_get_first.restype = ctypes.POINTER(ctypes.c_char)
    r_str_word_get_first.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_trim = _libr_util.r_str_trim
    r_str_trim.restype = None
    r_str_trim.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_ntrim = _libr_util.r_str_ntrim
    r_str_ntrim.restype = ctypes.c_int32
    r_str_ntrim.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_wrap = _libr_util.r_str_wrap
    r_str_wrap.restype = ctypes.POINTER(ctypes.c_char)
    r_str_wrap.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_trim_dup = _libr_util.r_str_trim_dup
    r_str_trim_dup.restype = ctypes.POINTER(ctypes.c_char)
    r_str_trim_dup.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_trim_lines = _libr_util.r_str_trim_lines
    r_str_trim_lines.restype = ctypes.POINTER(ctypes.c_char)
    r_str_trim_lines.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_trim_head = _libr_util.r_str_trim_head
    r_str_trim_head.restype = None
    r_str_trim_head.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_trim_head_ro = _libr_util.r_str_trim_head_ro
    r_str_trim_head_ro.restype = ctypes.POINTER(ctypes.c_char)
    r_str_trim_head_ro.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_trim_head_wp = _libr_util.r_str_trim_head_wp
    r_str_trim_head_wp.restype = ctypes.POINTER(ctypes.c_char)
    r_str_trim_head_wp.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_trim_tail = _libr_util.r_str_trim_tail
    r_str_trim_tail.restype = None
    r_str_trim_tail.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_trim_args = _libr_util.r_str_trim_args
    r_str_trim_args.restype = None
    r_str_trim_args.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_hash = _libr_util.r_str_hash
    r_str_hash.restype = uint32_t
    r_str_hash.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_hash64 = _libr_util.r_str_hash64
    r_str_hash64.restype = uint64_t
    r_str_hash64.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_trim_nc = _libr_util.r_str_trim_nc
    r_str_trim_nc.restype = ctypes.POINTER(ctypes.c_char)
    r_str_trim_nc.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_nstr = _libr_util.r_str_nstr
    r_str_nstr.restype = ctypes.POINTER(ctypes.c_char)
    r_str_nstr.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_lchr = _libr_util.r_str_lchr
    r_str_lchr.restype = ctypes.POINTER(ctypes.c_char)
    r_str_lchr.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_char]
except AttributeError:
    pass
try:
    r_sub_str_lchr = _libr_util.r_sub_str_lchr
    r_sub_str_lchr.restype = ctypes.POINTER(ctypes.c_char)
    r_sub_str_lchr.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32, ctypes.c_char]
except AttributeError:
    pass
try:
    r_sub_str_rchr = _libr_util.r_sub_str_rchr
    r_sub_str_rchr.restype = ctypes.POINTER(ctypes.c_char)
    r_sub_str_rchr.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32, ctypes.c_char]
except AttributeError:
    pass
try:
    r_str_ichr = _libr_util.r_str_ichr
    r_str_ichr.restype = ctypes.POINTER(ctypes.c_char)
    r_str_ichr.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_char]
except AttributeError:
    pass
try:
    r_str_ccmp = _libr_util.r_str_ccmp
    r_str_ccmp.restype = ctypes.c_bool
    r_str_ccmp.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_cmp_list = _libr_util.r_str_cmp_list
    r_str_cmp_list.restype = ctypes.c_bool
    r_str_cmp_list.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_char]
except AttributeError:
    pass
try:
    r_str_cmp = _libr_util.r_str_cmp
    r_str_cmp.restype = ctypes.c_int32
    r_str_cmp.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_casecmp = _libr_util.r_str_casecmp
    r_str_casecmp.restype = ctypes.c_int32
    r_str_casecmp.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_ncasecmp = _libr_util.r_str_ncasecmp
    r_str_ncasecmp.restype = ctypes.c_int32
    r_str_ncasecmp.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    r_str_ccpy = _libr_util.r_str_ccpy
    r_str_ccpy.restype = ctypes.c_int32
    r_str_ccpy.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_get = _libr_util.r_str_get
    r_str_get.restype = ctypes.POINTER(ctypes.c_char)
    r_str_get.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_get_fail = _libr_util.r_str_get_fail
    r_str_get_fail.restype = ctypes.POINTER(ctypes.c_char)
    r_str_get_fail.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_getf = _libr_util.r_str_getf
    r_str_getf.restype = ctypes.POINTER(ctypes.c_char)
    r_str_getf.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_ndup = _libr_util.r_str_ndup
    r_str_ndup.restype = ctypes.POINTER(ctypes.c_char)
    r_str_ndup.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_dup = _libr_util.r_str_dup
    r_str_dup.restype = ctypes.POINTER(ctypes.c_char)
    r_str_dup.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_inject = _libraries['FIXME_STUB'].r_str_inject
    r_str_inject.restype = ctypes.c_int32
    r_str_inject.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_delta = _libr_util.r_str_delta
    r_str_delta.restype = ctypes.c_int32
    r_str_delta.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_char, ctypes.c_char]
except AttributeError:
    pass
try:
    r_str_filter = _libr_util.r_str_filter
    r_str_filter.restype = None
    r_str_filter.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_tok = _libr_util.r_str_tok
    r_str_tok.restype = ctypes.POINTER(ctypes.c_char)
    r_str_tok.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_char, size_t]
except AttributeError:
    pass
try:
    r_str_mb_to_wc = _libr_util.r_str_mb_to_wc
    r_str_mb_to_wc.restype = ctypes.POINTER(ctypes.c_int32)
    r_str_mb_to_wc.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_wc_to_mb = _libr_util.r_str_wc_to_mb
    r_str_wc_to_mb.restype = ctypes.POINTER(ctypes.c_char)
    r_str_wc_to_mb.argtypes = [ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_str_mb_to_wc_l = _libr_util.r_str_mb_to_wc_l
    r_str_mb_to_wc_l.restype = ctypes.POINTER(ctypes.c_int32)
    r_str_mb_to_wc_l.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_wc_to_mb_l = _libr_util.r_str_wc_to_mb_l
    r_str_wc_to_mb_l.restype = ctypes.POINTER(ctypes.c_char)
    r_str_wc_to_mb_l.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_str_xy = _libr_util.r_str_str_xy
    r_str_str_xy.restype = ctypes.POINTER(ctypes.c_char)
    r_str_str_xy.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
str_operation = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_char))
try:
    r_str_do_until_token = _libr_util.r_str_do_until_token
    r_str_do_until_token.restype = ctypes.c_int32
    r_str_do_until_token.argtypes = [str_operation, ctypes.POINTER(ctypes.c_char), ctypes.c_char]
except AttributeError:
    pass
try:
    r_str_reverse = _libr_util.r_str_reverse
    r_str_reverse.restype = None
    r_str_reverse.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_re_match = _libraries['FIXME_STUB'].r_str_re_match
    r_str_re_match.restype = ctypes.c_int32
    r_str_re_match.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_re_replace = _libraries['FIXME_STUB'].r_str_re_replace
    r_str_re_replace.restype = ctypes.c_int32
    r_str_re_replace.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_path_unescape = _libr_util.r_str_path_unescape
    r_str_path_unescape.restype = ctypes.c_int32
    r_str_path_unescape.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_path_escape = _libr_util.r_str_path_escape
    r_str_path_escape.restype = ctypes.POINTER(ctypes.c_char)
    r_str_path_escape.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_unescape = _libr_util.r_str_unescape
    r_str_unescape.restype = ctypes.c_int32
    r_str_unescape.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_sanitize_r2 = _libr_util.r_str_sanitize_r2
    r_str_sanitize_r2.restype = ctypes.POINTER(ctypes.c_char)
    r_str_sanitize_r2.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_escape_raw = _libr_util.r_str_escape_raw
    r_str_escape_raw.restype = ctypes.POINTER(ctypes.c_char)
    r_str_escape_raw.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_escape = _libr_util.r_str_escape
    r_str_escape.restype = ctypes.POINTER(ctypes.c_char)
    r_str_escape.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_escape_sh = _libr_util.r_str_escape_sh
    r_str_escape_sh.restype = ctypes.POINTER(ctypes.c_char)
    r_str_escape_sh.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_escape_sql = _libr_util.r_str_escape_sql
    r_str_escape_sql.restype = ctypes.POINTER(ctypes.c_char)
    r_str_escape_sql.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_escape_dot = _libr_util.r_str_escape_dot
    r_str_escape_dot.restype = ctypes.POINTER(ctypes.c_char)
    r_str_escape_dot.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_escape_latin1 = _libr_util.r_str_escape_latin1
    r_str_escape_latin1.restype = ctypes.POINTER(ctypes.c_char)
    r_str_escape_latin1.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_bool, ctypes.c_bool, ctypes.c_bool]
except AttributeError:
    pass
try:
    r_str_escape_utf8 = _libr_util.r_str_escape_utf8
    r_str_escape_utf8.restype = ctypes.POINTER(ctypes.c_char)
    r_str_escape_utf8.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_bool, ctypes.c_bool]
except AttributeError:
    pass
try:
    r_str_escape_utf8_keep_printable = _libr_util.r_str_escape_utf8_keep_printable
    r_str_escape_utf8_keep_printable.restype = ctypes.POINTER(ctypes.c_char)
    r_str_escape_utf8_keep_printable.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_bool, ctypes.c_bool]
except AttributeError:
    pass
try:
    r_str_escape_utf16le = _libr_util.r_str_escape_utf16le
    r_str_escape_utf16le.restype = ctypes.POINTER(ctypes.c_char)
    r_str_escape_utf16le.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_bool, ctypes.c_bool]
except AttributeError:
    pass
try:
    r_str_escape_utf32le = _libr_util.r_str_escape_utf32le
    r_str_escape_utf32le.restype = ctypes.POINTER(ctypes.c_char)
    r_str_escape_utf32le.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_bool, ctypes.c_bool]
except AttributeError:
    pass
try:
    r_str_escape_utf16be = _libr_util.r_str_escape_utf16be
    r_str_escape_utf16be.restype = ctypes.POINTER(ctypes.c_char)
    r_str_escape_utf16be.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_bool, ctypes.c_bool]
except AttributeError:
    pass
try:
    r_str_escape_utf32be = _libr_util.r_str_escape_utf32be
    r_str_escape_utf32be.restype = ctypes.POINTER(ctypes.c_char)
    r_str_escape_utf32be.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_bool, ctypes.c_bool]
except AttributeError:
    pass
try:
    r_str_byte_escape = _libr_util.r_str_byte_escape
    r_str_byte_escape.restype = None
    r_str_byte_escape.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.c_int32, ctypes.c_bool, ctypes.c_bool]
except AttributeError:
    pass
try:
    r_str_format_msvc_argv = _libr_util.r_str_format_msvc_argv
    r_str_format_msvc_argv.restype = ctypes.POINTER(ctypes.c_char)
    r_str_format_msvc_argv.argtypes = [size_t, ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
except AttributeError:
    pass
try:
    r_str_uri_decode = _libr_util.r_str_uri_decode
    r_str_uri_decode.restype = None
    r_str_uri_decode.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_uri_encode = _libr_util.r_str_uri_encode
    r_str_uri_encode.restype = ctypes.POINTER(ctypes.c_char)
    r_str_uri_encode.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_utf16_decode = _libr_util.r_str_utf16_decode
    r_str_utf16_decode.restype = ctypes.POINTER(ctypes.c_char)
    r_str_utf16_decode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_utf16_to_utf8 = _libr_util.r_str_utf16_to_utf8
    r_str_utf16_to_utf8.restype = ctypes.c_int32
    r_str_utf16_to_utf8.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_utf16_encode = _libr_util.r_str_utf16_encode
    r_str_utf16_encode.restype = ctypes.POINTER(ctypes.c_char)
    r_str_utf16_encode.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_escape_utf8_for_json = _libr_util.r_str_escape_utf8_for_json
    r_str_escape_utf8_for_json.restype = ctypes.POINTER(ctypes.c_char)
    r_str_escape_utf8_for_json.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_escape_utf8_for_json_strip = _libr_util.r_str_escape_utf8_for_json_strip
    r_str_escape_utf8_for_json_strip.restype = ctypes.POINTER(ctypes.c_char)
    r_str_escape_utf8_for_json_strip.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_encoded_json = _libr_util.r_str_encoded_json
    r_str_encoded_json.restype = ctypes.POINTER(ctypes.c_char)
    r_str_encoded_json.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_home = _libr_util.r_str_home
    r_str_home.restype = ctypes.POINTER(ctypes.c_char)
    r_str_home.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_r2_prefix = _libr_util.r_str_r2_prefix
    r_str_r2_prefix.restype = ctypes.POINTER(ctypes.c_char)
    r_str_r2_prefix.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_nlen = _libr_util.r_str_nlen
    r_str_nlen.restype = size_t
    r_str_nlen.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_nlen_w = _libr_util.r_str_nlen_w
    r_str_nlen_w.restype = size_t
    r_str_nlen_w.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_wstr_clen = _libr_util.r_wstr_clen
    r_wstr_clen.restype = size_t
    r_wstr_clen.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_prepend = _libr_util.r_str_prepend
    r_str_prepend.restype = ctypes.POINTER(ctypes.c_char)
    r_str_prepend.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_prefix_all = _libr_util.r_str_prefix_all
    r_str_prefix_all.restype = ctypes.POINTER(ctypes.c_char)
    r_str_prefix_all.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_append = _libr_util.r_str_append
    r_str_append.restype = ctypes.POINTER(ctypes.c_char)
    r_str_append.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_append_owned = _libr_util.r_str_append_owned
    r_str_append_owned.restype = ctypes.POINTER(ctypes.c_char)
    r_str_append_owned.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_appendf = _libr_util.r_str_appendf
    r_str_appendf.restype = ctypes.POINTER(ctypes.c_char)
    r_str_appendf.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_appendch = _libr_util.r_str_appendch
    r_str_appendch.restype = ctypes.POINTER(ctypes.c_char)
    r_str_appendch.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_char]
except AttributeError:
    pass
try:
    r_str_case = _libr_util.r_str_case
    r_str_case.restype = None
    r_str_case.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_bool]
except AttributeError:
    pass
try:
    r_str_trim_path = _libr_util.r_str_trim_path
    r_str_trim_path.restype = None
    r_str_trim_path.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_contains_macro = _libr_util.r_str_contains_macro
    r_str_contains_macro.restype = uint8_t
    r_str_contains_macro.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_truncate_cmd = _libr_util.r_str_truncate_cmd
    r_str_truncate_cmd.restype = None
    r_str_truncate_cmd.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_glob = _libr_util.r_str_glob
    r_str_glob.restype = ctypes.c_bool
    r_str_glob.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_binstr2bin = _libr_util.r_str_binstr2bin
    r_str_binstr2bin.restype = ctypes.c_int32
    r_str_binstr2bin.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_between = _libr_util.r_str_between
    r_str_between.restype = ctypes.POINTER(ctypes.c_char)
    r_str_between.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_startswith = _libr_util.r_str_startswith
    r_str_startswith.restype = ctypes.c_bool
    r_str_startswith.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_startswith_inline = _libraries['FIXME_STUB'].r_str_startswith_inline
    r_str_startswith_inline.restype = ctypes.c_bool
    r_str_startswith_inline.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_skip_prefix = _libraries['FIXME_STUB'].r_str_skip_prefix
    r_str_skip_prefix.restype = ctypes.POINTER(ctypes.c_char)
    r_str_skip_prefix.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_endswith = _libr_util.r_str_endswith
    r_str_endswith.restype = ctypes.c_bool
    r_str_endswith.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_isnumber = _libr_util.r_str_isnumber
    r_str_isnumber.restype = ctypes.c_bool
    r_str_isnumber.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_last = _libr_util.r_str_last
    r_str_last.restype = ctypes.POINTER(ctypes.c_char)
    r_str_last.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_highlight = _libr_util.r_str_highlight
    r_str_highlight.restype = ctypes.POINTER(ctypes.c_char)
    r_str_highlight.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_qrcode_gen = _libr_util.r_qrcode_gen
    r_qrcode_gen.restype = ctypes.POINTER(ctypes.c_char)
    r_qrcode_gen.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.c_bool, ctypes.c_bool]
except AttributeError:
    pass
try:
    r_str_from_ut64 = _libr_util.r_str_from_ut64
    r_str_from_ut64.restype = ctypes.POINTER(ctypes.c_char)
    r_str_from_ut64.argtypes = [uint64_t]
except AttributeError:
    pass
try:
    r_str_stripLine = _libr_util.r_str_stripLine
    r_str_stripLine.restype = None
    r_str_stripLine.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_list_join = _libr_util.r_str_list_join
    r_str_list_join.restype = ctypes.POINTER(ctypes.c_char)
    r_str_list_join.argtypes = [ctypes.POINTER(struct_r_list_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_array_join = _libr_util.r_str_array_join
    r_str_array_join.restype = ctypes.POINTER(ctypes.c_char)
    r_str_array_join.argtypes = [ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), size_t, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_sep = _libr_util.r_str_sep
    r_str_sep.restype = ctypes.POINTER(ctypes.c_char)
    r_str_sep.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_rsep = _libr_util.r_str_rsep
    r_str_rsep.restype = ctypes.POINTER(ctypes.c_char)
    r_str_rsep.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_donut = _libr_util.r_str_donut
    r_str_donut.restype = ctypes.POINTER(ctypes.c_char)
    r_str_donut.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_str_version = _libr_util.r_str_version
    r_str_version.restype = ctypes.POINTER(ctypes.c_char)
    r_str_version.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_str_ss = _libr_util.r_str_ss
    r_str_ss.restype = ctypes.POINTER(ctypes.c_char)
    r_str_ss.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_string_get = _libr_util.r_string_get
    r_string_get.restype = ctypes.POINTER(ctypes.c_char)
    r_string_get.argtypes = [ctypes.POINTER(struct_RString), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_string_new = _libr_util.r_string_new
    r_string_new.restype = RString
    r_string_new.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_string_free = _libr_util.r_string_free
    r_string_free.restype = None
    r_string_free.argtypes = [ctypes.POINTER(struct_RString)]
except AttributeError:
    pass
try:
    r_string_from = _libr_util.r_string_from
    r_string_from.restype = RString
    r_string_from.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_string_unweak = _libr_util.r_string_unweak
    r_string_unweak.restype = None
    r_string_unweak.argtypes = [ctypes.POINTER(struct_RString)]
except AttributeError:
    pass
try:
    r_string_trim = _libr_util.r_string_trim
    r_string_trim.restype = None
    r_string_trim.argtypes = [ctypes.POINTER(struct_RString)]
except AttributeError:
    pass
try:
    r_string_newf = _libr_util.r_string_newf
    r_string_newf.restype = RString
    r_string_newf.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_string_append = _libr_util.r_string_append
    r_string_append.restype = ctypes.c_bool
    r_string_append.argtypes = [ctypes.POINTER(struct_RString), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_string_appendf = _libr_util.r_string_appendf
    r_string_appendf.restype = None
    r_string_appendf.argtypes = [ctypes.POINTER(struct_RString), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
class struct_r_str_constpool_t(Structure):
    pass

struct_r_str_constpool_t._pack_ = 1 # source:False
struct_r_str_constpool_t._fields_ = [
    ('ht', ctypes.POINTER(struct_ht_pp_t)),
]

RStrConstPool = struct_r_str_constpool_t
try:
    r_str_constpool_init = _libr_util.r_str_constpool_init
    r_str_constpool_init.restype = ctypes.c_bool
    r_str_constpool_init.argtypes = [ctypes.POINTER(struct_r_str_constpool_t)]
except AttributeError:
    pass
try:
    r_str_constpool_fini = _libr_util.r_str_constpool_fini
    r_str_constpool_fini.restype = None
    r_str_constpool_fini.argtypes = [ctypes.POINTER(struct_r_str_constpool_t)]
except AttributeError:
    pass
try:
    r_str_constpool_get = _libr_util.r_str_constpool_get
    r_str_constpool_get.restype = ctypes.POINTER(ctypes.c_char)
    r_str_constpool_get.argtypes = [ctypes.POINTER(struct_r_str_constpool_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    __errno_location = _libraries['FIXME_STUB'].__errno_location
    __errno_location.restype = ctypes.POINTER(ctypes.c_int32)
    __errno_location.argtypes = []
except AttributeError:
    pass
class struct_RSysInfo(Structure):
    pass

struct_RSysInfo._pack_ = 1 # source:False
struct_RSysInfo._fields_ = [
    ('sysname', ctypes.POINTER(ctypes.c_char)),
    ('nodename', ctypes.POINTER(ctypes.c_char)),
    ('release', ctypes.POINTER(ctypes.c_char)),
    ('version', ctypes.POINTER(ctypes.c_char)),
    ('machine', ctypes.POINTER(ctypes.c_char)),
]

RSysInfo = struct_RSysInfo
try:
    r_sys_info = _libr_util.r_sys_info
    r_sys_info.restype = ctypes.POINTER(struct_RSysInfo)
    r_sys_info.argtypes = []
except AttributeError:
    pass
try:
    r_sys_info_free = _libr_util.r_sys_info_free
    r_sys_info_free.restype = None
    r_sys_info_free.argtypes = [ctypes.POINTER(struct_RSysInfo)]
except AttributeError:
    pass
try:
    r_sys_sigaction = _libr_util.r_sys_sigaction
    r_sys_sigaction.restype = ctypes.c_int32
    r_sys_sigaction.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.CFUNCTYPE(None, ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_sys_signal = _libr_util.r_sys_signal
    r_sys_signal.restype = ctypes.c_int32
    r_sys_signal.argtypes = [ctypes.c_int32, ctypes.CFUNCTYPE(None, ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_sys_signable = _libr_util.r_sys_signable
    r_sys_signable.restype = None
    r_sys_signable.argtypes = [ctypes.c_bool]
except AttributeError:
    pass
try:
    r_sys_env_init = _libr_util.r_sys_env_init
    r_sys_env_init.restype = None
    r_sys_env_init.argtypes = []
except AttributeError:
    pass
try:
    r_sys_get_environ = _libr_util.r_sys_get_environ
    r_sys_get_environ.restype = ctypes.POINTER(ctypes.POINTER(ctypes.c_char))
    r_sys_get_environ.argtypes = []
except AttributeError:
    pass
try:
    r_sys_set_environ = _libr_util.r_sys_set_environ
    r_sys_set_environ.restype = None
    r_sys_set_environ.argtypes = [ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
except AttributeError:
    pass
try:
    r_sys_fork = _libr_util.r_sys_fork
    r_sys_fork.restype = ctypes.c_int32
    r_sys_fork.argtypes = []
except AttributeError:
    pass
try:
    r_sys_exit = _libr_util.r_sys_exit
    r_sys_exit.restype = None
    r_sys_exit.argtypes = [ctypes.c_int32, ctypes.c_bool]
except AttributeError:
    pass
try:
    r_sys_stop = _libr_util.r_sys_stop
    r_sys_stop.restype = ctypes.c_bool
    r_sys_stop.argtypes = []
except AttributeError:
    pass
try:
    r_sys_pid_to_path = _libr_util.r_sys_pid_to_path
    r_sys_pid_to_path.restype = ctypes.POINTER(ctypes.c_char)
    r_sys_pid_to_path.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_sys_run = _libr_util.r_sys_run
    r_sys_run.restype = ctypes.c_int32
    r_sys_run.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_sys_run_rop = _libr_util.r_sys_run_rop
    r_sys_run_rop.restype = ctypes.c_int32
    r_sys_run_rop.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_sys_getpid = _libr_util.r_sys_getpid
    r_sys_getpid.restype = ctypes.c_int32
    r_sys_getpid.argtypes = []
except AttributeError:
    pass
try:
    r_sys_crash_handler = _libr_util.r_sys_crash_handler
    r_sys_crash_handler.restype = ctypes.c_int32
    r_sys_crash_handler.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_sys_arch_str = _libr_util.r_sys_arch_str
    r_sys_arch_str.restype = ctypes.POINTER(ctypes.c_char)
    r_sys_arch_str.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_sys_arch_id = _libr_util.r_sys_arch_id
    r_sys_arch_id.restype = ctypes.c_int32
    r_sys_arch_id.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_sys_arch_match = _libr_util.r_sys_arch_match
    r_sys_arch_match.restype = ctypes.c_bool
    r_sys_arch_match.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_sys_dir = _libr_util.r_sys_dir
    r_sys_dir.restype = ctypes.POINTER(struct_r_list_t)
    r_sys_dir.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_sys_perror_str = _libr_util.r_sys_perror_str
    r_sys_perror_str.restype = None
    r_sys_perror_str.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_sys_tem = _libr_util.r_sys_tem
    r_sys_tem.restype = ctypes.c_int32
    r_sys_tem.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_sys_prefix = _libr_util.r_sys_prefix
    r_sys_prefix.restype = ctypes.POINTER(ctypes.c_char)
    r_sys_prefix.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_sys_mktemp = _libraries['FIXME_STUB'].r_sys_mktemp
    r_sys_mktemp.restype = ctypes.c_bool
    r_sys_mktemp.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_sys_mkdir = _libr_util.r_sys_mkdir
    r_sys_mkdir.restype = ctypes.c_bool
    r_sys_mkdir.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_sys_mkdirp = _libr_util.r_sys_mkdirp
    r_sys_mkdirp.restype = ctypes.c_bool
    r_sys_mkdirp.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_sys_sleep = _libr_util.r_sys_sleep
    r_sys_sleep.restype = ctypes.c_int32
    r_sys_sleep.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_sys_usleep = _libr_util.r_sys_usleep
    r_sys_usleep.restype = ctypes.c_int32
    r_sys_usleep.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_sys_getenv = _libr_util.r_sys_getenv
    r_sys_getenv.restype = ctypes.POINTER(ctypes.c_char)
    r_sys_getenv.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_sys_getenv_asbool = _libr_util.r_sys_getenv_asbool
    r_sys_getenv_asbool.restype = ctypes.c_bool
    r_sys_getenv_asbool.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_sys_getenv_asint = _libr_util.r_sys_getenv_asint
    r_sys_getenv_asint.restype = ctypes.c_int32
    r_sys_getenv_asint.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_sys_setenv = _libr_util.r_sys_setenv
    r_sys_setenv.restype = ctypes.c_int32
    r_sys_setenv.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_sys_clearenv = _libr_util.r_sys_clearenv
    r_sys_clearenv.restype = ctypes.c_int32
    r_sys_clearenv.argtypes = []
except AttributeError:
    pass
try:
    r_sys_whoami = _libr_util.r_sys_whoami
    r_sys_whoami.restype = ctypes.POINTER(ctypes.c_char)
    r_sys_whoami.argtypes = []
except AttributeError:
    pass
try:
    r_sys_uid = _libr_util.r_sys_uid
    r_sys_uid.restype = ctypes.c_int32
    r_sys_uid.argtypes = []
except AttributeError:
    pass
try:
    r_sys_getdir = _libr_util.r_sys_getdir
    r_sys_getdir.restype = ctypes.POINTER(ctypes.c_char)
    r_sys_getdir.argtypes = []
except AttributeError:
    pass
try:
    r_sys_chdir = _libr_util.r_sys_chdir
    r_sys_chdir.restype = ctypes.c_bool
    r_sys_chdir.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_sys_aslr = _libr_util.r_sys_aslr
    r_sys_aslr.restype = ctypes.c_bool
    r_sys_aslr.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_sys_thp_mode = _libraries['FIXME_STUB'].r_sys_thp_mode
    r_sys_thp_mode.restype = ctypes.c_int32
    r_sys_thp_mode.argtypes = []
except AttributeError:
    pass
try:
    r_sys_cmd_str_full = _libr_util.r_sys_cmd_str_full
    r_sys_cmd_str_full.restype = ctypes.c_int32
    r_sys_cmd_str_full.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
except AttributeError:
    pass
try:
    r_sys_truncate = _libr_util.r_sys_truncate
    r_sys_truncate.restype = ctypes.c_int32
    r_sys_truncate.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_sys_cmd = _libr_util.r_sys_cmd
    r_sys_cmd.restype = ctypes.c_int32
    r_sys_cmd.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_sys_cmdbg = _libr_util.r_sys_cmdbg
    r_sys_cmdbg.restype = ctypes.c_int32
    r_sys_cmdbg.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_sys_cmdf = _libr_util.r_sys_cmdf
    r_sys_cmdf.restype = ctypes.c_int32
    r_sys_cmdf.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_sys_cmd_str = _libr_util.r_sys_cmd_str
    r_sys_cmd_str.restype = ctypes.POINTER(ctypes.c_char)
    r_sys_cmd_str.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_sys_cmd_strf = _libr_util.r_sys_cmd_strf
    r_sys_cmd_strf.restype = ctypes.POINTER(ctypes.c_char)
    r_sys_cmd_strf.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_sys_backtrace = _libr_util.r_sys_backtrace
    r_sys_backtrace.restype = None
    r_sys_backtrace.argtypes = []
except AttributeError:
    pass
try:
    r_sys_tts = _libr_util.r_sys_tts
    r_sys_tts.restype = ctypes.c_bool
    r_sys_tts.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_bool]
except AttributeError:
    pass
try:
    r_syscmd_ls = _libr_util.r_syscmd_ls
    r_syscmd_ls.restype = ctypes.POINTER(ctypes.c_char)
    r_syscmd_ls.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_syscmd_cat = _libr_util.r_syscmd_cat
    r_syscmd_cat.restype = ctypes.POINTER(ctypes.c_char)
    r_syscmd_cat.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_syscmd_pushd = _libr_util.r_syscmd_pushd
    r_syscmd_pushd.restype = ctypes.c_bool
    r_syscmd_pushd.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_syscmd_popd = _libr_util.r_syscmd_popd
    r_syscmd_popd.restype = ctypes.c_bool
    r_syscmd_popd.argtypes = []
except AttributeError:
    pass
try:
    r_syscmd_popalld = _libr_util.r_syscmd_popalld
    r_syscmd_popalld.restype = ctypes.c_bool
    r_syscmd_popalld.argtypes = []
except AttributeError:
    pass
try:
    r_syscmd_mkdir = _libr_util.r_syscmd_mkdir
    r_syscmd_mkdir.restype = ctypes.c_bool
    r_syscmd_mkdir.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_syscmd_mktemp = _libr_util.r_syscmd_mktemp
    r_syscmd_mktemp.restype = ctypes.POINTER(ctypes.c_char)
    r_syscmd_mktemp.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_syscmd_mv = _libr_util.r_syscmd_mv
    r_syscmd_mv.restype = ctypes.c_bool
    r_syscmd_mv.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_syscmd_uniq = _libr_util.r_syscmd_uniq
    r_syscmd_uniq.restype = ctypes.POINTER(ctypes.c_char)
    r_syscmd_uniq.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_syscmd_head = _libr_util.r_syscmd_head
    r_syscmd_head.restype = ctypes.POINTER(ctypes.c_char)
    r_syscmd_head.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_syscmd_tail = _libr_util.r_syscmd_tail
    r_syscmd_tail.restype = ctypes.POINTER(ctypes.c_char)
    r_syscmd_tail.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_syscmd_join = _libr_util.r_syscmd_join
    r_syscmd_join.restype = ctypes.POINTER(ctypes.c_char)
    r_syscmd_join.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_syscmd_sort = _libr_util.r_syscmd_sort
    r_syscmd_sort.restype = ctypes.POINTER(ctypes.c_char)
    r_syscmd_sort.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_sys_unxz = _libr_util.r_sys_unxz
    r_sys_unxz.restype = ctypes.POINTER(ctypes.c_ubyte)
    r_sys_unxz.argtypes = [ctypes.POINTER(ctypes.c_ubyte), size_t, ctypes.POINTER(ctypes.c_uint64)]
except AttributeError:
    pass
try:
    r_w32_init = _libr_util.r_w32_init
    r_w32_init.restype = ctypes.c_bool
    r_w32_init.argtypes = []
except AttributeError:
    pass
cc_t = ctypes.c_ubyte
speed_t = ctypes.c_uint32
tcflag_t = ctypes.c_uint32
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

try:
    cfgetospeed = _libraries['FIXME_STUB'].cfgetospeed
    cfgetospeed.restype = speed_t
    cfgetospeed.argtypes = [ctypes.POINTER(struct_termios)]
except AttributeError:
    pass
try:
    cfgetispeed = _libraries['FIXME_STUB'].cfgetispeed
    cfgetispeed.restype = speed_t
    cfgetispeed.argtypes = [ctypes.POINTER(struct_termios)]
except AttributeError:
    pass
try:
    cfsetospeed = _libraries['FIXME_STUB'].cfsetospeed
    cfsetospeed.restype = ctypes.c_int32
    cfsetospeed.argtypes = [ctypes.POINTER(struct_termios), speed_t]
except AttributeError:
    pass
try:
    cfsetispeed = _libraries['FIXME_STUB'].cfsetispeed
    cfsetispeed.restype = ctypes.c_int32
    cfsetispeed.argtypes = [ctypes.POINTER(struct_termios), speed_t]
except AttributeError:
    pass
try:
    cfsetspeed = _libraries['FIXME_STUB'].cfsetspeed
    cfsetspeed.restype = ctypes.c_int32
    cfsetspeed.argtypes = [ctypes.POINTER(struct_termios), speed_t]
except AttributeError:
    pass
try:
    tcgetattr = _libraries['FIXME_STUB'].tcgetattr
    tcgetattr.restype = ctypes.c_int32
    tcgetattr.argtypes = [ctypes.c_int32, ctypes.POINTER(struct_termios)]
except AttributeError:
    pass
try:
    tcsetattr = _libraries['FIXME_STUB'].tcsetattr
    tcsetattr.restype = ctypes.c_int32
    tcsetattr.argtypes = [ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(struct_termios)]
except AttributeError:
    pass
try:
    cfmakeraw = _libraries['FIXME_STUB'].cfmakeraw
    cfmakeraw.restype = None
    cfmakeraw.argtypes = [ctypes.POINTER(struct_termios)]
except AttributeError:
    pass
try:
    tcsendbreak = _libraries['FIXME_STUB'].tcsendbreak
    tcsendbreak.restype = ctypes.c_int32
    tcsendbreak.argtypes = [ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    tcdrain = _libraries['FIXME_STUB'].tcdrain
    tcdrain.restype = ctypes.c_int32
    tcdrain.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    tcflush = _libraries['FIXME_STUB'].tcflush
    tcflush.restype = ctypes.c_int32
    tcflush.argtypes = [ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    tcflow = _libraries['FIXME_STUB'].tcflow
    tcflow.restype = ctypes.c_int32
    tcflow.argtypes = [ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    tcgetsid = _libraries['FIXME_STUB'].tcgetsid
    tcgetsid.restype = __pid_t
    tcgetsid.argtypes = [ctypes.c_int32]
except AttributeError:
    pass

# values for enumeration 'idtype_t'
idtype_t__enumvalues = {
    0: 'P_ALL',
    1: 'P_PID',
    2: 'P_PGID',
    3: 'P_PIDFD',
}
P_ALL = 0
P_PID = 1
P_PGID = 2
P_PIDFD = 3
idtype_t = ctypes.c_uint32 # enum
try:
    wait = _libraries['FIXME_STUB'].wait
    wait.restype = __pid_t
    wait.argtypes = [ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    waitpid = _libraries['FIXME_STUB'].waitpid
    waitpid.restype = __pid_t
    waitpid.argtypes = [__pid_t, ctypes.POINTER(ctypes.c_int32), ctypes.c_int32]
except AttributeError:
    pass
try:
    waitid = _libraries['FIXME_STUB'].waitid
    waitid.restype = ctypes.c_int32
    waitid.argtypes = [idtype_t, __id_t, ctypes.POINTER(struct_siginfo_t), ctypes.c_int32]
except AttributeError:
    pass
class struct_rusage(Structure):
    pass

try:
    wait3 = _libraries['FIXME_STUB'].wait3
    wait3.restype = __pid_t
    wait3.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.c_int32, ctypes.POINTER(struct_rusage)]
except AttributeError:
    pass
try:
    wait4 = _libraries['FIXME_STUB'].wait4
    wait4.restype = __pid_t
    wait4.argtypes = [__pid_t, ctypes.POINTER(ctypes.c_int32), ctypes.c_int32, ctypes.POINTER(struct_rusage)]
except AttributeError:
    pass
class struct_winsize(Structure):
    pass

struct_winsize._pack_ = 1 # source:False
struct_winsize._fields_ = [
    ('ws_row', ctypes.c_uint16),
    ('ws_col', ctypes.c_uint16),
    ('ws_xpixel', ctypes.c_uint16),
    ('ws_ypixel', ctypes.c_uint16),
]

class struct_termio(Structure):
    pass

struct_termio._pack_ = 1 # source:False
struct_termio._fields_ = [
    ('c_iflag', ctypes.c_uint16),
    ('c_oflag', ctypes.c_uint16),
    ('c_cflag', ctypes.c_uint16),
    ('c_lflag', ctypes.c_uint16),
    ('c_line', ctypes.c_ubyte),
    ('c_cc', ctypes.c_ubyte * 8),
    ('PADDING_0', ctypes.c_ubyte),
]

try:
    ioctl = _libraries['FIXME_STUB'].ioctl
    ioctl.restype = ctypes.c_int32
    ioctl.argtypes = [ctypes.c_int32, ctypes.c_uint64]
except AttributeError:
    pass
class struct_iovec(Structure):
    pass

struct_iovec._pack_ = 1 # source:False
struct_iovec._fields_ = [
    ('iov_base', ctypes.POINTER(None)),
    ('iov_len', ctypes.c_uint64),
]


# values for enumeration '__socket_type'
__socket_type__enumvalues = {
    1: 'SOCK_STREAM',
    2: 'SOCK_DGRAM',
    3: 'SOCK_RAW',
    4: 'SOCK_RDM',
    5: 'SOCK_SEQPACKET',
    6: 'SOCK_DCCP',
    10: 'SOCK_PACKET',
    524288: 'SOCK_CLOEXEC',
    2048: 'SOCK_NONBLOCK',
}
SOCK_STREAM = 1
SOCK_DGRAM = 2
SOCK_RAW = 3
SOCK_RDM = 4
SOCK_SEQPACKET = 5
SOCK_DCCP = 6
SOCK_PACKET = 10
SOCK_CLOEXEC = 524288
SOCK_NONBLOCK = 2048
__socket_type = ctypes.c_uint32 # enum
sa_family_t = ctypes.c_uint16
class struct_sockaddr(Structure):
    pass

struct_sockaddr._pack_ = 1 # source:False
struct_sockaddr._fields_ = [
    ('sa_family', ctypes.c_uint16),
    ('sa_data', ctypes.c_char * 14),
]

class struct_sockaddr_storage(Structure):
    pass

struct_sockaddr_storage._pack_ = 1 # source:False
struct_sockaddr_storage._fields_ = [
    ('ss_family', ctypes.c_uint16),
    ('__ss_padding', ctypes.c_char * 118),
    ('__ss_align', ctypes.c_uint64),
]


# values for enumeration 'c__Ea_MSG_OOB'
c__Ea_MSG_OOB__enumvalues = {
    1: 'MSG_OOB',
    2: 'MSG_PEEK',
    4: 'MSG_DONTROUTE',
    8: 'MSG_CTRUNC',
    16: 'MSG_PROXY',
    32: 'MSG_TRUNC',
    64: 'MSG_DONTWAIT',
    128: 'MSG_EOR',
    256: 'MSG_WAITALL',
    512: 'MSG_FIN',
    1024: 'MSG_SYN',
    2048: 'MSG_CONFIRM',
    4096: 'MSG_RST',
    8192: 'MSG_ERRQUEUE',
    16384: 'MSG_NOSIGNAL',
    32768: 'MSG_MORE',
    65536: 'MSG_WAITFORONE',
    262144: 'MSG_BATCH',
    67108864: 'MSG_ZEROCOPY',
    536870912: 'MSG_FASTOPEN',
    1073741824: 'MSG_CMSG_CLOEXEC',
}
MSG_OOB = 1
MSG_PEEK = 2
MSG_DONTROUTE = 4
MSG_CTRUNC = 8
MSG_PROXY = 16
MSG_TRUNC = 32
MSG_DONTWAIT = 64
MSG_EOR = 128
MSG_WAITALL = 256
MSG_FIN = 512
MSG_SYN = 1024
MSG_CONFIRM = 2048
MSG_RST = 4096
MSG_ERRQUEUE = 8192
MSG_NOSIGNAL = 16384
MSG_MORE = 32768
MSG_WAITFORONE = 65536
MSG_BATCH = 262144
MSG_ZEROCOPY = 67108864
MSG_FASTOPEN = 536870912
MSG_CMSG_CLOEXEC = 1073741824
c__Ea_MSG_OOB = ctypes.c_uint32 # enum
class struct_msghdr(Structure):
    pass

struct_msghdr._pack_ = 1 # source:False
struct_msghdr._fields_ = [
    ('msg_name', ctypes.POINTER(None)),
    ('msg_namelen', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('msg_iov', ctypes.POINTER(struct_iovec)),
    ('msg_iovlen', ctypes.c_uint64),
    ('msg_control', ctypes.POINTER(None)),
    ('msg_controllen', ctypes.c_uint64),
    ('msg_flags', ctypes.c_int32),
    ('PADDING_1', ctypes.c_ubyte * 4),
]

class struct_cmsghdr(Structure):
    pass

struct_cmsghdr._pack_ = 1 # source:False
struct_cmsghdr._fields_ = [
    ('cmsg_len', ctypes.c_uint64),
    ('cmsg_level', ctypes.c_int32),
    ('cmsg_type', ctypes.c_int32),
    ('__cmsg_data', ctypes.c_ubyte * 0),
]

try:
    __cmsg_nxthdr = _libraries['FIXME_STUB'].__cmsg_nxthdr
    __cmsg_nxthdr.restype = ctypes.POINTER(struct_cmsghdr)
    __cmsg_nxthdr.argtypes = [ctypes.POINTER(struct_msghdr), ctypes.POINTER(struct_cmsghdr)]
except AttributeError:
    pass

# values for enumeration 'c__Ea_SCM_RIGHTS'
c__Ea_SCM_RIGHTS__enumvalues = {
    1: 'SCM_RIGHTS',
}
SCM_RIGHTS = 1
c__Ea_SCM_RIGHTS = ctypes.c_uint32 # enum
class struct___kernel_fd_set(Structure):
    pass

struct___kernel_fd_set._pack_ = 1 # source:False
struct___kernel_fd_set._fields_ = [
    ('fds_bits', ctypes.c_uint64 * 16),
]

__kernel_fd_set = struct___kernel_fd_set
__kernel_sighandler_t = ctypes.CFUNCTYPE(None, ctypes.c_int32)
__kernel_key_t = ctypes.c_int32
__kernel_mqd_t = ctypes.c_int32
__kernel_old_uid_t = ctypes.c_uint16
__kernel_old_gid_t = ctypes.c_uint16
__kernel_old_dev_t = ctypes.c_uint64
__kernel_long_t = ctypes.c_int64
__kernel_ulong_t = ctypes.c_uint64
__kernel_ino_t = ctypes.c_uint64
__kernel_mode_t = ctypes.c_uint32
__kernel_pid_t = ctypes.c_int32
__kernel_ipc_pid_t = ctypes.c_int32
__kernel_uid_t = ctypes.c_uint32
__kernel_gid_t = ctypes.c_uint32
__kernel_suseconds_t = ctypes.c_int64
__kernel_daddr_t = ctypes.c_int32
__kernel_uid32_t = ctypes.c_uint32
__kernel_gid32_t = ctypes.c_uint32
__kernel_size_t = ctypes.c_uint64
__kernel_ssize_t = ctypes.c_int64
__kernel_ptrdiff_t = ctypes.c_int64
class struct___kernel_fsid_t(Structure):
    pass

struct___kernel_fsid_t._pack_ = 1 # source:False
struct___kernel_fsid_t._fields_ = [
    ('val', ctypes.c_int32 * 2),
]

__kernel_fsid_t = struct___kernel_fsid_t
__kernel_off_t = ctypes.c_int64
__kernel_loff_t = ctypes.c_int64
__kernel_old_time_t = ctypes.c_int64
__kernel_time_t = ctypes.c_int64
__kernel_time64_t = ctypes.c_int64
__kernel_clock_t = ctypes.c_int64
__kernel_timer_t = ctypes.c_int32
__kernel_clockid_t = ctypes.c_int32
__kernel_caddr_t = ctypes.POINTER(ctypes.c_char)
__kernel_uid16_t = ctypes.c_uint16
__kernel_gid16_t = ctypes.c_uint16
class struct_linger(Structure):
    pass

struct_linger._pack_ = 1 # source:False
struct_linger._fields_ = [
    ('l_onoff', ctypes.c_int32),
    ('l_linger', ctypes.c_int32),
]

class struct_osockaddr(Structure):
    pass

struct_osockaddr._pack_ = 1 # source:False
struct_osockaddr._fields_ = [
    ('sa_family', ctypes.c_uint16),
    ('sa_data', ctypes.c_ubyte * 14),
]


# values for enumeration 'c__Ea_SHUT_RD'
c__Ea_SHUT_RD__enumvalues = {
    0: 'SHUT_RD',
    1: 'SHUT_WR',
    2: 'SHUT_RDWR',
}
SHUT_RD = 0
SHUT_WR = 1
SHUT_RDWR = 2
c__Ea_SHUT_RD = ctypes.c_uint32 # enum
try:
    socket = _libraries['FIXME_STUB'].socket
    socket.restype = ctypes.c_int32
    socket.argtypes = [ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    socketpair = _libraries['FIXME_STUB'].socketpair
    socketpair.restype = ctypes.c_int32
    socketpair.argtypes = [ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32 * 2]
except AttributeError:
    pass
try:
    bind = _libraries['FIXME_STUB'].bind
    bind.restype = ctypes.c_int32
    bind.argtypes = [ctypes.c_int32, ctypes.POINTER(struct_sockaddr), socklen_t]
except AttributeError:
    pass
try:
    getsockname = _libraries['FIXME_STUB'].getsockname
    getsockname.restype = ctypes.c_int32
    getsockname.argtypes = [ctypes.c_int32, ctypes.POINTER(struct_sockaddr), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    connect = _libraries['FIXME_STUB'].connect
    connect.restype = ctypes.c_int32
    connect.argtypes = [ctypes.c_int32, ctypes.POINTER(struct_sockaddr), socklen_t]
except AttributeError:
    pass
try:
    getpeername = _libraries['FIXME_STUB'].getpeername
    getpeername.restype = ctypes.c_int32
    getpeername.argtypes = [ctypes.c_int32, ctypes.POINTER(struct_sockaddr), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    send = _libraries['FIXME_STUB'].send
    send.restype = ssize_t
    send.argtypes = [ctypes.c_int32, ctypes.POINTER(None), size_t, ctypes.c_int32]
except AttributeError:
    pass
try:
    recv = _libraries['FIXME_STUB'].recv
    recv.restype = ssize_t
    recv.argtypes = [ctypes.c_int32, ctypes.POINTER(None), size_t, ctypes.c_int32]
except AttributeError:
    pass
try:
    sendto = _libraries['FIXME_STUB'].sendto
    sendto.restype = ssize_t
    sendto.argtypes = [ctypes.c_int32, ctypes.POINTER(None), size_t, ctypes.c_int32, ctypes.POINTER(struct_sockaddr), socklen_t]
except AttributeError:
    pass
try:
    recvfrom = _libraries['FIXME_STUB'].recvfrom
    recvfrom.restype = ssize_t
    recvfrom.argtypes = [ctypes.c_int32, ctypes.POINTER(None), size_t, ctypes.c_int32, ctypes.POINTER(struct_sockaddr), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    sendmsg = _libraries['FIXME_STUB'].sendmsg
    sendmsg.restype = ssize_t
    sendmsg.argtypes = [ctypes.c_int32, ctypes.POINTER(struct_msghdr), ctypes.c_int32]
except AttributeError:
    pass
try:
    recvmsg = _libraries['FIXME_STUB'].recvmsg
    recvmsg.restype = ssize_t
    recvmsg.argtypes = [ctypes.c_int32, ctypes.POINTER(struct_msghdr), ctypes.c_int32]
except AttributeError:
    pass
try:
    getsockopt = _libraries['FIXME_STUB'].getsockopt
    getsockopt.restype = ctypes.c_int32
    getsockopt.argtypes = [ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    setsockopt = _libraries['FIXME_STUB'].setsockopt
    setsockopt.restype = ctypes.c_int32
    setsockopt.argtypes = [ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(None), socklen_t]
except AttributeError:
    pass
try:
    listen = _libraries['FIXME_STUB'].listen
    listen.restype = ctypes.c_int32
    listen.argtypes = [ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    accept = _libraries['FIXME_STUB'].accept
    accept.restype = ctypes.c_int32
    accept.argtypes = [ctypes.c_int32, ctypes.POINTER(struct_sockaddr), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    shutdown = _libraries['FIXME_STUB'].shutdown
    shutdown.restype = ctypes.c_int32
    shutdown.argtypes = [ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    sockatmark = _libraries['FIXME_STUB'].sockatmark
    sockatmark.restype = ctypes.c_int32
    sockatmark.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    isfdtype = _libraries['FIXME_STUB'].isfdtype
    isfdtype.restype = ctypes.c_int32
    isfdtype.argtypes = [ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_version = _libr_cons.r_cons_version
    r_cons_version.restype = ctypes.POINTER(ctypes.c_char)
    r_cons_version.argtypes = []
except AttributeError:
    pass
RConsGetSize = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_int32))
RConsGetCursor = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_int32))
RConsIsBreaked = ctypes.CFUNCTYPE(ctypes.c_bool)
RConsFlush = ctypes.CFUNCTYPE(None)
RConsGrepCallback = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_char))
RCoreHelpMessage = ctypes.POINTER(ctypes.c_char) * 0
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
    ('gron', ctypes.c_bool),
    ('json', ctypes.c_bool),
    ('json_path', ctypes.POINTER(ctypes.c_char)),
    ('range_line', ctypes.c_int32),
    ('line', ctypes.c_int32),
    ('sort', ctypes.c_int32),
    ('sort_row', ctypes.c_int32),
    ('sort_invert', ctypes.c_bool),
    ('PADDING_2', ctypes.c_ubyte * 3),
    ('f_line', ctypes.c_int32),
    ('l_line', ctypes.c_int32),
    ('tokens', ctypes.c_int32 * 64),
    ('tokens_used', ctypes.c_int32),
    ('amp', ctypes.c_int32),
    ('zoom', ctypes.c_int32),
    ('zoomy', ctypes.c_int32),
    ('neg', ctypes.c_int32 * 10),
    ('begin', ctypes.c_int32 * 10),
    ('end', ctypes.c_int32 * 10),
    ('icase', ctypes.c_bool),
    ('ascart', ctypes.c_bool),
    ('code', ctypes.c_bool),
    ('PADDING_3', ctypes.c_ubyte),
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
    ('bgprompt', RColor),
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
    ('bgprompt', ctypes.POINTER(ctypes.c_char)),
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
    ('constpool', RStrConstPool),
    ('sx', ctypes.c_int32),
    ('sy', ctypes.c_int32),
    ('color', ctypes.c_int32),
    ('linemode', ctypes.c_int32),
]

RConsCanvas = struct_r_cons_canvas_t
RConsEditorCallback = ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char))
RConsClickCallback = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.c_int32, ctypes.c_int32)
RConsBreakCallback = ctypes.CFUNCTYPE(None, ctypes.POINTER(None))
RConsSleepBeginCallback = ctypes.CFUNCTYPE(ctypes.POINTER(None), ctypes.POINTER(None))
RConsSleepEndCallback = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(None))
RConsQueueTaskOneshot = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None))
RConsFunctionKey = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.c_int32)

# values for enumeration 'RConsColorMode'
RConsColorMode__enumvalues = {
    0: 'COLOR_MODE_DISABLED',
    1: 'COLOR_MODE_16',
    2: 'COLOR_MODE_256',
    3: 'COLOR_MODE_16M',
}
COLOR_MODE_DISABLED = 0
COLOR_MODE_16 = 1
COLOR_MODE_256 = 2
COLOR_MODE_16M = 3
RConsColorMode = ctypes.c_uint32 # enum
class struct_r_cons_context_t(Structure):
    pass

struct_r_cons_context_t._pack_ = 1 # source:False
struct_r_cons_context_t._fields_ = [
    ('grep', RConsGrep),
    ('cons_stack', ctypes.POINTER(struct_r_stack_t)),
    ('buffer', ctypes.POINTER(ctypes.c_char)),
    ('buffer_len', ctypes.c_uint64),
    ('buffer_sz', ctypes.c_uint64),
    ('error', ctypes.POINTER(struct_RStrBuf)),
    ('errmode', ctypes.c_int32),
    ('breaked', ctypes.c_bool),
    ('was_breaked', ctypes.c_bool),
    ('unbreakable', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte),
    ('break_stack', ctypes.POINTER(struct_r_stack_t)),
    ('event_interrupt', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
    ('event_interrupt_data', ctypes.POINTER(None)),
    ('cmd_depth', ctypes.c_int32),
    ('cmd_str_depth', ctypes.c_int32),
    ('noflush', ctypes.c_bool),
    ('PADDING_1', ctypes.c_ubyte * 7),
    ('log_callback', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(None), ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char))),
    ('lastOutput', ctypes.POINTER(ctypes.c_char)),
    ('lastLength', ctypes.c_int32),
    ('lastMode', ctypes.c_bool),
    ('lastEnabled', ctypes.c_bool),
    ('is_interactive', ctypes.c_bool),
    ('pageable', ctypes.c_bool),
    ('color_mode', ctypes.c_int32),
    ('cpal', RConsPalette),
    ('PADDING_2', ctypes.c_ubyte * 5),
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
    ('colors', ctypes.c_int32 * 256),
    ('PADDING_3', ctypes.c_ubyte * 4),
]

RConsContext = struct_r_cons_context_t
class struct_RConsCursorPos(Structure):
    pass

struct_RConsCursorPos._pack_ = 1 # source:False
struct_RConsCursorPos._fields_ = [
    ('x', ctypes.c_int32),
    ('y', ctypes.c_int32),
]

RConsCursorPos = struct_RConsCursorPos
class struct_r_cons_t(Structure):
    pass

class struct_r_line_t(Structure):
    pass

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
    ('maxpage', ctypes.c_int32),
    ('PADDING_8', ctypes.c_ubyte * 4),
    ('break_word', ctypes.POINTER(ctypes.c_char)),
    ('break_word_len', ctypes.c_int32),
    ('PADDING_9', ctypes.c_ubyte * 4),
    ('timeout', ctypes.c_uint64),
    ('rgbstr', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_uint64, ctypes.c_uint64)),
    ('click_set', ctypes.c_bool),
    ('PADDING_10', ctypes.c_ubyte * 3),
    ('click_x', ctypes.c_int32),
    ('click_y', ctypes.c_int32),
    ('show_vals', ctypes.c_bool),
    ('PADDING_11', ctypes.c_ubyte * 3),
    ('lock', ctypes.POINTER(struct_r_th_lock_t)),
    ('cpos', RConsCursorPos),
]

class struct_r_selection_widget_t(Structure):
    pass

class struct_r_hud_t(Structure):
    pass

class struct_r_line_comp_t(Structure):
    pass

class struct_r_line_buffer_t(Structure):
    pass


# values for enumeration 'RLinePromptType'
RLinePromptType__enumvalues = {
    0: 'R_LINE_PROMPT_DEFAULT',
    1: 'R_LINE_PROMPT_OFFSET',
    2: 'R_LINE_PROMPT_FILE',
}
R_LINE_PROMPT_DEFAULT = 0
R_LINE_PROMPT_OFFSET = 1
R_LINE_PROMPT_FILE = 2
RLinePromptType = ctypes.c_uint32 # enum
struct_r_line_comp_t._pack_ = 1 # source:False
struct_r_line_comp_t._fields_ = [
    ('opt', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 7),
    ('args_limit', ctypes.c_uint64),
    ('quit', ctypes.c_bool),
    ('PADDING_1', ctypes.c_ubyte * 7),
    ('args', RPVector),
    ('run', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_line_comp_t), ctypes.POINTER(struct_r_line_buffer_t), RLinePromptType, ctypes.POINTER(None))),
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
    ('prompt_type', RLinePromptType),
    ('offset_hist_index', ctypes.c_int32),
    ('file_hist_index', ctypes.c_int32),
    ('hud', ctypes.POINTER(struct_r_hud_t)),
    ('sdbshell_hist', ctypes.POINTER(struct_r_list_t)),
    ('sdbshell_hist_iter', ctypes.POINTER(struct_r_list_iter_t)),
    ('vtmode', ctypes.c_int32),
    ('hist_size', ctypes.c_int32),
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

# values for enumeration 'RViMode'
RViMode__enumvalues = {
    105: 'INSERT_MODE',
    99: 'CONTROL_MODE',
}
INSERT_MODE = 105
CONTROL_MODE = 99
RViMode = ctypes.c_uint32 # enum
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
try:
    r_cons_image = _libr_cons.r_cons_image
    r_cons_image.restype = None
    r_cons_image.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_canvas_new = _libr_cons.r_cons_canvas_new
    r_cons_canvas_new.restype = ctypes.POINTER(struct_r_cons_canvas_t)
    r_cons_canvas_new.argtypes = [ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_canvas_free = _libr_cons.r_cons_canvas_free
    r_cons_canvas_free.restype = None
    r_cons_canvas_free.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t)]
except AttributeError:
    pass
try:
    r_cons_canvas_clear = _libr_cons.r_cons_canvas_clear
    r_cons_canvas_clear.restype = None
    r_cons_canvas_clear.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t)]
except AttributeError:
    pass
try:
    r_cons_canvas_print = _libr_cons.r_cons_canvas_print
    r_cons_canvas_print.restype = None
    r_cons_canvas_print.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t)]
except AttributeError:
    pass
try:
    r_cons_canvas_print_region = _libr_cons.r_cons_canvas_print_region
    r_cons_canvas_print_region.restype = None
    r_cons_canvas_print_region.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t)]
except AttributeError:
    pass
try:
    r_cons_canvas_to_string = _libr_cons.r_cons_canvas_to_string
    r_cons_canvas_to_string.restype = ctypes.POINTER(ctypes.c_char)
    r_cons_canvas_to_string.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t)]
except AttributeError:
    pass
try:
    r_cons_canvas_attr = _libraries['FIXME_STUB'].r_cons_canvas_attr
    r_cons_canvas_attr.restype = None
    r_cons_canvas_attr.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_canvas_write = _libr_cons.r_cons_canvas_write
    r_cons_canvas_write.restype = None
    r_cons_canvas_write.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_canvas_gotoxy = _libr_cons.r_cons_canvas_gotoxy
    r_cons_canvas_gotoxy.restype = ctypes.c_bool
    r_cons_canvas_gotoxy.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t), ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_canvas_goto_write = _libraries['FIXME_STUB'].r_cons_canvas_goto_write
    r_cons_canvas_goto_write.restype = None
    r_cons_canvas_goto_write.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t), ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_canvas_box = _libr_cons.r_cons_canvas_box
    r_cons_canvas_box.restype = None
    r_cons_canvas_box.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_canvas_circle = _libr_cons.r_cons_canvas_circle
    r_cons_canvas_circle.restype = None
    r_cons_canvas_circle.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_canvas_line = _libr_cons.r_cons_canvas_line
    r_cons_canvas_line.restype = None
    r_cons_canvas_line.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(struct_r_cons_canvas_line_style_t)]
except AttributeError:
    pass
try:
    r_cons_canvas_line_diagonal = _libr_cons.r_cons_canvas_line_diagonal
    r_cons_canvas_line_diagonal.restype = None
    r_cons_canvas_line_diagonal.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(struct_r_cons_canvas_line_style_t)]
except AttributeError:
    pass
try:
    r_cons_canvas_line_square = _libr_cons.r_cons_canvas_line_square
    r_cons_canvas_line_square.restype = None
    r_cons_canvas_line_square.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(struct_r_cons_canvas_line_style_t)]
except AttributeError:
    pass
try:
    r_cons_canvas_resize = _libr_cons.r_cons_canvas_resize
    r_cons_canvas_resize.restype = ctypes.c_int32
    r_cons_canvas_resize.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t), ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_canvas_fill = _libr_cons.r_cons_canvas_fill
    r_cons_canvas_fill.restype = None
    r_cons_canvas_fill.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_char]
except AttributeError:
    pass
try:
    r_cons_canvas_line_square_defined = _libr_cons.r_cons_canvas_line_square_defined
    r_cons_canvas_line_square_defined.restype = None
    r_cons_canvas_line_square_defined.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(struct_r_cons_canvas_line_style_t), ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_canvas_line_back_edge = _libr_cons.r_cons_canvas_line_back_edge
    r_cons_canvas_line_back_edge.restype = None
    r_cons_canvas_line_back_edge.argtypes = [ctypes.POINTER(struct_r_cons_canvas_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(struct_r_cons_canvas_line_style_t), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_new = _libr_cons.r_cons_new
    r_cons_new.restype = ctypes.POINTER(struct_r_cons_t)
    r_cons_new.argtypes = []
except AttributeError:
    pass
try:
    r_cons_singleton = _libr_cons.r_cons_singleton
    r_cons_singleton.restype = ctypes.POINTER(struct_r_cons_t)
    r_cons_singleton.argtypes = []
except AttributeError:
    pass
try:
    r_cons_chop = _libr_cons.r_cons_chop
    r_cons_chop.restype = None
    r_cons_chop.argtypes = []
except AttributeError:
    pass
try:
    r_cons_context = _libr_cons.r_cons_context
    r_cons_context.restype = ctypes.POINTER(struct_r_cons_context_t)
    r_cons_context.argtypes = []
except AttributeError:
    pass
try:
    r_cons_free = _libr_cons.r_cons_free
    r_cons_free.restype = ctypes.POINTER(struct_r_cons_t)
    r_cons_free.argtypes = []
except AttributeError:
    pass
try:
    r_cons_lastline = _libr_cons.r_cons_lastline
    r_cons_lastline.restype = ctypes.POINTER(ctypes.c_char)
    r_cons_lastline.argtypes = [ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_cons_lastline_utf8_ansi_len = _libr_cons.r_cons_lastline_utf8_ansi_len
    r_cons_lastline_utf8_ansi_len.restype = ctypes.POINTER(ctypes.c_char)
    r_cons_lastline_utf8_ansi_len.argtypes = [ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_cons_set_click = _libr_cons.r_cons_set_click
    r_cons_set_click.restype = None
    r_cons_set_click.argtypes = [ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_get_click = _libr_cons.r_cons_get_click
    r_cons_get_click.restype = ctypes.c_bool
    r_cons_get_click.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
RConsBreak = ctypes.CFUNCTYPE(None, ctypes.POINTER(None))
try:
    r_cons_is_initialized = _libr_cons.r_cons_is_initialized
    r_cons_is_initialized.restype = ctypes.c_bool
    r_cons_is_initialized.argtypes = []
except AttributeError:
    pass
try:
    r_cons_is_breaked = _libr_cons.r_cons_is_breaked
    r_cons_is_breaked.restype = ctypes.c_bool
    r_cons_is_breaked.argtypes = []
except AttributeError:
    pass
try:
    r_cons_was_breaked = _libr_cons.r_cons_was_breaked
    r_cons_was_breaked.restype = ctypes.c_bool
    r_cons_was_breaked.argtypes = []
except AttributeError:
    pass
try:
    r_cons_is_interactive = _libr_cons.r_cons_is_interactive
    r_cons_is_interactive.restype = ctypes.c_bool
    r_cons_is_interactive.argtypes = []
except AttributeError:
    pass
try:
    r_cons_default_context_is_interactive = _libr_cons.r_cons_default_context_is_interactive
    r_cons_default_context_is_interactive.restype = ctypes.c_bool
    r_cons_default_context_is_interactive.argtypes = []
except AttributeError:
    pass
try:
    r_cons_sleep_begin = _libr_cons.r_cons_sleep_begin
    r_cons_sleep_begin.restype = ctypes.POINTER(None)
    r_cons_sleep_begin.argtypes = []
except AttributeError:
    pass
try:
    r_cons_sleep_end = _libr_cons.r_cons_sleep_end
    r_cons_sleep_end.restype = None
    r_cons_sleep_end.argtypes = [ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_cons_break_push = _libr_cons.r_cons_break_push
    r_cons_break_push.restype = None
    r_cons_break_push.argtypes = [RConsBreak, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_cons_break_pop = _libr_cons.r_cons_break_pop
    r_cons_break_pop.restype = None
    r_cons_break_pop.argtypes = []
except AttributeError:
    pass
try:
    r_cons_break_clear = _libr_cons.r_cons_break_clear
    r_cons_break_clear.restype = None
    r_cons_break_clear.argtypes = []
except AttributeError:
    pass
try:
    r_cons_breakword = _libr_cons.r_cons_breakword
    r_cons_breakword.restype = None
    r_cons_breakword.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_break_end = _libr_cons.r_cons_break_end
    r_cons_break_end.restype = None
    r_cons_break_end.argtypes = []
except AttributeError:
    pass
try:
    r_cons_break_timeout = _libr_cons.r_cons_break_timeout
    r_cons_break_timeout.restype = None
    r_cons_break_timeout.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_pipe_open = _libr_cons.r_cons_pipe_open
    r_cons_pipe_open.restype = ctypes.c_int32
    r_cons_pipe_open.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_pipe_close = _libr_cons.r_cons_pipe_close
    r_cons_pipe_close.restype = None
    r_cons_pipe_close.argtypes = [ctypes.c_int32]
except AttributeError:
    pass

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
try:
    r_cons_push = _libr_cons.r_cons_push
    r_cons_push.restype = None
    r_cons_push.argtypes = []
except AttributeError:
    pass
try:
    r_cons_pop = _libr_cons.r_cons_pop
    r_cons_pop.restype = None
    r_cons_pop.argtypes = []
except AttributeError:
    pass
try:
    r_cons_context_new = _libr_cons.r_cons_context_new
    r_cons_context_new.restype = ctypes.POINTER(struct_r_cons_context_t)
    r_cons_context_new.argtypes = [ctypes.POINTER(struct_r_cons_context_t)]
except AttributeError:
    pass
try:
    r_cons_context_free = _libr_cons.r_cons_context_free
    r_cons_context_free.restype = None
    r_cons_context_free.argtypes = [ctypes.POINTER(struct_r_cons_context_t)]
except AttributeError:
    pass
try:
    r_cons_context_load = _libr_cons.r_cons_context_load
    r_cons_context_load.restype = None
    r_cons_context_load.argtypes = [ctypes.POINTER(struct_r_cons_context_t)]
except AttributeError:
    pass
try:
    r_cons_context_reset = _libr_cons.r_cons_context_reset
    r_cons_context_reset.restype = None
    r_cons_context_reset.argtypes = []
except AttributeError:
    pass
try:
    r_cons_context_is_main = _libr_cons.r_cons_context_is_main
    r_cons_context_is_main.restype = ctypes.c_bool
    r_cons_context_is_main.argtypes = []
except AttributeError:
    pass
try:
    r_cons_context_break = _libr_cons.r_cons_context_break
    r_cons_context_break.restype = None
    r_cons_context_break.argtypes = [ctypes.POINTER(struct_r_cons_context_t)]
except AttributeError:
    pass
try:
    r_cons_context_break_push = _libr_cons.r_cons_context_break_push
    r_cons_context_break_push.restype = None
    r_cons_context_break_push.argtypes = [ctypes.POINTER(struct_r_cons_context_t), RConsBreak, ctypes.POINTER(None), ctypes.c_bool]
except AttributeError:
    pass
try:
    r_cons_context_break_pop = _libr_cons.r_cons_context_break_pop
    r_cons_context_break_pop.restype = None
    r_cons_context_break_pop.argtypes = [ctypes.POINTER(struct_r_cons_context_t), ctypes.c_bool]
except AttributeError:
    pass
try:
    r_cons_editor = _libr_cons.r_cons_editor
    r_cons_editor.restype = ctypes.POINTER(ctypes.c_char)
    r_cons_editor.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_reset = _libr_cons.r_cons_reset
    r_cons_reset.restype = None
    r_cons_reset.argtypes = []
except AttributeError:
    pass
try:
    r_cons_reset_colors = _libr_cons.r_cons_reset_colors
    r_cons_reset_colors.restype = None
    r_cons_reset_colors.argtypes = []
except AttributeError:
    pass
try:
    r_cons_errstr = _libr_cons.r_cons_errstr
    r_cons_errstr.restype = ctypes.POINTER(ctypes.c_char)
    r_cons_errstr.argtypes = []
except AttributeError:
    pass
try:
    r_cons_errmode = _libr_cons.r_cons_errmode
    r_cons_errmode.restype = None
    r_cons_errmode.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_errmodes = _libr_cons.r_cons_errmodes
    r_cons_errmodes.restype = None
    r_cons_errmodes.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_eprintf = _libr_cons.r_cons_eprintf
    r_cons_eprintf.restype = ctypes.c_int32
    r_cons_eprintf.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_eflush = _libr_cons.r_cons_eflush
    r_cons_eflush.restype = None
    r_cons_eflush.argtypes = []
except AttributeError:
    pass
try:
    r_cons_print_clear = _libr_cons.r_cons_print_clear
    r_cons_print_clear.restype = None
    r_cons_print_clear.argtypes = []
except AttributeError:
    pass
try:
    r_cons_echo = _libr_cons.r_cons_echo
    r_cons_echo.restype = None
    r_cons_echo.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_zero = _libr_cons.r_cons_zero
    r_cons_zero.restype = None
    r_cons_zero.argtypes = []
except AttributeError:
    pass
try:
    r_cons_highlight = _libr_cons.r_cons_highlight
    r_cons_highlight.restype = None
    r_cons_highlight.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_clear = _libr_cons.r_cons_clear
    r_cons_clear.restype = None
    r_cons_clear.argtypes = []
except AttributeError:
    pass
try:
    r_cons_clear_buffer = _libr_cons.r_cons_clear_buffer
    r_cons_clear_buffer.restype = None
    r_cons_clear_buffer.argtypes = []
except AttributeError:
    pass
try:
    r_cons_clear00 = _libr_cons.r_cons_clear00
    r_cons_clear00.restype = None
    r_cons_clear00.argtypes = []
except AttributeError:
    pass
try:
    r_cons_clear_line = _libr_cons.r_cons_clear_line
    r_cons_clear_line.restype = None
    r_cons_clear_line.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_fill_line = _libr_cons.r_cons_fill_line
    r_cons_fill_line.restype = None
    r_cons_fill_line.argtypes = []
except AttributeError:
    pass
try:
    r_cons_stdout_open = _libraries['FIXME_STUB'].r_cons_stdout_open
    r_cons_stdout_open.restype = None
    r_cons_stdout_open.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_stdout_set_fd = _libraries['FIXME_STUB'].r_cons_stdout_set_fd
    r_cons_stdout_set_fd.restype = ctypes.c_int32
    r_cons_stdout_set_fd.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_gotoxy = _libr_cons.r_cons_gotoxy
    r_cons_gotoxy.restype = None
    r_cons_gotoxy.argtypes = [ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_get_cur_line = _libr_cons.r_cons_get_cur_line
    r_cons_get_cur_line.restype = ctypes.c_int32
    r_cons_get_cur_line.argtypes = []
except AttributeError:
    pass
try:
    r_cons_line = _libr_cons.r_cons_line
    r_cons_line.restype = None
    r_cons_line.argtypes = [ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_show_cursor = _libr_cons.r_cons_show_cursor
    r_cons_show_cursor.restype = None
    r_cons_show_cursor.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_swap_ground = _libr_cons.r_cons_swap_ground
    r_cons_swap_ground.restype = ctypes.POINTER(ctypes.c_char)
    r_cons_swap_ground.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_drop = _libr_cons.r_cons_drop
    r_cons_drop.restype = ctypes.c_bool
    r_cons_drop.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_set_raw = _libr_cons.r_cons_set_raw
    r_cons_set_raw.restype = None
    r_cons_set_raw.argtypes = [ctypes.c_bool]
except AttributeError:
    pass
try:
    r_cons_set_interactive = _libr_cons.r_cons_set_interactive
    r_cons_set_interactive.restype = None
    r_cons_set_interactive.argtypes = [ctypes.c_bool]
except AttributeError:
    pass
try:
    r_cons_set_last_interactive = _libr_cons.r_cons_set_last_interactive
    r_cons_set_last_interactive.restype = None
    r_cons_set_last_interactive.argtypes = []
except AttributeError:
    pass
try:
    r_cons_set_utf8 = _libr_cons.r_cons_set_utf8
    r_cons_set_utf8.restype = None
    r_cons_set_utf8.argtypes = [ctypes.c_bool]
except AttributeError:
    pass
try:
    r_cons_grep = _libr_cons.r_cons_grep
    r_cons_grep.restype = None
    r_cons_grep.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_printf = _libr_cons.r_cons_printf
    r_cons_printf.restype = ctypes.c_int32
    r_cons_printf.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_printf_list = _libr_cons.r_cons_printf_list
    r_cons_printf_list.restype = None
    r_cons_printf_list.argtypes = [ctypes.POINTER(ctypes.c_char), va_list]
except AttributeError:
    pass
try:
    r_cons_strcat = _libr_cons.r_cons_strcat
    r_cons_strcat.restype = None
    r_cons_strcat.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_strcat_at = _libr_cons.r_cons_strcat_at
    r_cons_strcat_at.restype = None
    r_cons_strcat_at.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_char, ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_println = _libr_cons.r_cons_println
    r_cons_println.restype = None
    r_cons_println.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_strcat_justify = _libr_cons.r_cons_strcat_justify
    r_cons_strcat_justify.restype = None
    r_cons_strcat_justify.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_char]
except AttributeError:
    pass
try:
    r_cons_printat = _libr_cons.r_cons_printat
    r_cons_printat.restype = None
    r_cons_printat.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_char]
except AttributeError:
    pass
try:
    r_cons_write = _libr_cons.r_cons_write
    r_cons_write.restype = ctypes.c_int32
    r_cons_write.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_newline = _libr_cons.r_cons_newline
    r_cons_newline.restype = None
    r_cons_newline.argtypes = []
except AttributeError:
    pass
try:
    r_cons_filter = _libr_cons.r_cons_filter
    r_cons_filter.restype = None
    r_cons_filter.argtypes = []
except AttributeError:
    pass
try:
    r_cons_flush = _libr_cons.r_cons_flush
    r_cons_flush.restype = None
    r_cons_flush.argtypes = []
except AttributeError:
    pass
try:
    r_cons_drain = _libr_cons.r_cons_drain
    r_cons_drain.restype = ctypes.POINTER(ctypes.c_char)
    r_cons_drain.argtypes = []
except AttributeError:
    pass
try:
    r_cons_print_fps = _libr_cons.r_cons_print_fps
    r_cons_print_fps.restype = None
    r_cons_print_fps.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_last = _libr_cons.r_cons_last
    r_cons_last.restype = None
    r_cons_last.argtypes = []
except AttributeError:
    pass
try:
    r_cons_less_str = _libr_cons.r_cons_less_str
    r_cons_less_str.restype = ctypes.c_int32
    r_cons_less_str.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_less = _libr_cons.r_cons_less
    r_cons_less.restype = None
    r_cons_less.argtypes = []
except AttributeError:
    pass
try:
    r_cons_2048 = _libr_cons.r_cons_2048
    r_cons_2048.restype = None
    r_cons_2048.argtypes = [ctypes.c_bool]
except AttributeError:
    pass
try:
    r_cons_memset = _libr_cons.r_cons_memset
    r_cons_memset.restype = None
    r_cons_memset.argtypes = [ctypes.c_char, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_visual_flush = _libr_cons.r_cons_visual_flush
    r_cons_visual_flush.restype = None
    r_cons_visual_flush.argtypes = []
except AttributeError:
    pass
try:
    r_cons_visual_write = _libr_cons.r_cons_visual_write
    r_cons_visual_write.restype = None
    r_cons_visual_write.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_is_utf8 = _libr_cons.r_cons_is_utf8
    r_cons_is_utf8.restype = ctypes.c_bool
    r_cons_is_utf8.argtypes = []
except AttributeError:
    pass
try:
    r_cons_is_windows = _libr_cons.r_cons_is_windows
    r_cons_is_windows.restype = ctypes.c_bool
    r_cons_is_windows.argtypes = []
except AttributeError:
    pass
try:
    r_cons_cmd_help = _libr_cons.r_cons_cmd_help
    r_cons_cmd_help.restype = None
    r_cons_cmd_help.argtypes = [ctypes.POINTER(ctypes.c_char) * 0, ctypes.c_bool]
except AttributeError:
    pass
try:
    r_cons_cmd_help_json = _libr_cons.r_cons_cmd_help_json
    r_cons_cmd_help_json.restype = None
    r_cons_cmd_help_json.argtypes = [ctypes.POINTER(ctypes.c_char) * 0]
except AttributeError:
    pass
try:
    r_cons_cmd_help_match = _libr_cons.r_cons_cmd_help_match
    r_cons_cmd_help_match.restype = None
    r_cons_cmd_help_match.argtypes = [RCoreHelpMessage, ctypes.c_bool, ctypes.POINTER(ctypes.c_char), ctypes.c_char, ctypes.c_bool]
except AttributeError:
    pass
try:
    r_cons_log_stub = _libraries['FIXME_STUB'].r_cons_log_stub
    r_cons_log_stub.restype = None
    r_cons_log_stub.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_uint32, ctypes.c_uint32, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_controlz = _libr_cons.r_cons_controlz
    r_cons_controlz.restype = ctypes.c_int32
    r_cons_controlz.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_readchar = _libr_cons.r_cons_readchar
    r_cons_readchar.restype = ctypes.c_int32
    r_cons_readchar.argtypes = []
except AttributeError:
    pass
try:
    r_cons_readpush = _libr_cons.r_cons_readpush
    r_cons_readpush.restype = ctypes.c_bool
    r_cons_readpush.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_readflush = _libr_cons.r_cons_readflush
    r_cons_readflush.restype = None
    r_cons_readflush.argtypes = []
except AttributeError:
    pass
try:
    r_cons_switchbuf = _libr_cons.r_cons_switchbuf
    r_cons_switchbuf.restype = None
    r_cons_switchbuf.argtypes = [ctypes.c_bool]
except AttributeError:
    pass
try:
    r_cons_readchar_timeout = _libr_cons.r_cons_readchar_timeout
    r_cons_readchar_timeout.restype = ctypes.c_int32
    r_cons_readchar_timeout.argtypes = [uint32_t]
except AttributeError:
    pass
try:
    r_cons_any_key = _libr_cons.r_cons_any_key
    r_cons_any_key.restype = ctypes.c_int32
    r_cons_any_key.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_eof = _libr_cons.r_cons_eof
    r_cons_eof.restype = ctypes.c_int32
    r_cons_eof.argtypes = []
except AttributeError:
    pass
try:
    r_cons_thready = _libr_cons.r_cons_thready
    r_cons_thready.restype = None
    r_cons_thready.argtypes = []
except AttributeError:
    pass
try:
    r_cons_palette_init = _libraries['FIXME_STUB'].r_cons_palette_init
    r_cons_palette_init.restype = ctypes.c_int32
    r_cons_palette_init.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
except AttributeError:
    pass
try:
    r_cons_pal_set = _libr_cons.r_cons_pal_set
    r_cons_pal_set.restype = ctypes.c_int32
    r_cons_pal_set.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_pal_update_event = _libr_cons.r_cons_pal_update_event
    r_cons_pal_update_event.restype = None
    r_cons_pal_update_event.argtypes = []
except AttributeError:
    pass
try:
    r_cons_pal_free = _libr_cons.r_cons_pal_free
    r_cons_pal_free.restype = None
    r_cons_pal_free.argtypes = [ctypes.POINTER(struct_r_cons_context_t)]
except AttributeError:
    pass
try:
    r_cons_pal_init = _libr_cons.r_cons_pal_init
    r_cons_pal_init.restype = None
    r_cons_pal_init.argtypes = [ctypes.POINTER(struct_r_cons_context_t)]
except AttributeError:
    pass
try:
    r_cons_pal_copy = _libr_cons.r_cons_pal_copy
    r_cons_pal_copy.restype = None
    r_cons_pal_copy.argtypes = [ctypes.POINTER(struct_r_cons_context_t), ctypes.POINTER(struct_r_cons_context_t)]
except AttributeError:
    pass
try:
    r_cons_pal_parse = _libr_cons.r_cons_pal_parse
    r_cons_pal_parse.restype = ctypes.POINTER(ctypes.c_char)
    r_cons_pal_parse.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_rcolor_t)]
except AttributeError:
    pass
try:
    r_cons_pal_random = _libr_cons.r_cons_pal_random
    r_cons_pal_random.restype = None
    r_cons_pal_random.argtypes = []
except AttributeError:
    pass
try:
    r_cons_pal_get = _libr_cons.r_cons_pal_get
    r_cons_pal_get.restype = RColor
    r_cons_pal_get.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_pal_get_i = _libr_cons.r_cons_pal_get_i
    r_cons_pal_get_i.restype = RColor
    r_cons_pal_get_i.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_pal_get_name = _libr_cons.r_cons_pal_get_name
    r_cons_pal_get_name.restype = ctypes.POINTER(ctypes.c_char)
    r_cons_pal_get_name.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_pal_len = _libr_cons.r_cons_pal_len
    r_cons_pal_len.restype = ctypes.c_int32
    r_cons_pal_len.argtypes = []
except AttributeError:
    pass
try:
    r_cons_rgb_parse = _libr_cons.r_cons_rgb_parse
    r_cons_rgb_parse.restype = ctypes.c_int32
    r_cons_rgb_parse.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
except AttributeError:
    pass
try:
    r_cons_rgb_tostring = _libr_cons.r_cons_rgb_tostring
    r_cons_rgb_tostring.restype = ctypes.POINTER(ctypes.c_char)
    r_cons_rgb_tostring.argtypes = [uint8_t, uint8_t, uint8_t]
except AttributeError:
    pass
try:
    r_cons_pal_list = _libr_cons.r_cons_pal_list
    r_cons_pal_list.restype = None
    r_cons_pal_list.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_pal_show = _libr_cons.r_cons_pal_show
    r_cons_pal_show.restype = None
    r_cons_pal_show.argtypes = []
except AttributeError:
    pass
try:
    r_cons_get_size = _libr_cons.r_cons_get_size
    r_cons_get_size.restype = ctypes.c_int32
    r_cons_get_size.argtypes = [ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_cons_is_tty = _libr_cons.r_cons_is_tty
    r_cons_is_tty.restype = ctypes.c_bool
    r_cons_is_tty.argtypes = []
except AttributeError:
    pass
try:
    r_cons_get_cursor = _libr_cons.r_cons_get_cursor
    r_cons_get_cursor.restype = ctypes.c_int32
    r_cons_get_cursor.argtypes = [ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_cons_arrow_to_hjkl = _libr_cons.r_cons_arrow_to_hjkl
    r_cons_arrow_to_hjkl.restype = ctypes.c_int32
    r_cons_arrow_to_hjkl.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_html_filter = _libr_cons.r_cons_html_filter
    r_cons_html_filter.restype = ctypes.POINTER(ctypes.c_char)
    r_cons_html_filter.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_cons_rainbow_get = _libr_cons.r_cons_rainbow_get
    r_cons_rainbow_get.restype = ctypes.POINTER(ctypes.c_char)
    r_cons_rainbow_get.argtypes = [ctypes.c_int32, ctypes.c_int32, ctypes.c_bool]
except AttributeError:
    pass
try:
    r_cons_rainbow_free = _libr_cons.r_cons_rainbow_free
    r_cons_rainbow_free.restype = None
    r_cons_rainbow_free.argtypes = [ctypes.POINTER(struct_r_cons_context_t)]
except AttributeError:
    pass
try:
    r_cons_rainbow_new = _libr_cons.r_cons_rainbow_new
    r_cons_rainbow_new.restype = None
    r_cons_rainbow_new.argtypes = [ctypes.POINTER(struct_r_cons_context_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_fgets = _libr_cons.r_cons_fgets
    r_cons_fgets.restype = ctypes.c_int32
    r_cons_fgets.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
except AttributeError:
    pass
try:
    r_cons_hud = _libr_cons.r_cons_hud
    r_cons_hud.restype = ctypes.POINTER(ctypes.c_char)
    r_cons_hud.argtypes = [ctypes.POINTER(struct_r_list_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_hud_line = _libr_cons.r_cons_hud_line
    r_cons_hud_line.restype = ctypes.POINTER(ctypes.c_char)
    r_cons_hud_line.argtypes = [ctypes.POINTER(struct_r_list_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_hud_line_string = _libr_cons.r_cons_hud_line_string
    r_cons_hud_line_string.restype = ctypes.POINTER(ctypes.c_char)
    r_cons_hud_line_string.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_hud_path = _libr_cons.r_cons_hud_path
    r_cons_hud_path.restype = ctypes.POINTER(ctypes.c_char)
    r_cons_hud_path.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_hud_string = _libr_cons.r_cons_hud_string
    r_cons_hud_string.restype = ctypes.POINTER(ctypes.c_char)
    r_cons_hud_string.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_hud_file = _libr_cons.r_cons_hud_file
    r_cons_hud_file.restype = ctypes.POINTER(ctypes.c_char)
    r_cons_hud_file.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_get_buffer = _libr_cons.r_cons_get_buffer
    r_cons_get_buffer.restype = ctypes.POINTER(ctypes.c_char)
    r_cons_get_buffer.argtypes = []
except AttributeError:
    pass
try:
    r_cons_get_buffer_len = _libr_cons.r_cons_get_buffer_len
    r_cons_get_buffer_len.restype = ctypes.c_int32
    r_cons_get_buffer_len.argtypes = []
except AttributeError:
    pass
try:
    r_cons_grep_help = _libr_cons.r_cons_grep_help
    r_cons_grep_help.restype = None
    r_cons_grep_help.argtypes = []
except AttributeError:
    pass
try:
    r_cons_grep_parsecmd = _libr_cons.r_cons_grep_parsecmd
    r_cons_grep_parsecmd.restype = None
    r_cons_grep_parsecmd.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_grep_strip = _libr_cons.r_cons_grep_strip
    r_cons_grep_strip.restype = ctypes.POINTER(ctypes.c_char)
    r_cons_grep_strip.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_grep_process = _libr_cons.r_cons_grep_process
    r_cons_grep_process.restype = None
    r_cons_grep_process.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_grep_line = _libr_cons.r_cons_grep_line
    r_cons_grep_line.restype = ctypes.c_int32
    r_cons_grep_line.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_grepbuf = _libr_cons.r_cons_grepbuf
    r_cons_grepbuf.restype = None
    r_cons_grepbuf.argtypes = []
except AttributeError:
    pass
try:
    r_cons_rgb = _libraries['FIXME_STUB'].r_cons_rgb
    r_cons_rgb.restype = None
    r_cons_rgb.argtypes = [uint8_t, uint8_t, uint8_t, uint8_t]
except AttributeError:
    pass
try:
    r_cons_rgb_fgbg = _libraries['FIXME_STUB'].r_cons_rgb_fgbg
    r_cons_rgb_fgbg.restype = None
    r_cons_rgb_fgbg.argtypes = [uint8_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t]
except AttributeError:
    pass
try:
    r_cons_rgb_init = _libr_cons.r_cons_rgb_init
    r_cons_rgb_init.restype = None
    r_cons_rgb_init.argtypes = []
except AttributeError:
    pass
try:
    r_cons_rgb_str_mode = _libr_cons.r_cons_rgb_str_mode
    r_cons_rgb_str_mode.restype = ctypes.POINTER(ctypes.c_char)
    r_cons_rgb_str_mode.argtypes = [RConsColorMode, ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(struct_rcolor_t)]
except AttributeError:
    pass
try:
    r_cons_rgb_str = _libr_cons.r_cons_rgb_str
    r_cons_rgb_str.restype = ctypes.POINTER(ctypes.c_char)
    r_cons_rgb_str.argtypes = [ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(struct_rcolor_t)]
except AttributeError:
    pass
try:
    r_cons_rgb_str_off = _libr_cons.r_cons_rgb_str_off
    r_cons_rgb_str_off.restype = ctypes.POINTER(ctypes.c_char)
    r_cons_rgb_str_off.argtypes = [ctypes.POINTER(ctypes.c_char), size_t, uint64_t]
except AttributeError:
    pass
try:
    r_cons_color = _libr_cons.r_cons_color
    r_cons_color.restype = None
    r_cons_color.argtypes = [ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_color_random = _libr_cons.r_cons_color_random
    r_cons_color_random.restype = RColor
    r_cons_color_random.argtypes = [uint8_t]
except AttributeError:
    pass
try:
    r_cons_invert = _libr_cons.r_cons_invert
    r_cons_invert.restype = None
    r_cons_invert.argtypes = [ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_yesno = _libr_cons.r_cons_yesno
    r_cons_yesno.restype = ctypes.c_bool
    r_cons_yesno.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_input = _libr_cons.r_cons_input
    r_cons_input.restype = ctypes.POINTER(ctypes.c_char)
    r_cons_input.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_password = _libr_cons.r_cons_password
    r_cons_password.restype = ctypes.POINTER(ctypes.c_char)
    r_cons_password.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_set_cup = _libr_cons.r_cons_set_cup
    r_cons_set_cup.restype = ctypes.c_bool
    r_cons_set_cup.argtypes = [ctypes.c_bool]
except AttributeError:
    pass
try:
    r_cons_column = _libr_cons.r_cons_column
    r_cons_column.restype = None
    r_cons_column.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_get_column = _libr_cons.r_cons_get_column
    r_cons_get_column.restype = ctypes.c_int32
    r_cons_get_column.argtypes = []
except AttributeError:
    pass
try:
    r_cons_message = _libr_cons.r_cons_message
    r_cons_message.restype = ctypes.POINTER(ctypes.c_char)
    r_cons_message.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_set_title = _libr_cons.r_cons_set_title
    r_cons_set_title.restype = None
    r_cons_set_title.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_enable_mouse = _libr_cons.r_cons_enable_mouse
    r_cons_enable_mouse.restype = ctypes.c_bool
    r_cons_enable_mouse.argtypes = [ctypes.c_bool]
except AttributeError:
    pass
try:
    r_cons_enable_highlight = _libr_cons.r_cons_enable_highlight
    r_cons_enable_highlight.restype = None
    r_cons_enable_highlight.argtypes = [ctypes.c_bool]
except AttributeError:
    pass
try:
    r_cons_bind = _libr_cons.r_cons_bind
    r_cons_bind.restype = None
    r_cons_bind.argtypes = [ctypes.POINTER(struct_r_cons_bind_t)]
except AttributeError:
    pass
try:
    r_cons_get_rune = _libr_cons.r_cons_get_rune
    r_cons_get_rune.restype = ctypes.POINTER(ctypes.c_char)
    r_cons_get_rune.argtypes = [uint8_t]
except AttributeError:
    pass
class struct_RConsPixel(Structure):
    pass

struct_RConsPixel._pack_ = 1 # source:False
struct_RConsPixel._fields_ = [
    ('w', ctypes.c_int32),
    ('h', ctypes.c_int32),
    ('buf', ctypes.POINTER(ctypes.c_ubyte)),
    ('buf_size', ctypes.c_uint64),
]

RConsPixel = struct_RConsPixel
try:
    r_cons_pixel_new = _libr_cons.r_cons_pixel_new
    r_cons_pixel_new.restype = ctypes.POINTER(struct_RConsPixel)
    r_cons_pixel_new.argtypes = [ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_pixel_free = _libr_cons.r_cons_pixel_free
    r_cons_pixel_free.restype = None
    r_cons_pixel_free.argtypes = [ctypes.POINTER(struct_RConsPixel)]
except AttributeError:
    pass
try:
    r_cons_pixel_flush = _libr_cons.r_cons_pixel_flush
    r_cons_pixel_flush.restype = None
    r_cons_pixel_flush.argtypes = [ctypes.POINTER(struct_RConsPixel), ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_pixel_drain = _libr_cons.r_cons_pixel_drain
    r_cons_pixel_drain.restype = ctypes.POINTER(ctypes.c_char)
    r_cons_pixel_drain.argtypes = [ctypes.POINTER(struct_RConsPixel)]
except AttributeError:
    pass
try:
    r_cons_pixel_get = _libr_cons.r_cons_pixel_get
    r_cons_pixel_get.restype = uint8_t
    r_cons_pixel_get.argtypes = [ctypes.POINTER(struct_RConsPixel), ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_pixel_set = _libr_cons.r_cons_pixel_set
    r_cons_pixel_set.restype = None
    r_cons_pixel_set.argtypes = [ctypes.POINTER(struct_RConsPixel), ctypes.c_int32, ctypes.c_int32, uint8_t]
except AttributeError:
    pass
try:
    r_cons_pixel_sets = _libr_cons.r_cons_pixel_sets
    r_cons_pixel_sets.restype = None
    r_cons_pixel_sets.argtypes = [ctypes.POINTER(struct_RConsPixel), ctypes.c_int32, ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_cons_pixel_fill = _libr_cons.r_cons_pixel_fill
    r_cons_pixel_fill.restype = None
    r_cons_pixel_fill.argtypes = [ctypes.POINTER(struct_RConsPixel), ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_cons_pixel_tostring = _libr_cons.r_cons_pixel_tostring
    r_cons_pixel_tostring.restype = ctypes.POINTER(ctypes.c_char)
    r_cons_pixel_tostring.argtypes = [ctypes.POINTER(struct_RConsPixel)]
except AttributeError:
    pass
RSelWidget = struct_r_selection_widget_t
RLineHistory = struct_r_line_hist_t
RLineBuffer = struct_r_line_buffer_t
RLineHud = struct_r_hud_t
RLine = struct_r_line_t
RLineCompletion = struct_r_line_comp_t
RLineCompletionCb = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_line_comp_t), ctypes.POINTER(struct_r_line_buffer_t), RLinePromptType, ctypes.POINTER(None))
RLineEditorCb = ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))
RLineHistoryUpCb = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_line_t))
RLineHistoryDownCb = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(struct_r_line_t))
try:
    r_line_new = _libr_cons.r_line_new
    r_line_new.restype = ctypes.POINTER(struct_r_line_t)
    r_line_new.argtypes = []
except AttributeError:
    pass
try:
    r_line_singleton = _libr_cons.r_line_singleton
    r_line_singleton.restype = ctypes.POINTER(struct_r_line_t)
    r_line_singleton.argtypes = []
except AttributeError:
    pass
try:
    r_line_free = _libr_cons.r_line_free
    r_line_free.restype = None
    r_line_free.argtypes = []
except AttributeError:
    pass
try:
    r_line_get_prompt = _libr_cons.r_line_get_prompt
    r_line_get_prompt.restype = ctypes.POINTER(ctypes.c_char)
    r_line_get_prompt.argtypes = []
except AttributeError:
    pass
try:
    r_line_set_prompt = _libr_cons.r_line_set_prompt
    r_line_set_prompt.restype = None
    r_line_set_prompt.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_line_dietline_init = _libr_cons.r_line_dietline_init
    r_line_dietline_init.restype = ctypes.c_int32
    r_line_dietline_init.argtypes = []
except AttributeError:
    pass
try:
    r_line_clipboard_push = _libr_cons.r_line_clipboard_push
    r_line_clipboard_push.restype = None
    r_line_clipboard_push.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_line_hist_free = _libr_cons.r_line_hist_free
    r_line_hist_free.restype = None
    r_line_hist_free.argtypes = []
except AttributeError:
    pass
RLineReadCallback = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))
try:
    r_line_readline = _libr_cons.r_line_readline
    r_line_readline.restype = ctypes.POINTER(ctypes.c_char)
    r_line_readline.argtypes = []
except AttributeError:
    pass
try:
    r_line_readline_cb = _libr_cons.r_line_readline_cb
    r_line_readline_cb.restype = ctypes.POINTER(ctypes.c_char)
    r_line_readline_cb.argtypes = [RLineReadCallback, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_line_hist_load = _libr_cons.r_line_hist_load
    r_line_hist_load.restype = ctypes.c_bool
    r_line_hist_load.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_line_hist_add = _libr_cons.r_line_hist_add
    r_line_hist_add.restype = ctypes.c_int32
    r_line_hist_add.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_line_hist_save = _libr_cons.r_line_hist_save
    r_line_hist_save.restype = ctypes.c_bool
    r_line_hist_save.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_line_hist_label = _libraries['FIXME_STUB'].r_line_hist_label
    r_line_hist_label.restype = ctypes.c_int32
    r_line_hist_label.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_char))]
except AttributeError:
    pass
try:
    r_line_label_show = _libraries['FIXME_STUB'].r_line_label_show
    r_line_label_show.restype = None
    r_line_label_show.argtypes = []
except AttributeError:
    pass
try:
    r_line_hist_list = _libr_cons.r_line_hist_list
    r_line_hist_list.restype = ctypes.c_int32
    r_line_hist_list.argtypes = []
except AttributeError:
    pass
try:
    r_line_hist_get_size = _libr_cons.r_line_hist_get_size
    r_line_hist_get_size.restype = ctypes.c_int32
    r_line_hist_get_size.argtypes = []
except AttributeError:
    pass
try:
    r_line_hist_set_size = _libr_cons.r_line_hist_set_size
    r_line_hist_set_size.restype = None
    r_line_hist_set_size.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_line_hist_get = _libr_cons.r_line_hist_get
    r_line_hist_get.restype = ctypes.POINTER(ctypes.c_char)
    r_line_hist_get.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_line_set_hist_callback = _libr_cons.r_line_set_hist_callback
    r_line_set_hist_callback.restype = ctypes.c_int32
    r_line_set_hist_callback.argtypes = [ctypes.POINTER(struct_r_line_t), RLineHistoryUpCb, RLineHistoryDownCb]
except AttributeError:
    pass
try:
    r_line_hist_cmd_up = _libr_cons.r_line_hist_cmd_up
    r_line_hist_cmd_up.restype = ctypes.c_int32
    r_line_hist_cmd_up.argtypes = [ctypes.POINTER(struct_r_line_t)]
except AttributeError:
    pass
try:
    r_line_hist_cmd_down = _libr_cons.r_line_hist_cmd_down
    r_line_hist_cmd_down.restype = ctypes.c_int32
    r_line_hist_cmd_down.argtypes = [ctypes.POINTER(struct_r_line_t)]
except AttributeError:
    pass
try:
    r_line_completion_init = _libr_cons.r_line_completion_init
    r_line_completion_init.restype = None
    r_line_completion_init.argtypes = [ctypes.POINTER(struct_r_line_comp_t), size_t]
except AttributeError:
    pass
try:
    r_line_completion_fini = _libr_cons.r_line_completion_fini
    r_line_completion_fini.restype = None
    r_line_completion_fini.argtypes = [ctypes.POINTER(struct_r_line_comp_t)]
except AttributeError:
    pass
try:
    r_line_completion_push = _libr_cons.r_line_completion_push
    r_line_completion_push.restype = None
    r_line_completion_push.argtypes = [ctypes.POINTER(struct_r_line_comp_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_line_completion_set = _libr_cons.r_line_completion_set
    r_line_completion_set.restype = None
    r_line_completion_set.argtypes = [ctypes.POINTER(struct_r_line_comp_t), ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
except AttributeError:
    pass
try:
    r_line_completion_clear = _libr_cons.r_line_completion_clear
    r_line_completion_clear.restype = None
    r_line_completion_clear.argtypes = [ctypes.POINTER(struct_r_line_comp_t)]
except AttributeError:
    pass
RPanelsMenuCallback = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None))
class struct_r_panels_menu_item(Structure):
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

# values for enumeration 'RPanelsMode'
RPanelsMode__enumvalues = {
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
RPanelsMode = ctypes.c_uint32 # enum

# values for enumeration 'RPanelsFun'
RPanelsFun__enumvalues = {
    0: 'PANEL_FUN_SNOW',
    1: 'PANEL_FUN_SAKURA',
    2: 'PANEL_FUN_NOFUN',
}
PANEL_FUN_SNOW = 0
PANEL_FUN_SAKURA = 1
PANEL_FUN_NOFUN = 2
RPanelsFun = ctypes.c_uint32 # enum

# values for enumeration 'RPanelsLayout'
RPanelsLayout__enumvalues = {
    0: 'PANEL_LAYOUT_DEFAULT_STATIC',
    1: 'PANEL_LAYOUT_DEFAULT_DYNAMIC',
}
PANEL_LAYOUT_DEFAULT_STATIC = 0
PANEL_LAYOUT_DEFAULT_DYNAMIC = 1
RPanelsLayout = ctypes.c_uint32 # enum
class struct_RPanelsSnow(Structure):
    pass

struct_RPanelsSnow._pack_ = 1 # source:False
struct_RPanelsSnow._fields_ = [
    ('x', ctypes.c_int32),
    ('y', ctypes.c_int32),
    ('stuck', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 3),
]

RPanelsSnow = struct_RPanelsSnow
class struct_RModal(Structure):
    pass

struct_RModal._pack_ = 1 # source:False
struct_RModal._fields_ = [
    ('data', ctypes.POINTER(struct_RStrBuf)),
    ('pos', RPanelPos),
    ('idx', ctypes.c_int32),
    ('offset', ctypes.c_int32),
]

RModal = struct_RModal
class struct_r_panels_t(Structure):
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

RPanels = struct_r_panels_t

# values for enumeration 'RPanelsRootState'
RPanelsRootState__enumvalues = {
    0: 'DEFAULT',
    1: 'ROTATE',
    2: 'DEL',
    3: 'QUIT',
}
DEFAULT = 0
ROTATE = 1
DEL = 2
QUIT = 3
RPanelsRootState = ctypes.c_uint32 # enum
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
try:
    r_diff_version = _libraries['FIXME_STUB'].r_diff_version
    r_diff_version.restype = ctypes.POINTER(ctypes.c_char)
    r_diff_version.argtypes = []
except AttributeError:
    pass
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

# values for enumeration 'RLevOp'
RLevOp__enumvalues = {
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
RLevOp = ctypes.c_uint32 # enum
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
try:
    r_diff_new = _libr_util.r_diff_new
    r_diff_new.restype = ctypes.POINTER(struct_r_diff_t)
    r_diff_new.argtypes = []
except AttributeError:
    pass
try:
    r_diff_new_from = _libr_util.r_diff_new_from
    r_diff_new_from.restype = ctypes.POINTER(struct_r_diff_t)
    r_diff_new_from.argtypes = [uint64_t, uint64_t]
except AttributeError:
    pass
try:
    r_diff_free = _libr_util.r_diff_free
    r_diff_free.restype = None
    r_diff_free.argtypes = [ctypes.POINTER(struct_r_diff_t)]
except AttributeError:
    pass
try:
    r_diff_buffers = _libr_util.r_diff_buffers
    r_diff_buffers.restype = ctypes.c_int32
    r_diff_buffers.argtypes = [ctypes.POINTER(struct_r_diff_t), ctypes.POINTER(ctypes.c_ubyte), uint32_t, ctypes.POINTER(ctypes.c_ubyte), uint32_t]
except AttributeError:
    pass
try:
    r_diff_buffers_static = _libr_util.r_diff_buffers_static
    r_diff_buffers_static.restype = ctypes.c_int32
    r_diff_buffers_static.argtypes = [ctypes.POINTER(struct_r_diff_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_diff_buffers_radiff = _libraries['FIXME_STUB'].r_diff_buffers_radiff
    r_diff_buffers_radiff.restype = ctypes.c_int32
    r_diff_buffers_radiff.argtypes = [ctypes.POINTER(struct_r_diff_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_diff_buffers_delta = _libr_util.r_diff_buffers_delta
    r_diff_buffers_delta.restype = ctypes.c_int32
    r_diff_buffers_delta.argtypes = [ctypes.POINTER(struct_r_diff_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_diff_buffers_to_string = _libr_util.r_diff_buffers_to_string
    r_diff_buffers_to_string.restype = ctypes.POINTER(ctypes.c_char)
    r_diff_buffers_to_string.argtypes = [ctypes.POINTER(struct_r_diff_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_diff_set_callback = _libr_util.r_diff_set_callback
    r_diff_set_callback.restype = ctypes.c_int32
    r_diff_set_callback.argtypes = [ctypes.POINTER(struct_r_diff_t), RDiffCallback, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_diff_buffers_distance = _libr_util.r_diff_buffers_distance
    r_diff_buffers_distance.restype = ctypes.c_bool
    r_diff_buffers_distance.argtypes = [ctypes.POINTER(struct_r_diff_t), ctypes.POINTER(ctypes.c_ubyte), uint32_t, ctypes.POINTER(ctypes.c_ubyte), uint32_t, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_double)]
except AttributeError:
    pass
try:
    r_diff_buffers_distance_myers = _libr_util.r_diff_buffers_distance_myers
    r_diff_buffers_distance_myers.restype = ctypes.c_bool
    r_diff_buffers_distance_myers.argtypes = [ctypes.POINTER(struct_r_diff_t), ctypes.POINTER(ctypes.c_ubyte), uint32_t, ctypes.POINTER(ctypes.c_ubyte), uint32_t, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_double)]
except AttributeError:
    pass
try:
    r_diff_buffers_distance_levenshtein = _libr_util.r_diff_buffers_distance_levenshtein
    r_diff_buffers_distance_levenshtein.restype = ctypes.c_bool
    r_diff_buffers_distance_levenshtein.argtypes = [ctypes.POINTER(struct_r_diff_t), ctypes.POINTER(ctypes.c_ubyte), uint32_t, ctypes.POINTER(ctypes.c_ubyte), uint32_t, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_double)]
except AttributeError:
    pass
try:
    r_diff_buffers_unified = _libr_util.r_diff_buffers_unified
    r_diff_buffers_unified.restype = ctypes.POINTER(ctypes.c_char)
    r_diff_buffers_unified.argtypes = [ctypes.POINTER(struct_r_diff_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_diff_lines = _libraries['FIXME_STUB'].r_diff_lines
    r_diff_lines.restype = ctypes.c_int32
    r_diff_lines.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_diff_set_delta = _libr_util.r_diff_set_delta
    r_diff_set_delta.restype = ctypes.c_int32
    r_diff_set_delta.argtypes = [ctypes.POINTER(struct_r_diff_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_diff_gdiff = _libraries['FIXME_STUB'].r_diff_gdiff
    r_diff_gdiff.restype = ctypes.c_int32
    r_diff_gdiff.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_diffchar_new = _libr_util.r_diffchar_new
    r_diffchar_new.restype = ctypes.POINTER(struct_r_diffchar_t)
    r_diffchar_new.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
except AttributeError:
    pass
try:
    r_diffchar_print = _libr_util.r_diffchar_print
    r_diffchar_print.restype = None
    r_diffchar_print.argtypes = [ctypes.POINTER(struct_r_diffchar_t)]
except AttributeError:
    pass
try:
    r_diffchar_free = _libr_util.r_diffchar_free
    r_diffchar_free.restype = None
    r_diffchar_free.argtypes = [ctypes.POINTER(struct_r_diffchar_t)]
except AttributeError:
    pass
try:
    r_diff_levenshtein_path = _libr_util.r_diff_levenshtein_path
    r_diff_levenshtein_path.restype = int32_t
    r_diff_levenshtein_path.argtypes = [ctypes.POINTER(struct_r_lev_buf), ctypes.POINTER(struct_r_lev_buf), uint32_t, RLevMatches, ctypes.POINTER(ctypes.POINTER(RLevOp))]
except AttributeError:
    pass
try:
    r_punycode_encode = _libr_util.r_punycode_encode
    r_punycode_encode.restype = ctypes.POINTER(ctypes.c_char)
    r_punycode_encode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_punycode_decode = _libr_util.r_punycode_decode
    r_punycode_decode.restype = ctypes.POINTER(ctypes.c_char)
    r_punycode_decode.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
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
try:
    r_queue_new = _libr_util.r_queue_new
    r_queue_new.restype = ctypes.POINTER(struct_r_queue_t)
    r_queue_new.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_queue_free = _libr_util.r_queue_free
    r_queue_free.restype = None
    r_queue_free.argtypes = [ctypes.POINTER(struct_r_queue_t)]
except AttributeError:
    pass
try:
    r_queue_enqueue = _libr_util.r_queue_enqueue
    r_queue_enqueue.restype = ctypes.c_int32
    r_queue_enqueue.argtypes = [ctypes.POINTER(struct_r_queue_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_queue_dequeue = _libr_util.r_queue_dequeue
    r_queue_dequeue.restype = ctypes.POINTER(None)
    r_queue_dequeue.argtypes = [ctypes.POINTER(struct_r_queue_t)]
except AttributeError:
    pass
try:
    r_queue_is_empty = _libr_util.r_queue_is_empty
    r_queue_is_empty.restype = ctypes.c_int32
    r_queue_is_empty.argtypes = [ctypes.POINTER(struct_r_queue_t)]
except AttributeError:
    pass
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
try:
    r_range_new = _libr_util.r_range_new
    r_range_new.restype = ctypes.POINTER(struct_r_range_t)
    r_range_new.argtypes = []
except AttributeError:
    pass
try:
    r_range_new_from_string = _libr_util.r_range_new_from_string
    r_range_new_from_string.restype = ctypes.POINTER(struct_r_range_t)
    r_range_new_from_string.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_range_free = _libr_util.r_range_free
    r_range_free.restype = ctypes.POINTER(struct_r_range_t)
    r_range_free.argtypes = [ctypes.POINTER(struct_r_range_t)]
except AttributeError:
    pass
try:
    r_range_item_get = _libr_util.r_range_item_get
    r_range_item_get.restype = ctypes.POINTER(struct_r_range_item_t)
    r_range_item_get.argtypes = [ctypes.POINTER(struct_r_range_t), uint64_t]
except AttributeError:
    pass
try:
    r_range_size = _libr_util.r_range_size
    r_range_size.restype = uint64_t
    r_range_size.argtypes = [ctypes.POINTER(struct_r_range_t)]
except AttributeError:
    pass
try:
    r_range_add_from_string = _libr_util.r_range_add_from_string
    r_range_add_from_string.restype = ctypes.c_int32
    r_range_add_from_string.argtypes = [ctypes.POINTER(struct_r_range_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_range_add = _libr_util.r_range_add
    r_range_add.restype = ctypes.POINTER(struct_r_range_item_t)
    r_range_add.argtypes = [ctypes.POINTER(struct_r_range_t), uint64_t, uint64_t, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_range_sub = _libr_util.r_range_sub
    r_range_sub.restype = ctypes.c_int32
    r_range_sub.argtypes = [ctypes.POINTER(struct_r_range_t), uint64_t, uint64_t]
except AttributeError:
    pass
try:
    r_range_merge = _libraries['FIXME_STUB'].r_range_merge
    r_range_merge.restype = None
    r_range_merge.argtypes = [ctypes.POINTER(struct_r_range_t), ctypes.POINTER(struct_r_range_t)]
except AttributeError:
    pass
try:
    r_range_contains = _libr_util.r_range_contains
    r_range_contains.restype = ctypes.c_int32
    r_range_contains.argtypes = [ctypes.POINTER(struct_r_range_t), uint64_t]
except AttributeError:
    pass
try:
    r_range_sort = _libr_util.r_range_sort
    r_range_sort.restype = ctypes.c_int32
    r_range_sort.argtypes = [ctypes.POINTER(struct_r_range_t)]
except AttributeError:
    pass
try:
    r_range_percent = _libr_util.r_range_percent
    r_range_percent.restype = None
    r_range_percent.argtypes = [ctypes.POINTER(struct_r_range_t)]
except AttributeError:
    pass
try:
    r_range_list = _libr_util.r_range_list
    r_range_list.restype = ctypes.c_int32
    r_range_list.argtypes = [ctypes.POINTER(struct_r_range_t), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_range_get_n = _libr_util.r_range_get_n
    r_range_get_n.restype = ctypes.c_int32
    r_range_get_n.argtypes = [ctypes.POINTER(struct_r_range_t), ctypes.c_int32, ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint64)]
except AttributeError:
    pass
try:
    r_range_inverse = _libr_util.r_range_inverse
    r_range_inverse.restype = ctypes.POINTER(struct_r_range_t)
    r_range_inverse.argtypes = [ctypes.POINTER(struct_r_range_t), uint64_t, uint64_t, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_range_overlap = _libr_util.r_range_overlap
    r_range_overlap.restype = ctypes.c_int32
    r_range_overlap.argtypes = [uint64_t, uint64_t, uint64_t, uint64_t, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
class struct_r_space_t(Structure):
    pass

struct_r_space_t._pack_ = 1 # source:False
struct_r_space_t._fields_ = [
    ('name', ctypes.POINTER(ctypes.c_char)),
]

RSpace = struct_r_space_t

# values for enumeration 'RSpaceEventType'
RSpaceEventType__enumvalues = {
    1: 'R_SPACE_EVENT_COUNT',
    2: 'R_SPACE_EVENT_RENAME',
    3: 'R_SPACE_EVENT_UNSET',
}
R_SPACE_EVENT_COUNT = 1
R_SPACE_EVENT_RENAME = 2
R_SPACE_EVENT_UNSET = 3
RSpaceEventType = ctypes.c_uint32 # enum
class struct_r_space_event_t(Structure):
    pass

class union_r_space_event_t_data(Union):
    pass

class struct_r_space_event_t_0_count(Structure):
    pass

struct_r_space_event_t_0_count._pack_ = 1 # source:False
struct_r_space_event_t_0_count._fields_ = [
    ('space', ctypes.POINTER(struct_r_space_t)),
]

class struct_r_space_event_t_0_unset(Structure):
    pass

struct_r_space_event_t_0_unset._pack_ = 1 # source:False
struct_r_space_event_t_0_unset._fields_ = [
    ('space', ctypes.POINTER(struct_r_space_t)),
]

class struct_r_space_event_t_0_rename(Structure):
    pass

struct_r_space_event_t_0_rename._pack_ = 1 # source:False
struct_r_space_event_t_0_rename._fields_ = [
    ('space', ctypes.POINTER(struct_r_space_t)),
    ('oldname', ctypes.POINTER(ctypes.c_char)),
    ('newname', ctypes.POINTER(ctypes.c_char)),
]

union_r_space_event_t_data._pack_ = 1 # source:False
union_r_space_event_t_data._fields_ = [
    ('count', struct_r_space_event_t_0_count),
    ('unset', struct_r_space_event_t_0_unset),
    ('rename', struct_r_space_event_t_0_rename),
]

struct_r_space_event_t._pack_ = 1 # source:False
struct_r_space_event_t._fields_ = [
    ('data', union_r_space_event_t_data),
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
    ('spaces', ctypes.POINTER(struct_r_crbtree_t)),
    ('spacestack', ctypes.POINTER(struct_r_list_t)),
    ('event', ctypes.POINTER(struct_r_event_t)),
]

RSpaces = struct_r_spaces_t
try:
    r_spaces_new = _libr_util.r_spaces_new
    r_spaces_new.restype = ctypes.POINTER(struct_r_spaces_t)
    r_spaces_new.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_spaces_init = _libr_util.r_spaces_init
    r_spaces_init.restype = ctypes.c_bool
    r_spaces_init.argtypes = [ctypes.POINTER(struct_r_spaces_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_spaces_fini = _libr_util.r_spaces_fini
    r_spaces_fini.restype = None
    r_spaces_fini.argtypes = [ctypes.POINTER(struct_r_spaces_t)]
except AttributeError:
    pass
try:
    r_spaces_free = _libr_util.r_spaces_free
    r_spaces_free.restype = None
    r_spaces_free.argtypes = [ctypes.POINTER(struct_r_spaces_t)]
except AttributeError:
    pass
try:
    r_spaces_purge = _libr_util.r_spaces_purge
    r_spaces_purge.restype = None
    r_spaces_purge.argtypes = [ctypes.POINTER(struct_r_spaces_t)]
except AttributeError:
    pass
try:
    r_spaces_get = _libr_util.r_spaces_get
    r_spaces_get.restype = ctypes.POINTER(struct_r_space_t)
    r_spaces_get.argtypes = [ctypes.POINTER(struct_r_spaces_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_spaces_add = _libr_util.r_spaces_add
    r_spaces_add.restype = ctypes.POINTER(struct_r_space_t)
    r_spaces_add.argtypes = [ctypes.POINTER(struct_r_spaces_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_spaces_set = _libr_util.r_spaces_set
    r_spaces_set.restype = ctypes.POINTER(struct_r_space_t)
    r_spaces_set.argtypes = [ctypes.POINTER(struct_r_spaces_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_spaces_unset = _libr_util.r_spaces_unset
    r_spaces_unset.restype = ctypes.c_bool
    r_spaces_unset.argtypes = [ctypes.POINTER(struct_r_spaces_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_spaces_rename = _libr_util.r_spaces_rename
    r_spaces_rename.restype = ctypes.c_bool
    r_spaces_rename.argtypes = [ctypes.POINTER(struct_r_spaces_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_spaces_count = _libr_util.r_spaces_count
    r_spaces_count.restype = ctypes.c_int32
    r_spaces_count.argtypes = [ctypes.POINTER(struct_r_spaces_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_spaces_push = _libr_util.r_spaces_push
    r_spaces_push.restype = ctypes.c_bool
    r_spaces_push.argtypes = [ctypes.POINTER(struct_r_spaces_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_spaces_pop = _libr_util.r_spaces_pop
    r_spaces_pop.restype = ctypes.c_bool
    r_spaces_pop.argtypes = [ctypes.POINTER(struct_r_spaces_t)]
except AttributeError:
    pass
try:
    r_spaces_current = _libraries['FIXME_STUB'].r_spaces_current
    r_spaces_current.restype = ctypes.POINTER(struct_r_space_t)
    r_spaces_current.argtypes = [ctypes.POINTER(struct_r_spaces_t)]
except AttributeError:
    pass
try:
    r_spaces_current_name = _libraries['FIXME_STUB'].r_spaces_current_name
    r_spaces_current_name.restype = ctypes.POINTER(ctypes.c_char)
    r_spaces_current_name.argtypes = [ctypes.POINTER(struct_r_spaces_t)]
except AttributeError:
    pass
try:
    r_spaces_is_empty = _libraries['FIXME_STUB'].r_spaces_is_empty
    r_spaces_is_empty.restype = ctypes.c_bool
    r_spaces_is_empty.argtypes = [ctypes.POINTER(struct_r_spaces_t)]
except AttributeError:
    pass
RSpaceIter = struct_r_crbtree_node
try:
    ret_ascii_table = _libr_util.ret_ascii_table
    ret_ascii_table.restype = ctypes.POINTER(ctypes.c_char)
    ret_ascii_table.argtypes = []
except AttributeError:
    pass
class struct_RStrpool(Structure):
    pass

struct_RStrpool._pack_ = 1 # source:False
struct_RStrpool._fields_ = [
    ('str', ctypes.POINTER(ctypes.c_char)),
    ('len', ctypes.c_int32),
    ('size', ctypes.c_int32),
]

RStrpool = struct_RStrpool
try:
    r_strpool_new = _libr_util.r_strpool_new
    r_strpool_new.restype = ctypes.POINTER(struct_RStrpool)
    r_strpool_new.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_strpool_alloc = _libr_util.r_strpool_alloc
    r_strpool_alloc.restype = ctypes.POINTER(ctypes.c_char)
    r_strpool_alloc.argtypes = [ctypes.POINTER(struct_RStrpool), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_strpool_memcat = _libr_util.r_strpool_memcat
    r_strpool_memcat.restype = ctypes.c_int32
    r_strpool_memcat.argtypes = [ctypes.POINTER(struct_RStrpool), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_strpool_ansi_chop = _libr_util.r_strpool_ansi_chop
    r_strpool_ansi_chop.restype = ctypes.c_int32
    r_strpool_ansi_chop.argtypes = [ctypes.POINTER(struct_RStrpool), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_strpool_append = _libr_util.r_strpool_append
    r_strpool_append.restype = ctypes.c_int32
    r_strpool_append.argtypes = [ctypes.POINTER(struct_RStrpool), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_strpool_free = _libr_util.r_strpool_free
    r_strpool_free.restype = None
    r_strpool_free.argtypes = [ctypes.POINTER(struct_RStrpool)]
except AttributeError:
    pass
try:
    r_strpool_fit = _libr_util.r_strpool_fit
    r_strpool_fit.restype = ctypes.c_int32
    r_strpool_fit.argtypes = [ctypes.POINTER(struct_RStrpool)]
except AttributeError:
    pass
try:
    r_strpool_get = _libr_util.r_strpool_get
    r_strpool_get.restype = ctypes.POINTER(ctypes.c_char)
    r_strpool_get.argtypes = [ctypes.POINTER(struct_RStrpool), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_strpool_get_i = _libr_util.r_strpool_get_i
    r_strpool_get_i.restype = ctypes.POINTER(ctypes.c_char)
    r_strpool_get_i.argtypes = [ctypes.POINTER(struct_RStrpool), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_strpool_get_index = _libr_util.r_strpool_get_index
    r_strpool_get_index.restype = ctypes.c_int32
    r_strpool_get_index.argtypes = [ctypes.POINTER(struct_RStrpool), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_strpool_next = _libr_util.r_strpool_next
    r_strpool_next.restype = ctypes.POINTER(ctypes.c_char)
    r_strpool_next.argtypes = [ctypes.POINTER(struct_RStrpool), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_strpool_slice = _libr_util.r_strpool_slice
    r_strpool_slice.restype = ctypes.POINTER(ctypes.c_char)
    r_strpool_slice.argtypes = [ctypes.POINTER(struct_RStrpool), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_strpool_empty = _libr_util.r_strpool_empty
    r_strpool_empty.restype = ctypes.POINTER(ctypes.c_char)
    r_strpool_empty.argtypes = [ctypes.POINTER(struct_RStrpool)]
except AttributeError:
    pass
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
try:
    r_tree_new = _libr_util.r_tree_new
    r_tree_new.restype = ctypes.POINTER(struct_r_tree_t)
    r_tree_new.argtypes = []
except AttributeError:
    pass
try:
    r_tree_add_node = _libr_util.r_tree_add_node
    r_tree_add_node.restype = ctypes.POINTER(struct_r_tree_node_t)
    r_tree_add_node.argtypes = [ctypes.POINTER(struct_r_tree_t), ctypes.POINTER(struct_r_tree_node_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_tree_reset = _libr_util.r_tree_reset
    r_tree_reset.restype = None
    r_tree_reset.argtypes = [ctypes.POINTER(struct_r_tree_t)]
except AttributeError:
    pass
try:
    r_tree_free = _libr_util.r_tree_free
    r_tree_free.restype = None
    r_tree_free.argtypes = [ctypes.POINTER(struct_r_tree_t)]
except AttributeError:
    pass
try:
    r_tree_dfs = _libr_util.r_tree_dfs
    r_tree_dfs.restype = None
    r_tree_dfs.argtypes = [ctypes.POINTER(struct_r_tree_t), ctypes.POINTER(struct_r_tree_visitor_t)]
except AttributeError:
    pass
try:
    r_tree_bfs = _libr_util.r_tree_bfs
    r_tree_bfs.restype = None
    r_tree_bfs.argtypes = [ctypes.POINTER(struct_r_tree_t), ctypes.POINTER(struct_r_tree_visitor_t)]
except AttributeError:
    pass
try:
    r_uleb128 = _libr_util.r_uleb128
    r_uleb128.restype = ctypes.POINTER(ctypes.c_ubyte)
    r_uleb128.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
except AttributeError:
    pass
try:
    r_uleb128_decode = _libr_util.r_uleb128_decode
    r_uleb128_decode.restype = ctypes.POINTER(ctypes.c_ubyte)
    r_uleb128_decode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_uint64)]
except AttributeError:
    pass
try:
    r_uleb128_len = _libr_util.r_uleb128_len
    r_uleb128_len.restype = ctypes.c_int32
    r_uleb128_len.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_uleb128_encode = _libr_util.r_uleb128_encode
    r_uleb128_encode.restype = ctypes.POINTER(ctypes.c_ubyte)
    r_uleb128_encode.argtypes = [uint64_t, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_leb128 = _libr_util.r_leb128
    r_leb128.restype = ctypes.POINTER(ctypes.c_ubyte)
    r_leb128.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_int64)]
except AttributeError:
    pass
try:
    r_sleb128 = _libr_util.r_sleb128
    r_sleb128.restype = int64_t
    r_sleb128.argtypes = [ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)), ctypes.POINTER(ctypes.c_ubyte)]
except AttributeError:
    pass
try:
    read_u32_leb128 = _libr_util.read_u32_leb128
    read_u32_leb128.restype = size_t
    read_u32_leb128.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    read_i32_leb128 = _libr_util.read_i32_leb128
    read_i32_leb128.restype = size_t
    read_i32_leb128.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    read_u64_leb128 = _libr_util.read_u64_leb128
    read_u64_leb128.restype = size_t
    read_u64_leb128.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_uint64)]
except AttributeError:
    pass
try:
    read_i64_leb128 = _libr_util.read_i64_leb128
    read_i64_leb128.restype = size_t
    read_i64_leb128.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_int64)]
except AttributeError:
    pass
class struct_RUtfBlock(Structure):
    pass

struct_RUtfBlock._pack_ = 1 # source:False
struct_RUtfBlock._fields_ = [
    ('from_', ctypes.c_uint32),
    ('to', ctypes.c_uint32),
    ('name', ctypes.POINTER(ctypes.c_char)),
]

RUtfBlock = struct_RUtfBlock
RRune = ctypes.c_uint32
try:
    r_utf8_encode = _libr_util.r_utf8_encode
    r_utf8_encode.restype = ctypes.c_int32
    r_utf8_encode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), RRune]
except AttributeError:
    pass
try:
    r_utf8_decode = _libr_util.r_utf8_decode
    r_utf8_decode.restype = ctypes.c_int32
    r_utf8_decode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    r_utf8_encode_str = _libr_util.r_utf8_encode_str
    r_utf8_encode_str.restype = ctypes.c_int32
    r_utf8_encode_str.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_utf8_size = _libr_util.r_utf8_size
    r_utf8_size.restype = ctypes.c_int32
    r_utf8_size.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
except AttributeError:
    pass
try:
    r_utf8_strlen = _libr_util.r_utf8_strlen
    r_utf8_strlen.restype = ctypes.c_int32
    r_utf8_strlen.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
except AttributeError:
    pass
try:
    r_isprint = _libr_util.r_isprint
    r_isprint.restype = ctypes.c_int32
    r_isprint.argtypes = [RRune]
except AttributeError:
    pass
try:
    r_utf16_to_utf8_l = _libraries['FIXME_STUB'].r_utf16_to_utf8_l
    r_utf16_to_utf8_l.restype = ctypes.POINTER(ctypes.c_char)
    r_utf16_to_utf8_l.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_utf_block_name = _libr_util.r_utf_block_name
    r_utf_block_name.restype = ctypes.POINTER(ctypes.c_char)
    r_utf_block_name.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_utf8_to_utf16_l = _libraries['FIXME_STUB'].r_utf8_to_utf16_l
    r_utf8_to_utf16_l.restype = ctypes.POINTER(ctypes.c_int32)
    r_utf8_to_utf16_l.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_utf_block_idx = _libr_util.r_utf_block_idx
    r_utf_block_idx.restype = ctypes.c_int32
    r_utf_block_idx.argtypes = [RRune]
except AttributeError:
    pass
try:
    r_utf_block_list = _libr_util.r_utf_block_list
    r_utf_block_list.restype = ctypes.POINTER(ctypes.c_int32)
    r_utf_block_list.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.POINTER(ctypes.c_int32))]
except AttributeError:
    pass
try:
    r_utf_bom_encoding = _libr_util.r_utf_bom_encoding
    r_utf_bom_encoding.restype = RStrEnc
    r_utf_bom_encoding.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_utf16_decode = _libr_util.r_utf16_decode
    r_utf16_decode.restype = ctypes.c_int32
    r_utf16_decode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_bool]
except AttributeError:
    pass
try:
    r_utf16le_decode = _libr_util.r_utf16le_decode
    r_utf16le_decode.restype = ctypes.c_int32
    r_utf16le_decode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    r_utf16be_decode = _libr_util.r_utf16be_decode
    r_utf16be_decode.restype = ctypes.c_int32
    r_utf16be_decode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    r_utf16le_encode = _libr_util.r_utf16le_encode
    r_utf16le_encode.restype = ctypes.c_int32
    r_utf16le_encode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), RRune]
except AttributeError:
    pass
try:
    r_utf32_decode = _libr_util.r_utf32_decode
    r_utf32_decode.restype = ctypes.c_int32
    r_utf32_decode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_bool]
except AttributeError:
    pass
try:
    r_utf32le_decode = _libr_util.r_utf32le_decode
    r_utf32le_decode.restype = ctypes.c_int32
    r_utf32le_decode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
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
try:
    r_id_pool_new = _libr_util.r_id_pool_new
    r_id_pool_new.restype = ctypes.POINTER(struct_r_id_pool_t)
    r_id_pool_new.argtypes = [uint32_t, uint32_t]
except AttributeError:
    pass
try:
    r_id_pool_grab_id = _libr_util.r_id_pool_grab_id
    r_id_pool_grab_id.restype = ctypes.c_bool
    r_id_pool_grab_id.argtypes = [ctypes.POINTER(struct_r_id_pool_t), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    r_id_pool_kick_id = _libr_util.r_id_pool_kick_id
    r_id_pool_kick_id.restype = ctypes.c_bool
    r_id_pool_kick_id.argtypes = [ctypes.POINTER(struct_r_id_pool_t), uint32_t]
except AttributeError:
    pass
try:
    r_id_pool_free = _libr_util.r_id_pool_free
    r_id_pool_free.restype = None
    r_id_pool_free.argtypes = [ctypes.POINTER(struct_r_id_pool_t)]
except AttributeError:
    pass
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
try:
    r_id_storage_new = _libr_util.r_id_storage_new
    r_id_storage_new.restype = ctypes.POINTER(struct_r_id_storage_t)
    r_id_storage_new.argtypes = [uint32_t, uint32_t]
except AttributeError:
    pass
try:
    r_id_storage_set = _libr_util.r_id_storage_set
    r_id_storage_set.restype = ctypes.c_bool
    r_id_storage_set.argtypes = [ctypes.POINTER(struct_r_id_storage_t), ctypes.POINTER(None), uint32_t]
except AttributeError:
    pass
try:
    r_id_storage_add = _libr_util.r_id_storage_add
    r_id_storage_add.restype = ctypes.c_bool
    r_id_storage_add.argtypes = [ctypes.POINTER(struct_r_id_storage_t), ctypes.POINTER(None), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    r_id_storage_get = _libr_util.r_id_storage_get
    r_id_storage_get.restype = ctypes.POINTER(None)
    r_id_storage_get.argtypes = [ctypes.POINTER(struct_r_id_storage_t), uint32_t]
except AttributeError:
    pass
try:
    r_id_storage_get_next = _libr_util.r_id_storage_get_next
    r_id_storage_get_next.restype = ctypes.c_bool
    r_id_storage_get_next.argtypes = [ctypes.POINTER(struct_r_id_storage_t), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    r_id_storage_get_prev = _libr_util.r_id_storage_get_prev
    r_id_storage_get_prev.restype = ctypes.c_bool
    r_id_storage_get_prev.argtypes = [ctypes.POINTER(struct_r_id_storage_t), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    r_id_storage_delete = _libr_util.r_id_storage_delete
    r_id_storage_delete.restype = None
    r_id_storage_delete.argtypes = [ctypes.POINTER(struct_r_id_storage_t), uint32_t]
except AttributeError:
    pass
try:
    r_id_storage_take = _libr_util.r_id_storage_take
    r_id_storage_take.restype = ctypes.POINTER(None)
    r_id_storage_take.argtypes = [ctypes.POINTER(struct_r_id_storage_t), uint32_t]
except AttributeError:
    pass
try:
    r_id_storage_foreach = _libr_util.r_id_storage_foreach
    r_id_storage_foreach.restype = ctypes.c_bool
    r_id_storage_foreach.argtypes = [ctypes.POINTER(struct_r_id_storage_t), RIDStorageForeachCb, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_id_storage_free = _libr_util.r_id_storage_free
    r_id_storage_free.restype = None
    r_id_storage_free.argtypes = [ctypes.POINTER(struct_r_id_storage_t)]
except AttributeError:
    pass
try:
    r_id_storage_list = _libr_util.r_id_storage_list
    r_id_storage_list.restype = ctypes.POINTER(struct_r_list_t)
    r_id_storage_list.argtypes = [ctypes.POINTER(struct_r_id_storage_t)]
except AttributeError:
    pass
try:
    r_id_storage_get_lowest = _libr_util.r_id_storage_get_lowest
    r_id_storage_get_lowest.restype = ctypes.c_bool
    r_id_storage_get_lowest.argtypes = [ctypes.POINTER(struct_r_id_storage_t), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    r_id_storage_get_highest = _libr_util.r_id_storage_get_highest
    r_id_storage_get_highest.restype = ctypes.c_bool
    r_id_storage_get_highest.argtypes = [ctypes.POINTER(struct_r_id_storage_t), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
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
try:
    r_oids_new = _libr_util.r_oids_new
    r_oids_new.restype = ctypes.POINTER(struct_r_ordered_id_storage_t)
    r_oids_new.argtypes = [uint32_t, uint32_t]
except AttributeError:
    pass
try:
    r_oids_get = _libr_util.r_oids_get
    r_oids_get.restype = ctypes.POINTER(None)
    r_oids_get.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), uint32_t]
except AttributeError:
    pass
try:
    r_oids_oget = _libr_util.r_oids_oget
    r_oids_oget.restype = ctypes.POINTER(None)
    r_oids_oget.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), uint32_t]
except AttributeError:
    pass
try:
    r_oids_get_id = _libr_util.r_oids_get_id
    r_oids_get_id.restype = ctypes.c_bool
    r_oids_get_id.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), uint32_t, ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    r_oids_get_od = _libr_util.r_oids_get_od
    r_oids_get_od.restype = ctypes.c_bool
    r_oids_get_od.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), uint32_t, ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    r_oids_to_front = _libr_util.r_oids_to_front
    r_oids_to_front.restype = ctypes.c_bool
    r_oids_to_front.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), uint32_t]
except AttributeError:
    pass
try:
    r_oids_to_rear = _libr_util.r_oids_to_rear
    r_oids_to_rear.restype = ctypes.c_bool
    r_oids_to_rear.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), uint32_t]
except AttributeError:
    pass
try:
    r_oids_delete = _libr_util.r_oids_delete
    r_oids_delete.restype = None
    r_oids_delete.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), uint32_t]
except AttributeError:
    pass
try:
    r_oids_odelete = _libr_util.r_oids_odelete
    r_oids_odelete.restype = None
    r_oids_odelete.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), uint32_t]
except AttributeError:
    pass
try:
    r_oids_free = _libr_util.r_oids_free
    r_oids_free.restype = None
    r_oids_free.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t)]
except AttributeError:
    pass
try:
    r_oids_add = _libr_util.r_oids_add
    r_oids_add.restype = ctypes.c_bool
    r_oids_add.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), ctypes.POINTER(None), ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
except AttributeError:
    pass
try:
    r_oids_take = _libr_util.r_oids_take
    r_oids_take.restype = ctypes.POINTER(None)
    r_oids_take.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), uint32_t]
except AttributeError:
    pass
try:
    r_oids_otake = _libr_util.r_oids_otake
    r_oids_otake.restype = ctypes.POINTER(None)
    r_oids_otake.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), uint32_t]
except AttributeError:
    pass
try:
    r_oids_foreach = _libr_util.r_oids_foreach
    r_oids_foreach.restype = ctypes.c_bool
    r_oids_foreach.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), RIDStorageForeachCb, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_oids_foreach_prev = _libr_util.r_oids_foreach_prev
    r_oids_foreach_prev.restype = ctypes.c_bool
    r_oids_foreach_prev.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), RIDStorageForeachCb, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_oids_insert = _libr_util.r_oids_insert
    r_oids_insert.restype = ctypes.c_bool
    r_oids_insert.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), ctypes.POINTER(None), ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_oids_sort = _libr_util.r_oids_sort
    r_oids_sort.restype = ctypes.c_bool
    r_oids_sort.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_oids_find = _libr_util.r_oids_find
    r_oids_find.restype = uint32_t
    r_oids_find.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t), ctypes.POINTER(None), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_oids_last = _libr_util.r_oids_last
    r_oids_last.restype = ctypes.POINTER(None)
    r_oids_last.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t)]
except AttributeError:
    pass
try:
    r_oids_first = _libr_util.r_oids_first
    r_oids_first.restype = ctypes.POINTER(None)
    r_oids_first.argtypes = [ctypes.POINTER(struct_r_ordered_id_storage_t)]
except AttributeError:
    pass
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
try:
    r_asn1_create_object = _libr_util.r_asn1_create_object
    r_asn1_create_object.restype = ctypes.POINTER(struct_r_asn1_object_t)
    r_asn1_create_object.argtypes = [ctypes.POINTER(ctypes.c_ubyte), uint32_t, ctypes.POINTER(ctypes.c_ubyte)]
except AttributeError:
    pass
try:
    r_asn1_create_binary = _libr_util.r_asn1_create_binary
    r_asn1_create_binary.restype = ctypes.POINTER(struct_r_asn1_bin_t)
    r_asn1_create_binary.argtypes = [ctypes.POINTER(ctypes.c_ubyte), uint32_t]
except AttributeError:
    pass
try:
    r_asn1_create_string = _libr_util.r_asn1_create_string
    r_asn1_create_string.restype = ctypes.POINTER(struct_r_asn1_string_t)
    r_asn1_create_string.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_bool, uint32_t]
except AttributeError:
    pass
try:
    r_asn1_stringify_bits = _libr_util.r_asn1_stringify_bits
    r_asn1_stringify_bits.restype = ctypes.POINTER(struct_r_asn1_string_t)
    r_asn1_stringify_bits.argtypes = [ctypes.POINTER(ctypes.c_ubyte), uint32_t]
except AttributeError:
    pass
try:
    r_asn1_stringify_utctime = _libr_util.r_asn1_stringify_utctime
    r_asn1_stringify_utctime.restype = ctypes.POINTER(struct_r_asn1_string_t)
    r_asn1_stringify_utctime.argtypes = [ctypes.POINTER(ctypes.c_ubyte), uint32_t]
except AttributeError:
    pass
try:
    r_asn1_stringify_time = _libr_util.r_asn1_stringify_time
    r_asn1_stringify_time.restype = ctypes.POINTER(struct_r_asn1_string_t)
    r_asn1_stringify_time.argtypes = [ctypes.POINTER(ctypes.c_ubyte), uint32_t]
except AttributeError:
    pass
try:
    r_asn1_stringify_integer = _libr_util.r_asn1_stringify_integer
    r_asn1_stringify_integer.restype = ctypes.POINTER(struct_r_asn1_string_t)
    r_asn1_stringify_integer.argtypes = [ctypes.POINTER(ctypes.c_ubyte), uint32_t]
except AttributeError:
    pass
try:
    r_asn1_stringify_string = _libr_util.r_asn1_stringify_string
    r_asn1_stringify_string.restype = ctypes.POINTER(struct_r_asn1_string_t)
    r_asn1_stringify_string.argtypes = [ctypes.POINTER(ctypes.c_ubyte), uint32_t]
except AttributeError:
    pass
try:
    r_asn1_stringify_bytes = _libr_util.r_asn1_stringify_bytes
    r_asn1_stringify_bytes.restype = ctypes.POINTER(struct_r_asn1_string_t)
    r_asn1_stringify_bytes.argtypes = [ctypes.POINTER(ctypes.c_ubyte), uint32_t]
except AttributeError:
    pass
try:
    r_asn1_stringify_boolean = _libr_util.r_asn1_stringify_boolean
    r_asn1_stringify_boolean.restype = ctypes.POINTER(struct_r_asn1_string_t)
    r_asn1_stringify_boolean.argtypes = [ctypes.POINTER(ctypes.c_ubyte), uint32_t]
except AttributeError:
    pass
try:
    r_asn1_stringify_oid = _libr_util.r_asn1_stringify_oid
    r_asn1_stringify_oid.restype = ctypes.POINTER(struct_r_asn1_string_t)
    r_asn1_stringify_oid.argtypes = [ctypes.POINTER(ctypes.c_ubyte), uint32_t]
except AttributeError:
    pass
try:
    r_asn1_free_object = _libr_util.r_asn1_free_object
    r_asn1_free_object.restype = None
    r_asn1_free_object.argtypes = [ctypes.POINTER(struct_r_asn1_object_t)]
except AttributeError:
    pass
try:
    r_asn1_to_string = _libr_util.r_asn1_to_string
    r_asn1_to_string.restype = ctypes.POINTER(ctypes.c_char)
    r_asn1_to_string.argtypes = [ctypes.POINTER(struct_r_asn1_object_t), uint32_t, ctypes.POINTER(struct_RStrBuf)]
except AttributeError:
    pass
try:
    r_asn1_free_string = _libr_util.r_asn1_free_string
    r_asn1_free_string.restype = None
    r_asn1_free_string.argtypes = [ctypes.POINTER(struct_r_asn1_string_t)]
except AttributeError:
    pass
try:
    r_asn1_free_binary = _libr_util.r_asn1_free_binary
    r_asn1_free_binary.restype = None
    r_asn1_free_binary.argtypes = [ctypes.POINTER(struct_r_asn1_bin_t)]
except AttributeError:
    pass
try:
    asn1_setformat = _libr_util.asn1_setformat
    asn1_setformat.restype = None
    asn1_setformat.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
class struct_r_bplist_t(Structure):
    pass

struct_r_bplist_t._pack_ = 1 # source:False
struct_r_bplist_t._fields_ = [
    ('data', ctypes.POINTER(ctypes.c_char)),
    ('size', ctypes.c_uint64),
    ('num_objects', ctypes.c_uint64),
    ('ref_size', ctypes.c_ubyte),
    ('offset_size', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte * 6),
    ('offset_table', ctypes.POINTER(ctypes.c_char)),
    ('pj', ctypes.POINTER(struct_pj_t)),
]

RBPlist = struct_r_bplist_t
try:
    r_bplist_parse = _libr_util.r_bplist_parse
    r_bplist_parse.restype = ctypes.c_bool
    r_bplist_parse.argtypes = [ctypes.POINTER(struct_pj_t), ctypes.POINTER(ctypes.c_ubyte), size_t]
except AttributeError:
    pass
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
try:
    r_x509_parse_crl = _libr_util.r_x509_parse_crl
    r_x509_parse_crl.restype = ctypes.POINTER(struct_r_x509_certificaterevocationlist)
    r_x509_parse_crl.argtypes = [ctypes.POINTER(struct_r_asn1_object_t)]
except AttributeError:
    pass
try:
    r_x509_crl_to_string = _libr_util.r_x509_crl_to_string
    r_x509_crl_to_string.restype = ctypes.POINTER(ctypes.c_char)
    r_x509_crl_to_string.argtypes = [ctypes.POINTER(struct_r_x509_certificaterevocationlist), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_x509_crl_json = _libr_util.r_x509_crl_json
    r_x509_crl_json.restype = None
    r_x509_crl_json.argtypes = [ctypes.POINTER(struct_pj_t), ctypes.POINTER(struct_r_x509_certificaterevocationlist)]
except AttributeError:
    pass
try:
    r_x509_parse_certificate = _libr_util.r_x509_parse_certificate
    r_x509_parse_certificate.restype = ctypes.POINTER(struct_r_x509_certificate_t)
    r_x509_parse_certificate.argtypes = [ctypes.POINTER(struct_r_asn1_object_t)]
except AttributeError:
    pass
try:
    r_x509_parse_certificate2 = _libr_util.r_x509_parse_certificate2
    r_x509_parse_certificate2.restype = ctypes.POINTER(struct_r_x509_certificate_t)
    r_x509_parse_certificate2.argtypes = [ctypes.POINTER(ctypes.c_ubyte), uint32_t]
except AttributeError:
    pass
try:
    r_x509_free_certificate = _libr_util.r_x509_free_certificate
    r_x509_free_certificate.restype = None
    r_x509_free_certificate.argtypes = [ctypes.POINTER(struct_r_x509_certificate_t)]
except AttributeError:
    pass
try:
    r_x509_certificate_to_string = _libraries['FIXME_STUB'].r_x509_certificate_to_string
    r_x509_certificate_to_string.restype = ctypes.POINTER(ctypes.c_char)
    r_x509_certificate_to_string.argtypes = [ctypes.POINTER(struct_r_x509_certificate_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_x509_certificate_json = _libr_util.r_x509_certificate_json
    r_x509_certificate_json.restype = None
    r_x509_certificate_json.argtypes = [ctypes.POINTER(struct_pj_t), ctypes.POINTER(struct_r_x509_certificate_t)]
except AttributeError:
    pass
try:
    r_x509_certificate_dump = _libr_util.r_x509_certificate_dump
    r_x509_certificate_dump.restype = None
    r_x509_certificate_dump.argtypes = [ctypes.POINTER(struct_r_x509_certificate_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_RStrBuf)]
except AttributeError:
    pass
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
class struct_SpcAttributeTypeAndOptionalValue(Structure):
    pass

struct_SpcAttributeTypeAndOptionalValue._pack_ = 1 # source:False
struct_SpcAttributeTypeAndOptionalValue._fields_ = [
    ('type', ctypes.POINTER(struct_r_asn1_string_t)),
    ('data', ctypes.POINTER(struct_r_asn1_bin_t)),
]

SpcAttributeTypeAndOptionalValue = struct_SpcAttributeTypeAndOptionalValue
class struct_SpcDigestInfo(Structure):
    pass

struct_SpcDigestInfo._pack_ = 1 # source:False
struct_SpcDigestInfo._fields_ = [
    ('digestAlgorithm', RX509AlgorithmIdentifier),
    ('digest', ctypes.POINTER(struct_r_asn1_bin_t)),
]

SpcDigestInfo = struct_SpcDigestInfo
class struct_SpcIndirectDataContent(Structure):
    _pack_ = 1 # source:False
    _fields_ = [
    ('data', SpcAttributeTypeAndOptionalValue),
    ('messageDigest', SpcDigestInfo),
     ]

SpcIndirectDataContent = struct_SpcIndirectDataContent
try:
    r_pkcs7_parse_cms = _libr_util.r_pkcs7_parse_cms
    r_pkcs7_parse_cms.restype = ctypes.POINTER(struct_r_pkcs7_container_t)
    r_pkcs7_parse_cms.argtypes = [ctypes.POINTER(ctypes.c_ubyte), uint32_t]
except AttributeError:
    pass
try:
    r_pkcs7_free_cms = _libr_util.r_pkcs7_free_cms
    r_pkcs7_free_cms.restype = None
    r_pkcs7_free_cms.argtypes = [ctypes.POINTER(struct_r_pkcs7_container_t)]
except AttributeError:
    pass
try:
    r_pkcs7_cms_to_string = _libr_util.r_pkcs7_cms_to_string
    r_pkcs7_cms_to_string.restype = ctypes.POINTER(ctypes.c_char)
    r_pkcs7_cms_to_string.argtypes = [ctypes.POINTER(struct_r_pkcs7_container_t)]
except AttributeError:
    pass
try:
    r_pkcs7_cms_json = _libr_util.r_pkcs7_cms_json
    r_pkcs7_cms_json.restype = ctypes.POINTER(struct_pj_t)
    r_pkcs7_cms_json.argtypes = [ctypes.POINTER(struct_r_pkcs7_container_t)]
except AttributeError:
    pass
try:
    r_pkcs7_parse_spcinfo = _libr_util.r_pkcs7_parse_spcinfo
    r_pkcs7_parse_spcinfo.restype = ctypes.POINTER(struct_SpcIndirectDataContent)
    r_pkcs7_parse_spcinfo.argtypes = [ctypes.POINTER(struct_r_pkcs7_container_t)]
except AttributeError:
    pass
try:
    r_pkcs7_free_spcinfo = _libr_util.r_pkcs7_free_spcinfo
    r_pkcs7_free_spcinfo.restype = None
    r_pkcs7_free_spcinfo.argtypes = [ctypes.POINTER(struct_SpcIndirectDataContent)]
except AttributeError:
    pass
try:
    r_protobuf_decode = _libr_util.r_protobuf_decode
    r_protobuf_decode.restype = ctypes.POINTER(ctypes.c_char)
    r_protobuf_decode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), uint64_t, ctypes.c_int32]
except AttributeError:
    pass
RRef = ctypes.c_int32

# values for enumeration 'RTokenType'
RTokenType__enumvalues = {
    0: 'R_TOKEN_NONE',
    1: 'R_TOKEN_INT',
    2: 'R_TOKEN_FLOAT',
    3: 'R_TOKEN_WORD',
    4: 'R_TOKEN_HASH',
    5: 'R_TOKEN_STRING',
    6: 'R_TOKEN_COMMENT',
    7: 'R_TOKEN_MATH',
    8: 'R_TOKEN_GROUP',
    9: 'R_TOKEN_BEGIN',
    10: 'R_TOKEN_END',
}
R_TOKEN_NONE = 0
R_TOKEN_INT = 1
R_TOKEN_FLOAT = 2
R_TOKEN_WORD = 3
R_TOKEN_HASH = 4
R_TOKEN_STRING = 5
R_TOKEN_COMMENT = 6
R_TOKEN_MATH = 7
R_TOKEN_GROUP = 8
R_TOKEN_BEGIN = 9
R_TOKEN_END = 10
RTokenType = ctypes.c_uint32 # enum
RTokenizerCallback = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(None))
class struct_r_tokenizer_t(Structure):
    pass

struct_r_tokenizer_t._pack_ = 1 # source:False
struct_r_tokenizer_t._fields_ = [
    ('hex', ctypes.c_bool),
    ('escape', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 6),
    ('buf', ctypes.POINTER(ctypes.c_char)),
    ('ch', ctypes.c_char),
    ('PADDING_1', ctypes.c_ubyte * 7),
    ('begin', ctypes.c_uint64),
    ('indent', ctypes.c_int32),
    ('PADDING_2', ctypes.c_ubyte * 4),
    ('end', ctypes.c_uint64),
    ('type', RTokenType),
    ('PADDING_3', ctypes.c_ubyte * 4),
    ('cb', ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(None))),
    ('user', ctypes.POINTER(None)),
]

RTokenizer = struct_r_tokenizer_t
try:
    r_str_tokenize_json = _libr_util.r_str_tokenize_json
    r_str_tokenize_json.restype = ctypes.POINTER(ctypes.c_char)
    r_str_tokenize_json.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_tokenizer_new = _libr_util.r_tokenizer_new
    r_tokenizer_new.restype = ctypes.POINTER(struct_r_tokenizer_t)
    r_tokenizer_new.argtypes = []
except AttributeError:
    pass
try:
    r_str_tokenize = _libr_util.r_str_tokenize
    r_str_tokenize.restype = None
    r_str_tokenize.argtypes = [ctypes.POINTER(ctypes.c_char), RTokenizerCallback, ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_axml_decode = _libr_util.r_axml_decode
    r_axml_decode.restype = ctypes.POINTER(ctypes.c_char)
    r_axml_decode.argtypes = [ctypes.POINTER(ctypes.c_ubyte), uint64_t, ctypes.POINTER(struct_pj_t)]
except AttributeError:
    pass
try:
    r_util_version = _libr_util.r_util_version
    r_util_version.restype = ctypes.POINTER(ctypes.c_char)
    r_util_version.argtypes = []
except AttributeError:
    pass
try:
    r_config_version = _libraries['FIXME_STUB'].r_config_version
    r_config_version.restype = ctypes.POINTER(ctypes.c_char)
    r_config_version.argtypes = []
except AttributeError:
    pass
RConfigCallback = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(None), ctypes.POINTER(None))
class struct_r_config_node_t(Structure):
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

RConfigNode = struct_r_config_node_t
try:
    r_config_node_type = _libr_config.r_config_node_type
    r_config_node_type.restype = ctypes.POINTER(ctypes.c_char)
    r_config_node_type.argtypes = [ctypes.POINTER(struct_r_config_node_t)]
except AttributeError:
    pass
class struct_r_config_t(Structure):
    pass

struct_r_config_t._pack_ = 1 # source:False
struct_r_config_t._fields_ = [
    ('user', ctypes.POINTER(None)),
    ('num', ctypes.POINTER(struct_r_num_t)),
    ('cb_printf', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(ctypes.c_char))),
    ('nodes', ctypes.POINTER(struct_r_list_t)),
    ('ht', ctypes.POINTER(struct_ht_pp_t)),
    ('lock', ctypes.c_bool),
    ('is_dirty', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 6),
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
try:
    r_config_hold_new = _libr_config.r_config_hold_new
    r_config_hold_new.restype = ctypes.POINTER(struct_r_config_hold_t)
    r_config_hold_new.argtypes = [ctypes.POINTER(struct_r_config_t)]
except AttributeError:
    pass
try:
    r_config_hold = _libr_config.r_config_hold
    r_config_hold.restype = ctypes.c_bool
    r_config_hold.argtypes = [ctypes.POINTER(struct_r_config_hold_t)]
except AttributeError:
    pass
try:
    r_config_hold_free = _libr_config.r_config_hold_free
    r_config_hold_free.restype = None
    r_config_hold_free.argtypes = [ctypes.POINTER(struct_r_config_hold_t)]
except AttributeError:
    pass
try:
    r_config_hold_restore = _libr_config.r_config_hold_restore
    r_config_hold_restore.restype = None
    r_config_hold_restore.argtypes = [ctypes.POINTER(struct_r_config_hold_t)]
except AttributeError:
    pass
try:
    r_config_new = _libr_config.r_config_new
    r_config_new.restype = ctypes.POINTER(struct_r_config_t)
    r_config_new.argtypes = [ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_config_clone = _libr_config.r_config_clone
    r_config_clone.restype = ctypes.POINTER(struct_r_config_t)
    r_config_clone.argtypes = [ctypes.POINTER(struct_r_config_t)]
except AttributeError:
    pass
try:
    r_config_free = _libr_config.r_config_free
    r_config_free.restype = None
    r_config_free.argtypes = [ctypes.POINTER(struct_r_config_t)]
except AttributeError:
    pass
try:
    r_config_lock = _libr_config.r_config_lock
    r_config_lock.restype = None
    r_config_lock.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.c_bool]
except AttributeError:
    pass
try:
    r_config_eval = _libr_config.r_config_eval
    r_config_eval.restype = ctypes.c_bool
    r_config_eval.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char), ctypes.c_bool]
except AttributeError:
    pass
try:
    r_config_bump = _libr_config.r_config_bump
    r_config_bump.restype = None
    r_config_bump.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_config_get_b = _libr_config.r_config_get_b
    r_config_get_b.restype = ctypes.c_bool
    r_config_get_b.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_config_set_b = _libr_config.r_config_set_b
    r_config_set_b.restype = ctypes.POINTER(struct_r_config_node_t)
    r_config_set_b.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char), ctypes.c_bool]
except AttributeError:
    pass
try:
    r_config_set_i = _libr_config.r_config_set_i
    r_config_set_i.restype = ctypes.POINTER(struct_r_config_node_t)
    r_config_set_i.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char), uint64_t]
except AttributeError:
    pass
try:
    r_config_set_cb = _libr_config.r_config_set_cb
    r_config_set_cb.restype = ctypes.POINTER(struct_r_config_node_t)
    r_config_set_cb.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), RConfigCallback]
except AttributeError:
    pass
try:
    r_config_set_i_cb = _libr_config.r_config_set_i_cb
    r_config_set_i_cb.restype = ctypes.POINTER(struct_r_config_node_t)
    r_config_set_i_cb.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, RConfigCallback]
except AttributeError:
    pass
try:
    r_config_set_b_cb = _libr_config.r_config_set_b_cb
    r_config_set_b_cb.restype = ctypes.POINTER(struct_r_config_node_t)
    r_config_set_b_cb.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char), ctypes.c_bool, RConfigCallback]
except AttributeError:
    pass
try:
    r_config_set = _libr_config.r_config_set
    r_config_set.restype = ctypes.POINTER(struct_r_config_node_t)
    r_config_set.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_config_rm = _libr_config.r_config_rm
    r_config_rm.restype = ctypes.c_bool
    r_config_rm.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_config_get_i = _libr_config.r_config_get_i
    r_config_get_i.restype = uint64_t
    r_config_get_i.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_config_get = _libr_config.r_config_get
    r_config_get.restype = ctypes.POINTER(ctypes.c_char)
    r_config_get.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_config_desc = _libr_config.r_config_desc
    r_config_desc.restype = ctypes.POINTER(struct_r_config_node_t)
    r_config_desc.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_config_list = _libr_config.r_config_list
    r_config_list.restype = None
    r_config_list.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_config_toggle = _libr_config.r_config_toggle
    r_config_toggle.restype = ctypes.c_bool
    r_config_toggle.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_config_readonly = _libr_config.r_config_readonly
    r_config_readonly.restype = ctypes.c_bool
    r_config_readonly.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_config_set_setter = _libr_config.r_config_set_setter
    r_config_set_setter.restype = ctypes.c_bool
    r_config_set_setter.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char), RConfigCallback]
except AttributeError:
    pass
try:
    r_config_set_getter = _libr_config.r_config_set_getter
    r_config_set_getter.restype = ctypes.c_bool
    r_config_set_getter.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char), RConfigCallback]
except AttributeError:
    pass
try:
    r_config_serialize = _libr_config.r_config_serialize
    r_config_serialize.restype = None
    r_config_serialize.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(struct_sdb_t)]
except AttributeError:
    pass
try:
    r_config_unserialize = _libr_config.r_config_unserialize
    r_config_unserialize.restype = ctypes.c_bool
    r_config_unserialize.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(struct_sdb_t), ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
except AttributeError:
    pass
try:
    r_config_node_desc = _libr_config.r_config_node_desc
    r_config_node_desc.restype = ctypes.POINTER(struct_r_config_node_t)
    r_config_node_desc.argtypes = [ctypes.POINTER(struct_r_config_node_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_config_node_to_string = _libr_config.r_config_node_to_string
    r_config_node_to_string.restype = ctypes.POINTER(ctypes.c_char)
    r_config_node_to_string.argtypes = [ctypes.POINTER(struct_r_config_node_t)]
except AttributeError:
    pass
try:
    r_config_node_add_option = _libr_config.r_config_node_add_option
    r_config_node_add_option.restype = None
    r_config_node_add_option.argtypes = [ctypes.POINTER(struct_r_config_node_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_config_node_purge_options = _libr_config.r_config_node_purge_options
    r_config_node_purge_options.restype = None
    r_config_node_purge_options.argtypes = [ctypes.POINTER(struct_r_config_node_t)]
except AttributeError:
    pass
try:
    r_config_node_get = _libr_config.r_config_node_get
    r_config_node_get.restype = ctypes.POINTER(struct_r_config_node_t)
    r_config_node_get.argtypes = [ctypes.POINTER(struct_r_config_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_config_node_new = _libr_config.r_config_node_new
    r_config_node_new.restype = ctypes.POINTER(struct_r_config_node_t)
    r_config_node_new.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_config_node_free = _libr_config.r_config_node_free
    r_config_node_free.restype = None
    r_config_node_free.argtypes = [ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    r_config_node_value_format_i = _libr_config.r_config_node_value_format_i
    r_config_node_value_format_i.restype = None
    r_config_node_value_format_i.argtypes = [ctypes.POINTER(ctypes.c_char), size_t, uint64_t, ctypes.POINTER(struct_r_config_node_t)]
except AttributeError:
    pass
try:
    r_config_node_is_bool = _libraries['FIXME_STUB'].r_config_node_is_bool
    r_config_node_is_bool.restype = ctypes.c_bool
    r_config_node_is_bool.argtypes = [ctypes.POINTER(struct_r_config_node_t)]
except AttributeError:
    pass
try:
    r_config_node_is_int = _libraries['FIXME_STUB'].r_config_node_is_int
    r_config_node_is_int.restype = ctypes.c_bool
    r_config_node_is_int.argtypes = [ctypes.POINTER(struct_r_config_node_t)]
except AttributeError:
    pass
try:
    r_config_node_is_ro = _libraries['FIXME_STUB'].r_config_node_is_ro
    r_config_node_is_ro.restype = ctypes.c_bool
    r_config_node_is_ro.argtypes = [ctypes.POINTER(struct_r_config_node_t)]
except AttributeError:
    pass
try:
    r_config_node_is_str = _libraries['FIXME_STUB'].r_config_node_is_str
    r_config_node_is_str.restype = ctypes.c_bool
    r_config_node_is_str.argtypes = [ctypes.POINTER(struct_r_config_node_t)]
except AttributeError:
    pass
__all__ = \
    ['ALPHA_BG', 'ALPHA_FG', 'ALPHA_FGBG', 'ALPHA_RESET', 'ASN1List',
    'BUS_ADRALN', 'BUS_ADRERR', 'BUS_MCEERR_AO', 'BUS_MCEERR_AR',
    'BUS_OBJERR', 'BufferOp', 'CLD_CONTINUED', 'CLD_DUMPED',
    'CLD_EXITED', 'CLD_KILLED', 'CLD_STOPPED', 'CLD_TRAPPED',
    'COLOR_MODE_16', 'COLOR_MODE_16M', 'COLOR_MODE_256',
    'COLOR_MODE_DISABLED', 'CONTROL_MODE', 'DEFAULT', 'DEL', 'DIR',
    'DT_BLK', 'DT_CHR', 'DT_DIR', 'DT_FIFO', 'DT_LNK', 'DT_REG',
    'DT_SOCK', 'DT_UNKNOWN', 'DT_WHT', 'FILE', 'FPE_CONDTRAP',
    'FPE_FLTDIV', 'FPE_FLTINV', 'FPE_FLTOVF', 'FPE_FLTRES',
    'FPE_FLTSUB', 'FPE_FLTUND', 'FPE_FLTUNK', 'FPE_INTDIV',
    'FPE_INTOVF', 'FP_INFINITE', 'FP_NAN', 'FP_NORMAL',
    'FP_SUBNORMAL', 'FP_ZERO', 'GperfForeachCallback', 'HtPP',
    'HtPPBucket', 'HtPPCalcSizeK', 'HtPPCalcSizeV', 'HtPPDupKey',
    'HtPPDupValue', 'HtPPForeachCallback', 'HtPPHashFunction',
    'HtPPKv', 'HtPPKvFreeFunc', 'HtPPListComparator', 'HtPPOptions',
    'HtUP', 'HtUPBucket', 'HtUPCalcSizeK', 'HtUPCalcSizeV',
    'HtUPDupKey', 'HtUPDupValue', 'HtUPForeachCallback',
    'HtUPHashFunction', 'HtUPKv', 'HtUPKvFreeFunc',
    'HtUPListComparator', 'HtUPOptions', 'ILL_BADIADDR', 'ILL_BADSTK',
    'ILL_COPROC', 'ILL_ILLADR', 'ILL_ILLOPC', 'ILL_ILLOPN',
    'ILL_ILLTRP', 'ILL_PRVOPC', 'ILL_PRVREG', 'INSERT_MODE',
    'ITIMER_PROF', 'ITIMER_REAL', 'ITIMER_VIRTUAL', 'LEVADD',
    'LEVDEL', 'LEVEND', 'LEVNOP', 'LEVSUB', 'LINE_FALSE', 'LINE_NONE',
    'LINE_NOSYM_HORIZ', 'LINE_NOSYM_VERT', 'LINE_TRUE', 'LINE_UNCJMP',
    'MSG_BATCH', 'MSG_CMSG_CLOEXEC', 'MSG_CONFIRM', 'MSG_CTRUNC',
    'MSG_DONTROUTE', 'MSG_DONTWAIT', 'MSG_EOR', 'MSG_ERRQUEUE',
    'MSG_FASTOPEN', 'MSG_FIN', 'MSG_MORE', 'MSG_NOSIGNAL', 'MSG_OOB',
    'MSG_PEEK', 'MSG_PROXY', 'MSG_RST', 'MSG_SYN', 'MSG_TRUNC',
    'MSG_WAITALL', 'MSG_WAITFORONE', 'MSG_ZEROCOPY', 'PAL_00',
    'PAL_7F', 'PAL_ADDRESS', 'PAL_CALL', 'PAL_CHANGED', 'PAL_CMP',
    'PAL_DEFAULT', 'PAL_FF', 'PAL_HEADER', 'PAL_JUMP', 'PAL_LINES0',
    'PAL_LINES1', 'PAL_LINES2', 'PAL_METADATA', 'PAL_NOP',
    'PAL_PRINTABLE', 'PAL_PROMPT', 'PAL_PUSH', 'PAL_RET', 'PAL_TRAP',
    'PANEL_EDGE_BOTTOM', 'PANEL_EDGE_NONE', 'PANEL_EDGE_RIGHT',
    'PANEL_FUN_NOFUN', 'PANEL_FUN_SAKURA', 'PANEL_FUN_SNOW',
    'PANEL_LAYOUT_DEFAULT_DYNAMIC', 'PANEL_LAYOUT_DEFAULT_STATIC',
    'PANEL_LAYOUT_HORIZONTAL', 'PANEL_LAYOUT_NONE',
    'PANEL_LAYOUT_VERTICAL', 'PANEL_MODE_DEFAULT', 'PANEL_MODE_HELP',
    'PANEL_MODE_MENU', 'PANEL_MODE_WINDOW', 'PANEL_MODE_ZOOM',
    'PANEL_TYPE_DEFAULT', 'PANEL_TYPE_MENU', 'PJ', 'PJEncodingNum',
    'PJEncodingStr', 'PJ_ENCODING_NUM_DEFAULT', 'PJ_ENCODING_NUM_HEX',
    'PJ_ENCODING_NUM_STR', 'PJ_ENCODING_STR_ARRAY',
    'PJ_ENCODING_STR_BASE64', 'PJ_ENCODING_STR_DEFAULT',
    'PJ_ENCODING_STR_HEX', 'PJ_ENCODING_STR_STRIP', 'POLL_ERR',
    'POLL_HUP', 'POLL_IN', 'POLL_MSG', 'POLL_OUT', 'POLL_PRI',
    'PTHREAD_CANCEL_ASYNCHRONOUS', 'PTHREAD_CANCEL_DEFERRED',
    'PTHREAD_CANCEL_DISABLE', 'PTHREAD_CANCEL_ENABLE',
    'PTHREAD_CREATE_DETACHED', 'PTHREAD_CREATE_JOINABLE',
    'PTHREAD_EXPLICIT_SCHED', 'PTHREAD_INHERIT_SCHED',
    'PTHREAD_MUTEX_ADAPTIVE_NP', 'PTHREAD_MUTEX_DEFAULT',
    'PTHREAD_MUTEX_ERRORCHECK', 'PTHREAD_MUTEX_ERRORCHECK_NP',
    'PTHREAD_MUTEX_NORMAL', 'PTHREAD_MUTEX_RECURSIVE',
    'PTHREAD_MUTEX_RECURSIVE_NP', 'PTHREAD_MUTEX_ROBUST',
    'PTHREAD_MUTEX_ROBUST_NP', 'PTHREAD_MUTEX_STALLED',
    'PTHREAD_MUTEX_STALLED_NP', 'PTHREAD_MUTEX_TIMED_NP',
    'PTHREAD_PRIO_INHERIT', 'PTHREAD_PRIO_NONE',
    'PTHREAD_PRIO_PROTECT', 'PTHREAD_PROCESS_PRIVATE',
    'PTHREAD_PROCESS_SHARED', 'PTHREAD_RWLOCK_DEFAULT_NP',
    'PTHREAD_RWLOCK_PREFER_READER_NP',
    'PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP',
    'PTHREAD_RWLOCK_PREFER_WRITER_NP', 'PTHREAD_SCOPE_PROCESS',
    'PTHREAD_SCOPE_SYSTEM', 'P_ALL', 'P_PGID', 'P_PID', 'P_PIDFD',
    'PrintfCallback', 'QUIT', 'RASN1Binary', 'RASN1Object',
    'RASN1String', 'RBComparator', 'RBIter', 'RBNode', 'RBNodeFree',
    'RBNodeSum', 'RBPlist', 'RBTree', 'RBitmap', 'RBuffer',
    'RBufferFini', 'RBufferFreeWholeBuf', 'RBufferGetSize',
    'RBufferGetWholeBuf', 'RBufferInit', 'RBufferMethods',
    'RBufferNonEmptyList', 'RBufferRead', 'RBufferResize',
    'RBufferSeek', 'RBufferSparse', 'RBufferWrite', 'RCMS', 'RCache',
    'RCalloc', 'RCanvasLineStyle', 'RCharset', 'RCharsetRune',
    'RColor', 'RConfig', 'RConfigCallback', 'RConfigHold',
    'RConfigNode', 'RCons', 'RConsBind', 'RConsBreak',
    'RConsBreakCallback', 'RConsCanvas', 'RConsClickCallback',
    'RConsColorMode', 'RConsContext', 'RConsCursorPos',
    'RConsEditorCallback', 'RConsEvent', 'RConsFlush',
    'RConsFunctionKey', 'RConsGetCursor', 'RConsGetSize', 'RConsGrep',
    'RConsGrepCallback', 'RConsIsBreaked', 'RConsPalette',
    'RConsPixel', 'RConsPrintablePalette', 'RConsQueueTaskOneshot',
    'RConsSleepBeginCallback', 'RConsSleepEndCallback',
    'RCoreHelpMessage', 'RDiff', 'RDiffCallback', 'RDiffChar',
    'RDiffOp', 'REvent', 'REventCallback', 'REventCallbackHandle',
    'REventClass', 'REventClassAttr', 'REventClassAttrRename',
    'REventClassAttrSet', 'REventClassRename',
    'REventDebugProcessFinished', 'REventIOWrite', 'REventMeta',
    'REventType', 'RFree', 'RGetopt', 'RGraph', 'RGraphEdge',
    'RGraphEdgeCallback', 'RGraphNode', 'RGraphNodeCallback',
    'RGraphVisitor', 'RIDPool', 'RIDStorage', 'RIDStorageForeachCb',
    'RInterval', 'RIntervalIterCb', 'RIntervalNode',
    'RIntervalNodeFree', 'RIntervalTree', 'RIntervalTreeIter',
    'RLevBuf', 'RLevMatches', 'RLevOp', 'RLine', 'RLineBuffer',
    'RLineCompletion', 'RLineCompletionCb', 'RLineEditorCb',
    'RLineHistory', 'RLineHistoryDownCb', 'RLineHistoryUpCb',
    'RLineHud', 'RLinePromptType', 'RLineReadCallback', 'RList',
    'RListComparator', 'RListComparatorItem', 'RListFree',
    'RListInfo', 'RListIter', 'RListRange', 'RLog', 'RLogCallback',
    'RLogLevel', 'RLogLevel__enumvalues', 'RLogSource', 'RMalloc',
    'RMemoryPool', 'RMmap', 'RModal', 'RNCAND', 'RNCASSIGN', 'RNCDEC',
    'RNCDIV', 'RNCEND', 'RNCGT', 'RNCINC', 'RNCLEFTP', 'RNCLT',
    'RNCMINUS', 'RNCMOD', 'RNCMUL', 'RNCNAME', 'RNCNEG', 'RNCNUMBER',
    'RNCOR', 'RNCPLUS', 'RNCPRINT', 'RNCRIGHTP', 'RNCROL', 'RNCROR',
    'RNCSHL', 'RNCSHR', 'RNCXOR', 'RNum', 'RNumBig', 'RNumCalc',
    'RNumCalcToken', 'RNumCalcValue', 'RNumCallback', 'RNumCallback2',
    'RNumFloat', 'ROIDStorage', 'ROIDStorageCompareCb', 'ROTATE',
    'RPKCS7Attribute', 'RPKCS7Attributes',
    'RPKCS7CertificateRevocationLists', 'RPKCS7ContentInfo',
    'RPKCS7DigestAlgorithmIdentifiers',
    'RPKCS7ExtendedCertificatesAndCertificates',
    'RPKCS7IssuerAndSerialNumber', 'RPKCS7SignedData',
    'RPKCS7SignerInfo', 'RPKCS7SignerInfos', 'RPVector',
    'RPVectorComparator', 'RPVectorFree', 'RPanel',
    'RPanelAlmightyCallback', 'RPanelDirectionCallback', 'RPanelEdge',
    'RPanelLayout', 'RPanelMenuUpdateCallback', 'RPanelModel',
    'RPanelPos', 'RPanelPrintCallback', 'RPanelRotateCallback',
    'RPanelType', 'RPanelView', 'RPanels', 'RPanelsFun',
    'RPanelsLayout', 'RPanelsMenu', 'RPanelsMenuCallback',
    'RPanelsMenuItem', 'RPanelsMode', 'RPanelsRoot',
    'RPanelsRootState', 'RPanelsSnow', 'RPoolFactory', 'RProfile',
    'RQueue', 'RRBComparator', 'RRBFree', 'RRBNode', 'RRBTree',
    'RRange', 'RRangeItem', 'RRealloc', 'RRef', 'RRegex',
    'RRegexMatch', 'RRune', 'RSelWidget', 'RSkipList',
    'RSkipListNode', 'RSpace', 'RSpaceEvent', 'RSpaceEventType',
    'RSpaceIter', 'RSpaces', 'RStack', 'RStackFree', 'RStrBuf',
    'RStrConstPool', 'RStrEnc', 'RStrRangeCallback', 'RString',
    'RStrpool', 'RSysArch', 'RSysInfo', 'RTable', 'RTableColumn',
    'RTableColumnType', 'RTableRow', 'RTableSelector', 'RThread',
    'RThreadChannel', 'RThreadChannelMessage',
    'RThreadChannelPromise', 'RThreadCond', 'RThreadFunction',
    'RThreadFunctionRet', 'RThreadLock', 'RThreadPool',
    'RThreadSemaphore', 'RTokenType', 'RTokenizer',
    'RTokenizerCallback', 'RTree', 'RTreeNode', 'RTreeNodeVisitCb',
    'RTreeVisitor', 'RTypeEnum', 'RTypeKind', 'RUtfBlock', 'RVector',
    'RVectorFree', 'RViMode', 'RX509AlgorithmIdentifier',
    'RX509AuthorityKeyIdentifier', 'RX509CRLEntry',
    'RX509Certificate', 'RX509CertificateRevocationList',
    'RX509Extension', 'RX509Extensions', 'RX509Name',
    'RX509SubjectPublicKeyInfo', 'RX509TBSCertificate',
    'RX509Validity', 'R_CONS_ATTR_BLINK', 'R_CONS_ATTR_BOLD',
    'R_CONS_ATTR_DIM', 'R_CONS_ATTR_ITALIC', 'R_CONS_ATTR_UNDERLINE',
    'R_CONS_ERRMODE_BUFFER', 'R_CONS_ERRMODE_ECHO',
    'R_CONS_ERRMODE_FLUSH', 'R_CONS_ERRMODE_NULL',
    'R_CONS_ERRMODE_QUIET', 'R_EVENT_ALL', 'R_EVENT_CLASS_ATTR_DEL',
    'R_EVENT_CLASS_ATTR_RENAME', 'R_EVENT_CLASS_ATTR_SET',
    'R_EVENT_CLASS_DEL', 'R_EVENT_CLASS_NEW', 'R_EVENT_CLASS_RENAME',
    'R_EVENT_DEBUG_PROCESS_FINISHED', 'R_EVENT_IO_WRITE',
    'R_EVENT_MAX', 'R_EVENT_META_CLEAR', 'R_EVENT_META_DEL',
    'R_EVENT_META_SET', 'R_LINE_PROMPT_DEFAULT', 'R_LINE_PROMPT_FILE',
    'R_LINE_PROMPT_OFFSET', 'R_LOGLVL_DEBUG', 'R_LOGLVL_ERROR',
    'R_LOGLVL_FATAL', 'R_LOGLVL_INFO', 'R_LOGLVL_LAST',
    'R_LOGLVL_TODO', 'R_LOGLVL_WARN', 'R_SPACE_EVENT_COUNT',
    'R_SPACE_EVENT_RENAME', 'R_SPACE_EVENT_UNSET',
    'R_STRING_ENC_GUESS', 'R_STRING_ENC_LATIN1',
    'R_STRING_ENC_UTF16BE', 'R_STRING_ENC_UTF16LE',
    'R_STRING_ENC_UTF32BE', 'R_STRING_ENC_UTF32LE',
    'R_STRING_ENC_UTF8', 'R_SYS_ARCH_8051', 'R_SYS_ARCH_ARC',
    'R_SYS_ARCH_ARM', 'R_SYS_ARCH_AVR', 'R_SYS_ARCH_BF',
    'R_SYS_ARCH_BPF', 'R_SYS_ARCH_CR16', 'R_SYS_ARCH_CRIS',
    'R_SYS_ARCH_DALVIK', 'R_SYS_ARCH_EBC', 'R_SYS_ARCH_ESIL',
    'R_SYS_ARCH_H8300', 'R_SYS_ARCH_HPPA', 'R_SYS_ARCH_I8080',
    'R_SYS_ARCH_JAVA', 'R_SYS_ARCH_LM32', 'R_SYS_ARCH_M68K',
    'R_SYS_ARCH_MIPS', 'R_SYS_ARCH_MSIL', 'R_SYS_ARCH_MSP430',
    'R_SYS_ARCH_NONE', 'R_SYS_ARCH_OBJD', 'R_SYS_ARCH_PPC',
    'R_SYS_ARCH_PROPELLER', 'R_SYS_ARCH_RAR', 'R_SYS_ARCH_RISCV',
    'R_SYS_ARCH_S390', 'R_SYS_ARCH_SH', 'R_SYS_ARCH_SPARC',
    'R_SYS_ARCH_TMS320', 'R_SYS_ARCH_V810', 'R_SYS_ARCH_V850',
    'R_SYS_ARCH_X86', 'R_SYS_ARCH_XAP', 'R_SYS_ARCH_XCORE',
    'R_SYS_ARCH_Z80', 'R_TABLE_ALIGN_CENTER', 'R_TABLE_ALIGN_LEFT',
    'R_TABLE_ALIGN_RIGHT', 'R_TH_FREED', 'R_TH_LOCK_TYPE_HEAP',
    'R_TH_LOCK_TYPE_STATIC', 'R_TH_REPEAT', 'R_TH_STOP',
    'R_TOKEN_BEGIN', 'R_TOKEN_COMMENT', 'R_TOKEN_END',
    'R_TOKEN_FLOAT', 'R_TOKEN_GROUP', 'R_TOKEN_HASH', 'R_TOKEN_INT',
    'R_TOKEN_MATH', 'R_TOKEN_NONE', 'R_TOKEN_STRING', 'R_TOKEN_WORD',
    'R_TYPE_BASIC', 'R_TYPE_ENUM', 'R_TYPE_STRUCT', 'R_TYPE_TYPEDEF',
    'R_TYPE_UNION', 'SCM_RIGHTS', 'SEGV_ACCADI', 'SEGV_ACCERR',
    'SEGV_ADIDERR', 'SEGV_ADIPERR', 'SEGV_BNDERR', 'SEGV_CPERR',
    'SEGV_MAPERR', 'SEGV_MTEAERR', 'SEGV_MTESERR', 'SEGV_PKUERR',
    'SHUT_RD', 'SHUT_RDWR', 'SHUT_WR', 'SIGEV_NONE', 'SIGEV_SIGNAL',
    'SIGEV_THREAD', 'SIGEV_THREAD_ID', 'SI_ASYNCIO', 'SI_ASYNCNL',
    'SI_DETHREAD', 'SI_KERNEL', 'SI_MESGQ', 'SI_QUEUE', 'SI_SIGIO',
    'SI_TIMER', 'SI_TKILL', 'SI_USER', 'SOCK_CLOEXEC', 'SOCK_DCCP',
    'SOCK_DGRAM', 'SOCK_NONBLOCK', 'SOCK_PACKET', 'SOCK_RAW',
    'SOCK_RDM', 'SOCK_SEQPACKET', 'SOCK_STREAM', 'SS_DISABLE',
    'SS_ONSTACK', 'ST16_DIV_OVFCHK', 'ST16_MUL_OVFCHK',
    'ST32_DIV_OVFCHK', 'ST32_MUL_OVFCHK', 'ST64_DIV_OVFCHK',
    'ST64_MUL_OVFCHK', 'ST8_DIV_OVFCHK', 'ST8_MUL_OVFCHK',
    'SZT_MUL_OVFCHK', 'Sdb', 'SdbDiff', 'SdbDiffCallback',
    'SdbForeachCallback', 'SdbGperf', 'SdbHook', 'SdbJsonString',
    'SdbKv', 'SdbList', 'SdbListComparator', 'SdbListFree',
    'SdbListIter', 'SdbMini', 'SdbNs',
    'SpcAttributeTypeAndOptionalValue', 'SpcDigestInfo',
    'SpcIndirectDataContent', 'UT16_ADD', 'UT16_DIV_OVFCHK',
    'UT16_MUL', 'UT16_MUL_OVFCHK', 'UT16_SUB', 'UT32_ADD',
    'UT32_DIV_OVFCHK', 'UT32_MUL', 'UT32_MUL_OVFCHK', 'UT32_SUB',
    'UT64_ADD', 'UT64_DIV_OVFCHK', 'UT64_MUL', 'UT64_MUL_OVFCHK',
    'UT64_SUB', 'UT8_ADD', 'UT8_DIV_OVFCHK', 'UT8_MUL',
    'UT8_MUL_OVFCHK', 'UT8_SUB', '_CS_GNU_LIBC_VERSION',
    '_CS_GNU_LIBPTHREAD_VERSION', '_CS_LFS64_CFLAGS',
    '_CS_LFS64_LDFLAGS', '_CS_LFS64_LIBS', '_CS_LFS64_LINTFLAGS',
    '_CS_LFS_CFLAGS', '_CS_LFS_LDFLAGS', '_CS_LFS_LIBS',
    '_CS_LFS_LINTFLAGS', '_CS_PATH',
    '_CS_POSIX_V6_ILP32_OFF32_CFLAGS',
    '_CS_POSIX_V6_ILP32_OFF32_LDFLAGS',
    '_CS_POSIX_V6_ILP32_OFF32_LIBS',
    '_CS_POSIX_V6_ILP32_OFF32_LINTFLAGS',
    '_CS_POSIX_V6_ILP32_OFFBIG_CFLAGS',
    '_CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS',
    '_CS_POSIX_V6_ILP32_OFFBIG_LIBS',
    '_CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS',
    '_CS_POSIX_V6_LP64_OFF64_CFLAGS',
    '_CS_POSIX_V6_LP64_OFF64_LDFLAGS', '_CS_POSIX_V6_LP64_OFF64_LIBS',
    '_CS_POSIX_V6_LP64_OFF64_LINTFLAGS',
    '_CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS',
    '_CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS',
    '_CS_POSIX_V6_LPBIG_OFFBIG_LIBS',
    '_CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS',
    '_CS_POSIX_V7_ILP32_OFF32_CFLAGS',
    '_CS_POSIX_V7_ILP32_OFF32_LDFLAGS',
    '_CS_POSIX_V7_ILP32_OFF32_LIBS',
    '_CS_POSIX_V7_ILP32_OFF32_LINTFLAGS',
    '_CS_POSIX_V7_ILP32_OFFBIG_CFLAGS',
    '_CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS',
    '_CS_POSIX_V7_ILP32_OFFBIG_LIBS',
    '_CS_POSIX_V7_ILP32_OFFBIG_LINTFLAGS',
    '_CS_POSIX_V7_LP64_OFF64_CFLAGS',
    '_CS_POSIX_V7_LP64_OFF64_LDFLAGS', '_CS_POSIX_V7_LP64_OFF64_LIBS',
    '_CS_POSIX_V7_LP64_OFF64_LINTFLAGS',
    '_CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS',
    '_CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS',
    '_CS_POSIX_V7_LPBIG_OFFBIG_LIBS',
    '_CS_POSIX_V7_LPBIG_OFFBIG_LINTFLAGS',
    '_CS_V5_WIDTH_RESTRICTED_ENVS', '_CS_V6_ENV',
    '_CS_V6_WIDTH_RESTRICTED_ENVS', '_CS_V7_ENV',
    '_CS_V7_WIDTH_RESTRICTED_ENVS', '_CS_XBS5_ILP32_OFF32_CFLAGS',
    '_CS_XBS5_ILP32_OFF32_LDFLAGS', '_CS_XBS5_ILP32_OFF32_LIBS',
    '_CS_XBS5_ILP32_OFF32_LINTFLAGS', '_CS_XBS5_ILP32_OFFBIG_CFLAGS',
    '_CS_XBS5_ILP32_OFFBIG_LDFLAGS', '_CS_XBS5_ILP32_OFFBIG_LIBS',
    '_CS_XBS5_ILP32_OFFBIG_LINTFLAGS', '_CS_XBS5_LP64_OFF64_CFLAGS',
    '_CS_XBS5_LP64_OFF64_LDFLAGS', '_CS_XBS5_LP64_OFF64_LIBS',
    '_CS_XBS5_LP64_OFF64_LINTFLAGS', '_CS_XBS5_LPBIG_OFFBIG_CFLAGS',
    '_CS_XBS5_LPBIG_OFFBIG_LDFLAGS', '_CS_XBS5_LPBIG_OFFBIG_LIBS',
    '_CS_XBS5_LPBIG_OFFBIG_LINTFLAGS', '_Exit', '_Float32',
    '_Float32x', '_Float64', '_Float64x', '_IO_lock_t', '_ISalnum',
    '_ISalpha', '_ISblank', '_IScntrl', '_ISdigit', '_ISgraph',
    '_ISlower', '_ISprint', '_ISpunct', '_ISspace', '_ISupper',
    '_ISxdigit', '_PC_2_SYMLINKS', '_PC_ALLOC_SIZE_MIN',
    '_PC_ASYNC_IO', '_PC_CHOWN_RESTRICTED', '_PC_FILESIZEBITS',
    '_PC_LINK_MAX', '_PC_MAX_CANON', '_PC_MAX_INPUT', '_PC_NAME_MAX',
    '_PC_NO_TRUNC', '_PC_PATH_MAX', '_PC_PIPE_BUF', '_PC_PRIO_IO',
    '_PC_REC_INCR_XFER_SIZE', '_PC_REC_MAX_XFER_SIZE',
    '_PC_REC_MIN_XFER_SIZE', '_PC_REC_XFER_ALIGN', '_PC_SOCK_MAXBUF',
    '_PC_SYMLINK_MAX', '_PC_SYNC_IO', '_PC_VDISABLE',
    '_SC_2_CHAR_TERM', '_SC_2_C_BIND', '_SC_2_C_DEV',
    '_SC_2_C_VERSION', '_SC_2_FORT_DEV', '_SC_2_FORT_RUN',
    '_SC_2_LOCALEDEF', '_SC_2_PBS', '_SC_2_PBS_ACCOUNTING',
    '_SC_2_PBS_CHECKPOINT', '_SC_2_PBS_LOCATE', '_SC_2_PBS_MESSAGE',
    '_SC_2_PBS_TRACK', '_SC_2_SW_DEV', '_SC_2_UPE', '_SC_2_VERSION',
    '_SC_ADVISORY_INFO', '_SC_AIO_LISTIO_MAX', '_SC_AIO_MAX',
    '_SC_AIO_PRIO_DELTA_MAX', '_SC_ARG_MAX', '_SC_ASYNCHRONOUS_IO',
    '_SC_ATEXIT_MAX', '_SC_AVPHYS_PAGES', '_SC_BARRIERS', '_SC_BASE',
    '_SC_BC_BASE_MAX', '_SC_BC_DIM_MAX', '_SC_BC_SCALE_MAX',
    '_SC_BC_STRING_MAX', '_SC_CHARCLASS_NAME_MAX', '_SC_CHAR_BIT',
    '_SC_CHAR_MAX', '_SC_CHAR_MIN', '_SC_CHILD_MAX', '_SC_CLK_TCK',
    '_SC_CLOCK_SELECTION', '_SC_COLL_WEIGHTS_MAX', '_SC_CPUTIME',
    '_SC_C_LANG_SUPPORT', '_SC_C_LANG_SUPPORT_R',
    '_SC_DELAYTIMER_MAX', '_SC_DEVICE_IO', '_SC_DEVICE_SPECIFIC',
    '_SC_DEVICE_SPECIFIC_R', '_SC_EQUIV_CLASS_MAX',
    '_SC_EXPR_NEST_MAX', '_SC_FD_MGMT', '_SC_FIFO',
    '_SC_FILE_ATTRIBUTES', '_SC_FILE_LOCKING', '_SC_FILE_SYSTEM',
    '_SC_FSYNC', '_SC_GETGR_R_SIZE_MAX', '_SC_GETPW_R_SIZE_MAX',
    '_SC_HOST_NAME_MAX', '_SC_INT_MAX', '_SC_INT_MIN', '_SC_IOV_MAX',
    '_SC_IPV6', '_SC_JOB_CONTROL', '_SC_LEVEL1_DCACHE_ASSOC',
    '_SC_LEVEL1_DCACHE_LINESIZE', '_SC_LEVEL1_DCACHE_SIZE',
    '_SC_LEVEL1_ICACHE_ASSOC', '_SC_LEVEL1_ICACHE_LINESIZE',
    '_SC_LEVEL1_ICACHE_SIZE', '_SC_LEVEL2_CACHE_ASSOC',
    '_SC_LEVEL2_CACHE_LINESIZE', '_SC_LEVEL2_CACHE_SIZE',
    '_SC_LEVEL3_CACHE_ASSOC', '_SC_LEVEL3_CACHE_LINESIZE',
    '_SC_LEVEL3_CACHE_SIZE', '_SC_LEVEL4_CACHE_ASSOC',
    '_SC_LEVEL4_CACHE_LINESIZE', '_SC_LEVEL4_CACHE_SIZE',
    '_SC_LINE_MAX', '_SC_LOGIN_NAME_MAX', '_SC_LONG_BIT',
    '_SC_MAPPED_FILES', '_SC_MB_LEN_MAX', '_SC_MEMLOCK',
    '_SC_MEMLOCK_RANGE', '_SC_MEMORY_PROTECTION',
    '_SC_MESSAGE_PASSING', '_SC_MINSIGSTKSZ', '_SC_MONOTONIC_CLOCK',
    '_SC_MQ_OPEN_MAX', '_SC_MQ_PRIO_MAX', '_SC_MULTI_PROCESS',
    '_SC_NETWORKING', '_SC_NGROUPS_MAX', '_SC_NL_ARGMAX',
    '_SC_NL_LANGMAX', '_SC_NL_MSGMAX', '_SC_NL_NMAX', '_SC_NL_SETMAX',
    '_SC_NL_TEXTMAX', '_SC_NPROCESSORS_CONF', '_SC_NPROCESSORS_ONLN',
    '_SC_NZERO', '_SC_OPEN_MAX', '_SC_PAGESIZE', '_SC_PASS_MAX',
    '_SC_PHYS_PAGES', '_SC_PII', '_SC_PII_INTERNET',
    '_SC_PII_INTERNET_DGRAM', '_SC_PII_INTERNET_STREAM',
    '_SC_PII_OSI', '_SC_PII_OSI_CLTS', '_SC_PII_OSI_COTS',
    '_SC_PII_OSI_M', '_SC_PII_SOCKET', '_SC_PII_XTI', '_SC_PIPE',
    '_SC_POLL', '_SC_PRIORITIZED_IO', '_SC_PRIORITY_SCHEDULING',
    '_SC_RAW_SOCKETS', '_SC_READER_WRITER_LOCKS',
    '_SC_REALTIME_SIGNALS', '_SC_REGEXP', '_SC_REGEX_VERSION',
    '_SC_RE_DUP_MAX', '_SC_RTSIG_MAX', '_SC_SAVED_IDS',
    '_SC_SCHAR_MAX', '_SC_SCHAR_MIN', '_SC_SELECT', '_SC_SEMAPHORES',
    '_SC_SEM_NSEMS_MAX', '_SC_SEM_VALUE_MAX',
    '_SC_SHARED_MEMORY_OBJECTS', '_SC_SHELL', '_SC_SHRT_MAX',
    '_SC_SHRT_MIN', '_SC_SIGNALS', '_SC_SIGQUEUE_MAX', '_SC_SIGSTKSZ',
    '_SC_SINGLE_PROCESS', '_SC_SPAWN', '_SC_SPIN_LOCKS',
    '_SC_SPORADIC_SERVER', '_SC_SSIZE_MAX', '_SC_SS_REPL_MAX',
    '_SC_STREAMS', '_SC_STREAM_MAX', '_SC_SYMLOOP_MAX',
    '_SC_SYNCHRONIZED_IO', '_SC_SYSTEM_DATABASE',
    '_SC_SYSTEM_DATABASE_R', '_SC_THREADS',
    '_SC_THREAD_ATTR_STACKADDR', '_SC_THREAD_ATTR_STACKSIZE',
    '_SC_THREAD_CPUTIME', '_SC_THREAD_DESTRUCTOR_ITERATIONS',
    '_SC_THREAD_KEYS_MAX', '_SC_THREAD_PRIORITY_SCHEDULING',
    '_SC_THREAD_PRIO_INHERIT', '_SC_THREAD_PRIO_PROTECT',
    '_SC_THREAD_PROCESS_SHARED', '_SC_THREAD_ROBUST_PRIO_INHERIT',
    '_SC_THREAD_ROBUST_PRIO_PROTECT', '_SC_THREAD_SAFE_FUNCTIONS',
    '_SC_THREAD_SPORADIC_SERVER', '_SC_THREAD_STACK_MIN',
    '_SC_THREAD_THREADS_MAX', '_SC_TIMEOUTS', '_SC_TIMERS',
    '_SC_TIMER_MAX', '_SC_TRACE', '_SC_TRACE_EVENT_FILTER',
    '_SC_TRACE_EVENT_NAME_MAX', '_SC_TRACE_INHERIT', '_SC_TRACE_LOG',
    '_SC_TRACE_NAME_MAX', '_SC_TRACE_SYS_MAX',
    '_SC_TRACE_USER_EVENT_MAX', '_SC_TTY_NAME_MAX',
    '_SC_TYPED_MEMORY_OBJECTS', '_SC_TZNAME_MAX', '_SC_T_IOV_MAX',
    '_SC_UCHAR_MAX', '_SC_UINT_MAX', '_SC_UIO_MAXIOV',
    '_SC_ULONG_MAX', '_SC_USER_GROUPS', '_SC_USER_GROUPS_R',
    '_SC_USHRT_MAX', '_SC_V6_ILP32_OFF32', '_SC_V6_ILP32_OFFBIG',
    '_SC_V6_LP64_OFF64', '_SC_V6_LPBIG_OFFBIG', '_SC_V7_ILP32_OFF32',
    '_SC_V7_ILP32_OFFBIG', '_SC_V7_LP64_OFF64', '_SC_V7_LPBIG_OFFBIG',
    '_SC_VERSION', '_SC_WORD_BIT', '_SC_XBS5_ILP32_OFF32',
    '_SC_XBS5_ILP32_OFFBIG', '_SC_XBS5_LP64_OFF64',
    '_SC_XBS5_LPBIG_OFFBIG', '_SC_XOPEN_CRYPT', '_SC_XOPEN_ENH_I18N',
    '_SC_XOPEN_LEGACY', '_SC_XOPEN_REALTIME',
    '_SC_XOPEN_REALTIME_THREADS', '_SC_XOPEN_SHM',
    '_SC_XOPEN_STREAMS', '_SC_XOPEN_UNIX', '_SC_XOPEN_VERSION',
    '_SC_XOPEN_XCU_VERSION', '_SC_XOPEN_XPG2', '_SC_XOPEN_XPG3',
    '_SC_XOPEN_XPG4', '__FILE', '__acos', '__acosf', '__acosh',
    '__acoshf', '__acoshl', '__acosl', '__asin', '__asinf', '__asinh',
    '__asinhf', '__asinhl', '__asinl', '__asprintf', '__assert',
    '__assert_fail', '__assert_perror_fail', '__atan', '__atan2',
    '__atan2f', '__atan2l', '__atanf', '__atanh', '__atanhf',
    '__atanhl', '__atanl', '__atomic_wide_counter', '__blkcnt64_t',
    '__blkcnt_t', '__blksize_t', '__bswap_16', '__bswap_32',
    '__bswap_64', '__caddr_t', '__cbrt', '__cbrtf', '__cbrtl',
    '__ceil', '__ceilf', '__ceill', '__clock_t', '__clockid_t',
    '__cmsg_nxthdr', '__compar_fn_t', '__copysign', '__copysignf',
    '__copysignl', '__cos', '__cosf', '__cosh', '__coshf', '__coshl',
    '__cosl', '__cpu_mask', '__ctype_b_loc', '__ctype_get_mb_cur_max',
    '__ctype_tolower_loc', '__ctype_toupper_loc', '__daddr_t',
    '__daylight', '__dev_t', '__drem', '__dremf', '__dreml',
    '__environ', '__erf', '__erfc', '__erfcf', '__erfcl', '__erff',
    '__erfl', '__errno_location', '__exp', '__exp2', '__exp2f',
    '__exp2l', '__expf', '__expl', '__expm1', '__expm1f', '__expm1l',
    '__fabs', '__fabsf', '__fabsl', '__fd_mask', '__fdim', '__fdimf',
    '__fdiml', '__finite', '__finitef', '__finitel', '__floor',
    '__floorf', '__floorl', '__fma', '__fmaf', '__fmal', '__fmax',
    '__fmaxf', '__fmaxl', '__fmin', '__fminf', '__fminl', '__fmod',
    '__fmodf', '__fmodl', '__fpclassify', '__fpclassifyf',
    '__fpclassifyl', '__fpos64_t', '__fpos_t', '__frexp', '__frexpf',
    '__frexpl', '__fsblkcnt64_t', '__fsblkcnt_t', '__fsfilcnt64_t',
    '__fsfilcnt_t', '__fsid_t', '__fsword_t', '__gamma', '__gammaf',
    '__gammal', '__getdelim', '__getpgid', '__gid_t',
    '__gnuc_va_list', '__gwchar_t', '__hypot', '__hypotf', '__hypotl',
    '__id_t', '__ilogb', '__ilogbf', '__ilogbl', '__ino64_t',
    '__ino_t', '__int16_t', '__int32_t', '__int64_t', '__int8_t',
    '__int_least16_t', '__int_least32_t', '__int_least64_t',
    '__int_least8_t', '__intmax_t', '__intptr_t', '__iseqsig',
    '__iseqsigf', '__iseqsigl', '__isinf', '__isinff', '__isinfl',
    '__isnan', '__isnanf', '__isnanl', '__issignaling',
    '__issignalingf', '__issignalingl', '__itimer_which',
    '__itimer_which_t', '__j0', '__j0f', '__j0l', '__j1', '__j1f',
    '__j1l', '__jmp_buf', '__jn', '__jnf', '__jnl',
    '__kernel_caddr_t', '__kernel_clock_t', '__kernel_clockid_t',
    '__kernel_daddr_t', '__kernel_fd_set', '__kernel_fsid_t',
    '__kernel_gid16_t', '__kernel_gid32_t', '__kernel_gid_t',
    '__kernel_ino_t', '__kernel_ipc_pid_t', '__kernel_key_t',
    '__kernel_loff_t', '__kernel_long_t', '__kernel_mode_t',
    '__kernel_mqd_t', '__kernel_off_t', '__kernel_old_dev_t',
    '__kernel_old_gid_t', '__kernel_old_time_t', '__kernel_old_uid_t',
    '__kernel_pid_t', '__kernel_ptrdiff_t', '__kernel_sighandler_t',
    '__kernel_size_t', '__kernel_ssize_t', '__kernel_suseconds_t',
    '__kernel_time64_t', '__kernel_time_t', '__kernel_timer_t',
    '__kernel_uid16_t', '__kernel_uid32_t', '__kernel_uid_t',
    '__kernel_ulong_t', '__key_t', '__ldexp', '__ldexpf', '__ldexpl',
    '__lgamma', '__lgamma_r', '__lgammaf', '__lgammaf_r', '__lgammal',
    '__lgammal_r', '__libc_current_sigrtmax',
    '__libc_current_sigrtmin', '__llrint', '__llrintf', '__llrintl',
    '__llround', '__llroundf', '__llroundl', '__locale_t', '__loff_t',
    '__log', '__log10', '__log10f', '__log10l', '__log1p', '__log1pf',
    '__log1pl', '__log2', '__log2f', '__log2l', '__logb', '__logbf',
    '__logbl', '__logf', '__logl', '__lrint', '__lrintf', '__lrintl',
    '__lround', '__lroundf', '__lroundl', '__mbrlen', '__mbstate_t',
    '__memcmpeq', '__mempcpy', '__mode_t', '__modf', '__modff',
    '__modfl', '__nan', '__nanf', '__nanl', '__nearbyint',
    '__nearbyintf', '__nearbyintl', '__nextafter', '__nextafterf',
    '__nextafterl', '__nexttoward', '__nexttowardf', '__nexttowardl',
    '__nlink_t', '__off64_t', '__off_t', '__once_flag', '__overflow',
    '__pid_t', '__pow', '__powf', '__powl', '__pthread_list_t',
    '__pthread_register_cancel', '__pthread_slist_t',
    '__pthread_unregister_cancel', '__pthread_unwind_buf_t',
    '__pthread_unwind_next', '__quad_t', '__remainder',
    '__remainderf', '__remainderl', '__remquo', '__remquof',
    '__remquol', '__rint', '__rintf', '__rintl', '__rlim64_t',
    '__rlim_t', '__round', '__roundf', '__roundl', '__scalb',
    '__scalbf', '__scalbl', '__scalbln', '__scalblnf', '__scalblnl',
    '__scalbn', '__scalbnf', '__scalbnl', '__sched_cpualloc',
    '__sched_cpucount', '__sched_cpufree', '__sig_atomic_t',
    '__sighandler_t', '__signbit', '__signbitf', '__signbitl',
    '__significand', '__significandf', '__significandl', '__sigset_t',
    '__sigsetjmp', '__sigval_t', '__sin', '__sinf', '__sinh',
    '__sinhf', '__sinhl', '__sinl', '__socket_type', '__socklen_t',
    '__sqrt', '__sqrtf', '__sqrtl', '__ssize_t', '__stpcpy',
    '__stpncpy', '__strtok_r', '__suseconds64_t', '__suseconds_t',
    '__syscall_slong_t', '__syscall_ulong_t', '__sysv_signal',
    '__tan', '__tanf', '__tanh', '__tanhf', '__tanhl', '__tanl',
    '__tgamma', '__tgammaf', '__tgammal', '__thrd_t', '__time_t',
    '__timer_t', '__timezone', '__tolower_l', '__toupper_l',
    '__trunc', '__truncf', '__truncl', '__tss_t', '__tzname',
    '__u_char', '__u_int', '__u_long', '__u_quad_t', '__u_short',
    '__uflow', '__uid_t', '__uint16_identity', '__uint16_t',
    '__uint32_identity', '__uint32_t', '__uint64_identity',
    '__uint64_t', '__uint8_t', '__uint_least16_t', '__uint_least32_t',
    '__uint_least64_t', '__uint_least8_t', '__uintmax_t',
    '__useconds_t', '__y0', '__y0f', '__y0l', '__y1', '__y1f',
    '__y1l', '__yn', '__ynf', '__ynl', '_exit', '_tolower',
    '_toupper', 'a64l', 'abort', 'abs', 'accept', 'access', 'acct',
    'acos', 'acosf', 'acosh', 'acoshf', 'acoshl', 'acosl', 'add_rune',
    'adjtime', 'alarm', 'aligned_alloc', 'alloca', 'alphasort',
    'arc4random', 'arc4random_buf', 'arc4random_uniform', 'asctime',
    'asctime_r', 'asin', 'asinf', 'asinh', 'asinhf', 'asinhl',
    'asinl', 'asn1_setformat', 'asprintf', 'at_quick_exit', 'atan',
    'atan2', 'atan2f', 'atan2l', 'atanf', 'atanh', 'atanhf', 'atanhl',
    'atanl', 'atexit', 'atof', 'atoi', 'atol', 'atoll', 'bcmp',
    'bcopy', 'bind', 'blkcnt_t', 'blksize_t', 'brk', 'bsearch',
    'btowc', 'buffer', 'buffer_bget', 'buffer_copy', 'buffer_feed',
    'buffer_flush', 'buffer_get', 'buffer_init', 'buffer_peek',
    'buffer_put', 'buffer_putalign', 'buffer_putflush', 'buffer_seek',
    'bzero', 'c__Ea_ALPHA_RESET', 'c__Ea_BUS_ADRALN',
    'c__Ea_CLD_EXITED', 'c__Ea_DT_UNKNOWN', 'c__Ea_FPE_INTDIV',
    'c__Ea_FP_NAN', 'c__Ea_ILL_ILLOPC', 'c__Ea_LINE_NONE',
    'c__Ea_MSG_OOB', 'c__Ea_PAL_PROMPT', 'c__Ea_POLL_IN',
    'c__Ea_PTHREAD_CANCEL_DEFERRED', 'c__Ea_PTHREAD_CANCEL_ENABLE',
    'c__Ea_PTHREAD_CREATE_JOINABLE', 'c__Ea_PTHREAD_INHERIT_SCHED',
    'c__Ea_PTHREAD_MUTEX_STALLED', 'c__Ea_PTHREAD_MUTEX_TIMED_NP',
    'c__Ea_PTHREAD_PRIO_NONE', 'c__Ea_PTHREAD_PROCESS_PRIVATE',
    'c__Ea_PTHREAD_RWLOCK_PREFER_READER_NP',
    'c__Ea_PTHREAD_SCOPE_SYSTEM', 'c__Ea_R_CONS_ATTR_BOLD',
    'c__Ea_R_CONS_ERRMODE_NULL', 'c__Ea_R_TABLE_ALIGN_LEFT',
    'c__Ea_SCM_RIGHTS', 'c__Ea_SEGV_MAPERR', 'c__Ea_SHUT_RD',
    'c__Ea_SIGEV_SIGNAL', 'c__Ea_SI_ASYNCNL', 'c__Ea_SS_ONSTACK',
    'c__Ea__CS_PATH', 'c__Ea__ISupper', 'c__Ea__PC_LINK_MAX',
    'c__Ea__SC_ARG_MAX', 'c_bool', 'c_bool__enumvalues', 'caddr_t',
    'calloc', 'cbrt', 'cbrtf', 'cbrtl', 'cc_t', 'cdb_findnext',
    'cdb_findstart', 'cdb_free', 'cdb_getkvlen', 'cdb_init',
    'cdb_make_add', 'cdb_make_addbegin', 'cdb_make_addend',
    'cdb_make_finish', 'cdb_make_start', 'cdb_read', 'ceil', 'ceilf',
    'ceill', 'cfgetispeed', 'cfgetospeed', 'cfmakeraw', 'cfsetispeed',
    'cfsetospeed', 'cfsetspeed', 'chdir', 'chmod', 'chown', 'chroot',
    'clearenv', 'clearerr', 'clearerr_unlocked', 'clock',
    'clock_getcpuclockid', 'clock_getres', 'clock_gettime',
    'clock_nanosleep', 'clock_settime', 'clock_t', 'clockid_t',
    'close', 'closedir', 'closefrom', 'confstr', 'connect',
    'cookie_close_function_t', 'cookie_io_functions_t',
    'cookie_read_function_t', 'cookie_seek_function_t',
    'cookie_write_function_t', 'copysign', 'copysignf', 'copysignl',
    'cos', 'cosf', 'cosh', 'coshf', 'coshl', 'cosl', 'cpu_set_t',
    'creat', 'crypt', 'ctermid', 'ctime', 'ctime_r', 'daddr_t',
    'daemon', 'daylight', 'dev_t', 'dict', 'dict_add', 'dict_del',
    'dict_fini', 'dict_foreach', 'dict_free', 'dict_freecb',
    'dict_get', 'dict_getr', 'dict_getu', 'dict_hash', 'dict_init',
    'dict_new', 'dict_set', 'dict_stats', 'dicti', 'dictkv',
    'dictkv_cb', 'difftime', 'dirfd', 'div', 'div_t', 'double_t',
    'dprintf', 'drand48', 'drand48_r', 'drem', 'dremf', 'dreml',
    'dup', 'dup2', 'dysize', 'ecvt', 'ecvt_r', 'endusershell',
    'erand48', 'erand48_r', 'erf', 'erfc', 'erfcf', 'erfcl', 'erff',
    'erfl', 'execl', 'execle', 'execlp', 'execv', 'execve', 'execvp',
    'exit', 'exp', 'exp2', 'exp2f', 'exp2l', 'expf', 'expl',
    'explicit_bzero', 'expm1', 'expm1f', 'expm1l', 'fabs', 'fabsf',
    'fabsl', 'faccessat', 'fchdir', 'fchmod', 'fchmodat', 'fchown',
    'fchownat', 'fclose', 'fcntl', 'fcvt', 'fcvt_r', 'fd_mask',
    'fd_set', 'fdatasync', 'fdim', 'fdimf', 'fdiml', 'fdopen',
    'fdopendir', 'feof', 'feof_unlocked', 'ferror', 'ferror_unlocked',
    'fexecve', 'fflush', 'fflush_unlocked', 'ffs', 'ffsl', 'ffsll',
    'fgetc', 'fgetc_unlocked', 'fgetpos', 'fgets', 'fgetwc', 'fgetws',
    'fileno', 'fileno_unlocked', 'finite', 'finitef', 'finitel',
    'float_t', 'flockfile', 'floor', 'floorf', 'floorl', 'fma',
    'fmaf', 'fmal', 'fmax', 'fmaxf', 'fmaxl', 'fmemopen', 'fmin',
    'fminf', 'fminl', 'fmod', 'fmodf', 'fmodl', 'fopen',
    'fopencookie', 'fork', 'fpathconf', 'fpos_t', 'fpregset_t',
    'fprintf', 'fputc', 'fputc_unlocked', 'fputs', 'fputwc', 'fputws',
    'fread', 'fread_unlocked', 'free', 'freopen', 'frexp', 'frexpf',
    'frexpl', 'fsblkcnt_t', 'fscanf', 'fseek', 'fseeko', 'fsetpos',
    'fsfilcnt_t', 'fsid_t', 'fstat', 'fstatat', 'fsync', 'ftell',
    'ftello', 'ftruncate', 'ftrylockfile', 'funlockfile', 'futimens',
    'futimes', 'fwide', 'fwprintf', 'fwrite', 'fwrite_unlocked',
    'fwscanf', 'gamma', 'gammaf', 'gammal', 'gcvt', 'getc',
    'getc_unlocked', 'getchar', 'getchar_unlocked', 'getcwd',
    'getdelim', 'getdirentries', 'getdomainname', 'getdtablesize',
    'getegid', 'getentropy', 'getenv', 'geteuid', 'getgid',
    'getgroups', 'gethostid', 'gethostname', 'getitimer', 'getline',
    'getloadavg', 'getlogin', 'getlogin_r', 'getopt', 'getpagesize',
    'getpass', 'getpeername', 'getpgid', 'getpgrp', 'getpid',
    'getppid', 'getsid', 'getsockname', 'getsockopt', 'getsubopt',
    'gettimeofday', 'getuid', 'getusershell', 'getw', 'getwc',
    'getwchar', 'getwd', 'gid_t', 'gmtime', 'gmtime_r', 'greg_t',
    'gregset_t', 'gsignal', 'ht_pp_delete', 'ht_pp_find',
    'ht_pp_find_kv', 'ht_pp_foreach', 'ht_pp_free', 'ht_pp_insert',
    'ht_pp_insert_kv', 'ht_pp_new', 'ht_pp_new0', 'ht_pp_new_opt',
    'ht_pp_new_size', 'ht_pp_update', 'ht_pp_update_key',
    'ht_up_delete', 'ht_up_find', 'ht_up_find_kv', 'ht_up_foreach',
    'ht_up_free', 'ht_up_insert', 'ht_up_insert_kv', 'ht_up_new',
    'ht_up_new0', 'ht_up_new_opt', 'ht_up_new_size', 'ht_up_update',
    'ht_up_update_key', 'hypot', 'hypotf', 'hypotl', 'id_t',
    'idtype_t', 'ilogb', 'ilogbf', 'ilogbl', 'imaxabs', 'imaxdiv',
    'imaxdiv_t', 'index', 'initstate', 'initstate_r', 'ino_t',
    'int16_t', 'int32_t', 'int64_t', 'int8_t', 'int_fast16_t',
    'int_fast32_t', 'int_fast64_t', 'int_fast8_t', 'int_least16_t',
    'int_least32_t', 'int_least64_t', 'int_least8_t', 'intmax_t',
    'intptr_t', 'ioctl', 'isalnum', 'isalnum_l', 'isalpha',
    'isalpha_l', 'isascii', 'isatty', 'isblank', 'isblank_l',
    'iscntrl', 'iscntrl_l', 'isdigit', 'isdigit_l', 'isfdtype',
    'isgraph', 'isgraph_l', 'isinf', 'isinff', 'isinfl', 'islower',
    'islower_l', 'isnan', 'isnanf', 'isnanl', 'isprint', 'isprint_l',
    'ispunct', 'ispunct_l', 'isspace', 'isspace_l', 'isupper',
    'isupper_l', 'isxdigit', 'isxdigit_l', 'j0', 'j0f', 'j0l', 'j1',
    'j1f', 'j1l', 'jn', 'jnf', 'jnl', 'jrand48', 'jrand48_r', 'key_t',
    'kill', 'killpg', 'l64a', 'labs', 'lchmod', 'lchown', 'lcong48',
    'lcong48_r', 'ldexp', 'ldexpf', 'ldexpl', 'ldiv', 'ldiv_t',
    'lgamma', 'lgamma_r', 'lgammaf', 'lgammaf_r', 'lgammal',
    'lgammal_r', 'link', 'linkat', 'listen', 'llabs', 'lldiv',
    'lldiv_t', 'llrint', 'llrintf', 'llrintl', 'llround', 'llroundf',
    'llroundl', 'locale_t', 'localtime', 'localtime_r', 'lockf',
    'loff_t', 'log', 'log10', 'log10f', 'log10l', 'log1p', 'log1pf',
    'log1pl', 'log2', 'log2f', 'log2l', 'logb', 'logbf', 'logbl',
    'logf', 'logl', 'lrand48', 'lrand48_r', 'lrint', 'lrintf',
    'lrintl', 'lround', 'lroundf', 'lroundl', 'ls_append', 'ls_clone',
    'ls_del_n', 'ls_delete', 'ls_delete_data', 'ls_destroy',
    'ls_free', 'ls_get_n', 'ls_get_top', 'ls_insert', 'ls_item_new',
    'ls_iter_init', 'ls_join', 'ls_merge_sort', 'ls_new', 'ls_newf',
    'ls_pop', 'ls_pop_head', 'ls_prepend', 'ls_reverse', 'ls_sort',
    'ls_split', 'ls_split_iter', 'ls_unlink', 'lseek', 'lstat',
    'lutimes', 'malloc', 'max_align_t', 'mblen', 'mbrlen', 'mbrtowc',
    'mbsinit', 'mbsnrtowcs', 'mbsrtowcs', 'mbstate_t', 'mbstowcs',
    'mbtowc', 'mcontext_t', 'memccpy', 'memchr', 'memcmp', 'memcpy',
    'memmem', 'memmove', 'mempcpy', 'memset', 'mkdir', 'mkdirat',
    'mkdtemp', 'mkfifo', 'mkfifoat', 'mknod', 'mknodat', 'mkstemp',
    'mkstemps', 'mktemp', 'mktime', 'mode_t', 'modf', 'modff',
    'modfl', 'mrand48', 'mrand48_r', 'nan', 'nanf', 'nanl',
    'nanosleep', 'nearbyint', 'nearbyintf', 'nearbyintl', 'nextafter',
    'nextafterf', 'nextafterl', 'nexttoward', 'nexttowardf',
    'nexttowardl', 'nice', 'nlink_t', 'nrand48', 'nrand48_r', 'off_t',
    'on_exit', 'open', 'open_memstream', 'open_wmemstream', 'openat',
    'opendir', 'optarg', 'opterr', 'optind', 'optopt', 'pathconf',
    'pause', 'pclose', 'perror', 'pid_t', 'pipe', 'pj_N', 'pj_a',
    'pj_b', 'pj_d', 'pj_drain', 'pj_end', 'pj_f', 'pj_free', 'pj_i',
    'pj_j', 'pj_k', 'pj_kN', 'pj_ka', 'pj_kb', 'pj_kd', 'pj_kf',
    'pj_ki', 'pj_kn', 'pj_knull', 'pj_ko', 'pj_kr', 'pj_kraw',
    'pj_ks', 'pj_n', 'pj_ne', 'pj_new', 'pj_new_with_encoding',
    'pj_null', 'pj_o', 'pj_r', 'pj_raw', 'pj_reset', 'pj_s', 'pj_se',
    'pj_string', 'popen', 'posix_fadvise', 'posix_fallocate',
    'posix_memalign', 'pow', 'powf', 'powl', 'pread', 'printf',
    'profil', 'pselect', 'psiginfo', 'psignal', 'pthread_atfork',
    'pthread_attr_destroy', 'pthread_attr_getdetachstate',
    'pthread_attr_getguardsize', 'pthread_attr_getinheritsched',
    'pthread_attr_getschedparam', 'pthread_attr_getschedpolicy',
    'pthread_attr_getscope', 'pthread_attr_getstack',
    'pthread_attr_getstackaddr', 'pthread_attr_getstacksize',
    'pthread_attr_init', 'pthread_attr_setdetachstate',
    'pthread_attr_setguardsize', 'pthread_attr_setinheritsched',
    'pthread_attr_setschedparam', 'pthread_attr_setschedpolicy',
    'pthread_attr_setscope', 'pthread_attr_setstack',
    'pthread_attr_setstackaddr', 'pthread_attr_setstacksize',
    'pthread_attr_t', 'pthread_barrier_destroy',
    'pthread_barrier_init', 'pthread_barrier_t',
    'pthread_barrier_wait', 'pthread_barrierattr_destroy',
    'pthread_barrierattr_getpshared', 'pthread_barrierattr_init',
    'pthread_barrierattr_setpshared', 'pthread_barrierattr_t',
    'pthread_cancel', 'pthread_cond_broadcast',
    'pthread_cond_destroy', 'pthread_cond_init',
    'pthread_cond_signal', 'pthread_cond_t', 'pthread_cond_timedwait',
    'pthread_cond_wait', 'pthread_condattr_destroy',
    'pthread_condattr_getclock', 'pthread_condattr_getpshared',
    'pthread_condattr_init', 'pthread_condattr_setclock',
    'pthread_condattr_setpshared', 'pthread_condattr_t',
    'pthread_create', 'pthread_detach', 'pthread_equal',
    'pthread_exit', 'pthread_getcpuclockid', 'pthread_getschedparam',
    'pthread_getspecific', 'pthread_join', 'pthread_key_create',
    'pthread_key_delete', 'pthread_key_t', 'pthread_kill',
    'pthread_mutex_consistent', 'pthread_mutex_destroy',
    'pthread_mutex_getprioceiling', 'pthread_mutex_init',
    'pthread_mutex_lock', 'pthread_mutex_setprioceiling',
    'pthread_mutex_t', 'pthread_mutex_timedlock',
    'pthread_mutex_trylock', 'pthread_mutex_unlock',
    'pthread_mutexattr_destroy', 'pthread_mutexattr_getprioceiling',
    'pthread_mutexattr_getprotocol', 'pthread_mutexattr_getpshared',
    'pthread_mutexattr_getrobust', 'pthread_mutexattr_gettype',
    'pthread_mutexattr_init', 'pthread_mutexattr_setprioceiling',
    'pthread_mutexattr_setprotocol', 'pthread_mutexattr_setpshared',
    'pthread_mutexattr_setrobust', 'pthread_mutexattr_settype',
    'pthread_mutexattr_t', 'pthread_once', 'pthread_once_t',
    'pthread_rwlock_destroy', 'pthread_rwlock_init',
    'pthread_rwlock_rdlock', 'pthread_rwlock_t',
    'pthread_rwlock_timedrdlock', 'pthread_rwlock_timedwrlock',
    'pthread_rwlock_tryrdlock', 'pthread_rwlock_trywrlock',
    'pthread_rwlock_unlock', 'pthread_rwlock_wrlock',
    'pthread_rwlockattr_destroy', 'pthread_rwlockattr_getkind_np',
    'pthread_rwlockattr_getpshared', 'pthread_rwlockattr_init',
    'pthread_rwlockattr_setkind_np', 'pthread_rwlockattr_setpshared',
    'pthread_rwlockattr_t', 'pthread_self', 'pthread_setcancelstate',
    'pthread_setcanceltype', 'pthread_setschedparam',
    'pthread_setschedprio', 'pthread_setspecific', 'pthread_sigmask',
    'pthread_spin_destroy', 'pthread_spin_init', 'pthread_spin_lock',
    'pthread_spin_trylock', 'pthread_spin_unlock',
    'pthread_spinlock_t', 'pthread_t', 'pthread_testcancel',
    'ptrdiff_t', 'putc', 'putc_unlocked', 'putchar',
    'putchar_unlocked', 'putenv', 'puts', 'putw', 'putwc', 'putwchar',
    'pwrite', 'qecvt', 'qecvt_r', 'qfcvt', 'qfcvt_r', 'qgcvt',
    'qsort', 'quad_t', 'quick_exit', 'r_asctime_r',
    'r_asn1_create_binary', 'r_asn1_create_object',
    'r_asn1_create_string', 'r_asn1_free_binary',
    'r_asn1_free_object', 'r_asn1_free_string',
    'r_asn1_stringify_bits', 'r_asn1_stringify_boolean',
    'r_asn1_stringify_bytes', 'r_asn1_stringify_integer',
    'r_asn1_stringify_oid', 'r_asn1_stringify_string',
    'r_asn1_stringify_time', 'r_asn1_stringify_utctime',
    'r_asn1_to_string', 'r_assert_log', 'r_atomic_exchange',
    'r_atomic_store', 'r_axml_decode', 'r_base64_decode',
    'r_base64_decode_dyn', 'r_base64_encode', 'r_base64_encode_dyn',
    'r_base91_decode', 'r_base91_encode', 'r_big_add', 'r_big_and',
    'r_big_assign', 'r_big_cmp', 'r_big_dec', 'r_big_div',
    'r_big_divmod', 'r_big_fini', 'r_big_free', 'r_big_from_hexstr',
    'r_big_from_int', 'r_big_inc', 'r_big_init', 'r_big_is_zero',
    'r_big_isqrt', 'r_big_lshift', 'r_big_mod', 'r_big_mul',
    'r_big_new', 'r_big_or', 'r_big_powm', 'r_big_rshift',
    'r_big_sub', 'r_big_to_hexstr', 'r_big_to_int', 'r_big_xor',
    'r_bitmap_free', 'r_bitmap_new', 'r_bitmap_set',
    'r_bitmap_set_bytes', 'r_bitmap_test', 'r_bitmap_unset',
    'r_bplist_parse', 'r_buf_append_buf', 'r_buf_append_buf_slice',
    'r_buf_append_bytes', 'r_buf_append_nbytes',
    'r_buf_append_string', 'r_buf_append_ut16', 'r_buf_append_ut32',
    'r_buf_append_ut64', 'r_buf_append_ut8', 'r_buf_data',
    'r_buf_dump', 'r_buf_fini', 'r_buf_fread', 'r_buf_fread_at',
    'r_buf_free', 'r_buf_fwrite', 'r_buf_fwrite_at',
    'r_buf_get_string', 'r_buf_insert_bytes', 'r_buf_new',
    'r_buf_new_empty', 'r_buf_new_file', 'r_buf_new_mmap',
    'r_buf_new_slice', 'r_buf_new_slurp', 'r_buf_new_sparse',
    'r_buf_new_with_buf', 'r_buf_new_with_bytes', 'r_buf_new_with_io',
    'r_buf_new_with_pointers', 'r_buf_new_with_string',
    'r_buf_nonempty_list', 'r_buf_prepend_bytes', 'r_buf_read',
    'r_buf_read8', 'r_buf_read8_at', 'r_buf_read_all',
    'r_buf_read_at', 'r_buf_read_be16', 'r_buf_read_be16_at',
    'r_buf_read_be32', 'r_buf_read_be32_at', 'r_buf_read_be64',
    'r_buf_read_be64_at', 'r_buf_read_ble16_at',
    'r_buf_read_ble32_at', 'r_buf_read_ble64_at', 'r_buf_read_le16',
    'r_buf_read_le16_at', 'r_buf_read_le32', 'r_buf_read_le32_at',
    'r_buf_read_le64', 'r_buf_read_le64_at', 'r_buf_ref',
    'r_buf_resize', 'r_buf_seek', 'r_buf_set_bytes', 'r_buf_size',
    'r_buf_sleb128', 'r_buf_sleb128_at', 'r_buf_tell',
    'r_buf_to_string', 'r_buf_uleb128', 'r_buf_uleb128_at',
    'r_buf_write', 'r_buf_write_at', 'r_cache_flush', 'r_cache_free',
    'r_cache_get', 'r_cache_new', 'r_cache_set', 'r_charset_close',
    'r_charset_decode_str', 'r_charset_encode_str', 'r_charset_free',
    'r_charset_list', 'r_charset_new', 'r_charset_open',
    'r_charset_rune_free', 'r_charset_rune_new', 'r_charset_use',
    'r_config_bump', 'r_config_clone', 'r_config_desc',
    'r_config_eval', 'r_config_free', 'r_config_get',
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
    'r_config_set_b', 'r_config_set_b_cb', 'r_config_set_cb',
    'r_config_set_getter', 'r_config_set_i', 'r_config_set_i_cb',
    'r_config_set_setter', 'r_config_toggle', 'r_config_unserialize',
    'r_config_version', 'r_cons_2048', 'r_cons_any_key',
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
    'r_cons_cmd_help', 'r_cons_cmd_help_json',
    'r_cons_cmd_help_match', 'r_cons_color', 'r_cons_color_random',
    'r_cons_column', 'r_cons_context', 'r_cons_context_break',
    'r_cons_context_break_pop', 'r_cons_context_break_push',
    'r_cons_context_free', 'r_cons_context_is_main',
    'r_cons_context_load', 'r_cons_context_new',
    'r_cons_context_reset', 'r_cons_controlz',
    'r_cons_default_context_is_interactive', 'r_cons_drain',
    'r_cons_drop', 'r_cons_echo', 'r_cons_editor', 'r_cons_eflush',
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
    'r_cons_invert', 'r_cons_is_breaked', 'r_cons_is_initialized',
    'r_cons_is_interactive', 'r_cons_is_tty', 'r_cons_is_utf8',
    'r_cons_is_windows', 'r_cons_last', 'r_cons_lastline',
    'r_cons_lastline_utf8_ansi_len', 'r_cons_less', 'r_cons_less_str',
    'r_cons_line', 'r_cons_log_stub', 'r_cons_memset',
    'r_cons_message', 'r_cons_new', 'r_cons_newline',
    'r_cons_pal_copy', 'r_cons_pal_free', 'r_cons_pal_get',
    'r_cons_pal_get_i', 'r_cons_pal_get_name', 'r_cons_pal_init',
    'r_cons_pal_len', 'r_cons_pal_list', 'r_cons_pal_parse',
    'r_cons_pal_random', 'r_cons_pal_set', 'r_cons_pal_show',
    'r_cons_pal_update_event', 'r_cons_palette_init',
    'r_cons_password', 'r_cons_pipe_close', 'r_cons_pipe_open',
    'r_cons_pixel_drain', 'r_cons_pixel_fill', 'r_cons_pixel_flush',
    'r_cons_pixel_free', 'r_cons_pixel_get', 'r_cons_pixel_new',
    'r_cons_pixel_set', 'r_cons_pixel_sets', 'r_cons_pixel_tostring',
    'r_cons_pop', 'r_cons_print_clear', 'r_cons_print_fps',
    'r_cons_printat', 'r_cons_printf', 'r_cons_printf_list',
    'r_cons_println', 'r_cons_push', 'r_cons_rainbow_free',
    'r_cons_rainbow_get', 'r_cons_rainbow_new', 'r_cons_readchar',
    'r_cons_readchar_timeout', 'r_cons_readflush', 'r_cons_readpush',
    'r_cons_reset', 'r_cons_reset_colors', 'r_cons_rgb',
    'r_cons_rgb_fgbg', 'r_cons_rgb_init', 'r_cons_rgb_parse',
    'r_cons_rgb_str', 'r_cons_rgb_str_mode', 'r_cons_rgb_str_off',
    'r_cons_rgb_tostring', 'r_cons_set_click', 'r_cons_set_cup',
    'r_cons_set_interactive', 'r_cons_set_last_interactive',
    'r_cons_set_raw', 'r_cons_set_title', 'r_cons_set_utf8',
    'r_cons_show_cursor', 'r_cons_singleton', 'r_cons_sleep_begin',
    'r_cons_sleep_end', 'r_cons_stdout_open', 'r_cons_stdout_set_fd',
    'r_cons_strcat', 'r_cons_strcat_at', 'r_cons_strcat_justify',
    'r_cons_swap_ground', 'r_cons_switchbuf', 'r_cons_thready',
    'r_cons_version', 'r_cons_visual_flush', 'r_cons_visual_write',
    'r_cons_was_breaked', 'r_cons_write', 'r_cons_yesno',
    'r_cons_zero', 'r_crbtree_clear', 'r_crbtree_delete',
    'r_crbtree_find', 'r_crbtree_find_node', 'r_crbtree_first_node',
    'r_crbtree_free', 'r_crbtree_insert', 'r_crbtree_last_node',
    'r_crbtree_new', 'r_crbtree_take', 'r_ctime_r',
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
    'r_event_send', 'r_event_unhook', 'r_file_abspath',
    'r_file_abspath_rel', 'r_file_basename', 'r_file_binsh',
    'r_file_chmod', 'r_file_copy', 'r_file_dirname', 'r_file_dump',
    'r_file_exists', 'r_file_extension', 'r_file_fexists',
    'r_file_glob', 'r_file_gzslurp', 'r_file_hexdump',
    'r_file_is_abspath', 'r_file_is_c', 'r_file_is_directory',
    'r_file_is_executable', 'r_file_is_regular', 'r_file_lsrf',
    'r_file_mkstemp', 'r_file_mmap', 'r_file_mmap_arch',
    'r_file_mmap_free', 'r_file_mmap_read', 'r_file_mmap_write',
    'r_file_move', 'r_file_new', 'r_file_path', 'r_file_readlink',
    'r_file_rm', 'r_file_rm_rf', 'r_file_root', 'r_file_size',
    'r_file_slurp', 'r_file_slurp_hexpairs', 'r_file_slurp_line',
    'r_file_slurp_lines', 'r_file_slurp_lines_from_bottom',
    'r_file_slurp_random_line', 'r_file_slurp_random_line_count',
    'r_file_slurp_range', 'r_file_temp', 'r_file_temp_ex',
    'r_file_tmpdir', 'r_file_touch', 'r_file_truncate',
    'r_free_aligned', 'r_get_input_num_value', 'r_getopt_init',
    'r_getopt_next', 'r_graph_add_edge', 'r_graph_add_edge_at',
    'r_graph_add_node', 'r_graph_add_nodef', 'r_graph_adjacent',
    'r_graph_all_neighbours', 'r_graph_del_edge', 'r_graph_del_node',
    'r_graph_dfs', 'r_graph_dfs_node', 'r_graph_dfs_node_reverse',
    'r_graph_free', 'r_graph_get_neighbours', 'r_graph_get_node',
    'r_graph_get_nodes', 'r_graph_innodes', 'r_graph_new',
    'r_graph_node_iter', 'r_graph_node_split_forward',
    'r_graph_nth_neighbour', 'r_graph_reset', 'r_hex_bin2str',
    'r_hex_bin2strdup', 'r_hex_bin_truncate', 'r_hex_from_c',
    'r_hex_from_c_array', 'r_hex_from_c_str', 'r_hex_from_code',
    'r_hex_from_py', 'r_hex_from_py_array', 'r_hex_from_py_str',
    'r_hex_no_code', 'r_hex_pair2bin', 'r_hex_str2bin',
    'r_hex_str2bin_until_new', 'r_hex_str2binmask',
    'r_hex_str_is_valid', 'r_hex_to_byte', 'r_id_pool_free',
    'r_id_pool_grab_id', 'r_id_pool_kick_id', 'r_id_pool_new',
    'r_id_storage_add', 'r_id_storage_delete', 'r_id_storage_foreach',
    'r_id_storage_free', 'r_id_storage_get',
    'r_id_storage_get_highest', 'r_id_storage_get_lowest',
    'r_id_storage_get_next', 'r_id_storage_get_prev',
    'r_id_storage_list', 'r_id_storage_new', 'r_id_storage_set',
    'r_id_storage_take', 'r_inflate', 'r_inflate_lz4',
    'r_inflate_raw', 'r_interval_tree_all_at',
    'r_interval_tree_all_in', 'r_interval_tree_all_intersect',
    'r_interval_tree_at', 'r_interval_tree_delete',
    'r_interval_tree_fini', 'r_interval_tree_first_at',
    'r_interval_tree_init', 'r_interval_tree_insert',
    'r_interval_tree_iter_get', 'r_interval_tree_node_at',
    'r_interval_tree_node_at_data', 'r_interval_tree_resize',
    'r_is_valid_input_num_value', 'r_isprint', 'r_itv_begin',
    'r_itv_contain', 'r_itv_end', 'r_itv_eq', 'r_itv_free',
    'r_itv_include', 'r_itv_intersect', 'r_itv_new', 'r_itv_overlap',
    'r_itv_overlap2', 'r_itv_size', 'r_itv_t', 'r_leb128',
    'r_line_clipboard_push', 'r_line_completion_clear',
    'r_line_completion_fini', 'r_line_completion_init',
    'r_line_completion_push', 'r_line_completion_set',
    'r_line_dietline_init', 'r_line_free', 'r_line_get_prompt',
    'r_line_hist_add', 'r_line_hist_cmd_down', 'r_line_hist_cmd_up',
    'r_line_hist_free', 'r_line_hist_get', 'r_line_hist_get_size',
    'r_line_hist_label', 'r_line_hist_list', 'r_line_hist_load',
    'r_line_hist_save', 'r_line_hist_set_size', 'r_line_label_show',
    'r_line_new', 'r_line_readline', 'r_line_readline_cb',
    'r_line_set_hist_callback', 'r_line_set_prompt',
    'r_line_singleton', 'r_list_add_sorted', 'r_list_append',
    'r_list_clone', 'r_list_contains', 'r_list_del_n',
    'r_list_delete', 'r_list_delete_data', 'r_list_find',
    'r_list_first', 'r_list_free', 'r_list_get_bottom',
    'r_list_get_n', 'r_list_get_top', 'r_list_init', 'r_list_insert',
    'r_list_insertion_sort', 'r_list_item_new',
    'r_list_iter_get_data', 'r_list_iter_get_next',
    'r_list_iter_get_prev', 'r_list_iter_init', 'r_list_iter_length',
    'r_list_iter_to_top', 'r_list_join', 'r_list_last',
    'r_list_length', 'r_list_merge_sort', 'r_list_new', 'r_list_newf',
    'r_list_pop', 'r_list_pop_head', 'r_list_prepend', 'r_list_purge',
    'r_list_reverse', 'r_list_set_n', 'r_list_sort', 'r_list_split',
    'r_list_split_iter', 'r_list_to_str', 'r_list_uniq',
    'r_list_uniq_inplace', 'r_log', 'r_log_add_callback',
    'r_log_del_callback', 'r_log_fini', 'r_log_get_level',
    'r_log_get_traplevel', 'r_log_init', 'r_log_level', 'r_log_match',
    'r_log_message', 'r_log_set_callback', 'r_log_set_colors',
    'r_log_set_file', 'r_log_set_filter', 'r_log_set_level',
    'r_log_set_quiet', 'r_log_set_traplevel', 'r_log_show_origin',
    'r_log_show_source', 'r_log_show_ts', 'r_log_vmessage',
    'r_malloc_aligned', 'r_mem_alloc', 'r_mem_cmp_mask',
    'r_mem_copybits', 'r_mem_copybits_delta', 'r_mem_copyloop',
    'r_mem_count', 'r_mem_dup', 'r_mem_eq', 'r_mem_free',
    'r_mem_get_num', 'r_mem_is_printable', 'r_mem_is_zero',
    'r_mem_mem', 'r_mem_mem_aligned', 'r_mem_memzero',
    'r_mem_mmap_resize', 'r_mem_pool_alloc', 'r_mem_pool_deinit',
    'r_mem_pool_free', 'r_mem_pool_new', 'r_mem_protect',
    'r_mem_reverse', 'r_mem_set_num', 'r_mem_swap',
    'r_mem_swapendian', 'r_mem_swaporcopy', 'r_name_check',
    'r_name_filter', 'r_name_filter_dup', 'r_name_filter_flag',
    'r_name_filter_print', 'r_name_filter_ro', 'r_name_validate_char',
    'r_name_validate_first', 'r_name_validate_print', 'r_new_copy',
    'r_num_abs', 'r_num_as_string', 'r_num_between',
    'r_num_bit_count', 'r_num_calc', 'r_num_calc_index', 'r_num_chs',
    'r_num_conditional', 'r_num_cos', 'r_num_dup', 'r_num_free',
    'r_num_get', 'r_num_get_float', 'r_num_get_input_value',
    'r_num_get_name', 'r_num_irand', 'r_num_is_op',
    'r_num_is_valid_input', 'r_num_math', 'r_num_minmax_swap',
    'r_num_minmax_swap_i', 'r_num_new', 'r_num_rand', 'r_num_segaddr',
    'r_num_sin', 'r_num_str_len', 'r_num_str_split',
    'r_num_str_split_list', 'r_num_tail', 'r_num_tail_base',
    'r_num_to_bits', 'r_num_to_ternary', 'r_num_units', 'r_oids_add',
    'r_oids_delete', 'r_oids_find', 'r_oids_first', 'r_oids_foreach',
    'r_oids_foreach_prev', 'r_oids_free', 'r_oids_get',
    'r_oids_get_id', 'r_oids_get_od', 'r_oids_insert', 'r_oids_last',
    'r_oids_new', 'r_oids_odelete', 'r_oids_oget', 'r_oids_otake',
    'r_oids_sort', 'r_oids_take', 'r_oids_to_front', 'r_oids_to_rear',
    'r_pkcs7_cms_json', 'r_pkcs7_cms_to_string', 'r_pkcs7_free_cms',
    'r_pkcs7_free_spcinfo', 'r_pkcs7_parse_cms',
    'r_pkcs7_parse_spcinfo', 'r_poolfactory_alloc',
    'r_poolfactory_free', 'r_poolfactory_init',
    'r_poolfactory_instance', 'r_poolfactory_new',
    'r_poolfactory_stats', 'r_prof_end', 'r_prof_start',
    'r_protobuf_decode', 'r_punycode_decode', 'r_punycode_encode',
    'r_pvector_at', 'r_pvector_bsearch', 'r_pvector_clear',
    'r_pvector_contains', 'r_pvector_data', 'r_pvector_empty',
    'r_pvector_fini', 'r_pvector_flush', 'r_pvector_free',
    'r_pvector_index_ptr', 'r_pvector_init', 'r_pvector_insert',
    'r_pvector_insert_range', 'r_pvector_len', 'r_pvector_new',
    'r_pvector_new_with_len', 'r_pvector_pop', 'r_pvector_pop_front',
    'r_pvector_push', 'r_pvector_push_front', 'r_pvector_remove_at',
    'r_pvector_remove_data', 'r_pvector_reserve', 'r_pvector_set',
    'r_pvector_shrink', 'r_pvector_sort', 'r_qrcode_gen',
    'r_queue_dequeue', 'r_queue_enqueue', 'r_queue_free',
    'r_queue_is_empty', 'r_queue_new', 'r_range_add',
    'r_range_add_from_string', 'r_range_contains', 'r_range_free',
    'r_range_get_n', 'r_range_inverse', 'r_range_item_get',
    'r_range_list', 'r_range_merge', 'r_range_new',
    'r_range_new_from_string', 'r_range_overlap', 'r_range_percent',
    'r_range_size', 'r_range_sort', 'r_range_sub', 'r_rbnode_next',
    'r_rbnode_prev', 'r_rbtree_aug_delete', 'r_rbtree_aug_insert',
    'r_rbtree_aug_update_sum', 'r_rbtree_delete', 'r_rbtree_find',
    'r_rbtree_first', 'r_rbtree_free', 'r_rbtree_insert',
    'r_rbtree_iter_next', 'r_rbtree_iter_prev', 'r_rbtree_last',
    'r_rbtree_lower_bound', 'r_rbtree_lower_bound_forward',
    'r_rbtree_upper_bound', 'r_rbtree_upper_bound_backward',
    'r_read_at_be16', 'r_read_at_be32', 'r_read_at_be64',
    'r_read_at_be8', 'r_read_at_ble16', 'r_read_at_ble32',
    'r_read_at_ble64', 'r_read_at_ble8', 'r_read_at_le16',
    'r_read_at_le32', 'r_read_at_le64', 'r_read_at_le8',
    'r_read_at_me16', 'r_read_at_me32', 'r_read_at_me64',
    'r_read_at_me8', 'r_read_be16', 'r_read_be32', 'r_read_be64',
    'r_read_be8', 'r_read_ble', 'r_read_ble16', 'r_read_ble32',
    'r_read_ble64', 'r_read_ble8', 'r_read_le16', 'r_read_le32',
    'r_read_le64', 'r_read_le8', 'r_read_me16', 'r_read_me27',
    'r_read_me32', 'r_read_me64', 'r_read_me8', 'r_regex_check',
    'r_regex_error', 'r_regex_exec', 'r_regex_fini', 'r_regex_flags',
    'r_regex_free', 'r_regex_init', 'r_regex_match',
    'r_regex_match_list', 'r_regex_new', 'r_regex_run', 'r_run_call1',
    'r_run_call10', 'r_run_call2', 'r_run_call3', 'r_run_call4',
    'r_run_call5', 'r_run_call6', 'r_run_call7', 'r_run_call8',
    'r_run_call9', 'r_sandbox_chdir', 'r_sandbox_check',
    'r_sandbox_check_path', 'r_sandbox_close', 'r_sandbox_creat',
    'r_sandbox_disable', 'r_sandbox_enable', 'r_sandbox_fopen',
    'r_sandbox_grain', 'r_sandbox_kill', 'r_sandbox_lseek',
    'r_sandbox_open', 'r_sandbox_opendir', 'r_sandbox_read',
    'r_sandbox_system', 'r_sandbox_truncate', 'r_sandbox_write',
    'r_signal_from_string', 'r_signal_sigmask', 'r_signal_to_human',
    'r_signal_to_string', 'r_skiplist_delete',
    'r_skiplist_delete_node', 'r_skiplist_empty', 'r_skiplist_find',
    'r_skiplist_find_geq', 'r_skiplist_find_leq', 'r_skiplist_free',
    'r_skiplist_get_first', 'r_skiplist_get_geq',
    'r_skiplist_get_leq', 'r_skiplist_get_n', 'r_skiplist_insert',
    'r_skiplist_insert_autofree', 'r_skiplist_join', 'r_skiplist_new',
    'r_skiplist_purge', 'r_skiplist_to_list', 'r_sleb128',
    'r_snprintf', 'r_spaces_add', 'r_spaces_count',
    'r_spaces_current', 'r_spaces_current_name', 'r_spaces_fini',
    'r_spaces_free', 'r_spaces_get', 'r_spaces_init',
    'r_spaces_is_empty', 'r_spaces_new', 'r_spaces_pop',
    'r_spaces_purge', 'r_spaces_push', 'r_spaces_rename',
    'r_spaces_set', 'r_spaces_unset', 'r_stack_free',
    'r_stack_is_empty', 'r_stack_new', 'r_stack_newf', 'r_stack_peek',
    'r_stack_pop', 'r_stack_push', 'r_stack_size', 'r_stdin_slurp',
    'r_str_ansi_chrn', 'r_str_ansi_crop', 'r_str_ansi_filter',
    'r_str_ansi_len', 'r_str_ansi_nlen', 'r_str_ansi_strip',
    'r_str_ansi_trim', 'r_str_append', 'r_str_append_owned',
    'r_str_appendch', 'r_str_appendf', 'r_str_appendlen',
    'r_str_arg_escape', 'r_str_arg_unescape', 'r_str_argv',
    'r_str_argv_free', 'r_str_array_join', 'r_str_between',
    'r_str_binstr2bin', 'r_str_bits', 'r_str_bits64',
    'r_str_bits_from_string', 'r_str_bool', 'r_str_bounds',
    'r_str_byte_escape', 'r_str_case', 'r_str_casecmp',
    'r_str_casestr', 'r_str_ccmp', 'r_str_ccpy', 'r_str_char_count',
    'r_str_char_fullwidth', 'r_str_closer_chr', 'r_str_cmp',
    'r_str_cmp_list', 'r_str_constpool_fini', 'r_str_constpool_get',
    'r_str_constpool_init', 'r_str_contains_macro', 'r_str_crop',
    'r_str_delta', 'r_str_distance', 'r_str_do_until_token',
    'r_str_donut', 'r_str_dup', 'r_str_encoded_json',
    'r_str_endswith', 'r_str_eq', 'r_str_eqi', 'r_str_escape',
    'r_str_escape_dot', 'r_str_escape_latin1', 'r_str_escape_raw',
    'r_str_escape_sh', 'r_str_escape_sql', 'r_str_escape_utf16be',
    'r_str_escape_utf16le', 'r_str_escape_utf32be',
    'r_str_escape_utf32le', 'r_str_escape_utf8',
    'r_str_escape_utf8_for_json', 'r_str_escape_utf8_for_json_strip',
    'r_str_escape_utf8_keep_printable', 'r_str_filter',
    'r_str_filter_zeroline', 'r_str_firstbut',
    'r_str_firstbut_escape', 'r_str_fixspaces', 'r_str_fmtargs',
    'r_str_format_msvc_argv', 'r_str_from_ut64', 'r_str_get',
    'r_str_get_fail', 'r_str_getf', 'r_str_glob', 'r_str_hash',
    'r_str_hash64', 'r_str_highlight', 'r_str_home', 'r_str_ichr',
    'r_str_inject', 'r_str_insert', 'r_str_is_ascii', 'r_str_is_bool',
    'r_str_is_false', 'r_str_is_printable',
    'r_str_is_printable_incl_newlines', 'r_str_is_printable_limited',
    'r_str_is_true', 'r_str_isnumber', 'r_str_last', 'r_str_lastbut',
    'r_str_lchr', 'r_str_len_utf8', 'r_str_len_utf8_ansi',
    'r_str_len_utf8char', 'r_str_list_join', 'r_str_mb_to_wc',
    'r_str_mb_to_wc_l', 'r_str_ncasecmp', 'r_str_ncpy', 'r_str_ndup',
    'r_str_new', 'r_str_newf', 'r_str_newlen', 'r_str_newvf',
    'r_str_nextword', 'r_str_nlen', 'r_str_nlen_w', 'r_str_nstr',
    'r_str_ntrim', 'r_str_pad', 'r_str_path_escape',
    'r_str_path_unescape', 'r_str_prefix_all', 'r_str_prepend',
    'r_str_r2_prefix', 'r_str_range_in', 'r_str_rchr',
    'r_str_re_match', 'r_str_re_replace', 'r_str_remove_char',
    'r_str_repeat', 'r_str_replace', 'r_str_replace_all',
    'r_str_replace_ch', 'r_str_replace_char',
    'r_str_replace_char_once', 'r_str_replace_icase',
    'r_str_replace_in', 'r_str_replace_thunked', 'r_str_reverse',
    'r_str_rsep', 'r_str_rstr', 'r_str_rwx', 'r_str_rwx_i',
    'r_str_sanitize', 'r_str_sanitize_r2', 'r_str_sanitize_sdb_key',
    'r_str_scale', 'r_str_sep', 'r_str_size', 'r_str_skip_prefix',
    'r_str_split', 'r_str_split_duplist', 'r_str_split_lines',
    'r_str_split_list', 'r_str_ss', 'r_str_startswith',
    'r_str_startswith_inline', 'r_str_str_xy', 'r_str_stripLine',
    'r_str_sysbits', 'r_str_tok', 'r_str_tokenize',
    'r_str_tokenize_json', 'r_str_trim', 'r_str_trim_args',
    'r_str_trim_dup', 'r_str_trim_head', 'r_str_trim_head_ro',
    'r_str_trim_head_wp', 'r_str_trim_lines', 'r_str_trim_nc',
    'r_str_trim_path', 'r_str_trim_tail', 'r_str_trunc_ellipsis',
    'r_str_truncate_cmd', 'r_str_unescape', 'r_str_uri_decode',
    'r_str_uri_encode', 'r_str_utf16_decode', 'r_str_utf16_encode',
    'r_str_utf16_to_utf8', 'r_str_utf8_charsize',
    'r_str_utf8_charsize_last', 'r_str_utf8_charsize_prev',
    'r_str_utf8_codepoint', 'r_str_version', 'r_str_wc_to_mb',
    'r_str_wc_to_mb_l', 'r_str_word_count', 'r_str_word_get0',
    'r_str_word_get0set', 'r_str_word_get_first', 'r_str_word_set0',
    'r_str_word_set0_stack', 'r_str_wrap', 'r_str_write',
    'r_strbuf_append', 'r_strbuf_append_n', 'r_strbuf_appendf',
    'r_strbuf_copy', 'r_strbuf_drain', 'r_strbuf_drain_nofree',
    'r_strbuf_equals', 'r_strbuf_fini', 'r_strbuf_free',
    'r_strbuf_get', 'r_strbuf_getbin', 'r_strbuf_init',
    'r_strbuf_initf', 'r_strbuf_is_empty', 'r_strbuf_length',
    'r_strbuf_new', 'r_strbuf_prepend', 'r_strbuf_replace',
    'r_strbuf_replacef', 'r_strbuf_reserve', 'r_strbuf_set',
    'r_strbuf_setbin', 'r_strbuf_setf', 'r_strbuf_setptr',
    'r_strbuf_size', 'r_strbuf_slice', 'r_strbuf_vappendf',
    'r_strbuf_vsetf', 'r_string_append', 'r_string_appendf',
    'r_string_free', 'r_string_from', 'r_string_get', 'r_string_new',
    'r_string_newf', 'r_string_trim', 'r_string_unweak',
    'r_strpool_alloc', 'r_strpool_ansi_chop', 'r_strpool_append',
    'r_strpool_empty', 'r_strpool_fit', 'r_strpool_free',
    'r_strpool_get', 'r_strpool_get_i', 'r_strpool_get_index',
    'r_strpool_memcat', 'r_strpool_new', 'r_strpool_next',
    'r_strpool_slice', 'r_strstr_ansi', 'r_sub_str_lchr',
    'r_sub_str_rchr', 'r_swap_st16', 'r_swap_st32', 'r_swap_st64',
    'r_swap_ut16', 'r_swap_ut32', 'r_swap_ut64', 'r_sys_arch_id',
    'r_sys_arch_match', 'r_sys_arch_str', 'r_sys_aslr',
    'r_sys_backtrace', 'r_sys_chdir', 'r_sys_clearenv', 'r_sys_cmd',
    'r_sys_cmd_str', 'r_sys_cmd_str_full', 'r_sys_cmd_strf',
    'r_sys_cmdbg', 'r_sys_cmdf', 'r_sys_crash_handler', 'r_sys_dir',
    'r_sys_env_init', 'r_sys_exit', 'r_sys_fork', 'r_sys_get_environ',
    'r_sys_getdir', 'r_sys_getenv', 'r_sys_getenv_asbool',
    'r_sys_getenv_asint', 'r_sys_getpid', 'r_sys_info',
    'r_sys_info_free', 'r_sys_mkdir', 'r_sys_mkdirp', 'r_sys_mktemp',
    'r_sys_perror_str', 'r_sys_pid_to_path', 'r_sys_prefix',
    'r_sys_run', 'r_sys_run_rop', 'r_sys_set_environ', 'r_sys_setenv',
    'r_sys_sigaction', 'r_sys_signable', 'r_sys_signal',
    'r_sys_sleep', 'r_sys_stop', 'r_sys_tem', 'r_sys_thp_mode',
    'r_sys_truncate', 'r_sys_tts', 'r_sys_uid', 'r_sys_unxz',
    'r_sys_usleep', 'r_sys_whoami', 'r_syscmd_cat', 'r_syscmd_head',
    'r_syscmd_join', 'r_syscmd_ls', 'r_syscmd_mkdir',
    'r_syscmd_mktemp', 'r_syscmd_mv', 'r_syscmd_popalld',
    'r_syscmd_popd', 'r_syscmd_pushd', 'r_syscmd_sort',
    'r_syscmd_tail', 'r_syscmd_uniq', 'r_table_add_column',
    'r_table_add_row', 'r_table_add_row_list', 'r_table_add_rowf',
    'r_table_align', 'r_table_clone', 'r_table_column_clone',
    'r_table_column_free', 'r_table_column_nth', 'r_table_columns',
    'r_table_filter', 'r_table_free', 'r_table_group', 'r_table_help',
    'r_table_hide_header', 'r_table_new', 'r_table_pop',
    'r_table_push', 'r_table_query', 'r_table_row_free',
    'r_table_row_new', 'r_table_set_columnsf', 'r_table_sort',
    'r_table_tocsv', 'r_table_tofancystring', 'r_table_tohtml',
    'r_table_tojson', 'r_table_tor2cmds', 'r_table_tosimplestring',
    'r_table_tosql', 'r_table_tostring', 'r_table_totsv',
    'r_table_type', 'r_table_uniq', 'r_table_visual_list',
    'r_th_break', 'r_th_channel_free', 'r_th_channel_message_free',
    'r_th_channel_message_new', 'r_th_channel_message_read',
    'r_th_channel_new', 'r_th_channel_post',
    'r_th_channel_promise_free', 'r_th_channel_promise_new',
    'r_th_channel_promise_wait', 'r_th_channel_query',
    'r_th_channel_read', 'r_th_channel_write', 'r_th_cond_free',
    'r_th_cond_new', 'r_th_cond_signal', 'r_th_cond_signal_all',
    'r_th_cond_wait', 'r_th_free', 'r_th_getname', 'r_th_is_running',
    'r_th_kill', 'r_th_kill_free', 'r_th_lock_enter',
    'r_th_lock_free', 'r_th_lock_leave', 'r_th_lock_new',
    'r_th_lock_tryenter', 'r_th_lock_type_t', 'r_th_lock_wait',
    'r_th_new', 'r_th_self', 'r_th_sem_free', 'r_th_sem_new',
    'r_th_sem_post', 'r_th_sem_wait', 'r_th_set_running',
    'r_th_setaffinity', 'r_th_setname', 'r_th_start', 'r_th_wait',
    'r_th_wait_async', 'r_time_dos_time_stamp_to_posix', 'r_time_now',
    'r_time_now_mono', 'r_time_stamp_is_dos_format',
    'r_time_stamp_to_str', 'r_time_to_string', 'r_tokenizer_new',
    'r_tree_add_node', 'r_tree_bfs', 'r_tree_dfs', 'r_tree_free',
    'r_tree_new', 'r_tree_reset', 'r_type_del',
    'r_type_enum_getbitfield', 'r_type_enum_member', 'r_type_format',
    'r_type_func_args_count', 'r_type_func_args_name',
    'r_type_func_args_type', 'r_type_func_cc', 'r_type_func_exist',
    'r_type_func_guess', 'r_type_func_ret', 'r_type_get_bitsize',
    'r_type_get_by_offset', 'r_type_get_enum',
    'r_type_get_struct_memb', 'r_type_kind', 'r_type_link_at',
    'r_type_link_offset', 'r_type_set', 'r_type_set_link',
    'r_type_unlink', 'r_uleb128', 'r_uleb128_decode',
    'r_uleb128_encode', 'r_uleb128_len', 'r_utf16_decode',
    'r_utf16_to_utf8_l', 'r_utf16be_decode', 'r_utf16le_decode',
    'r_utf16le_encode', 'r_utf32_decode', 'r_utf32le_decode',
    'r_utf8_decode', 'r_utf8_encode', 'r_utf8_encode_str',
    'r_utf8_size', 'r_utf8_strlen', 'r_utf8_to_utf16_l',
    'r_utf_block_idx', 'r_utf_block_list', 'r_utf_block_name',
    'r_utf_bom_encoding', 'r_util_version', 'r_vector_assign',
    'r_vector_assign_at', 'r_vector_clear', 'r_vector_clone',
    'r_vector_empty', 'r_vector_fini', 'r_vector_flush',
    'r_vector_free', 'r_vector_index_ptr', 'r_vector_init',
    'r_vector_insert', 'r_vector_insert_range', 'r_vector_len',
    'r_vector_new', 'r_vector_pop', 'r_vector_pop_front',
    'r_vector_push', 'r_vector_push_front', 'r_vector_remove_at',
    'r_vector_reserve', 'r_vector_shrink', 'r_vlog', 'r_w32_init',
    'r_write_at_be16', 'r_write_at_be32', 'r_write_at_be64',
    'r_write_at_be8', 'r_write_at_ble8', 'r_write_at_le16',
    'r_write_at_le32', 'r_write_at_le64', 'r_write_at_le8',
    'r_write_at_me16', 'r_write_at_me32', 'r_write_at_me64',
    'r_write_at_me8', 'r_write_be16', 'r_write_be24', 'r_write_be32',
    'r_write_be64', 'r_write_be8', 'r_write_ble', 'r_write_ble16',
    'r_write_ble24', 'r_write_ble32', 'r_write_ble64', 'r_write_ble8',
    'r_write_le16', 'r_write_le24', 'r_write_le32', 'r_write_le64',
    'r_write_le8', 'r_write_me16', 'r_write_me32', 'r_write_me64',
    'r_write_me8', 'r_wstr_clen', 'r_x509_certificate_dump',
    'r_x509_certificate_json', 'r_x509_certificate_to_string',
    'r_x509_crl_json', 'r_x509_crl_to_string',
    'r_x509_free_certificate', 'r_x509_parse_certificate',
    'r_x509_parse_certificate2', 'r_x509_parse_crl', 'r_xdg_cachedir',
    'r_xdg_configdir', 'r_xdg_datadir', 'raise_', 'rand', 'rand_r',
    'random', 'random_r', 'read', 'read_i32_leb128',
    'read_i64_leb128', 'read_u32_leb128', 'read_u64_leb128',
    'readdir', 'readdir_r', 'readlink', 'readlinkat', 'realloc',
    'reallocarray', 'realpath', 'recv', 'recvfrom', 'recvmsg',
    'register_t', 'remainder', 'remainderf', 'remainderl', 'remove',
    'remquo', 'remquof', 'remquol', 'rename', 'renameat',
    'ret_ascii_table', 'revoke', 'rewind', 'rewinddir', 'rindex',
    'rint', 'rintf', 'rintl', 'rmdir', 'round', 'roundf', 'roundl',
    'rpmatch', 'sa_family_t', 'sbrk', 'scalb', 'scalbf', 'scalbl',
    'scalbln', 'scalblnf', 'scalblnl', 'scalbn', 'scalbnf', 'scalbnl',
    'scandir', 'scanf', 'sched_get_priority_max',
    'sched_get_priority_min', 'sched_getparam', 'sched_getscheduler',
    'sched_rr_get_interval', 'sched_setparam', 'sched_setscheduler',
    'sched_yield', 'sdb_add', 'sdb_alen', 'sdb_alen_ignore_empty',
    'sdb_anext', 'sdb_array_add', 'sdb_array_add_num',
    'sdb_array_add_sorted', 'sdb_array_add_sorted_num',
    'sdb_array_append', 'sdb_array_append_num', 'sdb_array_compact',
    'sdb_array_contains', 'sdb_array_contains_num',
    'sdb_array_delete', 'sdb_array_get', 'sdb_array_get_idx',
    'sdb_array_get_num', 'sdb_array_indexof', 'sdb_array_insert',
    'sdb_array_insert_num', 'sdb_array_length', 'sdb_array_list',
    'sdb_array_pop', 'sdb_array_pop_head', 'sdb_array_pop_num',
    'sdb_array_pop_tail', 'sdb_array_prepend',
    'sdb_array_prepend_num', 'sdb_array_push', 'sdb_array_push_num',
    'sdb_array_remove', 'sdb_array_remove_num', 'sdb_array_set',
    'sdb_array_set_num', 'sdb_array_size', 'sdb_array_sort',
    'sdb_array_sort_num', 'sdb_array_unset', 'sdb_aslice', 'sdb_atoi',
    'sdb_bool_get', 'sdb_bool_set', 'sdb_close', 'sdb_concat',
    'sdb_config', 'sdb_const_anext', 'sdb_const_get',
    'sdb_const_get_len', 'sdb_copy', 'sdb_count', 'sdb_decode',
    'sdb_decode_raw', 'sdb_diff', 'sdb_diff_format',
    'sdb_disk_create', 'sdb_disk_finish', 'sdb_disk_insert',
    'sdb_disk_unlink', 'sdb_drain', 'sdb_dump_begin',
    'sdb_dump_dupnext', 'sdb_dump_hasnext', 'sdb_dump_next',
    'sdb_encode', 'sdb_encode_raw', 'sdb_exists', 'sdb_expire_get',
    'sdb_expire_set', 'sdb_file', 'sdb_fmt_array',
    'sdb_fmt_array_num', 'sdb_fmt_free', 'sdb_fmt_init',
    'sdb_fmt_tobin', 'sdb_fmt_tostr', 'sdb_foreach',
    'sdb_foreach_list', 'sdb_foreach_list_filter',
    'sdb_foreach_match', 'sdb_free', 'sdb_get', 'sdb_get_len',
    'sdb_hash', 'sdb_hash_byte', 'sdb_hash_len', 'sdb_hook',
    'sdb_hook_call', 'sdb_hook_free', 'sdb_ht_delete', 'sdb_ht_find',
    'sdb_ht_find_kvp', 'sdb_ht_free', 'sdb_ht_insert',
    'sdb_ht_insert_kvp', 'sdb_ht_new', 'sdb_ht_update', 'sdb_isempty',
    'sdb_isjson', 'sdb_isnum', 'sdb_itoa', 'sdb_itoas',
    'sdb_journal_clear', 'sdb_journal_close', 'sdb_journal_load',
    'sdb_journal_log', 'sdb_journal_open', 'sdb_journal_unlink',
    'sdb_json_format', 'sdb_json_get', 'sdb_json_get_bool',
    'sdb_json_get_str', 'sdb_json_indent', 'sdb_json_num_dec',
    'sdb_json_num_get', 'sdb_json_num_inc', 'sdb_json_num_set',
    'sdb_json_set', 'sdb_json_unindent', 'sdb_like', 'sdb_lock',
    'sdb_lock_file', 'sdb_lock_wait', 'sdb_match', 'sdb_merge',
    'sdb_nadd', 'sdb_new', 'sdb_new0', 'sdb_nget', 'sdb_now',
    'sdb_ns', 'sdb_ns_free', 'sdb_ns_init', 'sdb_ns_lock',
    'sdb_ns_path', 'sdb_ns_set', 'sdb_ns_sync', 'sdb_ns_unset',
    'sdb_nset', 'sdb_num_add', 'sdb_num_base', 'sdb_num_dec',
    'sdb_num_exists', 'sdb_num_get', 'sdb_num_inc', 'sdb_num_max',
    'sdb_num_min', 'sdb_num_nget', 'sdb_num_nset', 'sdb_num_set',
    'sdb_nunset', 'sdb_open', 'sdb_open_gperf', 'sdb_ptr_get',
    'sdb_ptr_set', 'sdb_query', 'sdb_query_file', 'sdb_query_lines',
    'sdb_queryf', 'sdb_querys', 'sdb_querysf', 'sdb_remove',
    'sdb_reset', 'sdb_set', 'sdb_set_owned', 'sdb_setup', 'sdb_stats',
    'sdb_sync', 'sdb_text_check', 'sdb_text_load',
    'sdb_text_load_buf', 'sdb_text_save', 'sdb_text_save_fd',
    'sdb_type', 'sdb_uncat', 'sdb_unhook', 'sdb_unlink', 'sdb_unlock',
    'sdb_unow', 'sdb_unset', 'sdb_unset_like', 'sdbkv_free',
    'sdbkv_key', 'sdbkv_key_len', 'sdbkv_new', 'sdbkv_new2',
    'sdbkv_value', 'sdbkv_value_len', 'search_from_char',
    'search_from_hex', 'seed48', 'seed48_r', 'seek_set', 'seekdir',
    'select', 'sem_close', 'sem_destroy', 'sem_getvalue', 'sem_init',
    'sem_open', 'sem_post', 'sem_t', 'sem_timedwait', 'sem_trywait',
    'sem_unlink', 'sem_wait', 'send', 'sendmsg', 'sendto', 'setbuf',
    'setbuffer', 'setdomainname', 'setegid', 'setenv', 'seteuid',
    'setgid', 'sethostid', 'sethostname', 'setitimer', 'setlinebuf',
    'setlogin', 'setpgid', 'setpgrp', 'setregid', 'setreuid',
    'setsid', 'setsockopt', 'setstate', 'setstate_r', 'settimeofday',
    'setuid', 'setusershell', 'setvbuf', 'shutdown', 'sig_atomic_t',
    'sig_t', 'sigaction', 'sigaddset', 'sigaltstack', 'sigblock',
    'sigdelset', 'sigemptyset', 'sigevent_t', 'sigfillset',
    'siggetmask', 'siginfo_t', 'siginterrupt', 'sigismember',
    'signal', 'signgam', 'significand', 'significandf',
    'significandl', 'sigpending', 'sigprocmask', 'sigqueue',
    'sigreturn', 'sigset_t', 'sigsetmask', 'sigstack', 'sigsuspend',
    'sigtimedwait', 'sigval_t', 'sigwait', 'sigwaitinfo', 'sin',
    'sinf', 'sinh', 'sinhf', 'sinhl', 'sinl', 'size_t', 'sleep',
    'snprintf', 'sockatmark', 'socket', 'socketpair', 'socklen_t',
    'speed_t', 'sprintf', 'sqrt', 'sqrtf', 'sqrtl', 'srand',
    'srand48', 'srand48_r', 'srandom', 'srandom_r', 'sscanf',
    'ssignal', 'ssize_t', 'stack_t', 'stat', 'stderr', 'stdin',
    'stdout', 'stpcpy', 'stpncpy', 'str_operation', 'strcasecmp',
    'strcasecmp_l', 'strcasestr', 'strcat', 'strchr', 'strchrnul',
    'strcmp', 'strcoll', 'strcoll_l', 'strcpy', 'strcspn', 'strdup',
    'strerror', 'strerror_l', 'strerror_r', 'strftime', 'strftime_l',
    'strlcat', 'strlcpy', 'strlen', 'strncasecmp', 'strncasecmp_l',
    'strncat', 'strncmp', 'strncpy', 'strndup', 'strnlen', 'strpbrk',
    'strrchr', 'strsep', 'strsignal', 'strspn', 'strstr', 'strtod',
    'strtof', 'strtoimax', 'strtok', 'strtok_r', 'strtol', 'strtold',
    'strtoll', 'strtoq', 'strtoul', 'strtoull', 'strtoumax',
    'strtouq', 'struct_RConsCursorPos', 'struct_RConsPixel',
    'struct_RListInfo', 'struct_RModal', 'struct_RNumCalcValue',
    'struct_RPanelsSnow', 'struct_RStrBuf', 'struct_RString',
    'struct_RStrpool', 'struct_RSysInfo', 'struct_RTable',
    'struct_RTableColumn', 'struct_RTableColumnType',
    'struct_RTableRow', 'struct_RThreadChannel',
    'struct_RThreadChannelMessage', 'struct_RThreadChannelPromise',
    'struct_RUtfBlock', 'struct_SdbJsonString',
    'struct_SpcAttributeTypeAndOptionalValue', 'struct_SpcDigestInfo',
    'struct_SpcIndirectDataContent', 'struct__G_fpos64_t',
    'struct__G_fpos_t', 'struct__IO_FILE', 'struct__IO_codecvt',
    'struct__IO_cookie_io_functions_t', 'struct__IO_marker',
    'struct__IO_wide_data', 'struct___atomic_wide_counter___value32',
    'struct___cancel_jmp_buf_tag', 'struct___dirstream',
    'struct___fsid_t', 'struct___jmp_buf_tag',
    'struct___kernel_fd_set', 'struct___kernel_fsid_t',
    'struct___locale_data', 'struct___locale_struct',
    'struct___mbstate_t', 'struct___once_flag',
    'struct___pthread_cleanup_frame', 'struct___pthread_cond_s',
    'struct___pthread_internal_list',
    'struct___pthread_internal_slist', 'struct___pthread_mutex_s',
    'struct___pthread_rwlock_arch_t', 'struct___pthread_unwind_buf_t',
    'struct___sigset_t', 'struct___va_list_tag', 'struct__fpreg',
    'struct__fpstate', 'struct__fpx_sw_bytes', 'struct__fpxreg',
    'struct__libc_fpstate', 'struct__libc_fpxreg',
    'struct__libc_xmmreg', 'struct__pthread_cleanup_buffer',
    'struct__ut128', 'struct__ut256', 'struct__ut80', 'struct__ut96',
    'struct__utX', 'struct__xmmreg', 'struct__xsave_hdr',
    'struct__xstate', 'struct__ymmh_state', 'struct_buffer',
    'struct_cdb', 'struct_cdb_hp', 'struct_cdb_hplist',
    'struct_cdb_make', 'struct_cmsghdr', 'struct_cpu_set_t',
    'struct_dict', 'struct_dictkv', 'struct_dirent', 'struct_div_t',
    'struct_drand48_data', 'struct_fd_set', 'struct_flock',
    'struct_ht_pp_bucket_t', 'struct_ht_pp_kv',
    'struct_ht_pp_options_t', 'struct_ht_pp_t',
    'struct_ht_up_bucket_t', 'struct_ht_up_kv',
    'struct_ht_up_options_t', 'struct_ht_up_t', 'struct_imaxdiv_t',
    'struct_iovec', 'struct_itimerspec', 'struct_itimerval',
    'struct_ldiv_t', 'struct_linger', 'struct_lldiv_t',
    'struct_ls_iter_t', 'struct_ls_t', 'struct_max_align_t',
    'struct_mcontext_t', 'struct_msghdr', 'struct_osockaddr',
    'struct_pj_t', 'struct_r_asn1_bin_t', 'struct_r_asn1_list_t',
    'struct_r_asn1_object_t', 'struct_r_asn1_string_t',
    'struct_r_bitmap_t', 'struct_r_bplist_t', 'struct_r_buf_cache_t',
    'struct_r_buf_t', 'struct_r_buffer_methods_t', 'struct_r_cache_t',
    'struct_r_charset_rune_t', 'struct_r_charset_t',
    'struct_r_config_hold_t', 'struct_r_config_node_t',
    'struct_r_config_t', 'struct_r_cons_bind_t',
    'struct_r_cons_canvas_line_style_t', 'struct_r_cons_canvas_t',
    'struct_r_cons_context_t', 'struct_r_cons_grep_t',
    'struct_r_cons_palette_t', 'struct_r_cons_printable_palette_t',
    'struct_r_cons_t', 'struct_r_crbtree_node', 'struct_r_crbtree_t',
    'struct_r_diff_op_t', 'struct_r_diff_t', 'struct_r_diffchar_t',
    'struct_r_event_callback_handle_t',
    'struct_r_event_class_attr_rename_t',
    'struct_r_event_class_attr_set_t', 'struct_r_event_class_attr_t',
    'struct_r_event_class_rename_t', 'struct_r_event_class_t',
    'struct_r_event_debug_process_finished_t',
    'struct_r_event_io_write_t', 'struct_r_event_meta_t',
    'struct_r_event_t', 'struct_r_getopt_t', 'struct_r_graph_edge_t',
    'struct_r_graph_node_t', 'struct_r_graph_t',
    'struct_r_graph_visitor_t', 'struct_r_hud_t',
    'struct_r_id_pool_t', 'struct_r_id_storage_t',
    'struct_r_interval_node_t', 'struct_r_interval_t',
    'struct_r_interval_tree_t', 'struct_r_lev_buf',
    'struct_r_line_buffer_t', 'struct_r_line_comp_t',
    'struct_r_line_hist_t', 'struct_r_line_t', 'struct_r_list_iter_t',
    'struct_r_list_range_t', 'struct_r_list_t',
    'struct_r_log_source_t', 'struct_r_log_t',
    'struct_r_mem_pool_factory_t', 'struct_r_mem_pool_t',
    'struct_r_mmap_t', 'struct_r_num_big_t', 'struct_r_num_calc_t',
    'struct_r_num_t', 'struct_r_ordered_id_storage_t',
    'struct_r_panel_model_t', 'struct_r_panel_pos_t',
    'struct_r_panel_t', 'struct_r_panel_view_t',
    'struct_r_panels_menu_item', 'struct_r_panels_menu_t',
    'struct_r_panels_root_t', 'struct_r_panels_t',
    'struct_r_pkcs7_attribute_t', 'struct_r_pkcs7_attributes_t',
    'struct_r_pkcs7_certificaterevocationlists_t',
    'struct_r_pkcs7_container_t', 'struct_r_pkcs7_contentinfo_t',
    'struct_r_pkcs7_digestalgorithmidentifiers_t',
    'struct_r_pkcs7_extendedcertificatesandcertificates_t',
    'struct_r_pkcs7_issuerandserialnumber_t',
    'struct_r_pkcs7_signeddata_t', 'struct_r_pkcs7_signerinfo_t',
    'struct_r_pkcs7_signerinfos_t', 'struct_r_prof_t',
    'struct_r_pvector_t', 'struct_r_queue_t', 'struct_r_range_item_t',
    'struct_r_range_t', 'struct_r_rb_iter_t', 'struct_r_rb_node_t',
    'struct_r_regex_t', 'struct_r_regmatch_t',
    'struct_r_selection_widget_t', 'struct_r_skiplist_node_t',
    'struct_r_skiplist_t', 'struct_r_space_event_t',
    'struct_r_space_event_t_0_count',
    'struct_r_space_event_t_0_rename',
    'struct_r_space_event_t_0_unset', 'struct_r_space_t',
    'struct_r_spaces_t', 'struct_r_stack_t',
    'struct_r_str_constpool_t', 'struct_r_th_cond_t',
    'struct_r_th_lock_t', 'struct_r_th_lock_t_0',
    'struct_r_th_pool_t', 'struct_r_th_sem_t', 'struct_r_th_t',
    'struct_r_tokenizer_t', 'struct_r_tree_node_t', 'struct_r_tree_t',
    'struct_r_tree_visitor_t', 'struct_r_type_enum',
    'struct_r_vector_t', 'struct_r_x509_algorithmidentifier_t',
    'struct_r_x509_authoritykeyidentifier_t',
    'struct_r_x509_certificate_t',
    'struct_r_x509_certificaterevocationlist',
    'struct_r_x509_crlentry', 'struct_r_x509_extension_t',
    'struct_r_x509_extensions_t', 'struct_r_x509_name_t',
    'struct_r_x509_subjectpublickeyinfo_t',
    'struct_r_x509_tbscertificate_t', 'struct_r_x509_validity_t',
    'struct_random_data', 'struct_rcolor_t', 'struct_re_guts',
    'struct_rusage', 'struct_sched_param', 'struct_sdb_diff_t',
    'struct_sdb_gperf_t', 'struct_sdb_kv', 'struct_sdb_ns_t',
    'struct_sdb_t', 'struct_sigaction', 'struct_sigcontext',
    'struct_sigevent', 'struct_sigevent_0__sigev_thread',
    'struct_siginfo_t', 'struct_siginfo_t_0_4_0__addr_bnd',
    'struct_siginfo_t_0__kill', 'struct_siginfo_t_0__rt',
    'struct_siginfo_t_0__sigchld', 'struct_siginfo_t_0__sigfault',
    'struct_siginfo_t_0__sigpoll', 'struct_siginfo_t_0__sigsys',
    'struct_siginfo_t_0__timer', 'struct_sigstack', 'struct_sockaddr',
    'struct_sockaddr_storage', 'struct_stack_t', 'struct_stat',
    'struct_termio', 'struct_termios', 'struct_timespec',
    'struct_timeval', 'struct_timezone', 'struct_tm',
    'struct_ucontext_t', 'struct_winsize', 'strxfrm', 'strxfrm_l',
    'suseconds_t', 'swprintf', 'swscanf', 'symlink', 'symlinkat',
    'sync', 'syscall', 'sysconf', 'system', 'tan', 'tanf', 'tanh',
    'tanhf', 'tanhl', 'tanl', 'tcdrain', 'tcflag_t', 'tcflow',
    'tcflush', 'tcgetattr', 'tcgetpgrp', 'tcgetsid', 'tcsendbreak',
    'tcsetattr', 'tcsetpgrp', 'telldir', 'tempnam', 'tgamma',
    'tgammaf', 'tgammal', 'time', 'time_t', 'timegm', 'timelocal',
    'timer_create', 'timer_delete', 'timer_getoverrun',
    'timer_gettime', 'timer_settime', 'timer_t', 'timespec_get',
    'timezone', 'tmpfile', 'tmpnam', 'tmpnam_r', 'toascii', 'tolower',
    'tolower_l', 'toupper', 'toupper_l', 'trunc', 'truncate',
    'truncf', 'truncl', 'ttyname', 'ttyname_r', 'ttyslot', 'tzname',
    'tzset', 'u_char', 'u_int', 'u_int16_t', 'u_int32_t', 'u_int64_t',
    'u_int8_t', 'u_long', 'u_quad_t', 'u_short', 'ualarm',
    'ucontext_t', 'uid_t', 'uint', 'uint16_t', 'uint32_t', 'uint64_t',
    'uint8_t', 'uint_fast16_t', 'uint_fast32_t', 'uint_fast64_t',
    'uint_fast8_t', 'uint_least16_t', 'uint_least32_t',
    'uint_least64_t', 'uint_least8_t', 'uintmax_t', 'uintptr_t',
    'ulong', 'umask', 'ungetc', 'ungetwc', 'union_RNumFloat',
    'union___atomic_wide_counter', 'union___mbstate_t___value',
    'union_pthread_attr_t', 'union_pthread_barrier_t',
    'union_pthread_barrierattr_t', 'union_pthread_cond_t',
    'union_pthread_condattr_t', 'union_pthread_mutex_t',
    'union_pthread_mutexattr_t', 'union_pthread_rwlock_t',
    'union_pthread_rwlockattr_t', 'union_r_space_event_t_data',
    'union_sem_t', 'union_sigaction___sigaction_handler',
    'union_sigcontext_0', 'union_sigevent__sigev_un',
    'union_siginfo_t_0_4__bounds', 'union_siginfo_t__sifields',
    'union_sigval', 'union_utAny', 'unlink', 'unlinkat', 'unsetenv',
    'useconds_t', 'ushort', 'usleep', 'ust16', 'ust32', 'ust64',
    'ut128', 'ut256', 'ut27', 'ut32_pack', 'ut32_pack_big',
    'ut32_unpack', 'ut80', 'ut96', 'utAny', 'utX', 'utimensat',
    'utimes', 'uut16', 'uut32', 'uut64', 'va_list', 'valloc',
    'vasprintf', 'vdprintf', 'vfork', 'vfprintf', 'vfscanf',
    'vfwprintf', 'vfwscanf', 'vhangup', 'vprintf', 'vscanf',
    'vsnprintf', 'vsprintf', 'vsscanf', 'vswprintf', 'vswscanf',
    'vwprintf', 'vwscanf', 'wait', 'wait3', 'wait4', 'waitid',
    'waitpid', 'wchar_t', 'wcpcpy', 'wcpncpy', 'wcrtomb',
    'wcscasecmp', 'wcscasecmp_l', 'wcscat', 'wcschr', 'wcscmp',
    'wcscoll', 'wcscoll_l', 'wcscpy', 'wcscspn', 'wcsdup', 'wcsftime',
    'wcslcat', 'wcslcpy', 'wcslen', 'wcsncasecmp', 'wcsncasecmp_l',
    'wcsncat', 'wcsncmp', 'wcsncpy', 'wcsnlen', 'wcsnrtombs',
    'wcspbrk', 'wcsrchr', 'wcsrtombs', 'wcsspn', 'wcsstr', 'wcstod',
    'wcstof', 'wcstoimax', 'wcstok', 'wcstol', 'wcstold', 'wcstoll',
    'wcstombs', 'wcstoul', 'wcstoull', 'wcstoumax', 'wcsxfrm',
    'wcsxfrm_l', 'wctob', 'wctomb', 'wint_t', 'wmemchr', 'wmemcmp',
    'wmemcpy', 'wmemmove', 'wmemset', 'wprintf', 'write', 'wscanf',
    'y0', 'y0f', 'y0l', 'y1', 'y1f', 'y1l', 'yn', 'ynf', 'ynl']
