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
    r_magic_version = _libr_magic.r_magic_version
    r_magic_version.restype = ctypes.POINTER(ctypes.c_char)
    r_magic_version.argtypes = []
except AttributeError:
    pass
class union_VALUETYPE(Union):
    pass

union_VALUETYPE._pack_ = 1 # source:False
union_VALUETYPE._fields_ = [
    ('b', ctypes.c_ubyte),
    ('h', ctypes.c_uint16),
    ('l', ctypes.c_uint32),
    ('q', ctypes.c_uint64),
    ('hs', ctypes.c_ubyte * 2),
    ('hl', ctypes.c_ubyte * 4),
    ('hq', ctypes.c_ubyte * 8),
    ('s', ctypes.c_char * 32),
    ('f', ctypes.c_float),
    ('d', ctypes.c_double),
    ('PADDING_0', ctypes.c_ubyte * 24),
]

class struct_r_magic(Structure):
    pass

class union_r_magic__u(Union):
    pass

class struct_r_magic_0__s(Structure):
    pass

struct_r_magic_0__s._pack_ = 1 # source:False
struct_r_magic_0__s._fields_ = [
    ('_count', ctypes.c_uint32),
    ('_flags', ctypes.c_uint32),
]

union_r_magic__u._pack_ = 1 # source:False
union_r_magic__u._fields_ = [
    ('_mask', ctypes.c_uint64),
    ('_s', struct_r_magic_0__s),
]

struct_r_magic._pack_ = 1 # source:False
struct_r_magic._fields_ = [
    ('cont_level', ctypes.c_uint16),
    ('flag', ctypes.c_ubyte),
    ('dummy1', ctypes.c_ubyte),
    ('reln', ctypes.c_ubyte),
    ('vallen', ctypes.c_ubyte),
    ('type', ctypes.c_ubyte),
    ('in_type', ctypes.c_ubyte),
    ('in_op', ctypes.c_ubyte),
    ('mask_op', ctypes.c_ubyte),
    ('cond', ctypes.c_ubyte),
    ('dummy2', ctypes.c_ubyte),
    ('offset', ctypes.c_uint32),
    ('in_offset', ctypes.c_uint32),
    ('lineno', ctypes.c_uint32),
    ('_u', union_r_magic__u),
    ('value', union_VALUETYPE),
    ('desc', ctypes.c_char * 64),
    ('mimetype', ctypes.c_char * 64),
]

class struct_mlist(Structure):
    pass

struct_mlist._pack_ = 1 # source:False
struct_mlist._fields_ = [
    ('magic', ctypes.POINTER(struct_r_magic)),
    ('nmagic', ctypes.c_uint32),
    ('mapped', ctypes.c_int32),
    ('next', ctypes.POINTER(struct_mlist)),
    ('prev', ctypes.POINTER(struct_mlist)),
]

class struct_r_magic_set(Structure):
    pass

class struct_cont(Structure):
    pass

class struct_level_info(Structure):
    pass

struct_cont._pack_ = 1 # source:False
struct_cont._fields_ = [
    ('len', ctypes.c_uint64),
    ('li', ctypes.POINTER(struct_level_info)),
]

class struct_out(Structure):
    pass

struct_out._pack_ = 1 # source:False
struct_out._fields_ = [
    ('buf', ctypes.POINTER(ctypes.c_char)),
    ('pbuf', ctypes.POINTER(ctypes.c_char)),
]

class struct_r_magic_set_search(Structure):
    pass

struct_r_magic_set_search._pack_ = 1 # source:False
struct_r_magic_set_search._fields_ = [
    ('s', ctypes.POINTER(ctypes.c_char)),
    ('s_len', ctypes.c_uint64),
    ('offset', ctypes.c_uint64),
    ('rm_len', ctypes.c_uint64),
]

struct_r_magic_set._pack_ = 1 # source:False
struct_r_magic_set._fields_ = [
    ('mlist', ctypes.POINTER(struct_mlist)),
    ('c', struct_cont),
    ('o', struct_out),
    ('offset', ctypes.c_uint32),
    ('error', ctypes.c_int32),
    ('flags', ctypes.c_int32),
    ('haderr', ctypes.c_int32),
    ('file', ctypes.POINTER(ctypes.c_char)),
    ('line', ctypes.c_uint64),
    ('search', struct_r_magic_set_search),
    ('ms_value', union_VALUETYPE),
    ('magic_file_formats', ctypes.c_int32 * 39),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('magic_file_names', ctypes.POINTER(ctypes.c_char) * 39),
    ('last_cont_level', ctypes.c_uint32),
    ('PADDING_1', ctypes.c_ubyte * 4),
]

struct_level_info._pack_ = 1 # source:False
struct_level_info._fields_ = [
    ('off', ctypes.c_int32),
    ('got_match', ctypes.c_int32),
    ('last_match', ctypes.c_int32),
    ('last_cond', ctypes.c_int32),
]

RMagic = struct_r_magic_set
try:
    r_magic_new = _libr_magic.r_magic_new
    r_magic_new.restype = ctypes.POINTER(struct_r_magic_set)
    r_magic_new.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_magic_free = _libr_magic.r_magic_free
    r_magic_free.restype = None
    r_magic_free.argtypes = [ctypes.POINTER(struct_r_magic_set)]
except AttributeError:
    pass
try:
    r_magic_file = _libr_magic.r_magic_file
    r_magic_file.restype = ctypes.POINTER(ctypes.c_char)
    r_magic_file.argtypes = [ctypes.POINTER(struct_r_magic_set), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_magic_descriptor = _libr_magic.r_magic_descriptor
    r_magic_descriptor.restype = ctypes.POINTER(ctypes.c_char)
    r_magic_descriptor.argtypes = [ctypes.POINTER(struct_r_magic_set), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_magic_buffer = _libr_magic.r_magic_buffer
    r_magic_buffer.restype = ctypes.POINTER(ctypes.c_char)
    r_magic_buffer.argtypes = [ctypes.POINTER(struct_r_magic_set), ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    r_magic_error = _libr_magic.r_magic_error
    r_magic_error.restype = ctypes.POINTER(ctypes.c_char)
    r_magic_error.argtypes = [ctypes.POINTER(struct_r_magic_set)]
except AttributeError:
    pass
try:
    r_magic_setflags = _libr_magic.r_magic_setflags
    r_magic_setflags.restype = None
    r_magic_setflags.argtypes = [ctypes.POINTER(struct_r_magic_set), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_magic_from_ebcdic = _libr_magic.r_magic_from_ebcdic
    r_magic_from_ebcdic.restype = None
    r_magic_from_ebcdic.argtypes = [ctypes.POINTER(ctypes.c_ubyte), size_t, ctypes.POINTER(ctypes.c_ubyte)]
except AttributeError:
    pass
try:
    r_magic_load = _libr_magic.r_magic_load
    r_magic_load.restype = ctypes.c_bool
    r_magic_load.argtypes = [ctypes.POINTER(struct_r_magic_set), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_magic_load_buffer = _libr_magic.r_magic_load_buffer
    r_magic_load_buffer.restype = ctypes.c_bool
    r_magic_load_buffer.argtypes = [ctypes.POINTER(struct_r_magic_set), ctypes.POINTER(ctypes.c_ubyte), size_t]
except AttributeError:
    pass
try:
    r_magic_compile = _libr_magic.r_magic_compile
    r_magic_compile.restype = ctypes.c_bool
    r_magic_compile.argtypes = [ctypes.POINTER(struct_r_magic_set), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_magic_check = _libr_magic.r_magic_check
    r_magic_check.restype = ctypes.c_bool
    r_magic_check.argtypes = [ctypes.POINTER(struct_r_magic_set), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_magic_errno = _libr_magic.r_magic_errno
    r_magic_errno.restype = ctypes.c_int32
    r_magic_errno.argtypes = [ctypes.POINTER(struct_r_magic_set)]
except AttributeError:
    pass
__all__ = \
    ['DIR', 'DT_BLK', 'DT_CHR', 'DT_DIR', 'DT_FIFO', 'DT_LNK',
    'DT_REG', 'DT_SOCK', 'DT_UNKNOWN', 'DT_WHT', 'FILE',
    'FP_INFINITE', 'FP_NAN', 'FP_NORMAL', 'FP_SUBNORMAL', 'FP_ZERO',
    'ITIMER_PROF', 'ITIMER_REAL', 'ITIMER_VIRTUAL', 'PrintfCallback',
    'RMagic', 'RSysArch', 'R_SYS_ARCH_8051', 'R_SYS_ARCH_ARC',
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
    'R_SYS_ARCH_Z80', 'ST16_DIV_OVFCHK', 'ST16_MUL_OVFCHK',
    'ST32_DIV_OVFCHK', 'ST32_MUL_OVFCHK', 'ST64_DIV_OVFCHK',
    'ST64_MUL_OVFCHK', 'ST8_DIV_OVFCHK', 'ST8_MUL_OVFCHK',
    'SZT_MUL_OVFCHK', 'UT16_ADD', 'UT16_DIV_OVFCHK', 'UT16_MUL',
    'UT16_MUL_OVFCHK', 'UT16_SUB', 'UT32_ADD', 'UT32_DIV_OVFCHK',
    'UT32_MUL', 'UT32_MUL_OVFCHK', 'UT32_SUB', 'UT64_ADD',
    'UT64_DIV_OVFCHK', 'UT64_MUL', 'UT64_MUL_OVFCHK', 'UT64_SUB',
    'UT8_ADD', 'UT8_DIV_OVFCHK', 'UT8_MUL', 'UT8_MUL_OVFCHK',
    'UT8_SUB', '_CS_GNU_LIBC_VERSION', '_CS_GNU_LIBPTHREAD_VERSION',
    '_CS_LFS64_CFLAGS', '_CS_LFS64_LDFLAGS', '_CS_LFS64_LIBS',
    '_CS_LFS64_LINTFLAGS', '_CS_LFS_CFLAGS', '_CS_LFS_LDFLAGS',
    '_CS_LFS_LIBS', '_CS_LFS_LINTFLAGS', '_CS_PATH',
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
    '__compar_fn_t', '__copysign', '__copysignf', '__copysignl',
    '__cos', '__cosf', '__cosh', '__coshf', '__coshl', '__cosl',
    '__ctype_b_loc', '__ctype_get_mb_cur_max', '__ctype_tolower_loc',
    '__ctype_toupper_loc', '__daddr_t', '__dev_t', '__drem',
    '__dremf', '__dreml', '__environ', '__erf', '__erfc', '__erfcf',
    '__erfcl', '__erff', '__erfl', '__exp', '__exp2', '__exp2f',
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
    '__j1l', '__jn', '__jnf', '__jnl', '__key_t', '__ldexp',
    '__ldexpf', '__ldexpl', '__lgamma', '__lgamma_r', '__lgammaf',
    '__lgammaf_r', '__lgammal', '__lgammal_r', '__llrint',
    '__llrintf', '__llrintl', '__llround', '__llroundf', '__llroundl',
    '__locale_t', '__loff_t', '__log', '__log10', '__log10f',
    '__log10l', '__log1p', '__log1pf', '__log1pl', '__log2',
    '__log2f', '__log2l', '__logb', '__logbf', '__logbl', '__logf',
    '__logl', '__lrint', '__lrintf', '__lrintl', '__lround',
    '__lroundf', '__lroundl', '__mbstate_t', '__memcmpeq',
    '__mempcpy', '__mode_t', '__modf', '__modff', '__modfl', '__nan',
    '__nanf', '__nanl', '__nearbyint', '__nearbyintf', '__nearbyintl',
    '__nextafter', '__nextafterf', '__nextafterl', '__nexttoward',
    '__nexttowardf', '__nexttowardl', '__nlink_t', '__off64_t',
    '__off_t', '__once_flag', '__overflow', '__pid_t', '__pow',
    '__powf', '__powl', '__pthread_list_t', '__pthread_slist_t',
    '__quad_t', '__remainder', '__remainderf', '__remainderl',
    '__remquo', '__remquof', '__remquol', '__rint', '__rintf',
    '__rintl', '__rlim64_t', '__rlim_t', '__round', '__roundf',
    '__roundl', '__scalb', '__scalbf', '__scalbl', '__scalbln',
    '__scalblnf', '__scalblnl', '__scalbn', '__scalbnf', '__scalbnl',
    '__sig_atomic_t', '__signbit', '__signbitf', '__signbitl',
    '__significand', '__significandf', '__significandl', '__sigset_t',
    '__sin', '__sinf', '__sinh', '__sinhf', '__sinhl', '__sinl',
    '__socklen_t', '__sqrt', '__sqrtf', '__sqrtl', '__ssize_t',
    '__stpcpy', '__stpncpy', '__strtok_r', '__suseconds64_t',
    '__suseconds_t', '__syscall_slong_t', '__syscall_ulong_t',
    '__tan', '__tanf', '__tanh', '__tanhf', '__tanhl', '__tanl',
    '__tgamma', '__tgammaf', '__tgammal', '__thrd_t', '__time_t',
    '__timer_t', '__tolower_l', '__toupper_l', '__trunc', '__truncf',
    '__truncl', '__tss_t', '__u_char', '__u_int', '__u_long',
    '__u_quad_t', '__u_short', '__uflow', '__uid_t',
    '__uint16_identity', '__uint16_t', '__uint32_identity',
    '__uint32_t', '__uint64_identity', '__uint64_t', '__uint8_t',
    '__uint_least16_t', '__uint_least32_t', '__uint_least64_t',
    '__uint_least8_t', '__uintmax_t', '__useconds_t', '__y0', '__y0f',
    '__y0l', '__y1', '__y1f', '__y1l', '__yn', '__ynf', '__ynl',
    '_exit', '_tolower', '_toupper', 'a64l', 'abort', 'abs', 'access',
    'acct', 'acos', 'acosf', 'acosh', 'acoshf', 'acoshl', 'acosl',
    'adjtime', 'alarm', 'aligned_alloc', 'alloca', 'alphasort',
    'arc4random', 'arc4random_buf', 'arc4random_uniform', 'asin',
    'asinf', 'asinh', 'asinhf', 'asinhl', 'asinl', 'asprintf',
    'at_quick_exit', 'atan', 'atan2', 'atan2f', 'atan2l', 'atanf',
    'atanh', 'atanhf', 'atanhl', 'atanl', 'atexit', 'atof', 'atoi',
    'atol', 'atoll', 'bcmp', 'bcopy', 'blkcnt_t', 'blksize_t', 'brk',
    'bsearch', 'bzero', 'c__Ea_DT_UNKNOWN', 'c__Ea_FP_NAN',
    'c__Ea__CS_PATH', 'c__Ea__ISupper', 'c__Ea__PC_LINK_MAX',
    'c__Ea__SC_ARG_MAX', 'caddr_t', 'calloc', 'cbrt', 'cbrtf',
    'cbrtl', 'ceil', 'ceilf', 'ceill', 'chdir', 'chmod', 'chown',
    'chroot', 'clearenv', 'clearerr', 'clearerr_unlocked', 'clock_t',
    'clockid_t', 'close', 'closedir', 'closefrom', 'confstr',
    'cookie_close_function_t', 'cookie_io_functions_t',
    'cookie_read_function_t', 'cookie_seek_function_t',
    'cookie_write_function_t', 'copysign', 'copysignf', 'copysignl',
    'cos', 'cosf', 'cosh', 'coshf', 'coshl', 'cosl', 'creat', 'crypt',
    'ctermid', 'daddr_t', 'daemon', 'dev_t', 'dirfd', 'div', 'div_t',
    'double_t', 'dprintf', 'drand48', 'drand48_r', 'drem', 'dremf',
    'dreml', 'dup', 'dup2', 'ecvt', 'ecvt_r', 'endusershell',
    'erand48', 'erand48_r', 'erf', 'erfc', 'erfcf', 'erfcl', 'erff',
    'erfl', 'execl', 'execle', 'execlp', 'execv', 'execve', 'execvp',
    'exit', 'exp', 'exp2', 'exp2f', 'exp2l', 'expf', 'expl',
    'explicit_bzero', 'expm1', 'expm1f', 'expm1l', 'fabs', 'fabsf',
    'fabsl', 'faccessat', 'fchdir', 'fchmod', 'fchmodat', 'fchown',
    'fchownat', 'fclose', 'fcntl', 'fcvt', 'fcvt_r', 'fd_mask',
    'fd_set', 'fdatasync', 'fdim', 'fdimf', 'fdiml', 'fdopen',
    'fdopendir', 'feof', 'feof_unlocked', 'ferror', 'ferror_unlocked',
    'fexecve', 'fflush', 'fflush_unlocked', 'ffs', 'ffsl', 'ffsll',
    'fgetc', 'fgetc_unlocked', 'fgetpos', 'fgets', 'fileno',
    'fileno_unlocked', 'finite', 'finitef', 'finitel', 'float_t',
    'flockfile', 'floor', 'floorf', 'floorl', 'fma', 'fmaf', 'fmal',
    'fmax', 'fmaxf', 'fmaxl', 'fmemopen', 'fmin', 'fminf', 'fminl',
    'fmod', 'fmodf', 'fmodl', 'fopen', 'fopencookie', 'fork',
    'fpathconf', 'fpos_t', 'fprintf', 'fputc', 'fputc_unlocked',
    'fputs', 'fread', 'fread_unlocked', 'free', 'freopen', 'frexp',
    'frexpf', 'frexpl', 'fsblkcnt_t', 'fscanf', 'fseek', 'fseeko',
    'fsetpos', 'fsfilcnt_t', 'fsid_t', 'fstat', 'fstatat', 'fsync',
    'ftell', 'ftello', 'ftruncate', 'ftrylockfile', 'funlockfile',
    'futimens', 'futimes', 'fwrite', 'fwrite_unlocked', 'gamma',
    'gammaf', 'gammal', 'gcvt', 'getc', 'getc_unlocked', 'getchar',
    'getchar_unlocked', 'getcwd', 'getdelim', 'getdirentries',
    'getdomainname', 'getdtablesize', 'getegid', 'getentropy',
    'getenv', 'geteuid', 'getgid', 'getgroups', 'gethostid',
    'gethostname', 'getitimer', 'getline', 'getloadavg', 'getlogin',
    'getlogin_r', 'getopt', 'getpagesize', 'getpass', 'getpgid',
    'getpgrp', 'getpid', 'getppid', 'getsid', 'getsubopt',
    'gettimeofday', 'getuid', 'getusershell', 'getw', 'getwd',
    'gid_t', 'hypot', 'hypotf', 'hypotl', 'id_t', 'ilogb', 'ilogbf',
    'ilogbl', 'imaxabs', 'imaxdiv', 'imaxdiv_t', 'index', 'initstate',
    'initstate_r', 'ino_t', 'int16_t', 'int32_t', 'int64_t', 'int8_t',
    'int_fast16_t', 'int_fast32_t', 'int_fast64_t', 'int_fast8_t',
    'int_least16_t', 'int_least32_t', 'int_least64_t', 'int_least8_t',
    'intmax_t', 'intptr_t', 'isalnum', 'isalnum_l', 'isalpha',
    'isalpha_l', 'isascii', 'isatty', 'isblank', 'isblank_l',
    'iscntrl', 'iscntrl_l', 'isdigit', 'isdigit_l', 'isgraph',
    'isgraph_l', 'isinf', 'isinff', 'isinfl', 'islower', 'islower_l',
    'isnan', 'isnanf', 'isnanl', 'isprint', 'isprint_l', 'ispunct',
    'ispunct_l', 'isspace', 'isspace_l', 'isupper', 'isupper_l',
    'isxdigit', 'isxdigit_l', 'j0', 'j0f', 'j0l', 'j1', 'j1f', 'j1l',
    'jn', 'jnf', 'jnl', 'jrand48', 'jrand48_r', 'key_t', 'l64a',
    'labs', 'lchmod', 'lchown', 'lcong48', 'lcong48_r', 'ldexp',
    'ldexpf', 'ldexpl', 'ldiv', 'ldiv_t', 'lgamma', 'lgamma_r',
    'lgammaf', 'lgammaf_r', 'lgammal', 'lgammal_r', 'link', 'linkat',
    'llabs', 'lldiv', 'lldiv_t', 'llrint', 'llrintf', 'llrintl',
    'llround', 'llroundf', 'llroundl', 'locale_t', 'lockf', 'loff_t',
    'log', 'log10', 'log10f', 'log10l', 'log1p', 'log1pf', 'log1pl',
    'log2', 'log2f', 'log2l', 'logb', 'logbf', 'logbl', 'logf',
    'logl', 'lrand48', 'lrand48_r', 'lrint', 'lrintf', 'lrintl',
    'lround', 'lroundf', 'lroundl', 'lseek', 'lstat', 'lutimes',
    'malloc', 'max_align_t', 'mblen', 'mbstowcs', 'mbtowc', 'memccpy',
    'memchr', 'memcmp', 'memcpy', 'memmem', 'memmove', 'mempcpy',
    'memset', 'mkdir', 'mkdirat', 'mkdtemp', 'mkfifo', 'mkfifoat',
    'mknod', 'mknodat', 'mkstemp', 'mkstemps', 'mktemp', 'mode_t',
    'modf', 'modff', 'modfl', 'mrand48', 'mrand48_r', 'nan', 'nanf',
    'nanl', 'nearbyint', 'nearbyintf', 'nearbyintl', 'nextafter',
    'nextafterf', 'nextafterl', 'nexttoward', 'nexttowardf',
    'nexttowardl', 'nice', 'nlink_t', 'nrand48', 'nrand48_r', 'off_t',
    'on_exit', 'open', 'open_memstream', 'openat', 'opendir',
    'optarg', 'opterr', 'optind', 'optopt', 'pathconf', 'pause',
    'pclose', 'perror', 'pid_t', 'pipe', 'popen', 'posix_fadvise',
    'posix_fallocate', 'posix_memalign', 'pow', 'powf', 'powl',
    'pread', 'printf', 'profil', 'pselect', 'pthread_attr_t',
    'pthread_barrier_t', 'pthread_barrierattr_t', 'pthread_cond_t',
    'pthread_condattr_t', 'pthread_key_t', 'pthread_mutex_t',
    'pthread_mutexattr_t', 'pthread_once_t', 'pthread_rwlock_t',
    'pthread_rwlockattr_t', 'pthread_spinlock_t', 'pthread_t',
    'ptrdiff_t', 'putc', 'putc_unlocked', 'putchar',
    'putchar_unlocked', 'putenv', 'puts', 'putw', 'pwrite', 'qecvt',
    'qecvt_r', 'qfcvt', 'qfcvt_r', 'qgcvt', 'qsort', 'quad_t',
    'quick_exit', 'r_magic_buffer', 'r_magic_check',
    'r_magic_compile', 'r_magic_descriptor', 'r_magic_errno',
    'r_magic_error', 'r_magic_file', 'r_magic_free',
    'r_magic_from_ebcdic', 'r_magic_load', 'r_magic_load_buffer',
    'r_magic_new', 'r_magic_setflags', 'r_magic_version',
    'r_new_copy', 'r_read_at_be16', 'r_read_at_be32',
    'r_read_at_be64', 'r_read_at_be8', 'r_read_at_ble16',
    'r_read_at_ble32', 'r_read_at_ble64', 'r_read_at_ble8',
    'r_read_at_le16', 'r_read_at_le32', 'r_read_at_le64',
    'r_read_at_le8', 'r_read_at_me16', 'r_read_at_me32',
    'r_read_at_me64', 'r_read_at_me8', 'r_read_be16', 'r_read_be32',
    'r_read_be64', 'r_read_be8', 'r_read_ble', 'r_read_ble16',
    'r_read_ble32', 'r_read_ble64', 'r_read_ble8', 'r_read_le16',
    'r_read_le32', 'r_read_le64', 'r_read_le8', 'r_read_me16',
    'r_read_me32', 'r_read_me64', 'r_read_me8', 'r_run_call1',
    'r_run_call10', 'r_run_call2', 'r_run_call3', 'r_run_call4',
    'r_run_call5', 'r_run_call6', 'r_run_call7', 'r_run_call8',
    'r_run_call9', 'r_swap_st16', 'r_swap_st32', 'r_swap_st64',
    'r_swap_ut16', 'r_swap_ut32', 'r_swap_ut64', 'r_write_at_be16',
    'r_write_at_be32', 'r_write_at_be64', 'r_write_at_be8',
    'r_write_at_ble8', 'r_write_at_le16', 'r_write_at_le32',
    'r_write_at_le64', 'r_write_at_le8', 'r_write_at_me16',
    'r_write_at_me32', 'r_write_at_me64', 'r_write_at_me8',
    'r_write_be16', 'r_write_be24', 'r_write_be32', 'r_write_be64',
    'r_write_be8', 'r_write_ble', 'r_write_ble16', 'r_write_ble24',
    'r_write_ble32', 'r_write_ble64', 'r_write_ble8', 'r_write_le16',
    'r_write_le24', 'r_write_le32', 'r_write_le64', 'r_write_le8',
    'r_write_me16', 'r_write_me32', 'r_write_me64', 'r_write_me8',
    'rand', 'rand_r', 'random', 'random_r', 'read', 'readdir',
    'readdir_r', 'readlink', 'readlinkat', 'realloc', 'reallocarray',
    'realpath', 'register_t', 'remainder', 'remainderf', 'remainderl',
    'remove', 'remquo', 'remquof', 'remquol', 'rename', 'renameat',
    'revoke', 'rewind', 'rewinddir', 'rindex', 'rint', 'rintf',
    'rintl', 'rmdir', 'round', 'roundf', 'roundl', 'rpmatch', 'sbrk',
    'scalb', 'scalbf', 'scalbl', 'scalbln', 'scalblnf', 'scalblnl',
    'scalbn', 'scalbnf', 'scalbnl', 'scandir', 'scanf', 'seed48',
    'seed48_r', 'seekdir', 'select', 'setbuf', 'setbuffer',
    'setdomainname', 'setegid', 'setenv', 'seteuid', 'setgid',
    'sethostid', 'sethostname', 'setitimer', 'setlinebuf', 'setlogin',
    'setpgid', 'setpgrp', 'setregid', 'setreuid', 'setsid',
    'setstate', 'setstate_r', 'settimeofday', 'setuid',
    'setusershell', 'setvbuf', 'signgam', 'significand',
    'significandf', 'significandl', 'sigset_t', 'sin', 'sinf', 'sinh',
    'sinhf', 'sinhl', 'sinl', 'size_t', 'sleep', 'snprintf',
    'socklen_t', 'sprintf', 'sqrt', 'sqrtf', 'sqrtl', 'srand',
    'srand48', 'srand48_r', 'srandom', 'srandom_r', 'sscanf',
    'ssize_t', 'stat', 'stderr', 'stdin', 'stdout', 'stpcpy',
    'stpncpy', 'strcasecmp', 'strcasecmp_l', 'strcasestr', 'strcat',
    'strchr', 'strchrnul', 'strcmp', 'strcoll', 'strcoll_l', 'strcpy',
    'strcspn', 'strdup', 'strerror', 'strerror_l', 'strerror_r',
    'strlcat', 'strlcpy', 'strlen', 'strncasecmp', 'strncasecmp_l',
    'strncat', 'strncmp', 'strncpy', 'strndup', 'strnlen', 'strpbrk',
    'strrchr', 'strsep', 'strsignal', 'strspn', 'strstr', 'strtod',
    'strtof', 'strtoimax', 'strtok', 'strtok_r', 'strtol', 'strtold',
    'strtoll', 'strtoq', 'strtoul', 'strtoull', 'strtoumax',
    'strtouq', 'struct__G_fpos64_t', 'struct__G_fpos_t',
    'struct__IO_FILE', 'struct__IO_codecvt',
    'struct__IO_cookie_io_functions_t', 'struct__IO_marker',
    'struct__IO_wide_data', 'struct___atomic_wide_counter___value32',
    'struct___dirstream', 'struct___fsid_t', 'struct___locale_data',
    'struct___locale_struct', 'struct___mbstate_t',
    'struct___once_flag', 'struct___pthread_cond_s',
    'struct___pthread_internal_list',
    'struct___pthread_internal_slist', 'struct___pthread_mutex_s',
    'struct___pthread_rwlock_arch_t', 'struct___sigset_t',
    'struct___va_list_tag', 'struct__ut128', 'struct__ut256',
    'struct__ut80', 'struct__ut96', 'struct__utX', 'struct_cont',
    'struct_dirent', 'struct_div_t', 'struct_drand48_data',
    'struct_fd_set', 'struct_flock', 'struct_imaxdiv_t',
    'struct_itimerval', 'struct_ldiv_t', 'struct_level_info',
    'struct_lldiv_t', 'struct_max_align_t', 'struct_mlist',
    'struct_out', 'struct_r_magic', 'struct_r_magic_0__s',
    'struct_r_magic_set', 'struct_r_magic_set_search',
    'struct_random_data', 'struct_stat', 'struct_timespec',
    'struct_timeval', 'struct_timezone', 'strxfrm', 'strxfrm_l',
    'suseconds_t', 'symlink', 'symlinkat', 'sync', 'syscall',
    'sysconf', 'system', 'tan', 'tanf', 'tanh', 'tanhf', 'tanhl',
    'tanl', 'tcgetpgrp', 'tcsetpgrp', 'telldir', 'tempnam', 'tgamma',
    'tgammaf', 'tgammal', 'time_t', 'timer_t', 'tmpfile', 'tmpnam',
    'tmpnam_r', 'toascii', 'tolower', 'tolower_l', 'toupper',
    'toupper_l', 'trunc', 'truncate', 'truncf', 'truncl', 'ttyname',
    'ttyname_r', 'ttyslot', 'u_char', 'u_int', 'u_int16_t',
    'u_int32_t', 'u_int64_t', 'u_int8_t', 'u_long', 'u_quad_t',
    'u_short', 'ualarm', 'uid_t', 'uint', 'uint16_t', 'uint32_t',
    'uint64_t', 'uint8_t', 'uint_fast16_t', 'uint_fast32_t',
    'uint_fast64_t', 'uint_fast8_t', 'uint_least16_t',
    'uint_least32_t', 'uint_least64_t', 'uint_least8_t', 'uintmax_t',
    'uintptr_t', 'ulong', 'umask', 'ungetc', 'union_VALUETYPE',
    'union___atomic_wide_counter', 'union___mbstate_t___value',
    'union_pthread_attr_t', 'union_pthread_barrier_t',
    'union_pthread_barrierattr_t', 'union_pthread_cond_t',
    'union_pthread_condattr_t', 'union_pthread_mutex_t',
    'union_pthread_mutexattr_t', 'union_pthread_rwlock_t',
    'union_pthread_rwlockattr_t', 'union_r_magic__u', 'union_utAny',
    'unlink', 'unlinkat', 'unsetenv', 'useconds_t', 'ushort',
    'usleep', 'ust16', 'ust32', 'ust64', 'ut128', 'ut256', 'ut80',
    'ut96', 'utAny', 'utX', 'utimensat', 'utimes', 'uut16', 'uut32',
    'uut64', 'va_list', 'valloc', 'vasprintf', 'vdprintf', 'vfork',
    'vfprintf', 'vfscanf', 'vhangup', 'vprintf', 'vscanf',
    'vsnprintf', 'vsprintf', 'vsscanf', 'wchar_t', 'wcstoimax',
    'wcstombs', 'wcstoumax', 'wctomb', 'write', 'y0', 'y0f', 'y0l',
    'y1', 'y1f', 'y1l', 'yn', 'ynf', 'ynl']
