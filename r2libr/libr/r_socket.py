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
RCoreCmd = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))
RCoreCmdF = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))
RCoreDebugBpHit = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(None))
RCoreDebugSyscallHit = ctypes.CFUNCTYPE(None, ctypes.POINTER(None))
RCoreCmdStr = ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))
RCoreCmdStrF = ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))
RCorePuts = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_char))
RCoreSetArchBits = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char), ctypes.c_int32)
RCoreIsMapped = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(None), ctypes.c_uint64, ctypes.c_int32)
RCoreDebugMapsSync = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(None))
RCoreGetName = ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.c_uint64)
RCoreGetNameDelta = ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.c_uint64)
RCoreSeekArchBits = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.c_uint64)
RCoreConfigGetI = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))
RCoreConfigGet = ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))
RCoreNumGet = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))
RCorePJWithEncoding = ctypes.CFUNCTYPE(ctypes.POINTER(None), ctypes.POINTER(None))
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

RCoreBind = struct_r_core_bind_t
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
try:
    r_socket_version = _libr_socket.r_socket_version
    r_socket_version.restype = ctypes.POINTER(ctypes.c_char)
    r_socket_version.argtypes = []
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
in_addr_t = ctypes.c_uint32
class struct_in_addr(Structure):
    pass

struct_in_addr._pack_ = 1 # source:False
struct_in_addr._fields_ = [
    ('s_addr', ctypes.c_uint32),
]

class struct_ip_opts(Structure):
    pass

struct_ip_opts._pack_ = 1 # source:False
struct_ip_opts._fields_ = [
    ('ip_dst', struct_in_addr),
    ('ip_opts', ctypes.c_char * 40),
]

class struct_in_pktinfo(Structure):
    pass

struct_in_pktinfo._pack_ = 1 # source:False
struct_in_pktinfo._fields_ = [
    ('ipi_ifindex', ctypes.c_int32),
    ('ipi_spec_dst', struct_in_addr),
    ('ipi_addr', struct_in_addr),
]


# values for enumeration 'c__Ea_IPPROTO_IP'
c__Ea_IPPROTO_IP__enumvalues = {
    0: 'IPPROTO_IP',
    1: 'IPPROTO_ICMP',
    2: 'IPPROTO_IGMP',
    4: 'IPPROTO_IPIP',
    6: 'IPPROTO_TCP',
    8: 'IPPROTO_EGP',
    12: 'IPPROTO_PUP',
    17: 'IPPROTO_UDP',
    22: 'IPPROTO_IDP',
    29: 'IPPROTO_TP',
    33: 'IPPROTO_DCCP',
    41: 'IPPROTO_IPV6',
    46: 'IPPROTO_RSVP',
    47: 'IPPROTO_GRE',
    50: 'IPPROTO_ESP',
    51: 'IPPROTO_AH',
    92: 'IPPROTO_MTP',
    94: 'IPPROTO_BEETPH',
    98: 'IPPROTO_ENCAP',
    103: 'IPPROTO_PIM',
    108: 'IPPROTO_COMP',
    115: 'IPPROTO_L2TP',
    132: 'IPPROTO_SCTP',
    136: 'IPPROTO_UDPLITE',
    137: 'IPPROTO_MPLS',
    143: 'IPPROTO_ETHERNET',
    255: 'IPPROTO_RAW',
    262: 'IPPROTO_MPTCP',
    263: 'IPPROTO_MAX',
}
IPPROTO_IP = 0
IPPROTO_ICMP = 1
IPPROTO_IGMP = 2
IPPROTO_IPIP = 4
IPPROTO_TCP = 6
IPPROTO_EGP = 8
IPPROTO_PUP = 12
IPPROTO_UDP = 17
IPPROTO_IDP = 22
IPPROTO_TP = 29
IPPROTO_DCCP = 33
IPPROTO_IPV6 = 41
IPPROTO_RSVP = 46
IPPROTO_GRE = 47
IPPROTO_ESP = 50
IPPROTO_AH = 51
IPPROTO_MTP = 92
IPPROTO_BEETPH = 94
IPPROTO_ENCAP = 98
IPPROTO_PIM = 103
IPPROTO_COMP = 108
IPPROTO_L2TP = 115
IPPROTO_SCTP = 132
IPPROTO_UDPLITE = 136
IPPROTO_MPLS = 137
IPPROTO_ETHERNET = 143
IPPROTO_RAW = 255
IPPROTO_MPTCP = 262
IPPROTO_MAX = 263
c__Ea_IPPROTO_IP = ctypes.c_uint32 # enum

# values for enumeration 'c__Ea_IPPROTO_HOPOPTS'
c__Ea_IPPROTO_HOPOPTS__enumvalues = {
    0: 'IPPROTO_HOPOPTS',
    43: 'IPPROTO_ROUTING',
    44: 'IPPROTO_FRAGMENT',
    58: 'IPPROTO_ICMPV6',
    59: 'IPPROTO_NONE',
    60: 'IPPROTO_DSTOPTS',
    135: 'IPPROTO_MH',
}
IPPROTO_HOPOPTS = 0
IPPROTO_ROUTING = 43
IPPROTO_FRAGMENT = 44
IPPROTO_ICMPV6 = 58
IPPROTO_NONE = 59
IPPROTO_DSTOPTS = 60
IPPROTO_MH = 135
c__Ea_IPPROTO_HOPOPTS = ctypes.c_uint32 # enum
in_port_t = ctypes.c_uint16

# values for enumeration 'c__Ea_IPPORT_ECHO'
c__Ea_IPPORT_ECHO__enumvalues = {
    7: 'IPPORT_ECHO',
    9: 'IPPORT_DISCARD',
    11: 'IPPORT_SYSTAT',
    13: 'IPPORT_DAYTIME',
    15: 'IPPORT_NETSTAT',
    21: 'IPPORT_FTP',
    23: 'IPPORT_TELNET',
    25: 'IPPORT_SMTP',
    37: 'IPPORT_TIMESERVER',
    42: 'IPPORT_NAMESERVER',
    43: 'IPPORT_WHOIS',
    57: 'IPPORT_MTP',
    69: 'IPPORT_TFTP',
    77: 'IPPORT_RJE',
    79: 'IPPORT_FINGER',
    87: 'IPPORT_TTYLINK',
    95: 'IPPORT_SUPDUP',
    512: 'IPPORT_EXECSERVER',
    513: 'IPPORT_LOGINSERVER',
    514: 'IPPORT_CMDSERVER',
    520: 'IPPORT_EFSSERVER',
    512: 'IPPORT_BIFFUDP',
    513: 'IPPORT_WHOSERVER',
    520: 'IPPORT_ROUTESERVER',
    1024: 'IPPORT_RESERVED',
    5000: 'IPPORT_USERRESERVED',
}
IPPORT_ECHO = 7
IPPORT_DISCARD = 9
IPPORT_SYSTAT = 11
IPPORT_DAYTIME = 13
IPPORT_NETSTAT = 15
IPPORT_FTP = 21
IPPORT_TELNET = 23
IPPORT_SMTP = 25
IPPORT_TIMESERVER = 37
IPPORT_NAMESERVER = 42
IPPORT_WHOIS = 43
IPPORT_MTP = 57
IPPORT_TFTP = 69
IPPORT_RJE = 77
IPPORT_FINGER = 79
IPPORT_TTYLINK = 87
IPPORT_SUPDUP = 95
IPPORT_EXECSERVER = 512
IPPORT_LOGINSERVER = 513
IPPORT_CMDSERVER = 514
IPPORT_EFSSERVER = 520
IPPORT_BIFFUDP = 512
IPPORT_WHOSERVER = 513
IPPORT_ROUTESERVER = 520
IPPORT_RESERVED = 1024
IPPORT_USERRESERVED = 5000
c__Ea_IPPORT_ECHO = ctypes.c_uint32 # enum
class struct_in6_addr(Structure):
    pass

class union_in6_addr___in6_u(Union):
    pass

union_in6_addr___in6_u._pack_ = 1 # source:False
union_in6_addr___in6_u._fields_ = [
    ('__u6_addr8', ctypes.c_ubyte * 16),
    ('__u6_addr16', ctypes.c_uint16 * 8),
    ('__u6_addr32', ctypes.c_uint32 * 4),
]

struct_in6_addr._pack_ = 1 # source:False
struct_in6_addr._fields_ = [
    ('__in6_u', union_in6_addr___in6_u),
]

in6addr_any = struct_in6_addr # Variable struct_in6_addr
in6addr_loopback = struct_in6_addr # Variable struct_in6_addr
class struct_sockaddr_in(Structure):
    pass

struct_sockaddr_in._pack_ = 1 # source:False
struct_sockaddr_in._fields_ = [
    ('sin_family', ctypes.c_uint16),
    ('sin_port', ctypes.c_uint16),
    ('sin_addr', struct_in_addr),
    ('sin_zero', ctypes.c_ubyte * 8),
]

class struct_sockaddr_in6(Structure):
    pass

struct_sockaddr_in6._pack_ = 1 # source:False
struct_sockaddr_in6._fields_ = [
    ('sin6_family', ctypes.c_uint16),
    ('sin6_port', ctypes.c_uint16),
    ('sin6_flowinfo', ctypes.c_uint32),
    ('sin6_addr', struct_in6_addr),
    ('sin6_scope_id', ctypes.c_uint32),
]

class struct_ip_mreq(Structure):
    _pack_ = 1 # source:False
    _fields_ = [
    ('imr_multiaddr', struct_in_addr),
    ('imr_interface', struct_in_addr),
     ]

class struct_ip_mreqn(Structure):
    pass

struct_ip_mreqn._pack_ = 1 # source:False
struct_ip_mreqn._fields_ = [
    ('imr_multiaddr', struct_in_addr),
    ('imr_address', struct_in_addr),
    ('imr_ifindex', ctypes.c_int32),
]

class struct_ip_mreq_source(Structure):
    _pack_ = 1 # source:False
    _fields_ = [
    ('imr_multiaddr', struct_in_addr),
    ('imr_interface', struct_in_addr),
    ('imr_sourceaddr', struct_in_addr),
     ]

class struct_ipv6_mreq(Structure):
    pass

struct_ipv6_mreq._pack_ = 1 # source:False
struct_ipv6_mreq._fields_ = [
    ('ipv6mr_multiaddr', struct_in6_addr),
    ('ipv6mr_interface', ctypes.c_uint32),
]

class struct_group_req(Structure):
    pass

struct_group_req._pack_ = 1 # source:False
struct_group_req._fields_ = [
    ('gr_interface', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('gr_group', struct_sockaddr_storage),
]

class struct_group_source_req(Structure):
    pass

struct_group_source_req._pack_ = 1 # source:False
struct_group_source_req._fields_ = [
    ('gsr_interface', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('gsr_group', struct_sockaddr_storage),
    ('gsr_source', struct_sockaddr_storage),
]

class struct_ip_msfilter(Structure):
    pass

struct_ip_msfilter._pack_ = 1 # source:False
struct_ip_msfilter._fields_ = [
    ('imsf_multiaddr', struct_in_addr),
    ('imsf_interface', struct_in_addr),
    ('imsf_fmode', ctypes.c_uint32),
    ('imsf_numsrc', ctypes.c_uint32),
    ('imsf_slist', struct_in_addr * 1),
]

class struct_group_filter(Structure):
    pass

struct_group_filter._pack_ = 1 # source:False
struct_group_filter._fields_ = [
    ('gf_interface', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('gf_group', struct_sockaddr_storage),
    ('gf_fmode', ctypes.c_uint32),
    ('gf_numsrc', ctypes.c_uint32),
    ('gf_slist', struct_sockaddr_storage * 1),
]

try:
    ntohl = _libraries['FIXME_STUB'].ntohl
    ntohl.restype = uint32_t
    ntohl.argtypes = [uint32_t]
except AttributeError:
    pass
try:
    ntohs = _libraries['FIXME_STUB'].ntohs
    ntohs.restype = uint16_t
    ntohs.argtypes = [uint16_t]
except AttributeError:
    pass
try:
    htonl = _libraries['FIXME_STUB'].htonl
    htonl.restype = uint32_t
    htonl.argtypes = [uint32_t]
except AttributeError:
    pass
try:
    htons = _libraries['FIXME_STUB'].htons
    htons.restype = uint16_t
    htons.argtypes = [uint16_t]
except AttributeError:
    pass
try:
    bindresvport = _libraries['FIXME_STUB'].bindresvport
    bindresvport.restype = ctypes.c_int32
    bindresvport.argtypes = [ctypes.c_int32, ctypes.POINTER(struct_sockaddr_in)]
except AttributeError:
    pass
try:
    bindresvport6 = _libraries['FIXME_STUB'].bindresvport6
    bindresvport6.restype = ctypes.c_int32
    bindresvport6.argtypes = [ctypes.c_int32, ctypes.POINTER(struct_sockaddr_in6)]
except AttributeError:
    pass
class struct_sockaddr_un(Structure):
    pass

struct_sockaddr_un._pack_ = 1 # source:False
struct_sockaddr_un._fields_ = [
    ('sun_family', ctypes.c_uint16),
    ('sun_path', ctypes.c_char * 108),
]

nfds_t = ctypes.c_uint64
class struct_pollfd(Structure):
    pass

struct_pollfd._pack_ = 1 # source:False
struct_pollfd._fields_ = [
    ('fd', ctypes.c_int32),
    ('events', ctypes.c_int16),
    ('revents', ctypes.c_int16),
]

try:
    poll = _libraries['FIXME_STUB'].poll
    poll.restype = ctypes.c_int32
    poll.argtypes = [ctypes.POINTER(struct_pollfd), nfds_t, ctypes.c_int32]
except AttributeError:
    pass
try:
    inet_addr = _libraries['FIXME_STUB'].inet_addr
    inet_addr.restype = in_addr_t
    inet_addr.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    inet_lnaof = _libraries['FIXME_STUB'].inet_lnaof
    inet_lnaof.restype = in_addr_t
    inet_lnaof.argtypes = [struct_in_addr]
except AttributeError:
    pass
try:
    inet_makeaddr = _libraries['FIXME_STUB'].inet_makeaddr
    inet_makeaddr.restype = struct_in_addr
    inet_makeaddr.argtypes = [in_addr_t, in_addr_t]
except AttributeError:
    pass
try:
    inet_netof = _libraries['FIXME_STUB'].inet_netof
    inet_netof.restype = in_addr_t
    inet_netof.argtypes = [struct_in_addr]
except AttributeError:
    pass
try:
    inet_network = _libraries['FIXME_STUB'].inet_network
    inet_network.restype = in_addr_t
    inet_network.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    inet_ntoa = _libraries['FIXME_STUB'].inet_ntoa
    inet_ntoa.restype = ctypes.POINTER(ctypes.c_char)
    inet_ntoa.argtypes = [struct_in_addr]
except AttributeError:
    pass
try:
    inet_pton = _libraries['FIXME_STUB'].inet_pton
    inet_pton.restype = ctypes.c_int32
    inet_pton.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None)]
except AttributeError:
    pass
try:
    inet_ntop = _libraries['FIXME_STUB'].inet_ntop
    inet_ntop.restype = ctypes.POINTER(ctypes.c_char)
    inet_ntop.argtypes = [ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char), socklen_t]
except AttributeError:
    pass
try:
    inet_aton = _libraries['FIXME_STUB'].inet_aton
    inet_aton.restype = ctypes.c_int32
    inet_aton.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_in_addr)]
except AttributeError:
    pass
try:
    inet_neta = _libraries['FIXME_STUB'].inet_neta
    inet_neta.restype = ctypes.POINTER(ctypes.c_char)
    inet_neta.argtypes = [in_addr_t, ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    inet_net_ntop = _libraries['FIXME_STUB'].inet_net_ntop
    inet_net_ntop.restype = ctypes.POINTER(ctypes.c_char)
    inet_net_ntop.argtypes = [ctypes.c_int32, ctypes.POINTER(None), ctypes.c_int32, ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    inet_net_pton = _libraries['FIXME_STUB'].inet_net_pton
    inet_net_pton.restype = ctypes.c_int32
    inet_net_pton.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), size_t]
except AttributeError:
    pass
try:
    inet_nsap_addr = _libraries['FIXME_STUB'].inet_nsap_addr
    inet_nsap_addr.restype = ctypes.c_uint32
    inet_nsap_addr.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    inet_nsap_ntoa = _libraries['FIXME_STUB'].inet_nsap_ntoa
    inet_nsap_ntoa.restype = ctypes.POINTER(ctypes.c_char)
    inet_nsap_ntoa.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
class struct_rpcent(Structure):
    pass

struct_rpcent._pack_ = 1 # source:False
struct_rpcent._fields_ = [
    ('r_name', ctypes.POINTER(ctypes.c_char)),
    ('r_aliases', ctypes.POINTER(ctypes.POINTER(ctypes.c_char))),
    ('r_number', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

try:
    setrpcent = _libraries['FIXME_STUB'].setrpcent
    setrpcent.restype = None
    setrpcent.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    endrpcent = _libraries['FIXME_STUB'].endrpcent
    endrpcent.restype = None
    endrpcent.argtypes = []
except AttributeError:
    pass
try:
    getrpcbyname = _libraries['FIXME_STUB'].getrpcbyname
    getrpcbyname.restype = ctypes.POINTER(struct_rpcent)
    getrpcbyname.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    getrpcbynumber = _libraries['FIXME_STUB'].getrpcbynumber
    getrpcbynumber.restype = ctypes.POINTER(struct_rpcent)
    getrpcbynumber.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    getrpcent = _libraries['FIXME_STUB'].getrpcent
    getrpcent.restype = ctypes.POINTER(struct_rpcent)
    getrpcent.argtypes = []
except AttributeError:
    pass
try:
    getrpcbyname_r = _libraries['FIXME_STUB'].getrpcbyname_r
    getrpcbyname_r.restype = ctypes.c_int32
    getrpcbyname_r.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_rpcent), ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(ctypes.POINTER(struct_rpcent))]
except AttributeError:
    pass
try:
    getrpcbynumber_r = _libraries['FIXME_STUB'].getrpcbynumber_r
    getrpcbynumber_r.restype = ctypes.c_int32
    getrpcbynumber_r.argtypes = [ctypes.c_int32, ctypes.POINTER(struct_rpcent), ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(ctypes.POINTER(struct_rpcent))]
except AttributeError:
    pass
try:
    getrpcent_r = _libraries['FIXME_STUB'].getrpcent_r
    getrpcent_r.restype = ctypes.c_int32
    getrpcent_r.argtypes = [ctypes.POINTER(struct_rpcent), ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(ctypes.POINTER(struct_rpcent))]
except AttributeError:
    pass
class struct_netent(Structure):
    pass

struct_netent._pack_ = 1 # source:False
struct_netent._fields_ = [
    ('n_name', ctypes.POINTER(ctypes.c_char)),
    ('n_aliases', ctypes.POINTER(ctypes.POINTER(ctypes.c_char))),
    ('n_addrtype', ctypes.c_int32),
    ('n_net', ctypes.c_uint32),
]

try:
    __h_errno_location = _libraries['FIXME_STUB'].__h_errno_location
    __h_errno_location.restype = ctypes.POINTER(ctypes.c_int32)
    __h_errno_location.argtypes = []
except AttributeError:
    pass
try:
    herror = _libraries['FIXME_STUB'].herror
    herror.restype = None
    herror.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    hstrerror = _libraries['FIXME_STUB'].hstrerror
    hstrerror.restype = ctypes.POINTER(ctypes.c_char)
    hstrerror.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
class struct_hostent(Structure):
    pass

struct_hostent._pack_ = 1 # source:False
struct_hostent._fields_ = [
    ('h_name', ctypes.POINTER(ctypes.c_char)),
    ('h_aliases', ctypes.POINTER(ctypes.POINTER(ctypes.c_char))),
    ('h_addrtype', ctypes.c_int32),
    ('h_length', ctypes.c_int32),
    ('h_addr_list', ctypes.POINTER(ctypes.POINTER(ctypes.c_char))),
]

try:
    sethostent = _libraries['FIXME_STUB'].sethostent
    sethostent.restype = None
    sethostent.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    endhostent = _libraries['FIXME_STUB'].endhostent
    endhostent.restype = None
    endhostent.argtypes = []
except AttributeError:
    pass
try:
    gethostent = _libraries['FIXME_STUB'].gethostent
    gethostent.restype = ctypes.POINTER(struct_hostent)
    gethostent.argtypes = []
except AttributeError:
    pass
try:
    gethostbyaddr = _libraries['FIXME_STUB'].gethostbyaddr
    gethostbyaddr.restype = ctypes.POINTER(struct_hostent)
    gethostbyaddr.argtypes = [ctypes.POINTER(None), __socklen_t, ctypes.c_int32]
except AttributeError:
    pass
try:
    gethostbyname = _libraries['FIXME_STUB'].gethostbyname
    gethostbyname.restype = ctypes.POINTER(struct_hostent)
    gethostbyname.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    gethostbyname2 = _libraries['FIXME_STUB'].gethostbyname2
    gethostbyname2.restype = ctypes.POINTER(struct_hostent)
    gethostbyname2.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    gethostent_r = _libraries['FIXME_STUB'].gethostent_r
    gethostent_r.restype = ctypes.c_int32
    gethostent_r.argtypes = [ctypes.POINTER(struct_hostent), ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(ctypes.POINTER(struct_hostent)), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    gethostbyaddr_r = _libraries['FIXME_STUB'].gethostbyaddr_r
    gethostbyaddr_r.restype = ctypes.c_int32
    gethostbyaddr_r.argtypes = [ctypes.POINTER(None), __socklen_t, ctypes.c_int32, ctypes.POINTER(struct_hostent), ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(ctypes.POINTER(struct_hostent)), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    gethostbyname_r = _libraries['FIXME_STUB'].gethostbyname_r
    gethostbyname_r.restype = ctypes.c_int32
    gethostbyname_r.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_hostent), ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(ctypes.POINTER(struct_hostent)), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    gethostbyname2_r = _libraries['FIXME_STUB'].gethostbyname2_r
    gethostbyname2_r.restype = ctypes.c_int32
    gethostbyname2_r.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(struct_hostent), ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(ctypes.POINTER(struct_hostent)), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    setnetent = _libraries['FIXME_STUB'].setnetent
    setnetent.restype = None
    setnetent.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    endnetent = _libraries['FIXME_STUB'].endnetent
    endnetent.restype = None
    endnetent.argtypes = []
except AttributeError:
    pass
try:
    getnetent = _libraries['FIXME_STUB'].getnetent
    getnetent.restype = ctypes.POINTER(struct_netent)
    getnetent.argtypes = []
except AttributeError:
    pass
try:
    getnetbyaddr = _libraries['FIXME_STUB'].getnetbyaddr
    getnetbyaddr.restype = ctypes.POINTER(struct_netent)
    getnetbyaddr.argtypes = [uint32_t, ctypes.c_int32]
except AttributeError:
    pass
try:
    getnetbyname = _libraries['FIXME_STUB'].getnetbyname
    getnetbyname.restype = ctypes.POINTER(struct_netent)
    getnetbyname.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    getnetent_r = _libraries['FIXME_STUB'].getnetent_r
    getnetent_r.restype = ctypes.c_int32
    getnetent_r.argtypes = [ctypes.POINTER(struct_netent), ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(ctypes.POINTER(struct_netent)), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    getnetbyaddr_r = _libraries['FIXME_STUB'].getnetbyaddr_r
    getnetbyaddr_r.restype = ctypes.c_int32
    getnetbyaddr_r.argtypes = [uint32_t, ctypes.c_int32, ctypes.POINTER(struct_netent), ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(ctypes.POINTER(struct_netent)), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    getnetbyname_r = _libraries['FIXME_STUB'].getnetbyname_r
    getnetbyname_r.restype = ctypes.c_int32
    getnetbyname_r.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_netent), ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(ctypes.POINTER(struct_netent)), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
class struct_servent(Structure):
    pass

struct_servent._pack_ = 1 # source:False
struct_servent._fields_ = [
    ('s_name', ctypes.POINTER(ctypes.c_char)),
    ('s_aliases', ctypes.POINTER(ctypes.POINTER(ctypes.c_char))),
    ('s_port', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('s_proto', ctypes.POINTER(ctypes.c_char)),
]

try:
    setservent = _libraries['FIXME_STUB'].setservent
    setservent.restype = None
    setservent.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    endservent = _libraries['FIXME_STUB'].endservent
    endservent.restype = None
    endservent.argtypes = []
except AttributeError:
    pass
try:
    getservent = _libraries['FIXME_STUB'].getservent
    getservent.restype = ctypes.POINTER(struct_servent)
    getservent.argtypes = []
except AttributeError:
    pass
try:
    getservbyname = _libraries['FIXME_STUB'].getservbyname
    getservbyname.restype = ctypes.POINTER(struct_servent)
    getservbyname.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    getservbyport = _libraries['FIXME_STUB'].getservbyport
    getservbyport.restype = ctypes.POINTER(struct_servent)
    getservbyport.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    getservent_r = _libraries['FIXME_STUB'].getservent_r
    getservent_r.restype = ctypes.c_int32
    getservent_r.argtypes = [ctypes.POINTER(struct_servent), ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(ctypes.POINTER(struct_servent))]
except AttributeError:
    pass
try:
    getservbyname_r = _libraries['FIXME_STUB'].getservbyname_r
    getservbyname_r.restype = ctypes.c_int32
    getservbyname_r.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_servent), ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(ctypes.POINTER(struct_servent))]
except AttributeError:
    pass
try:
    getservbyport_r = _libraries['FIXME_STUB'].getservbyport_r
    getservbyport_r.restype = ctypes.c_int32
    getservbyport_r.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_servent), ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(ctypes.POINTER(struct_servent))]
except AttributeError:
    pass
class struct_protoent(Structure):
    pass

struct_protoent._pack_ = 1 # source:False
struct_protoent._fields_ = [
    ('p_name', ctypes.POINTER(ctypes.c_char)),
    ('p_aliases', ctypes.POINTER(ctypes.POINTER(ctypes.c_char))),
    ('p_proto', ctypes.c_int32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

try:
    setprotoent = _libraries['FIXME_STUB'].setprotoent
    setprotoent.restype = None
    setprotoent.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    endprotoent = _libraries['FIXME_STUB'].endprotoent
    endprotoent.restype = None
    endprotoent.argtypes = []
except AttributeError:
    pass
try:
    getprotoent = _libraries['FIXME_STUB'].getprotoent
    getprotoent.restype = ctypes.POINTER(struct_protoent)
    getprotoent.argtypes = []
except AttributeError:
    pass
try:
    getprotobyname = _libraries['FIXME_STUB'].getprotobyname
    getprotobyname.restype = ctypes.POINTER(struct_protoent)
    getprotobyname.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    getprotobynumber = _libraries['FIXME_STUB'].getprotobynumber
    getprotobynumber.restype = ctypes.POINTER(struct_protoent)
    getprotobynumber.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    getprotoent_r = _libraries['FIXME_STUB'].getprotoent_r
    getprotoent_r.restype = ctypes.c_int32
    getprotoent_r.argtypes = [ctypes.POINTER(struct_protoent), ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(ctypes.POINTER(struct_protoent))]
except AttributeError:
    pass
try:
    getprotobyname_r = _libraries['FIXME_STUB'].getprotobyname_r
    getprotobyname_r.restype = ctypes.c_int32
    getprotobyname_r.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_protoent), ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(ctypes.POINTER(struct_protoent))]
except AttributeError:
    pass
try:
    getprotobynumber_r = _libraries['FIXME_STUB'].getprotobynumber_r
    getprotobynumber_r.restype = ctypes.c_int32
    getprotobynumber_r.argtypes = [ctypes.c_int32, ctypes.POINTER(struct_protoent), ctypes.POINTER(ctypes.c_char), size_t, ctypes.POINTER(ctypes.POINTER(struct_protoent))]
except AttributeError:
    pass
try:
    setnetgrent = _libraries['FIXME_STUB'].setnetgrent
    setnetgrent.restype = ctypes.c_int32
    setnetgrent.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    endnetgrent = _libraries['FIXME_STUB'].endnetgrent
    endnetgrent.restype = None
    endnetgrent.argtypes = []
except AttributeError:
    pass
try:
    getnetgrent = _libraries['FIXME_STUB'].getnetgrent
    getnetgrent.restype = ctypes.c_int32
    getnetgrent.argtypes = [ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
except AttributeError:
    pass
try:
    innetgr = _libraries['FIXME_STUB'].innetgr
    innetgr.restype = ctypes.c_int32
    innetgr.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    getnetgrent_r = _libraries['FIXME_STUB'].getnetgrent_r
    getnetgrent_r.restype = ctypes.c_int32
    getnetgrent_r.argtypes = [ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.POINTER(ctypes.c_char), size_t]
except AttributeError:
    pass
try:
    rcmd = _libraries['FIXME_STUB'].rcmd
    rcmd.restype = ctypes.c_int32
    rcmd.argtypes = [ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.c_uint16, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    rcmd_af = _libraries['FIXME_STUB'].rcmd_af
    rcmd_af.restype = ctypes.c_int32
    rcmd_af.argtypes = [ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.c_uint16, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_int32), sa_family_t]
except AttributeError:
    pass
try:
    rexec = _libraries['FIXME_STUB'].rexec
    rexec.restype = ctypes.c_int32
    rexec.argtypes = [ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    rexec_af = _libraries['FIXME_STUB'].rexec_af
    rexec_af.restype = ctypes.c_int32
    rexec_af.argtypes = [ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_int32), sa_family_t]
except AttributeError:
    pass
try:
    ruserok = _libraries['FIXME_STUB'].ruserok
    ruserok.restype = ctypes.c_int32
    ruserok.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    ruserok_af = _libraries['FIXME_STUB'].ruserok_af
    ruserok_af.restype = ctypes.c_int32
    ruserok_af.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), sa_family_t]
except AttributeError:
    pass
try:
    iruserok = _libraries['FIXME_STUB'].iruserok
    iruserok.restype = ctypes.c_int32
    iruserok.argtypes = [uint32_t, ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    iruserok_af = _libraries['FIXME_STUB'].iruserok_af
    iruserok_af.restype = ctypes.c_int32
    iruserok_af.argtypes = [ctypes.POINTER(None), ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), sa_family_t]
except AttributeError:
    pass
try:
    rresvport = _libraries['FIXME_STUB'].rresvport
    rresvport.restype = ctypes.c_int32
    rresvport.argtypes = [ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    rresvport_af = _libraries['FIXME_STUB'].rresvport_af
    rresvport_af.restype = ctypes.c_int32
    rresvport_af.argtypes = [ctypes.POINTER(ctypes.c_int32), sa_family_t]
except AttributeError:
    pass
class struct_addrinfo(Structure):
    pass

struct_addrinfo._pack_ = 1 # source:False
struct_addrinfo._fields_ = [
    ('ai_flags', ctypes.c_int32),
    ('ai_family', ctypes.c_int32),
    ('ai_socktype', ctypes.c_int32),
    ('ai_protocol', ctypes.c_int32),
    ('ai_addrlen', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('ai_addr', ctypes.POINTER(struct_sockaddr)),
    ('ai_canonname', ctypes.POINTER(ctypes.c_char)),
    ('ai_next', ctypes.POINTER(struct_addrinfo)),
]

try:
    getaddrinfo = _libraries['FIXME_STUB'].getaddrinfo
    getaddrinfo.restype = ctypes.c_int32
    getaddrinfo.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_addrinfo), ctypes.POINTER(ctypes.POINTER(struct_addrinfo))]
except AttributeError:
    pass
try:
    freeaddrinfo = _libraries['FIXME_STUB'].freeaddrinfo
    freeaddrinfo.restype = None
    freeaddrinfo.argtypes = [ctypes.POINTER(struct_addrinfo)]
except AttributeError:
    pass
try:
    gai_strerror = _libraries['FIXME_STUB'].gai_strerror
    gai_strerror.restype = ctypes.POINTER(ctypes.c_char)
    gai_strerror.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    getnameinfo = _libraries['FIXME_STUB'].getnameinfo
    getnameinfo.restype = ctypes.c_int32
    getnameinfo.argtypes = [ctypes.POINTER(struct_sockaddr), socklen_t, ctypes.POINTER(ctypes.c_char), socklen_t, ctypes.POINTER(ctypes.c_char), socklen_t, ctypes.c_int32]
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
class struct_sigevent(Structure):
    pass

class union_sigevent__sigev_un(Union):
    pass

class struct_sigevent_0__sigev_thread(Structure):
    pass

struct_sigevent_0__sigev_thread._pack_ = 1 # source:False
struct_sigevent_0__sigev_thread._fields_ = [
    ('_function', ctypes.CFUNCTYPE(None, union_sigval)),
    ('_attribute', ctypes.POINTER(union_pthread_attr_t)),
]

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
tcp_seq = ctypes.c_uint32
class struct_tcphdr(Structure):
    pass

class union_tcphdr_0(Union):
    pass

class struct_tcphdr_0_0(Structure):
    pass

struct_tcphdr_0_0._pack_ = 1 # source:False
struct_tcphdr_0_0._fields_ = [
    ('th_sport', ctypes.c_uint16),
    ('th_dport', ctypes.c_uint16),
    ('th_seq', ctypes.c_uint32),
    ('th_ack', ctypes.c_uint32),
    ('th_x2', ctypes.c_ubyte, 4),
    ('th_off', ctypes.c_ubyte, 4),
    ('th_flags', ctypes.c_ubyte, 8),
    ('th_win', ctypes.c_uint16),
    ('th_sum', ctypes.c_uint16),
    ('th_urp', ctypes.c_uint16),
]

class struct_tcphdr_0_1(Structure):
    pass

struct_tcphdr_0_1._pack_ = 1 # source:False
struct_tcphdr_0_1._fields_ = [
    ('source', ctypes.c_uint16),
    ('dest', ctypes.c_uint16),
    ('seq', ctypes.c_uint32),
    ('ack_seq', ctypes.c_uint32),
    ('res1', ctypes.c_uint16, 4),
    ('doff', ctypes.c_uint16, 4),
    ('fin', ctypes.c_uint16, 1),
    ('syn', ctypes.c_uint16, 1),
    ('rst', ctypes.c_uint16, 1),
    ('psh', ctypes.c_uint16, 1),
    ('ack', ctypes.c_uint16, 1),
    ('urg', ctypes.c_uint16, 1),
    ('res2', ctypes.c_uint16, 2),
    ('window', ctypes.c_uint16),
    ('check', ctypes.c_uint16),
    ('urg_ptr', ctypes.c_uint16),
]

union_tcphdr_0._pack_ = 1 # source:False
union_tcphdr_0._anonymous_ = ('_0', '_1',)
union_tcphdr_0._fields_ = [
    ('_0', struct_tcphdr_0_0),
    ('_1', struct_tcphdr_0_1),
]

struct_tcphdr._pack_ = 1 # source:False
struct_tcphdr._anonymous_ = ('_0',)
struct_tcphdr._fields_ = [
    ('_0', union_tcphdr_0),
]


# values for enumeration 'c__Ea_TCP_ESTABLISHED'
c__Ea_TCP_ESTABLISHED__enumvalues = {
    1: 'TCP_ESTABLISHED',
    2: 'TCP_SYN_SENT',
    3: 'TCP_SYN_RECV',
    4: 'TCP_FIN_WAIT1',
    5: 'TCP_FIN_WAIT2',
    6: 'TCP_TIME_WAIT',
    7: 'TCP_CLOSE',
    8: 'TCP_CLOSE_WAIT',
    9: 'TCP_LAST_ACK',
    10: 'TCP_LISTEN',
    11: 'TCP_CLOSING',
}
TCP_ESTABLISHED = 1
TCP_SYN_SENT = 2
TCP_SYN_RECV = 3
TCP_FIN_WAIT1 = 4
TCP_FIN_WAIT2 = 5
TCP_TIME_WAIT = 6
TCP_CLOSE = 7
TCP_CLOSE_WAIT = 8
TCP_LAST_ACK = 9
TCP_LISTEN = 10
TCP_CLOSING = 11
c__Ea_TCP_ESTABLISHED = ctypes.c_uint32 # enum

# values for enumeration 'tcp_ca_state'
tcp_ca_state__enumvalues = {
    0: 'TCP_CA_Open',
    1: 'TCP_CA_Disorder',
    2: 'TCP_CA_CWR',
    3: 'TCP_CA_Recovery',
    4: 'TCP_CA_Loss',
}
TCP_CA_Open = 0
TCP_CA_Disorder = 1
TCP_CA_CWR = 2
TCP_CA_Recovery = 3
TCP_CA_Loss = 4
tcp_ca_state = ctypes.c_uint32 # enum
class struct_tcp_info(Structure):
    pass

struct_tcp_info._pack_ = 1 # source:False
struct_tcp_info._fields_ = [
    ('tcpi_state', ctypes.c_ubyte),
    ('tcpi_ca_state', ctypes.c_ubyte),
    ('tcpi_retransmits', ctypes.c_ubyte),
    ('tcpi_probes', ctypes.c_ubyte),
    ('tcpi_backoff', ctypes.c_ubyte),
    ('tcpi_options', ctypes.c_ubyte),
    ('tcpi_snd_wscale', ctypes.c_ubyte, 4),
    ('tcpi_rcv_wscale', ctypes.c_ubyte, 4),
    ('PADDING_0', ctypes.c_uint8, 8),
    ('tcpi_rto', ctypes.c_uint32),
    ('tcpi_ato', ctypes.c_uint32),
    ('tcpi_snd_mss', ctypes.c_uint32),
    ('tcpi_rcv_mss', ctypes.c_uint32),
    ('tcpi_unacked', ctypes.c_uint32),
    ('tcpi_sacked', ctypes.c_uint32),
    ('tcpi_lost', ctypes.c_uint32),
    ('tcpi_retrans', ctypes.c_uint32),
    ('tcpi_fackets', ctypes.c_uint32),
    ('tcpi_last_data_sent', ctypes.c_uint32),
    ('tcpi_last_ack_sent', ctypes.c_uint32),
    ('tcpi_last_data_recv', ctypes.c_uint32),
    ('tcpi_last_ack_recv', ctypes.c_uint32),
    ('tcpi_pmtu', ctypes.c_uint32),
    ('tcpi_rcv_ssthresh', ctypes.c_uint32),
    ('tcpi_rtt', ctypes.c_uint32),
    ('tcpi_rttvar', ctypes.c_uint32),
    ('tcpi_snd_ssthresh', ctypes.c_uint32),
    ('tcpi_snd_cwnd', ctypes.c_uint32),
    ('tcpi_advmss', ctypes.c_uint32),
    ('tcpi_reordering', ctypes.c_uint32),
    ('tcpi_rcv_rtt', ctypes.c_uint32),
    ('tcpi_rcv_space', ctypes.c_uint32),
    ('tcpi_total_retrans', ctypes.c_uint32),
]

class struct_tcp_md5sig(Structure):
    pass

struct_tcp_md5sig._pack_ = 1 # source:False
struct_tcp_md5sig._fields_ = [
    ('tcpm_addr', struct_sockaddr_storage),
    ('tcpm_flags', ctypes.c_ubyte),
    ('tcpm_prefixlen', ctypes.c_ubyte),
    ('tcpm_keylen', ctypes.c_uint16),
    ('tcpm_ifindex', ctypes.c_int32),
    ('tcpm_key', ctypes.c_ubyte * 80),
]

class struct_tcp_repair_opt(Structure):
    pass

struct_tcp_repair_opt._pack_ = 1 # source:False
struct_tcp_repair_opt._fields_ = [
    ('opt_code', ctypes.c_uint32),
    ('opt_val', ctypes.c_uint32),
]


# values for enumeration 'c__Ea_TCP_NO_QUEUE'
c__Ea_TCP_NO_QUEUE__enumvalues = {
    0: 'TCP_NO_QUEUE',
    1: 'TCP_RECV_QUEUE',
    2: 'TCP_SEND_QUEUE',
    3: 'TCP_QUEUES_NR',
}
TCP_NO_QUEUE = 0
TCP_RECV_QUEUE = 1
TCP_SEND_QUEUE = 2
TCP_QUEUES_NR = 3
c__Ea_TCP_NO_QUEUE = ctypes.c_uint32 # enum
class struct_tcp_cookie_transactions(Structure):
    pass

struct_tcp_cookie_transactions._pack_ = 1 # source:False
struct_tcp_cookie_transactions._fields_ = [
    ('tcpct_flags', ctypes.c_uint16),
    ('__tcpct_pad1', ctypes.c_ubyte),
    ('tcpct_cookie_desired', ctypes.c_ubyte),
    ('tcpct_s_data_desired', ctypes.c_uint16),
    ('tcpct_used', ctypes.c_uint16),
    ('tcpct_value', ctypes.c_ubyte * 536),
]

class struct_tcp_repair_window(Structure):
    pass

struct_tcp_repair_window._pack_ = 1 # source:False
struct_tcp_repair_window._fields_ = [
    ('snd_wl1', ctypes.c_uint32),
    ('snd_wnd', ctypes.c_uint32),
    ('max_window', ctypes.c_uint32),
    ('rcv_wnd', ctypes.c_uint32),
    ('rcv_wup', ctypes.c_uint32),
]

class struct_tcp_zerocopy_receive(Structure):
    pass

struct_tcp_zerocopy_receive._pack_ = 1 # source:False
struct_tcp_zerocopy_receive._fields_ = [
    ('address', ctypes.c_uint64),
    ('length', ctypes.c_uint32),
    ('recv_skip_hint', ctypes.c_uint32),
]

class struct_R2Pipe(Structure):
    pass

struct_R2Pipe._pack_ = 1 # source:False
struct_R2Pipe._fields_ = [
    ('child', ctypes.c_int32),
    ('input', ctypes.c_int32 * 2),
    ('output', ctypes.c_int32 * 2),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('coreb', RCoreBind),
]

R2Pipe = struct_R2Pipe
class struct_r_socket_t(Structure):
    pass

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

RSocket = struct_r_socket_t
class struct_r_socket_http_options(Structure):
    pass

struct_r_socket_http_options._pack_ = 1 # source:False
struct_r_socket_http_options._fields_ = [
    ('authtokens', ctypes.POINTER(struct_r_list_t)),
    ('accept_timeout', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 3),
    ('timeout', ctypes.c_int32),
    ('httpauth', ctypes.c_bool),
    ('PADDING_1', ctypes.c_ubyte * 7),
]

RSocketHTTPOptions = struct_r_socket_http_options
try:
    r_socket_new_from_fd = _libr_socket.r_socket_new_from_fd
    r_socket_new_from_fd.restype = ctypes.POINTER(struct_r_socket_t)
    r_socket_new_from_fd.argtypes = [ctypes.c_int32]
except AttributeError:
    pass
try:
    r_socket_new = _libr_socket.r_socket_new
    r_socket_new.restype = ctypes.POINTER(struct_r_socket_t)
    r_socket_new.argtypes = [ctypes.c_bool]
except AttributeError:
    pass
try:
    r_socket_spawn = _libr_socket.r_socket_spawn
    r_socket_spawn.restype = ctypes.c_bool
    r_socket_spawn.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint32]
except AttributeError:
    pass
try:
    r_socket_connect = _libr_socket.r_socket_connect
    r_socket_connect.restype = ctypes.c_bool
    r_socket_connect.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_uint32]
except AttributeError:
    pass
try:
    r_socket_connect_serial = _libr_socket.r_socket_connect_serial
    r_socket_connect_serial.restype = ctypes.c_int32
    r_socket_connect_serial.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_socket_listen = _libr_socket.r_socket_listen
    r_socket_listen.restype = ctypes.c_bool
    r_socket_listen.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_socket_port_by_name = _libr_socket.r_socket_port_by_name
    r_socket_port_by_name.restype = ctypes.c_int32
    r_socket_port_by_name.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_socket_close_fd = _libr_socket.r_socket_close_fd
    r_socket_close_fd.restype = ctypes.c_int32
    r_socket_close_fd.argtypes = [ctypes.POINTER(struct_r_socket_t)]
except AttributeError:
    pass
try:
    r_socket_close = _libr_socket.r_socket_close
    r_socket_close.restype = ctypes.c_int32
    r_socket_close.argtypes = [ctypes.POINTER(struct_r_socket_t)]
except AttributeError:
    pass
try:
    r_socket_free = _libr_socket.r_socket_free
    r_socket_free.restype = ctypes.c_int32
    r_socket_free.argtypes = [ctypes.POINTER(struct_r_socket_t)]
except AttributeError:
    pass
try:
    r_socket_accept = _libr_socket.r_socket_accept
    r_socket_accept.restype = ctypes.POINTER(struct_r_socket_t)
    r_socket_accept.argtypes = [ctypes.POINTER(struct_r_socket_t)]
except AttributeError:
    pass
try:
    r_socket_accept_timeout = _libr_socket.r_socket_accept_timeout
    r_socket_accept_timeout.restype = ctypes.POINTER(struct_r_socket_t)
    r_socket_accept_timeout.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.c_uint32]
except AttributeError:
    pass
try:
    r_socket_block_time = _libr_socket.r_socket_block_time
    r_socket_block_time.restype = ctypes.c_bool
    r_socket_block_time.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.c_bool, ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_socket_flush = _libr_socket.r_socket_flush
    r_socket_flush.restype = ctypes.c_int32
    r_socket_flush.argtypes = [ctypes.POINTER(struct_r_socket_t)]
except AttributeError:
    pass
try:
    r_socket_ready = _libr_socket.r_socket_ready
    r_socket_ready.restype = ctypes.c_int32
    r_socket_ready.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_socket_to_string = _libr_socket.r_socket_to_string
    r_socket_to_string.restype = ctypes.POINTER(ctypes.c_char)
    r_socket_to_string.argtypes = [ctypes.POINTER(struct_r_socket_t)]
except AttributeError:
    pass
try:
    r_socket_write = _libr_socket.r_socket_write
    r_socket_write.restype = ctypes.c_int32
    r_socket_write.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(None), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_socket_puts = _libr_socket.r_socket_puts
    r_socket_puts.restype = ctypes.c_int32
    r_socket_puts.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_socket_printf = _libr_socket.r_socket_printf
    r_socket_printf.restype = None
    r_socket_printf.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_socket_read = _libr_socket.r_socket_read
    r_socket_read.restype = ctypes.c_int32
    r_socket_read.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_socket_read_block = _libr_socket.r_socket_read_block
    r_socket_read_block.restype = ctypes.c_int32
    r_socket_read_block.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_socket_gets = _libr_socket.r_socket_gets
    r_socket_gets.restype = ctypes.c_int32
    r_socket_gets.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_socket_slurp = _libr_socket.r_socket_slurp
    r_socket_slurp.restype = ctypes.POINTER(ctypes.c_ubyte)
    r_socket_slurp.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_socket_is_connected = _libr_socket.r_socket_is_connected
    r_socket_is_connected.restype = ctypes.c_bool
    r_socket_is_connected.argtypes = [ctypes.POINTER(struct_r_socket_t)]
except AttributeError:
    pass
class struct_r_socket_proc_t(Structure):
    pass

struct_r_socket_proc_t._pack_ = 1 # source:False
struct_r_socket_proc_t._fields_ = [
    ('fd0', ctypes.c_int32 * 2),
    ('fd1', ctypes.c_int32 * 2),
    ('pid', ctypes.c_int32),
]

RSocketProc = struct_r_socket_proc_t
try:
    r_socket_proc_open = _libr_socket.r_socket_proc_open
    r_socket_proc_open.restype = ctypes.POINTER(struct_r_socket_proc_t)
    r_socket_proc_open.argtypes = [ctypes.POINTER(ctypes.c_char) * 0]
except AttributeError:
    pass
try:
    r_socket_proc_close = _libr_socket.r_socket_proc_close
    r_socket_proc_close.restype = ctypes.c_int32
    r_socket_proc_close.argtypes = [ctypes.POINTER(struct_r_socket_proc_t)]
except AttributeError:
    pass
try:
    r_socket_proc_read = _libr_socket.r_socket_proc_read
    r_socket_proc_read.restype = ctypes.c_int32
    r_socket_proc_read.argtypes = [ctypes.POINTER(struct_r_socket_proc_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_socket_proc_gets = _libr_socket.r_socket_proc_gets
    r_socket_proc_gets.restype = ctypes.c_int32
    r_socket_proc_gets.argtypes = [ctypes.POINTER(struct_r_socket_proc_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_socket_proc_write = _libr_socket.r_socket_proc_write
    r_socket_proc_write.restype = ctypes.c_int32
    r_socket_proc_write.argtypes = [ctypes.POINTER(struct_r_socket_proc_t), ctypes.POINTER(None), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_socket_proc_printf = _libr_socket.r_socket_proc_printf
    r_socket_proc_printf.restype = None
    r_socket_proc_printf.argtypes = [ctypes.POINTER(struct_r_socket_proc_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_socket_proc_ready = _libr_socket.r_socket_proc_ready
    r_socket_proc_ready.restype = ctypes.c_int32
    r_socket_proc_ready.argtypes = [ctypes.POINTER(struct_r_socket_proc_t), ctypes.c_int32, ctypes.c_int32]
except AttributeError:
    pass
try:
    r_socket_http_get = _libr_socket.r_socket_http_get
    r_socket_http_get.restype = ctypes.POINTER(ctypes.c_char)
    r_socket_http_get.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_socket_http_post = _libr_socket.r_socket_http_post
    r_socket_http_post.restype = ctypes.POINTER(ctypes.c_char)
    r_socket_http_post.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_socket_http_server_set_breaked = _libr_socket.r_socket_http_server_set_breaked
    r_socket_http_server_set_breaked.restype = None
    r_socket_http_server_set_breaked.argtypes = [ctypes.POINTER(ctypes.c_bool)]
except AttributeError:
    pass
class struct_r_socket_http_request(Structure):
    pass

struct_r_socket_http_request._pack_ = 1 # source:False
struct_r_socket_http_request._fields_ = [
    ('s', ctypes.POINTER(struct_r_socket_t)),
    ('path', ctypes.POINTER(ctypes.c_char)),
    ('host', ctypes.POINTER(ctypes.c_char)),
    ('agent', ctypes.POINTER(ctypes.c_char)),
    ('method', ctypes.POINTER(ctypes.c_char)),
    ('referer', ctypes.POINTER(ctypes.c_char)),
    ('data', ctypes.POINTER(ctypes.c_ubyte)),
    ('data_length', ctypes.c_int32),
    ('auth', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 3),
]

RSocketHTTPRequest = struct_r_socket_http_request
try:
    r_socket_http_accept = _libr_socket.r_socket_http_accept
    r_socket_http_accept.restype = ctypes.POINTER(struct_r_socket_http_request)
    r_socket_http_accept.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(struct_r_socket_http_options)]
except AttributeError:
    pass
try:
    r_socket_http_response = _libr_socket.r_socket_http_response
    r_socket_http_response.restype = None
    r_socket_http_response.argtypes = [ctypes.POINTER(struct_r_socket_http_request), ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_socket_http_close = _libr_socket.r_socket_http_close
    r_socket_http_close.restype = None
    r_socket_http_close.argtypes = [ctypes.POINTER(struct_r_socket_http_request)]
except AttributeError:
    pass
try:
    r_socket_http_handle_upload = _libr_socket.r_socket_http_handle_upload
    r_socket_http_handle_upload.restype = ctypes.POINTER(ctypes.c_ubyte)
    r_socket_http_handle_upload.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_int32)]
except AttributeError:
    pass
try:
    r_socket_http_free = _libr_socket.r_socket_http_free
    r_socket_http_free.restype = None
    r_socket_http_free.argtypes = [ctypes.POINTER(struct_r_socket_http_request)]
except AttributeError:
    pass
rap_server_open = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32)
rap_server_seek = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.c_uint64, ctypes.c_int32)
rap_server_read = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)
rap_server_write = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)
rap_server_cmd = ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))
rap_server_close = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.c_int32)

# values for enumeration 'c__Ea_RAP_PACKET_OPEN'
c__Ea_RAP_PACKET_OPEN__enumvalues = {
    1: 'RAP_PACKET_OPEN',
    2: 'RAP_PACKET_READ',
    3: 'RAP_PACKET_WRITE',
    4: 'RAP_PACKET_SEEK',
    5: 'RAP_PACKET_CLOSE',
    7: 'RAP_PACKET_CMD',
    128: 'RAP_PACKET_REPLY',
    4096: 'RAP_PACKET_MAX',
}
RAP_PACKET_OPEN = 1
RAP_PACKET_READ = 2
RAP_PACKET_WRITE = 3
RAP_PACKET_SEEK = 4
RAP_PACKET_CLOSE = 5
RAP_PACKET_CMD = 7
RAP_PACKET_REPLY = 128
RAP_PACKET_MAX = 4096
c__Ea_RAP_PACKET_OPEN = ctypes.c_uint32 # enum
class struct_r_socket_rap_server_t(Structure):
    pass

struct_r_socket_rap_server_t._pack_ = 1 # source:False
struct_r_socket_rap_server_t._fields_ = [
    ('fd', ctypes.POINTER(struct_r_socket_t)),
    ('port', ctypes.POINTER(ctypes.c_char)),
    ('buf', ctypes.c_ubyte * 4128),
    ('open', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32)),
    ('seek', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.c_uint64, ctypes.c_int32)),
    ('read', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)),
    ('write', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32)),
    ('system', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))),
    ('cmd', ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))),
    ('close', ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(None), ctypes.c_int32)),
    ('user', ctypes.POINTER(None)),
]

RSocketRapServer = struct_r_socket_rap_server_t
try:
    r_socket_rap_server_new = _libr_socket.r_socket_rap_server_new
    r_socket_rap_server_new.restype = ctypes.POINTER(struct_r_socket_rap_server_t)
    r_socket_rap_server_new.argtypes = [ctypes.c_bool, ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_socket_rap_server_create = _libr_socket.r_socket_rap_server_create
    r_socket_rap_server_create.restype = ctypes.POINTER(struct_r_socket_rap_server_t)
    r_socket_rap_server_create.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_socket_rap_server_free = _libr_socket.r_socket_rap_server_free
    r_socket_rap_server_free.restype = None
    r_socket_rap_server_free.argtypes = [ctypes.POINTER(struct_r_socket_rap_server_t)]
except AttributeError:
    pass
try:
    r_socket_rap_server_listen = _libr_socket.r_socket_rap_server_listen
    r_socket_rap_server_listen.restype = ctypes.c_bool
    r_socket_rap_server_listen.argtypes = [ctypes.POINTER(struct_r_socket_rap_server_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_socket_rap_server_accept = _libr_socket.r_socket_rap_server_accept
    r_socket_rap_server_accept.restype = ctypes.POINTER(struct_r_socket_t)
    r_socket_rap_server_accept.argtypes = [ctypes.POINTER(struct_r_socket_rap_server_t)]
except AttributeError:
    pass
try:
    r_socket_rap_server_continue = _libr_socket.r_socket_rap_server_continue
    r_socket_rap_server_continue.restype = ctypes.c_bool
    r_socket_rap_server_continue.argtypes = [ctypes.POINTER(struct_r_socket_rap_server_t)]
except AttributeError:
    pass
try:
    r_socket_rap_client_open = _libr_socket.r_socket_rap_client_open
    r_socket_rap_client_open.restype = ctypes.c_int32
    r_socket_rap_client_open.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_socket_rap_client_command = _libr_socket.r_socket_rap_client_command
    r_socket_rap_client_command.restype = ctypes.POINTER(ctypes.c_char)
    r_socket_rap_client_command.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_core_bind_t)]
except AttributeError:
    pass
try:
    r_socket_rap_client_write = _libr_socket.r_socket_rap_client_write
    r_socket_rap_client_write.restype = ctypes.c_int32
    r_socket_rap_client_write.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_socket_rap_client_read = _libr_socket.r_socket_rap_client_read
    r_socket_rap_client_read.restype = ctypes.c_int32
    r_socket_rap_client_read.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
except AttributeError:
    pass
try:
    r_socket_rap_client_seek = _libr_socket.r_socket_rap_client_seek
    r_socket_rap_client_seek.restype = ctypes.c_int32
    r_socket_rap_client_seek.argtypes = [ctypes.POINTER(struct_r_socket_t), uint64_t, ctypes.c_int32]
except AttributeError:
    pass
class struct_r_run_profile_t(Structure):
    pass

struct_r_run_profile_t._pack_ = 1 # source:False
struct_r_run_profile_t._fields_ = [
    ('_args', ctypes.POINTER(ctypes.c_char) * 512),
    ('_argc', ctypes.c_int32),
    ('_daemon', ctypes.c_bool),
    ('PADDING_0', ctypes.c_ubyte * 3),
    ('_system', ctypes.POINTER(ctypes.c_char)),
    ('_program', ctypes.POINTER(ctypes.c_char)),
    ('_runlib', ctypes.POINTER(ctypes.c_char)),
    ('_runlib_fcn', ctypes.POINTER(ctypes.c_char)),
    ('_stdio', ctypes.POINTER(ctypes.c_char)),
    ('_stdin', ctypes.POINTER(ctypes.c_char)),
    ('_stdout', ctypes.POINTER(ctypes.c_char)),
    ('_stderr', ctypes.POINTER(ctypes.c_char)),
    ('_chgdir', ctypes.POINTER(ctypes.c_char)),
    ('_chroot', ctypes.POINTER(ctypes.c_char)),
    ('_libpath', ctypes.POINTER(ctypes.c_char)),
    ('_preload', ctypes.POINTER(struct_r_list_t)),
    ('_bits', ctypes.c_int32),
    ('_time', ctypes.c_bool),
    ('PADDING_1', ctypes.c_ubyte * 3),
    ('_pid', ctypes.c_int32),
    ('PADDING_2', ctypes.c_ubyte * 4),
    ('_pidfile', ctypes.POINTER(ctypes.c_char)),
    ('_r2preload', ctypes.c_bool),
    ('_docore', ctypes.c_bool),
    ('_dofork', ctypes.c_bool),
    ('PADDING_3', ctypes.c_ubyte),
    ('_aslr', ctypes.c_int32),
    ('_maxstack', ctypes.c_int32),
    ('_maxproc', ctypes.c_int32),
    ('_maxfd', ctypes.c_int32),
    ('_r2sleep', ctypes.c_int32),
    ('_execve', ctypes.c_int32),
    ('PADDING_4', ctypes.c_ubyte * 4),
    ('_setuid', ctypes.POINTER(ctypes.c_char)),
    ('_seteuid', ctypes.POINTER(ctypes.c_char)),
    ('_setgid', ctypes.POINTER(ctypes.c_char)),
    ('_setegid', ctypes.POINTER(ctypes.c_char)),
    ('_input', ctypes.POINTER(ctypes.c_char)),
    ('_connect', ctypes.POINTER(ctypes.c_char)),
    ('_listen', ctypes.POINTER(ctypes.c_char)),
    ('_pty', ctypes.c_int32),
    ('_timeout', ctypes.c_int32),
    ('_timeout_sig', ctypes.c_int32),
    ('_nice', ctypes.c_int32),
]

RRunProfile = struct_r_run_profile_t
try:
    r_run_new = _libr_socket.r_run_new
    r_run_new.restype = ctypes.POINTER(struct_r_run_profile_t)
    r_run_new.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_run_parse = _libr_socket.r_run_parse
    r_run_parse.restype = ctypes.c_bool
    r_run_parse.argtypes = [ctypes.POINTER(struct_r_run_profile_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_run_free = _libr_socket.r_run_free
    r_run_free.restype = None
    r_run_free.argtypes = [ctypes.POINTER(struct_r_run_profile_t)]
except AttributeError:
    pass
try:
    r_run_parseline = _libr_socket.r_run_parseline
    r_run_parseline.restype = ctypes.c_bool
    r_run_parseline.argtypes = [ctypes.POINTER(struct_r_run_profile_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_run_help = _libr_socket.r_run_help
    r_run_help.restype = ctypes.POINTER(ctypes.c_char)
    r_run_help.argtypes = []
except AttributeError:
    pass
try:
    r_run_config_env = _libr_socket.r_run_config_env
    r_run_config_env.restype = ctypes.c_bool
    r_run_config_env.argtypes = [ctypes.POINTER(struct_r_run_profile_t)]
except AttributeError:
    pass
try:
    r_run_start = _libr_socket.r_run_start
    r_run_start.restype = ctypes.c_bool
    r_run_start.argtypes = [ctypes.POINTER(struct_r_run_profile_t)]
except AttributeError:
    pass
try:
    r_run_reset = _libr_socket.r_run_reset
    r_run_reset.restype = None
    r_run_reset.argtypes = [ctypes.POINTER(struct_r_run_profile_t)]
except AttributeError:
    pass
try:
    r_run_parsefile = _libr_socket.r_run_parsefile
    r_run_parsefile.restype = ctypes.c_bool
    r_run_parsefile.argtypes = [ctypes.POINTER(struct_r_run_profile_t), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r_run_get_environ_profile = _libr_socket.r_run_get_environ_profile
    r_run_get_environ_profile.restype = ctypes.POINTER(ctypes.c_char)
    r_run_get_environ_profile.argtypes = [ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
except AttributeError:
    pass
try:
    rap_open = _libraries['FIXME_STUB'].rap_open
    rap_open.restype = ctypes.POINTER(struct_R2Pipe)
    rap_open.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    rap_open_corebind = _libraries['FIXME_STUB'].rap_open_corebind
    rap_open_corebind.restype = ctypes.POINTER(struct_R2Pipe)
    rap_open_corebind.argtypes = [ctypes.POINTER(struct_r_core_bind_t)]
except AttributeError:
    pass
try:
    rap_close = _libraries['FIXME_STUB'].rap_close
    rap_close.restype = ctypes.c_int32
    rap_close.argtypes = [ctypes.POINTER(struct_R2Pipe)]
except AttributeError:
    pass
try:
    rap_cmd = _libraries['FIXME_STUB'].rap_cmd
    rap_cmd.restype = ctypes.POINTER(ctypes.c_char)
    rap_cmd.argtypes = [ctypes.POINTER(struct_R2Pipe), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    rap_cmdf = _libraries['FIXME_STUB'].rap_cmdf
    rap_cmdf.restype = ctypes.POINTER(ctypes.c_char)
    rap_cmdf.argtypes = [ctypes.POINTER(struct_R2Pipe), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    rap_write = _libraries['FIXME_STUB'].rap_write
    rap_write.restype = ctypes.c_int32
    rap_write.argtypes = [ctypes.POINTER(struct_R2Pipe), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    rap_read = _libraries['FIXME_STUB'].rap_read
    rap_read.restype = ctypes.POINTER(ctypes.c_char)
    rap_read.argtypes = [ctypes.POINTER(struct_R2Pipe)]
except AttributeError:
    pass
try:
    r2pipe_write = _libr_socket.r2pipe_write
    r2pipe_write.restype = ctypes.c_int32
    r2pipe_write.argtypes = [ctypes.POINTER(struct_R2Pipe), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r2pipe_read = _libr_socket.r2pipe_read
    r2pipe_read.restype = ctypes.POINTER(ctypes.c_char)
    r2pipe_read.argtypes = [ctypes.POINTER(struct_R2Pipe)]
except AttributeError:
    pass
try:
    r2pipe_close = _libr_socket.r2pipe_close
    r2pipe_close.restype = ctypes.c_int32
    r2pipe_close.argtypes = [ctypes.POINTER(struct_R2Pipe)]
except AttributeError:
    pass
try:
    r2pipe_open_corebind = _libr_socket.r2pipe_open_corebind
    r2pipe_open_corebind.restype = ctypes.POINTER(struct_R2Pipe)
    r2pipe_open_corebind.argtypes = [ctypes.POINTER(struct_r_core_bind_t)]
except AttributeError:
    pass
try:
    r2pipe_open = _libr_socket.r2pipe_open
    r2pipe_open.restype = ctypes.POINTER(struct_R2Pipe)
    r2pipe_open.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r2pipe_open_dl = _libr_socket.r2pipe_open_dl
    r2pipe_open_dl.restype = ctypes.POINTER(struct_R2Pipe)
    r2pipe_open_dl.argtypes = [ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r2pipe_cmd = _libr_socket.r2pipe_cmd
    r2pipe_cmd.restype = ctypes.POINTER(ctypes.c_char)
    r2pipe_cmd.argtypes = [ctypes.POINTER(struct_R2Pipe), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
try:
    r2pipe_cmdf = _libr_socket.r2pipe_cmdf
    r2pipe_cmdf.restype = ctypes.POINTER(ctypes.c_char)
    r2pipe_cmdf.argtypes = [ctypes.POINTER(struct_R2Pipe), ctypes.POINTER(ctypes.c_char)]
except AttributeError:
    pass
__all__ = \
    ['BUS_ADRALN', 'BUS_ADRERR', 'BUS_MCEERR_AO', 'BUS_MCEERR_AR',
    'BUS_OBJERR', 'BufferOp', 'CLD_CONTINUED', 'CLD_DUMPED',
    'CLD_EXITED', 'CLD_KILLED', 'CLD_STOPPED', 'CLD_TRAPPED', 'DIR',
    'DT_BLK', 'DT_CHR', 'DT_DIR', 'DT_FIFO', 'DT_LNK', 'DT_REG',
    'DT_SOCK', 'DT_UNKNOWN', 'DT_WHT', 'FILE', 'FPE_CONDTRAP',
    'FPE_FLTDIV', 'FPE_FLTINV', 'FPE_FLTOVF', 'FPE_FLTRES',
    'FPE_FLTSUB', 'FPE_FLTUND', 'FPE_FLTUNK', 'FPE_INTDIV',
    'FPE_INTOVF', 'FP_INFINITE', 'FP_NAN', 'FP_NORMAL',
    'FP_SUBNORMAL', 'FP_ZERO', 'GperfForeachCallback', 'HtPP',
    'HtPPBucket', 'HtPPCalcSizeK', 'HtPPCalcSizeV', 'HtPPDupKey',
    'HtPPDupValue', 'HtPPForeachCallback', 'HtPPHashFunction',
    'HtPPKv', 'HtPPKvFreeFunc', 'HtPPListComparator', 'HtPPOptions',
    'ILL_BADIADDR', 'ILL_BADSTK', 'ILL_COPROC', 'ILL_ILLADR',
    'ILL_ILLOPC', 'ILL_ILLOPN', 'ILL_ILLTRP', 'ILL_PRVOPC',
    'ILL_PRVREG', 'IPPORT_BIFFUDP', 'IPPORT_CMDSERVER',
    'IPPORT_DAYTIME', 'IPPORT_DISCARD', 'IPPORT_ECHO',
    'IPPORT_EFSSERVER', 'IPPORT_EXECSERVER', 'IPPORT_FINGER',
    'IPPORT_FTP', 'IPPORT_LOGINSERVER', 'IPPORT_MTP',
    'IPPORT_NAMESERVER', 'IPPORT_NETSTAT', 'IPPORT_RESERVED',
    'IPPORT_RJE', 'IPPORT_ROUTESERVER', 'IPPORT_SMTP',
    'IPPORT_SUPDUP', 'IPPORT_SYSTAT', 'IPPORT_TELNET', 'IPPORT_TFTP',
    'IPPORT_TIMESERVER', 'IPPORT_TTYLINK', 'IPPORT_USERRESERVED',
    'IPPORT_WHOIS', 'IPPORT_WHOSERVER', 'IPPROTO_AH',
    'IPPROTO_BEETPH', 'IPPROTO_COMP', 'IPPROTO_DCCP',
    'IPPROTO_DSTOPTS', 'IPPROTO_EGP', 'IPPROTO_ENCAP', 'IPPROTO_ESP',
    'IPPROTO_ETHERNET', 'IPPROTO_FRAGMENT', 'IPPROTO_GRE',
    'IPPROTO_HOPOPTS', 'IPPROTO_ICMP', 'IPPROTO_ICMPV6',
    'IPPROTO_IDP', 'IPPROTO_IGMP', 'IPPROTO_IP', 'IPPROTO_IPIP',
    'IPPROTO_IPV6', 'IPPROTO_L2TP', 'IPPROTO_MAX', 'IPPROTO_MH',
    'IPPROTO_MPLS', 'IPPROTO_MPTCP', 'IPPROTO_MTP', 'IPPROTO_NONE',
    'IPPROTO_PIM', 'IPPROTO_PUP', 'IPPROTO_RAW', 'IPPROTO_ROUTING',
    'IPPROTO_RSVP', 'IPPROTO_SCTP', 'IPPROTO_TCP', 'IPPROTO_TP',
    'IPPROTO_UDP', 'IPPROTO_UDPLITE', 'ITIMER_PROF', 'ITIMER_REAL',
    'ITIMER_VIRTUAL', 'MSG_BATCH', 'MSG_CMSG_CLOEXEC', 'MSG_CONFIRM',
    'MSG_CTRUNC', 'MSG_DONTROUTE', 'MSG_DONTWAIT', 'MSG_EOR',
    'MSG_ERRQUEUE', 'MSG_FASTOPEN', 'MSG_FIN', 'MSG_MORE',
    'MSG_NOSIGNAL', 'MSG_OOB', 'MSG_PEEK', 'MSG_PROXY', 'MSG_RST',
    'MSG_SYN', 'MSG_TRUNC', 'MSG_WAITALL', 'MSG_WAITFORONE',
    'MSG_ZEROCOPY', 'POLL_ERR', 'POLL_HUP', 'POLL_IN', 'POLL_MSG',
    'POLL_OUT', 'POLL_PRI', 'P_ALL', 'P_PGID', 'P_PID', 'P_PIDFD',
    'PrintfCallback', 'R2Pipe', 'RAP_PACKET_CLOSE', 'RAP_PACKET_CMD',
    'RAP_PACKET_MAX', 'RAP_PACKET_OPEN', 'RAP_PACKET_READ',
    'RAP_PACKET_REPLY', 'RAP_PACKET_SEEK', 'RAP_PACKET_WRITE',
    'RCoreBind', 'RCoreCmd', 'RCoreCmdF', 'RCoreCmdStr',
    'RCoreCmdStrF', 'RCoreConfigGet', 'RCoreConfigGetI',
    'RCoreDebugBpHit', 'RCoreDebugMapsSync', 'RCoreDebugSyscallHit',
    'RCoreGetName', 'RCoreGetNameDelta', 'RCoreIsMapped',
    'RCoreNumGet', 'RCorePJWithEncoding', 'RCorePuts',
    'RCoreSeekArchBits', 'RCoreSetArchBits', 'RList',
    'RListComparator', 'RListComparatorItem', 'RListFree',
    'RListIter', 'RListRange', 'RRunProfile', 'RSocket',
    'RSocketHTTPOptions', 'RSocketHTTPRequest', 'RSocketProc',
    'RSocketRapServer', 'RSysArch', 'R_SYS_ARCH_8051',
    'R_SYS_ARCH_ARC', 'R_SYS_ARCH_ARM', 'R_SYS_ARCH_AVR',
    'R_SYS_ARCH_BF', 'R_SYS_ARCH_BPF', 'R_SYS_ARCH_CR16',
    'R_SYS_ARCH_CRIS', 'R_SYS_ARCH_DALVIK', 'R_SYS_ARCH_EBC',
    'R_SYS_ARCH_ESIL', 'R_SYS_ARCH_H8300', 'R_SYS_ARCH_HPPA',
    'R_SYS_ARCH_I8080', 'R_SYS_ARCH_JAVA', 'R_SYS_ARCH_LM32',
    'R_SYS_ARCH_M68K', 'R_SYS_ARCH_MIPS', 'R_SYS_ARCH_MSIL',
    'R_SYS_ARCH_MSP430', 'R_SYS_ARCH_NONE', 'R_SYS_ARCH_OBJD',
    'R_SYS_ARCH_PPC', 'R_SYS_ARCH_PROPELLER', 'R_SYS_ARCH_RAR',
    'R_SYS_ARCH_RISCV', 'R_SYS_ARCH_S390', 'R_SYS_ARCH_SH',
    'R_SYS_ARCH_SPARC', 'R_SYS_ARCH_TMS320', 'R_SYS_ARCH_V810',
    'R_SYS_ARCH_V850', 'R_SYS_ARCH_X86', 'R_SYS_ARCH_XAP',
    'R_SYS_ARCH_XCORE', 'R_SYS_ARCH_Z80', 'SCM_RIGHTS', 'SEGV_ACCADI',
    'SEGV_ACCERR', 'SEGV_ADIDERR', 'SEGV_ADIPERR', 'SEGV_BNDERR',
    'SEGV_CPERR', 'SEGV_MAPERR', 'SEGV_MTEAERR', 'SEGV_MTESERR',
    'SEGV_PKUERR', 'SHUT_RD', 'SHUT_RDWR', 'SHUT_WR', 'SIGEV_NONE',
    'SIGEV_SIGNAL', 'SIGEV_THREAD', 'SIGEV_THREAD_ID', 'SI_ASYNCIO',
    'SI_ASYNCNL', 'SI_DETHREAD', 'SI_KERNEL', 'SI_MESGQ', 'SI_QUEUE',
    'SI_SIGIO', 'SI_TIMER', 'SI_TKILL', 'SI_USER', 'SOCK_CLOEXEC',
    'SOCK_DCCP', 'SOCK_DGRAM', 'SOCK_NONBLOCK', 'SOCK_PACKET',
    'SOCK_RAW', 'SOCK_RDM', 'SOCK_SEQPACKET', 'SOCK_STREAM',
    'SS_DISABLE', 'SS_ONSTACK', 'ST16_DIV_OVFCHK', 'ST16_MUL_OVFCHK',
    'ST32_DIV_OVFCHK', 'ST32_MUL_OVFCHK', 'ST64_DIV_OVFCHK',
    'ST64_MUL_OVFCHK', 'ST8_DIV_OVFCHK', 'ST8_MUL_OVFCHK',
    'SZT_MUL_OVFCHK', 'Sdb', 'SdbDiff', 'SdbDiffCallback',
    'SdbForeachCallback', 'SdbGperf', 'SdbHook', 'SdbJsonString',
    'SdbKv', 'SdbList', 'SdbListComparator', 'SdbListFree',
    'SdbListIter', 'SdbMini', 'SdbNs', 'TCP_CA_CWR',
    'TCP_CA_Disorder', 'TCP_CA_Loss', 'TCP_CA_Open',
    'TCP_CA_Recovery', 'TCP_CLOSE', 'TCP_CLOSE_WAIT', 'TCP_CLOSING',
    'TCP_ESTABLISHED', 'TCP_FIN_WAIT1', 'TCP_FIN_WAIT2',
    'TCP_LAST_ACK', 'TCP_LISTEN', 'TCP_NO_QUEUE', 'TCP_QUEUES_NR',
    'TCP_RECV_QUEUE', 'TCP_SEND_QUEUE', 'TCP_SYN_RECV',
    'TCP_SYN_SENT', 'TCP_TIME_WAIT', 'UT16_ADD', 'UT16_DIV_OVFCHK',
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
    '__cosl', '__ctype_b_loc', '__ctype_get_mb_cur_max',
    '__ctype_tolower_loc', '__ctype_toupper_loc', '__daddr_t',
    '__dev_t', '__drem', '__dremf', '__dreml', '__environ', '__erf',
    '__erfc', '__erfcf', '__erfcl', '__erff', '__erfl', '__exp',
    '__exp2', '__exp2f', '__exp2l', '__expf', '__expl', '__expm1',
    '__expm1f', '__expm1l', '__fabs', '__fabsf', '__fabsl',
    '__fd_mask', '__fdim', '__fdimf', '__fdiml', '__finite',
    '__finitef', '__finitel', '__floor', '__floorf', '__floorl',
    '__fma', '__fmaf', '__fmal', '__fmax', '__fmaxf', '__fmaxl',
    '__fmin', '__fminf', '__fminl', '__fmod', '__fmodf', '__fmodl',
    '__fpclassify', '__fpclassifyf', '__fpclassifyl', '__fpos64_t',
    '__fpos_t', '__frexp', '__frexpf', '__frexpl', '__fsblkcnt64_t',
    '__fsblkcnt_t', '__fsfilcnt64_t', '__fsfilcnt_t', '__fsid_t',
    '__fsword_t', '__gamma', '__gammaf', '__gammal', '__getdelim',
    '__getpgid', '__gid_t', '__gnuc_va_list', '__gwchar_t',
    '__h_errno_location', '__hypot', '__hypotf', '__hypotl', '__id_t',
    '__ilogb', '__ilogbf', '__ilogbl', '__ino64_t', '__ino_t',
    '__int16_t', '__int32_t', '__int64_t', '__int8_t',
    '__int_least16_t', '__int_least32_t', '__int_least64_t',
    '__int_least8_t', '__intmax_t', '__intptr_t', '__iseqsig',
    '__iseqsigf', '__iseqsigl', '__isinf', '__isinff', '__isinfl',
    '__isnan', '__isnanf', '__isnanl', '__issignaling',
    '__issignalingf', '__issignalingl', '__itimer_which',
    '__itimer_which_t', '__j0', '__j0f', '__j0l', '__j1', '__j1f',
    '__j1l', '__jn', '__jnf', '__jnl', '__kernel_caddr_t',
    '__kernel_clock_t', '__kernel_clockid_t', '__kernel_daddr_t',
    '__kernel_fd_set', '__kernel_fsid_t', '__kernel_gid16_t',
    '__kernel_gid32_t', '__kernel_gid_t', '__kernel_ino_t',
    '__kernel_ipc_pid_t', '__kernel_key_t', '__kernel_loff_t',
    '__kernel_long_t', '__kernel_mode_t', '__kernel_mqd_t',
    '__kernel_off_t', '__kernel_old_dev_t', '__kernel_old_gid_t',
    '__kernel_old_time_t', '__kernel_old_uid_t', '__kernel_pid_t',
    '__kernel_ptrdiff_t', '__kernel_sighandler_t', '__kernel_size_t',
    '__kernel_ssize_t', '__kernel_suseconds_t', '__kernel_time64_t',
    '__kernel_time_t', '__kernel_timer_t', '__kernel_uid16_t',
    '__kernel_uid32_t', '__kernel_uid_t', '__kernel_ulong_t',
    '__key_t', '__ldexp', '__ldexpf', '__ldexpl', '__lgamma',
    '__lgamma_r', '__lgammaf', '__lgammaf_r', '__lgammal',
    '__lgammal_r', '__libc_current_sigrtmax',
    '__libc_current_sigrtmin', '__llrint', '__llrintf', '__llrintl',
    '__llround', '__llroundf', '__llroundl', '__locale_t', '__loff_t',
    '__log', '__log10', '__log10f', '__log10l', '__log1p', '__log1pf',
    '__log1pl', '__log2', '__log2f', '__log2l', '__logb', '__logbf',
    '__logbl', '__logf', '__logl', '__lrint', '__lrintf', '__lrintl',
    '__lround', '__lroundf', '__lroundl', '__mbstate_t', '__memcmpeq',
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
    '__sig_atomic_t', '__sighandler_t', '__signbit', '__signbitf',
    '__signbitl', '__significand', '__significandf', '__significandl',
    '__sigset_t', '__sigval_t', '__sin', '__sinf', '__sinh',
    '__sinhf', '__sinhl', '__sinl', '__socket_type', '__socklen_t',
    '__sqrt', '__sqrtf', '__sqrtl', '__ssize_t', '__stpcpy',
    '__stpncpy', '__strtok_r', '__suseconds64_t', '__suseconds_t',
    '__syscall_slong_t', '__syscall_ulong_t', '__sysv_signal',
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
    '_exit', '_tolower', '_toupper', 'a64l', 'abort', 'abs', 'accept',
    'access', 'acct', 'acos', 'acosf', 'acosh', 'acoshf', 'acoshl',
    'acosl', 'adjtime', 'alarm', 'aligned_alloc', 'alloca',
    'alphasort', 'arc4random', 'arc4random_buf', 'arc4random_uniform',
    'asin', 'asinf', 'asinh', 'asinhf', 'asinhl', 'asinl', 'asprintf',
    'at_quick_exit', 'atan', 'atan2', 'atan2f', 'atan2l', 'atanf',
    'atanh', 'atanhf', 'atanhl', 'atanl', 'atexit', 'atof', 'atoi',
    'atol', 'atoll', 'bcmp', 'bcopy', 'bind', 'bindresvport',
    'bindresvport6', 'blkcnt_t', 'blksize_t', 'brk', 'bsearch',
    'buffer', 'buffer_bget', 'buffer_copy', 'buffer_feed',
    'buffer_flush', 'buffer_get', 'buffer_init', 'buffer_peek',
    'buffer_put', 'buffer_putalign', 'buffer_putflush', 'buffer_seek',
    'bzero', 'c__Ea_BUS_ADRALN', 'c__Ea_CLD_EXITED',
    'c__Ea_DT_UNKNOWN', 'c__Ea_FPE_INTDIV', 'c__Ea_FP_NAN',
    'c__Ea_ILL_ILLOPC', 'c__Ea_IPPORT_ECHO', 'c__Ea_IPPROTO_HOPOPTS',
    'c__Ea_IPPROTO_IP', 'c__Ea_MSG_OOB', 'c__Ea_POLL_IN',
    'c__Ea_RAP_PACKET_OPEN', 'c__Ea_SCM_RIGHTS', 'c__Ea_SEGV_MAPERR',
    'c__Ea_SHUT_RD', 'c__Ea_SIGEV_SIGNAL', 'c__Ea_SI_ASYNCNL',
    'c__Ea_SS_ONSTACK', 'c__Ea_TCP_ESTABLISHED', 'c__Ea_TCP_NO_QUEUE',
    'c__Ea__CS_PATH', 'c__Ea__ISupper', 'c__Ea__PC_LINK_MAX',
    'c__Ea__SC_ARG_MAX', 'caddr_t', 'calloc', 'cbrt', 'cbrtf',
    'cbrtl', 'cdb_findnext', 'cdb_findstart', 'cdb_free',
    'cdb_getkvlen', 'cdb_init', 'cdb_make_add', 'cdb_make_addbegin',
    'cdb_make_addend', 'cdb_make_finish', 'cdb_make_start',
    'cdb_read', 'ceil', 'ceilf', 'ceill', 'chdir', 'chmod', 'chown',
    'chroot', 'clearenv', 'clearerr', 'clearerr_unlocked', 'clock_t',
    'clockid_t', 'close', 'closedir', 'closefrom', 'confstr',
    'connect', 'cookie_close_function_t', 'cookie_io_functions_t',
    'cookie_read_function_t', 'cookie_seek_function_t',
    'cookie_write_function_t', 'copysign', 'copysignf', 'copysignl',
    'cos', 'cosf', 'cosh', 'coshf', 'coshl', 'cosl', 'creat', 'crypt',
    'ctermid', 'daddr_t', 'daemon', 'dev_t', 'dict', 'dict_add',
    'dict_del', 'dict_fini', 'dict_foreach', 'dict_free',
    'dict_freecb', 'dict_get', 'dict_getr', 'dict_getu', 'dict_hash',
    'dict_init', 'dict_new', 'dict_set', 'dict_stats', 'dicti',
    'dictkv', 'dictkv_cb', 'dirfd', 'div', 'div_t', 'double_t',
    'dprintf', 'drand48', 'drand48_r', 'drem', 'dremf', 'dreml',
    'dup', 'dup2', 'ecvt', 'ecvt_r', 'endhostent', 'endnetent',
    'endnetgrent', 'endprotoent', 'endrpcent', 'endservent',
    'endusershell', 'erand48', 'erand48_r', 'erf', 'erfc', 'erfcf',
    'erfcl', 'erff', 'erfl', 'execl', 'execle', 'execlp', 'execv',
    'execve', 'execvp', 'exit', 'exp', 'exp2', 'exp2f', 'exp2l',
    'expf', 'expl', 'explicit_bzero', 'expm1', 'expm1f', 'expm1l',
    'fabs', 'fabsf', 'fabsl', 'faccessat', 'fchdir', 'fchmod',
    'fchmodat', 'fchown', 'fchownat', 'fclose', 'fcntl', 'fcvt',
    'fcvt_r', 'fd_mask', 'fd_set', 'fdatasync', 'fdim', 'fdimf',
    'fdiml', 'fdopen', 'fdopendir', 'feof', 'feof_unlocked', 'ferror',
    'ferror_unlocked', 'fexecve', 'fflush', 'fflush_unlocked', 'ffs',
    'ffsl', 'ffsll', 'fgetc', 'fgetc_unlocked', 'fgetpos', 'fgets',
    'fileno', 'fileno_unlocked', 'finite', 'finitef', 'finitel',
    'float_t', 'flockfile', 'floor', 'floorf', 'floorl', 'fma',
    'fmaf', 'fmal', 'fmax', 'fmaxf', 'fmaxl', 'fmemopen', 'fmin',
    'fminf', 'fminl', 'fmod', 'fmodf', 'fmodl', 'fopen',
    'fopencookie', 'fork', 'fpathconf', 'fpos_t', 'fpregset_t',
    'fprintf', 'fputc', 'fputc_unlocked', 'fputs', 'fread',
    'fread_unlocked', 'free', 'freeaddrinfo', 'freopen', 'frexp',
    'frexpf', 'frexpl', 'fsblkcnt_t', 'fscanf', 'fseek', 'fseeko',
    'fsetpos', 'fsfilcnt_t', 'fsid_t', 'fstat', 'fstatat', 'fsync',
    'ftell', 'ftello', 'ftruncate', 'ftrylockfile', 'funlockfile',
    'futimens', 'futimes', 'fwrite', 'fwrite_unlocked',
    'gai_strerror', 'gamma', 'gammaf', 'gammal', 'gcvt',
    'getaddrinfo', 'getc', 'getc_unlocked', 'getchar',
    'getchar_unlocked', 'getcwd', 'getdelim', 'getdirentries',
    'getdomainname', 'getdtablesize', 'getegid', 'getentropy',
    'getenv', 'geteuid', 'getgid', 'getgroups', 'gethostbyaddr',
    'gethostbyaddr_r', 'gethostbyname', 'gethostbyname2',
    'gethostbyname2_r', 'gethostbyname_r', 'gethostent',
    'gethostent_r', 'gethostid', 'gethostname', 'getitimer',
    'getline', 'getloadavg', 'getlogin', 'getlogin_r', 'getnameinfo',
    'getnetbyaddr', 'getnetbyaddr_r', 'getnetbyname',
    'getnetbyname_r', 'getnetent', 'getnetent_r', 'getnetgrent',
    'getnetgrent_r', 'getopt', 'getpagesize', 'getpass',
    'getpeername', 'getpgid', 'getpgrp', 'getpid', 'getppid',
    'getprotobyname', 'getprotobyname_r', 'getprotobynumber',
    'getprotobynumber_r', 'getprotoent', 'getprotoent_r',
    'getrpcbyname', 'getrpcbyname_r', 'getrpcbynumber',
    'getrpcbynumber_r', 'getrpcent', 'getrpcent_r', 'getservbyname',
    'getservbyname_r', 'getservbyport', 'getservbyport_r',
    'getservent', 'getservent_r', 'getsid', 'getsockname',
    'getsockopt', 'getsubopt', 'gettimeofday', 'getuid',
    'getusershell', 'getw', 'getwd', 'gid_t', 'greg_t', 'gregset_t',
    'gsignal', 'herror', 'hstrerror', 'ht_pp_delete', 'ht_pp_find',
    'ht_pp_find_kv', 'ht_pp_foreach', 'ht_pp_free', 'ht_pp_insert',
    'ht_pp_insert_kv', 'ht_pp_new', 'ht_pp_new0', 'ht_pp_new_opt',
    'ht_pp_new_size', 'ht_pp_update', 'ht_pp_update_key', 'htonl',
    'htons', 'hypot', 'hypotf', 'hypotl', 'id_t', 'idtype_t', 'ilogb',
    'ilogbf', 'ilogbl', 'imaxabs', 'imaxdiv', 'imaxdiv_t',
    'in6addr_any', 'in6addr_loopback', 'in_addr_t', 'in_port_t',
    'index', 'inet_addr', 'inet_aton', 'inet_lnaof', 'inet_makeaddr',
    'inet_net_ntop', 'inet_net_pton', 'inet_neta', 'inet_netof',
    'inet_network', 'inet_nsap_addr', 'inet_nsap_ntoa', 'inet_ntoa',
    'inet_ntop', 'inet_pton', 'initstate', 'initstate_r', 'innetgr',
    'ino_t', 'int16_t', 'int32_t', 'int64_t', 'int8_t',
    'int_fast16_t', 'int_fast32_t', 'int_fast64_t', 'int_fast8_t',
    'int_least16_t', 'int_least32_t', 'int_least64_t', 'int_least8_t',
    'intmax_t', 'intptr_t', 'iruserok', 'iruserok_af', 'isalnum',
    'isalnum_l', 'isalpha', 'isalpha_l', 'isascii', 'isatty',
    'isblank', 'isblank_l', 'iscntrl', 'iscntrl_l', 'isdigit',
    'isdigit_l', 'isfdtype', 'isgraph', 'isgraph_l', 'isinf',
    'isinff', 'isinfl', 'islower', 'islower_l', 'isnan', 'isnanf',
    'isnanl', 'isprint', 'isprint_l', 'ispunct', 'ispunct_l',
    'isspace', 'isspace_l', 'isupper', 'isupper_l', 'isxdigit',
    'isxdigit_l', 'j0', 'j0f', 'j0l', 'j1', 'j1f', 'j1l', 'jn', 'jnf',
    'jnl', 'jrand48', 'jrand48_r', 'key_t', 'kill', 'killpg', 'l64a',
    'labs', 'lchmod', 'lchown', 'lcong48', 'lcong48_r', 'ldexp',
    'ldexpf', 'ldexpl', 'ldiv', 'ldiv_t', 'lgamma', 'lgamma_r',
    'lgammaf', 'lgammaf_r', 'lgammal', 'lgammal_r', 'link', 'linkat',
    'listen', 'llabs', 'lldiv', 'lldiv_t', 'llrint', 'llrintf',
    'llrintl', 'llround', 'llroundf', 'llroundl', 'locale_t', 'lockf',
    'loff_t', 'log', 'log10', 'log10f', 'log10l', 'log1p', 'log1pf',
    'log1pl', 'log2', 'log2f', 'log2l', 'logb', 'logbf', 'logbl',
    'logf', 'logl', 'lrand48', 'lrand48_r', 'lrint', 'lrintf',
    'lrintl', 'lround', 'lroundf', 'lroundl', 'ls_append', 'ls_clone',
    'ls_del_n', 'ls_delete', 'ls_delete_data', 'ls_destroy',
    'ls_free', 'ls_get_n', 'ls_get_top', 'ls_insert', 'ls_item_new',
    'ls_iter_init', 'ls_join', 'ls_merge_sort', 'ls_new', 'ls_newf',
    'ls_pop', 'ls_pop_head', 'ls_prepend', 'ls_reverse', 'ls_sort',
    'ls_split', 'ls_split_iter', 'ls_unlink', 'lseek', 'lstat',
    'lutimes', 'malloc', 'max_align_t', 'mblen', 'mbstowcs', 'mbtowc',
    'mcontext_t', 'memccpy', 'memchr', 'memcmp', 'memcpy', 'memmem',
    'memmove', 'mempcpy', 'memset', 'mkdir', 'mkdirat', 'mkdtemp',
    'mkfifo', 'mkfifoat', 'mknod', 'mknodat', 'mkstemp', 'mkstemps',
    'mktemp', 'mode_t', 'modf', 'modff', 'modfl', 'mrand48',
    'mrand48_r', 'nan', 'nanf', 'nanl', 'nearbyint', 'nearbyintf',
    'nearbyintl', 'nextafter', 'nextafterf', 'nextafterl',
    'nexttoward', 'nexttowardf', 'nexttowardl', 'nfds_t', 'nice',
    'nlink_t', 'nrand48', 'nrand48_r', 'ntohl', 'ntohs', 'off_t',
    'on_exit', 'open', 'open_memstream', 'openat', 'opendir',
    'optarg', 'opterr', 'optind', 'optopt', 'pathconf', 'pause',
    'pclose', 'perror', 'pid_t', 'pipe', 'poll', 'popen',
    'posix_fadvise', 'posix_fallocate', 'posix_memalign', 'pow',
    'powf', 'powl', 'pread', 'printf', 'profil', 'pselect',
    'psiginfo', 'psignal', 'pthread_attr_t', 'pthread_barrier_t',
    'pthread_barrierattr_t', 'pthread_cond_t', 'pthread_condattr_t',
    'pthread_key_t', 'pthread_kill', 'pthread_mutex_t',
    'pthread_mutexattr_t', 'pthread_once_t', 'pthread_rwlock_t',
    'pthread_rwlockattr_t', 'pthread_sigmask', 'pthread_spinlock_t',
    'pthread_t', 'ptrdiff_t', 'putc', 'putc_unlocked', 'putchar',
    'putchar_unlocked', 'putenv', 'puts', 'putw', 'pwrite', 'qecvt',
    'qecvt_r', 'qfcvt', 'qfcvt_r', 'qgcvt', 'qsort', 'quad_t',
    'quick_exit', 'r2pipe_close', 'r2pipe_cmd', 'r2pipe_cmdf',
    'r2pipe_open', 'r2pipe_open_corebind', 'r2pipe_open_dl',
    'r2pipe_read', 'r2pipe_write', 'r_list_add_sorted',
    'r_list_append', 'r_list_clone', 'r_list_contains',
    'r_list_del_n', 'r_list_delete', 'r_list_delete_data',
    'r_list_find', 'r_list_first', 'r_list_free', 'r_list_get_bottom',
    'r_list_get_n', 'r_list_get_top', 'r_list_init', 'r_list_insert',
    'r_list_insertion_sort', 'r_list_item_new',
    'r_list_iter_get_data', 'r_list_iter_get_next',
    'r_list_iter_get_prev', 'r_list_iter_init', 'r_list_iter_length',
    'r_list_iter_to_top', 'r_list_join', 'r_list_last',
    'r_list_length', 'r_list_merge_sort', 'r_list_new', 'r_list_newf',
    'r_list_pop', 'r_list_pop_head', 'r_list_prepend', 'r_list_purge',
    'r_list_reverse', 'r_list_set_n', 'r_list_sort', 'r_list_split',
    'r_list_split_iter', 'r_list_to_str', 'r_list_uniq',
    'r_list_uniq_inplace', 'r_new_copy', 'r_read_at_be16',
    'r_read_at_be32', 'r_read_at_be64', 'r_read_at_be8',
    'r_read_at_ble16', 'r_read_at_ble32', 'r_read_at_ble64',
    'r_read_at_ble8', 'r_read_at_le16', 'r_read_at_le32',
    'r_read_at_le64', 'r_read_at_le8', 'r_read_at_me16',
    'r_read_at_me32', 'r_read_at_me64', 'r_read_at_me8',
    'r_read_be16', 'r_read_be32', 'r_read_be64', 'r_read_be8',
    'r_read_ble', 'r_read_ble16', 'r_read_ble32', 'r_read_ble64',
    'r_read_ble8', 'r_read_le16', 'r_read_le32', 'r_read_le64',
    'r_read_le8', 'r_read_me16', 'r_read_me32', 'r_read_me64',
    'r_read_me8', 'r_run_call1', 'r_run_call10', 'r_run_call2',
    'r_run_call3', 'r_run_call4', 'r_run_call5', 'r_run_call6',
    'r_run_call7', 'r_run_call8', 'r_run_call9', 'r_run_config_env',
    'r_run_free', 'r_run_get_environ_profile', 'r_run_help',
    'r_run_new', 'r_run_parse', 'r_run_parsefile', 'r_run_parseline',
    'r_run_reset', 'r_run_start', 'r_socket_accept',
    'r_socket_accept_timeout', 'r_socket_block_time',
    'r_socket_close', 'r_socket_close_fd', 'r_socket_connect',
    'r_socket_connect_serial', 'r_socket_flush', 'r_socket_free',
    'r_socket_gets', 'r_socket_http_accept', 'r_socket_http_close',
    'r_socket_http_free', 'r_socket_http_get',
    'r_socket_http_handle_upload', 'r_socket_http_post',
    'r_socket_http_response', 'r_socket_http_server_set_breaked',
    'r_socket_is_connected', 'r_socket_listen', 'r_socket_new',
    'r_socket_new_from_fd', 'r_socket_port_by_name',
    'r_socket_printf', 'r_socket_proc_close', 'r_socket_proc_gets',
    'r_socket_proc_open', 'r_socket_proc_printf',
    'r_socket_proc_read', 'r_socket_proc_ready',
    'r_socket_proc_write', 'r_socket_puts',
    'r_socket_rap_client_command', 'r_socket_rap_client_open',
    'r_socket_rap_client_read', 'r_socket_rap_client_seek',
    'r_socket_rap_client_write', 'r_socket_rap_server_accept',
    'r_socket_rap_server_continue', 'r_socket_rap_server_create',
    'r_socket_rap_server_free', 'r_socket_rap_server_listen',
    'r_socket_rap_server_new', 'r_socket_read', 'r_socket_read_block',
    'r_socket_ready', 'r_socket_slurp', 'r_socket_spawn',
    'r_socket_to_string', 'r_socket_version', 'r_socket_write',
    'r_swap_st16', 'r_swap_st32', 'r_swap_st64', 'r_swap_ut16',
    'r_swap_ut32', 'r_swap_ut64', 'r_write_at_be16',
    'r_write_at_be32', 'r_write_at_be64', 'r_write_at_be8',
    'r_write_at_ble8', 'r_write_at_le16', 'r_write_at_le32',
    'r_write_at_le64', 'r_write_at_le8', 'r_write_at_me16',
    'r_write_at_me32', 'r_write_at_me64', 'r_write_at_me8',
    'r_write_be16', 'r_write_be24', 'r_write_be32', 'r_write_be64',
    'r_write_be8', 'r_write_ble', 'r_write_ble16', 'r_write_ble24',
    'r_write_ble32', 'r_write_ble64', 'r_write_ble8', 'r_write_le16',
    'r_write_le24', 'r_write_le32', 'r_write_le64', 'r_write_le8',
    'r_write_me16', 'r_write_me32', 'r_write_me64', 'r_write_me8',
    'raise_', 'rand', 'rand_r', 'random', 'random_r', 'rap_close',
    'rap_cmd', 'rap_cmdf', 'rap_open', 'rap_open_corebind',
    'rap_read', 'rap_server_close', 'rap_server_cmd',
    'rap_server_open', 'rap_server_read', 'rap_server_seek',
    'rap_server_write', 'rap_write', 'rcmd', 'rcmd_af', 'read',
    'readdir', 'readdir_r', 'readlink', 'readlinkat', 'realloc',
    'reallocarray', 'realpath', 'recv', 'recvfrom', 'recvmsg',
    'register_t', 'remainder', 'remainderf', 'remainderl', 'remove',
    'remquo', 'remquof', 'remquol', 'rename', 'renameat', 'revoke',
    'rewind', 'rewinddir', 'rexec', 'rexec_af', 'rindex', 'rint',
    'rintf', 'rintl', 'rmdir', 'round', 'roundf', 'roundl', 'rpmatch',
    'rresvport', 'rresvport_af', 'ruserok', 'ruserok_af',
    'sa_family_t', 'sbrk', 'scalb', 'scalbf', 'scalbl', 'scalbln',
    'scalblnf', 'scalblnl', 'scalbn', 'scalbnf', 'scalbnl', 'scandir',
    'scanf', 'sdb_add', 'sdb_alen', 'sdb_alen_ignore_empty',
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
    'sdbkv_value', 'sdbkv_value_len', 'seed48', 'seed48_r',
    'seek_set', 'seekdir', 'select', 'send', 'sendmsg', 'sendto',
    'setbuf', 'setbuffer', 'setdomainname', 'setegid', 'setenv',
    'seteuid', 'setgid', 'sethostent', 'sethostid', 'sethostname',
    'setitimer', 'setlinebuf', 'setlogin', 'setnetent', 'setnetgrent',
    'setpgid', 'setpgrp', 'setprotoent', 'setregid', 'setreuid',
    'setrpcent', 'setservent', 'setsid', 'setsockopt', 'setstate',
    'setstate_r', 'settimeofday', 'setuid', 'setusershell', 'setvbuf',
    'shutdown', 'sig_atomic_t', 'sig_t', 'sigaction', 'sigaddset',
    'sigaltstack', 'sigblock', 'sigdelset', 'sigemptyset',
    'sigevent_t', 'sigfillset', 'siggetmask', 'siginfo_t',
    'siginterrupt', 'sigismember', 'signal', 'signgam', 'significand',
    'significandf', 'significandl', 'sigpending', 'sigprocmask',
    'sigqueue', 'sigreturn', 'sigset_t', 'sigsetmask', 'sigstack',
    'sigsuspend', 'sigtimedwait', 'sigval_t', 'sigwait',
    'sigwaitinfo', 'sin', 'sinf', 'sinh', 'sinhf', 'sinhl', 'sinl',
    'size_t', 'sleep', 'snprintf', 'sockatmark', 'socket',
    'socketpair', 'socklen_t', 'sprintf', 'sqrt', 'sqrtf', 'sqrtl',
    'srand', 'srand48', 'srand48_r', 'srandom', 'srandom_r', 'sscanf',
    'ssignal', 'ssize_t', 'stack_t', 'stat', 'stderr', 'stdin',
    'stdout', 'stpcpy', 'stpncpy', 'strcasecmp', 'strcasecmp_l',
    'strcasestr', 'strcat', 'strchr', 'strchrnul', 'strcmp',
    'strcoll', 'strcoll_l', 'strcpy', 'strcspn', 'strdup', 'strerror',
    'strerror_l', 'strerror_r', 'strlcat', 'strlcpy', 'strlen',
    'strncasecmp', 'strncasecmp_l', 'strncat', 'strncmp', 'strncpy',
    'strndup', 'strnlen', 'strpbrk', 'strrchr', 'strsep', 'strsignal',
    'strspn', 'strstr', 'strtod', 'strtof', 'strtoimax', 'strtok',
    'strtok_r', 'strtol', 'strtold', 'strtoll', 'strtoq', 'strtoul',
    'strtoull', 'strtoumax', 'strtouq', 'struct_R2Pipe',
    'struct_SdbJsonString', 'struct__G_fpos64_t', 'struct__G_fpos_t',
    'struct__IO_FILE', 'struct__IO_codecvt',
    'struct__IO_cookie_io_functions_t', 'struct__IO_marker',
    'struct__IO_wide_data', 'struct___atomic_wide_counter___value32',
    'struct___dirstream', 'struct___fsid_t', 'struct___kernel_fd_set',
    'struct___kernel_fsid_t', 'struct___locale_data',
    'struct___locale_struct', 'struct___mbstate_t',
    'struct___once_flag', 'struct___pthread_cond_s',
    'struct___pthread_internal_list',
    'struct___pthread_internal_slist', 'struct___pthread_mutex_s',
    'struct___pthread_rwlock_arch_t', 'struct___sigset_t',
    'struct___va_list_tag', 'struct__fpreg', 'struct__fpstate',
    'struct__fpx_sw_bytes', 'struct__fpxreg', 'struct__libc_fpstate',
    'struct__libc_fpxreg', 'struct__libc_xmmreg', 'struct__ut128',
    'struct__ut256', 'struct__ut80', 'struct__ut96', 'struct__utX',
    'struct__xmmreg', 'struct__xsave_hdr', 'struct__xstate',
    'struct__ymmh_state', 'struct_addrinfo', 'struct_buffer',
    'struct_cdb', 'struct_cdb_hp', 'struct_cdb_hplist',
    'struct_cdb_make', 'struct_cmsghdr', 'struct_dict',
    'struct_dictkv', 'struct_dirent', 'struct_div_t',
    'struct_drand48_data', 'struct_fd_set', 'struct_flock',
    'struct_group_filter', 'struct_group_req',
    'struct_group_source_req', 'struct_hostent',
    'struct_ht_pp_bucket_t', 'struct_ht_pp_kv',
    'struct_ht_pp_options_t', 'struct_ht_pp_t', 'struct_imaxdiv_t',
    'struct_in6_addr', 'struct_in_addr', 'struct_in_pktinfo',
    'struct_iovec', 'struct_ip_mreq', 'struct_ip_mreq_source',
    'struct_ip_mreqn', 'struct_ip_msfilter', 'struct_ip_opts',
    'struct_ipv6_mreq', 'struct_itimerval', 'struct_ldiv_t',
    'struct_linger', 'struct_lldiv_t', 'struct_ls_iter_t',
    'struct_ls_t', 'struct_max_align_t', 'struct_mcontext_t',
    'struct_msghdr', 'struct_netent', 'struct_osockaddr',
    'struct_pollfd', 'struct_protoent', 'struct_r_core_bind_t',
    'struct_r_list_iter_t', 'struct_r_list_range_t',
    'struct_r_list_t', 'struct_r_run_profile_t',
    'struct_r_socket_http_options', 'struct_r_socket_http_request',
    'struct_r_socket_proc_t', 'struct_r_socket_rap_server_t',
    'struct_r_socket_t', 'struct_random_data', 'struct_rpcent',
    'struct_rusage', 'struct_sdb_diff_t', 'struct_sdb_gperf_t',
    'struct_sdb_kv', 'struct_sdb_ns_t', 'struct_sdb_t',
    'struct_servent', 'struct_sigaction', 'struct_sigcontext',
    'struct_sigevent', 'struct_sigevent_0__sigev_thread',
    'struct_siginfo_t', 'struct_siginfo_t_0_4_0__addr_bnd',
    'struct_siginfo_t_0__kill', 'struct_siginfo_t_0__rt',
    'struct_siginfo_t_0__sigchld', 'struct_siginfo_t_0__sigfault',
    'struct_siginfo_t_0__sigpoll', 'struct_siginfo_t_0__sigsys',
    'struct_siginfo_t_0__timer', 'struct_sigstack', 'struct_sockaddr',
    'struct_sockaddr_in', 'struct_sockaddr_in6',
    'struct_sockaddr_storage', 'struct_sockaddr_un', 'struct_stack_t',
    'struct_stat', 'struct_tcp_cookie_transactions',
    'struct_tcp_info', 'struct_tcp_md5sig', 'struct_tcp_repair_opt',
    'struct_tcp_repair_window', 'struct_tcp_zerocopy_receive',
    'struct_tcphdr', 'struct_tcphdr_0_0', 'struct_tcphdr_0_1',
    'struct_timespec', 'struct_timeval', 'struct_timezone',
    'struct_ucontext_t', 'strxfrm', 'strxfrm_l', 'suseconds_t',
    'symlink', 'symlinkat', 'sync', 'syscall', 'sysconf', 'system',
    'tan', 'tanf', 'tanh', 'tanhf', 'tanhl', 'tanl', 'tcgetpgrp',
    'tcp_ca_state', 'tcp_seq', 'tcsetpgrp', 'telldir', 'tempnam',
    'tgamma', 'tgammaf', 'tgammal', 'time_t', 'timer_t', 'tmpfile',
    'tmpnam', 'tmpnam_r', 'toascii', 'tolower', 'tolower_l',
    'toupper', 'toupper_l', 'trunc', 'truncate', 'truncf', 'truncl',
    'ttyname', 'ttyname_r', 'ttyslot', 'u_char', 'u_int', 'u_int16_t',
    'u_int32_t', 'u_int64_t', 'u_int8_t', 'u_long', 'u_quad_t',
    'u_short', 'ualarm', 'ucontext_t', 'uid_t', 'uint', 'uint16_t',
    'uint32_t', 'uint64_t', 'uint8_t', 'uint_fast16_t',
    'uint_fast32_t', 'uint_fast64_t', 'uint_fast8_t',
    'uint_least16_t', 'uint_least32_t', 'uint_least64_t',
    'uint_least8_t', 'uintmax_t', 'uintptr_t', 'ulong', 'umask',
    'ungetc', 'union___atomic_wide_counter',
    'union___mbstate_t___value', 'union_in6_addr___in6_u',
    'union_pthread_attr_t', 'union_pthread_barrier_t',
    'union_pthread_barrierattr_t', 'union_pthread_cond_t',
    'union_pthread_condattr_t', 'union_pthread_mutex_t',
    'union_pthread_mutexattr_t', 'union_pthread_rwlock_t',
    'union_pthread_rwlockattr_t',
    'union_sigaction___sigaction_handler', 'union_sigcontext_0',
    'union_sigevent__sigev_un', 'union_siginfo_t_0_4__bounds',
    'union_siginfo_t__sifields', 'union_sigval', 'union_tcphdr_0',
    'union_utAny', 'unlink', 'unlinkat', 'unsetenv', 'useconds_t',
    'ushort', 'usleep', 'ust16', 'ust32', 'ust64', 'ut128', 'ut256',
    'ut32_pack', 'ut32_pack_big', 'ut32_unpack', 'ut80', 'ut96',
    'utAny', 'utX', 'utimensat', 'utimes', 'uut16', 'uut32', 'uut64',
    'va_list', 'valloc', 'vasprintf', 'vdprintf', 'vfork', 'vfprintf',
    'vfscanf', 'vhangup', 'vprintf', 'vscanf', 'vsnprintf',
    'vsprintf', 'vsscanf', 'wait', 'wait3', 'wait4', 'waitid',
    'waitpid', 'wchar_t', 'wcstoimax', 'wcstombs', 'wcstoumax',
    'wctomb', 'write', 'y0', 'y0f', 'y0l', 'y1', 'y1f', 'y1l', 'yn',
    'ynf', 'ynl']
