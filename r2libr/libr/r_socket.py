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


r_socket_version = _libr_socket.r_socket_version
r_socket_version.restype = ctypes.POINTER(ctypes.c_char)
r_socket_version.argtypes = []
class struct_c__SA_R2Pipe(Structure):
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

struct_c__SA_R2Pipe._pack_ = 1 # source:False
struct_c__SA_R2Pipe._fields_ = [
    ('child', ctypes.c_int32),
    ('input', ctypes.c_int32 * 2),
    ('output', ctypes.c_int32 * 2),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('coreb', struct_r_core_bind_t),
]

R2Pipe = struct_c__SA_R2Pipe
class struct_r_socket_t(Structure):
    pass

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

RSocket = struct_r_socket_t
class struct_r_socket_http_options(Structure):
    pass

class struct_r_list_t(Structure):
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

RSocketHTTPOptions = struct_r_socket_http_options
r_socket_new_from_fd = _libr_socket.r_socket_new_from_fd
r_socket_new_from_fd.restype = ctypes.POINTER(struct_r_socket_t)
r_socket_new_from_fd.argtypes = [ctypes.c_int32]
r_socket_new = _libr_socket.r_socket_new
r_socket_new.restype = ctypes.POINTER(struct_r_socket_t)
r_socket_new.argtypes = [ctypes.c_bool]
r_socket_spawn = _libr_socket.r_socket_spawn
r_socket_spawn.restype = ctypes.c_bool
r_socket_spawn.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(ctypes.c_char), ctypes.c_uint32]
r_socket_connect = _libr_socket.r_socket_connect
r_socket_connect.restype = ctypes.c_bool
r_socket_connect.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_uint32]
r_socket_connect_serial = _libr_socket.r_socket_connect_serial
r_socket_connect_serial.restype = ctypes.c_int32
r_socket_connect_serial.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_int32]
r_socket_listen = _libr_socket.r_socket_listen
r_socket_listen.restype = ctypes.c_bool
r_socket_listen.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
r_socket_port_by_name = _libr_socket.r_socket_port_by_name
r_socket_port_by_name.restype = ctypes.c_int32
r_socket_port_by_name.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_socket_close_fd = _libr_socket.r_socket_close_fd
r_socket_close_fd.restype = ctypes.c_int32
r_socket_close_fd.argtypes = [ctypes.POINTER(struct_r_socket_t)]
r_socket_close = _libr_socket.r_socket_close
r_socket_close.restype = ctypes.c_int32
r_socket_close.argtypes = [ctypes.POINTER(struct_r_socket_t)]
r_socket_free = _libr_socket.r_socket_free
r_socket_free.restype = ctypes.c_int32
r_socket_free.argtypes = [ctypes.POINTER(struct_r_socket_t)]
r_socket_accept = _libr_socket.r_socket_accept
r_socket_accept.restype = ctypes.POINTER(struct_r_socket_t)
r_socket_accept.argtypes = [ctypes.POINTER(struct_r_socket_t)]
r_socket_accept_timeout = _libr_socket.r_socket_accept_timeout
r_socket_accept_timeout.restype = ctypes.POINTER(struct_r_socket_t)
r_socket_accept_timeout.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.c_uint32]
r_socket_block_time = _libr_socket.r_socket_block_time
r_socket_block_time.restype = ctypes.c_bool
r_socket_block_time.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.c_bool, ctypes.c_int32, ctypes.c_int32]
r_socket_flush = _libr_socket.r_socket_flush
r_socket_flush.restype = ctypes.c_int32
r_socket_flush.argtypes = [ctypes.POINTER(struct_r_socket_t)]
r_socket_ready = _libr_socket.r_socket_ready
r_socket_ready.restype = ctypes.c_int32
r_socket_ready.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.c_int32, ctypes.c_int32]
r_socket_to_string = _libr_socket.r_socket_to_string
r_socket_to_string.restype = ctypes.POINTER(ctypes.c_char)
r_socket_to_string.argtypes = [ctypes.POINTER(struct_r_socket_t)]
r_socket_write = _libr_socket.r_socket_write
r_socket_write.restype = ctypes.c_int32
r_socket_write.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(None), ctypes.c_int32]
r_socket_puts = _libr_socket.r_socket_puts
r_socket_puts.restype = ctypes.c_int32
r_socket_puts.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(ctypes.c_char)]
r_socket_printf = _libr_socket.r_socket_printf
r_socket_printf.restype = None
r_socket_printf.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(ctypes.c_char)]
r_socket_read = _libr_socket.r_socket_read
r_socket_read.restype = ctypes.c_int32
r_socket_read.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_socket_read_block = _libr_socket.r_socket_read_block
r_socket_read_block.restype = ctypes.c_int32
r_socket_read_block.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_socket_gets = _libr_socket.r_socket_gets
r_socket_gets.restype = ctypes.c_int32
r_socket_gets.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_socket_slurp = _libr_socket.r_socket_slurp
r_socket_slurp.restype = ctypes.POINTER(ctypes.c_ubyte)
r_socket_slurp.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(ctypes.c_int32)]
r_socket_is_connected = _libr_socket.r_socket_is_connected
r_socket_is_connected.restype = ctypes.c_bool
r_socket_is_connected.argtypes = [ctypes.POINTER(struct_r_socket_t)]
class struct_r_socket_proc_t(Structure):
    pass

struct_r_socket_proc_t._pack_ = 1 # source:False
struct_r_socket_proc_t._fields_ = [
    ('fd0', ctypes.c_int32 * 2),
    ('fd1', ctypes.c_int32 * 2),
    ('pid', ctypes.c_int32),
]

RSocketProc = struct_r_socket_proc_t
r_socket_proc_open = _libr_socket.r_socket_proc_open
r_socket_proc_open.restype = ctypes.POINTER(struct_r_socket_proc_t)
r_socket_proc_open.argtypes = [ctypes.POINTER(ctypes.c_char) * 0]
r_socket_proc_close = _libr_socket.r_socket_proc_close
r_socket_proc_close.restype = ctypes.c_int32
r_socket_proc_close.argtypes = [ctypes.POINTER(struct_r_socket_proc_t)]
r_socket_proc_read = _libr_socket.r_socket_proc_read
r_socket_proc_read.restype = ctypes.c_int32
r_socket_proc_read.argtypes = [ctypes.POINTER(struct_r_socket_proc_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_socket_proc_gets = _libr_socket.r_socket_proc_gets
r_socket_proc_gets.restype = ctypes.c_int32
r_socket_proc_gets.argtypes = [ctypes.POINTER(struct_r_socket_proc_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_socket_proc_write = _libr_socket.r_socket_proc_write
r_socket_proc_write.restype = ctypes.c_int32
r_socket_proc_write.argtypes = [ctypes.POINTER(struct_r_socket_proc_t), ctypes.POINTER(None), ctypes.c_int32]
r_socket_proc_printf = _libr_socket.r_socket_proc_printf
r_socket_proc_printf.restype = None
r_socket_proc_printf.argtypes = [ctypes.POINTER(struct_r_socket_proc_t), ctypes.POINTER(ctypes.c_char)]
r_socket_proc_ready = _libr_socket.r_socket_proc_ready
r_socket_proc_ready.restype = ctypes.c_int32
r_socket_proc_ready.argtypes = [ctypes.POINTER(struct_r_socket_proc_t), ctypes.c_int32, ctypes.c_int32]
r_socket_http_get = _libr_socket.r_socket_http_get
r_socket_http_get.restype = ctypes.POINTER(ctypes.c_char)
r_socket_http_get.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32)]
r_socket_http_post = _libr_socket.r_socket_http_post
r_socket_http_post.restype = ctypes.POINTER(ctypes.c_char)
r_socket_http_post.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32)]
r_socket_http_server_set_breaked = _libr_socket.r_socket_http_server_set_breaked
r_socket_http_server_set_breaked.restype = None
r_socket_http_server_set_breaked.argtypes = [ctypes.POINTER(ctypes.c_bool)]
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
r_socket_http_accept = _libr_socket.r_socket_http_accept
r_socket_http_accept.restype = ctypes.POINTER(struct_r_socket_http_request)
r_socket_http_accept.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(struct_r_socket_http_options)]
r_socket_http_response = _libr_socket.r_socket_http_response
r_socket_http_response.restype = None
r_socket_http_response.argtypes = [ctypes.POINTER(struct_r_socket_http_request), ctypes.c_int32, ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.POINTER(ctypes.c_char)]
r_socket_http_close = _libr_socket.r_socket_http_close
r_socket_http_close.restype = None
r_socket_http_close.argtypes = [ctypes.POINTER(struct_r_socket_http_request)]
r_socket_http_handle_upload = _libr_socket.r_socket_http_handle_upload
r_socket_http_handle_upload.restype = ctypes.POINTER(ctypes.c_ubyte)
r_socket_http_handle_upload.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32, ctypes.POINTER(ctypes.c_int32)]
r_socket_http_free = _libr_socket.r_socket_http_free
r_socket_http_free.restype = None
r_socket_http_free.argtypes = [ctypes.POINTER(struct_r_socket_http_request)]
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
r_socket_rap_server_new = _libr_socket.r_socket_rap_server_new
r_socket_rap_server_new.restype = ctypes.POINTER(struct_r_socket_rap_server_t)
r_socket_rap_server_new.argtypes = [ctypes.c_bool, ctypes.POINTER(ctypes.c_char)]
r_socket_rap_server_create = _libr_socket.r_socket_rap_server_create
r_socket_rap_server_create.restype = ctypes.POINTER(struct_r_socket_rap_server_t)
r_socket_rap_server_create.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_socket_rap_server_free = _libr_socket.r_socket_rap_server_free
r_socket_rap_server_free.restype = None
r_socket_rap_server_free.argtypes = [ctypes.POINTER(struct_r_socket_rap_server_t)]
r_socket_rap_server_listen = _libr_socket.r_socket_rap_server_listen
r_socket_rap_server_listen.restype = ctypes.c_bool
r_socket_rap_server_listen.argtypes = [ctypes.POINTER(struct_r_socket_rap_server_t), ctypes.POINTER(ctypes.c_char)]
r_socket_rap_server_accept = _libr_socket.r_socket_rap_server_accept
r_socket_rap_server_accept.restype = ctypes.POINTER(struct_r_socket_t)
r_socket_rap_server_accept.argtypes = [ctypes.POINTER(struct_r_socket_rap_server_t)]
r_socket_rap_server_continue = _libr_socket.r_socket_rap_server_continue
r_socket_rap_server_continue.restype = ctypes.c_bool
r_socket_rap_server_continue.argtypes = [ctypes.POINTER(struct_r_socket_rap_server_t)]
r_socket_rap_client_open = _libr_socket.r_socket_rap_client_open
r_socket_rap_client_open.restype = ctypes.c_int32
r_socket_rap_client_open.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(ctypes.c_char), ctypes.c_int32]
r_socket_rap_client_command = _libr_socket.r_socket_rap_client_command
r_socket_rap_client_command.restype = ctypes.POINTER(ctypes.c_char)
r_socket_rap_client_command.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(struct_r_core_bind_t)]
r_socket_rap_client_write = _libr_socket.r_socket_rap_client_write
r_socket_rap_client_write.restype = ctypes.c_int32
r_socket_rap_client_write.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_socket_rap_client_read = _libr_socket.r_socket_rap_client_read
r_socket_rap_client_read.restype = ctypes.c_int32
r_socket_rap_client_read.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int32]
r_socket_rap_client_seek = _libr_socket.r_socket_rap_client_seek
r_socket_rap_client_seek.restype = ctypes.c_int32
r_socket_rap_client_seek.argtypes = [ctypes.POINTER(struct_r_socket_t), ctypes.c_uint64, ctypes.c_int32]
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
    ('_preload', ctypes.POINTER(ctypes.c_char)),
    ('_bits', ctypes.c_int32),
    ('_pid', ctypes.c_int32),
    ('_pidfile', ctypes.POINTER(ctypes.c_char)),
    ('_r2preload', ctypes.c_int32),
    ('_docore', ctypes.c_int32),
    ('_dofork', ctypes.c_int32),
    ('_dodebug', ctypes.c_int32),
    ('_aslr', ctypes.c_int32),
    ('_maxstack', ctypes.c_int32),
    ('_maxproc', ctypes.c_int32),
    ('_maxfd', ctypes.c_int32),
    ('_r2sleep', ctypes.c_int32),
    ('_execve', ctypes.c_int32),
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
r_run_new = _libr_socket.r_run_new
r_run_new.restype = ctypes.POINTER(struct_r_run_profile_t)
r_run_new.argtypes = [ctypes.POINTER(ctypes.c_char)]
r_run_parse = _libr_socket.r_run_parse
r_run_parse.restype = ctypes.c_bool
r_run_parse.argtypes = [ctypes.POINTER(struct_r_run_profile_t), ctypes.POINTER(ctypes.c_char)]
r_run_free = _libr_socket.r_run_free
r_run_free.restype = None
r_run_free.argtypes = [ctypes.POINTER(struct_r_run_profile_t)]
r_run_parseline = _libr_socket.r_run_parseline
r_run_parseline.restype = ctypes.c_bool
r_run_parseline.argtypes = [ctypes.POINTER(struct_r_run_profile_t), ctypes.POINTER(ctypes.c_char)]
r_run_help = _libr_socket.r_run_help
r_run_help.restype = ctypes.POINTER(ctypes.c_char)
r_run_help.argtypes = []
r_run_config_env = _libr_socket.r_run_config_env
r_run_config_env.restype = ctypes.c_int32
r_run_config_env.argtypes = [ctypes.POINTER(struct_r_run_profile_t)]
r_run_start = _libr_socket.r_run_start
r_run_start.restype = ctypes.c_int32
r_run_start.argtypes = [ctypes.POINTER(struct_r_run_profile_t)]
r_run_reset = _libr_socket.r_run_reset
r_run_reset.restype = None
r_run_reset.argtypes = [ctypes.POINTER(struct_r_run_profile_t)]
r_run_parsefile = _libr_socket.r_run_parsefile
r_run_parsefile.restype = ctypes.c_bool
r_run_parsefile.argtypes = [ctypes.POINTER(struct_r_run_profile_t), ctypes.POINTER(ctypes.c_char)]
r_run_get_environ_profile = _libr_socket.r_run_get_environ_profile
r_run_get_environ_profile.restype = ctypes.POINTER(ctypes.c_char)
r_run_get_environ_profile.argtypes = [ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
rap_open = _libraries['FIXME_STUB'].rap_open
rap_open.restype = ctypes.POINTER(struct_c__SA_R2Pipe)
rap_open.argtypes = [ctypes.POINTER(ctypes.c_char)]
rap_open_corebind = _libraries['FIXME_STUB'].rap_open_corebind
rap_open_corebind.restype = ctypes.POINTER(struct_c__SA_R2Pipe)
rap_open_corebind.argtypes = [ctypes.POINTER(struct_r_core_bind_t)]
rap_close = _libraries['FIXME_STUB'].rap_close
rap_close.restype = ctypes.c_int32
rap_close.argtypes = [ctypes.POINTER(struct_c__SA_R2Pipe)]
rap_cmd = _libraries['FIXME_STUB'].rap_cmd
rap_cmd.restype = ctypes.POINTER(ctypes.c_char)
rap_cmd.argtypes = [ctypes.POINTER(struct_c__SA_R2Pipe), ctypes.POINTER(ctypes.c_char)]
rap_cmdf = _libraries['FIXME_STUB'].rap_cmdf
rap_cmdf.restype = ctypes.POINTER(ctypes.c_char)
rap_cmdf.argtypes = [ctypes.POINTER(struct_c__SA_R2Pipe), ctypes.POINTER(ctypes.c_char)]
rap_write = _libraries['FIXME_STUB'].rap_write
rap_write.restype = ctypes.c_int32
rap_write.argtypes = [ctypes.POINTER(struct_c__SA_R2Pipe), ctypes.POINTER(ctypes.c_char)]
rap_read = _libraries['FIXME_STUB'].rap_read
rap_read.restype = ctypes.POINTER(ctypes.c_char)
rap_read.argtypes = [ctypes.POINTER(struct_c__SA_R2Pipe)]
r2pipe_write = _libr_socket.r2pipe_write
r2pipe_write.restype = ctypes.c_int32
r2pipe_write.argtypes = [ctypes.POINTER(struct_c__SA_R2Pipe), ctypes.POINTER(ctypes.c_char)]
r2pipe_read = _libr_socket.r2pipe_read
r2pipe_read.restype = ctypes.POINTER(ctypes.c_char)
r2pipe_read.argtypes = [ctypes.POINTER(struct_c__SA_R2Pipe)]
r2pipe_close = _libr_socket.r2pipe_close
r2pipe_close.restype = ctypes.c_int32
r2pipe_close.argtypes = [ctypes.POINTER(struct_c__SA_R2Pipe)]
r2pipe_open_corebind = _libr_socket.r2pipe_open_corebind
r2pipe_open_corebind.restype = ctypes.POINTER(struct_c__SA_R2Pipe)
r2pipe_open_corebind.argtypes = [ctypes.POINTER(struct_r_core_bind_t)]
r2pipe_open = _libr_socket.r2pipe_open
r2pipe_open.restype = ctypes.POINTER(struct_c__SA_R2Pipe)
r2pipe_open.argtypes = [ctypes.POINTER(ctypes.c_char)]
r2pipe_open_dl = _libr_socket.r2pipe_open_dl
r2pipe_open_dl.restype = ctypes.POINTER(struct_c__SA_R2Pipe)
r2pipe_open_dl.argtypes = [ctypes.POINTER(ctypes.c_char)]
r2pipe_cmd = _libr_socket.r2pipe_cmd
r2pipe_cmd.restype = ctypes.POINTER(ctypes.c_char)
r2pipe_cmd.argtypes = [ctypes.POINTER(struct_c__SA_R2Pipe), ctypes.POINTER(ctypes.c_char)]
r2pipe_cmdf = _libr_socket.r2pipe_cmdf
r2pipe_cmdf.restype = ctypes.POINTER(ctypes.c_char)
r2pipe_cmdf.argtypes = [ctypes.POINTER(struct_c__SA_R2Pipe), ctypes.POINTER(ctypes.c_char)]
__all__ = \
    ['R2Pipe', 'RAP_PACKET_CLOSE', 'RAP_PACKET_CMD', 'RAP_PACKET_MAX',
    'RAP_PACKET_OPEN', 'RAP_PACKET_READ', 'RAP_PACKET_REPLY',
    'RAP_PACKET_SEEK', 'RAP_PACKET_WRITE', 'RRunProfile', 'RSocket',
    'RSocketHTTPOptions', 'RSocketHTTPRequest', 'RSocketProc',
    'RSocketRapServer', 'c__Ea_RAP_PACKET_OPEN', 'r2pipe_close',
    'r2pipe_cmd', 'r2pipe_cmdf', 'r2pipe_open',
    'r2pipe_open_corebind', 'r2pipe_open_dl', 'r2pipe_read',
    'r2pipe_write', 'r_run_config_env', 'r_run_free',
    'r_run_get_environ_profile', 'r_run_help', 'r_run_new',
    'r_run_parse', 'r_run_parsefile', 'r_run_parseline',
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
    'rap_close', 'rap_cmd', 'rap_cmdf', 'rap_open',
    'rap_open_corebind', 'rap_read', 'rap_server_close',
    'rap_server_cmd', 'rap_server_open', 'rap_server_read',
    'rap_server_seek', 'rap_server_write', 'rap_write',
    'struct_c__SA_R2Pipe', 'struct_in_addr', 'struct_r_core_bind_t',
    'struct_r_list_iter_t', 'struct_r_list_t',
    'struct_r_run_profile_t', 'struct_r_socket_http_options',
    'struct_r_socket_http_request', 'struct_r_socket_proc_t',
    'struct_r_socket_rap_server_t', 'struct_r_socket_t',
    'struct_sockaddr_in']
