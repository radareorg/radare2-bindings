/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> */

namespace Radare {
	[Compact]
	[CCode (cheader_filename="r_io.h", cname="RIO", free_function="r_io_free", cprefix="r_io_")]
	public class RIO {
		// public Desc desc;
		// public bool cached;
		// public bool cached_read;
		// public bool enforce_rwx;
		// public bool enforce_seek;
		public uint64 off;
		public bool debug;

		[CCode (cprefix="R_IO_")]
		public enum Perm {
			READ = 0,
			WRITE = 1,
			EXEC = 2,
		}

		[CCode (cprefix="R_IO_SEEK_")]
		public enum Seek {
			SET = 0,
			CUR = 1,
			END = 2,
		}
		public uint64 va;

		public RIO();
		public void free();
		public bool set_write_mask(uint8 *buf, int len);

		//public uint64 off;
		/**
		 * Open a file using an uri specifying flags and mode
		 *
		 * uri: URI with path to file
		 * flags: See Radare.Io.Flags
		 * mode: ...
		 */
/*
		public RIO.Desc open(string uri, int flags, int mode);
		public RIO.Desc open_as(string urihandler, string path, int flags, int mode);
		public int redirect(string uri);
		public void use_fd(int fd);
		public void use_desc(RIO.Desc desc);
		public int read(out uint8 *buf, int len);
		public int read_at(uint64 addr, uint8 *buf, int len);
		public RBuffer *read_buf(uint64 addr, int len);
		public int write(uint8 *buf, int len);
		public int write_at(uint64 addr, uint8 *buf, int len);
		public uint64 seek(uint64 addr, int whence);
		public int system(string cmd);
		public int close(RIO.Desc fd);
		public uint64 size();
*/

/*
		public void cache_commit (uint64 from, uint64 to);
		public void cache_init ();
		public int cache_list (bool rad);
		public void cache_reset (bool set);
		public void cache_enable(bool rd, bool wr);
		public void cache_write(uint64 addr, ref uint8 *buf, int len);
		public void cache_read(uint64 addr, ref uint8 *buf, int len);
*/

		/* undo */
		// TODO: Implement seek and write undo apis..they must be unified..

		[Compact]
		[CCode(cname="RIOUndos", free_function="")]
		public class Undos {
			uint64 off;
			int cursor;
		}
		public bool undo_init();
		public void undo_enable(bool set, bool write);

		public Undos sundo(uint64 offset);
		public Undos sundo_redo();
		public void sundo_push(uint64 off, int cursor);
		public void sundo_reset();
		public void sundo_list(int mode);

		[Compact]
		[CCode(cname="RIOUndoWrite", free_function="")]
		public class UndoWrite {
			int set;
			uint64 off;
			uint8 *o;   /* old data */
			uint8 *n;   /* new data */
			int len;    /* length */
		}

		public void wundo_new(uint64 off, uint8 *data, int len);
		public void wundo_clear();
		public int wundo_size();
		public void wundo_list();
		public int wundo_apply(UndoWrite *u, int set);
		public void wundo_apply_all(int set);
		public int wundo_set(int n, int set);

/*
		[Compact]
		[CCode(cname="RIOUndo")]
		public class Undo {
			bool s_enable;
			bool w_enable;
			bool w_init;
			int idx;
			int limit;
		}
*/
		//public uint64 undo_seek();
		//public void undo_redo();
		//public void undo_push();

		/* plugin */
		[Compact]
		[CCode (cname="RIOPlugin", cprefix="r_io_plugin_", free_function="")]
		public class Plugin {
			string name;
			string desc;
			// TODO: lot of missing stuff here :)
		}

		/* TODO: make them methods of Plugin class ? */
		public bool plugin_add(RIO.Plugin plugin);
		//public int plugin_generate();
		public void plugin_list();

/*
		[CCode (cname="RIOMap", cprefix="r_io_map_", free_function="", unref_function="")]
		public class Map {
			int fd;
			int flags;
			uint64 delta;
			uint64 from;
			uint64 to;
		}
		public Map map_resolve(int fd);
		public bool map_add(int fd, int flags, uint64 delta, uint64 addr, uint64 size);
		public bool map_del(int fd);
*/

		[Compact]
		[CCode (cname="RIODesc",free_function="")]
		public class Desc {
			public int fd;
			public int perm;
			public string name;
			RIO io;
		}
/*
		// int perms -> RIOPerm ?
		public void desc_add(RIO.Desc *desc);
		public bool desc_del(int fd);
		//public RIO.Desc desc_get (int fd);
		//public int desc_generate();
*/
	}
}
