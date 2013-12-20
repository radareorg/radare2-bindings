#!/usr/bin/ruby

require 'r_core'

core = R_core::RCore.new
core.file_open("/bin/ls", 0, 0);
print core.cmd_str("pd 20");
