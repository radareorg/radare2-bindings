#!/usr/bin/perl

use r_bp;

$a = new r_bp::RBreakpoint ();
$a->use ("x86");
$a->add_hw (0x8048000, 10, 0);
$a->add_sw (0x8048000, 10, 0);
$a->list (0);
