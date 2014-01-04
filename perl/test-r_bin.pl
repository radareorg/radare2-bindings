#!/usr/bin/perl

use r_bin;

local $file = ($ARGV[0] ne "")?$ARGV[0]:"/bin/ls";
local $b = r_bin::RBin->new ();
$b->load ($file, undef);
local $baddr = $b->get_baddr ();
local $info = $b->get_info ();
local @sects = $b->get_sections ();

print "$info\n";
print "  Type: $info->{type}\n";
print "  File: $info->{file}\n";
print "  Arch: $info->{arch}\n";
print "  VA: $info->{has_va}\n";
printf ("  Base Address: 0x%x\n", $baddr);

print "-> Sections $#sects\n";
print "$#sects\n";

# this fails because swig generates wrong glue for RList :(
for ($i = 0; $i < $#sects ; $i++) {
	$s = $sects[$i]; #->get ($i);
	$s = $sects->get ($i);
	printf ("offset=0x%08x va=0x%08x size=%05i %s\n",
			$s->{offset}, $baddr + $s->{rva}, $s->{size}, $s->{name});
}
