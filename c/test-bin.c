#include <r_bin.h>

int main() {
	RBin *bin = r_bin_new();
	bin->verbose = false;
	ut64 baseaddr = UT64_MAX;
	bool isLoaded = r_bin_load (bin, "/bin/ls",
		baseaddr, 0, -1, -1, false);
	if (isLoaded) {
		RListIter *iter;
		RBinAddr *ent;
		const RList *entries = r_bin_get_entries (bin);
		r_list_foreach (entries, iter, ent) {
			printf ("-> 0x%"PFMT64x"\n", ent->vaddr);
		}
		RBinSymbol *sym;
		const RList *symbols = r_bin_get_symbols (bin);
		r_list_foreach (symbols, iter, sym) {
			printf ("-> %s\n", sym->name);
		}
	}
	r_bin_free (bin);
	return 0;
}
