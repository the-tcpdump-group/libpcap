
#include <stdio.h>
#include <string.h>
#include <pcap/pcap.h>

#define DELIM "=============================\n"

int dflag = 2;

int main(int argc, char *argv[])
{
	pcap_t *phdr;
	struct bpf_program prog;
	FILE *f;
	char linebuf[8192];
	int err;
	int optimize = 1;

	if (argc >= 2 && strcmp(argv[1], "noopt") == 0) {
		optimize = 0;
	}

	phdr = pcap_open_dead(DLT_EN10MB, 1500);
	if (phdr == NULL) {
		fprintf(stderr, "can't open pcap handler.\n");
		return 1;
	}

	f = fopen("bpfset.txt", "rt");
	if (f == NULL) {
		fprintf(stderr, "can't open input testset.txt.\n");
		pcap_close(phdr);
		return 1;
	}

	while (fgets(linebuf, sizeof linebuf, f)) {
		{
			int empty;
			char *pch;
			// remove comment after #
			for (pch = linebuf; *pch; pch++) {
				if (*pch == '#') {
					*pch = '\0';
					break;
				}
			}
			// ignore empty line
			empty = 1;
			for (pch = linebuf; *pch; pch++) {
				if (!isspace(*pch)) {
					empty = 0;
					break;
				}
			}
			if (empty) {
				continue;
			}
		}
	   
		printf("compile BPF expression: %s\n", linebuf);
		err = pcap_compile(phdr, &prog, linebuf, optimize, 
						   PCAP_NETMASK_UNKNOWN);
		if (err < 0) {
			pcap_close(phdr);
			return 1;
		}
		printf("dump BPF assembly:\n");
		bpf_dump(&prog, 0);

		printf("%s", DELIM);
		pcap_freecode(&prog);
	}


	pcap_close(phdr);
	return 0;
}
