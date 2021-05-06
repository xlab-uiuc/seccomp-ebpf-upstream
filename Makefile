all: ebpf user_trap

%.bpf.o: %.bpf.c
	clang -target bpf -Wall -O2 -g -D__x86_64__ -c $< -o $@
	llvm-strip -g $@

%.skel.h: %.bpf.o
	bpftool gen skeleton $< > $@

ebpf: ebpf.c config.h ebpf.skel.h
	gcc -Wall -O2 $< -o $@ -lbpf

user_trap: user_trap.c config.h
	gcc -Wall -O2 $< -o $@

clean:
	rm -rf ebpf user_trap *.o *.skel.h
