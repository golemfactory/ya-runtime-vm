PBSRC=pb_common.c  pb_decode.c  pb_encode.c
DEMO_SRC=demo.c vm-agent.pb.c

all: demo

demo: $(DEMO_SRC) $(PBSRC)
	gcc -O2 -o $@ -Wall -I. $^


