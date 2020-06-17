PBSRC=pb_common.c  pb_decode.c  pb_encode.c
DEMO_SRC=demo.c vm-agent.pb.c

all: demo

demo: $(DEMO_SRC) $(PBSRC)
	musl-gcc -Os -flto -static -fdata-sections -ffunction-sections -Wl,--gc-sections -fwhole-program -o $@ -Wall -I. $^


