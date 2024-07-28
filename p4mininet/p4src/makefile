P4_PROGRAM := switch
P4_JSON = $(P4_PROGRAM).json

P4C = p4c-bm2-ss
P4C_ARGS = --p4runtime-files
P4_INFO = p4info.txt

.PHONY: build clean

build: $(P4_JSON) $(LOG_DIR)

%.json: %.p4
# p4c-bm2-ss --p4runtime-files p4info.txt -o switch.json switch.p4
	$(P4C) $(P4C_ARGS) $(P4_INFO) -o $@ $<

clean:
	rm -f $(P4_JSON) $(P4_INFO)
