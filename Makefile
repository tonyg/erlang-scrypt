export CC
export CFLAGS
export ERL
export ERL_CFLAGS
export LDFLAGS
export ERL_LDFLAGS

all: test

test: compile
	./rebar eunit

compile: deps
	./rebar compile

clean:
	./rebar clean
#	rm -rf ebin

veryclean: clean
	rm -rf rel
	rm -f erl_crash.dump

ultraclean: veryclean
	rm -rf deps

deps:
	./rebar get-deps

run: compile justrun

justrun:
	ERL_LIBS=$(CURDIR)/deps erl \
		-pa ebin \
		$$(for dep in deps/*; do echo -pa $$dep/ebin; done) \
		\
		-boot start_sasl \
		-s scrypt
