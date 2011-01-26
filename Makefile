.PHONY: all test clean doc

all:
	./rebar compile

test:
	./rebar eunit

clean:
	./rebar clean

doc:
	./rebar doc
