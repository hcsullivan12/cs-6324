CC	:= gcc
CFLAGS	:= -ggdb -Wall
RM	:= rm -f

sources	:= basic_stack_buffer_overflow.c format_string_problem.c integer_overflow.c
targets	:= basic_stack_buffer_overflow format_string_problem integer_overflow

all: $(targets)

clean:
	$(RM) $(targets) $(source:.c=.o)

