# SPDX-License-Identifier: MPL-2.0

SUBDIRS := \
	alarm \
	clock_nanosleep \
	gettimeofday \
	itimer \
	timerfd \

include ../common/Makefile

$(OBJ_OUTPUT_DIR)/cpu_tick_accounting: EXTRA_C_FLAGS += -pthread
