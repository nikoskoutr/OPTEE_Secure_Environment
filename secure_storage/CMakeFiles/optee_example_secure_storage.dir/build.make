# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.8

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /home/nk/optee/out-br/host/bin/cmake

# The command to remove a file.
RM = /home/nk/optee/out-br/host/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/nk/optee/out-br/build/optee_examples_ext-1.0

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/nk/optee/out-br/build/optee_examples_ext-1.0

# Include any dependencies generated for this target.
include secure_storage/CMakeFiles/optee_example_secure_storage.dir/depend.make

# Include the progress variables for this target.
include secure_storage/CMakeFiles/optee_example_secure_storage.dir/progress.make

# Include the compile flags for this target's objects.
include secure_storage/CMakeFiles/optee_example_secure_storage.dir/flags.make

secure_storage/CMakeFiles/optee_example_secure_storage.dir/host/main.c.o: secure_storage/CMakeFiles/optee_example_secure_storage.dir/flags.make
secure_storage/CMakeFiles/optee_example_secure_storage.dir/host/main.c.o: secure_storage/host/main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --progress-dir=/home/nk/optee/out-br/build/optee_examples_ext-1.0/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object secure_storage/CMakeFiles/optee_example_secure_storage.dir/host/main.c.o"
	cd /home/nk/optee/out-br/build/optee_examples_ext-1.0/secure_storage && ccache /home/nk/optee/out-br/host/bin/aarch64-linux-gnu-gcc --sysroot=/home/nk/optee/out-br/host/aarch64-buildroot-linux-gnu/sysroot $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/optee_example_secure_storage.dir/host/main.c.o   -c /home/nk/optee/out-br/build/optee_examples_ext-1.0/secure_storage/host/main.c

secure_storage/CMakeFiles/optee_example_secure_storage.dir/host/main.c.i: cmake_force
	@echo "Preprocessing C source to CMakeFiles/optee_example_secure_storage.dir/host/main.c.i"
	cd /home/nk/optee/out-br/build/optee_examples_ext-1.0/secure_storage && /home/nk/optee/out-br/host/bin/aarch64-linux-gnu-gcc --sysroot=/home/nk/optee/out-br/host/aarch64-buildroot-linux-gnu/sysroot $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/nk/optee/out-br/build/optee_examples_ext-1.0/secure_storage/host/main.c > CMakeFiles/optee_example_secure_storage.dir/host/main.c.i

secure_storage/CMakeFiles/optee_example_secure_storage.dir/host/main.c.s: cmake_force
	@echo "Compiling C source to assembly CMakeFiles/optee_example_secure_storage.dir/host/main.c.s"
	cd /home/nk/optee/out-br/build/optee_examples_ext-1.0/secure_storage && /home/nk/optee/out-br/host/bin/aarch64-linux-gnu-gcc --sysroot=/home/nk/optee/out-br/host/aarch64-buildroot-linux-gnu/sysroot $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/nk/optee/out-br/build/optee_examples_ext-1.0/secure_storage/host/main.c -o CMakeFiles/optee_example_secure_storage.dir/host/main.c.s

secure_storage/CMakeFiles/optee_example_secure_storage.dir/host/main.c.o.requires:

.PHONY : secure_storage/CMakeFiles/optee_example_secure_storage.dir/host/main.c.o.requires

secure_storage/CMakeFiles/optee_example_secure_storage.dir/host/main.c.o.provides: secure_storage/CMakeFiles/optee_example_secure_storage.dir/host/main.c.o.requires
	$(MAKE) -f secure_storage/CMakeFiles/optee_example_secure_storage.dir/build.make secure_storage/CMakeFiles/optee_example_secure_storage.dir/host/main.c.o.provides.build
.PHONY : secure_storage/CMakeFiles/optee_example_secure_storage.dir/host/main.c.o.provides

secure_storage/CMakeFiles/optee_example_secure_storage.dir/host/main.c.o.provides.build: secure_storage/CMakeFiles/optee_example_secure_storage.dir/host/main.c.o


# Object files for target optee_example_secure_storage
optee_example_secure_storage_OBJECTS = \
"CMakeFiles/optee_example_secure_storage.dir/host/main.c.o"

# External object files for target optee_example_secure_storage
optee_example_secure_storage_EXTERNAL_OBJECTS =

secure_storage/optee_example_secure_storage: secure_storage/CMakeFiles/optee_example_secure_storage.dir/host/main.c.o
secure_storage/optee_example_secure_storage: secure_storage/CMakeFiles/optee_example_secure_storage.dir/build.make
secure_storage/optee_example_secure_storage: secure_storage/CMakeFiles/optee_example_secure_storage.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --progress-dir=/home/nk/optee/out-br/build/optee_examples_ext-1.0/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable optee_example_secure_storage"
	cd /home/nk/optee/out-br/build/optee_examples_ext-1.0/secure_storage && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/optee_example_secure_storage.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
secure_storage/CMakeFiles/optee_example_secure_storage.dir/build: secure_storage/optee_example_secure_storage

.PHONY : secure_storage/CMakeFiles/optee_example_secure_storage.dir/build

secure_storage/CMakeFiles/optee_example_secure_storage.dir/requires: secure_storage/CMakeFiles/optee_example_secure_storage.dir/host/main.c.o.requires

.PHONY : secure_storage/CMakeFiles/optee_example_secure_storage.dir/requires

secure_storage/CMakeFiles/optee_example_secure_storage.dir/clean:
	cd /home/nk/optee/out-br/build/optee_examples_ext-1.0/secure_storage && $(CMAKE_COMMAND) -P CMakeFiles/optee_example_secure_storage.dir/cmake_clean.cmake
.PHONY : secure_storage/CMakeFiles/optee_example_secure_storage.dir/clean

secure_storage/CMakeFiles/optee_example_secure_storage.dir/depend:
	cd /home/nk/optee/out-br/build/optee_examples_ext-1.0 && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/nk/optee/out-br/build/optee_examples_ext-1.0 /home/nk/optee/out-br/build/optee_examples_ext-1.0/secure_storage /home/nk/optee/out-br/build/optee_examples_ext-1.0 /home/nk/optee/out-br/build/optee_examples_ext-1.0/secure_storage /home/nk/optee/out-br/build/optee_examples_ext-1.0/secure_storage/CMakeFiles/optee_example_secure_storage.dir/DependInfo.cmake
.PHONY : secure_storage/CMakeFiles/optee_example_secure_storage.dir/depend

