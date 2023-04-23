HESEA uses CMake to create the Makefiles that build and install the HESEA Library. This page describes how CMake is used in HESEA, and how contributors should use CMake when adding new files or new components.

# Using HESEA's CMake system

The first step in using CMake is deciding where the build should be performed. This is the "build tree". The "source tree" is where the HESEA source is located. These should be different directories! The build tree can be in a subdirectory of the source directory (such as "build") or in some other place.

The project is described in files named ```CMakeLists.txt```.

CMake is run in the build tree. The source tree is passed to CMake as an argument on the command line. CMake will create a Makefile in the build tree. Once this is done, make can be run inside of the build tree.

Therefore the basic steps are:
1. `cd build-tree-location`
2. `cmake {other CMake arguments} source-tree-location`
3. `make`


CMake does not usually have to be rerun. A `make` will rerun CMake if it detects changes to any of the project's CMakeLists.txt files.

## Required Compilers
HESEA supports any GNU C++ compiler version 6 or above and clang C++ compiler version 6 or above.

A warning is issued if an older version of the compiler is found. The build may run but such compilers are unsupported.

## Required Packages
HESEA requires that certain packages and applications be available on the system. CMake searches for these packages and may either stop if a required package is missing, or disable functionality.


These packages are as follows:
- OpenMP
- Autoconfig tools (for some third party code)
- Git
- Doxygen (if not found, generating Doxygen files is disabled)

## Command Line Options
There are a large number of CMake command line options. Most important for our purposes here is the -D option,
which allows variables to be set, cached, and used in constructing the Makefile and making HESEA.

### Combining multiple CMake flags

Different flags can be combined together. For example, to configure cmake with NTL, tcmalloc, MATHBACKEND 6, and have it run in the debug mode, the following command can be used:
```
cmake -DCMAKE_BUILD_TYPE=Debug -DWITH_NTL=ON -DWITH_TCM=ON -DMATHBACKEND=6 .. 
```

## Important CMake Flags Used
We point out a number of the standard CMake variables that can be set using -D from the CMake command line, which may be of use to HESEA users. To set one of these variables, use -D*VARIABLE_NAME*=*VALUE* on the command line.

| *VARIABLE_NAME* | Definition | Notes |
| ------ | ------ | ----- |
| CMAKE_INSTALL_PREFIX | Base directory for installs | Base directory for installation of HESEA. Libraries are installed in ${CMAKE_INSTALL_PREFIX}/lib and include files are installed in ${CMAKE_INSTALL_PREFIX}/include/hesea. HESEA is also exported as a CMake package for the benefit of any users wanting to use HESEA; the package files are also installed here |
| CMAKE_BUILD_TYPE | Debug, Release | Default is to build HESEA for release, with no debug information; developers may want to specify -DCMAKE_BUILD_TYPE=Debug |

## Flags for HESEA Builds
Beginning with release 1.10, the HESEA build has a number of options to control
what is built and what features are included/excluded.

Each of the options is enabled by saying -DOPTION_NAME=ON and is disabled by saying -DOPTION_NAME=OFF

The table below shows the current list of options, definition for the option, and a default value.

| OPTION_NAME | Description | Default |
| ----- | ----- | ----- |
| BUILD_UNITTESTS | Set to ON to build unit tests for the library | ON |
| BUILD_EXAMPLES | Set to ON to build examples for the library | ON |
| BUILD_BENCHMARKS | Set to ON to build benchmarks for the library | ON |
| BUILD_EXTRAS | Set to ON to build extra examples for the library | OFF |
| BUILD_SHARED | Set to ON to include shared versions of the library | ON |
| BUILD_STATIC | Set to ON to include static versions of the library | OFF |
| WITH_BE2 | Include Backend 2 in build by setting WITH_BE2 to ON | ON |
| WITH_BE4 | Include Backend 4 in build by setting WITH_BE4 to ON | ON |
| WITH_NTL | Include Backend 6 and NTL in build by setting WITH_NTL to ON | OFF |
| WITH_TCM | Activate tcmalloc by setting WITH_TCM to ON | OFF |
| WITH_INTEL_HEXL | Use Intel HEXL library | OFF |
| USE_OpenMP | Use OpenMP to enable <omp.h> | ON |
| WITH_NATIVEOPT | Use machine-specific optimizations (major speedup for clang) | OFF |
| NATIVE_SIZE | Set default word size for native integer arithmetic to 64 or 128 bits | 64 |
| CKKS_M_FACTOR | Parameter used to strengthen the CKKS adversarial model in scenarios where decryption results are shared among multiple parties (See Security.md for more details) | 1 |

Note that more options will be added as development progresses.


The default math backend for the HESEA build is Backend 2 (basic fixed-maximum-length big integers). This default can be changed on the CMake command line by setting the MATHBACKEND variable. For example, to select backend 6 (high performance fixed integers based on the GMP and NTL libraries), use -DMATHBACKEND=6 on the CMake command line.

## Detecting Local Environments
HESEA detects most of the capabilities of the target machine. It uses the machine's capabilities and the values of the user options to create header files that are used to control the build. These files are placed in the src subdirectory of the CMake build tree, and are included in the HESEA install.


As of release 1.10.0, src/core/config_core.h is used to control the build of the core component, and any library code that depends on it. Future developments will expand this to other components.

## Third-Party Components
HESEA uses some third-party components from Google for testing and benchmarking, and it uses a third-party serialization library called CEREAL. These libraries are git submodules under HESEA and are fully integrated into the build.

### Turn on NTL/GMP (Only for Advanced Users)

By default HESEA builds without external dependencies. If you wish to use the NTL/GMP implementation of BigInteger/BigVector, you can [install GMP and NTL manually](Instructions-for-installing-GMP-and-NTL) and run cmake with "-DWITH_NTL=ON". The complete command is
```
cmake -DWITH_NTL=ON .. 
```
We have tested HESEA with GMP 6.1.2 and 6.2.1, and NTL 10.5.0 and 11.4.4. Please note that a regular binary install (using tools like `apt-get`) will not work as special compilation flags need to be passed. See [Installation of GMP and NTL](Instructions-for-installing-GMP-and-NTL) for further details on the manual installation.

Note the performance w/o and w/ NTL is almost the same for all schemes/operations. NTL is used only for multiprecision integer arithmetic (the latter only when the MATHBACKEND variable is set to 6). Most of the crypto operations are executed using native arithmetic (by employing RNS procedures), and do not use these higher-precision capabilities.

### Turn on tcmalloc

If you wish to use tcmalloc, you can add "-DWITH_TCM=ON" to the cmake command. The complete command is
```
cmake -DWITH_TCM=ON .. 
```
tcmalloc can improve performance in the multi-threaded mode (when OMP_NUM_THREADS>1). It provides efficient thread-caching block allocation for all HESEA objects.

Note that tcmalloc only works in Linux and macOS, and is not currently supported in MinGW.

Tcmalloc should be installed after running cmake and right before running make for HESEA. To build tcmalloc, run
```
make tcm
```

To remove tcmalloc, run
```
make tcm_clean
```

### Turn on Intel HEXL
If you wish to use the Intel HEXL library, you can add "-WITH_INTEL_HEXL=ON" to the cmake command. The complete command is
```
cmake -WITH_INTEL_HEXL=ON .. 
```
Please also make sure `make` for HESEA is run using `sudo`, i.e., `sudo make`. 

Intel HEXL library improves HESEA performance on Intel processors supporting AVX-512 extensions.

## Location of Build Products
The Makefile created by CMake creates all HESEA build products inside the build subdirectory.


The actual libraries are placed in the subdirectory lib.


Third party libraries are placed in third-party/lib.


Unit tests are placed in unittest.


Benchmarks are placed in bin/benchmark.


Examples (of basic HESEA features) are placed in bin/examples, and additional examples (more complicated and research-oriented examples) are placed in bin/extras. Note demos are built as part of each sub-component of the library (core, pke, trapdoor, etc.) 

## Installing HESEA on your system for use by applications external to the HESEA source tree

Running `make install` will install all libraries and header files in the directories designated by CMAKE_INSTALL_PREFIX. Demos, unittests, benchmarks, examples and extras are not installed.

### Building applications with an installed HESEA library
A user can create a CMake environment for their own HESEA application development.
Simply copy the file CMakeLists.User.txt from the HESEA source tree to
CMakeLists.txt in your source tree, and add your CMake directives for your own programs to
the end of the file.


This file imports the HESEA package that was built and installed by the HESEA build.

## Cross Compiling with CMake [experimental feature]
Cross compiling HESEA for other target environments is an experimental feature. Cross-compilation for new targets should require the following steps:

1. Obtain and configure  a cross-compiler for your target environment (or use the appropriate command line arguments to your compiler to initiate cross compilation).
2. Specify that CMake should use the cross-compiler.
3. Proceed with the CMake/make process.


It should be noted that the third-party libgmp and NTL libraries will probably need to be built manually for cross compilation using their internal build sequence, and that they may not be supported on the target platform at all. Configuring  HESEA with -DWITH_NTL=ON will circumvent this issue.

## Using CMake with Eclipse
Developers that wish to use Eclipse for building HESEA can use the shell script configure/setup-eclipse-cmake.sh.
This script should be run in the users build tree. All command line arguments are passed to CMake. The shell configures the build tree so that it can be imported into Eclipse, and built directly from Eclipse.

# Documentation for extending HESEA CMake Files

## CMake Files for HESEA Components
Each component of the library (core, pke, trapdoor, etc.) has its own CMakeLists.txt file. Each of these files is included by the main HESEA CMakeLists.txt file. The structure of all of these component CMakeList.txt files is identical:

1. Determine the files that are built into the component library
2. Set include directories to build the component library
3. Set the version number from the HESEA version number
4. Add rules to build the objects in the component library
5. Add rules to build and install the component library, dynamic as well as static
6. If unit tests are included in the build, add rules to build unit tests
7. Add rules to build all the source files in the demo directory into demos
8. Add targets to build "all" of various pieces of the component

## Adding a new file to HESEA
A new file can simply be added to the directory tree, and CMake will add it to the build.

## Adding a new component to HESEA
When adding a new component to HESEA

1. Observe the structure discussed above when making your new CMakeLists.txt for the component
2. Be sure to include the component in the master CMakeLists.txt file at the root of the source tree
3. Be sure to update the "all" targets to include targets from the new component

# Documentation of make targets created by HESEA CMake system

make flags
============

When "make" is run without any target specified, it builds all modules, unit tests (if BUILD_UNITTESTS=ON), examples (if BUILD_EXAMPLES=ON), benchmarks (if BUILD_BENCHMARKS=ON), and extras (if BUILD_EXTRAS=ON). HESEA also provides more granular control over which components of HESEA are built. We discuss these options below. Each of these commands can be used instead of "make" in the main build instructions. Note that for many users, it may be easier to rely on CMake flags "BUILD_UNITTESTS", "BUILD_EXAMPLES", and the like, to control what is built using the standard "make" command without specifying a target.

Build only the library files
-------------------
```
make allmodules
```

Build library files + main examples (available if BUILD_EXAMPLES=ON)
-----------
```
make allexamples
```

Build additional examples (not built as part of default build)
-----------
```
make allextras
```

Build library files + unit tests + run all tests (available if BUILD_UNITTESTS=ON)
-----------
```
make testall
```

Build only benchmarks and their dependencies (available if BUILD_BENCHMARKS=ON)
----
```
make allbenchmark
```

Build a specific module and its dependencies
------
The options for the make command are HESEAEcore, HESEApke, HESEAabe, HESEAsignature, HESEAbinfhe (these correspond to core, pke, abe, signature, and binfhe modules). To install pke, enter
```
make HESEApke
```

Build a specific module + examples (available if BUILD_EXAMPLES=ON)
------
Using pke as an example, enter
```
make allpkeexamples
```

Build a specific module + additional examples (available if BUILD_EXTRAS=ON)
------
Using pke as an example, enter
```
make allpkeextras
```

Build a specific module + unit tests (available if BUILD_UNITTESTS=ON)
------
Using pke as an example, enter
```
make pke_tests
```

Build a specific module + unit tests (if BUILD_UNITTESTS=ON) + examples (if BUILD_EXAMPLES=ON)
------
Using pke as an example, enter
```
make allpke
```

Build doxygen documentation
------
To build doxygen documentation, doxygen and dot need to be installed. Then run the following make command to generate the HTML/LaTeX documentation:
```
make apidocs
```