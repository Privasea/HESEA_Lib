HESEA provides a sample CMake file for building your own C++ project that links to the HESEA library. 

The high-level instructions for building projects that use HESEA are as follows:

1. Build and install HESEA using "make install". This will copy the HESEA library files and header files to the directory chosen for installation.
1. Create the folder for your project on your system.
2. Copy CMakeLists.User.txt from the root directory of the git repo to the folder for your project.
3. Rename CMakeLists.User.txt to CMakeLists.txt.
4. Update CMakeLists.txt to specify the name of the executable and the source code files. For example, include the following line
```
add_executable( fhe-demo simple-integers.cpp )
```
5. If using MinGW/Windows (skip this step for other platforms), copy PreLoad.cmake from the root directory of the git repo to the folder of your project.
6. Create the build directory and cd to it.
```
mkdir build
cd build
```
7. Run
```
cmake ..
```
8. Run "make" to build the executable.

To include a specific module, e.g., core or pke, in your C++ demo, use the main header file for that module, e.g., heseacore.h or hesea.h. Please see the demos provided for that module for more examples. If your application uses serialization, additional header files will be needed (see the demos with serialization for more details).
