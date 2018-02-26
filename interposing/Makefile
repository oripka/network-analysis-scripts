all:
	gcc -shared -ldl -fPIC setsockopt.c -o setsockopt.so
	gcc -force_flat_namespace main.c -o main
	echo "DYLD_INSERT_LIBRARIES=./setsockopt.so ./main"
