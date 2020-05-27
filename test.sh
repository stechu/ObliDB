# NOTE if you can not compile with errors in isv_enclave/isv_enclave.cpp. Refer to another branch containing my modified isv_enclave.cpp 
# install SGX driver and SDK first.
make SGX_MODE=SIM DEBUG=0
./app # run app(default JOINTEST() without profilin. uncomment other test functions and recompile. Currently BDB2 & 3 series do not work properly)
LD_PRELOAD=/usr/lib/libprofiler.so.0 CPUPROFILE=./app.prof ./app # run with gperf. Seg Faults. If you replace ./app with other normal executable binary, for example /bin/ls, it works just fine