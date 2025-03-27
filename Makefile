# Makefile for SGX CKKS application

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_FLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_FLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
	SGX_COMMON_FLAGS += -O0 -g
else
	SGX_COMMON_FLAGS += -O2
endif

SGX_COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
					-Waddress -Wsequence-point -Wformat-security \
					-Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
					-Wcast-align -Wcast-qual -Wconversion -Wredundant-decls
SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants
SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -Wnon-virtual-dtor -std=c++11

# App settings
App_Cpp_Files := App/App.cpp
App_Include_Paths := -I$(SGX_SDK)/include -I./App

App_C_Flags := -fPIC -Wno-attributes $(App_Include_Paths)
App_Cxx_Flags := $(App_C_Flags) $(SGX_COMMON_CXXFLAGS)

ifeq ($(SGX_MODE), HW)
	App_Link_Flags := -L$(SGX_LIBRARY_PATH) -lsgx_urts -lsgx_uae_service -lpthread
else
	App_Link_Flags := -L$(SGX_LIBRARY_PATH) -lsgx_urts_sim -lsgx_uae_service_sim -lpthread
endif

App_Link_Flags += -lcrypto

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

# Enclave settings
Enclave_Cpp_Files := Enclave/Enclave.cpp Enclave/CKKS.cpp
Enclave_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx -I./Enclave

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)
Enclave_Cxx_Flags := $(Enclave_C_Flags) $(SGX_COMMON_CXXFLAGS) -nostdinc++

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags := -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -lsgx_tservice -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)

# Enclave name and signing key
Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := Enclave/Enclave.config.xml
Enclave_Key_File := Enclave/Enclave_private.pem

.PHONY: all clean

all: ckks_app $(Signed_Enclave_Name)

# Generate EDL files
App/Enclave_u.c App/Enclave_u.h: Enclave/Enclave.edl
	@mkdir -p App
	$(SGX_EDGER8R) --untrusted Enclave/Enclave.edl --search-path $(SGX_SDK)/include --search-path ./Enclave --untrusted-dir ./App

Enclave/Enclave_t.c Enclave/Enclave_t.h: Enclave/Enclave.edl
	@mkdir -p Enclave
	$(SGX_EDGER8R) --trusted Enclave/Enclave.edl --search-path $(SGX_SDK)/include --search-path ./Enclave --trusted-dir ./Enclave

# Compile App
App/Enclave_u.o: App/Enclave_u.c
	$(CC) $(App_C_Flags) -c $< -o $@

App/%.o: App/%.cpp App/Enclave_u.h
	$(CXX) $(App_Cxx_Flags) -c $< -o $@

# Compile Enclave
Enclave/Enclave_t.o: Enclave/Enclave_t.c
	$(CC) $(Enclave_C_Flags) -c $< -o $@

Enclave/%.o: Enclave/%.cpp Enclave/Enclave_t.h
	$(CXX) $(Enclave_Cxx_Flags) -c $< -o $@

# Link App
ckks_app: App/Enclave_u.o $(App_Cpp_Objects)
	$(CXX) $^ -o $@ $(App_Link_Flags)

# Link Enclave
$(Enclave_Name): Enclave/Enclave_t.o $(Enclave_Cpp_Objects)
	$(CXX) $^ -o $@ $(Enclave_Link_Flags)

# Sign Enclave
$(Signed_Enclave_Name): $(Enclave_Name) $(Enclave_Config_File) $(Enclave_Key_File)
	$(SGX_ENCLAVE_SIGNER) sign -key $(Enclave_Key_File) -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)

# Generate signing key if it doesn't exist
$(Enclave_Key_File):
	@mkdir -p Enclave
	openssl genrsa -out $(Enclave_Key_File) 3072

clean:
	rm -f ckks_app $(Enclave_Name) $(Signed_Enclave_Name)
	rm -f App/Enclave_u.* Enclave/Enclave_t.*
	rm -f App/*.o Enclave/*.o
