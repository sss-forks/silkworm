FROM ethereum/cpp-build-env:18-gcc-12

RUN sudo apt-get update
RUN sudo apt-get install -y libgmp3-dev unzip libc

COPY ./build/cmd/t8ntool /silkworm
