FROM ubuntu:16.04
ARG extra_modules="zrest drain"
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y curl make gcc libssl-dev
RUN mkdir -p build && curl -sSLf https://github.com/creytiv/re/archive/v0.4.15.tar.gz  -o v0.4.15.tar.gz \
    && echo "53276499837f44256929ae7274c760a798467e16f90c7dcca7bc5ce157a2c4c4  v0.4.15.tar.gz" | sha256sum --check \
    && tar -C /build -xmvf v0.4.15.tar.gz

COPY . /build/restund
WORKDIR /build/restund

RUN make -C /build/re-0.4.15 RELEASE=1 EXTRA_CFLAGS="-std=gnu99" && make -C /build/re-0.4.15 PREFIX=/usr/local install && ldconfig
RUN make -C /build/restund RELEASE=1 EXTRA_CFLAGS="-std=gnu99" && make -C /build/restund PREFIX=/usr/local install
RUN apt-get remove -y make gcc && apt-get autoremove -y

VOLUME /etc/restund.conf
VOLUME /etc/restund.auth
ENTRYPOINT [ "/usr/local/sbin/restund", "-n" ]
