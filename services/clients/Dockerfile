FROM alpine:3.19

# Installazione delle dipendenze necessarie per scaricare i binari ed eseguire la shell
RUN apk add --no-cache openssl jq bash ca-certificates wget curl gcompat

# Scaricamento e installazione dei binari ufficiali di MongoDB Shell (mongosh)
RUN wget https://downloads.mongodb.com/compass/mongosh-2.2.6-linux-x64.tgz && \
    tar -zxvf mongosh-2.2.6-linux-x64.tgz && \
    mv mongosh-2.2.6-linux-x64/bin/mongosh /usr/bin/mongosh && \
    chmod +x /usr/bin/mongosh && \
    rm -rf mongosh-2.2.6-linux-x64*

WORKDIR /workspace

# Creazione delle directory per i volumi dei certificati
RUN mkdir -p /certs /ca

CMD ["bash"]