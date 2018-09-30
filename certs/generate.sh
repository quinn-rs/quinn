#!/bin/sh

set -xe
openssl req -nodes \
          -x509 \
          -newkey rsa:8192 \
          -keyout ca.key \
          -out ca.crt \
          -sha256 \
          -batch \
          -days 3650 \
          -subj "/CN=Quinn CA"

openssl req -nodes \
          -newkey rsa:2048 \
          -keyout server.key \
          -out server.csr \
          -sha256 \
          -batch \
          -subj "/CN=example.com"

openssl x509 -req \
          -in server.csr \
          -out server.crt \
          -CA ca.crt \
          -CAkey ca.key \
          -sha256 \
          -days 2000 \
          -set_serial 20283 \
          -extensions server -extfile openssl.cnf

cat server.crt ca.crt > server.chain
openssl asn1parse -in ca.crt -out ca.der
openssl rsa -in server.key -out server.rsa
rm *.csr ca.crt ca.key server.crt server.key
