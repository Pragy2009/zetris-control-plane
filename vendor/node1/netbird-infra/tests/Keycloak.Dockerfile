FROM quay.io/keycloak/keycloak:26.6.2
RUN JAVA_OPTS_KC_HEAP="-Xms128m -Xmx512m" /opt/keycloak/bin/kc.sh build --db=dev-file
