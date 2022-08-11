FROM java:8-jre-alpine

COPY target/Gateway-1.0.0.jar Gateway.jar

EXPOSE 8088

ENTRYPOINT ["java","-Duser.timezone=Asia/Seoul","-Djava.security.egd=file:/dev/./urandom","-jar","Gateway.jar"]