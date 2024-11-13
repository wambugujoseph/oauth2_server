FROM eclipse-temurin:21-jre-alpine

ENV APP sds_auth-1.0.0.jar

WORKDIR /

ADD $APP $APP

EXPOSE 18450

ENTRYPOINT ["java","-jar","sds_auth-1.0.0.jar","--server"]