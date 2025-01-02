FROM eclipse-temurin:21-jre-alpine

ENV APP auth-1.0.0.jar

WORKDIR /

ADD $APP $APP

EXPOSE 18450

ENTRYPOINT ["java","-jar","auth-1.0.0.jar","--server"]