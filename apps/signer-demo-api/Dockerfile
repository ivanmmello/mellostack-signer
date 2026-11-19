FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /workspace
COPY pom.xml .
COPY mellostack-signer-core mellostack-signer-core
COPY mellostack-signer-providers mellostack-signer-providers
COPY mellostack-signer-validator mellostack-signer-validator
COPY mellostack-signer-sdk mellostack-signer-sdk
COPY examples examples
RUN mvn -pl mellostack-signer-sdk -am install -DskipTests

COPY apps/signer-demo-api apps/signer-demo-api
RUN mvn -f apps/signer-demo-api/pom.xml -DskipTests package

FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=build /workspace/apps/signer-demo-api/target/signer-demo-api-*.jar app.jar
EXPOSE 8096
ENTRYPOINT ["java", "-jar", "app.jar"]
