# 베이스 이미지: Java 17 슬림 이미지 사용
FROM openjdk:17-jdk-slim

# 컨테이너 내 작업 디렉토리 생성 및 설정
WORKDIR /app

# 빌드된 JAR 복사 (GitHub Actions의 gradlew 빌드 후 결과물)
COPY build/libs/app.jar app.jar

# Spring Boot 앱 실행 java -jar app.jar 싫행
ENTRYPOINT ["java", "-jar", "app.jar"]


## wait-for-it.sh & entrypoint.sh 복사
#COPY wait-for-it.sh /wait-for-it.sh
#COPY docker-entrypoint.sh /entrypoint.sh
#RUN chmod +x /wait-for-it.sh /entrypoint.sh
#
## ENTRYPOINT 설정
#ENTRYPOINT ["/entrypoint.sh"]