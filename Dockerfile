FROM openjdk:17-jdk
WORKDIR /
ADD forestfishd.jar forestfishd.jar
ADD etc ./etc
EXPOSE 6969 
CMD java -jar forestfishd.jar -l 6969 -t -n
