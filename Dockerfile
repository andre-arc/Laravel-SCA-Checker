FROM python:3.12-alpine

RUN apk add --no-cache php83 php83-json composer

WORKDIR /checker
COPY checker.py .
RUN chmod +x checker.py

ENTRYPOINT ["python3", "/checker/checker.py"]
CMD ["/project"]
