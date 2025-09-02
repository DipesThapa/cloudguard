FROM python:3.11-slim

WORKDIR /app
COPY . /app

RUN pip install -r requirements.txt

ENTRYPOINT ["python", "-m", "src.cloudguard.cli"]
CMD ["--help"]
