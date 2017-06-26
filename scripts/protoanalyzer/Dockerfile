FROM python:2-alpine
WORKDIR /app
ADD requirements.txt .
RUN pip install -r requirements.txt
ADD *.py .
ENTRYPOINT [ "python", "protoanalyzer.py" ]
