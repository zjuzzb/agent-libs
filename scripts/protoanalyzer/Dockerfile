FROM python:2
ADD requirements.txt .
ADD *.py ./
RUN pip install -r requirements.txt
ENTRYPOINT [ "python", "./protoanalyzer.py" ]
