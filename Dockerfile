FROM python:3.8

COPY src/solution.py src/requirements.txt /


RUN apt-get update --fix-missing && apt-get -y install gcc


RUN  pip install -r requirements.txt

ENTRYPOINT ["python3","solution.py"]
