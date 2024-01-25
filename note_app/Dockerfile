FROM python:latest

RUN mkdir -p /home/project/note_app
WORKDIR /home/project/note_app
COPY requirements.txt /home/project/note_app
RUN pip install --no-cache-dir -r requirements.txt

COPY . /home/project/note_app