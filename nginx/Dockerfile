FROM nginx:latest

RUN rm /etc/nginx/nginx.conf
COPY nginx.conf /etc/nginx/

RUN rm /etc/nginx/conf.d/default.conf
COPY project.conf /etc/nginx/conf.d/

COPY certs/note_app.crt /etc/nginx/certs/

COPY certs/note_app.key /etc/nginx/certs/
