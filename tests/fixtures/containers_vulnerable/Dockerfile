FROM python:latest

ENV DATABASE_PASSWORD=hunter2

RUN apt-get update && apt-get install -y curl build-essential

COPY . .
RUN pip install -r requirements.txt

CMD ["python", "app.py"]
