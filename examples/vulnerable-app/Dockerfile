# Everything a production image should not be.
FROM python:latest

COPY . /app
WORKDIR /app

RUN pip install -r requirements.txt

ENV JWT_SECRET=n0t3n3st-hs256-9f2c4ab71de85306

EXPOSE 5000
CMD ["python", "app.py"]
