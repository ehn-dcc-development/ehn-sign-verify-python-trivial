FROM python:3

COPY requirements.txt ./

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

ADD hc1_verify.py /

COPY . .

ENTRYPOINT [ "python", "./hc1_verify.py" ]