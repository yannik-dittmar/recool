# docker build -t recool .
# docker run -it --rm --net=host -v ./recool-output:/recool/dist kryptolyser/recool -I eth0

FROM golang:1.22.0-bullseye

WORKDIR /recool

# Install dependencies
RUN apt-get update \
	&& apt-get install -y \
		python3 \
		python3-pip \
		nmap \
		ipv6toolkit \
		sudo \
	&& apt-get clean
RUN go install github.com/richartkeil/nplan@latest

# Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Install recool
COPY recool.py .
COPY ip_tools.py .

# Run recool
ENTRYPOINT ["python3", "recool.py"]
