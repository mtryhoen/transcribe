# rekon

On Ubuntu 17.10,
Install
 - sudo apt-get install python3-pip
 - pip3 install boto3
 - sudo apt-get install python3-dev
 - sudo apt-get install git
 - sudo apt-get install python3-opencv
 - sudo apt install awscli
 - aws configure
 - pip install flask, WTForms

 Clone the repo:
  - git clone https://github.com/mtryhoen/rekon
  
  
# Webapp

docker login \
docker pull mtryhoen/rekon:v0 \
docker run -d -p 5000:5000 rekon:vo 

# lambda

To zip the function:
Install required modules in same dir as python script:
pip3 install pillow -t .
cd in the directory where all modules are installed
then
zip -r9 rekon_lambda.zip rekon_lambda.py PIL <other module dir>