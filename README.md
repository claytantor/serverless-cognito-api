## install for python 2.7
```
virtualenv venv --system-site-packages
source venv/bin/activate
curl https://bootstrap.pypa.io/get-pip.py | python
pip install --upgrade pip
pip install -r requirements.txt
```

## deploy dev
```
serverless deploy --stage dev --region us-east-1

serverless deploy function --function postMessage --region us-east-1 --stage dev

```
