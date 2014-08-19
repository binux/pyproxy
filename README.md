Usage
=====

```
Usage: ./application.py [OPTIONS]

Options:

  --bind                           addrs that debugger bind to (default
                                   127.0.0.1)
  --config                         config file
  --debug                          debug mode (default False)
  --help                           show this help information
  --username                       proxy username
  --password                       proxy password
  --port                           the port that debugger listen to (default
                                   8888)
```

API
===

1. Use as http proxy

`curl -x http://localhost:8888/ http://httpbin.org/get`

2. with GET/POST parameters

`curl http://localhost:8888/anypath?method=POST&url=http://httpbin.org/post`

3. pass params with JSON (work with GET parameters as well)

`curl -d '{"url": "http://httpbin.org/get","method": "GET", "headers": {"User-Agent":"Baidu"}}' http://localhost:8888/?callback=callback`

Auth
====

1. http proxy auth

`curl -x http://username:password@localhost:8888/ http://httpbin.org/get`

2. http basic auth

`curl http://username:password@localhost:8888/anypath?method=POST&url=http://httpbin.org/post`

3. username & password in GET/POST parameters / JSON

`curl http://localhost:8888/anypath?method=POST&url=http://httpbin.org/post&username=usernmae&password=password`

4. host_sign / path_sign / url_sign

sign a host / path / url with current username/password:

visit http://username:password@localhost:8888/sign?url=http://httpbin.org/get to get sign

request with: `http://localhost:8888/?url=http://httpbin.org/get&path_sign=abc123`
