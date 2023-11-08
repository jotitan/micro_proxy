# Micro proxy 

Developped in Go

To launch proxy : 
```shell
./micro_proxy <port> <configuration_file>
```

Configuration files :

```json
{
  "challenges-folder": "folder where challenses let's encrypted are generated",
  "routes": [
    {
      "route": "path_of_route",
      "host": "url of service like http://127.0.0.1:8000"
    },
    {
      "route": "route_with_sse",
      "host": "host",
      "sse": true
    },
    {
      "route": "secured_route",
      "host": "host",
      "security": true
    },
    {
      "route": "security_and_guest_route",
      "host": "host",
      "security": true,
      "guest": true
    }
  ],
  "security": {
    "type": "oauth2",
    "secret": "secret in hs256 format",
    "oauth2": {
      "provider": "google",
      "client_id": "client_id",
      "client_secret": "client_secret",
      "redirect_url": "your url finishing with /callback",
      "emails": [
        "authorized mail 1",
        "authorized mail 2"
      ],
      "admin_emails": [
        "authorized admin mail 1"
      ]
    }
  }
}
```