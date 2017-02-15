Security
==============
The following defines the different security policies you can enforce on your APIs.

## Currently supported security policies:
- `apiKey`
- `oauth`

## API Key (`apiKey`)

Enforce API calls to include an API Key.

- **type**: `apiKey`
- **scope**: `api`, `tenant`, `resource`
- **header** (optional): custom name of auth header (default is `x-api-key`)
- **hashed** (optional): `true`, `false`

Example
```
"security":[
  {
    "type":"apiKey",
    "scope":"api",
    "header":"test"
  },
  {
    "type":"apiKey", 
    "scope":"resource"
    "header":"secret",
    "hashed":true
  }  
]
```
This will create two API keys for the API, which will need to be supplied in the `test` and `secret` headers, respectively.

## OAuth (`oauth`)
