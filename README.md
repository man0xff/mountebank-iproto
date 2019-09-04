# an iproto protocol implementation for mountebank mocking server

iproto is a proprietary serialization format and at the same time trivial message protocol.

To use it add to _protocols.json_ file:
```json
{
  "iproto": {
    "createCommand": "python3 path/to/start.py"
  }
}
```
