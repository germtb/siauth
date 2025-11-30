# siauth-ts

TypeScript client and types for the Siauth RPC service.

## Installation

```bash
npm install siauth-ts
```

## Usage

```typescript
import { AuthClientImpl, SignupParams } from "siauth-ts";

const rpc = /* your RPC transport implementation */;
const client = new AuthClientImpl(rpc);

const params: SignupParams = {
  username: "user1",
  password: "pass123"
};

client.Signup(params).then(result => {
  console.log(result);
});
```

## Regenerating Types

To regenerate TypeScript types from your `.proto` files, use `protoc-gen-ts_proto` or similar tools.

## Development

- Types and client are auto-generated from `siauth_schema.proto`.
- Ensure dependencies (like `@bufbuild/protobuf`) are installed.

## License

MIT
