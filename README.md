# PolarStrategy

A strategy for [Polar.sh](https://polar.sh) that allows you to authorize Polar customizers in your app.

## Supported runtimes

| Runtime    | Has Support |
| ---------- | ----------- |
| Node.js    | ✅          |
| Cloudflare | ✅          |

## How to use

> [!TIP]
> You can find an example React Router application using this strategy on https://github.com/sergiodxa/remix-auth-polar-example.

### Installation

```bash
npm add remix-auth-polar
```

### Directly

You can use this strategy by adding it to your authenticator instance and configuring the correct endpoints.

```ts
import { PolarStrategy } from "remix-auth-polar";

export const authenticator = new Authenticator<User>();

authenticator.use(
  new OAuth2Strategy(
    {
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      redirectURI: "https://example.app/auth/callback",
      scopes: ["openid", "email", "profile"],

      cookie: "polar", // Optional, can also be an object with more options
    },
    async ({ tokens, request }) => {
      // here you can use the params above to get the user and return it
      // what you do inside this and how you find the user is up to you
      return await getUser(tokens, request);
    }
  ),
  // this is optional, but if you setup more than one Polar instance you will
  // need to set a custom name to each one
  "strategy-name"
);
```

Then you will need to setup your routes, for the OAuth2 flows required by Polar you will need to call the `authenticate` method twice.

First, you will call the `authenticate` method with the strategy name you set in the authenticator, default to `polar`.

```ts
export async function action({ request }: Route.ActionArgs) {
  await authenticator.authenticate("polar", { request });
}
```

> [!NOTE]
> This route can be an `action` or a `loader`, it depends if you trigger the flow doing a POST or GET request.

This will start the OAuth2 flow and redirect the user to the Polar's login page. Once the user logs in and authorizes your application, Polar will redirect the user back to your application redirect URI.

You will now need a route on that URI to handle the callback from Polar.

```ts
export async function loader({ request }: Route.LoaderArgs) {
  let user = await authenticator.authenticate("polar", request);
  // now you have the user object with the data you returned in the verify function
}
```

> [!NOTE]
> This route must be a `loader` as the redirect will trigger a `GET` request.

Once you have the `user` object returned by your strategy verify function, you can do whatever you want with that information. This can be storing the user in a session, creating a new user in your database, link the account to an existing user in your database, etc.

### Using the Refresh Token

The strategy exposes a public `refreshToken` method that you can use to refresh the access token.

```ts
let strategy = new PolarStrategy<User>(options, verify);
let tokens = await strategy.refreshToken(refreshToken);
```

The refresh token is part of the `tokens` object the verify function receives. How you store it to call `strategy.refreshToken` and what you do with the `tokens` object after it is up to you.

The most common approach would be to store the refresh token in the user data and then update the session after refreshing the token.

```ts
authenticator.use(
  new PolarStrategy<User>(
    options,
    async ({ tokens, request }) => {
      let user = await getUser(tokens, request);
      return {
        ...user,
        accessToken: tokens.accessToken()
        refreshToken: tokens.hasRefreshToken() ? tokens.refreshToken() : null,
      }
    }
  )
);

// later in your code you can use it to get new tokens object
let tokens = await strategy.refreshToken(user.refreshToken);
```

### Revoking Tokens

You can revoke the access token the user has with the provider.

```ts
await strategy.revokeToken(user.accessToken);
```

### Customizing the Cookie

You can customize the cookie options by passing an object to the `cookie` option.

```ts
authenticator.use(
  new PolarStrategy<User>(
    {
      cookie: {
        name: "polar",
        maxAge: 60 * 60 * 24 * 7, // 1 week
        path: "/auth",
        httpOnly: true,
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production",
      },
      ...otherOptions,
    },
    async ({ tokens, request }) => {
      return await getUser(tokens, request);
    }
  )
);
```

This will set the cookie with the name `polar`, with a max age of 1 week, only accessible on the `/auth` path, http only, same site lax and secure if the application is running in production.

### Scopes

The `PolarStrategy` constructor accepts a `scopes` option that is an array of strings with the scopes you want to request from Polar.

The scopes are the permissions you are requesting from the user. The strategy providers a type with all the supported scopes by Polar to the date of the package release.

```ts
import { PolarStrategy } from "remix-auth-polar";

const scopes: Array<PolarStrategy.Scope> = [
  "openid",
  "email",
  "profile",
  "user:read",
  "benefits:read",
  "benefits:write",
  // ...more scopes
];
```

### Usage with Polar SDK

If you are using the Polar SDK in your application, you can use the `PolarStrategy` to get the user's access token and authenticate the SDK.

First return the access token from the strategy.

```ts
import { PolarStrategy } from "remix-auth-polar";

authenticator.use(
  new PolarStrategy<User>(
    {
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      redirectURI: "https://example.app/auth/callback",
      scopes: ["openid", "email", "profile"],
    },
    async ({ tokens }) => tokens.accessToken()
  )
);
```

> [!TIP]
> Return the refresh token and keep that in your session, then use it to get a new access token when needed.

Then you can use the access token to authenticate the SDK.

```ts
// routes/auth.callback.ts
import { Polar } from "@polar-sh/sdk";

export async function loader({ request }: Route.ActionArgs) {
  let accessToken = await authenticator.authenticate("polar", request);
  let polar = new Polar({ accessToken });
  return data({ user: await polar.oauth2.userinfo() });
}
```
