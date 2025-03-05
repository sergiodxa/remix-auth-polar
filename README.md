# PolarStrategy

A strategy for [Polar.sh](https://polar.sh) that allows you to authorize Polar customizers in your app.

## Supported runtimes

| Runtime    | Has Support |
| ---------- | ----------- |
| Node.js    | ✅          |
| Cloudflare | ✅          |

## How to use

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

      cookie: "oauth2", // Optional, can also be an object with more options
      scopes: ["openid", "email", "profile"], // optional, fully typed
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
