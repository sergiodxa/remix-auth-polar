import { CodeChallengeMethod, OAuth2Strategy } from "remix-auth-oauth2";
import type { Strategy } from "remix-auth/strategy";

export class PolarStrategy<User> extends OAuth2Strategy<User> {
	override name = "polar";

	constructor(
		options: PolarStrategy.ConstructorOptions,
		verify: Strategy.VerifyFunction<User, OAuth2Strategy.VerifyOptions>,
	) {
		super(
			{
				authorizationEndpoint: "https://polar.sh/oauth2/authorize",
				clientId: options.clientId,
				clientSecret: options.clientSecret,
				codeChallengeMethod: CodeChallengeMethod.S256,
				cookie: options.cookie,
				redirectURI: options.redirectURI,
				scopes: options.scopes,
				tokenEndpoint: "https://api.polar.sh/v1/oauth2/token",
				tokenRevocationEndpoint: "https://api.polar.sh/v1/oauth2/revoke",
			},
			verify,
		);
	}
}

export namespace PolarStrategy {
	export interface ConstructorOptions
		extends Pick<
			OAuth2Strategy.ConstructorOptions,
			"clientId" | "clientSecret" | "redirectURI" | "cookie"
		> {
		scopes: Array<
			| "openid"
			| "profile"
			| "email"
			| "user:read"
			| "organizations:read"
			| "organizations:write"
			| "custom_fields:read"
			| "custom_fields:write"
			| "discounts:read"
			| "discounts:write"
			| "checkout_links:read"
			| "checkout_links:write"
			| "checkouts:read"
			| "checkouts:write"
			| "products:read"
			| "products:write"
			| "benefits:read"
			| "benefits:write"
			| "events:read"
			| "events:write"
			| "meters:read"
			| "meters:write"
			| "files:read"
			| "files:write"
			| "subscriptions:read"
			| "subscriptions:write"
			| "customers:read"
			| "customers:write"
			| "customer_sessions:write"
			| "orders:read"
			| "refunds:read"
			| "refunds:write"
			| "metrics:read"
			| "webhooks:read"
			| "webhooks:write"
			| "external_organizations:read"
			| "license_keys:read"
			| "license_keys:write"
			| "repositories:read"
			| "repositories:write"
			| "issues:read"
			| "issues:write"
			| "customer_portal:read"
			| "customer_portal:write"
		>;
	}
}
