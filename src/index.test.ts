import {
	afterAll,
	afterEach,
	beforeAll,
	describe,
	expect,
	mock,
	test,
} from "bun:test";
import { Cookie, SetCookie } from "@mjackson/headers";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/native";
import { PolarStrategy } from ".";

const server = setupServer(
	http.post("https://api.polar.sh/v1/oauth2/token", async () => {
		return HttpResponse.json({
			access_token: "mocked",
			expires_in: 3600,
			refresh_token: "mocked",
			scope: ["user:read", "benefits:read"].join(" "),
			token_type: "Bearer",
		});
	}),
);

describe(PolarStrategy.name, () => {
	let verify = mock();

	let options = Object.freeze({
		clientId: "MY_CLIENT_ID",
		clientSecret: "MY_CLIENT_SECRET",
		redirectURI: "https://example.com/callback",
		scopes: ["user:read", "benefits:read"],
	} satisfies PolarStrategy.ConstructorOptions);

	interface User {
		id: string;
	}

	beforeAll(() => {
		server.listen();
	});

	afterEach(() => {
		server.resetHandlers();
	});

	afterAll(() => {
		server.close();
	});

	test("should have the name `polar`", () => {
		let strategy = new PolarStrategy<User>(options, verify);
		expect(strategy.name).toBe("polar");
	});

	test("redirects to authorization url if there's no state", async () => {
		let strategy = new PolarStrategy<User>(options, verify);

		let request = new Request("https://remix.auth/login");

		let response = await catchResponse(strategy.authenticate(request));

		// biome-ignore lint/style/noNonNullAssertion: This is a test
		let redirect = new URL(response.headers.get("location")!);

		let setCookie = new SetCookie(response.headers.get("set-cookie") ?? "");
		let params = new URLSearchParams(setCookie.value);

		expect(redirect.pathname).toBe("/oauth2/authorize");
		expect(redirect.searchParams.get("response_type")).toBe("code");
		expect(redirect.searchParams.get("client_id")).toBe(options.clientId);
		expect(redirect.searchParams.get("redirect_uri")).toBe(options.redirectURI);
		expect(redirect.searchParams.has("state")).toBeTruthy();
		expect(redirect.searchParams.get("scope")).toBe(options.scopes.join(" "));
		expect(params.get("state")).toBe(redirect.searchParams.get("state"));
		expect(redirect.searchParams.get("code_challenge_method")).toBe("S256");
	});

	test("throws if there's no state in the session", async () => {
		let strategy = new PolarStrategy<User>(options, verify);

		let request = new Request(
			"https://example.com/callback?state=random-state&code=random-code",
		);

		expect(strategy.authenticate(request)).rejects.toThrowError(
			new ReferenceError("Missing state on cookie."),
		);
	});

	test("handles race condition of state and code verifier", async () => {
		let verify = mock().mockImplementation(() => ({ id: "123" }));
		let strategy = new PolarStrategy<User>(options, verify);

		let responses = await Promise.all(
			Array.from({ length: random() }, () =>
				catchResponse(
					strategy.authenticate(new Request("https://remix.auth/login")),
				),
			),
		);

		let setCookies: SetCookie[] = responses
			.flatMap((res) => res.headers.getSetCookie())
			.map((header) => new SetCookie(header));

		let cookie = new Cookie();

		for (let setCookie of setCookies) {
			cookie.set(setCookie.name as string, setCookie.value as string);
		}

		let urls = setCookies.map((setCookie) => {
			let params = new URLSearchParams(setCookie.value);
			let url = new URL("https://remix.auth/callback");
			url.searchParams.set("state", params.get("state") as string);
			url.searchParams.set("code", crypto.randomUUID());
			return url;
		});

		await Promise.all(
			urls.map((url) =>
				strategy.authenticate(
					new Request(url, { headers: { cookie: cookie.toString() } }),
				),
			),
		);

		expect(verify).toHaveBeenCalledTimes(responses.length);
	});
});

function isResponse(value: unknown): value is Response {
	return value instanceof Response;
}

async function catchResponse(promise: Promise<unknown>) {
	try {
		await promise;
		throw new Error("Should have failed.");
	} catch (error) {
		if (isResponse(error)) return error;
		throw error;
	}
}

function random(min = 1, max = 10) {
	return Math.floor(Math.random() * (max - min + 1)) + min;
}
