declare module "playwright" {
  export interface Request {
    url(): string;
    method(): string;
    resourceType(): string;
    redirectedFrom(): Request | null;
  }
  export interface Response {
    url(): string;
    status(): number;
    headers(): Promise<Record<string, string>>;
    request(): Request;
  }
  export interface Route {
    request(): Request;
    continue(): Promise<void>;
    abort(errorCode?: string): Promise<void>;
  }
  export interface ConsoleMessage { type(): string; text(): string; }
  export interface Cookie { name: string; domain: string; path: string; expires: number; httpOnly: boolean; secure: boolean; sameSite: string; }
  export interface Page {
    route(url: string, handler: (route: Route) => void | Promise<void>): Promise<void>;
    on(event: "request", listener: (request: Request) => void): void;
    on(event: "response", listener: (response: Response) => void | Promise<void>): void;
    on(event: "console", listener: (message: ConsoleMessage) => void): void;
    on(event: "pageerror", listener: (error: Error) => void): void;
    goto(url: string, options?: { waitUntil?: "domcontentloaded" | "load" | "networkidle"; timeout?: number }): Promise<Response | null>;
    url(): string;
    title(): Promise<string>;
    content(): Promise<string>;
  }
  export interface BrowserContext {
    newPage(): Promise<Page>;
    cookies(): Promise<Cookie[]>;
    close(): Promise<void>;
  }
  export interface Browser {
    newContext(options?: { ignoreHTTPSErrors?: boolean; serviceWorkers?: "allow" | "block"; javaScriptEnabled?: boolean }): Promise<BrowserContext>;
    close(): Promise<void>;
  }
  export const chromium: { launch(options?: { headless?: boolean }): Promise<Browser> };
}
