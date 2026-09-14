declare namespace JSX {
  interface Element {}
  interface IntrinsicElements { [elementName: string]: any; }
  interface IntrinsicAttributes { key?: string | number; }
}

declare module "react" {
  export type ReactNode = unknown;
  export function useActionState<State, Payload>(
    action: (state: State, payload: Payload) => State | Promise<State>,
    initialState: State,
  ): [State, (payload: Payload) => void, boolean];
}

declare module "next" {
  export interface Metadata {
    title?: string | { default: string; template?: string };
    description?: string;
  }
  export interface NextConfig { [key: string]: unknown; }
}

declare module "next/link" {
  export default function Link(props: any): JSX.Element;
}
declare module "next/navigation" {
  export function redirect(path: string): never;
  export function notFound(): never;
}
declare module "next/headers" {
  export function cookies(): Promise<{ toString(): string }>;
}
declare module "next/cache" {
  export function revalidatePath(path: string): void;
}
declare module "server-only" {}

declare const process: {
  env: Record<string, string | undefined>;
};
