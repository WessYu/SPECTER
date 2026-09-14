// Shared by CLI help and the installation welcome screen. No scanner imports.
const GHOST = [
  "                  .────.",
  "               · ╱  ··  ╲ ·",
  "          ·     ╱· ╱──╲ ·╲     ·",
  "       +      ·╱· ╱    ╲ ·╲",
  "    ·        ╱╱  ╱      ╲  ╲╲      +",
  "            ╱·  ╱  ▄▄▄▄  ╲  ·╲",
  "      ·    ╱╱  ╱ ╱    ╲ ╲  ╲╲",
  "          ╱·  ╱ ╱      ╲ ╲  ·╲    ·",
  "   +     ╱╱  ╱ │ ◣    ◢ │ ╲  ╲╲",
  "        ╱·  ╱  │ ▝▀  ▀▘ │  ╲  ·╲",
  "       ╱╱  ╱   ╲        ╱   ╲  ╲╲",
  "   ·  ╱·  ╱╲    ╲      ╱    ╱╲  ·╲",
  "     ╱╱  ╱ ·╲    ╲    ╱    ╱· ╲  ╲╲",
  "    ╱·──╱    ╲    ╲  ╱    ╱    ╲──·╲",
  "   ╱╱ ▄▄╲··   ╲    ╲╱    ╱   ··╱▄▄ ╲╲",
  " +╱· ╱  ▀▄╲    ╲   ··   ╱    ╱▄▀  ╲ ·╲",
  "  ╱ ╱     ╲╲    │  ··  │    ╱╱     ╲ ╲",
  " ╱·╱       ╲╲   │  ··  │   ╱╱       ╲·╲",
  "╱ ╱   ·     ╲   │  ··  │   ╱     ·   ╲ ╲",
  "│╱  ╱╲      │ · │  ··  │ · │      ╱╲  ╲│",
  "│  ╱  ╲     │ · │  ··  │ · │     ╱  ╲  │",
  "· ╱    ╲   ╱│ · │  ··  │ · │╲   ╱    ╲ ·",
  "  ·  │  ╲ ╱ │ · │  ··  │ · │ ╲ ╱  │  ·",
  "  +  ·   ▏  ┆ + ┆  ··  ┆ + ┆  ▕   ·  +",
  "     ·   ·  ┆ · ┆  ··  ┆ · ┆  ·   ·",
  "       · ┆  + · ┆  ··  ┆ · +  ┆ ·",
  "         ·  ┆ + ·  ··  · + ┆  ·",
  "      +     · ┆ ·  ··  · ┆ ·     +",
  "          ·   + ┆  ··  ┆ +   ·",
  "              · ┆  ··  ┆ ·",
  "           ·    ·  ··  ·    ·",
  "                ·  ··  ·",
  "                   ··",
  "                   ·"
];
const LOGO = [
  " ███████╗██████╗ ███████╗ ██████╗████████╗███████╗██████╗ ",
  " ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗",
  " ███████╗██████╔╝█████╗  ██║        ██║   █████╗  ██████╔╝",
  " ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══╝  ██╔══██╗",
  " ███████║██║     ███████╗╚██████╗   ██║   ███████╗██║  ██║",
  " ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝"
];
const COMMANDS = [
  [
    "scan [path|url]",
    "scan source, build or a published app"
  ],
  [
    "compare <old> <new>",
    "compare two SPECTER reports"
  ],
  [
    "doctor",
    "check the local environment"
  ],
  [
    "init",
    "create specter.config.ts"
  ],
  [
    "config",
    "print the resolved configuration"
  ],
  [
    "version",
    "print the CLI version"
  ],
  [
    "help",
    "show this screen"
  ]
];

export function renderWelcome(version: string, columns = 120, color = false): string {
  const paint = (text: string, rgb: string): string =>
    color ? `\u001b[38;2;${rgb}m${text}\u001b[0m` : text;
  const mint = (text: string) => paint(text, "0;255;170");
  const cyan = (text: string) => paint(text, "0;200;240");
  const gray = (text: string) => paint(text, "184;184;202");
  const width = Math.max(30, Math.floor(columns));
  const wide = width >= 118;
  const rightWidth = wide ? width - 46 : width;
  const heading = (title: string) =>
    cyan(title + " " + "─".repeat(Math.max(0, rightWidth - title.length - 1)));
  const logoRows = rightWidth >= 66
    ? LOGO.map((line, i) => mint(line) + (i === 5 ? cyan(` v${version}`) : ""))
    : [mint("SPECTER") + cyan(` v${version}`)];
  const commands = COMMANDS.flatMap(([syntax = "", description = ""]) =>
    rightWidth >= 72
      ? [mint("specter") + " " + gray(syntax.padEnd(25) + description)]
      : [mint("specter") + " " + gray(syntax), gray("  " + description)]);
  const flags = ["--json", "--sarif", "--ci", "--baseline <report>", "--output <path>"];
  const flagRows: string[] = [];
  let flagRow = "";
  for (const flag of flags) {
    if (flagRow && flagRow.length + flag.length + 2 > rightWidth) {
      flagRows.push(gray(flagRow));
      flagRow = "";
    }
    flagRow += (flagRow ? "  " : "") + flag;
  }
  if (flagRow) flagRows.push(gray(flagRow));
  const right = [
    "", ...logoRows,
    gray("Application security from source to production."),
    "", "", heading("COMMANDS"), "",
    ...commands, "", "", heading("COMMON FLAGS"), "", ...flagRows,
  ];
  const ghostLine = (line: string) => [...line].map((char, i) =>
    char === " " ? char : /[·┆+]/u.test(char) ? cyan(char) :
    /[◣◢▝▘▀▄]/u.test(char) ? mint(char) : i % 5 === 0 ? cyan(char) : mint(char)
  ).join("");
  if (!wide) return ["", ...logoRows, "",
    ...(width >= 42 ? GHOST.map(ghostLine) : []), "",
    gray("Application security from source to production."), "",
    heading("COMMANDS"), ...commands, "", heading("COMMON FLAGS"), ...flagRows, ""
  ].join("\n");
  return ["", ...Array.from({ length: Math.max(GHOST.length, right.length) }, (_, i) =>
    ghostLine((GHOST[i] ?? "").padEnd(42)) + "  " + cyan("│") + " " + (right[i] ?? "")
  ), ""].join("\n");
}

export function welcomeColor(): boolean {
  if (process.env.NO_COLOR !== undefined || process.env.TERM === "dumb") return false;
  if (process.env.FORCE_COLOR !== undefined) return process.env.FORCE_COLOR !== "0";
  return Boolean(process.stdout.isTTY);
}
