import type { NormalizedProxySnareMode } from "./detector.js";

export type ProxySnareNaturalLanguagePlan =
  | {
      input: string;
      intent: "demo";
      goal: string;
      options: { port: number; mode: NormalizedProxySnareMode };
      command: string;
      reasons: string[];
    }
  | {
      input: string;
      intent: "protect";
      goal: string;
      options: {
        target: string;
        port: number;
        mode: NormalizedProxySnareMode;
        protectedPaths: string[];
        trustProxy: string;
      };
      command: string;
      reasons: string[];
    };

export function compileNaturalLanguage(prompt: string): ProxySnareNaturalLanguagePlan;
