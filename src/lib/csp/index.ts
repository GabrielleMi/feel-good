import type { AstroIntegration, AstroIntegrationLogger } from "astro";
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parse as htmlParse } from "node-html-parser";
import { createHash } from 'crypto';
import path from "node:path";

type CSPConfigValue = (string|null|undefined|false)[]|null;

type CSPConfig = {
    "default-src"?: CSPConfigValue
    
    /**
     * The HTTP Content-Security-Policy base-uri restricts the URLs which can be used in a document's <base> element.
     * If this value is absent, then any URI is allowed.
     * If this directive is absent, the user agent will use the value in the <base> element.
     * 
     * @link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/base-uri
     */
    "base-uri"?: CSPConfigValue
    /**
     * @deprecated This feature is no longer recommended.
     * Though some browsers might still support it, it may have already been removed from the relevant web standards,
     * may be in the process of being dropped, or may only be kept for compatibility purposes.
     * Be aware that this feature may cease to work at any time.
     * 
     * @link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/block-all-mixed-content
     */
    "block-all-mixed-content"?: CSPConfigValue
    /**
     * The HTTP Content-Security-Policy (CSP) child-src directive defines the valid sources for web workers and
     * nested browsing contexts loaded using elements such as <frame> and <iframe>.
     * For workers, non-compliant requests are treated as fatal network errors by the user agent.
     * 
     * @link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/child-src
     */
    "child-src"?: CSPConfigValue
    /**
     * The HTTP Content-Security-Policy (CSP) connect-src restricts the URLs loaded using script interfaces.
     * The following APIs are controlled by this directive:
     * The ping attribute in <a> elements
     * - fetch()
     * - XMLHttpRequest
     * - WebSocket
     * - EventSource
     * - Navigator.sendBeacon()
     * 
     * @link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/connect-src
     */
    "connect-src"?: CSPConfigValue
    /**
     * @experimental
     * The HTTP Content-Security-Policy (CSP) fenced-frame-src directive specifies valid sources for nested
     * browsing contexts loaded into <fencedframe> elements.
     * 
     * @link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/fenced-frame-src
     */
    "fenced-frame-src"?: CSPConfigValue
    /**
     * The HTTP Content-Security-Policy (CSP) font-src specifies valid sources for fonts loaded using @font-face.
     * 
     * @link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/font-src
     */
    "font-src"?: CSPConfigValue
    /**
     * The HTTP Content-Security-Policy (CSP) form-action directive restricts the URLs which can be used
     * as the target of form submissions from a given context.
     * 
     * @link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/form-action
     */
    "form-action"?: CSPConfigValue
    /**
     * The HTTP Content-Security-Policy (CSP) frame-ancestors directive specifies valid parents that may embed
     * a page using <frame>, <iframe>, <object>, or <embed>.
     * Setting this directive to 'none' is similar to X-Frame-Options: deny (which is also supported in older browsers).
     * 
     * @link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors
     */
    "frame-ancestors"?: CSPConfigValue
    /**
     * The HTTP Content-Security-Policy (CSP) frame-src directive specifies valid sources
     * for nested browsing contexts loading using elements such as <frame> and <iframe>.
     * 
     * @link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-src
     */
    "frame-src"?: CSPConfigValue
    /**
     * The HTTP Content-Security-Policy img-src directive specifies valid sources of images and favicons.
     * 
     * @link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/img-src
     */
    "img-src"?: CSPConfigValue
    /**
     * The HTTP Content-Security-Policy (CSP) script-src directive specifies valid sources for JavaScript.
     * This includes not only URLs loaded directly into <script> elements, but also things like
     * inline script event handlers (onclick) and XSLT stylesheets which can trigger script execution.
     * 
     * @link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src
     */
    "script-src"?: CSPConfigValue
    /**
     * The HTTP Content-Security-Policy (CSP) style-src directive specifies valid sources for stylesheets.
     * 
     * @link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/style-src
     */
    "style-src"?: CSPConfigValue
};

export const joinStr = (strings: (string|null|undefined|false)[], splitter?: string): string => {
  return strings.reduce((finalStr: string, str) => {
      if(!!str) {
          return finalStr ? `${finalStr}${splitter||""}${str}` : `${str}`;
      }

      return finalStr; 
  }, "");
};

export function buildCSP(config: CSPConfig) {
  return Object.entries(config).reduce((csp, [ policy, value ]) => {
      if(!value || value.length === 0) {
          return csp;
      }

      const policyContent = joinStr(value, ' ');

      return joinStr([
          csp,
          policyContent ? `${policy} ${policyContent}` : null
      ], '; ');
  }, '');
}

const createCSPHash = (s: string) => {
	const hash = createHash('sha256');
	hash.update(s);
	const hashBase64 = hash.digest('base64');
  
	return `sha256-${hashBase64}`;
};

const addIntegrityToHtml = (html: string, logger: AstroIntegrationLogger, config?: CSPConfig): string => {
	const hashes = {
	  "style-src": [] as string[],
	  "script-src": [] as string[]
	};
  const root = htmlParse(html);
  root.querySelectorAll('script').forEach((script) => {
    const src = script.getAttribute('src');
    logger.info(`Adding CSP to script ${src || script.textContent}`);

    if(!src) {
      const hash = createCSPHash(script.textContent);
      hashes['script-src'] = [ ...hashes['script-src'], `'${hash}'` ];
      script.setAttribute('integrity', hash);
    }
  });

  root.querySelectorAll('link, style').forEach((link) => {
    const href = link.getAttribute('href');
    logger.info(`Adding CSP to link ${href || link.textContent}`);
    
    if(!href) {
      const hash = createCSPHash(link.textContent);
      hashes['style-src'] = [...hashes['style-src'], `'${hash}'`];
      link.setAttribute('integrity', hash);
    }
  });

  const head = root.querySelector('head');
  logger.info(`Adding meta tag to head`);

  if(head) {
    const fullCsp = {
        ...config,
        'script-src': [ ...(config?.['script-src'] || []), ...hashes['script-src'] ],
        'style-src': [ ...(config?.['style-src'] || []), ...hashes['style-src'] ]
    }
    const contentCsp = buildCSP(fullCsp);
    const metaContent = `<meta http-equiv="Content-Security-Policy" content="${contentCsp}">`;
    
    logger.info(`Adding CSP meta tag ${metaContent}`);
    head.insertAdjacentHTML("afterbegin", metaContent);
  } else {
    logger.error(`Cannot find head tag in the HTML`);
  }

  return root.toString();
};

export function csp(config: { policies?: CSPConfig, output: 'meta'|'headers' }): AstroIntegration {
  return {
		name: 'csp',
		hooks: {
      'astro:config:setup': ({ logger }) => {
        const cspLogger = logger.fork('csp/config:setup');

        if(!config.policies) {
          cspLogger.warn('No CSP policies provided!');
        }
      },
      'astro:server:setup': ({ logger, server }) => {
        const cspLogger = logger.fork('csp/server:setup');
        cspLogger.info('Setting up CSP server middleware');

        server.middlewares.use(
          async function middleware(req, res, next) {
            try {
              // read
              // modify
              // next
            } catch (e) {
              // Handle errors
            }
            next();
          }
        );
      },
      'astro:server:start': ({ logger }) => {
        const cspLogger = logger.fork('csp/server:start');
        cspLogger.info('Starting CSP server setup');
      },
      'astro:build:done': ({ pages, dir, logger }) => {
				const cspLogger = logger.fork('csp/build:done');

				pages.forEach((page) => {
					const filePath = fileURLToPath(`${dir.href}${page.pathname}index.html`);
			
					try {
            cspLogger.info(`Adding CSP to ${filePath}`);
					  const modifiedHtml = addIntegrityToHtml(
              readFileSync(filePath, { encoding: 'utf-8' }),
              cspLogger,
              config?.policies
            );
            writeFileSync(filePath, modifiedHtml, "utf-8");
					} catch (e) {
					  cspLogger.error(`Cannot read file ${filePath}: ${e}`);
					}
				});
			},
		},
	}
}